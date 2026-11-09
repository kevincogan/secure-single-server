# SPDX-License-Identifier: Apache-2.0
"""Controller mode cannot silently fall back to administrative registration."""
from copy import deepcopy
from argparse import Namespace
from contextlib import contextmanager
import json

import execution_context as execution

import pytest

import identity_demo_controller_identity as controller
from deployment_profile import LEGACY
from execution_context import resolve_context

from checks.support.execution_context import fixture

IMAGE = 'registry.example.test/native/supervisor@sha256:' + 'a' * 64


def test_controller_mode_refuses_unknown_value(monkeypatch):
    monkeypatch.setenv('IDENTITY_DEMO_REGISTRATION_MODE', 'automatic')
    with pytest.raises(ValueError):
        controller.enabled()


def test_policy_has_no_administrative_identity_and_exact_namespace():
    value = controller.policy(LEGACY, 'reader', IMAGE)
    spec = value['spec']
    assert spec['namespaceSelector']['matchLabels'] == {'kubernetes.io/metadata.name': 'demo-reader'}
    assert spec['admin'] is False and spec['downstream'] is False
    assert spec['workloadSelectorTemplates'][-1] == 'k8s:container-image:' + IMAGE
    assert 'fixture-openshell-sandbox' in spec['spiffeIDTemplate']
    assert '(eq .PodMeta.Name' in spec['spiffeIDTemplate']
    assert spec['ttl'] == '2m' and spec['jwtTtl'] == '2m'


def controller_fixture(tmp_path, monkeypatch):
    context, path, records = fixture(tmp_path)
    supervisor = records['pod', 'os-supervisor-' + context.sandbox_id]
    supervisor['metadata']['labels'] = {'openshell.ai/sandbox-id': context.sandbox_id,
        'openshell.ai/boundary-pair': context.sandbox_id, 'openshell.ai/boundary-role': 'supervisor',
        'openshell.ai/gateway-id': LEGACY.gateway_id, 'openshell.ai/managed-by': 'openshell'}
    supervisor['status']['containerStatuses'][0]['imageID'] = supervisor['spec']['containers'][0]['image']
    monkeypatch.setenv('IDENTITY_DEMO_REGISTRATION_MODE', 'controller')
    monkeypatch.setattr(controller, 'configured_native_image', lambda role: IMAGE)
    policy = controller.policy(LEGACY, context.role, IMAGE)
    policy['metadata']['uid'] = 'policy-uid'
    policy['status'] = {'stats': {'namespacesSelected': 1, 'podsSelected': 1, 'entriesToSet': 1,
        'podEntryRenderFailures': 0, 'entryFailures': 0}}
    records['clusterspiffeids.spire.spiffe.io', policy['metadata']['name']] = policy
    records.pop(('clusterstaticentries.spire.spiffe.io', context.registration_name))
    read = lambda kind, name, namespace=None: records[kind, name]
    return context, path, records, policy, read


@pytest.mark.parametrize('change', ['image', 'namespace', 'admin', 'uid', 'status', 'supervisor_owner'])
def test_controller_validation_rejects_policy_and_owner_drift(tmp_path, monkeypatch, change):
    context, path, records, policy, read = controller_fixture(tmp_path, monkeypatch)
    assert resolve_context(str(path), read) == context
    if change == 'image': policy['spec']['workloadSelectorTemplates'][-1] += 'forged'
    if change == 'namespace': policy['spec']['namespaceSelector']['matchLabels']['kubernetes.io/metadata.name'] = 'foreign'
    if change == 'admin': policy['spec']['admin'] = True
    if change == 'uid': policy['metadata'].pop('uid')
    if change == 'status': policy['status']['stats']['entryFailures'] = 1
    if change == 'supervisor_owner': records['pod', 'os-supervisor-' + context.sandbox_id]['metadata']['ownerReferences'] = []
    with pytest.raises(ValueError):
        resolve_context(str(path), read)


def test_missing_policy_never_uses_static_registration(tmp_path, monkeypatch):
    context, path, records = fixture(tmp_path)
    supervisor = records['pod', 'os-supervisor-' + context.sandbox_id]
    supervisor['metadata']['labels'] = {'openshell.ai/sandbox-id': context.sandbox_id,
        'openshell.ai/boundary-pair': context.sandbox_id, 'openshell.ai/boundary-role': 'supervisor',
        'openshell.ai/gateway-id': LEGACY.gateway_id, 'openshell.ai/managed-by': 'openshell'}
    supervisor['status']['containerStatuses'][0]['imageID'] = supervisor['spec']['containers'][0]['image']
    monkeypatch.setenv('IDENTITY_DEMO_REGISTRATION_MODE', 'controller')
    monkeypatch.setattr(controller, 'configured_native_image', lambda role: IMAGE)
    with pytest.raises(KeyError):
        resolve_context(str(path), lambda k, n, ns=None: records[k, n])


def clock(monkeypatch, on_sleep=lambda: None):
    now = [0.0]
    monkeypatch.setattr(execution.time, 'monotonic', lambda: now[0])
    def sleep(duration):
        now[0] += duration
        on_sleep()
    monkeypatch.setattr(execution.time, 'sleep', sleep)
    return now


def test_pending_registration_rechecks_full_context_before_recovery(tmp_path, monkeypatch):
    context, path, records, policy, read = controller_fixture(tmp_path, monkeypatch)
    policy['status']['stats']['entriesToSet'] = 0
    now = clock(monkeypatch, lambda: policy['status']['stats'].update(entriesToSet=1))
    reads = []
    def observe(kind, name, namespace=None):
        reads.append(kind)
        return read(kind, name, namespace)
    assert resolve_context(str(path), observe, wait_timeout=60) == context
    assert now[0] == 1 and reads.count('namespace') == 2


@pytest.mark.parametrize('mode', ['ready', 'pending', 'controller_failure'])
def test_cold_provision_uses_real_controller_validation_without_creation_replay(tmp_path, monkeypatch, mode):
    import identity_demo_execution_setup as setup
    context, _, records, policy, _ = controller_fixture(tmp_path, monkeypatch)
    records['namespace', context.namespace]['metadata']['labels'].update(setup.LABELS)
    gateway = controller.gateway_policy(LEGACY, IMAGE)
    gateway['metadata']['uid'] = 'gateway-policy'
    gateway['status'] = {'stats': {'namespacesSelected': 1, 'podsSelected': 1, 'entriesToSet': 1}}
    records['clusterspiffeids.spire.spiffe.io', gateway['metadata']['name']] = gateway
    records['statefulset', 'fixture-openshell'] = {'metadata': {'uid': 'gateway', 'labels': dict(setup.LABELS)}}
    records['pod', 'fixture-openshell-0'] = {'metadata': {'ownerReferences': [{'uid': 'gateway', 'kind': 'StatefulSet'}]},
        'spec': {'serviceAccountName': 'fixture-openshell', 'containers': [{'name': 'openshell-gateway', 'image': IMAGE}]},
        'status': {'containerStatuses': [{'ready': True, 'imageID': IMAGE}]}}
    created = []
    def read(args, kind, name, namespace=None, *, optional=False):
        if kind == 'sandboxes.agents.x-k8s.io' and optional and not created:
            return None
        return records[kind, name]
    def execute(words, **kwargs):
        if words[:2] == ['sandbox', 'create']:
            created.append(words)
            return {'id': context.sandbox_id}
        assert words[:2] == ['sandbox', 'get']
        return {'phase': 'Ready', 'id': context.sandbox_id}
    @contextmanager
    def session(*args, **kwargs):
        yield execute
    monkeypatch.setattr(setup, 'guard', lambda args: (None, {}, None))
    monkeypatch.setattr(setup, 'read', read)
    monkeypatch.setattr(setup.native, 'native_session', session)
    if mode == 'pending':
        policy['status']['stats']['entriesToSet'] = 0
    elif mode == 'controller_failure':
        policy['status']['stats']['entryFailures'] = 1
    now = clock(monkeypatch, lambda: policy['status']['stats'].update(entriesToSet=1))
    output = tmp_path/'provision'; output.mkdir()
    args = Namespace(role='triage', suffix='a', output_dir=output, action='provision', apply=True)
    if mode == 'controller_failure':
        with pytest.raises(ValueError, match='failures or masked'):
            setup.provision(args)
        assert not (output/'controller-policy.private.json').exists() and now[0] == 0
    else:
        result = setup.provision(args)
        assert result['registration_exact'] and result['registration_mode'] == 'controller'
        assert resolve_context(str(output/'context.private.json'), lambda k,n,ns=None: records[k,n]) == context
        assert now[0] == (1 if mode == 'pending' else 0)
    assert len(created) == 1


@pytest.mark.parametrize('change', ['owner', 'policy', 'context', 'permissions'])
def test_readiness_wait_cannot_hide_changed_identity_or_private_input(tmp_path, monkeypatch, change):
    context, path, records, policy, read = controller_fixture(tmp_path, monkeypatch)
    policy['status']['stats']['entriesToSet'] = 0
    def drift():
        if change == 'owner':
            records['pod', 'os-supervisor-' + context.sandbox_id]['metadata']['ownerReferences'] = []
        elif change == 'policy':
            policy['spec']['admin'] = True
        elif change == 'context':
            path.write_text(path.read_text() + ' ')
        else:
            path.chmod(0o644)
    now = clock(monkeypatch, drift)
    with pytest.raises(ValueError) as error:
        resolve_context(str(path), read, wait_timeout=60)
    assert not isinstance(error.value, controller.ControllerRegistrationPending)
    assert now[0] == 1


@pytest.mark.parametrize('failure', ['podEntryRenderFailures', 'entryFailures', 'entriesMasked'])
def test_controller_failure_is_terminal_even_when_counts_pending(tmp_path, monkeypatch, failure):
    _, path, _, policy, read = controller_fixture(tmp_path, monkeypatch)
    policy['status']['stats'].update(entriesToSet=0, **{failure: 1})
    now = clock(monkeypatch)
    with pytest.raises(ValueError, match='failures or masked'):
        resolve_context(str(path), read, wait_timeout=60)
    assert now[0] == 0


def test_pending_registration_stops_before_native_setup_or_credential_release(tmp_path, monkeypatch):
    import native_exchange as probe
    _, path, _, policy, read = controller_fixture(tmp_path, monkeypatch)
    policy['status']['stats']['entriesToSet'] = 0
    now = clock(monkeypatch)
    calls = []
    def kube(args, *words):
        assert words[0] == 'get'
        calls.append(words)
        return read(words[1], words[2])
    monkeypatch.setattr(probe, 'kube', kube)
    args = Namespace(context_file=str(path), investigate_substitution=False)
    with pytest.raises(controller.ControllerRegistrationPending):
        probe.run(args)
    assert now[0] == 60 and calls
    assert not hasattr(args, 'execution_context')
    assert list(tmp_path.iterdir()) == [path]
