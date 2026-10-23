# SPDX-License-Identifier: Apache-2.0
"""Controller mode cannot silently fall back to administrative registration."""
from copy import deepcopy
from dataclasses import asdict

import pytest

import identity_demo_controller_identity as controller
from deployment_profile import LEGACY
from checks.test_execution_context import fixture
from execution_context import resolve_context

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


@pytest.mark.parametrize('change', ['image', 'namespace', 'admin', 'uid', 'status', 'supervisor_owner'])
def test_controller_validation_rejects_policy_and_owner_drift(tmp_path, monkeypatch, change):
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
    static = records.pop(('clusterstaticentries.spire.spiffe.io', context.registration_name))
    read = lambda kind, name, namespace=None: records[kind, name]
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
