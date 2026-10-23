# SPDX-License-Identifier: Apache-2.0
"""Capacity estimation and native readiness must fail closed before presentation acceptance."""

from argparse import Namespace
from contextlib import contextmanager
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

import pytest

import identity_demo_presentation as presentation
from identity_demo_execution_setup import context_template


@pytest.mark.parametrize('value,expected', [
    ('250m', '.25'), ('768Mi', '805306368'), ('2Gi', '2147483648'),
    ('1000u', '.001'), ('1e3', '1000'), ('1G', '1000000000'), ('0', '0'),
])
def test_kubernetes_capacity_quantities(value: str, expected: str) -> None:
    assert presentation.quantity(value) == Decimal(expected)


@pytest.mark.parametrize('value', ['-1', 'NaN', 'infinity', '1XB', '1mib', ''])
def test_unknown_or_unsafe_quantity_cannot_prove_capacity(value: str) -> None:
    with pytest.raises(ValueError):
        presentation.quantity(value)


def node(name: str = 'worker') -> dict:
    return {'metadata': {'name': name}, 'spec': {}, 'status': {
        'conditions': [{'type': 'Ready', 'status': 'True'}],
        'allocatable': {'cpu': '1', 'memory': '3Gi', 'pods': '8'}}}


def test_capacity_requires_pairs_and_accounts_for_init_requests_and_overhead() -> None:
    pods = [{'spec': {'nodeName': 'worker', 'containers': [{'resources': {'requests': {'cpu': '250m', 'memory': '768Mi'}}}],
                     'initContainers': [{'resources': {'requests': {'cpu': '250m', 'memory': '768Mi'}}}],
                     'overhead': {'cpu': '250m', 'memory': '768Mi'}}, 'status': {'phase': 'Running'}}]
    value = presentation.node_slots([node()], pods)
    assert value['estimated_extra_context_slots'] == 3
    assert value['free_requested_cpu_millicores'] == 250
    assert value['free_requested_memory_mib'] == 768


@pytest.mark.parametrize('change', [{'unschedulable': True}, {'taints': [{'effect': 'NoSchedule'}]},
                                   {'taints': [{'effect': 'NoExecute'}]}])
def test_unavailable_nodes_cannot_be_counted_as_spare_capacity(change: dict) -> None:
    value = node()
    value['spec'] = change
    assert presentation.node_slots([value], [])['estimated_extra_context_slots'] == 0


def test_sequence_and_buffer_only_add_the_missing_matching_contexts() -> None:
    plan = {'sequence': [{'workflow': 'cve', 'role': 'triage'}] * 2 + [{'workflow': 'cve', 'role': 'reader'}], 'buffer': 1}
    snapshot = {'contexts': [{'workflow': 'cve', 'role': 'triage'}, {'workflow': 'service-request', 'role': 'triage'}]}
    assert presentation.additions_for(plan, snapshot) == {'triage': 2, 'reader': 2}


def test_namespace_storage_quota_prevents_additive_provisioning(monkeypatch) -> None:
    args = Namespace()
    quota = {'spec': {'hard': {'requests.storage': '2Gi'}},
             'status': {'hard': {'requests.storage': '2Gi'}, 'used': {'requests.storage': '2Gi'}}}
    def kube(_args: object, *words: str) -> dict:
        return {'items': [node()] if words[1] == 'nodes' else [quota] if words[1] == 'resourcequotas' else []}
    monkeypatch.setattr(presentation.native, 'kube', kube)
    monkeypatch.setattr(presentation, 'read', lambda *a: {})
    monkeypatch.setattr(presentation, 'owned', lambda *a: None)
    with pytest.raises(ValueError, match='quota headroom'):
        presentation.check_capacity(args, 1, {'triage': 1})


@pytest.mark.parametrize('attached', [False, True])
def test_live_verifier_checks_native_identity_and_empty_provider_bindings(
    tmp_path: Path, monkeypatch, attached: bool
) -> None:
    import execution_context
    import identity_demo_sender_trust
    from dataclasses import asdict
    context = replace(context_template('triage', 'xyz'), sandbox_id=str(uuid4()))
    item = {**asdict(context), 'workload': context.workload, 'workflow': 'cve'}
    identifier = uuid4().hex
    snapshot = {'batch': {'id': identifier, 'filled': True}, 'preparation_pending': False, 'contexts': [item]}
    args = Namespace(output_dir=tmp_path)
    monkeypatch.setattr(presentation, 'guard', lambda a: (None, {}, None))
    monkeypatch.setattr(identity_demo_sender_trust, 'current', lambda a: True)
    monkeypatch.setattr(execution_context, 'validate_context', lambda *a: context)
    monkeypatch.setattr(presentation, 'owned', lambda *a: None)
    monkeypatch.setattr(presentation, 'check_capacity', lambda *a: {})
    def read(_args: object, kind: str, *rest: str) -> dict:
        if kind.startswith('gateways'):
            return {'metadata': {'name': 'fixture-mcp', 'uid': 'gateway', 'generation': 1}, 'status': {'conditions': [
                {'type': 'Programmed', 'status': 'True', 'observedGeneration': 1}]}}
        if kind == 'statefulset':
            return {'spec': {'replicas': 1}, 'status': {'readyReplicas': 1}}
        return {'metadata': {}, 'status': {'phase': 'Running', 'conditions': [{'type': 'Ready', 'status': 'True'}]}}
    monkeypatch.setattr(presentation, 'read', read)
    from identity_demo_lab import LABELS
    deployment = {'metadata': {'generation': 1, 'labels': dict(LABELS), 'ownerReferences': [
        {'uid': 'gateway', 'kind': 'Gateway', 'name': 'fixture-mcp'}]},
        'spec': {'replicas': 1}, 'status': {'readyReplicas': 1, 'observedGeneration': 1}}
    monkeypatch.setattr(presentation.native, 'kube', lambda *a: {'items': [deployment]})
    calls = []
    @contextmanager
    def session(*_args):
        def execute(words: list[str], **kwargs: object) -> dict:
            calls.append(words)
            return {'id': context.sandbox_id, 'phase': 'Ready'} if words[1] == 'get' else {'providers': ['stale'] if attached else []}
        yield execute
    monkeypatch.setattr(presentation.native, 'native_session', session)
    class Control:
        def request(self, route: str) -> dict:
            return {'online': True} if route == 'state' else snapshot
    if attached:
        with pytest.raises(ValueError, match='no attached credentials'):
            presentation.verify_batch(args, Control(), snapshot)
    else:
        receipt = presentation.verify_batch(args, Control(), snapshot)
        assert receipt['unused_contexts_have_no_attached_credentials']
        assert receipt['contexts'][0]['context_sha256'] and context.workload not in str(receipt)
        assert len(calls) == 2


@pytest.mark.parametrize('temporary', [
    {'online': True, 'reason': 'operator_login'},
    {'online': True, 'reason': 'sender_trust'},
    {'online': False, 'auto_prepare': False},
])
def test_batch_observer_waits_through_refresh_without_restarting_preparation(monkeypatch, temporary: dict) -> None:
    pending = {'batch': {'id': 'batch', 'filled': False, 'slots': [{'target': 1, 'available': 0}]},
               'preparation_pending': True, 'unused': 0}
    ready = {'batch': {'id': 'batch', 'filled': True}, 'preparation_pending': False}
    calls = []
    class Control:
        def request(self, route: str) -> dict:
            calls.append(route)
            return temporary if route == 'state' else ready
    monkeypatch.setattr(presentation.time, 'sleep', lambda _: None)
    assert presentation.wait_for_batch(Control(), pending, 30) is ready
    assert calls == ['state', 'pool']


@pytest.mark.parametrize('failure', [{'recovery_required': True}, {'reason': 'context_preparation_failed'}])
def test_batch_observer_stops_on_uncertain_native_preparation(monkeypatch, failure: dict) -> None:
    class Control:
        def request(self, route: str) -> dict:
            assert route == 'state'
            return failure
    pending = {'batch': {'filled': False}, 'preparation_pending': True}
    with pytest.raises(ValueError, match='Preparation blocked'):
        presentation.wait_for_batch(Control(), pending, 30)


def test_seal_waits_for_positive_refresh_and_unchanged_inventory(monkeypatch) -> None:
    snapshot = {'batch': {'id': 'same', 'filled': True}, 'contexts': [{'workload': 'unique'}],
                'preparation_pending': False}
    calls = []
    class Control:
        def request(self, route: str) -> dict:
            calls.append(route)
            if route == 'state':
                return {'online': True}
            return {**snapshot, 'worker': {'phase': 'ready' if len(calls) >= 4 else 'preparing',
                    'updated': 1000, 'checked_at': 1000, 'catalog_expires': 2000}}
    monkeypatch.setattr(presentation.time, 'time', lambda: 1000)
    monkeypatch.setattr(presentation.time, 'sleep', lambda _: None)
    presentation.wait_for_seal_window(Control(), snapshot, 30)
    assert calls == ['state', 'pool', 'state', 'pool']


def test_seal_wait_refuses_inventory_changed_after_verification(monkeypatch) -> None:
    snapshot = {'batch': {'id': 'same', 'filled': True}, 'contexts': [{'workload': 'unique'}],
                'preparation_pending': False}
    class Control:
        def request(self, route: str) -> dict:
            return {'online': True} if route == 'state' else {**snapshot, 'contexts': []}
    with pytest.raises(ValueError, match='inventory changed'):
        presentation.wait_for_seal_window(Control(), snapshot, 30)
