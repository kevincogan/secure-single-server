# SPDX-License-Identifier: Apache-2.0
"""Capacity estimation must fail closed before profile preparation."""

from argparse import Namespace
from decimal import Decimal

import pytest

import identity_demo_capacity as capacity


@pytest.mark.parametrize('value,expected', [
    ('250m', '.25'), ('768Mi', '805306368'), ('2Gi', '2147483648'),
    ('1000u', '.001'), ('1e3', '1000'), ('1G', '1000000000'), ('0', '0'),
])
def test_kubernetes_capacity_quantities(value: str, expected: str) -> None:
    assert capacity.quantity(value) == Decimal(expected)


@pytest.mark.parametrize('value', ['-1', 'NaN', 'infinity', '1XB', '1mib', ''])
def test_unknown_or_unsafe_quantity_cannot_prove_capacity(value: str) -> None:
    with pytest.raises(ValueError):
        capacity.quantity(value)


def node(name: str = 'worker') -> dict:
    return {'metadata': {'name': name}, 'spec': {}, 'status': {
        'conditions': [{'type': 'Ready', 'status': 'True'}],
        'allocatable': {'cpu': '1', 'memory': '3Gi', 'pods': '8'}}}


def test_capacity_requires_pairs_and_accounts_for_init_requests_and_overhead() -> None:
    pods = [{'spec': {'nodeName': 'worker', 'containers': [{'resources': {'requests': {'cpu': '250m', 'memory': '768Mi'}}}],
                     'initContainers': [{'resources': {'requests': {'cpu': '250m', 'memory': '768Mi'}}}],
                     'overhead': {'cpu': '250m', 'memory': '768Mi'}}, 'status': {'phase': 'Running'}}]
    value = capacity.node_slots([node()], pods)
    assert value['estimated_extra_context_slots'] == 3
    assert value['free_requested_cpu_millicores'] == 250
    assert value['free_requested_memory_mib'] == 768


@pytest.mark.parametrize('change', [{'unschedulable': True}, {'taints': [{'effect': 'NoSchedule'}]},
                                   {'taints': [{'effect': 'NoExecute'}]}])
def test_unavailable_nodes_cannot_be_counted_as_spare_capacity(change: dict) -> None:
    value = node()
    value['spec'] = change
    assert capacity.node_slots([value], [])['estimated_extra_context_slots'] == 0


def test_namespace_storage_quota_prevents_additive_provisioning(monkeypatch) -> None:
    args = Namespace()
    quota = {'spec': {'hard': {'requests.storage': '2Gi'}},
             'status': {'hard': {'requests.storage': '2Gi'}, 'used': {'requests.storage': '2Gi'}}}
    def kube(_args: object, *words: str) -> dict:
        return {'items': [node()] if words[1] == 'nodes' else [quota] if words[1] == 'resourcequotas' else []}
    monkeypatch.setattr(capacity.native, 'kube', kube)
    monkeypatch.setattr(capacity, 'read', lambda *a: {})
    monkeypatch.setattr(capacity, 'owned', lambda *a: None)
    with pytest.raises(ValueError, match='quota headroom'):
        capacity.check_capacity(args, 1, {'triage': 1})
