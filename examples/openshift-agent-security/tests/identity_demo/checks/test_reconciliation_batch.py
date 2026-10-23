# SPDX-License-Identifier: Apache-2.0
"""Batched observations save process launches without caching trust or ownership."""

from argparse import Namespace
from copy import deepcopy

import pytest

import native_backend as backend


def objects() -> list[dict]:
    """Return exactly the two protected discovery resources."""
    return [{'apiVersion': api, 'kind': kind,
             'metadata': {'name': backend.route.READ_NAME, 'namespace': backend.shared.NS,
                          'labels': dict(backend.shared.LABELS)}, 'status': {}}
            for api, kind in [('authorino.kuadrant.io/v1beta3', 'AuthConfig'),
                              ('mcp.kuadrant.io/v1alpha1', 'MCPServerRegistration')]]


def test_one_read_process_validates_each_exact_object_independently(monkeypatch) -> None:
    calls = []
    values = objects()
    def kube(_args: object, *words: str, payload: dict) -> dict:
        calls.append(words)
        assert words == ('get', '-f', '-', '-n', backend.shared.NS, '-o', 'json')
        assert all(set(v) == {'apiVersion', 'kind', 'metadata'} for v in payload['items'])
        assert payload['items'][0]['metadata']['name'] == backend.route.READ_NAME
        return {'kind': 'List', 'items': list(reversed(values))}
    monkeypatch.setattr(backend.shared, 'kube', kube)
    assert backend.reconciliation_status(Namespace()) == tuple(values)
    assert len(calls) == 1


@pytest.mark.parametrize('change', ['missing', 'duplicate', 'foreign_owner', 'foreign_namespace',
                                    'wrong_api', 'wrong_kind', 'wrong_name', 'terminating', 'extra', 'malformed'])
def test_partial_or_substituted_reconciliation_is_never_ready(monkeypatch, change: str) -> None:
    values = objects()
    if change == 'missing':
        values.pop()
    elif change == 'duplicate':
        values[1] = deepcopy(values[0])
    elif change == 'foreign_owner':
        values[1]['metadata']['labels']['identity-demo-owner'] = 'foreign'
    elif change == 'foreign_namespace':
        values[1]['metadata']['namespace'] = 'foreign'
    elif change == 'wrong_api':
        values[1]['apiVersion'] = 'foreign/v1'
    elif change == 'wrong_kind':
        values[1]['kind'] = 'Secret'
    elif change == 'wrong_name':
        values[1]['metadata']['name'] = 'foreign'
    elif change == 'terminating':
        values[1]['metadata']['deletionTimestamp'] = 'now'
    elif change == 'extra':
        values.append(deepcopy(values[0]))
    else:
        values[1] = None
    monkeypatch.setattr(backend.shared, 'kube', lambda *a, **kw: {'kind': 'List', 'items': values})
    with pytest.raises(ValueError):
        backend.reconciliation_status(Namespace())


def test_next_poll_does_not_reuse_previous_ownership(monkeypatch) -> None:
    values = objects()
    monkeypatch.setattr(backend.shared, 'kube', lambda *a, **kw: {'kind': 'List', 'items': values})
    backend.reconciliation_status(Namespace())
    values[0]['metadata']['labels']['identity-demo-owner'] = 'foreign'
    with pytest.raises(ValueError):
        backend.reconciliation_status(Namespace())
