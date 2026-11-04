# SPDX-License-Identifier: Apache-2.0
"""Public harness runs without infrastructure and rejects a bypassed consent gate."""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def exercise(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / 'examples/document-agent'))
    host = load(ROOT / 'examples/document-agent/host.py', 'conformance_document_host')
    harness = load(ROOT / 'examples/adapter_conformance.py', 'public_adapter_conformance')
    def backend(directory):
        value = host.Documents(directory)
        value.dispatch = value.publish
        return value
    return harness.verify(host.DOCUMENTS, lambda scope: {'collection': scope, 'document': 'runbook',
        'revision': 1, 'content': 'Synthetic conformance'}, backend, 'engineering', 'research')


def test_public_harness_exercises_exact_action_permissions_and_uncertainty(monkeypatch):
    result = exercise(monkeypatch)
    assert len(result['passed']) == 13
    assert {'wrong-run', 'altered-effects', 'committed-lost-response-reconciliation'} <= set(result['passed'])
    assert not result['deployed_authentication_or_isolation_proven']


def test_conformance_detects_missing_approval_gate(monkeypatch):
    from agent_security_runtime import SecurityService
    monkeypatch.setattr(SecurityService, 'execute', lambda self, actor, body: {'dispatched': True})
    with pytest.raises(AssertionError, match='Expected security denial'):
        exercise(monkeypatch)


def test_same_conformance_definition_checks_existing_jira_contract():
    from copy import deepcopy
    from identity_demo_jira_contract import JIRA
    harness = load(ROOT / 'examples/adapter_conformance.py', 'jira_adapter_conformance')
    class SyntheticJira:
        def __init__(self, directory):
            self.records = {}
        def dispatch(self, effects):
            reference = effects['project'] + '-' + str(len(self.records) + 1)
            self.records[reference] = deepcopy(effects)
            return reference
        def observe(self, reference):
            return deepcopy(self.records[reference])
        def read(self, scope):
            return {'project': scope}
    result = harness.verify(JIRA, lambda scope: {'project': scope,
        'summary': 'Synthetic shared contract check', 'description': 'No network or Jira server'},
        SyntheticJira, 'TEST', 'OPS')
    assert len(result['passed']) == 13
    assert not result['deployed_authentication_or_isolation_proven']
