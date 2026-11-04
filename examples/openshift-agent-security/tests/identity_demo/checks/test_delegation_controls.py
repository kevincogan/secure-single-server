# SPDX-License-Identifier: Apache-2.0
"""Evidence guards for deployed delegation probes; these cases are synthetic."""
from types import SimpleNamespace

import pytest

from deployment_profile import active_profile
from native_delegation_acceptance import DelegationAcceptance
import native_delegation_acceptance as controls


@pytest.mark.parametrize('outcome,body,accepted', [(7, b'', True), (0, b'credential', False),
    (9, b'', False), (7, b'credential', False)])
def test_subject_probe_requires_positive_release_and_permission_denial(monkeypatch, outcome, body, accepted):
    first, second = DelegationAcceptance.__new__(DelegationAcceptance), DelegationAcceptance.__new__(DelegationAcceptance)
    first.args = SimpleNamespace(execution_context=SimpleNamespace(workload='spiffe://' + active_profile().trust_domain + '/a'))
    second.args = SimpleNamespace(execution_context=SimpleNamespace(workload='spiffe://' + active_profile().trust_domain + '/b'))
    replies = iter([(0, b'positive'), (outcome, body)])
    first.intermediate = lambda assertion=None: next(replies)
    second.intermediate = lambda: (0, b'other-positive')
    second.fetch = lambda: {'token': 'synthetic-signed-b-assertion'}
    first.save = lambda *args: None
    monkeypatch.setattr(controls.subject, 'token_from_response', lambda message: 'synthetic-control')
    if accepted:
        result = first.subject_controls(second)
        assert result['different_subject_grpc_status'] == 7
        assert result['different_subject_response_message_present'] is False
    else:
        with pytest.raises(ValueError):
            first.subject_controls(second)


def test_delegation_probe_cannot_fetch_private_certificate_material():
    probe = DelegationAcceptance.__new__(DelegationAcceptance)
    with pytest.raises(ValueError, match='Only JWT-SVIDs'):
        probe.fetch('x509')
