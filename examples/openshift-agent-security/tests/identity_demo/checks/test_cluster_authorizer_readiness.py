# SPDX-License-Identifier: Apache-2.0
"""Runtime policy evidence is exact, current and never reads shared credentials."""
from argparse import Namespace
from copy import deepcopy
import json

import pytest

from deployment_profile import active_profile
import identity_demo_gateway_observation as observation
import probe_broker_discovery as shared
import probe_native_exchange as native


@pytest.fixture
def policy(tmp_path, monkeypatch):
    spec = {'rules': {'authorization': {'exact': {'opa': {'rego': 'allow = true'}}}}}
    value = {'kind': 'AuthPolicy', 'metadata': {'name': 'fixture-mcp-bound',
        'namespace': active_profile().core_namespace, 'uid': 'owned-policy', 'generation': 2},
        'spec': spec, 'status': {'observedGeneration': 2, 'conditions': [
            {'type': name, 'status': 'True'} for name in ('Accepted', 'Enforced')]}}
    receipt = {'kind': 'persistent-live-gateway-v1', 'profile': active_profile().to_dict(),
               'policies_after': [deepcopy(value)]}
    path = tmp_path / 'gateway.private.json'
    path.write_text(json.dumps(receipt)); path.chmod(0o600)
    args = Namespace(gateway_receipt=str(path), gateway_mode='persistent')
    calls = []
    monkeypatch.setattr(shared, 'owned', lambda *a: calls.append(a[1:]) or value)
    def forbidden(*a, **k):
        raise AssertionError('No generated shared configuration or shell fallback')
    monkeypatch.setattr(native, 'kube', forbidden)
    monkeypatch.setenv('IDENTITY_DEMO_RUNTIME', 'cluster')
    return args, value, calls


def test_cluster_wait_observes_only_exact_owned_policy(policy):
    args, value, calls = policy
    native.wait_authorizer(args, value['spec'])
    assert calls == [('authpolicy', 'fixture-mcp-bound')]


@pytest.mark.parametrize('change', ['uid', 'namespace', 'spec', 'deleted', 'requested-spec'])
def test_replaced_or_changed_policy_cannot_authorize_readiness(policy, change):
    args, value, _ = policy
    spec = deepcopy(value['spec'])
    if change in ('uid', 'namespace'): value['metadata'][change] = 'another'
    elif change == 'deleted': value['metadata']['deletionTimestamp'] = 'now'
    elif change == 'spec': value['spec'] = {}
    else: spec = {}
    with pytest.raises(ValueError): observation.authorizer_current(args, spec)


@pytest.mark.parametrize('change', ['stale', 'condition-stale', 'not-enforced', 'missing', 'duplicate', 'no-generation'])
def test_unreconciled_policy_is_not_ready(policy, change):
    args, value, _ = policy
    status = value['status']
    if change == 'stale': status['observedGeneration'] = 1
    elif change == 'condition-stale': status['conditions'][1]['observedGeneration'] = 1
    elif change == 'not-enforced': status['conditions'][1]['status'] = 'False'
    elif change == 'missing': status['conditions'].pop()
    elif change == 'duplicate': status['conditions'].append(deepcopy(status['conditions'][1]))
    else: value['metadata'].pop('generation')
    assert observation.authorizer_current(args, value['spec']) is False


def test_temporary_mode_never_uses_cluster_shared_config_fallback(policy):
    args, value, _ = policy
    args.gateway_mode = 'temporary'
    with pytest.raises(ValueError, match='persistent'): native.wait_authorizer(args, value['spec'])
