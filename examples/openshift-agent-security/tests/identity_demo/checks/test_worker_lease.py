# SPDX-License-Identifier: Apache-2.0
"""Real lease transitions with a mock API; no claim/mutation replay on loss."""
import argparse
from copy import deepcopy
from datetime import datetime, timezone
import json

import httpx
import pytest

from deployment_profile import LEGACY
import identity_demo_worker_lease as lease


def setup(tmp_path):
    token = tmp_path / 'token'
    token.write_text('first-projected-token-value')
    args = argparse.Namespace(service_account_token_file=str(token),
        service_account_namespace=LEGACY.core_namespace,
        service_account_name='fixture-console-coordinator', pod_uid='pod-uid')
    obj = {'apiVersion': 'coordination.k8s.io/v1', 'kind': 'Lease',
        'metadata': {'name': 'fixture-console-coordinator', 'namespace': LEGACY.core_namespace,
                     'uid': 'lease-uid', 'resourceVersion': '1', 'labels': dict(LEGACY.labels)},
        'spec': {'leaseDurationSeconds': 45}}
    seen = []
    def api(request):
        seen.append((request.method, request.headers['authorization']))
        if request.method == 'PUT':
            incoming = json.loads(request.content)
            if incoming['metadata']['resourceVersion'] != obj['metadata']['resourceVersion']:
                return httpx.Response(409)
            obj.update(incoming)
            obj['metadata']['resourceVersion'] = str(int(obj['metadata']['resourceVersion']) + 1)
        return httpx.Response(200, json=deepcopy(obj))
    client = httpx.Client(base_url=LEGACY.expected_server, transport=httpx.MockTransport(api))
    clock = {'now': 1000.0, 'mono': 0.0}
    worker = lease.WorkerLease(args, 'coordinator', client=client,
        monotonic=lambda: clock['mono'], now=lambda: clock['now'])
    return worker, obj, clock, token, seen


def test_lease_renews_with_replaced_projected_token(tmp_path):
    worker, obj, clock, token, seen = setup(tmp_path)
    worker.renew(acquire=True)
    worker.assert_current()
    replacement = token.with_suffix('.new')
    replacement.write_text('rotated-projected-token-value')
    replacement.replace(token)
    clock['mono'] += 4
    worker.renew()
    assert all(value.endswith('rotated-projected-token-value') for _, value in seen[-2:])
    assert obj['spec']['holderIdentity'] == worker.holder
    assert obj['spec']['leaseTransitions'] == 1


def test_other_owner_and_recreated_lease_stop_execution(tmp_path):
    worker, obj, clock, token, seen = setup(tmp_path)
    worker.renew(acquire=True)
    obj['spec']['holderIdentity'] = 'another-pod/process'
    with pytest.raises(lease.LeaseUnavailable): worker.renew()
    assert seen[-1][0] == 'GET'
    with pytest.raises(lease.LeaseUnavailable): worker.assert_current()
    obj['spec']['holderIdentity'] = worker.holder
    with pytest.raises(lease.LeaseUnavailable): worker.renew()


def test_no_mutation_after_stale_lease_or_unknown_owner(tmp_path):
    worker, obj, clock, token, seen = setup(tmp_path)
    with pytest.raises(lease.LeaseUnavailable): worker.assert_current()
    worker.renew(acquire=True)
    clock['mono'] = worker.freshness
    with pytest.raises(lease.LeaseUnavailable): worker.assert_current()
    obj['metadata']['uid'] = 'replacement'
    with pytest.raises(lease.LeaseUnavailable): worker.renew()


def test_only_expired_competitor_can_be_acquired(tmp_path):
    worker, obj, clock, token, seen = setup(tmp_path)
    obj['spec'].update(holderIdentity='old-pod/process', renewTime='1970-01-01T00:00:00Z')
    worker.renew(acquire=True)
    assert obj['spec']['holderIdentity'] == worker.holder
    assert obj['spec']['leaseTransitions'] == 1


def test_alive_competitor_is_not_displaced(tmp_path):
    worker, obj, clock, token, seen = setup(tmp_path)
    obj['spec'].update(holderIdentity='old-pod/process', renewTime=datetime.fromtimestamp(clock['now'], timezone.utc).isoformat())
    with pytest.raises(lease.LeaseUnavailable): worker.renew(acquire=True)
    assert [m for m, _ in seen] == ['GET']
