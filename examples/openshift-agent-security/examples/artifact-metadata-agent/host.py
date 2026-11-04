# SPDX-License-Identifier: Apache-2.0
"""Offline host, explicitly synthetic authentication/consent, protected execution."""
import argparse
import json
from pathlib import Path
import sqlite3
import tempfile
import time
from uuid import uuid4

from agent_security_runtime import BackendPort, Denied, RunStore, SecurityService, VerifiedActor

from agent import propose_metadata
from backend import ArtifactCatalog
from contract import CONTRACT

SCOPE = 'catalog:release-lab'
OTHER_SCOPE = 'catalog:other-lab'
TRUST_DOMAIN = 'artifact-offline.example.test'


class HostAllocationError(Exception):
    """Safe host-facing allocation failure; never a policy grant or workload retry."""


def request_body(run, action, arguments=None):
    return json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {
        'name': CONTRACT.tool, 'arguments': {'run_id': run, 'action_id': action['action_id'],
            **(action['arguments'] if arguments is None else arguments)}}}).encode()


def synthetic_host(directory, *, user_role='catalog-curator', workload_role='metadata-worker',
                   dispatch_wrapper=None, observe_wrapper=None, backend=None, actor=None):
    """Trusted test fixture; no identity, role or callback is accepted from agent output."""
    root = Path(directory)
    backend = backend or ArtifactCatalog(root / 'backend')
    store = RunStore(root / 'runs.db', connector=CONTRACT, trust_domain=TRUST_DOMAIN)
    actor = actor or VerifiedActor('synthetic-curator',
        'spiffe://' + TRUST_DOMAIN + '/openshell/sandbox/' + str(uuid4()))
    try:
        run = store.create_run(issuer='https://synthetic-issuer.example.test', user=actor.user,
            user_role=user_role, workload=actor.workload, workload_role=workload_role,
            project=SCOPE, expires=int(time.time()) + 300, assessment='Synthetic artifact metadata fixture')
    except sqlite3.IntegrityError:
        raise HostAllocationError('Workload allocation failed; obtain a fresh trusted context') from None
    dispatch = backend.dispatch if dispatch_wrapper is None else dispatch_wrapper(backend.dispatch)
    observe = backend.observe if observe_wrapper is None else observe_wrapper(backend.observe)
    service = SecurityService(store, BackendPort(CONTRACT.fingerprint, dispatch, observe, backend.read))
    return service, actor, run, backend


def run_demo(approve=False, user_role='catalog-curator', workload_role='metadata-worker'):
    with tempfile.TemporaryDirectory(prefix='artifact-metadata-host-') as directory:
        service, actor, run, backend = synthetic_host(directory,
            user_role=user_role, workload_role=workload_role)
        action = service.propose(actor, run, propose_metadata(b'local deterministic build output\n'))
        report = {'synthetic_identity': True, 'proposal': action, 'approved': approve}
        if approve:
            service.approve(actor, run, action['action_id'], action['digest'], int(time.time()) + 120)
        try:
            report['execution'] = service.execute(actor, request_body(run, action))
        except Denied as exc:
            report['denial'] = str(exc)
        report['backend_dispatches'] = backend.dispatch_calls
        report['observed_metadata'] = backend.read(SCOPE)
        return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--approve', action='store_true', help='Supply separate synthetic human consent')
    parser.add_argument('--user-role', choices=sorted(CONTRACT.user_roles), default='catalog-curator')
    parser.add_argument('--workload-role', choices=sorted(CONTRACT.workload_roles), default='metadata-worker')
    args = parser.parse_args()
    print(json.dumps(run_demo(args.approve, args.user_role, args.workload_role), indent=2, sort_keys=True))
