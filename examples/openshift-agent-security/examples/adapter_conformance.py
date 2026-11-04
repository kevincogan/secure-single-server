# SPDX-License-Identifier: Apache-2.0
"""Offline public-contract harness; synthetic identity, no network or deployment proof.

Supply a reviewed ConnectorContract, effects(scope) and backend_factory(directory).
The backend implements dispatch(effects), observe(reference) and read(scope).
Each case gets private empty storage and a fresh single-use native-shaped identity.
"""
from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
import time
from uuid import uuid4

from agent_security_runtime import BackendPort, Denied, RunStore, SecurityService, VerifiedActor


def verify(contract, effects, backend_factory, scope, other_scope):
    """Raise on a failed security invariant; return the independently exercised cases."""
    passed = []
    writer = sorted(contract.write_user_roles)[0]
    worker = sorted(contract.write_workload_roles)[0]

    @contextmanager
    def fresh(*, user_role=writer, workload_role=worker, lose=False):
        with tempfile.TemporaryDirectory(prefix='adapter-conformance-') as directory:
            root = Path(directory)
            backend = backend_factory(root / 'backend')
            store = RunStore(root / 'runs.db', connector=contract, trust_domain='conformance.example.test')
            actor = VerifiedActor('synthetic-user', 'spiffe://conformance.example.test/openshell/sandbox/' + str(uuid4()))
            run = store.create_run(issuer='https://issuer.example.test', user=actor.user, user_role=user_role,
                workload=actor.workload, workload_role=workload_role, project=scope,
                expires=int(time.time()) + 300, assessment='Synthetic adapter conformance')
            dispatched = []
            def dispatch(value):
                reference = backend.dispatch(value)
                dispatched.append(reference)
                if lose:
                    raise TimeoutError('Synthetic loss after backend commit')
                return reference
            service = SecurityService(store, BackendPort(contract.fingerprint, dispatch, backend.observe, backend.read))
            yield service, actor, run, dispatched, backend

    def body(run, action, arguments=None):
        return json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {
            'name': contract.tool, 'arguments': {'run_id': run, 'action_id': action['action_id'],
                **(action['arguments'] if arguments is None else arguments)}}}).encode()

    def denied(operation):
        try:
            operation()
        except Denied:
            return
        raise AssertionError('Expected security denial')

    def approve(service, actor, run, action):
        service.approve(actor, run, action['action_id'], action['digest'], int(time.time()) + 120)

    with fresh() as (service, actor, run, writes, backend):
        service.read(actor, run, scope)
        denied(lambda: service.read(actor, run, other_scope))
        action = service.propose(actor, run, effects(scope))
        denied(lambda: service.execute(actor, body(run, action)))
        denied(lambda: service.approve(actor, run, action['action_id'], '0' * 64, int(time.time()) + 120))
        approve(service, actor, run, action)
        denied(lambda: service.execute(VerifiedActor('another-user', actor.workload), body(run, action)))
        denied(lambda: service.execute(VerifiedActor(actor.user,
            'spiffe://conformance.example.test/openshell/sandbox/' + str(uuid4())), body(run, action)))
        altered = contract.proposal(effects(scope), uuid4().hex)
        denied(lambda: service.execute(actor, body(run, action, altered)))
        denied(lambda: service.execute(actor, body(uuid4().hex, action)))
        changed = contract.proposal(effects(other_scope), action['action_id'])
        denied(lambda: service.execute(actor, body(run, action, changed)))
        if writes:
            raise AssertionError('A negative case contacted dispatch')
        result = service.execute(actor, body(run, action))
        if not result['verified'] or not result['dispatched'] or len(writes) != 1:
            raise AssertionError('Approved dispatch did not succeed exactly once')
        if contract.canonical(backend.observe(writes[0]))[1] != action['digest']:
            raise AssertionError('Independent observation differs from approved effects')
        if service.execute(actor, body(run, action))['dispatched'] or len(writes) != 1:
            raise AssertionError('Replay dispatched again')
        passed += ['read-scope', 'missing-approval', 'altered-approval', 'wrong-user', 'wrong-workload',
            'wrong-run', 'altered-effects', 'changed-effects-scope', 'exact-dispatch-observation', 'replay']

    for permission, roles in [('user', contract.user_roles - contract.write_user_roles),
                              ('workload', contract.workload_roles - contract.write_workload_roles)]:
        for role in sorted(roles):
            with fresh(**{permission + '_role': role}) as (service, actor, run, writes, _):
                action = service.propose(actor, run, effects(scope))
                approve(service, actor, run, action)
                denied(lambda: service.execute(actor, body(run, action)))
                if writes:
                    raise AssertionError('Approval supplied missing authority')
                passed.append(permission + '-denial:' + role)

    with fresh(lose=True) as (service, actor, run, writes, backend):
        action = service.propose(actor, run, effects(scope))
        approve(service, actor, run, action)
        denied(lambda: service.execute(actor, body(run, action)))
        denied(lambda: service.execute(actor, body(run, action)))
        if len(writes) != 1:
            raise AssertionError('Unknown outcome was replayed or never committed')
        pending = service.store.reconciliation(run, action['action_id'])
        service.store.reconcile_result(run, action['action_id'], pending['execution_id'],
            writes[0], backend.observe(writes[0]))
        if service.execute(actor, body(run, action))['dispatched'] or len(writes) != 1:
            raise AssertionError('Reconciliation enabled replay')
        passed.append('committed-lost-response-reconciliation')
    return {'passed': passed, 'synthetic_identity': True, 'deployed_authentication_or_isolation_proven': False}
