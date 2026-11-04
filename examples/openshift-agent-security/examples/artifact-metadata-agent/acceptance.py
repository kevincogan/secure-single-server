# SPDX-License-Identifier: Apache-2.0
"""Independent installed-wheel acceptance; no private runtime imports or network."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import importlib.metadata
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from uuid import uuid4

import agent_security_runtime as runtime
from agent_security_runtime import BackendPort, Denied, RunStore, SecurityService, VerifiedActor

from adapter_conformance import verify
from agent import propose_metadata
from backend import ArtifactCatalog
from contract import CONTRACT, check_reference
from host import HostAllocationError, OTHER_SCOPE, SCOPE, TRUST_DOMAIN, request_body, run_demo, synthetic_host


def effects(scope):
    return propose_metadata(b'offline acceptance build\n', scope)


@contextmanager
def fresh(**kwargs):
    with tempfile.TemporaryDirectory(prefix='artifact-specific-') as directory:
        yield directory, synthetic_host(directory, **kwargs)


def approved(service, actor, run):
    action = service.propose(actor, run, effects(SCOPE))
    service.approve(actor, run, action['action_id'], action['digest'], int(time.time()) + 120)
    return action


class ArtifactIntegrationTests(unittest.TestCase):
    def test_01_agent_is_deterministic_and_metadata_only(self):
        result = propose_metadata(b'build')
        self.assertEqual(result, propose_metadata(b'build'))
        self.assertNotEqual(result['artifact'], propose_metadata(b'changed build')['artifact'])
        self.assertEqual(set(result), {'catalog', 'artifact', 'component', 'media_type', 'size_bytes', 'tags'})

    def test_02_distinct_role_denials_and_pending_consent(self):
        for kwargs, reason in [({}, 'action_proposed'),
                ({'approve': True, 'user_role': 'catalog-observer'}, 'user_permission'),
                ({'approve': True, 'workload_role': 'catalog-reader'}, 'workload_permission')]:
            with self.subTest(reason=reason):
                report = run_demo(**kwargs)
                self.assertEqual(report['denial'], reason)
                self.assertEqual(report['backend_dispatches'], 0)
                self.assertEqual(report['observed_metadata'], [])

    def test_03_schema_rejects_agent_routing_types_bounds_and_marker(self):
        invalid = [dict(effects(SCOPE), destination='file:///tmp/elsewhere'),
            dict(effects(SCOPE), credential='chosen-by-agent'),
            dict(effects(SCOPE), user_role='catalog-curator'),
            dict(effects(SCOPE), workload='chosen-by-agent'),
            dict(effects(SCOPE), size_bytes=True), dict(effects(SCOPE), size_bytes=-1),
            dict(effects(SCOPE), size_bytes=1024 ** 3 + 1),
            dict(effects(SCOPE), tags=['duplicate', 'duplicate']),
            dict(effects(SCOPE), tags=['a'] * 9), dict(effects(SCOPE), tags=[]),
            dict(effects(SCOPE), artifact='sha256:wrong'),
            dict(effects(SCOPE), component='../escape'),
            dict(effects(SCOPE), media_type='text/html'),
            dict(effects(SCOPE), catalog='catalog:../escape'),
            dict(effects(SCOPE), operation_id=uuid4().hex)]
        with fresh() as (_, (service, actor, run, backend)):
            for value in invalid:
                with self.subTest(value=value), self.assertRaises(Denied):
                    service.propose(actor, run, value)
            self.assertEqual(backend.dispatch_calls, 0)

    def test_04_strict_mcp_body_envelope_duplicate_keys_and_tool(self):
        with fresh() as (_, (service, actor, run, backend)):
            action = approved(service, actor, run)
            valid = request_body(run, action)
            wrong_tool = json.loads(valid)
            wrong_tool['params']['name'] = 'publish_document'
            extra_route = json.loads(valid)
            extra_route['params']['arguments']['destination'] = 'https://chosen.example.test'
            duplicate = valid.replace(b'"jsonrpc": "2.0"', b'"jsonrpc":"2.0","jsonrpc":"2.0"')
            for value in (b'{invalid', duplicate, json.dumps(wrong_tool).encode(), json.dumps(extra_route).encode()):
                with self.subTest(body=value), self.assertRaises(Denied):
                    service.execute(actor, value)
            self.assertEqual(backend.dispatch_calls, 0)
            self.assertTrue(service.execute(actor, valid)['verified'])

    def test_05_concurrent_requests_commit_exactly_once(self):
        entered, release = threading.Event(), threading.Event()
        def blocked(dispatch):
            def invoke(value):
                entered.set()
                if not release.wait(5):
                    raise TimeoutError('Test synchronization timed out')
                return dispatch(value)
            return invoke
        with fresh(dispatch_wrapper=blocked) as (_, (service, actor, run, backend)):
            action = approved(service, actor, run)
            body = request_body(run, action)
            def execute():
                try:
                    return service.execute(actor, body)
                except Denied as exc:
                    return {'denied': str(exc)}
            with ThreadPoolExecutor(max_workers=9) as pool:
                first = pool.submit(execute)
                self.assertTrue(entered.wait(5))
                others = [pool.submit(execute) for _ in range(8)]
                results = [value.result(timeout=5) for value in others]
                self.assertEqual(backend.dispatch_calls, 0)
                release.set()
                results.append(first.result(timeout=5))
            self.assertEqual(backend.dispatch_calls, 1)
            self.assertEqual(sum(value.get('dispatched', False) for value in results), 1)
            self.assertEqual(len(backend.read(SCOPE)), 1)

    def test_06_success_survives_store_restart_without_replay(self):
        with fresh() as (directory, (service, actor, run, backend)):
            action = approved(service, actor, run)
            service.execute(actor, request_body(run, action))
            reopened = RunStore(Path(directory) / 'runs.db', connector=CONTRACT, trust_domain=TRUST_DOMAIN)
            restarted = SecurityService(reopened,
                BackendPort(CONTRACT.fingerprint, backend.dispatch, backend.observe, backend.read))
            result = restarted.execute(actor, request_body(run, action))
            self.assertFalse(result['dispatched'])
            self.assertEqual(result['state'], 'succeeded')
            self.assertEqual(CONTRACT.canonical(backend.observe(result['result_ref']))[1], action['digest'])
            self.assertEqual(backend.dispatch_calls, 1)
            self.assertEqual(len(reopened.describe(run, actor.user)['actions']), 1)

    def test_07_unknown_restart_positive_reconciliation_and_negative_evidence(self):
        def lost(dispatch):
            def invoke(value):
                dispatch(value)
                raise TimeoutError('Synthetic committed response loss')
            return invoke
        with fresh(dispatch_wrapper=lost) as (directory, (service, actor, run, backend)):
            action = approved(service, actor, run)
            with self.assertRaises(Denied):
                service.execute(actor, request_body(run, action))
            reopened = RunStore(Path(directory) / 'runs.db', connector=CONTRACT, trust_domain=TRUST_DOMAIN)
            restarted = SecurityService(reopened,
                BackendPort(CONTRACT.fingerprint, backend.dispatch, backend.observe, backend.read))
            with self.assertRaises(Denied):
                restarted.execute(actor, request_body(run, action))
            pending = reopened.reconciliation(run, action['action_id'])
            reference = 'artifact-meta://' + SCOPE + '/' + action['action_id']
            observed = backend.observe(reference)
            for wrong in (dict(observed, size_bytes=999), dict(observed, operation_id=uuid4().hex)):
                with self.assertRaises(Denied):
                    reopened.reconcile_result(run, action['action_id'], pending['execution_id'], reference, wrong)
            with self.assertRaises(Denied):
                restarted.execute(actor, request_body(run, action))
            reopened.reconcile_result(run, action['action_id'], pending['execution_id'], reference, observed)
            self.assertFalse(restarted.execute(actor, request_body(run, action))['dispatched'])
            self.assertEqual(backend.dispatch_calls, 1)

    def test_08_observation_mismatch_freezes_action(self):
        def mismatch(observe):
            return lambda reference: dict(observe(reference), tags=['tampered'])
        with fresh(observe_wrapper=mismatch) as (_, (service, actor, run, backend)):
            action = approved(service, actor, run)
            for _ in range(2):
                with self.assertRaises(Denied):
                    service.execute(actor, request_body(run, action))
            self.assertEqual(backend.dispatch_calls, 1)
            self.assertTrue(service.store.reconciliation(run, action['action_id'])['execution_id'])

    def test_09_backend_reference_scope_and_traversal(self):
        for reference in ('file:///tmp/x', 'artifact-meta://' + OTHER_SCOPE + '/' + uuid4().hex,
                'artifact-meta://' + SCOPE + '/../escape', 'artifact-meta://' + SCOPE + '/' + uuid4().hex + '?redirect=x'):
            with self.subTest(reference=reference), self.assertRaises(Denied):
                check_reference(SCOPE, reference)

    def test_10_invalid_reference_after_commit_remains_unknown(self):
        def redirected(dispatch):
            def invoke(value):
                dispatch(value)
                return 'artifact-meta://' + OTHER_SCOPE + '/' + value['operation_id']
            return invoke
        with fresh(dispatch_wrapper=redirected) as (_, (service, actor, run, backend)):
            action = approved(service, actor, run)
            for _ in range(2):
                with self.assertRaises(Denied):
                    service.execute(actor, request_body(run, action))
            self.assertEqual(backend.dispatch_calls, 1)

    def test_11_synthetic_actor_binding_and_one_use_native_shape(self):
        with fresh() as (_, (service, actor, run, backend)):
            action = approved(service, actor, run)
            wrong_actors = [VerifiedActor('forged-curator', actor.workload),
                VerifiedActor(actor.user, 'spiffe://' + TRUST_DOMAIN + '/openshell/sandbox/' + str(uuid4())),
                VerifiedActor(actor.user, 'spiffe://foreign.test/openshell/sandbox/' + str(uuid4()))]
            for wrong in wrong_actors:
                with self.subTest(actor=wrong), self.assertRaises(Denied):
                    service.execute(wrong, request_body(run, action))
            with self.assertRaises(sqlite3.IntegrityError):
                service.store.create_run(issuer='https://synthetic-issuer.example.test', user=actor.user,
                    user_role='catalog-curator', workload=actor.workload, workload_role='metadata-worker',
                    project=SCOPE, expires=int(time.time()) + 300, assessment='Attempted workload reuse')
            self.assertEqual(backend.dispatch_calls, 0)

    def test_15_interrupted_dispatch_requires_coordinated_recovery(self):
        def crash(dispatch):
            def invoke(value):
                dispatch(value)
                raise SystemExit('Synthetic host interruption after commit')
            return invoke
        with fresh(dispatch_wrapper=crash) as (directory, (service, actor, run, backend)):
            action = approved(service, actor, run)
            with self.assertRaises(SystemExit):
                service.execute(actor, request_body(run, action))
            reopened = RunStore(Path(directory) / 'runs.db', connector=CONTRACT, trust_domain=TRUST_DOMAIN)
            reopened.recover_dispatched()
            restarted = SecurityService(reopened,
                BackendPort(CONTRACT.fingerprint, backend.dispatch, backend.observe, backend.read))
            with self.assertRaises(Denied):
                restarted.execute(actor, request_body(run, action))
            pending = reopened.reconciliation(run, action['action_id'])
            reference = 'artifact-meta://' + SCOPE + '/' + action['action_id']
            reopened.reconcile_result(run, action['action_id'], pending['execution_id'],
                reference, backend.observe(reference))
            self.assertFalse(restarted.execute(actor, request_body(run, action))['dispatched'])
            self.assertEqual(backend.dispatch_calls, 1)

    def test_16_success_audit_preserves_correlated_action_and_digest(self):
        with fresh() as (_, (service, actor, run, backend)):
            action = approved(service, actor, run)
            result = service.execute(actor, request_body(run, action))
            history = service.store.describe(run, actor.user)
            expected = {'proposed', 'approved', 'claimed', 'succeeded'}
            correlated = [event for event in history['audit'] if event['action_id'] == action['action_id']]
            self.assertEqual({event['event'] for event in correlated}, expected)
            for event in correlated:
                self.assertEqual(event['run_id'], run)
                detail = json.loads(event['detail'])
                if event['event'] in {'proposed', 'approved', 'claimed'}:
                    self.assertEqual(detail['digest'], action['digest'])
                else:
                    self.assertEqual(detail['result_ref'], result['result_ref'])

    def test_17_host_translates_allocation_error_without_retrying_workload(self):
        with fresh() as (directory, (service, actor, run, backend)):
            with self.assertRaisesRegex(HostAllocationError, 'fresh trusted context') as caught:
                synthetic_host(directory, actor=actor)
            self.assertNotIn('UNIQUE', str(caught.exception))
            self.assertEqual(service.store.describe(run, actor.user)['run']['workload'], actor.workload)
            fresh_service, fresh_actor, fresh_run, _ = synthetic_host(directory)
            self.assertNotEqual(fresh_actor.workload, actor.workload)
            self.assertNotEqual(fresh_run, run)
            self.assertEqual(backend.dispatch_calls, 0)

    def test_12_cancellation_prevents_future_dispatch(self):
        with fresh() as (_, (service, actor, run, backend)):
            action = approved(service, actor, run)
            service.store.cancel(run, actor.user)
            with self.assertRaises(Denied):
                service.execute(actor, request_body(run, action))
            self.assertEqual(backend.dispatch_calls, 0)

    def test_13_read_scope_observed_records_and_private_backend_modes(self):
        with fresh() as (directory, (service, actor, run, backend)):
            action = approved(service, actor, run)
            service.execute(actor, request_body(run, action))
            records = service.read(actor, run, SCOPE)
            self.assertTrue(records)
            with self.assertRaises(Denied):
                service.read(actor, run, OTHER_SCOPE)
            self.assertEqual((Path(directory) / 'backend').stat().st_mode & 0o777, 0o700)
            for path in (Path(directory) / 'backend').glob('*.json'):
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_14_changed_metadata_requires_new_exact_consent(self):
        with fresh() as (_, (service, actor, run, backend)):
            first = approved(service, actor, run)
            second = service.propose(actor, run, dict(effects(SCOPE), tags=['changed']))
            self.assertNotEqual(first['action_id'], second['action_id'])
            with self.assertRaises(Denied):
                service.approve(actor, run, second['action_id'], first['digest'], int(time.time()) + 120)
            with self.assertRaises(Denied):
                service.execute(actor, request_body(run, second))
            self.assertEqual(backend.dispatch_calls, 0)


def main():
    if 'PYTHONPATH' in os.environ:
        raise SystemExit('Run without PYTHONPATH')
    if (Path.cwd() / '.git').exists():
        raise SystemExit('Run from outside any repository')
    conformance = verify(CONTRACT, effects, ArtifactCatalog, SCOPE, OTHER_SCOPE)
    print('PUBLIC_CONFORMANCE ' + json.dumps(conformance, sort_keys=True), flush=True)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ArtifactIntegrationTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = {'public_conformance': conformance, 'integration_tests': result.testsRun,
        'integration_failures': len(result.failures), 'integration_errors': len(result.errors),
        'successful': result.wasSuccessful(), 'python': sys.version,
        'executable': sys.executable, 'runtime_namespace_file': runtime.__file__,
        'distribution_version': importlib.metadata.version('agent-security-runtime'),
        'cwd': str(Path.cwd()), 'pythonpath_present': 'PYTHONPATH' in os.environ,
        'synthetic_identity': True, 'real_authentication_or_network_isolation_proven': False}
    (Path(__file__).resolve().parent / 'acceptance-results.json').write_text(json.dumps(report, indent=2) + '\n')
    print('ACCEPTANCE_RESULT ' + json.dumps(report, sort_keys=True), flush=True)
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
