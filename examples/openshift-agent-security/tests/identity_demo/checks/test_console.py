# SPDX-License-Identifier: Apache-2.0
"""Console behavior, custody and coordination boundaries; live proof is separate."""

from dataclasses import replace
import json
from pathlib import Path
import time
from uuid import uuid4

import pytest
from starlette.testclient import TestClient

from checks.test_driver import setup
from identity_demo_console_store import safe_evidence
from identity_demo_driver import COOKIE, Driver
from identity_demo_run_store import Denied
from identity_demo_console_worker import AttachedFlow


def configured(tmp_path: Path) -> tuple:
    previous, _, _, _ = setup(tmp_path)
    context = dict(previous.config.contexts[0])
    context['sandbox_id'] = str(uuid4())
    context['console_prepared'] = True
    context['workload'] = 'spiffe://agents.example.test/openshell/sandbox/' + context['sandbox_id']
    driver = Driver(replace(previous.config, contexts=(context,), coordinator_enabled=True), previous.verify)
    driver.sessions = previous.sessions
    driver.sessions['opaque']['claims']['exp'] = int(time.time()) + 600
    client = TestClient(driver.app, base_url=driver.config.origin)
    client.cookies.set(COOKIE, 'opaque')
    return driver, client, context


def operator(driver: Driver) -> dict:
    return {'Authorization': 'Bearer ' + driver.config.operator_secret}


def submit(driver: Driver, client: TestClient) -> object:
    return client.post('/submit', headers={'Origin': driver.config.origin},
        data={'csrf': 'csrf-fixture', 'role': 'triage', 'cve': 'CVE-2099-0001'}, follow_redirects=False)


def claim(driver: Driver, client: TestClient) -> tuple:
    worker = uuid4().hex
    assert client.post('/internal/operator/console/heartbeat', headers=operator(driver), json={'worker': worker}).status_code == 200
    response = submit(driver, client)
    assert response.status_code == 303
    job = client.post('/internal/operator/console/next', headers=operator(driver), json={'worker': worker}).json()['job']
    return worker, job


def test_console_renders_reference_sections_and_preserves_browser_security(tmp_path: Path) -> None:
    driver, client, run, _ = setup(tmp_path)
    page = client.get('/runs/' + run)
    for value in ['Agent Security Console', 'Security context', 'Sandbox &amp; identity', 'View tools &amp; routing',
                  'Decision and outcome audit', 'Runtime verification pending', 'Frozen synthetic assessment']:
        assert value in page.text
    assert 'unsafe-eval' not in page.headers['content-security-policy']
    assert "default-src 'none'" in page.headers['content-security-policy']
    assert page.headers['cache-control'] == 'no-store'
    assert 'refresh' not in page.headers
    assert '/assets/console.js' in page.text
    assert 'backend credentials' not in page.text.lower() or 'outside' in page.text.lower()
    assert driver.config.operator_secret not in page.text
    assert driver.sessions['opaque']['token'] not in page.text


def test_proposal_waits_without_refresh_and_escapes_model_output(tmp_path: Path) -> None:
    driver, client, run, _ = setup(tmp_path)
    driver.store.propose(run, 'user-a', {'project': 'TEST', 'summary': '<script>steal()</script>', 'description': 'Synthetic <img onerror=steal()>'})
    page = client.get('/runs/' + run)
    assert 'refresh' not in page.headers
    assert 'Approve this exact proposal' in page.text
    assert '<script>steal' not in page.text and '&lt;script&gt;' in page.text
    assert 'No issue created' in page.text


@pytest.mark.parametrize('key,expected', [('TEST-12', True), ('SERVICE-7', True),
                                         ('TEST-1?redirect=evil', False), ('OTHER-1', False)])
def test_jira_button_requires_success_and_a_safe_preview_key(tmp_path: Path, key: str, expected: bool) -> None:
    driver, client, run, _ = setup(tmp_path)
    proposal = driver.store.propose(run, 'user-a', {'project': 'TEST', 'summary': 'Summary', 'description': 'Synthetic'})
    assert 'Access Jira' not in client.get('/runs/' + run).text
    with driver.store.transaction() as db:
        db.execute("UPDATE actions SET state='succeeded',issue_key=? WHERE id=?", (key, proposal['action_id']))
    page = client.get('/runs/' + run)
    assert ('Access Jira' in page.text) is expected
    if expected:
        assert ('href="http://127.0.0.1:18088/issue/' + key + '" target="_blank" rel="noopener noreferrer"') in page.text
    with driver.store.transaction() as db:
        db.execute("UPDATE actions SET state='unknown' WHERE id=?", (proposal['action_id'],))
    assert 'Access Jira' not in client.get('/runs/' + run).text


def test_offline_coordinator_consumes_no_identity(tmp_path: Path) -> None:
    driver, client, context = configured(tmp_path)
    response = submit(driver, client)
    assert response.status_code == 409 and response.json()['reason'] == 'coordinator_offline'
    with driver.store.transaction() as db:
        assert db.execute('SELECT count(*) FROM runs WHERE workload=?', (context['workload'],)).fetchone()[0] == 0


def test_consumed_workflows_remain_visible_and_report_fresh_context_needed(tmp_path: Path) -> None:
    """Exhausted one-use identities must not make a configured workflow disappear."""
    driver, client, triage = configured(tmp_path)
    reader = {**triage, 'role': 'reader', 'sandbox_id': str(uuid4()),
              'workload': 'spiffe://agents.example.test/openshell/sandbox/' + str(uuid4())}
    service = {**triage, 'project': 'SERVICE', 'workflow': 'service-request',
               'sandbox_id': str(uuid4()),
               'workload': 'spiffe://agents.example.test/openshell/sandbox/' + str(uuid4())}
    driver.config = replace(driver.config, contexts=(triage, reader, service), coordinator_enabled=True)
    claims = driver.sessions['opaque']['claims']
    driver.register_run(claims, triage)
    driver.register_run(claims, service)
    worker = uuid4().hex
    driver.console.heartbeat(worker)

    page = client.get('/')
    assert 'CVE triage' in page.text and 'Remediation change request' in page.text
    assert 'Approved chat model' in page.text
    assert 'Triage — assessment and controlled create · fresh context needed' in page.text
    assert 'A fresh context is needed. Ask the demo operator.' in page.text
    assert 'Start remediation request</button>' in page.text
    assert 'Start remediation request</button>' in page.text and 'disabled' in page.text
    live = client.get('/console/live').json()
    assert live['cve_roles'] == ['reader']
    assert live['service_available'] is False


def test_job_requires_operator_and_exact_claim_owner(tmp_path: Path) -> None:
    driver, client, _ = configured(tmp_path)
    worker, job = claim(driver, client)
    for secret in ['', driver.config.gateway_secret, driver.config.adapter_secret]:
        response = client.post('/internal/operator/console/update', headers={'Authorization': 'Bearer ' + secret},
            json={'worker': worker, 'run_id': job['run_id'], 'stage': 'identity_verified', 'evidence': {}})
        assert response.status_code == 403
    with pytest.raises(Denied, match='console_claim'):
        driver.console.update(job['run_id'], uuid4().hex, 'completed', {})
    assert client.post('/internal/operator/console/next', headers=operator(driver), json={'worker': worker}).json()['job'] is None


def test_only_one_live_job_and_one_coordinator(tmp_path: Path) -> None:
    driver, client, _ = configured(tmp_path)
    worker, job = claim(driver, client)
    assert submit(driver, client).json()['reason'] == 'console_busy'
    other = client.post('/internal/operator/console/heartbeat', headers=operator(driver), json={'worker': uuid4().hex})
    assert other.status_code == 403
    driver.console.update(job['run_id'], worker, 'completed', {})
    assert not driver.console.available(True)['busy']


@pytest.mark.parametrize('evidence', [
    {'token': 'private'}, {'certificate': 'private'}, {'model': 'other'}, {'native_bound_read': 'true'},
    {'backend_after': True}, {'backend_after': -1}, {'tool_names': ['https://untrusted']}, {'verified_issue_key': '../secret'}, []])
def test_arbitrary_private_or_invalid_evidence_rejected(evidence: object) -> None:
    with pytest.raises(Denied):
        safe_evidence(evidence)


def test_observed_evidence_is_owner_scoped_and_audited(tmp_path: Path) -> None:
    driver, client, _ = configured(tmp_path)
    worker, job = claim(driver, client)
    response = client.post('/internal/operator/console/update', headers=operator(driver), json={
        'worker': worker, 'run_id': job['run_id'], 'stage': 'identity_verified',
        'evidence': {'native_bound_read': True, 'gateway_ready': True, 'tool_names': ['createJiraIssue']}})
    assert response.status_code == 200
    page = client.get('/runs/' + job['run_id'])
    assert 'Verified native certificate-bound read' in page.text and 'createJiraIssue' in page.text
    assert worker not in page.text
    client.cookies.clear()
    assert client.get('/runs/' + job['run_id']).status_code == 403
    assert client.get('/runs').status_code == 403


def test_cancelled_queued_run_is_never_dispatched(tmp_path: Path) -> None:
    driver, client, _ = configured(tmp_path)
    worker = uuid4().hex
    driver.console.heartbeat(worker)
    response = submit(driver, client)
    run = response.headers['location'].split('/')[-1]
    client.post('/runs/' + run + '/cancel', headers={'Origin': driver.config.origin}, data={'csrf': 'csrf-fixture'})
    assert driver.console.claim(worker) is None
    assert driver.console.describe(run)['stage'] == 'cancelled'


def test_expired_job_and_unknown_write_never_start_new_work(tmp_path: Path, monkeypatch: object) -> None:
    driver, client, _ = configured(tmp_path)
    worker, job = claim(driver, client)
    with driver.store.transaction() as db:
        db.execute('UPDATE runs SET expires=? WHERE id=?', (int(time.time()) - 1, job['run_id']))
    page = client.get('/runs/' + job['run_id'])
    assert 'Run expired' in page.text and 'Approve this exact proposal' not in page.text
    assert 'refresh' not in page.headers
    assert driver.console.claim(worker) is None  # running is never automatically reclaimed


def test_history_does_not_leak_other_users_or_change_permissions(tmp_path: Path) -> None:
    driver, client, run, _ = setup(tmp_path)
    assert run[:12] in client.get('/runs').text
    driver.sessions['opaque']['claims']['sub'] = 'another-user'
    assert run[:12] not in client.get('/runs').text
    assert client.get('/runs/' + run).status_code == 403
    for path in ['/evidence', '/settings']:
        page = client.get(path)
        assert page.status_code == 200
        assert driver.config.operator_secret not in page.text


def test_sign_out_requires_csrf_and_does_not_impersonate_another_user(tmp_path: Path) -> None:
    driver, client, _, _ = setup(tmp_path)
    assert client.post('/logout', data={'csrf': 'csrf-fixture'}).status_code == 403
    response = client.post('/logout', headers={'Origin': driver.config.origin},
        data={'csrf': 'csrf-fixture'}, follow_redirects=False)
    assert response.status_code == 303 and not driver.sessions
    assert client.get('/').status_code == 200 and 'Sign in' in client.get('/').text


def test_worker_waits_for_actual_approval_and_rejects_tampering() -> None:
    proposal = {'action_id': 'a', 'digest': 'd', 'arguments': {'summary': 'Synthetic'}}
    flow = object.__new__(AttachedFlow)
    flow.run_id, flow.user, flow.proposal = 'run', 'user', proposal
    from types import SimpleNamespace
    import threading
    calls = []
    record = {'run': {'active': True, 'expires': int(time.time()) + 30}, 'actions': [
        {'id': 'a', 'digest': 'd', 'payload': json.dumps(proposal['arguments']),
         'state': 'approved', 'approver': 'user', 'approval_expires': int(time.time()) + 20}]}
    flow.control = SimpleNamespace(update=lambda *a: calls.append(a), request=lambda _: record,
        lost=threading.Event(), stopping=threading.Event())
    flow.approve_proposal({})
    assert calls[0][1] == 'awaiting_approval'
    record['actions'][0]['digest'] = 'changed'
    with pytest.raises(ValueError, match='binding'):
        flow.approve_proposal({})


def test_worker_cannot_approve_cancelled_run() -> None:
    from types import SimpleNamespace
    import threading
    flow = object.__new__(AttachedFlow)
    flow.run_id = 'run'
    flow.control = SimpleNamespace(update=lambda *a: None,
        request=lambda _: {'run': {'active': False, 'expires': int(time.time()) + 30}},
        lost=threading.Event(), stopping=threading.Event())
    with pytest.raises(RuntimeError, match='cancelled'):
        flow.approve_proposal({})


def test_fixed_login_audience_does_not_depend_on_temporary_client() -> None:
    from identity_demo_execution_setup import console_audience_mapper
    audience = 'spiffe://agents.example.test/openshell/gateway/fixture-example'
    client = {'clientId': 'identity-demo-driver', 'publicClient': True, 'standardFlowEnabled': True,
        'attributes': {'identity-demo-owner': 'owner', 'pkce.code.challenge.method': 'S256'},
        'protocolMappers': [{'id': 'mapper', 'name': 'next-recipient', 'protocolMapper': 'oidc-audience-mapper',
            'config': {'included.client.audience': audience, 'access.token.claim': 'true', 'id.token.claim': 'false'}}]}
    before = json.loads(json.dumps(client))
    mapper = console_audience_mapper(client, 'owner', audience)
    assert client == before
    assert mapper['config']['included.custom.audience'] == audience
    assert 'included.client.audience' not in mapper['config']
    client['protocolMappers'] = [mapper]
    assert console_audience_mapper(client, 'owner', audience) == mapper
    with pytest.raises(ValueError):
        console_audience_mapper(client, 'another-owner', audience)
    with pytest.raises(ValueError):
        console_audience_mapper(client, 'owner', 'spiffe://untrusted/gateway')
    client['attributes']['pkce.code.challenge.method'] = 'plain'
    with pytest.raises(ValueError):
        console_audience_mapper(client, 'owner', audience)


def test_historical_unprepared_context_is_never_consumed_by_console(tmp_path: Path) -> None:
    driver, _, prepared = configured(tmp_path)
    legacy = {**prepared, 'sandbox_id': str(uuid4()), 'console_prepared': False}
    legacy['workload'] = 'spiffe://agents.example.test/openshell/sandbox/' + legacy['sandbox_id']
    replacement = Driver(replace(driver.config, contexts=(legacy, prepared)), driver.verify)
    replacement.sessions = driver.sessions
    client = TestClient(replacement.app, base_url=replacement.config.origin)
    client.cookies.set(COOKIE, 'opaque')
    replacement.console.heartbeat(uuid4().hex)
    response = submit(replacement, client)
    assert response.status_code == 303
    run = response.headers['location'].rsplit('/', 1)[-1]
    assert replacement.store.describe(run, 'user-a')['run']['workload'] == prepared['workload']


def test_legacy_presentation_parameter_keeps_navigation_and_identity(tmp_path: Path) -> None:
    driver, client, run, _ = setup(tmp_path)
    page = client.get('/?present=1')
    assert 'Presentation mode' not in page.text and 'Main navigation' in page.text
    for route in ['/runs/' + run, '/runs', '/evidence', '/settings']:
        page = client.get(route)
        assert 'Presentation mode' not in page.text and 'Main navigation' in page.text and 'Sign out' in page.text
    assert driver.sessions['opaque']['claims']['sub'] == 'user-a'
    assert 'class="presentation"' not in client.get('/?present=0').text


def test_terminal_action_waits_for_coordinator_verification_refresh(tmp_path: Path) -> None:
    driver, client, _ = configured(tmp_path)
    worker, job = claim(driver, client)
    proposal = driver.store.propose(job['run_id'], 'user-a', {'project': 'TEST', 'summary': 'Summary', 'description': 'Synthetic'})
    with driver.store.transaction() as db:
        db.execute("UPDATE actions SET state='succeeded',issue_key='TEST-1' WHERE id=?", (proposal['action_id'],))
        db.execute('UPDATE runs SET active=0 WHERE id=?', (job['run_id'],))
    page = client.get('/runs/' + job['run_id'])
    assert 'refresh' not in page.headers
    assert client.get('/runs/' + job['run_id'] + '/live').json()['poll'] is True
    assert 'Independent backend field verification has not yet been reported.' in page.text
    driver.console.update(job['run_id'], worker, 'completed', {'backend_fields_match_approval': True})
    page = client.get('/runs/' + job['run_id'])
    assert 'refresh' not in page.headers
    assert 'Independent backend field verification passed.' in page.text
    assert client.get('/runs/' + job['run_id'] + '/live').json()['poll'] is False


def test_console_update_refuses_active_run_before_any_cluster_mutation(tmp_path: Path, monkeypatch: object) -> None:
    import identity_demo_execution_setup as execution
    from types import SimpleNamespace
    monkeypatch.setattr(execution, 'guard', lambda _: None)
    monkeypatch.setattr(execution, 'inspect_state', lambda _: {'rollback_quiescent': False})
    with pytest.raises(ValueError, match='no active runs'):
        execution.register_driver(SimpleNamespace(action='update-console', context_file=[]))


def test_sanitized_mcp_schema_preserves_shape_without_secret_values() -> None:
    value = {'tool_schemas': [{'name': 'createJiraIssue', 'arguments': [
        {'name': 'project', 'type': 'string', 'required': True}]}],
        'gateway_backend_services': ['fixture-protected-adapter'], 'live_run_identity_check': True}
    assert safe_evidence(value) == value
    value['tool_schemas'][0]['arguments'][0]['credential'] = 'private'
    with pytest.raises(Denied):
        safe_evidence(value)


def test_historical_probe_denial_does_not_replace_verified_success(tmp_path: Path) -> None:
    driver, client, run, _ = setup(tmp_path)
    proposal = driver.store.propose(run, 'user-a', {'project': 'TEST', 'summary': 'Summary', 'description': 'Synthetic'})
    with driver.store.transaction() as db:
        db.execute("UPDATE actions SET state='succeeded',issue_key='TEST-1' WHERE id=?", (proposal['action_id'],))
        driver.store.event(db, run, proposal['action_id'], 'denied', {'reason': 'action_binding'})
    page = client.get('/runs/' + run)
    assert 'Protected action succeeded' in page.text
    assert '<strong>Protected action denied:' not in page.text


def test_credentials_use_the_session_that_created_this_run(tmp_path: Path) -> None:
    """An older same-user login must not shorten the new native grant's lifetime."""
    driver, client, _ = configured(tmp_path)
    driver.sessions['old-login'] = driver.sessions.pop('opaque')
    old = driver.sessions['old-login']
    driver.sessions['opaque'] = {**old, 'claims': {**old['claims'], 'exp': old['claims']['exp'] + 300},
                                 'token': 'fresh-human', 'runs': set()}
    _, job = claim(driver, client)
    response = client.get('/internal/operator/credentials/' + job['run_id'], headers=operator(driver))
    assert response.status_code == 200
    assert response.json()['access_token'] == 'fresh-human'
    assert response.json()['expires_at'] == driver.sessions['opaque']['claims']['exp']
    driver.sessions.pop('opaque')
    response = client.get('/internal/operator/credentials/' + job['run_id'], headers=operator(driver))
    assert response.status_code == 403  # never fall back to another same-user session


def test_overview_is_owner_scoped_with_consistent_navigation(tmp_path: Path) -> None:
    """Overview reports actual retained activity without pretending to scan the cluster."""
    driver, client, run, _ = setup(tmp_path)
    page = client.get('/?view=overview&present=1')
    assert 'Workspace overview' in page.text and run[:12] in page.text
    assert 'Coordinator offline' in page.text and 'Your active runs' in page.text
    assert 'Main navigation' in client.get('/runs').text
    driver.sessions['opaque']['claims']['sub'] = 'another-owner'
    assert run[:12] not in client.get('/?view=overview').text


def test_html_offline_response_preserves_conflict_status(tmp_path: Path) -> None:
    """A browser receives an explanatory error and no new execution identity."""
    driver, client, context = configured(tmp_path)
    response = client.post('/submit', headers={'Origin': driver.config.origin, 'Accept': 'text/html'},
        data={'csrf': 'csrf-fixture', 'role': 'triage', 'cve': 'CVE-2099-0001'})
    assert response.status_code == 409 and 'Workflow not started' in response.text
    assert not driver.console.available(True)['busy']


@pytest.mark.parametrize('state,quiescent', [('queued', False), ('running', False), ('completed', True)])
def test_rollout_waits_for_console_cleanup_even_after_run_is_closed(tmp_path: Path, monkeypatch: object, state: str, quiescent: bool) -> None:
    """A closed security run does not mean its coordinator has finished restoring services."""
    import os
    import sys
    from types import SimpleNamespace
    import identity_demo_execution_setup as execution
    driver, _, run, _ = setup(tmp_path)
    worker = uuid4().hex
    driver.console.heartbeat(worker)
    driver.console.enqueue(run, 'cve')
    if state != 'queued':
        driver.console.claim(worker)
    if state == 'completed':
        driver.console.update(run, worker, 'completed', {})
    with driver.store.transaction() as db:
        db.execute('UPDATE runs SET active=0')
    monkeypatch.setattr(execution, 'guard', lambda _: None)
    from identity_demo_lab import LABELS
    monkeypatch.setattr(execution, 'read', lambda *a: {'metadata': {'labels': dict(LABELS)}})
    original = execution.subprocess.run
    def local_inventory(words: list, **kwargs: object) -> object:
        return original([sys.executable, '-c', words[-1]], env={**os.environ, 'DRIVER_DATABASE': str(driver.config.database)}, **kwargs)
    monkeypatch.setattr(execution.subprocess, 'run', local_inventory)
    result = execution.inspect_state(SimpleNamespace(kubeconfig='synthetic'))
    assert result['active_runs'] == 0
    assert result['active_console_jobs'] == int(not quiescent)
    assert result['rollback_quiescent'] is quiescent


def test_history_preserves_success_after_access_expires(tmp_path: Path) -> None:
    """Credential expiry must not replace a verified business outcome in the run list."""
    driver, client, run, _ = setup(tmp_path)
    proposal = driver.store.propose(run, 'user-a', {'project': 'TEST', 'summary': 'Summary', 'description': 'Synthetic'})
    with driver.store.transaction() as db:
        db.execute("UPDATE actions SET state='succeeded',issue_key='TEST-1' WHERE id=?", (proposal['action_id'],))
        db.execute('UPDATE runs SET active=0,expires=? WHERE id=?', (int(time.time()) - 1, run))
        driver.store.event(db, run, proposal['action_id'], 'denied', {'reason': 'action_binding'})
    page = client.get('/runs')
    assert 'Succeeded' in page.text and 'Expired' in page.text
    assert '<th>Outcome</th><th>Access</th>' in page.text


def test_anonymous_login_has_one_unambiguous_entry_point(tmp_path: Path) -> None:
    """Keep the existing real-browser sign-in selector usable on the new shell."""
    _, client, _, _ = setup(tmp_path)
    client.cookies.clear()
    assert client.get('/').text.count('>Sign in</a>') == 1



def test_live_fragment_owner_scope_stability_and_local_script_policy(tmp_path: Path) -> None:
    """Polling returns only the authenticated owner's escaped, stable recorded state."""
    driver, client, _ = configured(tmp_path)
    _, job = claim(driver, client)
    path = '/runs/' + job['run_id'] + '/live'
    first, second = client.get(path), client.get(path)
    assert first.status_code == 200 and first.json()['revision'] == second.json()['revision']
    assert first.headers['cache-control'] == 'no-store'
    assert client.get(path, headers={'If-None-Match':first.headers['etag']}).status_code == 304
    assert 'Agent activity' in first.json()['html'] and 'Next:' in first.json()['html']
    for secret in (driver.config.operator_secret, driver.sessions['opaque']['token']):
        assert secret not in first.text
    page = client.get('/runs/' + job['run_id'])
    assert "script-src 'self'" in page.headers['content-security-policy']
    assert "connect-src 'self'" in page.headers['content-security-policy']
    assert client.get('/assets/console.js').headers['content-type'].startswith('application/javascript')
    driver.sessions['opaque']['claims']['sub'] = 'another-owner'
    assert client.get(path, headers={'If-None-Match':first.headers['etag']}).status_code == 403
    client.cookies.clear()
    assert client.get('/console/live').status_code == 403


def test_stale_signin_is_rejected_before_identity_allocation(tmp_path: Path) -> None:
    """An almost-expired but still-valid login cannot consume a prepared sandbox."""
    driver, client, context = configured(tmp_path)
    driver.console.heartbeat(uuid4().hex)
    driver.sessions['opaque']['claims']['exp'] = int(time.time()) + 180
    assert submit(driver, client).json()['reason'] == 'fresh_login_required'
    assert client.get('/console/live').json()['can_start'] is False
    assert 'Fresh sign-in required' in client.get('/').text
    with driver.store.transaction() as db:
        assert db.execute('SELECT count(*) FROM runs WHERE workload=?', (context['workload'],)).fetchone()[0] == 0


def test_alive_but_blocked_worker_cannot_claim_or_enable_start(tmp_path: Path) -> None:
    """Liveness must not advertise readiness when recovery or renewal is required."""
    driver, client, _ = configured(tmp_path)
    worker = uuid4().hex
    driver.console.heartbeat(worker, phase='blocked', reason='recovery_required')
    status = driver.console.available(True)
    assert status['online'] and not status['ready']
    assert client.get('/console/live').json()['can_start'] is False
    assert submit(driver, client).json()['reason'] == 'coordinator_not_ready'
    assert driver.console.claim(worker) is None
    assert 'Operator review required' in client.get('/').text


def test_catalog_deadline_prevents_stale_ready_state(tmp_path: Path) -> None:
    """A previous ready heartbeat cannot outlive its discovery credential window."""
    driver, client, _ = configured(tmp_path)
    driver.console.heartbeat(uuid4().hex, catalog_expires=int(time.time())+550)
    status = driver.console.available(True)
    assert status['online'] and not status['ready'] and status['reason'] == 'catalog_expiring'
    assert not client.get('/console/live').json()['can_start']


def test_clean_failure_allows_next_fresh_job_without_replaying_old_one(tmp_path: Path) -> None:
    """A terminal failed job releases single-flight only after explicit closure."""
    driver, client, context = configured(tmp_path)
    worker, first = claim(driver, client)
    driver.store.revoke('run_id', first['run_id'])
    driver.console.update(first['run_id'], worker, 'execution_failed', {'cleanup_verified': True, 'failure_code':'preparation_failed'})
    second = {**context, 'sandbox_id':str(uuid4())}
    second['workload'] = 'spiffe://agents.example.test/openshell/sandbox/'+second['sandbox_id']
    driver.config = replace(driver.config, contexts=(*driver.config.contexts, second))
    assert submit(driver, client).status_code == 303
    job = driver.console.claim(worker)
    assert job['run_id'] != first['run_id']
    assert driver.console.describe(first['run_id'])['state'] == 'failed'


def test_expired_queue_closes_atomically_without_execution(tmp_path: Path) -> None:
    """Settling an expired queue preserves history and does not keep rollback stuck."""
    driver, client, _ = configured(tmp_path)
    worker = uuid4().hex
    driver.console.heartbeat(worker)
    run = submit(driver, client).headers['location'].split('/')[-1]
    with driver.store.transaction() as db:
        db.execute('UPDATE runs SET expires=? WHERE id=?',(int(time.time())-1,run))
    assert driver.console.claim(worker) is None
    assert driver.console.describe(run)['stage'] == 'expired'
    with driver.store.transaction() as db:
        assert db.execute('SELECT active FROM runs WHERE id=?',(run,)).fetchone()[0] == 0
        assert db.execute('SELECT count(*) FROM actions WHERE run_id=?',(run,)).fetchone()[0] == 0



def test_recovery_block_survives_worker_replacement_and_requires_operator_review(tmp_path: Path) -> None:
    """A fresh heartbeat cannot erase incomplete cleanup or an unknown write."""
    driver, client, _ = configured(tmp_path)
    worker, job = claim(driver, client)
    driver.store.revoke('run_id',job['run_id'])
    driver.console.update(job['run_id'],worker,'execution_failed',{'cleanup_verified':False,'failure_code':'recovery_required'})
    with driver.store.transaction() as db:
        db.execute('UPDATE console_worker SET updated=0')
    replacement = uuid4().hex
    driver.console.heartbeat(replacement)
    assert driver.console.available(True)['recovery_required']
    assert not driver.console.available(True)['ready']
    assert driver.console.claim(replacement) is None
    endpoint='/internal/operator/console/review-recovery'
    review={'run_id':job['run_id'],'receipt_sha256':'a'*64}
    assert client.post(endpoint,json=review).status_code==403
    assert client.post(endpoint,headers=operator(driver),json={**review,'receipt_sha256':'private path'}).status_code==403
    assert client.post(endpoint,headers=operator(driver),json=review).status_code==200
    assert not driver.console.available(True)['recovery_required']
    assert 'safely closed' in client.get('/runs/'+job['run_id']).text
    assert driver.console.describe(job['run_id'])['state']=='failed'
    assert any(e['event']=='console_recovery_reviewed' for e in driver.store.describe(job['run_id'],'user-a')['audit'])



@pytest.mark.parametrize('state',['executing','unknown'])
def test_operator_review_cannot_clear_unreconciled_write(tmp_path: Path,state: str) -> None:
    """A receipt cannot override backend outcome reconciliation."""
    driver,client,_=configured(tmp_path)
    worker,job=claim(driver,client)
    action=driver.store.propose(job['run_id'],'user-a',{'project':'TEST','summary':'Synthetic','description':'Synthetic'})
    with driver.store.transaction() as db:
        db.execute('UPDATE actions SET state=? WHERE id=?',(state,action['action_id']))
    driver.store.revoke('run_id',job['run_id'])
    driver.console.update(job['run_id'],worker,'execution_failed',{'cleanup_verified':False,'failure_code':'recovery_required'})
    response=client.post('/internal/operator/console/review-recovery',headers=operator(driver),json={'run_id':job['run_id'],'receipt_sha256':'a'*64})
    assert response.status_code==403
    assert driver.console.available(True)['recovery_required']


def test_overview_uses_live_consistent_readiness_label(tmp_path: Path) -> None:
    """A heartbeat and a page label cannot disagree about a blocked coordinator."""
    driver,client,_=configured(tmp_path)
    driver.console.heartbeat(uuid4().hex,phase='blocked',reason='recovery_required')
    page=client.get('/?view=overview')
    assert 'data-readiness-status>Operator review required' in page.text
    assert 'Coordinator online' not in page.text
    assert '<h2>Recent runs</h2>' in page.text
    assert client.get('/console/live').json()['coordinator_label']=='Operator review required'



def test_browser_denial_explains_recovery_without_binding_internals(tmp_path: Path) -> None:
    """The browser gets useful recovery text while API callers retain fixed reason codes."""
    driver,client,run,_=setup(tmp_path)
    driver.sessions['opaque']['claims']['sub']='another-owner'
    page=client.get('/runs/'+run,headers={'Accept':'text/html'})
    assert page.status_code==403 and 'not available to the current account' in page.text
    assert 'run binding' not in page.text
    assert client.get('/runs/'+run).json()['reason']=='run_binding'



def test_recorded_approval_does_not_ask_for_consent_again(tmp_path: Path) -> None:
    """Persisted consent wins immediately while the coordinator acknowledges the next stage."""
    driver,client,_=configured(tmp_path)
    worker,job=claim(driver,client)
    action=driver.store.propose(job['run_id'],'user-a',{'project':'TEST','summary':'Synthetic','description':'Synthetic'})
    driver.console.update(job['run_id'],worker,'awaiting_approval',{})
    driver.store.approve(job['run_id'],action['action_id'],'user-a',action['digest'],int(time.time())+120)
    html=client.get('/runs/'+job['run_id']).text
    assert '<h2>Approval recorded</h2>' in html
    assert '<h2>Your approval is needed</h2>' not in html
    assert '>Approve this exact proposal</button>' not in html



def test_queued_and_cluster_waits_are_not_reported_as_active_processing(tmp_path: Path) -> None:
    """Visible status must distinguish recorded, claimed and dependency-waiting work."""
    driver,client,_=configured(tmp_path)
    worker=uuid4().hex
    driver.console.heartbeat(worker)
    rid=submit(driver,client).headers['location'].split('/')[-1]
    assert '<h2>Queued for coordinator</h2>' in client.get('/runs/'+rid).text
    driver.console.claim(worker)
    assert '<h2>Checking the run</h2>' in client.get('/runs/'+rid).text
    driver.console.update(rid,worker,'waiting_gateway',{})
    html=client.get('/runs/'+rid).text
    assert 'Waiting on cluster' in html and '<span class="step-state">Waiting</span>' in html


def test_agent_failure_is_terminal_and_never_keeps_the_execution_lane(tmp_path: Path) -> None:
    driver, client, _ = configured(tmp_path)
    worker, job = claim(driver, client)
    driver.store.revoke('run_id', job['run_id'])
    driver.console.update(job['run_id'], worker, 'agent_failed', {
        'failure_code':'agent_failed','agent_error_category':'retry_limit','cleanup_verified':True})
    assert driver.console.describe(job['run_id'])['state'] == 'failed'
    assert driver.console.available(True)['busy'] is False
    page = client.get('/runs/'+job['run_id'])
    assert 'Agent could not finish' in page.text and 'retry limit' in page.text


def test_agent_observations_cannot_change_the_run_project(tmp_path: Path) -> None:
    driver, client, _ = configured(tmp_path)
    worker, job = claim(driver, client)
    for evidence in ({'jira_project':'OTHER'},{'agent_query':'project = OTHER'},
                     {'jira_issues':[{'key':'OTHER-1','summary':'Foreign','status':'Open'}]}):
        with pytest.raises(Denied,match='project_permission'):
            driver.console.update(job['run_id'], worker, 'agent_read_complete', evidence)


def test_incident_workflow_uses_a_trusted_ops_context_and_cannot_select_another_project(tmp_path: Path) -> None:
    """The new scenario reuses consent and identity; form text cannot grant a project."""
    driver, client, context = configured(tmp_path)
    incident = {**context, 'workflow': 'incident-triage', 'project': 'OPS'}
    driver.config = replace(driver.config, contexts=(incident,))
    worker = uuid4().hex
    driver.console.heartbeat(worker)
    page = client.get('/')
    assert 'Incident triage' in page.text and 'Authorized project: OPS' in page.text
    data = {'csrf': 'csrf-fixture', 'role': 'triage', 'request': 'OPS-0001'}
    denied = client.post('/submit', headers={'Origin': driver.config.origin}, data={**data, 'project': 'OTHER'})
    assert denied.status_code == 403 and denied.json()['reason'] == 'unapproved_source'
    response = client.post('/submit', headers={'Origin': driver.config.origin}, data=data, follow_redirects=False)
    assert response.status_code == 303
    job = client.post('/internal/operator/console/next', headers=operator(driver), json={'worker': worker}).json()['job']
    assert job['workflow'] == 'incident-triage' and job['context']['project'] == 'OPS'
    assert driver.store.describe(job['run_id'], job['user'])['actions'] == []


def test_jira_preview_restores_only_independently_verified_created_issues(tmp_path: Path) -> None:
    """A successful write alone cannot populate the operator observer's allowlist."""
    driver, client, _ = configured(tmp_path)
    worker, job = claim(driver, client)
    run = job['run_id']
    action = driver.store.propose(run, job['user'], {'project': 'TEST', 'summary': 'Synthetic', 'description': 'Training'})
    with driver.store.transaction() as db:
        db.execute("UPDATE actions SET state='succeeded',issue_key='TEST-8' WHERE id=?", (action['action_id'],))
    assert driver.console.verified_issue_keys() == []
    assert 'Access Jira' not in client.get('/runs/' + run).text
    driver.console.update(run, worker, 'outcome_verified', {'verified_issue_key': 'TEST-8', 'backend_fields_match_approval': True, 'jira_preview_ready': True})
    assert driver.console.verified_issue_keys() == ['TEST-8']
    assert 'Access Jira' in client.get('/runs/' + run).text
    state = client.get('/internal/operator/console/state', headers=operator(driver)).json()
    assert state['verified_issue_keys'] == ['TEST-8']
    assert client.get('/internal/operator/console/state').status_code == 403


def test_start_reserves_time_for_native_preparation_and_human_review(tmp_path: Path) -> None:
    """A seven-minute login can read history but must not consume a fresh identity."""
    driver, client, context = configured(tmp_path)
    worker = uuid4().hex
    driver.console.heartbeat(worker)
    driver.sessions['opaque']['claims']['exp'] = int(time.time()) + 420
    response = submit(driver, client)
    assert response.status_code == 409 and response.json()['reason'] == 'fresh_login_required'
    with driver.store.transaction() as db:
        assert db.execute('SELECT count(*) FROM runs WHERE workload=?', (context['workload'],)).fetchone()[0] == 0
    assert client.get('/runs').status_code == 200


def test_read_probe_denial_does_not_replace_pending_create_review(tmp_path: Path) -> None:
    """An independent read denial stays in the audit, not the create outcome."""
    driver, client, run, _ = setup(tmp_path)
    with driver.store.transaction() as db:
        driver.store.event(db, run, None, 'denied', {'reason': 'project_permission'})
    proposal = driver.store.propose(run, 'user-a', {'project': 'TEST', 'summary': 'Summary', 'description': 'Synthetic'})
    page = client.get('/runs/' + run)
    assert 'Awaiting your approval' in page.text
    assert 'Protected action denied:' not in page.text
    with driver.store.transaction() as db:
        driver.store.event(db, run, proposal['action_id'], 'denied', {'reason': 'user_permission'})
    page = client.get('/runs/' + run)
    assert 'Protected action denied: user permission' in page.text


@pytest.mark.parametrize('cleanup_verified', [True, False])
def test_rejection_copy_keeps_uncertain_cleanup_warning(tmp_path: Path, cleanup_verified: bool) -> None:
    """A deliberate rejection is distinct from failure; unsafe cleanup stays visible."""
    driver, client, _ = configured(tmp_path)
    worker, job = claim(driver, client)
    run = job['run_id']
    driver.store.propose(run, 'user-a', {'project': 'TEST', 'summary': 'Summary', 'description': 'Synthetic'})
    driver.store.cancel(run, 'user-a')
    driver.console.update(run, worker, 'cancelled', {'cleanup_verified': cleanup_verified})
    with driver.store.transaction() as db:
        db.execute('UPDATE runs SET expires=? WHERE id=?', (int(time.time()) - 1, run))
    page = client.get('/runs/' + run)
    assert ('Proposal rejected — no issue created' in page.text) is cleanup_verified
    assert ('An execution problem was recorded' in page.text) is not cleanup_verified
    assert ('This run has expired.' in page.text) is not cleanup_verified



def test_start_waits_for_fresh_routine_check_before_allocating_a_run(
    tmp_path: Path, monkeypatch
) -> None:
    import identity_demo_console as driver_console
    import identity_demo_driver as implementation
    driver, client, _ = configured(tmp_path)
    checked_at = int(time.time()) - 61
    worker_id = uuid4().hex
    driver.console.heartbeat(worker_id, phase='preparing', checked_at=checked_at)
    preparing = driver.console.available(True)
    assert not preparing['ready'] and driver_console.can_start_during_check(preparing)
    page=client.get('/')
    assert 'Background checks are running. You can request a workflow now' in page.text
    assert '<button class="primary">Start assessment</button>' in page.text
    ready = {**preparing, 'ready': True, 'phase': 'ready', 'checked_at': int(time.time())}
    states = iter([preparing] * 47 + [ready])
    def next_readiness(_force: bool) -> dict:
        state = next(states, ready)
        if state['ready']:
            driver.console.heartbeat(worker_id, phase='ready', checked_at=state['checked_at'])
        return state
    monkeypatch.setattr(driver.console, 'available', next_readiness)
    with driver.store.transaction() as db:
        before=db.execute('SELECT count(*) FROM runs').fetchone()[0]
    waits=[]
    async def wait(seconds):
        waits.append(seconds)
        with driver.store.transaction() as db:
            assert db.execute('SELECT count(*) FROM runs').fetchone()[0] == before
    monkeypatch.setattr(implementation.asyncio,'sleep',wait)
    response=submit(driver,client)
    assert response.status_code == 303, response.text
    with driver.store.transaction() as db:
        assert db.execute('SELECT count(*) FROM runs').fetchone()[0] == before+1
    assert waits == [0.25] * 47


def test_preflight_wait_is_bounded_and_never_creates_a_run_when_unready(tmp_path: Path, monkeypatch) -> None:
    import identity_demo_driver as implementation
    driver, client, _ = configured(tmp_path)
    driver.console.heartbeat(uuid4().hex)
    preparing = {**driver.console.available(True),'ready':False,'phase':'preparing','reason':''}
    monkeypatch.setattr(driver.console,'available',lambda _:preparing)
    waits=[]
    async def wait(seconds):waits.append(seconds)
    monkeypatch.setattr(implementation.asyncio,'sleep',wait)
    assert submit(driver,client).status_code == 409
    assert len(waits) == 120 and sum(waits) == 30
    with driver.store.transaction() as db:
        assert db.execute('SELECT count(*) FROM console_jobs').fetchone()[0] == 0


@pytest.mark.parametrize('change', [{'busy':True},{'online':False},{'preparing_context':True},
    {'recovery_required':True},{'reason':'sender_trust'},{'phase':'blocked'}])
def test_busy_or_security_block_is_not_treated_as_short_preflight(tmp_path: Path, monkeypatch, change) -> None:
    import identity_demo_driver as implementation
    driver,client,_ = configured(tmp_path)
    driver.console.heartbeat(uuid4().hex)
    state = {**driver.console.available(True),'ready':False,'phase':'preparing','reason':'',**change}
    monkeypatch.setattr(driver.console,'available',lambda _:state)
    async def wait(seconds):raise AssertionError('must not wait past a security/lifecycle block')
    monkeypatch.setattr(implementation.asyncio,'sleep',wait)
    assert submit(driver,client).status_code == 409


def test_signout_during_preflight_wait_cannot_create_a_run(tmp_path: Path, monkeypatch) -> None:
    import identity_demo_driver as implementation
    driver,client,_ = configured(tmp_path)
    driver.console.heartbeat(uuid4().hex)
    ready=driver.console.available(True)
    states=iter([{**ready,'ready':False,'phase':'preparing','reason':''},ready])
    monkeypatch.setattr(driver.console,'available',lambda _:next(states,ready))
    async def wait(seconds):driver.sessions.clear()
    monkeypatch.setattr(implementation.asyncio,'sleep',wait)
    assert submit(driver,client).status_code in (401,403)
    with driver.store.transaction() as db:
        assert db.execute('SELECT count(*) FROM console_jobs').fetchone()[0] == 0



def test_routine_readiness_check_is_neutral_and_still_blocks_admission(tmp_path: Path) -> None:
    """An idle preflight must not look like deployment work or admit an unchecked run."""
    driver, client, _ = configured(tmp_path)
    driver.console.heartbeat(uuid4().hex, phase='preparing', checked_at=int(time.time()) - 61)
    state = driver.console.available(True)
    assert state['online'] and not state['ready'] and not state['busy']
    assert not state['preparing_context'] and not state['recovery_required']
    page = client.get('/')
    live = client.get('/console/live').json()
    assert '<span class="tag active">Checking readiness</span>' in page.text
    assert 'Background checks are running. You can request a workflow now' in page.text
    assert 'Preparing demo' not in page.text and 'Ready to start' not in page.text
    assert live['coordinator_label'] == 'Checking readiness' and live['can_start']
    assert '<span class="tag active">Checking readiness</span>' in live['readiness_html']
    assert 'data-readiness-status>Checking readiness' in client.get('/?view=overview').text


@pytest.mark.parametrize('change, expected', [
    ({'reason': 'context_preparing', 'preparing_context': True}, 'Preparing fresh demo sandbox'),
    ({'phase': 'blocked', 'reason': 'sender_trust'}, 'Operator review required'),
    ({'reason': 'recovery_required', 'recovery_required': True}, 'Operator review required'),
    ({'phase': 'offline', 'online': False}, 'Coordinator offline'),
    ({'phase': 'ready', 'ready': True}, 'Ready to start'),
])
def test_routine_check_does_not_hide_preparation_or_security_state(change: dict, expected: str) -> None:
    """Real lifecycle/security blocks and restored readiness keep their existing meaning."""
    import identity_demo_console as console
    state = {'enabled': True, 'online': True, 'ready': False, 'busy': False,
             'phase': 'preparing', 'reason': '', 'preparing_context': False, 'recovery_required': False,
             **change}
    assert not console.checking_readiness(state)
    assert console.coordinator_label(state) == expected
    page = console.readiness_panel({'exp': time.time() + 600}, state)
    assert expected in page and 'Routine background checks are running.' not in page


@pytest.mark.parametrize('checked_age, expected', [(61, True), (89, True), (91, False), (0, False)])
def test_only_a_recent_successful_check_keeps_workflow_buttons_available(
    checked_age: int, expected: bool
) -> None:
    import identity_demo_console as driver_console
    state = {'enabled': True, 'online': True, 'ready': False, 'busy': False,
             'phase': 'preparing', 'reason': '', 'uncertain': 0,
             'recovery_required': False, 'preparing_context': False,
             'checked_at': int(time.time()) - checked_age if checked_age else 0}
    assert driver_console.can_start_during_check(state) is expected



def test_output_limit_diagnostic_cannot_expose_an_approvable_partial_draft(tmp_path: Path) -> None:
    """Persist the real allowlisted failure and render its deliberate no-write boundary."""
    driver, client, _ = configured(tmp_path)
    worker, job = claim(driver, client)
    driver.console.update(job['run_id'], worker, 'agent_stopping',
        {'failure_code': 'agent_failed', 'agent_error_category': 'model_output_limit'})
    page = client.get('/runs/' + job['run_id']).text
    assert 'model reached its output limit' in page
    assert 'no approval or Jira write was attempted' in page
    assert 'Approve this exact proposal' not in page and 'Access Jira' not in page
    assert driver.store.describe(job['run_id'], job['user'])['actions'] == []
