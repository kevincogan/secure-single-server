# SPDX-License-Identifier: Apache-2.0
"""A presenter can request a bounded batch without gaining operator API access."""

from argparse import Namespace
from dataclasses import replace
from pathlib import Path
import time
from uuid import uuid4

import pytest

from checks.test_console import configured, operator, submit
from checks.test_console_preparer import mapping
from identity_demo_console_preparer import verify_browser_batch
from identity_demo_run_store import Denied
import identity_demo_presentation as presentation


def ready(tmp_path: Path) -> tuple:
    driver, client, _, = configured(tmp_path)
    values = [('cve', 'triage', 'TEST'), ('cve', 'triage', 'TEST'), ('cve', 'reader', 'TEST'),
              ('service-request', 'triage', 'SERVICE'), ('incident-triage', 'triage', 'OPS')]
    contexts = tuple(mapping({'workflow': w, 'role': r, 'project': project, 'suffix': f'x{i}a'})
                     for i, (w, r, project) in enumerate(values))
    driver.config = replace(driver.config, contexts=contexts, presenter_subjects=('user-a',))
    worker = uuid4().hex
    driver.console.heartbeat(worker, checked_at=int(time.time()))
    with driver.store.transaction() as db:
        db.execute('UPDATE runs SET active=0')
        db.execute('INSERT INTO console_preparer VALUES(1,?)', (int(time.time()),))
    return driver, client, worker


def request(driver: object, client: object, **fields: str) -> object:
    return client.post('/settings/prepare', headers={'Origin': driver.config.origin},
                       data={'csrf': 'csrf-fixture', **fields}, follow_redirects=False)


def test_presenter_button_requests_all_five_slots_without_exposing_operator_data(tmp_path: Path) -> None:
    driver, client, _ = ready(tmp_path)
    page = client.get('/settings')
    assert 'Verify demo batch' in page.text and '/settings/live' in page.text
    assert request(driver, client).status_code == 303
    snapshot = driver.console.pool_status(driver.config.contexts, driver.config.project)
    assert snapshot['batch']['browser_requested'] and snapshot['batch']['filled']
    assert len(snapshot['batch']['plan']['sequence']) == 5
    assert snapshot['batch']['plan']['global_limit'] == 6
    assert not driver.console.available(True)['ready']
    safe = client.get('/settings/live').text
    assert driver.config.operator_secret not in safe and driver.sessions['opaque']['token'] not in safe
    assert all(c['workload'] not in safe and c['sandbox_id'] not in safe for c in driver.config.contexts)
    assert client.get('/internal/operator/console/pool').status_code == 403


@pytest.mark.parametrize('fault', ['viewer', 'not_allowlisted', 'no_csrf', 'foreign_origin', 'custom_scope'])
def test_untrusted_browser_cannot_trigger_preparation(tmp_path: Path, fault: str) -> None:
    driver, client, _ = ready(tmp_path)
    if fault == 'viewer':
        driver.sessions['opaque']['claims']['realm_access']['roles'] = ['viewer']
    elif fault == 'not_allowlisted':
        driver.config = replace(driver.config, presenter_subjects=())
    data = {'csrf': 'wrong' if fault == 'no_csrf' else 'csrf-fixture'}
    if fault == 'custom_scope':
        data['global_limit'] = '100'
    response = client.post('/settings/prepare', headers={'Origin': 'https://foreign.invalid' if fault == 'foreign_origin' else driver.config.origin}, data=data)
    assert response.status_code == 403
    assert driver.console.pool_status(driver.config.contexts, driver.config.project)['batch'] is None
    if fault in ('viewer', 'not_allowlisted'):
        assert 'action="/settings/prepare"' not in client.get('/settings').text


def test_duplicate_clicks_observe_one_durable_batch(tmp_path: Path) -> None:
    driver, client, _ = ready(tmp_path)
    assert request(driver, client).status_code == 303
    before = driver.console.pool_status(driver.config.contexts, driver.config.project)['batch']['id']
    assert request(driver, client).status_code == 303
    assert driver.console.pool_status(driver.config.contexts, driver.config.project)['batch']['id'] == before
    with driver.store.transaction() as db:
        assert db.execute('SELECT count(*) FROM console_batches').fetchone()[0] == 1
        assert db.execute('SELECT count(*) FROM console_preparations').fetchone()[0] == 0


def test_running_demo_prevents_browser_preparation(tmp_path: Path) -> None:
    driver, client, _ = ready(tmp_path)
    assert submit(driver, client).status_code == 303
    assert request(driver, client).status_code == 403
    assert driver.console.pool_status(driver.config.contexts, driver.config.project)['batch'] is None


def test_revoked_refresh_cannot_start_a_batch(tmp_path: Path, monkeypatch) -> None:
    driver, client, _ = ready(tmp_path)
    original = driver.session
    async def session(request: object, **kwargs: object) -> dict:
        if kwargs.get('force'):
            raise Denied('session_renewal_required')
        return await original(request, **kwargs)
    monkeypatch.setattr(driver, 'session', session)
    assert request(driver, client).status_code == 403
    assert driver.console.pool_status(driver.config.contexts, driver.config.project)['batch'] is None


class Control:
    def __init__(self, driver: object, client: object, *, lose_seal: bool = False) -> None:
        self.driver, self.client, self.lose_seal = driver, client, lose_seal
        self.actions = []
    def request(self, suffix: str, data: dict | None = None) -> dict:
        assert suffix == 'pool'
        if data is None:
            return self.driver.console.pool_status(self.driver.config.contexts, self.driver.config.project)
        self.actions.append(data['action'])
        response = self.client.post('/internal/operator/console/pool', headers=operator(self.driver), json=data)
        assert response.status_code == 200
        if data['action'] == 'seal' and self.lose_seal:
            raise OSError('Lost observation; do not replay native work')
        return response.json()


@pytest.mark.parametrize('lose_seal', [False, True])
def test_existing_preparer_verifies_then_seals_without_new_contexts(tmp_path: Path, monkeypatch, lose_seal: bool) -> None:
    driver, client, _ = ready(tmp_path)
    assert request(driver, client).status_code == 303
    calls = []
    monkeypatch.setattr(presentation, 'verify_batch', lambda *a: calls.append('verify') or {'verified': True})
    monkeypatch.setattr(presentation, 'wait_for_seal_window', lambda *a: calls.append('fresh'))
    control = Control(driver, client, lose_seal=lose_seal)
    result = verify_browser_batch(Namespace(output_dir=tmp_path), control)
    assert result['presentation_ready'] and calls == ['verify', 'fresh']
    assert control.actions == ['verification-status', 'seal']
    assert driver.console.pool_status(driver.config.contexts, driver.config.project)['batch']['phase'] == 'holding'
    assert verify_browser_batch(Namespace(output_dir=tmp_path), control) is None


def test_verification_failure_requires_explicit_read_only_retry_not_reprovisioning(tmp_path: Path, monkeypatch) -> None:
    driver, client, _ = ready(tmp_path)
    assert request(driver, client).status_code == 303
    identifier = driver.console.pool_status(driver.config.contexts, driver.config.project)['batch']['id']
    def fail(*args: object) -> dict:
        raise OSError('private diagnostic must not reach browser')
    monkeypatch.setattr(presentation, 'verify_batch', fail)
    control = Control(driver, client)
    result = verify_browser_batch(Namespace(output_dir=tmp_path), control)
    assert result['verification_blocked'] and result['provisioning_replayed'] is False
    assert verify_browser_batch(Namespace(output_dir=tmp_path), control) is None
    page = client.get('/settings').text
    assert 'Verification paused' in page and 'Retry verification' in page
    assert 'No further action is needed' not in page
    assert 'Ask the operator' in page
    assert 'private diagnostic' not in page
    assert request(driver, client).status_code == 303
    after = driver.console.pool_status(driver.config.contexts, driver.config.project)
    assert after['batch']['id'] == identifier and after['batch']['verification_state'] == ''
    with driver.store.transaction() as db:
        assert db.execute('SELECT count(*) FROM console_preparations').fetchone()[0] == 0


def test_ready_batch_disables_preparation_and_repeated_post_does_not_replace_it(tmp_path: Path) -> None:
    driver, client, _ = ready(tmp_path)
    assert request(driver, client).status_code == 303
    pool = driver.console.pool_status(driver.config.contexts, driver.config.project)
    driver.console.finish_pool(pool['batch']['id'], 'b' * 64, driver.config.contexts, driver.config.project)
    page = client.get('/settings').text
    assert 'Ready for your demo' in page and '5 prepared' in page and '0 remaining' in page
    assert 'disabled>All demos prepared' in page
    assert request(driver, client).status_code == 303
    assert driver.console.pool_status(driver.config.contexts, driver.config.project)['batch']['id'] == pool['batch']['id']


def test_used_context_shows_remaining_work_and_enables_presenter_button(tmp_path: Path) -> None:
    driver, client, worker = ready(tmp_path)
    assert submit(driver, client).status_code == 303
    job = driver.console.claim(worker)
    driver.store.cancel(job['run_id'], 'user-a')
    driver.console.update(job['run_id'], worker, 'completed', {'cleanup_verified': True})
    page = client.get('/settings').text
    assert '4 prepared' in page and '1 remaining' in page and '1 needed' in page
    assert 'class="primary">Prepare next demo batch' in page


def test_cve_only_legacy_batch_does_not_hide_exhausted_service_slot(tmp_path: Path) -> None:
    driver, client, _ = ready(tmp_path)
    plan = driver.presentation_plan()
    plan['sequence'] = [v for v in plan['sequence'] if v['workflow'] == 'cve']
    pool = driver.console.configure_pool(plan, driver.config.contexts, driver.config.project)
    driver.console.finish_pool(pool['batch']['id'], 'b' * 64, driver.config.contexts, driver.config.project)
    service = next(c for c in driver.config.contexts if c['workflow'] == 'service-request')
    run = driver.store.create_run(issuer=driver.config.issuer, user='user-a', user_role='analyst',
        workload=service['workload'], workload_role='triage', project='SERVICE',
        expires=int(time.time()) + 600, assessment='Synthetic')
    driver.store.cancel(run, 'user-a')
    assert driver.console.pool_status(driver.config.contexts, driver.config.project)['batch']['filled']
    assert request(driver, client).status_code == 303
    after = driver.console.pool_status(driver.config.contexts, driver.config.project)
    assert after['batch']['id'] != pool['batch']['id']
    assert len(after['batch']['plan']['sequence']) == 5 and not after['batch']['filled']


@pytest.mark.parametrize('coordinator_online', [True, False])
def test_preparation_status_distinguishes_delayed_preparer_heartbeat(coordinator_online: bool) -> None:
    """A long serial prepare may age its heartbeat; it must not enable a second batch."""
    from identity_demo_console import settings
    html = settings('synthetic-csrf', [{'workflow':'cve','role':'triage','target':2,'available':1}],
        {'phase':'preparing','verification_state':''},
        {'online':coordinator_online,'auto_prepare':False,'preparing_context':True,'busy':False}, True)
    assert '<button class="primary" disabled>' in html
    if coordinator_online:
        assert 'Awaiting preparation update' in html
        assert 'Preparation unavailable' not in html
        assert 'demos stay disabled until verification passes' in html
    else:
        assert 'Preparation unavailable' in html
        assert 'Ask the demo operator' in html


@pytest.mark.parametrize('cluster_jira', [False, True])
def test_automatic_settings_explains_the_configured_jira_view(tmp_path, cluster_jira):
    from checks.test_automatic_warm_pool import automatic
    driver, client, _, _ = automatic(tmp_path)
    if cluster_jira:
        driver.config = replace(driver.config, jira_view_url='https://adapter.test:8443')
    page = client.get('/settings')
    assert page.status_code == 200
    assert ('authenticated, read-only run view' in page.text) is cluster_jira
    assert ('preview on the operator machine' in page.text) is not cluster_jira
