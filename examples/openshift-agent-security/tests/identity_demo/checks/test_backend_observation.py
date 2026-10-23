# SPDX-License-Identifier: Apache-2.0
"""Read-only verification cannot substitute a project/issue or authorize writes."""
from dataclasses import replace
import json
import time

import pytest
from starlette.testclient import TestClient

from checks.test_driver import setup, approved
from identity_demo_driver import Driver
from deployment_profile import active_profile
import identity_demo_backend_observation as observation


def fixture(tmp_path):
    previous, _, run, _ = setup(tmp_path)
    driver = Driver(replace(previous.config, coordinator_enabled=True, private_operator_api=True,
        coordinator_secret='c'*40, preparer_secret='p'*40,
        jira_view_url='https://'+active_profile().service_host('fixture-protected-adapter')+':8443',
        jira_view_ca='/unused'), previous.verify)
    return driver, TestClient(driver.private_app, base_url=driver.config.origin), run


def test_observation_is_scoped_to_record_and_returns_no_backend_fields(tmp_path, monkeypatch):
    driver, client, run = fixture(tmp_path)
    proposal = approved(driver, run)
    with driver.store.read_transaction() as db:
        workload = db.execute('SELECT workload FROM runs WHERE id=?', (run,)).fetchone()[0]
    claim = driver.store.decision(run, proposal['action_id'], 'user-a', workload,
                                 proposal['arguments'], claim=True)
    driver.store.finish(run, proposal['action_id'], claim['execution_id'], state='succeeded', issue_key='TEST-1')
    fields = {**proposal['arguments'], 'project': {'key': 'TEST'}, 'issuetype': {'name': 'Task'}}
    seen = []
    def fetch(base, ca, ticket):
        record = driver.tickets[ticket]
        assert record['purpose'] == 'observation' and record['project'] == 'TEST' and record['issue_key'] == 'TEST-1'
        seen.append(ticket)
        return {'total': 3, 'issue': {'key': 'TEST-1', 'fields': fields}}
    monkeypatch.setattr(observation, 'fetch', fetch)
    url = '/internal/operator/console/backend-state/' + run
    for key in ('p'*40, 'o'*40):
        assert client.get(url, headers={'Authorization': 'Bearer '+key}).status_code == 403
    response = client.get(url+'?issue_key=TEST-999', headers={'Authorization': 'Bearer '+'c'*40})
    assert response.status_code == 200 and response.json()['total'] == 3
    assert response.json()['outcome']['backend_fields_match_approval'] is True
    assert 'Summary' not in response.text and 'Description' not in response.text
    assert driver.tickets == {} and len(seen) == 1
    fields['summary'] = 'unapproved'
    assert client.get(url, headers={'Authorization': 'Bearer '+'c'*40}).status_code == 403
    assert driver.tickets == {}


def test_observation_ticket_is_one_use_and_never_a_mutation_capability(tmp_path):
    driver, private, run = fixture(tmp_path)
    public = TestClient(driver.app, base_url=driver.config.origin)
    driver.tickets['synthetic'] = {'purpose': 'observation', 'expires': time.time()+15,
        'project': 'OPS', 'issue_key': None}
    headers = {'Authorization': 'Bearer '+'a'*40}
    assert public.post('/internal/adapter/claim', json={'decision_ticket': 'synthetic'}, headers=headers).status_code == 403
    response = public.post('/internal/adapter/observation', json={'decision_ticket': 'synthetic'}, headers=headers)
    assert response.json() == {'allowed': True, 'project': 'OPS', 'issue_key': None}
    assert public.post('/internal/adapter/observation', json={'decision_ticket': 'synthetic'}, headers=headers).status_code == 403


def test_adapter_observation_is_fixed_read_only_sdk_route(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from mcp.server.fastmcp import FastMCP
    import identity_demo_jira_action_adapter as adapter
    secret=tmp_path/'secret';secret.write_text('s'*40)
    for key, value in {'DRIVER_ADAPTER_SECRET_FILE': str(secret), 'JIRA_USER': 'synthetic',
        'JIRA_TOKEN': 'synthetic', 'DRIVER_CA_FILE': 'unused', 'JIRA_HISTORY_VIEW_ENABLED': '1'}.items():
        monkeypatch.setenv(key, value)
    calls=[]
    async def driver(endpoint, value):
        assert endpoint == 'observation' and value == {'decision_ticket': 'one-use'}
        return {'allowed': True, 'project': 'OPS', 'issue_key': 'OPS-1'}
    async def http(method, url, **kwargs):
        calls.append((method, url))
        assert method == 'GET' and kwargs == {'backend': True}
        if '/search?' in url:
            assert 'project+%3D+OPS' in url
            return 200, {'total': 1}
        assert url == adapter.JIRA+'/rest/api/2/issue/OPS-1'
        return 200, {'key': 'OPS-1', 'fields': {}}
    monkeypatch.setattr(adapter, 'JiraTools', lambda *a, **kw: SimpleNamespace(driver=driver, http=http))
    server=FastMCP('observation-test');adapter.install_tools(server)
    with TestClient(server.streamable_http_app()) as client:
        assert client.post('/internal/observed-state', json={'issue_key': 'OTHER-1'}).status_code == 403
        response=client.post('/internal/observed-state', json={'decision_ticket': 'one-use'})
        assert response.status_code == 200 and response.json()['total'] == 1
    assert len(calls) == 2 and all(method == 'GET' for method, _ in calls)
