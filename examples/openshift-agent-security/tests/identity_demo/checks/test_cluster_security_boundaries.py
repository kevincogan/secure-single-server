# SPDX-License-Identifier: Apache-2.0
"""Adversarial candidate boundaries; these do not replace live acceptance."""
from dataclasses import replace
import json
import secrets
import time

import pytest
from starlette.testclient import TestClient
from identity_demo_driver import Driver, COOKIE, STATE_COOKIE
from identity_demo_login_state import LoginState
from identity_demo_run_store import Denied
from identity_demo_issue_view import issue_html, fetch_issue
from identity_demo_realm_access import realm_token
from deployment_profile import active_profile
from checks.test_driver import setup, approved


def test_anonymous_logins_do_not_exhaust_pending_capacity(tmp_path):
    previous, _, _, _ = setup(tmp_path)
    driver = Driver(replace(previous.config, stateless_login=True), previous.verify)
    client = TestClient(driver.app, base_url=driver.config.origin)
    responses = [client.get('/login', follow_redirects=False) for _ in range(100)]
    assert responses[0].status_code == 302
    assert responses[-1].status_code == 429
    response = responses[0]
    assert driver.pending == {} and driver.sessions == {}
    assert 'Secure' in response.headers['set-cookie'] and 'HttpOnly' in response.headers['set-cookie']
    assert client.get('/callback?state=forged&code=forged').status_code == 429
    assert client.get('/healthz').status_code == 200


def test_login_cookie_binds_browser_state_and_fails_after_process_replacement():
    state, nonce, verifier = [secrets.token_urlsafe(32) for _ in range(3)]
    keeper = LoginState()
    cookie = keeper.issue(state, nonce, verifier)
    assert state not in cookie and nonce not in cookie and verifier not in cookie
    assert keeper.consume(cookie, state)['verifier'] == verifier
    for candidate, supplied in [(cookie, secrets.token_urlsafe(32)), (cookie[:-1], state), ('x'*2049, state)]:
        with pytest.raises(Denied): keeper.consume(candidate, supplied)
    with pytest.raises(Denied): LoginState().consume(cookie, state)


def test_private_operator_listener_does_not_accept_role_substitution(tmp_path):
    previous, _, _, _ = setup(tmp_path)
    driver = Driver(replace(previous.config, coordinator_enabled=True, private_operator_api=True,
        coordinator_secret='c'*40, preparer_secret='p'*40), previous.verify)
    public = TestClient(driver.app, base_url=driver.config.origin)
    private = TestClient(driver.private_app, base_url=driver.config.origin)
    assert public.get('/internal/operator/console/state', headers={'Authorization':'Bearer '+'c'*40}).status_code == 404
    assert private.get('/internal/operator/console/state').status_code == 403
    for secret in ('c'*40, 'p'*40, 'o'*40):
        assert private.get('/internal/operator/console/state', headers={'Authorization':'Bearer '+secret}).status_code == 200
    # The preparer cannot claim runs or publish coordinator heartbeats.
    for route in ('next', 'heartbeat'):
        assert private.post('/internal/operator/console/'+route,
            headers={'Authorization':'Bearer '+'p'*40}, json={'worker':'x'*32}).status_code == 403
    assert private.post('/internal/operator/console/prepare/next',
        headers={'Authorization':'Bearer '+'c'*40}, json={'owner':'x'*32}).status_code == 403


def historical(tmp_path):
    driver, client, run, _ = setup(tmp_path)
    object.__setattr__(driver.config, 'jira_view_url', 'https://'+active_profile().service_host('fixture-protected-adapter')+':8443')
    object.__setattr__(driver.config, 'jira_view_ca', '/unused-test-ca')
    proposal = approved(driver, run)
    # Simulate a completed independent receipt, not a live backend write.
    with driver.store.transaction() as db:
        db.execute("UPDATE actions SET state='succeeded',issue_key='TEST-123' WHERE id=?", (proposal['action_id'],))
        db.execute("UPDATE runs SET active=0,expires=? WHERE id=?", (int(time.time())-1, run))
    return driver, client, run


def test_retirement_endpoint_requires_preparer_and_positive_durable_cleanup(tmp_path):
    previous, _, run, _ = setup(tmp_path)
    driver = Driver(replace(previous.config, coordinator_enabled=True, private_operator_api=True,
        coordinator_secret='c'*40, preparer_secret='p'*40), previous.verify)
    client = TestClient(driver.private_app, base_url=driver.config.origin)
    headers = {'Authorization': 'Bearer ' + 'p'*40}
    with driver.store.read_transaction() as db:
        workload = db.execute('SELECT workload FROM runs WHERE id=?', (run,)).fetchone()[0]
    route = '/internal/operator/console/prepare/retirement-check'
    assert client.post(route, json={'workload': workload}).status_code == 403
    assert client.post(route, json={'workload': workload}, headers={'Authorization': 'Bearer '+'c'*40}).status_code == 403
    assert client.post(route, json={'workload': workload}, headers=headers).status_code == 403
    with driver.store.transaction() as db:
        db.execute('UPDATE runs SET active=0 WHERE id=?', (run,))
    # A closed run alone is insufficient: terminal verified cleanup is required.
    assert client.post(route, json={'workload': workload}, headers=headers).status_code == 403


def test_issue_view_is_owner_scoped_historical_and_escaped(tmp_path, monkeypatch):
    import identity_demo_issue_view as view
    driver, client, run = historical(tmp_path)
    seen=[]
    def fetch(base, ca, ticket, key):
        assert key == 'TEST-123'
        seen.append(ticket)
        return {'key':key, 'fields':{'summary':'<script>bad()</script>', 'description':'<img onerror=bad()>'}}
    monkeypatch.setattr(view, 'fetch_issue', fetch)
    response=client.get('/runs/'+run+'/jira')
    assert response.status_code == 200 and '&lt;script&gt;' in response.text
    assert '<script>bad()' not in response.text
    assert driver.tickets == {} and len(seen) == 1
    driver.sessions['opaque']['claims']['sub']='foreign-owner'
    assert client.get('/runs/'+run+'/jira').status_code == 403
    assert len(seen) == 1


def test_history_ticket_is_one_use_and_cannot_authorize_mutation(tmp_path):
    driver, _, run, _ = setup(tmp_path)
    private=TestClient(driver.app,base_url=driver.config.origin)
    driver.tickets['synthetic']={'purpose':'history','expires':time.time()+15,'issue_key':'TEST-123','run':run}
    headers={'Authorization':'Bearer '+'a'*40}
    # Mutation redemption refuses a historical capability without consuming it.
    assert private.post('/internal/adapter/claim',headers=headers,json={'decision_ticket':'synthetic'}).status_code == 403
    result=private.post('/internal/adapter/history',headers=headers,json={'decision_ticket':'synthetic'})
    assert result.json()=={'allowed':True,'issue_key':'TEST-123'}
    assert private.post('/internal/adapter/history',headers=headers,json={'decision_ticket':'synthetic'}).status_code == 403


def test_issue_view_refuses_unverified_or_caller_selected_destinations(tmp_path):
    driver, client, run, _ = setup(tmp_path)
    assert client.get('/runs/'+run+'/jira?issue=TEST-999').status_code == 403
    with pytest.raises(ValueError): fetch_issue('https://attacker.example', '/unused', 'x'*43, 'TEST-1')
    with pytest.raises(ValueError): fetch_issue('https://'+active_profile().service_host('fixture-protected-adapter')+':8443', '/unused', 'x'*43, '../admin')


def test_cluster_realm_admin_has_no_bootstrap_fallback_or_other_realm():
    profile=active_profile()
    base=profile.origin('fixture-keycloak')
    credentials={'realm_management':{base:{'client_id':'fixture-console-realm-coordinator','client_secret':'s'*40}}}
    calls=[]
    def request(origin,path,**kw):
        calls.append((origin,path,kw));return 200,{'access_token':'synthetic'},{}
    assert realm_token(request,base,credentials)=='synthetic'
    assert calls[0][1]=='/realms/identity-demo/protocol/openid-connect/token'
    assert calls[0][2]['fields']['grant_type']=='client_credentials'
    assert 'password' not in calls[0][2]['fields']
    with pytest.raises(ValueError): realm_token(request,'https://foreign.example',credentials)
    with pytest.raises(ValueError): realm_token(request,base,{**credentials,'keycloak_admin':'bootstrap'})
    assert len(calls)==1


def test_real_sdk_history_route_is_read_only_and_requires_a_redeemable_ticket(tmp_path,monkeypatch):
    from mcp.server.fastmcp import FastMCP
    import identity_demo_jira_action_adapter as adapter
    from types import SimpleNamespace
    secret=tmp_path/'secret';secret.write_text('s'*40)
    for key,value in {'DRIVER_ADAPTER_SECRET_FILE':str(secret),'JIRA_USER':'synthetic',
                      'JIRA_TOKEN':'synthetic','DRIVER_CA_FILE':'unused',
                      'JIRA_HISTORY_VIEW_ENABLED':'1'}.items():monkeypatch.setenv(key,value)
    calls=[]
    async def driver(endpoint,value):
        calls.append(('driver',endpoint))
        if endpoint!='history' or value!={'decision_ticket':'redeem-once'}:raise Denied('ticket')
        return {'allowed':True,'issue_key':'OPS-123'}
    async def http(method,url,**kw):
        calls.append((method,url))
        assert method=='GET' and url==adapter.JIRA+'/rest/api/2/issue/OPS-123' and kw=={'backend':True}
        return 200,{'key':'OPS-123','fields':{'summary':'Synthetic','description':'Owned fixture','private_extra':'excluded'}}
    async def unused(ctx):raise AssertionError('MCP mutation/read tools are not the history route')
    monkeypatch.setattr(adapter,'JiraTools',lambda *args,**kw:SimpleNamespace(driver=driver,http=http,read=unused,create=unused))
    server=FastMCP('history-test')
    adapter.install_tools(server)
    with TestClient(server.streamable_http_app()) as client:
        assert client.post('/internal/verified-issue',json={'issue_key':'OPS-999'}).status_code==403
        assert client.post('/internal/verified-issue',json={'decision_ticket':'forged'}).status_code==403
        response=client.post('/internal/verified-issue',json={'decision_ticket':'redeem-once'})
        assert response.status_code==200
        assert response.json()=={'key':'OPS-123','fields':{'summary':'Synthetic','description':'Owned fixture'}}
        assert response.headers['cache-control']=='no-store'
    assert sum(c[0]=='GET' for c in calls)==1
    assert not any(c[0] in ('POST','DELETE','PATCH','PUT') for c in calls)


def test_preparer_can_verify_only_presenter_requested_batches(tmp_path):
    from checks.test_console_pool import setup_pool, plan
    previous, _, _, _ = setup_pool(tmp_path)
    driver = Driver(replace(previous.config, private_operator_api=True,
        coordinator_secret='c'*40, preparer_secret='p'*40), previous.verify)
    client = TestClient(driver.private_app, base_url=driver.config.origin)
    endpoint = '/internal/operator/console/pool'
    headers = {'Authorization': 'Bearer '+'p'*40}
    batch = driver.console.configure_pool(plan(1), driver.config.contexts, driver.config.project)
    identifier = batch['batch']['id']
    seal = {'action': 'seal', 'id': identifier, 'receipt_sha256': 'b'*64}
    assert client.post(endpoint, headers=headers, json=seal).status_code == 403
    with driver.store.transaction() as db:
        db.execute("UPDATE console_batches SET requested_by='synthetic-presenter' WHERE id=?", (identifier,))
    assert client.post(endpoint, headers=headers, json={
        'action': 'verification-status', 'id': identifier, 'status': 'verifying'}).status_code == 200
    assert client.post(endpoint, headers=headers, json=seal).status_code == 200
    for data in ({**seal, 'action': 'release'}, {'action': 'configure', 'plan': plan(1)},
                 {'action': 'automatic', 'enabled': True, 'receipt_sha256': 'a'*64, 'retired_workloads': []}):
        assert client.post(endpoint, headers=headers, json=data).status_code == 403
    assert client.post(endpoint, headers={'Authorization':'Bearer '+'c'*40}, json=seal).status_code == 403


def test_runtime_roles_never_read_issuer_or_gateway_private_keys():
    from cluster_console_resources import permissions
    from deployment_profile import LEGACY
    for obj in permissions(LEGACY, 'fixture-step4-read-route-catalog'):
        for rule in obj.get('rules', []):
            if 'secrets' in rule['resources']:
                assert set(rule.get('resourceNames', [])) <= {
                    'fixture-adapter-catalog-trust-v1', 'fixture-step4-read-route-catalog',
                    'fixture-step4-read-route', 'fixture-step4-read-route-ca'}
                assert set(rule['verbs']) <= {'get','patch'}


def test_retired_identity_ledger_is_read_only_and_coordinator_only():
    from cluster_console_resources import permissions
    from deployment_profile import LEGACY
    matching = [(obj, rule) for obj in permissions(LEGACY, 'fixture-step4-read-route-catalog')
                for rule in obj.get('rules', []) if 'configmaps' in rule['resources']
                and 'fixture-step4-retired-runs' in rule.get('resourceNames', [])]
    assert len(matching) == 1
    obj, rule = matching[0]
    assert obj['metadata']['namespace'] == LEGACY.core_namespace
    assert obj['metadata']['name'] == 'fixture-console-coordinator-observe'
    assert rule['verbs'] == ['get']


def test_initial_empty_pool_bootstrap_is_explicit_operator_only_and_not_replayed(tmp_path):
    previous, _, _, _ = setup(tmp_path)
    driver = Driver(replace(previous.config, database=tmp_path/'fresh.db',contexts=(),
        coordinator_enabled=True,private_operator_api=True,coordinator_secret='c'*40,preparer_secret='p'*40), previous.verify)
    client = TestClient(driver.private_app,base_url=driver.config.origin)
    endpoint='/internal/operator/console/pool'
    data={'action':'automatic','enabled':True,'receipt_sha256':'b'*64,'retired_workloads':[]}
    operator={'Authorization':'Bearer '+driver.config.operator_secret}
    assert client.post(endpoint,headers=operator,json=data).status_code==403
    data['initial_empty']=True
    for secret in ('c'*40,'p'*40):
        assert client.post(endpoint,headers={'Authorization':'Bearer '+secret},json=data).status_code==403
    response=client.post(endpoint,headers=operator,json=data)
    assert response.status_code==200 and response.json()['automatic']['target']==8
    assert response.json()['automatic']['managed']==0
    # An unknown activation outcome is inspected, never replayed as fresh.
    assert client.post(endpoint,headers=operator,json=data).status_code==403
    assert client.get(endpoint,headers=operator).json()['automatic']['managed']==0


def test_initial_empty_pool_cannot_erase_prior_run_history(tmp_path):
    previous, _, _, _ = setup(tmp_path)
    driver=Driver(replace(previous.config,contexts=(),coordinator_enabled=True,
        private_operator_api=True,coordinator_secret='c'*40,preparer_secret='p'*40),previous.verify)
    client=TestClient(driver.private_app,base_url=driver.config.origin)
    with driver.store.transaction() as db:
        db.execute('UPDATE runs SET active=0')
    response=client.post('/internal/operator/console/pool',headers={'Authorization':'Bearer '+driver.config.operator_secret},
        json={'action':'automatic','enabled':True,'receipt_sha256':'b'*64,'retired_workloads':[],'initial_empty':True})
    assert response.status_code==403
    with driver.store.read_transaction() as db:
        assert db.execute('SELECT count(*) FROM runs').fetchone()[0]>0
        assert db.execute('SELECT count(*) FROM console_pool_settings').fetchone()[0]==0


@pytest.mark.parametrize('enabled', [False, True])
@pytest.mark.parametrize('credential', ['', 'o'*40, 'c'*40, 'p'*40, 'g'*40, 'a'*40])
def test_direct_cli_auth_is_explicit_and_never_a_cluster_fallback(tmp_path, enabled, credential):
    """Private direct mode uses only the installer key; cluster mode only coordination."""
    previous, _, run, _ = setup(tmp_path)
    driver = Driver(replace(previous.config, coordinator_enabled=enabled, private_operator_api=True,
        coordinator_secret='c'*40, preparer_secret='p'*40), previous.verify)
    driver.sessions = previous.sessions
    private = TestClient(driver.private_app, base_url=driver.config.origin)
    public = TestClient(driver.app, base_url=driver.config.origin)
    headers = {'Authorization': 'Bearer ' + credential}
    permitted = credential == ('c'*40 if enabled else 'o'*40)
    initial = driver.store.describe(run, 'user-a')['run']
    report = {'run_id': run, 'user': 'user-a', 'workload': initial['workload'],
              'assessment': 'Synthetic retained report', 'arguments': {
                  'project': 'TEST', 'summary': 'Synthetic proposal', 'description': 'Unapproved synthetic text'}}
    assert public.get('/internal/operator/credentials/' + run, headers=headers).status_code == 404
    assert public.post('/internal/operator/report', headers=headers, json=report).status_code == 404
    response = private.get('/internal/operator/credentials/' + run, headers=headers)
    assert response.status_code == (200 if permitted else 403)
    if permitted:
        assert response.json()['access_token'] == 'human'
        assert response.json()['expires_at'] == initial['expires']
    assert private.post('/internal/operator/report', headers=headers, json=report).status_code == (200 if permitted else 403)
    assert private.post('/internal/operator/revoke', headers=headers, json={'run_id': run}).status_code == (200 if permitted else 403)
    after = driver.store.describe(run, 'user-a')
    assert after['run']['expires'] == initial['expires']
    assert after['run']['active'] == (0 if permitted else 1)
    assert all(a['state'] == 'proposed' for a in after['actions'])
    assert private.get('/internal/operator/credentials/' + run, headers=headers).status_code == 403
    if not enabled:
        assert private.get('/internal/operator/console/state', headers=headers).status_code == 403
