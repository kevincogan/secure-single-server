# SPDX-License-Identifier: Apache-2.0
"""Fixed, read-only backend verification without privileged container execution."""
from __future__ import annotations

import json
import secrets
import ssl
import time
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse
from deployment_profile import active_profile
from identity_demo_run_store import Denied, strict_json


def fetch(base, ca, ticket):
    from identity_demo_driver import NoIssuerRedirect
    if base != 'https://' + active_profile().service_host('fixture-protected-adapter') + ':8443':
        raise ValueError('Fixed protected adapter origin required')
    client = build_opener(ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context(cafile=ca)), NoIssuerRedirect())
    with client.open(Request(base+'/internal/observed-state',
            data=json.dumps({'decision_ticket': ticket}).encode(),
            headers={'Content-Type': 'application/json'}), timeout=8) as response:
        body = response.read(65_537)
        if response.status != 200 or len(body) > 65_536:
            raise Denied('observation_backend')
    return strict_json(body)


async def observe(driver, request):
    driver.console_operator(request)
    run_id = request.path_params['run']
    if not driver.config.jira_view_url:
        raise Denied('observation_not_configured')
    with driver.store.read_transaction() as db:
        run = db.execute('SELECT * FROM runs WHERE id=?', (run_id,)).fetchone()
        if not run or run['project'] not in ('TEST', 'OPS', 'SERVICE'):
            raise Denied('run_binding')
        actions = db.execute("SELECT * FROM actions WHERE run_id=? AND state='succeeded'", (run_id,)).fetchall()
        if len(actions) > 1:
            raise Denied('observation_action')
        action = dict(actions[0]) if actions else None
        audit = [dict(v) for v in db.execute('SELECT * FROM audit WHERE run_id=? ORDER BY sequence', (run_id,))]
    driver.tickets = {k: v for k, v in driver.tickets.items() if v['expires'] > time.time()}
    if len(driver.tickets) >= 512:
        raise Denied('observation_capacity')
    ticket = secrets.token_urlsafe(32)
    driver.tickets[ticket] = {'purpose': 'observation', 'expires': time.time()+15,
        'project': run['project'], 'run': run_id, 'issue_key': action['issue_key'] if action else None}
    try:
        backend = await run_in_threadpool(fetch, driver.config.jira_view_url, driver.config.jira_view_ca, ticket)
    finally:
        driver.tickets.pop(ticket, None)
    if type(backend.get('total')) is not int or backend['total'] < 0:
        raise Denied('observation_count')
    outcome = None
    if action:
        issue = backend.get('issue', {})
        fields, approved = issue.get('fields', {}), strict_json(action['payload'])
        events = [v for v in audit if v['action_id'] == action['id']]
        if (issue.get('key') != action['issue_key']
                or fields.get('project', {}).get('key') != approved['project']
                or fields.get('issuetype', {}).get('name') != approved['issue_type']
                or any(fields.get(k) != approved[k] for k in ('summary', 'description', 'labels'))
                or not action['execution_id']
                or sum(e['event'] == 'claimed' for e in events) != 1
                or sum(e['event'] == 'succeeded' for e in events) != 1
                or not any(e['event'] == 'approved' and strict_json(e['detail'])['digest'] == action['digest'] for e in events)):
            raise Denied('observation_approval')
        outcome = {'backend_fields_match_approval': True, 'verified_issue_key': action['issue_key'],
            'durable_action_succeeded': True, 'one_dispatch_claim': True,
            'approval_digest_correlated': True, 'user_workload_run_action_correlated': True,
            'workload': run['workload'], 'user': run['user'], 'project': run['project'],
            'action_id': action['id'], 'digest': action['digest']}
    return JSONResponse({'total': backend['total'], 'outcome': outcome}, headers={'Cache-Control': 'no-store'})


async def redeem(driver, request):
    driver.internal(request, driver.config.adapter_secret)
    data = strict_json(await driver.body(request, 1024))
    if set(data) != {'decision_ticket'} or not isinstance(data['decision_ticket'], str):
        raise Denied('observation_ticket')
    ticket = driver.tickets.get(data['decision_ticket'])
    if not ticket or ticket.get('purpose') != 'observation' or ticket['expires'] <= time.time():
        raise Denied('observation_ticket')
    del driver.tickets[data['decision_ticket']]
    return JSONResponse({'allowed': True, 'project': ticket['project'], 'issue_key': ticket['issue_key']},
                        headers={'Cache-Control': 'no-store'})
