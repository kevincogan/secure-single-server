# SPDX-License-Identifier: Apache-2.0
"""Fixed-destination read-only issue retrieval; never a browser-controlled proxy."""
from __future__ import annotations

from html import escape
import json
import re
import ssl
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

from deployment_profile import active_profile


def fetch_issue(base: str, ca: str, ticket: str, key: str) -> dict:
    """Read one verified fixture issue over hostname-verified TLS, without redirects."""
    from identity_demo_driver import NoIssuerRedirect
    expected = 'https://' + active_profile().service_host('fixture-protected-adapter') + ':8443'
    if base != expected or not re.fullmatch(r'(?:TEST|OPS|SERVICE)-[1-9][0-9]*', key):
        raise ValueError('Exact fixture destination and verified issue key required')
    if not isinstance(ticket, str) or not re.fullmatch(r'[A-Za-z0-9_-]{40,64}', ticket):
        raise ValueError('Bounded one-use issue-view ticket required')
    client = build_opener(ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context(cafile=ca)), NoIssuerRedirect())
    request = Request(base + '/internal/verified-issue',
        data=json.dumps({'decision_ticket': ticket}).encode(),
        headers={'Content-Type': 'application/json', 'Accept': 'application/json'}, method='POST')
    with client.open(request, timeout=8) as response:
        body = response.read(131073)
        if response.status != 200 or len(body) > 131072:
            raise ValueError('Bounded issue response required')
    from identity_demo_run_store import strict_json
    result = strict_json(body)
    if result.get('key') != key or not isinstance(result.get('fields'), dict):
        raise ValueError('Backend issue binding mismatch')
    return result


def issue_html(issue: dict, run_id: str) -> str:
    """Render backend fields as escaped text; no upstream HTML or scripts execute."""
    fields = issue['fields']
    rows = ''.join('<dt>' + label + '</dt><dd>' + escape(str(fields.get(name, ''))) + '</dd>'
                   for name, label in [('summary', 'Summary'), ('description', 'Description')])
    return ('<section class="card"><span class="eyebrow">Jira · Read-only issue view</span><h1>'
            + escape(issue['key']) + '</h1><dl class="fields">' + rows
            + '</dl><p>This issue was independently verified for this run. Creating or editing '
              'issues requires the protected approval workflow.</p><a class="button" href="/runs/'
            + escape(run_id, quote=True) + '">Return to run</a></section>')
