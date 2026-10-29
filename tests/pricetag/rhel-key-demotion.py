#!/usr/bin/env python3
"""Cross-service stale-session regression; synthetic users on a mock host only."""
import http.cookiejar
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/pricetag'))
from metering_admin import request as management, NoRedirect


def main():
    if os.geteuid() != 0:
        raise ValueError('run with sudo on the mock benchmark')
    loader = importlib.machinery.SourceFileLoader('benchmark', str(ROOT / 'scripts/pricetag/benchmark'))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    bench = importlib.util.module_from_spec(spec)
    loader.exec_module(bench)
    bench.require_mock(Path('/etc/praxis-pricetag'))
    origin = next(line.split('=', 1)[1] for line in Path('/etc/praxis-pricetag/metering.env').read_text().splitlines() if line.startswith('MANAGEMENT_PUBLIC_ORIGIN='))
    tls = ssl.create_default_context(cafile='/etc/praxis-pricetag/ca.pem')
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=tls), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    local = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    subjects = ['demo-demote-' + uuid.uuid4().hex[:12], 'demo-owner-' + uuid.uuid4().hex[:12]]
    keys, created = [], []
    def maas(subject, method, path, body=None, admin=False):
        groups = ['system:authenticated'] + (['single-server-admin'] if admin else [])
        req = urllib.request.Request('http://127.0.0.1:18086/v1/api-keys' + path,
            None if body is None else json.dumps(body).encode(), method=method,
            headers={'X-MaaS-Username': subject, 'X-MaaS-Group': json.dumps(groups), 'Content-Type': 'application/json'})
        with local.open(req, timeout=15) as response:
            return json.load(response)
    def public(method, path):
        req = urllib.request.Request('https://localhost:8443' + path, method=method, headers={'Origin': origin})
        try:
            with client.open(req, timeout=15) as r:
                r.read()
                return r.status
        except urllib.error.HTTPError as e:
            e.close()
            return e.code
    try:
        for i, subject in enumerate(subjects):
            management('PUT', 'users', {'subject': subject, 'role': 'super_admin' if i == 0 else 'user'})
            created.append(subject)
            keys.append(maas(subject, 'POST', '', {'name': 'security-regression', 'expiresIn': '1h'}, admin=i == 0))
        login = urllib.request.Request('https://localhost:8443/login', urllib.parse.urlencode({'api_key': keys[0]['key']}).encode(), headers={'Origin': origin})
        try:
            client.open(login, timeout=15).close()
            raise AssertionError('expected login redirect')
        except urllib.error.HTTPError as e:
            assert e.code == 302, 'login failed'
            e.close()
        assert public('GET', '/api/v1/management/users') == 200
        management('PUT', 'users', {'subject': subjects[0], 'role': 'user'})
        assert public('GET', '/api/v1/management/users') == 403
        assert public('DELETE', '/me/keys/' + keys[1]['id']) in (403, 404), 'demoted session revoked foreign key'
        assert maas(subjects[1], 'GET', '/' + keys[1]['id'])['status'] == 'active'
        assert public('DELETE', '/me/keys/' + keys[0]['id']) == 200
        print('PASS: demoted session denied admin API and foreign revocation; own revocation succeeds')
    finally:
        for subject, key in zip(subjects, keys):
            try:
                maas(subject, 'DELETE', '/' + key['id'])
            except urllib.error.HTTPError as error:
                if error.code != 404:
                    raise
                error.close()
        for subject in created:
            management('PUT', 'users', {'subject': subject, 'active': False})


if __name__ == '__main__':
    main()
