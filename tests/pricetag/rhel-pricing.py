#!/usr/bin/env python3
"""Check pricing administration through HTTPS on the mock-only RHEL gateway."""
import argparse
import http.cookiejar
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

ROOT = Path(__file__).resolve().parents[2]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run with sudo on the mock RHEL host')
    loader = importlib.machinery.SourceFileLoader('benchmark', str(ROOT / 'scripts/pricetag/benchmark'))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    benchmark = importlib.util.module_from_spec(spec)
    loader.exec_module(benchmark)
    benchmark.require_mock(Path('/etc/praxis-pricetag'))
    os.umask(0o077)
    args.output.mkdir(mode=0o700)
    base = 'https://localhost:8443'
    origin = next(line.split('=', 1)[1] for line in Path('/etc/praxis-pricetag/metering.env').read_text().splitlines() if line.startswith('MANAGEMENT_PUBLIC_ORIGIN='))
    tls = ssl.create_default_context(cafile='/etc/praxis-pricetag/ca.pem')
    checks = []

    def check(name, condition):
        checks.append({'check': name, 'passed': bool(condition)})
        (args.output / 'checks.json').write_text(json.dumps(checks, indent=2) + '\n')
        if not condition:
            raise RuntimeError(name)
        print('PASS: ' + name, flush=True)

    def client(key=None):
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                    urllib.request.HTTPSHandler(context=tls), urllib.request.HTTPCookieProcessor(jar))
        if key:
            req = urllib.request.Request(base + '/login', urllib.parse.urlencode({'api_key': key}).encode(),
                       headers={'Origin': origin, 'Content-Type': 'application/x-www-form-urlencoded'})
            try:
                opener.open(req, timeout=15)
            except urllib.error.HTTPError as error:
                check('login succeeds', error.code == 302 and any(c.name == 'metering_session' for c in jar))
        return opener

    def request(opener, path, method='GET', data=None, headers=None):
        req = urllib.request.Request(base + path, None if data is None else json.dumps(data).encode(),
                method=method, headers={'Origin': origin, 'Content-Type': 'application/json', **(headers or {})})
        try:
            with opener.open(req, timeout=120) as response:
                return response.status, json.load(response), None
        except urllib.error.HTTPError as error:
            return error.code, {'error': error.read(2048).decode(errors='replace')}, error.headers.get('Location')

    subject = 'perf-pricing-' + uuid.uuid4().hex[:10]
    keyfile = args.output / 'user.key'
    subprocess.run([sys.executable, str(ROOT / 'scripts/pricetag/user'), '--subject',
                    subject, '--output', str(keyfile)],
                   check=True, stdout=subprocess.DEVNULL, cwd='/tmp')
    try:
        user = client(keyfile.read_text().strip())
        admin = client(Path('/root/pricetag-admin/admin.key').read_text().strip())
        anonymous = client()
        routes = [('/api/v1/admin/pricing-discounts', 'GET'),
                  ('/api/v1/admin/pricing-discounts', 'PUT'),
                  ('/api/v1/admin/pricing/refresh', 'POST'),
                  ('/api/v1/admin/pricing/reprice', 'POST'),
                  ('/api/v1/admin/pricing/reprice/not-an-operation', 'GET')]
        for path, method in routes:
            data = {} if method != 'GET' else None
            check('ordinary user denied: ' + method + ' ' + path,
                  request(user, path, method, data)[0] == 403)
            status, _, location = request(anonymous, path, method, data,
                                         {'X-MaaS-Username': 'admin', 'X-Tenant-Username': 'admin'})
            check('anonymous/spoofed identity denied: ' + method + ' ' + path,
                  status in (401, 403) or (status == 302 and location == '/login'))

        status, catalog, _ = request(admin, '/api/v1/pricing?used=0')
        check('complete catalog includes unused models', status == 200 and bool(catalog.get('models')))
        status, used, _ = request(user, '/api/v1/pricing')
        check('ordinary user can inspect rate card', status == 200 and isinstance(used.get('models'), list))
        status, policy, _ = request(admin, '/api/v1/admin/pricing-discounts')
        check('admin reads discount policy', status == 200 and bool(policy.get('version')))
        check('invalid policy rejected', request(admin, '/api/v1/admin/pricing-discounts', 'PUT',
              {'version': 'invalid-test', 'rules': [{'name': 'invalid', 'provider': 'openai', 'multiplier': -1}]})[0] == 400)
        status, saved, _ = request(admin, '/api/v1/admin/pricing-discounts', 'PUT', policy)
        check('admin saves unchanged policy', status == 200)
        status, refreshed, _ = request(admin, '/api/v1/admin/pricing/refresh', 'POST', {})
        check('admin refreshes source catalog', status == 200 and not refreshed.get('error'))
        check('discount policy preserved', request(admin, '/api/v1/admin/pricing-discounts')[1] == policy)
        until = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        model = 'fixture-reprice-' + uuid.uuid4().hex[:12]
        event = {'specversion': '1.0', 'id': str(uuid.uuid4()), 'source': 'synthetic-pricing-acceptance', 'type': 'inference.usage',
                 'time': (until - timedelta(minutes=30)).isoformat(),
                 'data': {'user': subject, 'model': model, 'provider': 'mock', 'prompt_tokens': 2, 'completion_tokens': 3, 'total_tokens': 5}}
        ingestion = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with ingestion.open(urllib.request.Request('http://127.0.0.1:18087/api/v1/events', json.dumps(event).encode(), headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + Path('/etc/praxis-pricetag/m2m-secret').read_text().strip()}), timeout=15) as response:
            check('synthetic event accepted through service API', response.status == 204)
        scope = {'model': model, 'from': (until - timedelta(hours=1)).isoformat(),
                 'until': until.isoformat(), 'policy_version': policy['version'], 'confirm': False}
        status, preview, _ = request(admin, '/api/v1/admin/pricing/reprice', 'POST', scope)
        check('historical repricing dry-run available', status == 200 and preview['status'] == 'dry_run' and not preview['applied'])
        check('repricing status available', request(admin, '/api/v1/admin/pricing/reprice/' + preview['operation_id'])[0] == 200)
        check('confirmation requires bound operation and hash', request(admin, '/api/v1/admin/pricing/reprice',
              'POST', dict(scope, confirm=True))[0] == 400)
        check('dry-run remains unapplied', request(admin, '/api/v1/admin/pricing/reprice/' + preview['operation_id'])[1]['status'] == 'dry_run')
        check('preview selects only one synthetic event', preview['rows'] == 1)
        confirm = dict(scope, confirm=True, operation_id=preview['operation_id'], policy_hash=preview['policy_hash'])
        status, applied, _ = request(admin, '/api/v1/admin/pricing/reprice', 'POST', confirm)
        check('bounded historical repricing applied', status == 200 and applied['status'] == 'completed' and applied['applied'])
        status, repeated, _ = request(admin, '/api/v1/admin/pricing/reprice', 'POST', confirm)
        check('repeated confirmation is idempotent', status == 200 and repeated['operation_id'] == preview['operation_id'] and repeated['status'] == 'completed')
        check('completed operation status available', request(admin, '/api/v1/admin/pricing/reprice/' + preview['operation_id'])[1]['status'] == 'completed')
        print('Only the unique synthetic model was repriced; no direct SQL. Evidence: ' + str(args.output / 'checks.json'))
    finally:
        sys.path.insert(0, str(ROOT / 'scripts/pricetag'))
        import metering_admin
        metering_admin.request('PUT', 'users', {'subject': subject, 'active': False})



if __name__ == '__main__':
    main()
