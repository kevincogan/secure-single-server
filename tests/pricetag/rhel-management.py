#!/usr/bin/env python3
"""Record management capability boundaries on a mock-only RHEL deployment.

This is a non-mutating baseline probe, not completion of management acceptance.
Response bodies, cookies and credentials are never written to the report.
"""
import argparse
import http.cookiejar
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import ssl
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[2]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run with sudo on the mock benchmark host')
    loader = importlib.machinery.SourceFileLoader('benchmark', str(ROOT / 'scripts/pricetag/benchmark'))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    benchmark = importlib.util.module_from_spec(spec)
    loader.exec_module(benchmark)
    benchmark.require_mock(Path('/etc/praxis-pricetag'))
    os.umask(0o077)
    args.output.mkdir(mode=0o700)
    tls = ssl.create_default_context(cafile='/etc/praxis-pricetag/ca.pem')
    base = 'https://localhost:8443'
    origin = next(line.split('=', 1)[1] for line in Path('/etc/praxis-pricetag/metering.env').read_text().splitlines() if line.startswith('MANAGEMENT_PUBLIC_ORIGIN='))
    results = []
    for role in ('anonymous', 'alice', 'admin'):
        jar = http.cookiejar.CookieJar()
        client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                    urllib.request.HTTPSHandler(context=tls), urllib.request.HTTPCookieProcessor(jar))
        if role != 'anonymous':
            key = Path('/root/pricetag-admin', role + '.key').read_text().strip()
            req = urllib.request.Request(base + '/login',
                    urllib.parse.urlencode({'api_key': key}).encode(),
                    headers={'Origin': origin})
            try:
                client.open(req, timeout=15).close()
            except urllib.error.HTTPError as error:
                if error.code != 302 or not any(c.name == 'metering_session' for c in jar):
                    raise RuntimeError('login failed for ' + role) from None
        for path in ('/dashboard', '/manager', '/api/v1/dashboard/overview', '/api/v1/org/scope',
                     '/api/v1/admin/partner-users', '/api/v1/admin/safety-net',
                     '/me/keys', '/api/v1/admin/keys', '/api/v1/users', '/api/v1/events'):
            request = urllib.request.Request(base + path, headers={'Origin': origin,
                'X-MaaS-Username': 'admin', 'X-Tenant-Username': 'admin',
                'X-Forwarded-User': 'admin'})
            try:
                with client.open(request, timeout=15) as response:
                    status = response.status
                    body = response.read(2_000_000)
            except urllib.error.HTTPError as error:
                status = error.code
                body = error.read(2_000_000)
            results.append({'role': role, 'path': path, 'status': status,
                            'coming_soon': b'Dashboard coming soon' in body})
    (args.output / 'observations.json').write_text(json.dumps(results, indent=2) + '\n')
    for row in results:
        print(f"{row['role']}: {row['path']} -> {row['status']}" +
              (' (coming-soon page)' if row['coming_soon'] else ''))
    # Negative authorization must pass even before functionality is enabled.
    failures = [r for r in results if r['role'] in ('anonymous', 'alice') and
                r['path'] in ('/api/v1/admin/partner-users', '/api/v1/admin/safety-net') and
                r['status'] not in (302, 401, 403)]
    if failures:
        raise RuntimeError('management authorization regression; inspect sanitized observations')


if __name__ == '__main__':
    main()
