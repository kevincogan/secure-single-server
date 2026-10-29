#!/usr/bin/env python3
"""Read-only public route/authentication inventory on the deployed mock gateway."""
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import ssl
import sys
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/pricetag'))
import gateway
from metering_admin import NoRedirect


def main():
    loader = importlib.machinery.SourceFileLoader('benchmark', str(ROOT / 'scripts/pricetag/benchmark'))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    benchmark = importlib.util.module_from_spec(spec)
    loader.exec_module(benchmark)
    deploy = Path('/etc/praxis-pricetag')
    benchmark.require_mock(deploy)
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(deploy / 'ca.pem'))))
    spoof = {'X-Forwarded-User': 'admin', 'X-Forwarded-Real-User': 'admin',
             'X-Forwarded-Groups': 'super_admin', 'X-MaaS-Username': 'admin',
             'X-MaaS-Group': '["single-server-admin"]', 'X-Tenant-Username': 'admin',
             'Authorization': 'Bearer invalid-test-key', 'X-Api-Key': 'invalid-test-key'}

    def status(route, method='GET', headers=None):
        request = urllib.request.Request('https://localhost:8443' + route,
            data=b'{}' if method == 'POST' else None, method=method,
            headers={'Content-Type': 'application/json', **(headers or {})})
        try:
            with client.open(request, timeout=15) as response:
                body = response.read()
                return response.status, body
        except urllib.error.HTTPError as error:
            code = error.code
            error.close()
            return code, b''

    # Login/welcome and logout confirmation are deliberately public navigation.
    navigation = {'/', '/login', '/welcome', '/logout', '/me'}
    protected = [p for p in gateway.DASHBOARD if p not in navigation]
    protected += ['/api/v1/management/' + p for p in
                  ('users', 'budgets', 'prices', 'policy', 'keys')]
    protected += ['/me/keys/test-id', '/api/v1/admin/partner-users/test-id',
                  '/api/v1/admin/pricing/reprice/test-id']
    for headers in ({}, spoof):
        for route in protected:
            code, _ = status(route, headers=headers)
            assert code in (301, 302, 303, 307, 308, 401, 403), (route, code)
        for route in gateway.INFERENCE + ['/v1/messages/count_tokens']:
            code, _ = status(route, 'POST', headers)
            assert code == 401, (route, code)
    print(f'PASS: {len(protected)} protected routes deny anonymous and spoofed identity access; inference requires keys')
    for route in ('/api/v1/events', '/api/v1/customers/test', '/api/v1/users',
                  '/api/v1/admin/keys', '/internal/v1/api-keys/validate', '/v1/api-keys',
                  '/metrics', '/health', '/ready', '/routing', '/api/v1/admin/config'):
        for method in ('GET', 'POST'):
            code, _ = status(route, method, spoof)
            assert code == 404, (method, route, code)
    print('PASS: internal accounting, MaaS, legacy Kubernetes configuration and diagnostic routes are not exposed')
    code, body = status('/v1/models')
    assert code == 200
    catalog = json.loads(body)
    assert all(m['id'].startswith('mock/') for m in catalog['data'])
    assert not any(word in body.lower() for word in
                   (b'api_key', b'credential', b'password', b'http://', b'https://', b'/run/secrets'))
    print('PASS: public static model catalog contains mock model metadata, no endpoints or credentials')


if __name__ == '__main__':
    main()
