#!/usr/bin/env python3
"""Create an opt-in 20-user mock demo through APIs; never writes business SQL.

Run on the dedicated benchmark host. Keys remain in a root-only output directory.
A manifest records stable profile IDs and key IDs, not secret values.
"""
import argparse
import http.cookiejar
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


class APIError(ValueError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', default='demo-team')
    parser.add_argument('--resume', action='store_true')
    parser.add_argument('--cleanup', action='store_true', help='suspend fixture users, revoke fixture keys, retain accounting history')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--requests-per-model', type=int, default=3, choices=range(1, 101))
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run with sudo on the benchmark host')
    if not re.fullmatch(r'demo-[a-z0-9-]{1,30}', args.prefix):
        parser.error('prefix must start demo- and contain lowercase letters, digits or hyphens')
    if args.output.exists() and not (args.resume or args.cleanup):
        parser.error('output already exists; use --resume to reuse its manifest and keys')
    os.umask(0o077)
    deploy = Path('/etc/praxis-pricetag')
    import importlib.machinery
    import importlib.util
    loader = importlib.machinery.SourceFileLoader('demo_benchmark', str(Path(__file__).resolve().parents[2] / 'scripts/pricetag/benchmark'))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    benchmark = importlib.util.module_from_spec(spec)
    loader.exec_module(benchmark)
    benchmark.require_mock(deploy)
    context = ssl.create_default_context(cafile=str(deploy / 'ca.pem'))
    origin = next(line.split('=', 1)[1] for line in (deploy / 'metering.env').read_text().splitlines()
                  if line.startswith('MANAGEMENT_PUBLIC_ORIGIN='))
    base = 'https://localhost:8443'
    jar = http.cookiejar.CookieJar()
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
        urllib.request.HTTPSHandler(context=context), urllib.request.HTTPCookieProcessor(jar))
    def call(method, route, body=None, key=None):
        time.sleep(0.06)  # Stay below the public listener rate limit.
        headers = {'Origin': origin, 'Content-Type': 'application/json'}
        if key:
            headers['Authorization'] = 'Bearer ' + key
        req = urllib.request.Request(base + route, None if body is None else json.dumps(body).encode(),
                                     method=method, headers=headers)
        try:
            with client.open(req, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            raise APIError(f'{method} {route.split("?")[0]} returned HTTP {error.code}') from None
    admin = Path('/root/pricetag-admin/admin.key').read_text().strip()
    request = urllib.request.Request(base + '/login', urllib.parse.urlencode({'api_key': admin}).encode(),
                                     headers={'Origin': origin})
    try:
        client.open(request, timeout=20).close()
    except urllib.error.HTTPError as error:
        if error.code != 302 or not any(c.name == 'metering_session' for c in jar):
            raise ValueError('administrator login failed') from None
    expected = {'mock/fixture', 'mock/demo-cheap'}
    if not expected <= {m['id'] for m in json.loads((deploy / 'models.json').read_text())}:
        raise ValueError('install the synthetic demo provider configuration first')
    if args.resume or args.cleanup:
        if args.output.is_symlink() or args.output.stat().st_mode & 0o077:
            raise ValueError('fixture directory must be private')
        manifest = json.loads((args.output / 'manifest.json').read_text())
        if manifest.get('prefix') != args.prefix or not manifest.get('synthetic') or manifest.get('requests_per_model', 3) != args.requests_per_model:
            raise ValueError('resume inputs differ from the fixture')
    else:
        args.output.mkdir(mode=0o700)
        manifest = {'synthetic': True, 'prefix': args.prefix, 'users': [], 'requests': 0, 'requests_per_model': args.requests_per_model}
    def save():
        (args.output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    save()
    if args.cleanup:
        profiles = {row['user_id']: row for row in call('GET', '/api/v1/management/users')}
        for index, user in enumerate(manifest['users']):
            subject = f'{args.prefix}-{index + 1:02d}'
            if (user['subject'] != subject or user['user_id'] not in profiles or
                    subject not in profiles[user['user_id']].get('logins', [])):
                raise ValueError('fixture identity does not match the current directory')
            call('PUT', '/api/v1/management/users', {'subject': subject, 'active': False})
            if not user.get('key_revoked'):
                subprocess.run([sys.executable, str(Path(__file__).resolve().parents[2] / 'scripts/pricetag/maas-key'),
                    'revoke', '--subject', subject, '--key-id', user['key_id']],
                    check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd='/tmp')
                user['key_revoked'] = True
                save()
            (args.output / (subject + '.key')).unlink(missing_ok=True)
        manifest['cleaned'] = True
        save()
        print('Fixture accounts suspended; fixture keys revoked and local key files removed. Accounting history retained.')
        return
    if manifest.get('cleaned'):
        raise ValueError('fixture was cleaned; use a new prefix/output for another demo')
    for index in range(20):
        if index < len(manifest['users']):
            continue
        subject = f'{args.prefix}-{index + 1:02d}'
        profile = call('PUT', '/api/v1/management/users', {'subject': subject, 'name': f'Demo person {index + 1:02d}', 'role': 'user'})
        call('PUT', '/api/v1/management/budgets', {'subject': subject, 'monthly_usd': 5})
        issued = call('POST', '/api/v1/management/keys', {'subject': subject, 'name': 'mock-demo', 'expiresIn': '30d'})
        (args.output / (subject + '.key')).write_text(issued['key'] + '\n')
        manifest['users'].append({'subject': subject, 'user_id': profile['user_id'], 'key_id': issued['id'],
                                  'manager': index in (0, 10), 'team': 1 if index < 10 else 2})
        save()
    for index, user in enumerate(manifest['users']):
        leader = manifest['users'][0 if index < 10 else 10]
        manager = None if user['manager'] else leader['user_id']
        call('PATCH', '/api/v1/admin/partner-users/' + user['user_id'], {'role': 'user', 'manager_user_id': manager})
        user['manager_user_id'] = manager
        save()
    # Traffic is synthetic; rates and budgets remain administrator-managed.
    ordinal = 0
    for index, user in enumerate(manifest['users']):
        key = (args.output / (user['subject'] + '.key')).read_text().strip()
        for model in sorted(expected):
            count = args.requests_per_model * (2 if index % 3 == 0 and model == 'mock/fixture' else 1)
            for _ in range(count):
                ordinal += 1
                if ordinal <= manifest['requests']:
                    continue
                call('POST', '/v1/chat/completions', {'model': model,
                     'messages': [{'role': 'user', 'content': 'synthetic dashboard demonstration'}],
                     'max_completion_tokens': 16}, key=key)
                manifest['requests'] += 1
                save()
    print(f'Created 20 synthetic users in two teams; completed {manifest["requests"]} mock requests.')
    print('Private fixture manifest and keys: ' + str(args.output))


if __name__ == '__main__':
    try:
        main()
    except APIError as error:
        raise SystemExit(str(error) + '; partial fixture preserved for --resume. No credentials printed.') from None
    except (OSError, ValueError, subprocess.CalledProcessError):
        raise SystemExit('Demo setup failed; partial manifest and keys are preserved. No credential values printed.') from None
