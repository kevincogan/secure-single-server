#!/usr/bin/env python3
"""Exercise SSH key/budget scripts and dashboard APIs on a mock-only RHEL host."""
import argparse
import http.cookiejar
import importlib.machinery
import importlib.util
import json
import os
import pwd
from pathlib import Path
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True, help='new private directory for test keys and sanitized evidence')
    args = p.parse_args()
    if os.geteuid() != 0:
        p.error('run with sudo on the mock RHEL host')
    loader = importlib.machinery.SourceFileLoader('benchmark', str(ROOT / 'scripts/pricetag/benchmark'))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    module.require_mock(Path('/etc/praxis-pricetag'))
    os.umask(0o077)
    args.output.mkdir(mode=0o700)
    checks = []
    url = 'https://localhost:8443'
    origin = next(line.split('=', 1)[1] for line in Path('/etc/praxis-pricetag/metering.env').read_text().splitlines() if line.startswith('MANAGEMENT_PUBLIC_ORIGIN='))
    models = json.loads(Path('/etc/praxis-pricetag/models.json').read_text())
    selected = next((m for m in models if m['id'] != m['model'] and set(m['apis']) == {'openai', 'anthropic'}), None)
    if selected is None:
        p.error('acceptance requires a dual-API model alias; install mock mode with --demo-fixture')
    tls = ssl.create_default_context(cafile='/etc/praxis-pricetag/ca.pem')
    noauth = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                         urllib.request.HTTPSHandler(context=tls))

    def check(name, condition):
        checks.append({'check': name, 'passed': bool(condition)})
        (args.output / 'checks.json').write_text(json.dumps(checks, indent=2) + '\n')
        if not condition:
            raise RuntimeError(name)
        print('PASS: ' + name, flush=True)

    def request(opener, path, data=None, method=None, headers=None):
        payload = None if data is None else json.dumps(data).encode()
        req = urllib.request.Request(url + path, payload, method=method,
            headers={'Content-Type': 'application/json', 'Origin': origin, **(headers or {})})
        try:
            with opener.open(req, timeout=30) as response:
                raw = response.read()
                return response.status, json.loads(raw) if 'application/json' in response.headers.get('Content-Type', '') else raw.decode()
        except urllib.error.HTTPError as error:
            return error.code, None

    def login(key):
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                    urllib.request.HTTPCookieProcessor(jar), urllib.request.HTTPSHandler(context=tls))
        req = urllib.request.Request(url + '/login', urllib.parse.urlencode({'api_key': key}).encode(),
              headers={'Origin': origin, 'Content-Type': 'application/x-www-form-urlencoded'})
        try:
            opener.open(req, timeout=15)
        except urllib.error.HTTPError as error:
            check('login creates a session', error.code == 302 and any(c.name == 'metering_session' for c in jar))
        return opener

    def user(*options):
        subprocess.run([sys.executable, str(ROOT / 'scripts/pricetag/user'), *options],
                       check=True, stdout=subprocess.DEVNULL, cwd='/tmp')

    subject = 'perf-accept-' + uuid.uuid4().hex[:10]
    keyfile = args.output / 'first.key'
    user('--subject', subject, '--name', 'Acceptance user', '--monthly-usd', '5', '--output', str(keyfile))
    key = keyfile.read_text().strip()
    browser = login(key)
    admin = login(Path('/root/pricetag-admin/admin.key').read_text().strip())
    check('admin page loads', request(admin, '/admin')[0] == 200)
    check('personal dashboard available', request(browser, '/dashboard')[0] == 200)
    check('personal dashboard API available', request(browser, '/api/v1/dashboard/overview')[0] == 200)
    check('own key management available', request(browser, '/me/keys')[0] == 200)
    check('ordinary user cannot open admin page', request(browser, '/admin')[0] == 403)
    check('ordinary user cannot list partner users', request(browser, '/api/v1/admin/partner-users')[0] == 403)
    check('ordinary user cannot edit safety net', request(browser, '/api/v1/admin/safety-net',
                                                          {'default_monthly_usd': 10000}, 'PUT')[0] == 403)
    for path in ('/api/v1/admin/keys', '/routing', '/api/v1/users'):
        check('unconfigured or private route denied: ' + path, request(admin, path)[0] == 404)
    check('admin dashboard API available', request(admin, '/api/v1/dashboard/overview')[0] == 200)
    check('admin safety net available', request(admin, '/api/v1/admin/safety-net')[0] == 200)

    check('admin model suggestions available', request(admin, '/api/v1/admin/models')[0] == 200)
    check('ordinary user cannot read admin model suggestions',
          request(browser, '/api/v1/admin/models')[0] == 403)
    try:
        noauth.open(url + '/api/v1/admin/models', timeout=30)
        anonymous_denied = False
    except urllib.error.HTTPError as error:
        anonymous_denied = (error.code in (401, 403) or
                            (error.code == 302 and error.headers.get('Location') == '/login'))
    check('anonymous cannot read admin model suggestions', anonymous_denied)

    def sql(query):
        uid = pwd.getpwnam('praxis-svc').pw_uid
        result = subprocess.run(['sudo', '-u', 'praxis-svc', 'env', f'XDG_RUNTIME_DIR=/run/user/{uid}',
                    'podman', 'exec', 'pricetag-db', 'psql', '-X', '-qAt', '-U', 'metering', '-d', 'metering',
                    '-v', 'ON_ERROR_STOP=1', '-c', query], cwd='/tmp', check=True, text=True, capture_output=True)
        return result.stdout.strip()

    def allowance():
        return float(sql(f"SELECT monthly_usd FROM quota_overrides WHERE scope='user' AND principal='{subject}'"))

    def spend():
        return int(sql(f"SELECT count(*) FROM usage_events WHERE username='{subject}' AND status_code < 400"))

    check('SSH user has exactly one partner login', int(sql(
        f"SELECT count(*) FROM partner_user_logins WHERE username='{subject}'")) == 1)
    check('personal allowance is five dollars', allowance() == 5)

    def maas(path, body=None, who=subject, method=None):
        req = urllib.request.Request('http://127.0.0.1:18086' + path,
             None if body is None else json.dumps(body).encode(), method=method,
             headers={'Content-Type': 'application/json', 'X-MaaS-Username': who,
                      'X-MaaS-Group': '["system:authenticated"]'})
        try:
            with noauth.open(req, timeout=15) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            return error.code, None

    def keys():
        return maas('/v1/api-keys/search', {'filters': {'status': ['active']}})[1]['data']

    before = keys()
    user('--subject', subject, '--monthly-usd', '7', '--no-key')
    check('budget-only update does not issue a key', keys() == before)
    check('budget-only update reaches the login allowance', allowance() == 7)
    check('another subject cannot inspect the key', maas('/v1/api-keys/' + before[0]['id'],
                                                        who=subject + '-other')[0] in (403, 404))
    check('lifetime above 90 days rejected', maas('/v1/api-keys', {'name': 'too-long', 'expiresIn': '91d'})[0] == 400)
    body = {'model': selected['id'], 'messages': [{'role': 'user', 'content': 'synthetic acceptance'}], 'max_tokens': 16}
    check('anonymous inference rejected', request(noauth, '/v1/chat/completions', body)[0] == 401)
    check('key inference succeeds', request(noauth, '/v1/chat/completions', body,
                                          headers={'Authorization': 'Bearer ' + key})[0] == 200)
    # Verify the deployed alias contract without modifying native gateway files.
    for path, auth_headers in [('/v1/chat/completions', {'Authorization': 'Bearer ' + key}),
                               ('/v1/messages', {'x-api-key': key, 'anthropic-version': '2023-06-01'})]:
        check('registered alias accepted: ' + path, request(noauth, path, body, headers=auth_headers)[0] == 200)
        bare = dict(body, model=selected['model'])
        check('bare upstream ID denied: ' + path, request(noauth, path, bare, headers=auth_headers)[0] in (403, 404))
        check('spoofed model header denied: ' + path, request(noauth, path, bare,
              headers={**auth_headers, 'X-Gateway-Model': selected['id']})[0] in (403, 404))
        check('unknown alias denied: ' + path, request(noauth, path, dict(body, model='unknown/model'),
              headers=auth_headers)[0] in (403, 404))
        check('alias still requires authentication: ' + path, request(noauth, path, body)[0] == 401)
    for _ in range(30):
        spending = spend()
        if spending > 0:
            break
        time.sleep(1)
    check('personal spend recorded', spending > 0)
    user('--subject', subject, '--rotate', '--key-lifetime', '30d', '--output', str(args.output / 'next.key'))
    check('rotation rejects old key', request(noauth, '/v1/chat/completions', body,
                                             headers={'Authorization': 'Bearer ' + key})[0] == 401)
    next_browser = login((args.output / 'next.key').read_text().strip())
    check('rotation preserves spend and allowance', spend() == spending and allowance() == 7)
    active = keys()
    check('rotation leaves one active key', len(active) == 1)
    subprocess.run([sys.executable, str(ROOT / 'scripts/pricetag/maas-key'), 'revoke',
                    '--subject', subject, '--key-id', active[0]['id']], check=True, stdout=subprocess.DEVNULL)
    check('revoked replacement rejected', request(noauth, '/v1/chat/completions', body,
          headers={'Authorization': 'Bearer ' + (args.output / 'next.key').read_text().strip()})[0] == 401)
    check('known gap: existing browser session survives key revocation',
          request(next_browser, '/api/v1/whoami')[0] == 200)
    print('Evidence: ' + str(args.output / 'checks.json'))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        raise SystemExit('Acceptance stopped: ' + type(error).__name__ + '; inspect sanitized checks.json') from None
