#!/usr/bin/env python3
"""Exercise global post-budget exceptions through APIs and mock inference only.

Temporarily changes the global safety-net policy and restores it in finally.
Run without other benchmark traffic. No business-table SQL writes are used.
"""
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
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    if os.geteuid() != 0:
        p.error('run as root on an idle mock benchmark host')
    loader = importlib.machinery.SourceFileLoader('benchmark', str(ROOT / 'scripts/pricetag/benchmark'))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    benchmark = importlib.util.module_from_spec(spec)
    loader.exec_module(benchmark)
    benchmark.require_mock(Path('/etc/praxis-pricetag'))
    os.umask(0o077)
    args.output.mkdir(mode=0o700)
    base = 'https://localhost:8443'
    origin = next(line.split('=', 1)[1] for line in Path('/etc/praxis-pricetag/metering.env').read_text().splitlines() if line.startswith('MANAGEMENT_PUBLIC_ORIGIN='))
    model = json.loads(Path('/etc/praxis-pricetag/models.json').read_text())[0]
    tls = ssl.create_default_context(cafile='/etc/praxis-pricetag/ca.pem')
    jar = http.cookiejar.CookieJar()
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
        urllib.request.HTTPSHandler(context=tls), urllib.request.HTTPCookieProcessor(jar))

    def call(path, method='GET', body=None, headers=None):
        req = urllib.request.Request(base + path,
            None if body is None else json.dumps(body).encode(), method=method,
            headers={'Origin': origin, 'Content-Type': 'application/json', **(headers or {})})
        try:
            with client.open(req, timeout=20) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            error.close()
            return error.code, None

    key = Path('/root/pricetag-admin/admin.key').read_text().strip()
    req = urllib.request.Request(base + '/login',
        urllib.parse.urlencode({'api_key': key}).encode(), headers={'Origin': origin})
    try:
        client.open(req, timeout=15).close()
    except urllib.error.HTTPError as error:
        if error.code != 302 or not any(c.name == 'metering_session' for c in jar):
            raise RuntimeError('admin login failed') from None
    policy_path = '/api/v1/admin/safety-net'
    status, original = call(policy_path)
    if status != 200:
        raise RuntimeError('cannot read original policy')
    restore = {k: original[k] for k in ('default_monthly_usd', 'enforced', 'allowed_over_limit_models')}
    # Persist only non-secret policy for recovery if the process is interrupted.
    (args.output / 'original-policy.json').write_text(json.dumps(restore) + '\n')
    subject = 'over-budget-' + uuid.uuid4().hex[:10]
    keyfile = args.output / 'user.key'
    subprocess.run([sys.executable, str(ROOT / 'scripts/pricetag/user'),
        '--subject', subject, '--key-lifetime', '1h', '--output', str(keyfile)],
        check=True, stdout=subprocess.DEVNULL, cwd='/tmp')
    user_key = keyfile.read_text().strip()
    observations = []

    def infer(label, spoof=None):
        headers = {'Authorization': 'Bearer ' + user_key, **(spoof or {})}
        status, _ = call('/v1/chat/completions', 'POST',
            {'model': model['id'], 'messages': [{'role': 'user', 'content': 'quota test'}],
             'max_tokens': 16}, headers)
        observations.append({'case': label, 'status': status})
        if not label.startswith('spend probe') or status != 200:
            print(label + ': HTTP ' + str(status), flush=True)
        return status

    try:
        status, _ = call(policy_path, 'PUT', {'default_monthly_usd': 0.01,
                         'enforced': True, 'allowed_over_limit_models': []})
        if status != 200:
            raise RuntimeError('policy update failed')
        if infer('initial request') != 200:
            raise RuntimeError('fresh user must start below budget')
        for attempt in range(1200):
            time.sleep(.05)
            if infer('spend probe ' + str(attempt + 1)) == 429:
                break
        time.sleep(17)
        denied = infer('over budget without exception')
        status, _ = call(policy_path, 'PUT', {'allowed_over_limit_models': [model['model']]})
        if status != 200:
            raise RuntimeError('exception update failed')
        time.sleep(17)
        allowed = infer('over budget with exact exception')
        status, _ = call(policy_path, 'PUT', {'allowed_over_limit_models': ['different-model']})
        if status != 200:
            raise RuntimeError('exception replacement failed')
        time.sleep(17)
        spoofed = infer('different exception cannot be selected by spoofed headers',
            {'X-Model': 'different-model', 'X-Gateway-Model': 'different-model'})
        (args.output / 'observations.json').write_text(json.dumps(observations, indent=2) + '\n')
        if (denied, allowed) != (429, 200) or spoofed not in (403, 429):
            raise RuntimeError('post-budget exception contract failed; inspect sanitized observations')
    finally:
        status, _ = call(policy_path, 'PUT', restore)
        if status != 200:
            raise RuntimeError('RESTORE FAILED: restore original-policy.json through the admin API')
        print('Original global safety-net policy restored.', flush=True)


if __name__ == '__main__':
    main()
