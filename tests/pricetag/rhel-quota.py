#!/usr/bin/env python3
"""Reach a USD allowance using real mock requests, then verify recovery."""
import argparse
import importlib.machinery
import importlib.util
import json
import math
import os
from pathlib import Path
import pwd
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', required=True, type=Path)
    args = p.parse_args()
    if os.geteuid() != 0:
        p.error('run with sudo on the mock host')
    loader = importlib.machinery.SourceFileLoader('benchmark', str(ROOT / 'scripts/pricetag/benchmark'))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    benchmark = importlib.util.module_from_spec(spec)
    loader.exec_module(benchmark)
    benchmark.require_mock(Path('/etc/praxis-pricetag'))
    os.umask(0o077)
    args.output.mkdir(mode=0o700)
    subject = 'perf-quota-' + uuid.uuid4().hex[:10]
    keyfile = args.output / 'user.key'
    user = [sys.executable, str(ROOT / 'scripts/pricetag/user'), '--subject', subject]
    subprocess.run(user + ['--monthly-usd', '0.01', '--output', str(keyfile)], check=True, cwd='/tmp')
    uid = pwd.getpwnam('praxis-svc').pw_uid
    sql = "SELECT (2*input_cost_per_mtok+3*output_cost_per_mtok)/1000000 FROM model_pricing WHERE model='fixture'"
    result = subprocess.run(['sudo', '-u', 'praxis-svc', 'env', f'XDG_RUNTIME_DIR=/run/user/{uid}',
             'podman', 'exec', 'pricetag-db', 'psql', '-X', '-qAt', '-U', 'metering', '-d', 'metering', '-c', sql],
             check=True, capture_output=True, text=True, cwd='/tmp')
    cost = float(result.stdout.strip())
    if not math.isfinite(cost) or cost <= 0:
        raise ValueError('fixture must have a positive reviewed price')
    count = math.ceil(.01 / cost) + 2
    if count > 5000:
        raise ValueError('fixture price would require more than 5000 requests')
    key = keyfile.read_text().strip()
    tls = ssl.create_default_context(cafile='/etc/praxis-pricetag/ca.pem')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=tls))
    data = json.dumps({'model': 'fixture', 'messages': [{'role': 'user', 'content': 'synthetic quota probe'}],
                       'max_tokens': 16}).encode()

    def request(token=key):
        req = urllib.request.Request('https://localhost:8443/v1/chat/completions', data,
            headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token})
        try:
            with opener.open(req, timeout=15) as r:
                r.read()
                return r.status
        except urllib.error.HTTPError as e:
            return e.code

    passed = []
    def check(label, condition):
        passed.append({'check': label, 'passed': bool(condition)})
        (args.output / 'checks.json').write_text(json.dumps(passed, indent=2) + '\n')
        if not condition:
            raise ValueError(label)
        print('PASS: ' + label, flush=True)

    # Stay below the gateway's 30 requests/s transport limit: this test must
    # demonstrate USD enforcement, not exhaust the shared rate-limit bucket.
    time.sleep(5)
    successes = 0
    for _ in range(count):
        status = request()
        if status == 429:
            break
        if status != 200:
            raise ValueError(f'unexpected inference HTTP {status}')
        successes += 1
        time.sleep(.075)
    check('inference allowed below the USD limit', successes > 0)
    for _ in range(45):
        status = request()
        if status == 429:
            break
        if status != 200:
            raise ValueError(f'unexpected inference HTTP {status}')
        time.sleep(1)
    check('recorded mock usage triggers HTTP 429', status == 429)
    spend_sql = f"SELECT COALESCE(sum(cost_usd),0) FROM usage_events WHERE username='{subject}' AND status_code < 400"
    spent = subprocess.run(['sudo', '-u', 'praxis-svc', 'env', f'XDG_RUNTIME_DIR=/run/user/{uid}',
             'podman', 'exec', 'pricetag-db', 'psql', '-X', '-qAt', '-U', 'metering', '-d', 'metering', '-c', spend_sql],
             check=True, capture_output=True, text=True, cwd='/tmp')
    check('ledger spend reached the USD allowance', float(spent.stdout.strip()) >= .01)
    time.sleep(5)
    check('another user remains permitted', request(Path('/root/pricetag-admin/bob.key').read_text().strip()) == 200)
    subprocess.run(user + ['--monthly-usd', '1', '--no-key'], check=True, cwd='/tmp')
    for _ in range(30):
        status = request()
        if status == 200:
            break
        time.sleep(1)
    check('raising the allowance restores the existing key', status == 200)
    print('Evidence: ' + str(args.output / 'checks.json'))


if __name__ == '__main__':
    main()
