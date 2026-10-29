#!/usr/bin/env python3
"""Mock-only global USD exception/token-gate check using synthetic API events.

Run on an idle benchmark host. Retains labelled synthetic accounting history,
restores global policy, suspends test identities, and deletes local test keys.
This tests enforcement; browser-pricing.cjs separately tests the UI controls.
"""
import argparse
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
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/pricetag'))
import metering_admin


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run as root on the mock benchmark host')
    loader = importlib.machinery.SourceFileLoader('benchmark', str(ROOT / 'scripts/pricetag/benchmark'))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    benchmark = importlib.util.module_from_spec(spec)
    loader.exec_module(benchmark)
    deploy = Path('/etc/praxis-pricetag')
    benchmark.require_mock(deploy)
    env = dict(line.split('=', 1) for line in (deploy / 'metering.env').read_text().splitlines()
               if '=' in line and not line.startswith('#'))
    assert env.get('MONTHLY_TOKEN_QUOTA') == '10000000000', 'expected the shipped 10B token gate'
    models = json.loads((deploy / 'models.json').read_text())
    model = next(m for m in models if m['id'] == 'mock/demo-cheap')
    os.umask(0o077)
    args.output.mkdir(mode=0o700)
    original = metering_admin.request('GET', 'policy')
    restore = {k: original[k] for k in ('default_monthly_usd', 'enforced', 'allowed_over_limit_models')}
    (args.output / 'original-policy.json').write_text(json.dumps(restore) + '\n')
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}), metering_admin.NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(deploy / 'ca.pem'))))

    def call(url, body, key):
        request = urllib.request.Request(url, json.dumps(body).encode(),
            headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + key})
        try:
            with client.open(request, timeout=30) as response:
                response.read()
                return response.status
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()
            return status

    run = uuid.uuid4().hex[:10]
    subjects = []
    credentials = {}
    observations = []
    m2m = (deploy / 'm2m-secret').read_text().strip()

    def event(subject, billed_model, tokens):
        assert call('http://127.0.0.1:18087/api/v1/events', {
            'specversion': '1.0', 'id': str(uuid.uuid4()),
            'source': 'synthetic-quota-matrix', 'type': 'inference.usage',
            'data': {'user': subject, 'model': billed_model, 'provider': 'mock',
                     'prompt_tokens': tokens, 'completion_tokens': 0, 'total_tokens': tokens}}, m2m) == 204

    def check(label, expected):
        statuses = []
        for subject in subjects:
            statuses.append(call('https://localhost:8443/v1/chat/completions', {
                'model': model['id'], 'messages': [{'role': 'user', 'content': 'synthetic quota matrix'}],
                'max_completion_tokens': 16}, credentials[subject]))
        observations.append({'case': label, 'statuses': statuses, 'expected': expected})
        (args.output / 'observations.json').write_text(json.dumps(observations, indent=2) + '\n')
        assert statuses == expected, f'{label}: expected {expected}, received {statuses}'
        print('PASS: ' + label + ': ' + str(statuses), flush=True)

    try:
        for suffix in ('usd-a', 'usd-b', 'token'):
            subject = 'synthetic-quota-' + run + '-' + suffix
            subjects.append(subject)
            output = args.output / (subject + '.key')
            subprocess.run([sys.executable, str(ROOT / 'scripts/pricetag/user'), '--subject', subject,
                '--name', 'Synthetic enforcement test ' + suffix, '--monthly-usd', '0.01',
                '--key-lifetime', '1h', '--output', str(output)], check=True, stdout=subprocess.DEVNULL)
            credentials[subject] = output.read_text().strip()
        for kind, rate in (('paid', 1), ('zero', 0)):
            metering_admin.request('PUT', 'prices', {'model': run + '-' + kind, 'provider': 'mock',
                'input_cost_per_mtok': rate, 'output_cost_per_mtok': rate,
                'cache_write_cost_per_mtok': rate, 'cache_read_cost_per_mtok': rate})
        for subject in subjects[:2]:
            event(subject, run + '-paid', 20000)  # $0.02, above each $0.01 allowance.
        for _ in range(5):
            event(subjects[2], run + '-zero', 2000000000)  # 10B tokens, $0; bounded INTEGER fields.
        metering_admin.request('PUT', 'policy', {**restore, 'enforced': True, 'allowed_over_limit_models': []})
        time.sleep(17)
        check('no exception blocks both USD users and the zero-dollar token-exhausted user', [429, 429, 429])
        metering_admin.request('PUT', 'policy', {'allowed_over_limit_models': [model['model']]})
        time.sleep(17)
        check('one global exception admits both USD users but cannot bypass the token gate', [200, 200, 429])
        metering_admin.request('PUT', 'policy', {'allowed_over_limit_models': [model['id']]})
        time.sleep(17)
        check('public alias does not replace the billed upstream ID in exception policy', [429, 429, 429])
    finally:
        # Restore policy first; do not hide a failed restoration behind cleanup.
        metering_admin.request('PUT', 'policy', restore)
        for subject in subjects:
            metering_admin.request('PUT', 'users', {'subject': subject, 'active': False})
            (args.output / (subject + '.key')).unlink(missing_ok=True)
        print('Global policy restored; synthetic identities suspended, key files removed; history retained.', flush=True)


if __name__ == '__main__':
    main()
