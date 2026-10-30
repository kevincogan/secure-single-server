#!/usr/bin/env python3
"""Exercise documented user/manage/api helpers against a verified mock gateway."""
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/pricetag'))
from metering_admin import request


def main():
    if os.geteuid() != 0:
        raise ValueError('requires root on the mock test host')
    loader = importlib.machinery.SourceFileLoader('benchmark', str(ROOT / 'scripts/pricetag/benchmark'))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    bench = importlib.util.module_from_spec(spec)
    loader.exec_module(bench)
    bench.require_mock(Path('/etc/praxis-pricetag'))
    origin = next(line.split('=', 1)[1] for line in Path('/etc/praxis-pricetag/metering.env').read_text().splitlines()
                  if line.startswith('MANAGEMENT_PUBLIC_ORIGIN='))
    subject = 'demo-cli-' + uuid.uuid4().hex[:12]
    os.umask(0o077)
    def command(*args):
        return subprocess.run([sys.executable, *map(str, args)], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, timeout=45)
    def checked(*args):
        if command(*args).returncode:
            raise RuntimeError('documented CLI operation failed; sensitive output withheld')
    try:
        with tempfile.TemporaryDirectory(prefix='pricetag-cli-', dir='/root') as temporary:
            directory = Path(temporary)
            key = directory / 'user.key'
            checked(ROOT / 'scripts/pricetag/user', '--subject', subject, '--name', 'CLI fixture',
                    '--monthly-usd', '5', '--key-lifetime', '1h', '--output', key)
            body = directory / 'budget.json'
            body.write_text(json.dumps({'subject': subject, 'monthly_usd': 7.25}))
            checked(ROOT / 'scripts/pricetag/manage', 'PUT', 'budgets', '--input', body,
                    '--output', directory / 'budget-result.json')
            revocations = directory / 'key-count.json'
            revocations.write_text(json.dumps({'subject': subject, 'dry_run': True}))
            checked(ROOT / 'scripts/pricetag/manage', 'POST', 'key-revocations',
                    '--input', revocations, '--output', directory / 'key-count-result.json')
            assert json.loads((directory / 'key-count-result.json').read_text())['count'] == 1
            def api(method, route, credential, output):
                return (ROOT / 'scripts/pricetag/api', method, route, '--url', origin,
                        '--key-file', credential, '--ca-file', '/etc/praxis-pricetag/ca.pem',
                        '--output', directory / output)
            checked(*api('GET', '/api/v1/whoami', key, 'whoami.json'))
            who = json.loads((directory / 'whoami.json').read_text())
            assert who['quota']['limit_usd'] == 7.25
            assert command(*api('GET', '/api/v1/management/users', key, 'denied.json')).returncode != 0
            checked(*api('GET', '/api/v1/management/users', '/root/pricetag-admin/admin.key', 'users.json'))
            checked(*api('GET', '/me/keys', key, 'keys.json'))
            keys = json.loads((directory / 'keys.json').read_text())['data']
            assert len(keys) == 1
            checked(*api('DELETE', '/me/keys/' + keys[0]['id'], key, 'revoked.json'))
            print('PASS: user CLI onboarding, manage budget write, HTTPS api scope/role denial and own-key revocation')
    finally:
        request('PUT', 'users', {'subject': subject, 'active': False})


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('FAIL: documented CLI/API acceptance; credentials and response bodies withheld') from None
