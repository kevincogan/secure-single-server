#!/usr/bin/env python3
"""Qualify the CI PostgreSQL runtime before building application images."""
import importlib.util
import os
import json
import re
import time
from pathlib import Path
import secrets
import subprocess
import sys
import uuid

spec = importlib.util.spec_from_file_location('container_demo', Path(__file__).with_name('container-demo.py'))
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)


def signal_denials(log):
    """Extract policy metadata only; never publish raw kernel/audit messages."""
    rows = []
    for line in log.splitlines():
        fields = {key: quoted or plain for key, quoted, plain in
                  re.findall(r'(\w+)=(?:"([^"]*)"|(\S+))', line)}
        if fields.get('apparmor') != 'DENIED' or fields.get('operation') != 'signal':
            continue
        if fields.get('comm') not in {'pg_ctl', 'postgres', 'bash', 'sh', 'crun', 'podman'}:
            continue
        row = {key: fields[key] for key in
               ('profile', 'peer', 'comm', 'signal', 'requested_mask', 'denied_mask')
               if key in fields and re.fullmatch(r'[A-Za-z0-9_./&+,:() *=-]{1,256}', fields[key])}
        if row not in rows:
            rows.append(row)
    return rows[-20:]


def report_signal_denials(since):
    try:
        result = subprocess.run(
            ['journalctl', '-k', '--since', '@' + str(since), '--no-pager', '-o', 'cat'],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        if result.returncode:
            raise RuntimeError('journal unavailable')
        print('AppArmor signal denials: ' + json.dumps(signal_denials(result.stdout)), file=sys.stderr)
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        print('AppArmor audit metadata unavailable', file=sys.stderr)


def main():
    if os.geteuid() != 0:
        raise SystemExit('Run on the disposable CI host as root.')
    os.umask(0o077)
    name = 'pricetag-db-smoke-' + uuid.uuid4().hex[:10]
    password = secrets.token_urlsafe(32)
    started = False
    since = int(time.time())
    try:
        print(demo.podman('version'), flush=True)
        print(demo.podman('info', '--format',
                         'arch={{.Host.Arch}} runtime={{.Host.OCIRuntime.Name}} '
                         'apparmor={{.Host.Security.AppArmorEnabled}} '
                         'selinux={{.Host.Security.SELinuxEnabled}}'), flush=True)
        uid, gid = demo.postgres_identity()
        print(f'PostgreSQL account: {uid}:{gid}', flush=True)
        # No host mounts, application data, provider credentials or published
        # ports. The only credential is this disposable, redacted test password.
        demo.run(['podman', 'run', '-d', '--name', name, '--network', 'none',
                  '--user', f'{uid}:{gid}', '--cap-drop', 'all',
                  '--security-opt', 'no-new-privileges',
                  '--env', 'POSTGRES_PASSWORD',
                  '--tmpfs', '/var/lib/postgresql/data:rw,size=1g,mode=1777',
                  '-e', 'PGDATA=/var/lib/postgresql/data/pgdata', demo.POSTGRES],
                 env={**os.environ, 'POSTGRES_PASSWORD': password})
        started = True
        print('Database AppArmor profile: ' + demo.podman(
            'inspect', '--format', '{{.AppArmorProfile}}', name), flush=True)
        demo.wait_database(name, database_name='postgres')
        print('PASS: isolated PostgreSQL initialization and authenticated TCP query')
    except Exception:
        # Only this dedicated, mount-free container can be logged here. Never
        # apply this policy to the application suite or an installed deployment.
        if started:
            logs = subprocess.run(['podman', 'logs', name], text=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print((logs.stdout + logs.stderr).replace(password, '[redacted]'), file=sys.stderr)
        report_signal_denials(since)
        print('FAIL: isolated PostgreSQL preflight; application tests were not started', file=sys.stderr)
        raise SystemExit(1) from None
    finally:
        subprocess.run(['podman', 'rm', '-f', name],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
