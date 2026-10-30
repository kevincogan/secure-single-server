#!/usr/bin/env python3
"""Disposable Podman deployment for the demo CI suite; never use an installed host."""
import argparse
import importlib.machinery
import importlib.util
import json
import ipaddress
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = Path('/etc/praxis-pricetag')
ADMIN = Path('/root/pricetag-admin')
sys.path.insert(0, str(ROOT / 'scripts/pricetag'))
from prepare import POSTGRES, PYTHON


def run(command, **options):
    return subprocess.run(list(map(str, command)), check=True, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, **options).stdout.strip()


def podman(*args):
    return run(['podman', *args])


def ready(url):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for _ in range(90):
        try:
            with opener.open(url, timeout=2) as response:
                if response.status == 200:
                    return
        except OSError:
            pass
        time.sleep(1)
    raise RuntimeError('service readiness timeout')


def database_failure_reason(diagnostic):
    """Return a fixed public code without copying potentially secret log text."""
    for message, code in (
            ('No space left on device', 'database-storage-full'),
            ('Permission denied', 'database-permission-denied'),
            ('Operation not permitted', 'database-operation-not-permitted'),
            ('Out of memory', 'database-out-of-memory'),
            ('password authentication failed', 'database-authentication-failed'),
            ('no pg_hba.conf entry', 'database-client-not-allowed'),
            ('database "maas" does not exist', 'database-maas-missing'),
            ('syntax error', 'database-bootstrap-syntax-error'),
            ('Connection refused', 'database-connection-refused'),
            ('No such file or directory', 'database-file-or-socket-missing'),
            ('container state improper', 'database-container-stopped')):
        if message in diagnostic:
            return code
    return 'database-bootstrap-failed'


def database_startup_progress(diagnostic):
    """Publish known bootstrap milestones, never interpolated log contents."""
    markers = (
        ('creating configuration files ... ok', 'configuration-created'),
        ('running bootstrap script ... ok', 'bootstrap-complete'),
        ('performing post-bootstrap initialization ... ok', 'post-bootstrap-complete'),
        ('syncing data to disk ...', 'data-sync-started'),
        ('syncing data to disk ... ok', 'data-sync-complete'),
        ('listening on Unix socket', 'socket-listening'),
        ('running /docker-entrypoint-initdb.d/10-create-databases.sql', 'application-sql-started'),
        ('PostgreSQL init process complete; ready for start up.', 'entrypoint-complete'),
        ('listening on IPv4 address', 'tcp-listening'),
    )
    return [code for marker, code in markers if marker in diagnostic]


def database_processes(database):
    """Report allowlisted process names only; never arguments or arbitrary text."""
    known = {'postgres', 'initdb', 'pg_ctl', 'psql', 'bash', 'sh', 'find',
             'chown', 'chmod', 'sleep', 'gosu', 'su-exec'}
    rows = podman('top', database, 'comm').splitlines()[1:]
    return sorted({row.strip() if row.strip() in known else 'other' for row in rows})


def postgres_identity():
    """Resolve the pinned image's account instead of assuming Debian/Alpine IDs."""
    result = podman('run', '--rm', '--network', 'none', '--read-only',
                    '--cap-drop', 'all', '--security-opt', 'no-new-privileges',
                    '--entrypoint', 'sh', POSTGRES, '-c',
                    'id -u postgres; id -g postgres').splitlines()
    if len(result) != 2 or not all(value.isascii() and value.isdecimal()
                                  and 0 < int(value) < 2**31 for value in result):
        raise ValueError('PostgreSQL image must declare a non-root user and group')
    return tuple(map(int, result))


def wait_database(database, attempts=90, database_name="maas"):
    """Wait for the final TCP server, retaining the last failed probe privately."""
    last_error = None
    for _ in range(attempts):
        # During init scripts PostgreSQL only listens on its Unix socket. A TCP
        # probe avoids treating the temporary bootstrap server as ready.
        try:
            podman('exec', database, 'sh', '-c',
                   'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -w -h 127.0.0.1 '
                   '-U postgres -d "$1" -Atc "SELECT 1"', 'probe', database_name)
            return
        except subprocess.CalledProcessError as error:
            last_error = error
        if podman('inspect', '--format', '{{.State.Running}}', database) != 'true':
            break
        time.sleep(1)
    raise last_error


def bootstrap_database(database):
    """Use the installer's stdin bootstrap, without a host SQL bind mount."""
    wait_database(database, database_name='postgres')
    with (DEPLOY / 'initdb/10-create-databases.sql').open() as sql:
        run(['podman', 'exec', '-i', database, 'psql', '-X', '-U', 'postgres',
             '-d', 'postgres', '-v', 'ON_ERROR_STOP=1'], stdin=sql)
    wait_database(database)


def database_state(database):
    """Expose only numeric/boolean state; never environment or raw errors."""
    state = json.loads(podman('inspect', database))[0]['State']
    return {key: state[key] for key in ('Running', 'ExitCode', 'OOMKilled')
            if type(state.get(key)) in (bool, int)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--maas-image', required=True)
    parser.add_argument('--metering-image', required=True)
    parser.add_argument('--praxis-image', required=True)
    parser.add_argument('--node-modules', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or DEPLOY.exists() or DEPLOY.is_symlink() or ADMIN.exists() or ADMIN.is_symlink():
        parser.error('requires root on a disposable host without an existing deployment')
    if not args.node_modules.is_absolute() or not args.output.is_absolute():
        parser.error('use absolute node-modules and output paths')
    os.umask(0o077)
    args.output.mkdir(mode=0o700)
    try:
        pwd.getpwnam('praxis-svc')
    except KeyError:
        run(['useradd', '--system', '--no-create-home', '--shell', '/usr/sbin/nologin', 'praxis-svc'])
    prefix = 'pricetag-ci-' + uuid.uuid4().hex[:10]
    networks, containers = [], []
    stage = 'prepare'
    try:
        images = []
        for image in (args.praxis_image, args.maas_image, args.metering_image):
            info = json.loads(podman('image', 'inspect', image))[0]
            images.append('sha256:' + info['Id'].removeprefix('sha256:'))
        with tempfile.TemporaryDirectory(prefix='pricetag-ci-') as temporary:
            sources = Path(temporary) / 'prices.json'
            sources.write_text('{}')
            run([sys.executable, ROOT / 'scripts/pricetag/prepare.py', '--hostname', 'localhost',
                 '--praxis-image', images[0], '--maas-image', images[1], '--metering-image', images[2],
                 '--mock-provider', '--managed-mock', '--price-sources', sources])
        # Container UID 1001 needs the generated test mounts; parents stay private.
        for path in (DEPLOY / 'gateway').iterdir():
            path.chmod(0o644)
        (DEPLOY / 'gateway').chmod(0o755)
        (DEPLOY / 'maas-db-url').chmod(0o644)
        (DEPLOY / 'm2m-secret').chmod(0o644)
        (DEPLOY / 'catalog').chmod(0o755)
        (DEPLOY / 'catalog/models.json').chmod(0o644)
        for suffix in ('private', 'mock'):
            name = prefix + '-' + suffix
            podman('network', 'create', name)
            networks.append(name)
        private, mock = networks
        subnet = json.loads(podman('network', 'inspect', private))[0]['subnets'][0]
        gateway = subnet['gateway']
        praxis_ip = str(ipaddress.ip_network(subnet['subnet']).network_address + 11)
        def start(role, image, network, *options):
            name = prefix + '-' + role
            containers.append(name)
            podman('run', '-d', '--name', name, '--network', network,
                   '--network-alias', 'pricetag-' + role,
                   '--cap-drop', 'all',
                   '--security-opt', 'no-new-privileges', *options, image)
            return name
        stage = 'postgres'
        # Start as the image account directly: the hosted runner stalled in
        # gosu before initdb. The non-root entrypoint creates its own 0700
        # PGDATA below a private writable tmpfs, so no chown is needed.
        database_uid, database_gid = postgres_identity()
        db = start('db', POSTGRES, private, '--user', f'{database_uid}:{database_gid}',
                   '--env-file', DEPLOY / 'postgres.env',
                   # Do not inherit Podman's host-dependent tmpfs size (64 MiB
                   # cannot hold bootstrap databases plus PostgreSQL WAL).
                   '--tmpfs', '/var/lib/postgresql/data:rw,size=1g,mode=1777',
                   '-e', 'PGDATA=/var/lib/postgresql/data/pgdata')
        bootstrap_database(db)
        stage = 'maas'
        maas = start('maas', images[1], private, '--read-only', '--user', '1001:1001',
                    '-p', '127.0.0.1:18086:8080',
                    '-v', str(DEPLOY / 'maas-db-url') + ':/run/secrets/db:ro,Z',
                    '-e', 'DB_CONNECTION_URL_FILE=/run/secrets/db',
                    '-e', 'MAAS_RUNTIME_MODE=standalone', '-e', 'MAAS_SUBSCRIPTION_MODE=standalone',
                    '-e', 'ADDRESS=:8080', '-e', 'SECURE=false', '-e', 'API_KEY_MAX_EXPIRATION_DAYS=90',
                    '-e', 'MAAS_ADMIN_GROUPS=single-server-admin',
                    '-e', 'METRICS_SECURE=false', '-e', 'METRICS_ADDRESS=127.0.0.1:9090',
                    '-e', 'MAAS_TRUSTED_PROXY_CIDRS=' + gateway + '/32')
        ready('http://127.0.0.1:18086/health')
        # Only the metering container and loopback-published host mint keys.
        stage = 'metering'
        meter = start('metering', images[2], private, '--read-only', '--user', '1001:1001',
                      '-p', '127.0.0.1:18087:8080', '--env-file', DEPLOY / 'metering.env',
                      '-v', str(DEPLOY / 'catalog') + ':/etc/gateway-catalog:ro,Z')
        meter_ip = json.loads(podman('inspect', meter))[0]['NetworkSettings']['Networks'][private]['IPAddress']
        podman('rm', '-f', maas)
        containers.remove(maas)
        # Recreate with the specific metering peer address, not the whole subnet.
        maas = start('maas', images[1], private, '--read-only', '--user', '1001:1001',
                    '-p', '127.0.0.1:18086:8080', '-v', str(DEPLOY / 'maas-db-url') + ':/run/secrets/db:ro,Z',
                    '-e', 'DB_CONNECTION_URL_FILE=/run/secrets/db',
                    '-e', 'MAAS_RUNTIME_MODE=standalone', '-e', 'MAAS_SUBSCRIPTION_MODE=standalone',
                    '-e', 'ADDRESS=:8080', '-e', 'SECURE=false', '-e', 'API_KEY_MAX_EXPIRATION_DAYS=90',
                    '-e', 'MAAS_ADMIN_GROUPS=single-server-admin',
                    '-e', 'METRICS_SECURE=false', '-e', 'METRICS_ADDRESS=127.0.0.1:9090',
                    '-e', 'MAAS_TRUSTED_PROXY_CIDRS=' + gateway + '/32,' + meter_ip + '/32,' + praxis_ip + '/32')
        ready('http://127.0.0.1:18086/health')
        ready('http://127.0.0.1:18087/ready')
        stage = 'bootstrap APIs'
        run([sys.executable, ROOT / 'scripts/pricetag/maas-key', 'create', '--subject', 'admin',
             '--admin', '--name', 'admin', '--output', ADMIN / 'admin.key'])
        from metering_admin import provision, bootstrap
        provision('admin', 'Administrator', admin=True)
        bootstrap(DEPLOY / 'bootstrap.json')
        for subject in ('alice', 'bob'):
            run([sys.executable, ROOT / 'scripts/pricetag/user', '--subject', subject,
                 '--name', subject, '--output', ADMIN / (subject + '.key')])
        stage = 'mock provider'
        # The fixture image's default entrypoint is python; specify the script.
        name = prefix + '-provider'
        containers.append(name)
        podman('run', '-d', '--name', name, '--network', mock, '--network-alias', 'pricetag-provider',
               '--cap-drop', 'all', '--security-opt', 'no-new-privileges', '--read-only',
               '-e', 'MOCK_MANAGEMENT=1', '-v', str(DEPLOY / 'fixtures') + ':/fixtures:ro,Z',
               PYTHON, 'python3', '/fixtures/run.py')
        stage = 'praxis'
        name = prefix + '-gateway'
        containers.append(name)
        podman('run', '-d', '--name', name, '--network', private + ':ip=' + praxis_ip, '--network', mock,
               '--cap-drop', 'all', '--security-opt', 'no-new-privileges', '--read-only',
               '-p', '127.0.0.1:8443:8443', '-e', 'CUSTOM_MOCK_API_KEY=synthetic-anthropic',
               '-v', str(DEPLOY / 'gateway') + ':/etc/praxis:ro,Z',
               '-v', str(DEPLOY / 'm2m-secret') + ':/run/secrets/pricetag-m2m:ro,Z',
               images[0], '-c', '/etc/praxis/gateway.json')
        for _ in range(60):
            result = subprocess.run(['curl', '--noproxy', '*', '--fail', '--silent', '--cacert',
                                     str(DEPLOY / 'ca.pem'), 'https://localhost:8443/login', '-o', '/dev/null'],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError('gateway HTTPS readiness failed')
        stage = 'demo suite'
        # Logs and credentials remain private. Only results.json is published.
        with (args.output / 'suite-private.log').open('w') as log:
            subprocess.run([sys.executable, str(ROOT / 'tests/pricetag/demo-suite'),
                            '--output', str(args.output / 'suite'), '--node-modules', str(args.node_modules)],
                           stdout=log, stderr=subprocess.STDOUT, check=True, timeout=1800)
        shutil.copyfile(args.output / 'suite/results.json', args.output / 'results.json')
        print('PASS: disposable demo deployment and API/browser/quota suite')
    except Exception as error:
        if (args.output / 'suite/results.json').is_file():
            shutil.copyfile(args.output / 'suite/results.json', args.output / 'results.json')
        with (args.output / 'diagnostics-private.log').open('w') as log:
            traceback.print_exc(file=log)
            if isinstance(error, subprocess.CalledProcessError):
                log.write(error.stdout or '')
                log.write(error.stderr or '')
            for container in containers:
                subprocess.run(['podman', 'logs', '--tail', '200', container], stdout=log, stderr=log)
        failure = {'passed': False, 'stage': stage}
        if stage == 'postgres':
            # Classify only known messages; never publish logs or exception text.
            diagnostic = (args.output / 'diagnostics-private.log').read_text()
            failure['reason'] = database_failure_reason(diagnostic)
            failure['startup_progress'] = database_startup_progress(diagnostic)
            if 'db' in locals():
                try:
                    failure['database'] = database_state(db)
                    if failure['database'].get('Running'):
                        failure['processes'] = database_processes(db)
                except (subprocess.CalledProcessError, ValueError, KeyError):
                    failure['database'] = {'inspect_failed': True}
        (args.output / 'failure.json').write_text(json.dumps(failure) + '\n')
        print('FAIL: ' + stage + '; private diagnostics retained, no credentials printed', file=sys.stderr)
        raise SystemExit(1) from None
    finally:
        for name in reversed(containers):
            subprocess.run(['podman', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for name in reversed(networks):
            subprocess.run(['podman', 'network', 'rm', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # These exact directories were absent at entry and belong to this test.
        shutil.rmtree(DEPLOY, ignore_errors=True)
        shutil.rmtree(ADMIN, ignore_errors=True)


if __name__ == '__main__':
    main()
