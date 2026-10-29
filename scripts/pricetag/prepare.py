#!/usr/bin/env python3
"""Prepare an isolated rootless Quadlet deployment; do not start services."""
import argparse
import copy
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import subprocess

from gateway import render

ROOT = Path(__file__).resolve().parents[2]
POSTGRES = 'docker.io/library/postgres@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea'
PYTHON = 'docker.io/library/python@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7'


def literal(value):
    return "'" + value.replace("'", "''") + "'"


def vllm_only(original, models):
    selected = [m for m in models if m['provider'] == 'vllm']
    if not selected:
        raise ValueError('vLLM-only deployment requires a local vLLM model')
    config = copy.deepcopy(original)
    for chain in config['filter_chains']:
        chain['filters'] = [f for f in chain['filters'] if f['filter'] != 'credential_injection']
        for item in chain['filters']:
            if item['filter'] == 'load_balancer':
                item['clusters'] = [c for c in item['clusters'] if c['name'] == 'vllm']
    return config, selected


def mock_inputs(managed=False):
    if managed:
        from demo_config import mock_configuration, native_inputs
        document = mock_configuration()
        return native_inputs(document), document['models']
    models = [{'id': 'fixture', 'provider': 'vllm', 'model': 'fixture',
               'apis': ['openai', 'anthropic'], 'context': 32768, 'output': 4096}]
    config = {'filter_chains': [{'name': api, 'filters': [
        {'filter': 'headers', 'request_remove': ['Authorization', 'X-Api-Key']},
        {'filter': 'load_balancer', 'clusters': [{'name': 'vllm',
         'endpoints': ['pricetag-provider:' + port]}]}]}
        for api, port in [('openai', '18080'), ('anthropic', '18081')]]}
    return config, models


def postgres_bootstrap(metering_password, maas_password):
    """Create the application roles/databases idempotently through psql."""
    statements = []
    for role, password, database in (
            ('metering', metering_password, 'metering'),
            ('maas', maas_password, 'maas')):
        statements += [
            f"SELECT format('CREATE ROLE {role} LOGIN PASSWORD %L', {literal(password)}) "
            f"WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname={literal(role)}) \\gexec",
            f'ALTER ROLE {role} LOGIN PASSWORD {literal(password)};',
            f"SELECT 'CREATE DATABASE {database} OWNER {role}' "
            f"WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname={literal(database)}) \\gexec",
        ]
    return '\n'.join(statements) + '\n'


def gateway_quadlet_body(image, provider_secrets, mount, mock_provider):
    mock_network = 'Network=pricetag-mock.network\n' if mock_provider else ''
    return (
        f'Image={image}\nPull=never\nNetworkAlias=pricetag-gateway\n'
        + mock_network
        + 'Secret=pricetag-m2m,type=mount,target=/run/secrets/pricetag-m2m,uid=1001,gid=1001,mode=0400\n'
        + 'PublishPort=0.0.0.0:8443:8443\n'
        + '\n'.join(provider_secrets) + '\n'
        + mount + 'Exec=-c /etc/praxis/gateway.json\n'
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--providers', type=Path, default=Path('/etc/praxis/shared-gateway.yaml'))
    parser.add_argument('--models', type=Path, default=Path('/etc/praxis/unified-models.json'))
    parser.add_argument('--provider-unit', type=Path)
    parser.add_argument('--praxis-image', required=True, help='local immutable image ID containing MaaS auth and metering filters')
    parser.add_argument('--maas-image', required=True, help='local immutable cluster-free MaaS API image ID')
    parser.add_argument('--metering-image', required=True, help='local image ID sha256:... in praxis-svc storage')
    parser.add_argument('--hostname', required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--vllm-only', action='store_true',
                        help='expose only local vLLM; do not mount cloud provider secrets')
    mode.add_argument('--mock-provider', action='store_true',
                      help='isolated synthetic provider for a fresh performance-test VM')
    parser.add_argument('--managed-mock', action='store_true', help='authenticated mock providers for the management demo')
    parser.add_argument('--mock-secret', default='pricetag-mock-ui-v1', help='existing synthetic credential Podman secret')
    parser.add_argument('--sample-users', action=argparse.BooleanOptionalAction, default=True,
                        help='create sample users on start; admin is always created')
    parser.add_argument('--monthly-usd', type=int, default=5)
    parser.add_argument('--price-sources', type=Path, required=True,
                        help='JSON mapping gateway aliases to reviewed PriceTag pricing model IDs')
    parser.add_argument('--directory', type=Path, default=Path('/etc/praxis-pricetag'))
    parser.add_argument('--admin-directory', type=Path, default=Path('/root/pricetag-admin'))
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run as root on the RHEL host')
    if args.managed_mock and not args.mock_provider:
        parser.error('--managed-mock requires --mock-provider')
    if args.managed_mock and not re.fullmatch(r'pricetag-mock-ui-v[0-9]+', args.mock_secret):
        parser.error('managed mock requires a versioned synthetic secret reference')
    if not args.mock_provider and args.provider_unit is None:
        parser.error('--provider-unit is required unless --mock-provider is selected')
    if not all(re.fullmatch(r'sha256:[0-9a-f]{64}', image)
               for image in (args.metering_image, args.praxis_image, args.maas_image)):
        parser.error('image arguments must be immutable local sha256 image IDs')
    if not 1 <= args.monthly_usd <= 10000:
        parser.error('monthly-usd must be 1–10000')
    for directory in (args.directory, args.admin_directory):
        if not directory.is_absolute() or re.search(r'[\s%]', str(directory)) or directory.exists():
            parser.error('use new absolute directories without whitespace or percent signs')
    owner = pwd.getpwnam('praxis-svc')
    if args.mock_provider:
        original, models = mock_inputs(managed=args.managed_mock)
    else:
        models = json.loads(args.models.read_text())
        original = json.loads(args.providers.read_text())
    if args.vllm_only:
        original, models = vllm_only(original, models)
    config = render(original, models,
                    list(dict.fromkeys([f'https://{args.hostname}:8443', 'https://localhost:8443'])))
    sources = json.loads(args.price_sources.read_text())
    if not isinstance(sources, dict) or any(not isinstance(v, str) for v in sources.values()):
        parser.error('price-sources must map aliases to model names')
    if not args.mock_provider and any(m['id'] == sources.get(m['id'], m['model']) for m in models):
        parser.error('use distinct gateway aliases to keep their initial pricing snapshot stable')
    provider_secrets = [f'Secret={args.mock_secret},type=env,target=CUSTOM_MOCK_API_KEY'] if args.managed_mock else []
    for line in ([] if args.mock_provider else args.provider_unit.read_text().splitlines()):
        if re.fullmatch(r'Secret=[A-Za-z0-9_.-]+,type=env,target=[A-Z0-9_]+_API_KEY', line):
            provider_secrets.append(line)
    needed = {entry['env_var'] for chain in config['filter_chains'] for f in chain['filters']
              if f['filter'] == 'credential_injection' for entry in f['clusters']
              if 'env_var' in entry and entry['env_var'] != 'M2M_SHARED_SECRET'}
    supplied = {line.rsplit('=', 1)[1] for line in provider_secrets}
    if not needed <= supplied:
        parser.error('provider Quadlet does not supply every required API-key secret')
    provider_secrets = [line for line in provider_secrets if line.rsplit('=', 1)[1] in needed]
    os.umask(0o077)
    args.admin_directory.mkdir(mode=0o700)
    args.directory.mkdir(mode=0o750)
    bundle = args.directory / 'gateway'
    units = args.directory / 'quadlets'
    bundle.mkdir(mode=0o750)
    units.mkdir(mode=0o750)
    credential = ROOT / 'scripts/remote-gateway/credentials'

    def credentials(*options):
        subprocess.run([str(credential), *map(str, options)], check=True, stdout=subprocess.DEVNULL)

    credentials('lab-tls', '--directory', args.admin_directory / 'tls', '--hostname', args.hostname,
                '--alt-hostname', 'localhost', '--alt-hostname', '127.0.0.1')
    for source, target in [(args.admin_directory / 'tls/server.pem', 'tls.pem'),
                           (args.admin_directory / 'tls/server-key.pem', 'tls-key.pem')]:
        shutil.copyfile(source, bundle / target)
    (bundle / 'gateway.json').write_text(json.dumps(config, indent=2) + '\n')
    shutil.copyfile(args.admin_directory / 'tls/ca.pem', args.directory / 'ca.pem')
    postgres_password, metering_password, maas_password = (secrets.token_urlsafe(32) for _ in range(3))

    def env(name, values):
        (args.directory / name).write_text(''.join(f'{k}={v}\n' for k, v in values.items()))

    initdb = args.directory / 'initdb'
    initdb.mkdir(mode=0o750)
    env('postgres.env', {'POSTGRES_USER': 'postgres', 'POSTGRES_DB': 'postgres',
                        'POSTGRES_PASSWORD': postgres_password, 'TZ': 'UTC', 'PGTZ': 'UTC'})
    (initdb / '10-create-databases.sql').write_text(
        postgres_bootstrap(metering_password, maas_password))
    m2m_secret = secrets.token_urlsafe(48)
    management_secret = secrets.token_urlsafe(48)
    env('metering.env', {'DATABASE_URL': f'postgres://metering:{metering_password}@pricetag-db:5432/metering?sslmode=disable',
        'M2M_AUTH_REQUIRED': 'true', 'M2M_SHARED_SECRET': m2m_secret,
        'SESSION_SECRET': secrets.token_urlsafe(48),
        'MANAGEMENT_API_SECRET': management_secret,
        'MANAGEMENT_PUBLIC_ORIGIN': f'https://{args.hostname}:8443',
        'USER_DASHBOARDS_ENABLED': 'true',
        'GATEWAY_MODELS_FILE': '/etc/gateway-catalog/models.json',
        'KEY_SERVICE_URL': 'http://pricetag-maas:8080',
        'KEY_SERVICE_USER_HEADER': 'X-MaaS-Username',
        'KEY_SERVICE_GROUPS_HEADER': 'X-MaaS-Group',
        'PARTNER_USER_KEY_GROUP': 'system:authenticated',
        'SUPERADMIN_USERS': 'admin', 'MONTHLY_TOKEN_QUOTA': '10000000000', 'TZ': 'UTC',
        'MAAS_VALIDATE_URL': 'http://pricetag-maas:8080/internal/v1/api-keys/validate'})
    (args.directory / 'm2m-secret').write_text(m2m_secret + '\n')
    (args.directory / 'maas-db-url').write_text(
        f'postgres://maas:{maas_password}@pricetag-db:5432/maas?sslmode=disable\n')
    (args.directory / 'sample-users').write_text('yes\n' if args.sample_users else 'no\n')
    (args.directory / 'admin-directory').write_text(str(args.admin_directory) + '\n')
    (args.directory / 'management-secret').write_text(management_secret + '\n')
    (args.directory / 'bootstrap.json').write_text(json.dumps({'models': models, 'sources': sources, 'monthly_usd': args.monthly_usd}) + '\n')
    (args.directory / 'models.json').write_text(json.dumps(models, indent=2) + '\n')
    catalog = args.directory / 'catalog'
    catalog.mkdir(mode=0o750)
    (catalog / 'models.json').write_text(json.dumps([{k: m[k] for k in ('id', 'model', 'provider')} for m in models]) + '\n')
    (args.directory / 'price-sources.json').write_text(json.dumps(sources, indent=2) + '\n')
    (units / 'pricetag.network').write_text(
        '[Network]\nNetworkName=pricetag-private\nDriver=bridge\nSubnet=10.77.0.0/24\n')
    (units / 'pricetag-db.volume').write_text('[Volume]\nVolumeName=pricetag-data\n')
    common = 'ReadOnly=true\nNoNewPrivileges=true\n'
    app = common + 'User=1001\nGroup=1001\nUserNS=keep-id:uid=1001,gid=1001\nDropCapability=all\n'
    mount = f'Volume={bundle}:/etc/praxis:ro\n'

    def container(name, description, dependencies, body, memory, network='pricetag.network'):
        (units / (name + '.container')).write_text(
            f'[Unit]\nDescription={description}\nWants=network-online.target\nAfter=network-online.target {dependencies}\n'
            f'Requires={dependencies}\n\n[Container]\nContainerName={name}\nNetwork={network}\n'
            f'{body}\n[Service]\nRestart=on-failure\nRestartSec=5\nTimeoutStartSec=900\n'
            f'MemoryMax={memory}\n\n[Install]\nWantedBy=default.target\n')

    container('pricetag-db', 'MaaS and PriceTag PostgreSQL', '',
        f'Image={POSTGRES}\nEnvironmentFile={args.directory}/postgres.env\n'
        'Volume=pricetag-db.volume:/var/lib/postgresql/data\n'
        'Tmpfs=/var/run/postgresql:rw,mode=3775\nTmpfs=/tmp\n'
        'HealthCmd=pg_isready -U postgres -d postgres\nHealthInterval=10s\n' + common, '1G')
    container('pricetag-maas', 'MaaS standalone key API', 'pricetag-db.service',
        f'Image={args.maas_image}\nPull=never\nNetworkAlias=pricetag-maas\n'
        'IP=10.77.0.10\n'
        'PublishPort=127.0.0.1:18086:8080\n'
        f'Volume={args.directory}/maas-db-url:/run/secrets/maas-db-url:ro\n'
        'Environment=MAAS_RUNTIME_MODE=standalone\nEnvironment=MAAS_SUBSCRIPTION_MODE=standalone\n'
        'Environment=ADDRESS=:8080\nEnvironment=SECURE=false\n'
        'Environment=DB_CONNECTION_URL_FILE=/run/secrets/maas-db-url\n'
        'Environment=API_KEY_MAX_EXPIRATION_DAYS=90\nEnvironment=MAAS_ADMIN_GROUPS=single-server-admin\n'
        'Environment=MAAS_TRUSTED_PROXY_CIDRS=127.0.0.1/32,10.77.0.10/32,10.77.0.11/32,10.77.0.12/32\n'
        'Environment=METRICS_SECURE=false\nEnvironment=METRICS_ADDRESS=127.0.0.1:9090\n' + app, '1G')
    container('pricetag-metering', 'PriceTag metering and dashboards', 'pricetag-db.service',
        f'Image={args.metering_image}\nPull=never\nNetworkAlias=pricetag-metering\n'
        f'EnvironmentFile={args.directory}/metering.env\nPublishPort=127.0.0.1:18087:8080\n'
        f'Volume={args.directory}/catalog:/etc/gateway-catalog:ro\n' + app, '2G',
        network='pricetag.network:ip=10.77.0.12')
    dependencies = 'pricetag-metering.service'
    if args.mock_provider:
        (units / 'pricetag-mock.network').write_text(
            '[Network]\nNetworkName=pricetag-mock\nDriver=bridge\nSubnet=10.78.0.0/24\n')
        fixtures = args.directory / 'fixtures'
        fixtures.mkdir()
        shutil.copyfile(ROOT / 'tests/common/provider.py', fixtures / 'provider.py')
        shutil.copyfile(ROOT / 'tests/pricetag/provider.py', fixtures / 'run.py')
        container('pricetag-provider', 'Synthetic LLM for performance testing only', '',
            f'Image={PYTHON}\nVolume={fixtures}:/fixtures:ro\nEnvironment=MOCK_STREAM_DELAY=1\n' +
            ('Environment=MOCK_MANAGEMENT=1\n' if args.managed_mock else '') +
            'Exec=python3 /fixtures/run.py\n' + app, '1G', network='pricetag-mock.network')
        dependencies += ' pricetag-provider.service'
    container('pricetag-gateway', 'Praxis HTTPS gateway with MaaS identity and USD budgets',
        'pricetag-metering.service pricetag-maas.service',
        gateway_quadlet_body(args.praxis_image, provider_secrets, mount, args.mock_provider) + app,
        '1G', network='pricetag.network:ip=10.77.0.11')
    for path in [args.directory, *args.directory.rglob('*')]:
        os.chown(path, 0, owner.pw_gid)
        path.chmod(0o750 if path.is_dir() else 0o640)
    (args.directory / 'management-secret').chmod(0o600)
    print(f'Prepared {args.directory}; no services started. Administrator credentials: {args.admin_directory}')


if __name__ == '__main__':
    main()
