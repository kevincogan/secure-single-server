# SPDX-License-Identifier: Apache-2.0
"""Materialize role-specific mounted inputs privately, then run existing services.

Kubernetes Secret mounts use atomic symlinks. Only these fixed mount roots may
be followed; the ordinary runtime helpers continue refusing symlinked inputs.
Projected API tokens are never copied and remain kubelet-rotated tokenFile inputs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys


def mounted(root, name, maximum=1_000_000):
    source = root / name
    resolved = source.resolve(strict=True)
    if (not resolved.is_relative_to(root.resolve()) or not resolved.is_file()
            or resolved.stat().st_size > maximum):
        raise ValueError('Bounded fixed mounted input required')
    return resolved.read_bytes()


def prepare(role, inputs, state, namespace, pod_uid):
    from deployment_profile import DeploymentProfile
    from deployment_artifacts import validate_artifacts
    if role not in ('coordinator', 'preparer') or not namespace or not pod_uid:
        raise ValueError('Role and downward-API Pod identity required')
    names = ['installation-profile.json', 'artifacts.json', 'runtime-credentials.json',
             'driver-credentials.json', 'management-ca.crt', 'service-ca.crt', 'kubernetes-ca.crt']
    if role == 'coordinator':
        names += ['catalog-credential.json', 'gateway.receipt.json', 'sender-trust.receipt.json', 'inference.json', 'inference.key']
    else:
        names += ['capacity-budget.json']
    if (inputs / 'certificate-management.json').exists():
        names += ['certificate-management.json']
    files = {name: mounted(inputs, name) for name in names}
    profile = DeploymentProfile.from_dict(json.loads(files['installation-profile.json']))
    if namespace != profile.core_namespace:
        raise ValueError('Runtime Pod belongs to another installation')
    artifacts = validate_artifacts(json.loads(files['artifacts.json']))
    if artifacts.get('native_build_contract') != profile.native_build_contract:
        raise ValueError('Runtime artifacts do not match the installation')
    credentials = json.loads(files['runtime-credentials.json'])
    allowed = {'namespace', 'keycloak_url', 'gateway_url', 'runtime_management'}
    if role == 'coordinator':
        allowed.add('realm_management')
    if (set(credentials) != allowed or credentials['namespace'] != namespace
            or credentials['keycloak_url'] != profile.origin('fixture-keycloak')
            or credentials['gateway_url'] != profile.origin('fixture-mcp') + '/mcp'):
        raise ValueError('Minimal role credentials required; human/bootstrap credentials refused')
    management = credentials['runtime_management']
    if (not isinstance(management, dict) or set(management) != {'client_id', 'audience', 'client_secret'}
            or management['client_id'] != 'fixture-runtime-operator' or management['audience'] != 'identity-demo-runtime'
            or not isinstance(management['client_secret'], str) or len(management['client_secret']) < 32):
        raise ValueError('Exact native management service credential required')
    if role == 'coordinator':
        realms = credentials['realm_management']
        if not isinstance(realms, dict) or set(realms) != {profile.origin(v) for v in ('fixture-keycloak', 'fixture-keycloak-upstream')}:
            raise ValueError('Exact two owned realm service clients required')
        for client in realms.values():
            if (not isinstance(client, dict) or set(client) != {'client_id', 'client_secret'}
                    or client['client_id'] != 'fixture-console-realm-coordinator'
                    or not isinstance(client['client_secret'], str) or len(client['client_secret']) < 32):
                raise ValueError('Minimal realm service credentials required')
    keys = json.loads(files['driver-credentials.json'])
    if (set(keys) != {'operator_secret'} or not isinstance(keys['operator_secret'], str)
            or len(keys['operator_secret']) < 32):
        raise ValueError('One role-specific private API credential required')
    state.mkdir(mode=0o700, exist_ok=True)
    if state.is_symlink():
        raise ValueError('Regular persistent runtime directory required')
    os.chmod(state, 0o700)
    identity = hashlib.sha256(b''.join(name.encode()+b'\x00'+files[name] for name in sorted(files))).hexdigest()
    config = state / ('config-' + identity[:24])
    config.mkdir(mode=0o700, exist_ok=True)
    if config.is_symlink():
        raise ValueError('Regular private configuration directory required')
    for name, content in files.items():
        destination = config/name
        if destination.exists():
            if destination.is_symlink() or destination.read_bytes() != content:
                raise ValueError('Private runtime input changed during bootstrap')
        else:
            with destination.open('xb') as stream:
                stream.write(content)
        destination.chmod(0o600)
    token_root = '/var/run/secrets/kubernetes.io/serviceaccount'
    kubeconfig = {'apiVersion': 'v1', 'kind': 'Config', 'current-context': 'runtime',
        'clusters': [{'name': 'installation', 'cluster': {'server': profile.expected_server,
                     'certificate-authority': str(config/'kubernetes-ca.crt')}}],
        'users': [{'name': 'runtime', 'user': {'tokenFile': token_root+'/token'}}],
        'contexts': [{'name': 'runtime', 'context': {'cluster': 'installation',
                      'user': 'runtime', 'namespace': namespace}}]}
    path = config/'kubeconfig.json'
    payload = json.dumps(kubeconfig).encode()
    if path.exists() and (path.is_symlink() or path.read_bytes() != payload):
        raise ValueError('Existing private kubeconfig differs')
    path.write_bytes(payload)
    path.chmod(0o600)
    for folder in ('profile', 'receipts'):
        (state/folder).mkdir(mode=0o700, exist_ok=True)
        os.chmod(state/folder, 0o700)
    environment = {**os.environ, 'HOME': str(state), 'IDENTITY_DEMO_RUNTIME': 'cluster',
        'IDENTITY_DEMO_CONFIG': str(config/'installation-profile.json'),
        'IDENTITY_DEMO_ARTIFACTS': str(config/'artifacts.json'),
        'IDENTITY_DEMO_REGISTRATION_MODE': 'controller',
        'IDENTITY_DEMO_KUBERNETES_CA': str(config/'kubernetes-ca.crt'),
        'IDENTITY_DEMO_OPERATOR_ORIGIN': 'https://'+profile.service_host('fixture-identity-operator')+':8444',
        'IDENTITY_DEMO_OPERATOR_CA': str(config/'service-ca.crt')}
    if 'certificate-management.json' in files:
        from managed_certificates import validate_contract
        policy = json.loads(files['certificate-management.json'])
        if set(policy) != {'contract', 'authority'}:
            raise ValueError('Exact public certificate policy required')
        validate_contract(policy['contract'], policy['authority'])
        if policy['authority'].encode() != files['management-ca.crt']:
            raise ValueError('Management CA differs from approved certificate trust')
        environment['IDENTITY_DEMO_CERTIFICATE_POLICY'] = str(config/'certificate-management.json')
    arguments = ['--kubeconfig', str(path), '--expected-server', profile.expected_server,
        '--credentials-file', str(config/'runtime-credentials.json'), '--cli', '/usr/local/bin/openshell',
        '--cli-config-dir', str(state/'profile'), '--driver-credentials-file', str(config/'driver-credentials.json'),
        '--output-dir', str(state/'receipts'), '--ca-file', str(config/'management-ca.crt'),
        '--service-account-token-file', token_root+'/token',
        '--service-account-token-root', token_root, '--service-account-namespace', namespace,
        '--service-account-name', 'fixture-console-'+role, '--pod-uid', pod_uid,
        '--management-port', '18443' if role == 'coordinator' else '18444']
    if role == 'coordinator':
        environment['IDENTITY_DEMO_SENDER_TRUST_RECEIPT'] = str(config/'sender-trust.receipt.json')
        trust_reference = json.loads(files['sender-trust.receipt.json'])
        if trust_reference.get('automatic_public_refresh') is True:
            arguments += ['--auto-refresh-sender-trust']
        inference = json.loads(files['inference.json'])
        inference['chat']['credential_file'] = str(config/'inference.key')
        runtime_inference = config/'inference.runtime.json'
        runtime_inference.write_text(json.dumps(inference))
        runtime_inference.chmod(0o600)
        arguments += ['--catalog-credential-file', str(config/'catalog-credential.json'),
            '--inference-config', str(runtime_inference), '--gateway-mode', 'persistent',
            '--gateway-receipt', str(config/'gateway.receipt.json'), '--auto-refresh-catalog']
    else:
        from identity_demo_capacity import validate_budget
        validate_budget(json.loads(files['capacity-budget.json']))
        arguments += ['--initialize-management-profile', '--namespace-capacity-budget-file',
                      str(config/'capacity-budget.json')]
    return arguments, environment


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('role', choices=('coordinator', 'preparer'))
    args = parser.parse_args()
    os.umask(0o077)
    try:
        arguments, environment = prepare(args.role, Path('/runtime-inputs'), Path('/state/private'),
            os.environ['POD_NAMESPACE'], os.environ['POD_UID'])
        module = 'identity_demo_console_worker' if args.role == 'coordinator' else 'identity_demo_console_preparer'
        os.execve(sys.executable, [sys.executable, '-m', module, *arguments], environment)
    except Exception as error:
        print(json.dumps({'runtime_bootstrap_failed': True, 'failure_kind': type(error).__name__,
                          'details_withheld': True}), flush=True)
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
