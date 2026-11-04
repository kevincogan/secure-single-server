# SPDX-License-Identifier: Apache-2.0
"""Credential-free reachability and mount checks inside the real sandbox."""
import argparse
import json
import os
from pathlib import Path
import re
import socket


PRIVATE_FILES = ('/.openshell/supervisor/auth.json', '/.openshell/supervisor/proxy-ca.key',
    '/.openshell/state/bootstrap/tls.key', '/.openshell/bootstrap-input/tls.key', '/var/run/secrets/openshell/token',
    '/var/run/secrets/kubernetes.io/serviceaccount/token', '/keys/write', '/write/write',
    '/observe/observe', '/keys/operator', '/state/private/history.db')
PRIVATE_SOCKETS = ('/spiffe-workload-api/spire-agent.sock', '/run/openshell/ssh.sock',
    '/run/openshell/credential-driver.sock', '/run/openshell/compute-driver.sock')


def readable(path):
    """Measure access without retaining or printing any file contents."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except OSError:
        return False
    os.close(fd)
    return True


def credential_access():
    """Look for known custody boundaries, never disclose a credential value."""
    sockets = {}
    for path in PRIVATE_SOCKETS:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(1)
            try:
                client.connect(path)
                sockets[path] = True
            except OSError:
                sockets[path] = False
    supervisors = []
    for path in list(Path('/proc').glob('[0-9]*/comm'))[:4096]:
        try:
            name = path.read_text()[:128].strip()
        except OSError:
            continue
        if name.startswith('openshell-super'):
            supervisors.append(path.parent)
    sensitive = {'subject_token', 'access_token', 'gateway_token', 'api_key', 'jira_api_token',
        'openshell_gateway_token', 'openshell_sandbox_token', 'kubernetes_service_token'}
    names = sorted(k for k, value in os.environ.items() if k.lower() in sensitive
        and value and not value.startswith('OPENSHELL-RESOLVE-ENV-'))
    return {'private_files_readable': {p: readable(p) for p in PRIVATE_FILES},
        'privileged_sockets_connected': sockets, 'sensitive_environment_names': names,
        'supervisor_process_visible': bool(supervisors),
        'supervisor_environment_readable': any(readable(p / 'environ') for p in supervisors),
        'supervisor_memory_readable': any(readable(p / 'mem') for p in supervisors)}


def probe(destinations):
    if (not isinstance(destinations, list) or not 1 <= len(destinations) <= 24
            or any(set(v) != {'host', 'port'} or not isinstance(v['host'], str)
                or not re.fullmatch(r'[a-z0-9.:-]{1,253}', v['host'])
                or type(v['port']) is not int or v['port'] not in (443, 8080, 8443, 8444)
                for v in destinations)):
        raise ValueError('Bounded operator-observed destinations required')
    results = []
    for value in destinations:
        try:
            with socket.create_connection((value['host'], value['port']), timeout=2):
                connected = True
        except OSError:
            connected = False
        results.append({**value, 'connected': connected})
    return {'destinations': results, 'sensitive_mounts': {v: Path(v).exists() for v in PRIVATE_FILES},
        'credential_access': credential_access()}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destinations', required=True)
    print(json.dumps(probe(json.loads(parser.parse_args().destinations))))
