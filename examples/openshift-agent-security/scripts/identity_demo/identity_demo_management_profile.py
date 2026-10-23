#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Measure read-only management overhead in an isolated profile and owned tunnel.

This does not change the coordinator, sandbox, provider, policy or issuer setup.
Only existing operator authentication is requested. No CLI response/token is logged.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import asdict
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import time
from typing import Callable, Iterator

from identity_demo_execution_setup import owned, read
from identity_demo_runtime import guard, NAMESPACE
from identity_demo_runtime_cli import private_path
from execution_context import resolve_context

MODES = ('fresh_tunnel_fresh_login', 'shared_tunnel_fresh_login', 'shared_tunnel_valid_login')


def remaining_seconds(path: Path) -> float:
    """Use the CLI's actual expiry metadata; never extend or log a token."""
    value = json.loads(private_path(str(path)).read_text())
    expiry = value.get('expires_at')
    if type(expiry) not in (int, float):
        raise ValueError('Numeric management token expiry required')
    return expiry - time.time()


def isolated_profile(source: Path, target: Path, issuer: str) -> Path:
    """Copy public trust/endpoint metadata only, never the coordinator token or last context."""
    private_path(str(source), directory=True)
    original = source / 'openshell/gateways/identity-demo-runtime'
    data = json.loads(private_path(str(original / 'metadata.json')).read_text())
    expected = {'name': 'identity-demo-runtime', 'auth_mode': 'oidc',
                'oidc_issuer': issuer + '/realms/identity-demo',
                'oidc_client_id': 'fixture-runtime-operator', 'oidc_audience': 'identity-demo-runtime'}
    if any(data.get(k) != v for k, v in expected.items()) or data.get('gateway_endpoint') != 'https://127.0.0.1:18443':
        raise ValueError('Existing exact owned management profile required')
    ca = private_path(str(original / 'mtls/ca.crt'))
    destination = target / 'openshell/gateways/identity-demo-runtime'
    (destination / 'mtls').mkdir(mode=0o700, parents=True)
    for directory in (target, target / 'openshell', target / 'openshell/gateways', destination):
        os.chmod(directory, 0o700)
    for path, payload in ((destination / 'metadata.json', json.dumps(data).encode()),
                          (destination / 'mtls/ca.crt', ca.read_bytes()),
                          (target / 'openshell/active_gateway', b'identity-demo-runtime\n')):
        path.write_bytes(payload)
        path.chmod(0o600)
    return destination


class Recorder:
    """Record phase names and elapsed durations; command arguments/results stay private."""

    def __init__(self) -> None:
        self.events: list[dict] = []
        self.mode = 'preflight'
        self.sample = 0

    def measure(self, phase: str, operation: Callable) -> object:
        """Record failures too, without copying exception strings or subprocess output."""
        started = time.monotonic()
        succeeded = False
        try:
            result = operation()
            succeeded = True
            return result
        finally:
            event = {'mode': self.mode, 'sample': self.sample, 'phase': phase,
                     'seconds': round(time.monotonic() - started, 4), 'passed': succeeded}
            self.events.append(event)
            print(json.dumps(event), flush=True)


@contextmanager
def tunnel(args: argparse.Namespace, profile: Path, recorder: Recorder) -> Iterator[int]:
    """Use an OS-selected loopback port; terminate only this probe's own process."""
    recorder.measure('owned_service_check', lambda: owned(read(args, 'service', 'fixture-openshell', NAMESPACE)))
    logfile = args.output_dir / ('tunnel-' + str(len(recorder.events)) + '.private.log')
    with logfile.open('x') as log:
        logfile.chmod(0o600)
        process = subprocess.Popen(['oc', '--kubeconfig', args.kubeconfig, '-n', NAMESPACE,
            'port-forward', '--address', '127.0.0.1', 'service/fixture-openshell', '0:8080'], stdout=log, stderr=log)
        try:
            def connect() -> int:
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    match = re.search(r'Forwarding from 127\.0\.0\.1:(\d+) ->', logfile.read_text())
                    if match:
                        return int(match[1])
                    if process.poll() is not None:
                        raise RuntimeError('Own probe tunnel exited; output withheld')
                    time.sleep(.05)
                raise TimeoutError('Own probe tunnel did not become ready')
            port = recorder.measure('tunnel_ready', connect)
            metadata = profile / 'metadata.json'
            value = json.loads(metadata.read_text())
            value['gateway_endpoint'] = 'https://127.0.0.1:' + str(port)
            metadata.write_text(json.dumps(value))
            context = ssl.create_default_context(cafile=str(profile / 'mtls/ca.crt'))
            def verify() -> None:
                with socket.create_connection(('127.0.0.1', port), timeout=10) as connection:
                    with context.wrap_socket(connection, server_hostname='127.0.0.1'):
                        pass
            recorder.measure('tls_probe', verify)
            yield port
        finally:
            def stop() -> None:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
            recorder.measure('tunnel_stop', stop)


def run(args: argparse.Namespace, recorder: Recorder) -> dict:
    """Compare fresh and reused management sessions using the same exact sandbox GET."""
    args.namespace = NAMESPACE
    _, credentials, issuer = recorder.measure('cluster_owner_guard', lambda: guard(args))
    context = recorder.measure('validate_execution_context', lambda: resolve_context(args.context_file,
        lambda kind, name, ns=None: read(args, kind, name, ns)))
    profile = recorder.measure('isolate_profile', lambda: isolated_profile(Path(args.cli_config_dir),
        args.output_dir / 'cli-profile', issuer))
    env = {**os.environ, 'XDG_CONFIG_HOME': str(args.output_dir / 'cli-profile'),
           'OPENSHELL_OIDC_CLIENT_SECRET': credentials['runtime_management']['client_secret']}
    for key in ('OPENSHELL_GATEWAY', 'OPENSHELL_GATEWAY_ENDPOINT', 'OPENSHELL_GATEWAY_INSECURE',
                'OPENSHELL_WORKSPACE', 'subject_token', 'api_key'):
        env.pop(key, None)
    token_path = profile / 'oidc_token.json'
    observed_lifetimes = []

    def login() -> None:
        result = subprocess.run([args.cli, 'gateway', 'login', 'identity-demo-runtime'], env=env,
                                capture_output=True, timeout=35)
        if result.returncode:
            raise RuntimeError('Isolated management login failed; output withheld')
        remaining = remaining_seconds(token_path)
        if remaining <= 30:
            raise ValueError('New management session has insufficient remaining lifetime')
        observed_lifetimes.append(round(remaining, 2))

    def query(words: list[str], kind: str) -> None:
        if remaining_seconds(token_path) <= 30:
            recorder.measure('expiry_refresh_login', login)
        def execute() -> None:
            result = subprocess.run([args.cli, '--gateway', 'identity-demo-runtime', '--workspace', context.workspace,
                *words], env=env, capture_output=True, text=True, timeout=35)
            if result.returncode:
                raise RuntimeError('Read-only query failed; output withheld; no retry')
            value = json.loads(result.stdout)
            if kind == 'sandbox_get' and (value.get('id') != context.sandbox_id or value.get('phase') != 'Ready'):
                raise ValueError('Exact ready execution identity required')
        recorder.measure(kind, execute)

    words = ['sandbox', 'get', context.sandbox_name, '--output', 'json']
    for mode in MODES:
        recorder.mode, recorder.sample = mode, 0
        if mode == 'fresh_tunnel_fresh_login':
            # Match native_session's initial login and immediate reconnect/relogin before the first command.
            with tunnel(args, profile, recorder):
                recorder.measure('initial_login', login)
            for sample in range(1, args.samples + 1):
                recorder.sample = sample
                with tunnel(args, profile, recorder):
                    recorder.measure('command_login', login)
                    query(words, 'sandbox_get')
        else:
            with tunnel(args, profile, recorder):
                recorder.measure('initial_login', login)
                for sample in range(1, args.samples + 1):
                    recorder.sample = sample
                    if mode == 'shared_tunnel_fresh_login':
                        recorder.measure('command_login', login)
                    query(words, 'sandbox_get')
                if mode == 'shared_tunnel_valid_login':
                    query(['sandbox', 'provider', 'list', context.sandbox_name, '--output', 'json'], 'provider_list')
                    query(['workspace', 'list', '--output', 'json'], 'workspace_list')
    return {'passed': True, 'samples_per_mode': args.samples, 'read_only_queries': args.samples * 3 + 2,
            'credential_values_logged': False, 'coordinator_profile_modified': False,
            'main_loopback_port_used': False, 'management_session_lifetimes_seconds': observed_lifetimes,
            'context': asdict(context), 'events': recorder.events}


def main() -> int:
    """Require private explicit inputs and a new output directory; print sanitized durations only."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('kubeconfig', 'expected-server', 'credentials-file', 'cli', 'cli-config-dir', 'context-file', 'output-dir'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--samples', type=int, choices=range(1, 6), default=3)
    args = parser.parse_args()
    os.umask(0o077)
    location = Path(args.output_dir)
    private_path(str(location.parent), directory=True)
    location.mkdir(mode=0o700)
    args.output_dir = location
    recorder = Recorder()
    result = {'passed': False}
    try:
        result = run(args, recorder)
        return 0
    except Exception as error:
        result.update(failure_kind=type(error).__name__, events=recorder.events)
        print(json.dumps({'passed': False, 'failure_kind': type(error).__name__, 'details_withheld': True}))
        return 1
    finally:
        token = args.output_dir / 'cli-profile/openshell/gateways/identity-demo-runtime/oidc_token.json'
        token.unlink(missing_ok=True)
        result['local_session_artifact_removed'] = not token.exists()
        destination = args.output_dir / 'management-profile.summary.private.json'
        destination.write_text(json.dumps(result, indent=2))
        destination.chmod(0o600)


if __name__ == '__main__':
    raise SystemExit(main())
