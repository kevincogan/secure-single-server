# SPDX-License-Identifier: Apache-2.0
"""The timing probe isolates operator state, logs no credentials and never retries reads."""
import json
from pathlib import Path
from types import SimpleNamespace
import time
from contextlib import contextmanager

import pytest

import identity_demo_management_profile as probe
from identity_demo_execution_setup import context_template


def source_profile(tmp_path: Path) -> Path:
    root = tmp_path / 'source'
    target = root / 'openshell/gateways/identity-demo-runtime'
    (target / 'mtls').mkdir(parents=True)
    metadata = {'name': 'identity-demo-runtime', 'auth_mode': 'oidc',
                'gateway_endpoint': 'https://127.0.0.1:18443',
                'oidc_issuer': 'https://issuer.example.test/realms/identity-demo',
                'oidc_client_id': 'fixture-runtime-operator', 'oidc_audience': 'identity-demo-runtime'}
    (target / 'metadata.json').write_text(json.dumps(metadata))
    (target / 'oidc_token.json').write_text(json.dumps({'access_token': 'do-not-copy-fixture-token', 'expires_at': 1}))
    (target / 'mtls/ca.crt').write_text('public-ca-fixture')
    (target / 'last_sandbox').write_text('another-user-context')
    for path in (root, *root.rglob('*')):
        path.chmod(0o700 if path.is_dir() else 0o600)
    return root


def test_profile_copies_public_trust_but_never_existing_token_or_last_context(tmp_path: Path) -> None:
    source = source_profile(tmp_path)
    destination = probe.isolated_profile(source, tmp_path / 'isolated', 'https://issuer.example.test')
    assert (destination / 'mtls/ca.crt').read_text() == 'public-ca-fixture'
    assert not (destination / 'oidc_token.json').exists()
    assert not (destination / 'last_sandbox').exists()
    assert (source / 'openshell/gateways/identity-demo-runtime/oidc_token.json').exists()
    assert all(p.stat().st_mode & 0o077 == 0 for p in (tmp_path / 'isolated').rglob('*'))
    with pytest.raises(FileExistsError):
        probe.isolated_profile(source, tmp_path / 'isolated', 'https://issuer.example.test')


@pytest.mark.parametrize('field,value', [('gateway_endpoint', 'https://other.invalid'),
                                       ('oidc_issuer', 'https://other.invalid'), ('oidc_client_id', 'admin')])
def test_profile_refuses_different_identity_or_endpoint(tmp_path: Path, field: str, value: str) -> None:
    source = source_profile(tmp_path)
    location = source / 'openshell/gateways/identity-demo-runtime/metadata.json'
    data = json.loads(location.read_text())
    data[field] = value
    location.write_text(json.dumps(data))
    with pytest.raises(ValueError, match='exact owned'):
        probe.isolated_profile(source, tmp_path / 'new', 'https://issuer.example.test')
    assert not (tmp_path / 'new').exists()


def test_expiry_is_observed_without_extending_it(tmp_path: Path) -> None:
    token = tmp_path / 'token.private.json'
    token.write_text(json.dumps({'expires_at': time.time() - 5, 'access_token': 'fixture'}))
    token.chmod(0o600)
    before = token.read_bytes()
    assert probe.remaining_seconds(token) < 0
    assert token.read_bytes() == before
    token.write_text(json.dumps({'expires_at': True}))
    with pytest.raises(ValueError):
        probe.remaining_seconds(token)


def test_failure_timing_does_not_log_secret_exception_text(capsys) -> None:
    recorder = probe.Recorder()
    def failed() -> None:
        raise RuntimeError('private-fixture-token')
    with pytest.raises(RuntimeError):
        recorder.measure('management_login', failed)
    assert recorder.events[0]['passed'] is False
    assert 'private-fixture-token' not in capsys.readouterr().out


def test_modes_only_issue_fixed_reads_and_cached_mode_avoids_relogin(tmp_path: Path, monkeypatch) -> None:
    context = context_template('triage', 'abc')
    args = SimpleNamespace(output_dir=tmp_path, context_file='private', cli_config_dir='private', cli='openshell', samples=3)
    profile = tmp_path / 'profile'
    profile.mkdir(mode=0o700)
    monkeypatch.setattr(probe, 'guard', lambda a: (None, {'runtime_management': {'client_secret': 'fixture-only'}}, 'issuer'))
    monkeypatch.setattr(probe, 'resolve_context', lambda *a: context)
    monkeypatch.setattr(probe, 'isolated_profile', lambda *a: profile)
    @contextmanager
    def tunnel(*args: object):
        yield 10000
    monkeypatch.setattr(probe, 'tunnel', tunnel)
    commands = []
    def command(words: list, **kwargs: object) -> object:
        commands.append(words)
        if words[1:3] == ['gateway', 'login']:
            token = profile / 'oidc_token.json'
            token.write_text(json.dumps({'expires_at': time.time() + 300}))
            token.chmod(0o600)
            return SimpleNamespace(returncode=0)
        assert words[5:7] in (['sandbox', 'get'], ['sandbox', 'provider'], ['workspace', 'list'])
        return SimpleNamespace(returncode=0, stdout=json.dumps({'id': context.sandbox_id, 'phase': 'Ready'}))
    monkeypatch.setattr(probe.subprocess, 'run', command)
    recorder = probe.Recorder()
    result = probe.run(args, recorder)
    assert result['passed'] and result['read_only_queries'] == 11
    logins = [e for e in recorder.events if e['phase'].endswith('login')]
    assert [sum(e['mode'] == mode for e in logins) for mode in probe.MODES] == [4, 4, 1]
    assert len([e for e in recorder.events if e['phase'] == 'sandbox_get']) == 9
    assert 'fixture-only' not in json.dumps(result)
