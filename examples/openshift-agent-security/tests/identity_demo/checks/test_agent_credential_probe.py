# SPDX-License-Identifier: Apache-2.0
"""Custody diagnostics report capabilities without leaking synthetic secrets."""
import importlib.util
import json
from pathlib import Path

import pytest


@pytest.fixture
def probe():
    path = Path(__file__).resolve().parents[3] / 'examples/document-agent/isolation_probe.py'
    spec = importlib.util.spec_from_file_location('custody_probe', path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def test_readability_check_never_returns_file_contents(probe, tmp_path):
    path = tmp_path / 'credential'
    path.write_text('synthetic-private-value')
    assert probe.readable(path) is True
    assert probe.readable(tmp_path / 'missing') is False
    linked = tmp_path / 'projected-credential'
    linked.symlink_to(path)
    assert probe.readable(linked) is True


def test_exposure_report_redacts_values_and_distinguishes_resolver_stubs(probe, monkeypatch):
    class Socket:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def settimeout(self, value): pass
        def connect(self, path): raise OSError('not mounted')
    monkeypatch.setattr(probe.socket, 'socket', lambda *args: Socket())
    monkeypatch.setattr(probe.Path, 'glob', lambda *args: [])
    monkeypatch.setattr(probe, 'readable', lambda path: str(path).endswith('/auth.json'))
    monkeypatch.setattr(probe.os, 'environ', {'access_token': 'synthetic-private-token',
        'api_key': 'OPENSHELL-RESOLVE-ENV-API_KEY', 'PUBLIC_VALUE': 'safe'})
    result = probe.credential_access()
    assert any(result['private_files_readable'].values())
    assert not any(result['privileged_sockets_connected'].values())
    assert result['sensitive_environment_names'] == ['access_token']
    assert 'synthetic-private-token' not in json.dumps(result)
    assert result['supervisor_process_visible'] is False
