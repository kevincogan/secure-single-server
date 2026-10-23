# SPDX-License-Identifier: Apache-2.0
"""Real native session dispatch retains expiry, ownership, TLS and mutation safety."""

from argparse import Namespace
from contextlib import nullcontext
import json
from pathlib import Path
import ssl
import subprocess
import time

import pytest

import probe_native_exchange as native
import identity_demo_management_session as session
from checks.test_management_profile import source_profile


def harness(tmp_path: Path, monkeypatch, operation=None, health=None) -> tuple:
    config = source_profile(tmp_path)
    profile = config / "openshell/gateways/identity-demo-runtime"
    processes, commands, logins, ownership = [], [], [], []

    class Process:
        def __init__(self, *a, **kw):
            self.active = True
            processes.append(self)

        def poll(self):
            return None if self.active else 0

        def terminate(self):
            self.active = False

        def wait(self, timeout):
            return 0

    def connect(*a, **kw):
        if processes and processes[-1].active:
            return nullcontext()
        raise OSError("no listener")

    def run(words, **kw):
        if words[1:3] == ["gateway", "login"]:
            logins.append(True)
            (profile / "oidc_token.json").write_text(
                json.dumps({"expires_at": time.time() + 60})
            )
        else:
            commands.append(words)
            if operation:
                return operation(words, profile, processes)
        return subprocess.CompletedProcess(words, 0, "{}", "")

    def owned(*a, **kw):
        ownership.append(True)
        return {"metadata": {"labels": dict(native.LABELS)}}

    monkeypatch.setattr(native.socket, "create_connection", connect)
    monkeypatch.setattr(native.subprocess, "Popen", Process)
    monkeypatch.setattr(native.subprocess, "run", run)
    monkeypatch.setattr(native, "kube", owned)
    monkeypatch.setattr(session, "verify_transport", health or (lambda *a: None))
    args = Namespace(
        cli_config_dir=str(config),
        output_dir=tmp_path,
        label="candidate",
        kubeconfig="private",
        cli="openshell",
        reuse_management_session=True,
    )
    credentials = {
        "keycloak_url": "https://issuer.example.test",
        "runtime_management": {"client_secret": "fixture-only"},
    }
    return args, credentials, processes, commands, logins, ownership


def test_healthy_short_burst_reuses_tunnel_and_login(tmp_path, monkeypatch):
    args, credentials, processes, commands, logins, ownership = harness(
        tmp_path, monkeypatch
    )
    with native.native_session(args, credentials) as execute:
        execute(["provider", "list"])
        execute(["workspace", "list"])
        execute(["provider", "delete", "owned-provider"])
    assert len(processes) == 1 and len(logins) == 1 and len(commands) == 3
    assert len(ownership) == 4  # Initial target and every command, including reads.
    assert not processes[0].active
    evidence = json.loads(
        (tmp_path / "candidate.management-timing.private.json").read_text()
    )
    assert evidence["reuse_enabled"] and evidence["operation_transport_replays"] == 0
    assert "fixture-only" not in json.dumps(evidence)


def test_subject_bearing_commands_never_persist_reflected_output(tmp_path,monkeypatch):
    canary='synthetic-subject-secret-canary'
    def operation(words,profile,processes):
        return subprocess.CompletedProcess(words,0,canary,'reflected '+canary)
    args,credentials,*_=harness(tmp_path,monkeypatch,operation=operation)
    with native.native_session(args,credentials) as execute:
        execute(['provider','create','owned'],subject=canary)
    for path in tmp_path.glob('candidate.cli-*'):
        assert canary not in path.read_text()
    assert 'withheld' in (tmp_path/'candidate.cli-01.stdout').read_text()


def test_expiry_refresh_does_not_reconnect_or_change_subject(tmp_path, monkeypatch):
    def operation(words, profile, processes):
        (profile / "oidc_token.json").write_text(
            json.dumps({"expires_at": time.time() + 10})
        )
        return subprocess.CompletedProcess(words, 0, "{}", "")

    args, credentials, processes, commands, logins, _ = harness(
        tmp_path, monkeypatch, operation
    )
    with native.native_session(args, credentials) as execute:
        execute(["provider", "list"])
        execute(["provider", "list"])
    assert len(logins) == 2 and len(processes) == 1 and len(commands) == 2


def test_dead_channel_is_replaced_before_any_operation_not_replayed(
    tmp_path, monkeypatch
):
    health_calls = []

    def health(*a):
        health_calls.append(True)
        if len(health_calls) == 1:
            raise ConnectionResetError("fixture reset before dispatch")

    args, credentials, processes, commands, logins, _ = harness(
        tmp_path, monkeypatch, health=health
    )
    with native.native_session(args, credentials) as execute:
        execute(["provider", "list"])
    assert len(processes) == 2 and len(commands) == 1 and len(logins) == 1
    assert all(not p.active for p in processes)


def test_certificate_failure_does_not_reconnect_or_dispatch(tmp_path, monkeypatch):
    def health(*a):
        raise ssl.SSLCertVerificationError("fixture certificate rejected")

    args, credentials, processes, commands, logins, _ = harness(
        tmp_path, monkeypatch, health=health
    )
    with native.native_session(args, credentials) as execute:
        with pytest.raises(ssl.SSLCertVerificationError):
            execute(["provider", "delete", "owned-provider"])
    assert (
        len(processes) == len(logins) == 1 and not commands and not processes[0].active
    )


def test_ambiguous_cli_write_is_never_replayed(tmp_path, monkeypatch):
    def operation(words, *a):
        return subprocess.CompletedProcess(words, 1, "", "connection reset after save")

    args, credentials, processes, commands, _, _ = harness(
        tmp_path, monkeypatch, operation
    )
    with native.native_session(args, credentials) as execute:
        with pytest.raises(RuntimeError):
            execute(["provider", "delete", "owned-provider"])
    assert len(commands) == len(processes) == 1 and not processes[0].active


def test_profile_change_is_rejected_before_next_command(tmp_path, monkeypatch):
    args, credentials, processes, commands, _, _ = harness(tmp_path, monkeypatch)
    with native.native_session(args, credentials) as execute:
        location = (
            Path(args.cli_config_dir)
            / "openshell/gateways/identity-demo-runtime/metadata.json"
        )
        value = json.loads(location.read_text())
        value["oidc_audience"] = "another-gateway"
        location.write_text(json.dumps(value))
        with pytest.raises(ValueError, match="Exact owned"):
            execute(["provider", "list"])
    assert not commands and not processes[0].active


@pytest.mark.parametrize("expiry", [True, None, float("inf"), float("nan"), "tomorrow"])
def test_invalid_expiry_cannot_authorize_session_reuse(tmp_path, expiry):
    p = tmp_path / "oidc_token.json"
    p.write_text(json.dumps({"expires_at": expiry}))
    p.chmod(0o600)
    before = p.read_bytes()
    with pytest.raises(ValueError):
        session.remaining_seconds(tmp_path)
    assert p.read_bytes() == before


def test_initial_tunnel_timeout_retries_only_connection_before_dispatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A cold management tunnel is replaced once without replaying an operation."""
    args, credentials, processes, commands, logins, _ = harness(tmp_path, monkeypatch)
    monkeypatch.setattr(native.time, "sleep", lambda _: None)

    def cold_first(*a: object, **kw: object) -> object:
        if len(processes) >= 2 and processes[-1].active:
            return nullcontext()
        raise OSError("cold tunnel")

    monkeypatch.setattr(native.socket, "create_connection", cold_first)
    with native.native_session(args, credentials) as execute:
        execute(["provider", "list"])
    assert len(processes) == 2 and len(commands) == 1 and len(logins) == 1
    assert not any(p.active for p in processes)
    receipt = json.loads((tmp_path / "candidate.management-timing.private.json").read_text())
    assert receipt["operation_transport_replays"] == 0
    assert any(v["phase"] == "tunnel_startup_retry" and v["passed"] for v in receipt["events"])


def test_exhausted_initial_tunnels_stop_before_authentication_or_dispatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Two failed startup attempts terminate both owned processes and fail closed."""
    args, credentials, processes, commands, logins, _ = harness(tmp_path, monkeypatch)
    monkeypatch.setattr(native.time, "sleep", lambda _: None)

    def unavailable(*a: object, **kw: object) -> object:
        raise OSError("unavailable")

    monkeypatch.setattr(native.socket, "create_connection", unavailable)
    with pytest.raises(native.NativeTunnelStartupError):
        with native.native_session(args, credentials):
            pytest.fail("No native dispatch is allowed")
    assert len(processes) == 2 and not commands and not logins
    assert not any(p.active for p in processes)
