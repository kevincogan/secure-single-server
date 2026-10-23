# SPDX-License-Identifier: Apache-2.0
"""Offline guards for exact API groups, private SVID parsing and run retirement."""

from __future__ import annotations

import argparse
import base64
from copy import deepcopy
import json
import subprocess
from contextlib import nullcontext

import pytest

import native_backend as backend
import native_run_lifecycle as lifecycle
import native_sender_acceptance as sender
import probe_native_exchange as native
import native_audit
from run_binding import ReadRun


def ledger(records: list[dict]) -> dict:
    """Build synthetic retained state with the established ownership labels."""
    return {"metadata": {"labels": dict(native.LABELS)}, "data": {"runs.json": json.dumps(records)}}


def test_retired_identity_cannot_move_to_another_user_or_run(monkeypatch: pytest.MonkeyPatch) -> None:
    """Changing user/run data never frees an old execution identity."""
    monkeypatch.setattr(native, "kube", lambda *a, **kw: ledger([
        {"workload": native.WORKLOAD, "user_subject": "old-user", "run_id": "old-run", "active": False}]))
    with pytest.raises(lifecycle.RetiredIdentityError):
        lifecycle.require_unused_identity(argparse.Namespace(), native.WORKLOAD)


@pytest.mark.parametrize("change", ["labels", "malformed", "oversized"])
def test_untrusted_retirement_state_never_counts_as_unused(change: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Unreadable or unowned state must fail before a new provider is attached."""
    item = ledger([])
    if change == "labels":
        item["metadata"]["labels"] = {}
    elif change == "malformed":
        item["data"]["runs.json"] = "{}"
    else:
        item = ledger([{"workload": "another"}] * 17)
    monkeypatch.setattr(native, "kube", lambda *a, **kw: item)
    with pytest.raises(ValueError):
        lifecycle.require_unused_identity(argparse.Namespace(), native.WORKLOAD)


def test_conditional_cleanup_retries_only_matching_owned_state(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Controller status churn can retry; API group/UID/spec guards stay mandatory."""
    item = {"apiVersion": "mcp.kuadrant.io/v1alpha1", "kind": "MCPServerRegistration",
            "metadata": {"name": "fixture-step4-read-route", "uid": "exact", "resourceVersion": "1",
                         "labels": dict(native.LABELS)}, "spec": {"prefix": "step4_read_"}}
    calls, deletes = [], []

    def kube(args, *words, **kwargs):
        calls.append(words)
        if words[0] == "delete":
            deletes.append(json.loads(open(words[-1]).read()))
            if len(deletes) == 1:
                raise RuntimeError("Conflict")
            return {}
        result = deepcopy(item)
        if deletes:
            result["metadata"]["resourceVersion"] = "2"
        return result

    monkeypatch.setattr(backend.shared, "kube", kube)
    probe = backend.NativeBackend(argparse.Namespace(output_dir=tmp_path, label="test"))
    probe.ledger = [item]
    probe.cleanup()
    assert all(call[1] == "mcpserverregistration.mcp.kuadrant.io" for call in calls if call[0] == "get")
    assert [v["preconditions"] for v in deletes] == [
        {"uid": "exact", "resourceVersion": "1"}, {"uid": "exact", "resourceVersion": "2"}]


def test_native_jwt_output_requires_one_exact_svid(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """SPIRE's multi-response JSON is normalized without broad identity selection."""
    probe = sender.SenderAcceptance.__new__(sender.SenderAcceptance)
    probe.args = argparse.Namespace(kubeconfig="private", label="test")
    probe.directory, probe.count = tmp_path, 0
    value = [{"svids": [{"spiffe_id": native.WORKLOAD, "svid": "synthetic.assertion.only"}]}, {"bundles": {}}]
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: subprocess.CompletedProcess(
        a[0], 0, stdout=json.dumps(value), stderr=""))
    result = probe.fetch("jwt")
    assert result["token"] == "synthetic.assertion.only"
    value[0]["svids"].append({"spiffe_id": "another", "svid": "synthetic"})
    with pytest.raises(ValueError):
        probe.fetch("jwt")


def test_viewer_tool_denial_uses_a_real_broker_session(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A missing-session 400 must never stand in for the actual tool's 403."""
    probe = sender.SenderAcceptance.__new__(sender.SenderAcceptance)
    probe.args = argparse.Namespace(label="viewer")
    probe.directory = tmp_path
    calls = []

    def request(port: int, host: str, path: str, body: bytes, certificate: sender.Certificate | None,
                headers: dict[str, str], response_headers: dict[str, str] | None = None) -> tuple[int, bytes]:
        payload = json.loads(body)
        calls.append((payload, dict(headers)))
        if payload["method"] == "initialize":
            assert response_headers is not None
            response_headers["Mcp-Session-Id"] = "synthetic-session"
            return 200, b'{}'
        assert headers["Mcp-Session-Id"] == "synthetic-session"
        assert headers["Authorization"] == "Bearer synthetic-token"
        assert headers["MCP-Protocol-Version"] == "2025-11-25"
        return (202, b'') if payload["method"] == "notifications/initialized" else (403, b'{}')

    monkeypatch.setattr(probe, "request", request)
    assert probe.gateway("viewer", "synthetic-token", None, tool_call=True)["http_status"] == 403
    assert [call[0]["method"] for call in calls] == [
        "initialize", "notifications/initialized", "tools/call"]


def test_viewer_tool_denial_refuses_failed_session_setup(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Protocol errors stop the diagnostic before any permission claim."""
    probe = sender.SenderAcceptance.__new__(sender.SenderAcceptance)
    probe.args, probe.directory = argparse.Namespace(label="viewer"), tmp_path
    monkeypatch.setattr(probe, "request", lambda *a, **kw: (400, b'{}'))
    with pytest.raises(ValueError, match="Real broker initialization required"):
        probe.gateway("viewer", "synthetic-token", None, tool_call=True)


def test_viewer_cannot_replace_user_in_existing_session(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The tool uses the substituted credential even on an analyst's session."""
    probe = sender.SenderAcceptance.__new__(sender.SenderAcceptance)
    probe.args, probe.directory = argparse.Namespace(label="viewer"), tmp_path
    calls = []

    def request(port: int, host: str, path: str, body: bytes, certificate: sender.Certificate | None,
                headers: dict[str, str]) -> tuple[int, bytes]:
        calls.append(json.loads(body)["method"])
        assert headers["Authorization"] == "Bearer viewer-token"
        assert headers["Mcp-Session-Id"] == "analyst-session"
        return 403, b'{}'

    monkeypatch.setattr(probe, "request", request)
    assert probe.gateway("viewer", "viewer-token", None, tool_call=True, session_headers={
        "Mcp-Session-Id": "analyst-session", "MCP-Protocol-Version": "2025-11-25"})["http_status"] == 403
    assert calls == ["tools/call"]


@pytest.mark.parametrize("values", [[], ["x" * 700], ["same", "same"]])
def test_broker_session_header_supports_jwt_and_exact_duplicates(values: list[str]) -> None:
    """The installed signed session format fits the bounded diagnostic."""
    assert sender.session_header(values) == (values[0] if values else None)


@pytest.mark.parametrize("values", [["a", "b"], ["x" * 4097], ["x\r\ny"], ["has space"]])
def test_broker_session_header_refuses_ambiguity_and_injection(values: list[str]) -> None:
    """A response cannot smuggle conflicting or unsafe session headers."""
    with pytest.raises(ValueError):
        sender.session_header(values)


def test_sender_http_requests_each_use_fresh_tunnel_without_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    """A failed streaming connection is never retained across HTTP operations."""
    probe = sender.SenderAcceptance.__new__(sender.SenderAcceptance)
    tunnels, requests = [], []

    def tunnel(service: str, port: int, remote: int) -> nullcontext:
        tunnels.append((service, port, remote))
        return nullcontext()

    def request(*args: object) -> tuple[int, bytes]:
        requests.append(args)
        return 403, b'{}'

    monkeypatch.setattr(probe, "tunnel", tunnel)
    monkeypatch.setattr(probe, "_request_once", request)
    for _ in range(2):
        assert probe.request(19444, sender.HOST, "/mcp", b'{}', None, {}) == (403, b'{}')
    assert len(tunnels) == len(requests) == 2
    with pytest.raises(ValueError, match="Exact owned"):
        probe.request(19444, "another-host", "/mcp", b'{}', None, {})
    assert len(tunnels) == 2

    def fail(*args: object) -> tuple[int, bytes]:
        requests.append(args)
        raise ConnectionRefusedError("synthetic dropped tunnel")

    monkeypatch.setattr(probe, "_request_once", fail)
    with pytest.raises(ConnectionRefusedError):
        probe.request(19444, sender.HOST, "/mcp", b'{}', None, {})
    assert len(tunnels) == len(requests) == 3


def test_native_commands_refresh_only_owned_tunnel_without_operation_retries(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Reset streaming channels are replaced before issuing each CLI command."""
    config = tmp_path / "config"
    config.mkdir(mode=0o700)
    processes = []
    commands = []

    class Process:
        """Represent one exclusively owned private management tunnel."""

        def __init__(self, *args: object, **kwargs: object) -> None:
            self.active = True
            processes.append(self)

        def poll(self) -> int | None:
            return None if self.active else 0

        def terminate(self) -> None:
            self.active = False

        def wait(self, timeout: int) -> int:
            return 0

    def connect(*args: object, **kwargs: object) -> nullcontext:
        if processes and processes[-1].active:
            return nullcontext()
        raise OSError("no local listener")

    def run(words: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        commands.append(words)
        return subprocess.CompletedProcess(words, 0, stdout="{}", stderr="")

    monkeypatch.setattr(native.socket, "create_connection", connect)
    monkeypatch.setattr(native.subprocess, "Popen", Process)
    monkeypatch.setattr(native.subprocess, "run", run)
    monkeypatch.setattr(native, "kube", lambda *a, **kw: {"metadata": {"labels": dict(native.LABELS)}})
    args = argparse.Namespace(cli_config_dir=str(config), output_dir=tmp_path, label="fresh-tunnels",
                              kubeconfig="private", cli="openshell")
    with native.native_session(args, {"runtime_management": {"client_secret": "synthetic"}}) as execute:
        execute(["provider", "list"])
        execute(["provider", "profile", "list"])
    assert len(processes) == 3 and all(not p.active for p in processes)
    operations = [words for words in commands if "--workspace" in words]
    assert len(operations) == 2


def test_expired_native_credential_requires_release_denial_not_readiness(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A negative credential is proved through gRPC, without a Ready observer."""
    replies = iter([(0, b'positive'), (9, b''), (7, b'')])
    monkeypatch.setattr(lifecycle, "SenderAcceptance", lambda *a: type("Sender", (), {
        "intermediate": lambda self: next(replies)})())
    monkeypatch.setattr(native, "wait_authorizer", lambda *a: None)
    spec = {"rules": {"authorization": {}}}
    before = {"metadata": {"uid": "owned", "resourceVersion": "1"}, "spec": spec}
    monkeypatch.setattr(native, "kube", lambda args, *words, **kw: (
        {**before, "spec": json.loads(words[words.index("-p") + 1])[-1]["value"]}
        if words[0] == "patch" else before))
    monkeypatch.setattr(lifecycle, "retire", lambda *a: {"identity_reassignment_denied": True})
    commands = []

    def execute(words: list[str], **kwargs: object) -> dict:
        commands.append(words)
        return {"read_passed": False, "events": [{"http_status": 403}]}

    backend = type("Backend", (), {"set_run": lambda self, run: None})()
    run = ReadRun("run", "https://issuer.test/realms/demo", "analyst", native.WORKLOAD,
                  "https://mcp.test/mcp", 100, 300)
    result, _ = lifecycle.check(argparse.Namespace(label="expiry", output_dir=tmp_path), execute,
        {}, {"access_token": "synthetic"}, run, "frontend", before, spec, backend, "owned-provider")
    assert result["passed"]
    assert "--wait" not in commands[1]
    assert result["cases"][0] == {"case": "expired_subject_denied_before_release", "grpc_status": 9,
                                 "response_message_present": False, "passed": True}


@pytest.mark.parametrize("change", [None, "leaf", "user", "token", "request", "private_only"])
def test_audit_requires_actual_tls_binding_and_safe_fields(change: str | None) -> None:
    """Private forwarded headers or leaked credentials cannot replace TLS proof."""
    run = ReadRun("run", "https://issuer.test/realms/demo", "analyst", native.WORKLOAD,
                  "https://mcp.test/mcp", 100, 300)
    digest = bytes(range(32))
    record = {"event": "step4-private-read", "status": 200, "request": "correlation",
              "peer_hash": digest.hex(), "verified": {
                  "run": "run", "user": "analyst", "workload": native.WORKLOAD,
                  "expiry": 200, "policy": "step4-protected-read",
                  "cnf": base64.urlsafe_b64encode(digest).decode().rstrip("=")}}
    if change == "leaf":
        record["peer_hash"] = "00" * 32
    elif change == "user":
        record["verified"]["user"] = "different-user"
    elif change == "token":
        record["verified"]["access_token"] = "synthetic-forbidden"
    elif change == "request":
        record.pop("request")
    elif change == "private_only":
        record["peer_hash"] = None
    if change is None:
        assert native_audit.assess(json.dumps(record), run)["passed"]
    else:
        with pytest.raises(ValueError):
            native_audit.assess(json.dumps(record), run)


def test_bound_router_moves_after_existing_authorization_only() -> None:
    """Change filter order without changing the broker endpoint or adding services."""
    generated = {"applyTo": "HTTP_FILTER", "match": {"context": "GATEWAY", "listener": {"portNumber": 8443}},
                 "patch": {"operation": "INSERT_FIRST", "value": {"name": "envoy.filters.http.ext_proc",
                            "typed_config": {"failure_mode_allow": False}}}}
    original = deepcopy(generated)
    private, remove, bound = backend.router_patches(generated)
    assert generated == original
    assert private["match"]["listener"]["portNumber"] == 8080
    assert remove["patch"]["operation"] == "REMOVE"
    assert bound["patch"]["operation"] == "INSERT_AFTER"
    assert bound["patch"]["value"] == generated["patch"]["value"]
    assert bound["match"]["listener"]["filterChain"]["filter"]["subFilter"]["name"] == "envoy.filters.http.wasm"


@pytest.mark.parametrize("change", [None, "first", "duplicate", "absent"])
def test_bound_readiness_requires_authorization_before_mcp(change: str | None) -> None:
    """An HTTP 500 cannot be hidden by accepting the wrong effective order."""
    names = ["envoy.filters.http.wasm", "envoy.filters.http.ext_proc",
             backend.route.FILTER + "-step4", "envoy.filters.http.router"]
    if change == "first":
        names[0], names[1] = names[1], names[0]
    elif change == "duplicate":
        names.append("envoy.filters.http.ext_proc")
    elif change == "absent":
        names.remove("envoy.filters.http.wasm")
    dump = {"listener": {"address": {"socket_address": {"port_value": 8443}},
                         "config": {"http_filters": [{"name": n} for n in names]}}}
    assert backend.bound_authorization_first(dump) == (change is None)


@pytest.mark.parametrize("failure, expected_attempts, succeeds", [
    ("Error:   × Failed to attach provider: sandbox was modified by another operation.\n"
     "  │ Please retry the command.\n", 2, True),
    ("persistent", 3, False),
    ("saved attachment; readiness outcome uncertain; Please retry the command.", 1, False),
    ("connection reset by peer", 1, False),
])
def test_native_attachment_retries_only_explicit_presave_conflict(
    tmp_path, monkeypatch: pytest.MonkeyPatch, failure: str, expected_attempts: int, succeeds: bool,
) -> None:
    """CAS rejection can retry; post-save uncertainty and transport failures cannot."""
    config = tmp_path / "config"
    config.mkdir(mode=0o700)
    processes, operations, sleeps = [], [], []

    class Process:
        def __init__(self, *args: object, **kwargs: object) -> None:
            self.active = True
            processes.append(self)

        def poll(self) -> int | None:
            return None if self.active else 0

        def terminate(self) -> None:
            self.active = False

        def wait(self, timeout: int) -> int:
            return 0

    def connect(*args: object, **kwargs: object) -> nullcontext:
        if processes and processes[-1].active:
            return nullcontext()
        raise OSError("no local listener")

    conflict = ("Error:   × Failed to attach provider: sandbox was modified by another operation.\n"
                "  │ Please retry the command.\n")

    def run(words: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        if "--workspace" not in words:
            return subprocess.CompletedProcess(words, 0, stdout="{}", stderr="")
        operations.append(words)
        if succeeds and len(operations) == 2:
            return subprocess.CompletedProcess(words, 0, stdout='{"ready":true}', stderr="")
        return subprocess.CompletedProcess(words, 1, stdout="", stderr=conflict if failure == "persistent" else failure)

    monkeypatch.setattr(native.socket, "create_connection", connect)
    monkeypatch.setattr(native.subprocess, "Popen", Process)
    monkeypatch.setattr(native.subprocess, "run", run)
    monkeypatch.setattr(native.time, "sleep", sleeps.append)
    monkeypatch.setattr(native, "kube", lambda *a, **kw: {"metadata": {"labels": dict(native.LABELS)}})
    args = argparse.Namespace(cli_config_dir=str(config), output_dir=tmp_path, label="provider-conflict",
                              kubeconfig="private", cli="openshell")
    words = ["sandbox", "provider", "attach", "owned-sandbox", "owned-provider", "--wait", "-o", "json"]
    with native.native_session(args, {"runtime_management": {"client_secret": "synthetic"}}) as execute:
        if succeeds:
            assert execute(words, json_output=True) == {"ready": True}
        else:
            with pytest.raises(RuntimeError):
                execute(words, json_output=True)
    assert len(operations) == expected_attempts
    assert sleeps == [1, 2][:expected_attempts - 1]
    assert len(list(tmp_path.glob("*.command.json"))) == expected_attempts
    assert all(not p.active for p in processes)


def test_provider_conflict_classifier_excludes_tool_calls_and_extra_errors() -> None:
    """A retry hint cannot cause a business write or ambiguous response to repeat."""
    message = ("Error: Failed to attach provider: sandbox was modified by another operation. "
               "Please retry the command.")
    assert native.provider_attachment_conflict(["sandbox", "provider", "attach"], message)
    assert not native.provider_attachment_conflict(["sandbox", "exec"], message)
    assert not native.provider_attachment_conflict(["sandbox", "provider", "attach"], message + " saved")


def test_cleanup_rechecks_ownership_after_a_conditional_delete_conflict(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An ownership transfer must not be mistaken for harmless controller-status churn."""
    item = {'apiVersion': 'mcp.kuadrant.io/v1alpha1', 'kind': 'MCPServerRegistration',
            'metadata': {'name': 'fixture-step4-read-route', 'uid': 'exact', 'resourceVersion': '1',
                         'labels': dict(native.LABELS)}, 'spec': {'prefix': 'step4_read_'}}
    deletes = []

    def kube(args, *words, **kwargs):
        if words[0] == 'delete':
            deletes.append(words)
            raise RuntimeError('Conflict')
        result = deepcopy(item)
        if deletes:
            result['metadata'].update(resourceVersion='2', labels={'identity-demo-owner': 'someone-else'})
        return result

    monkeypatch.setattr(backend.shared, 'kube', kube)
    probe = backend.NativeBackend(argparse.Namespace(output_dir=tmp_path, label='owned-conflict'))
    probe.ledger = [item]
    with pytest.raises(ValueError, match='Owned discovery fixture'):
        probe.cleanup()
    assert len(deletes) == 1


@pytest.mark.parametrize('selection', ['temporary', 'persistent', 'missing-receipt', 'implicit-mode'])
def test_cli_selects_existing_gateway_mode_explicitly(tmp_path, monkeypatch, capsys, selection):
    """CLI keeps stable gateway mode explicit and rejects partial configuration before dispatch."""
    import sys
    receipt = tmp_path / 'gateway.private.json'
    receipt.write_text('{}')
    receipt.chmod(0o600)
    arguments = ['probe_native_exchange.py']
    for flag in ('kubeconfig', 'expected-server', 'credentials-file', 'cli', 'cli-config-dir', 'label', 'output-dir'):
        arguments += ['--' + flag, str(tmp_path) if flag == 'output-dir' else 'synthetic']
    if selection in ('persistent', 'missing-receipt'):
        arguments += ['--gateway-mode', 'persistent', '--driver-credentials-file', str(tmp_path/'driver.private.json')]
    if selection in ('persistent', 'implicit-mode'):
        arguments += ['--gateway-receipt', str(receipt)]
    monkeypatch.setattr(sys, 'argv', arguments)
    calls = []
    monkeypatch.setattr(native, 'driver_flow', lambda a: None)
    monkeypatch.setattr(native, 'run', lambda a: calls.append(a) or {'passed': True})
    with pytest.raises(SystemExit) as result:
        native.main()
    if selection in ('missing-receipt', 'implicit-mode'):
        assert result.value.code == 1 and not calls
        assert 'details_withheld' in capsys.readouterr().out
    else:
        assert result.value.code == 0 and len(calls) == 1
        assert calls[0].gateway_mode == selection
        assert calls[0].gateway_receipt == (str(receipt) if selection == 'persistent' else None)
