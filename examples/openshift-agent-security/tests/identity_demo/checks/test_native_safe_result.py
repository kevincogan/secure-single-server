# SPDX-License-Identifier: Apache-2.0
"""Check bounded result reporting without claiming native cluster execution."""

from __future__ import annotations

from contextlib import redirect_stdout
import argparse
import io
import json
import subprocess
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from probe_native_exchange import read_program, run as native_run
from permission_flow import PermissionFlow


@pytest.mark.parametrize("duplicate", [False, True])
def test_create_result_reports_only_validated_outcome_fields(duplicate: bool) -> None:
    """Keep duplicate evidence while excluding response secrets and arbitrary data."""
    content = {
        "key": "TEST-1",
        "duplicate": duplicate,
        "access_token": "must-not-escape",
        "description": "private-content",
        "run_id": "a" * 32,
        "project_scope": "TEST",
    }

    class Response:
        """Provide only the HTTP response interface used by the generated probe."""

        status = 200
        headers: dict[str, str] = {}

        def __init__(self, body: dict) -> None:
            self.body = body

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self, limit: int) -> bytes:
            return json.dumps(self.body).encode()

    class Client:
        """Return deterministic MCP responses without opening a network socket."""

        def open(self, request: object, timeout: int) -> Response:
            body = json.loads(request.data)
            if body["method"] == "initialize":
                return Response({"result": {"protocolVersion": "2025-11-25"}})
            if body["method"] == "tools/call":
                return Response(
                    {"result": {"content": [{"type": "text", "text": json.dumps(content)}]}}
                )
            return Response({})

    output = io.StringIO()
    with patch("urllib.request.build_opener", return_value=Client()):
        with redirect_stdout(output):
            exec(read_program("https://mcp.example/mcp", "createJiraIssue", {}, "key"), {})
    result = json.loads(output.getvalue())
    assert result["read_passed"]
    assert result["verified_tool_result"] == {
        "key": "TEST-1",
        "duplicate": duplicate,
        "run_id": "a" * 32,
        "project_scope": "TEST",
    }
    assert "must-not-escape" not in output.getvalue()
    assert "private-content" not in output.getvalue()


def test_outcome_verifier_checks_backend_and_read_only_durable_state(monkeypatch) -> None:
    """Both independent checks must execute; raw backend data is never returned."""
    flow = PermissionFlow.__new__(PermissionFlow)
    flow.args = SimpleNamespace(kubeconfig="private-test-config")
    flow.run_id, flow.user = "a" * 32, "verified-user"
    flow.proposal = {
        "action_id": "b" * 32,
        "digest": "c" * 64,
        "arguments": {
            "project": "TEST", "issue_type": "Task", "summary": "synthetic",
            "description": "synthetic", "labels": ["synthetic"],
        },
    }
    programs = []

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        program = command[-1]
        compile(program, "outcome-check", "exec")
        programs.append(program)
        if len(programs) == 1:
            assert "fields[name]==approved[name]" in program
            output = {"backend_fields_match_approval": True}
        else:
            assert "?mode=ro" in program
            assert "e['event']=='claimed'" in program
            assert "e['event']=='succeeded'" in program
            output = {"one_dispatch_claim": True}
        return subprocess.CompletedProcess(command, 0, json.dumps(output), "")

    monkeypatch.setattr(subprocess, "run", run)
    assert flow.verify_created_outcome("TEST-1", "verified-workload") == {
        "backend_fields_match_approval": True, "one_dispatch_claim": True,
    }
    assert len(programs) == 2


def test_real_create_requires_authenticated_permission_flow() -> None:
    """Reject a write-mode probe before it can contact any live resource."""
    with pytest.raises(ValueError, match="authenticated permission flow"):
        native_run(argparse.Namespace(enable_create=True))


def test_rpc_failure_reports_code_without_private_error_text() -> None:
    """Successful HTTP transport is insufficient when MCP returns a protocol error."""
    class Response:
        """Return a synthetic bounded MCP response."""
        status = 200
        headers = {}
        def __init__(self, body: dict) -> None:
            self.body = body
        def __enter__(self) -> Response:
            return self
        def __exit__(self, *args: object) -> None:
            return None
        def read(self, limit: int) -> bytes:
            """Encode only synthetic test content."""
            return json.dumps(self.body).encode()
    class Client:
        """Exercise protocol failure without opening network connections."""
        def open(self, request: object, timeout: int) -> Response:
            """Return protocol-specific test responses."""
            method = json.loads(request.data)["method"]
            if method == "initialize":
                return Response({"result": {"protocolVersion": "2025-11-25"}})
            if method == "tools/list":
                return Response({"result": {"tools": []}})
            if method == "tools/call":
                return Response({"error": {"code": -32602, "message": "private-content"}})
            return Response({})
    output = io.StringIO()
    with patch("urllib.request.build_opener", return_value=Client()), redirect_stdout(output):
        exec(read_program("https://mcp.example/mcp", "createJiraIssue", {}, "key"), {})
    result = json.loads(output.getvalue())
    assert result["read_passed"] is False
    assert result["mcp_failure_category"] == "rpc_error"
    assert result["mcp_error_code"] == -32602
    assert result["requested_tool_advertised"] is False
    assert "private-content" not in output.getvalue()


@pytest.mark.parametrize("error,expected", [
    ("Error calling tool: action_executing; private-content", "action_executing"),
    ("Unexpected private-content", None),
])
def test_mcp_error_exposes_only_recognized_concurrency_denial(error: str, expected: str | None) -> None:
    """A non-JSON SDK error must remain failure without leaking its raw text."""
    class Response:
        """Supply the native probe's bounded HTTP interface."""
        status = 200
        headers = {}

        def __init__(self, body: dict) -> None:
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, limit):
            return json.dumps(self.body).encode()

    class Client:
        """Simulate a deliberately rejected MCP call, never a network success."""
        def open(self, request, timeout):
            method = json.loads(request.data)["method"]
            return Response({"result": {"protocolVersion": "2025-11-25"}} if method == "initialize"
                else {"result": {"isError": True, "content": [{"type": "text", "text": error}]}}
                if method == "tools/call" else {})

    output = io.StringIO()
    with patch("urllib.request.build_opener", return_value=Client()), redirect_stdout(output):
        exec(read_program("https://mcp.example/mcp", "createJiraIssue", {}, "key"), {})
    result = json.loads(output.getvalue())
    assert result["read_passed"] is False and result["mcp_error_reason"] == expected
    assert "private-content" not in output.getvalue()


@pytest.mark.parametrize("flag", [
    "check_sender_rejection", "check_renewal", "check_key_rollover",
    "check_backend_rotation", "retain_run_retirement",
])
def test_driver_flow_never_silently_skips_requested_step4_checks(flag: str) -> None:
    """A green driver probe cannot imply an ignored renewal/rotation check ran."""
    with pytest.raises(ValueError, match="silently skipped"):
        native_run(argparse.Namespace(permission_flow=object(), **{flag: True}))


def test_rpc_timings_measure_methods_without_exposing_requests_or_credentials() -> None:
    """Use deterministic monotonic intervals around the real generated RPC client."""
    class Reply:
        status = 200
        headers: dict[str, str] = {}
        def __init__(self, body: dict) -> None:
            self.body = body
        def __enter__(self) -> Reply:
            return self
        def __exit__(self, *args: object) -> None:
            return None
        def read(self, limit: int) -> bytes:
            return json.dumps(self.body).encode()
    class Client:
        def open(self, request: object, timeout: int) -> Reply:
            method = json.loads(request.data)['method']
            if method == 'initialize':
                return Reply({'result': {'protocolVersion': '2025-11-25'}})
            if method == 'tools/call':
                return Reply({'result': {'content': [{'type': 'text', 'text': '{"total":0,"issues":[]}'}]}})
            return Reply({})
    output = io.StringIO()
    with patch('urllib.request.build_opener', return_value=Client()), patch(
        'time.monotonic', side_effect=[0, .1, 1, 1.2, 2, 2.3, 3, 3.4]
    ), redirect_stdout(output):
        exec(read_program('https://mcp.example/mcp'), {})
    value = json.loads(output.getvalue())
    assert value['read_passed']
    assert [e['elapsed_seconds'] for e in value['events']] == [.1, .2, .3, .4]
    assert [e['method'] for e in value['events']] == ['initialize', 'notifications/initialized', 'tools/list', 'tools/call']
    assert all(set(e) == {'method', 'http_status', 'elapsed_seconds'} for e in value['events'])
