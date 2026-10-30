# SPDX-License-Identifier: Apache-2.0
"""Offline integration boundaries; these mocks are not live gateway acceptance."""

import asyncio
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import json
from types import SimpleNamespace
import urllib.request

import pytest

import agent_runtime
import probe_native_exchange as native
from provider_contract import MODEL
from identity_demo_run_store import Denied, read_call
from identity_demo_jira_action_adapter import BODY_KEY
from checks.test_jira_action_adapter import context, instance


def rpc(arguments: dict) -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "step56_jira_readJiraProject",
                "arguments": {"run_id": "a" * 32, "project": "SERVICE", **arguments},
            },
        }
    ).encode()


@pytest.mark.parametrize(
    "query,issue",
    [
        ("project = SERVICE", None),
        ('project = "SERVICE"', None),
        ("project = SERVICE AND key = SERVICE-12", "SERVICE-12"),
    ],
)
def test_trusted_read_parser_accepts_only_the_selected_project(
    query: str, issue: str | None
) -> None:
    assert read_call(rpc({"jql": query})) == ("a" * 32, "SERVICE", issue)


@pytest.mark.parametrize(
    "query",
    [
        "project = TEST",
        "project = SERVICE OR project = TEST",
        "project = SERVICE AND key = TEST-1",
        "project = SERVICE; reset",
        "project = SERVICE AND labels in (secret)",
    ],
)
def test_gateway_side_parser_independently_denies_unsafe_model_queries(
    query: str,
) -> None:
    with pytest.raises(Denied):
        read_call(rpc({"jql": query}))


def test_adapter_denies_a_foreign_query_before_backend_or_credential_release() -> None:
    tools, calls, _ = instance()
    ctx = context("readJiraProject")
    value = json.loads(ctx.request_context.request.scope[BODY_KEY])
    value["params"]["arguments"]["jql"] = "project = OTHER"
    ctx.request_context.request.scope[BODY_KEY] = json.dumps(value).encode()
    with pytest.raises(Denied, match="project_permission"):
        asyncio.run(tools.read(ctx))
    assert calls == []


def observation(project: str = "SERVICE") -> dict:
    return {
        "project": project,
        "total": 1,
        "issues": [
            {
                "key": project + "-1",
                "summary": "Existing workspace request",
                "description": "Untrusted synthetic context",
                "status": "Open",
            }
        ],
        "truncated": False,
        "untrusted_external_data": True,
    }


def test_runner_uses_sandbox_model_turns_and_native_governed_reads(tmp_path) -> None:
    commands, events, programs = [], [], []
    turns = iter(
        [
            {"kind": "read", "id": "read_1", "jql": "project = SERVICE"},
            {
                "kind": "draft",
                "summary": "Workspace task",
                "description": "Related to SERVICE-1.",
            },
        ]
    )

    def execute(words: list, **kwargs: object) -> dict:
        commands.append(words)
        assert (
            words[:2] == ["sandbox", "exec"]
            and words[words.index("--name") + 1] == "owned-sandbox"
        )
        assert "--credential" not in words and kwargs == {"json_output": True}
        import base64
        argv = words[words.index("--") + 1:]
        program = argv[2] if len(argv) == 3 else base64.b64decode("".join(argv[3:])).decode()
        programs.append(program)
        if "from inference import request_messages" in program:
            import ast
            # The provider request must match the parser's single-action contract.
            body_line = next(line.strip() for line in program.splitlines() if line.strip().startswith("body="))
            body = ast.literal_eval(body_line.removeprefix("body="))
            assert "CVE-2099-0001" in body["messages"][0]["content"]
            assert "Rollback and triggers" in body["messages"][0]["content"]
            assert "not a verified fix" in body["messages"][0]["content"]
            assert body["tool_choice"].get("disable_parallel_tool_use") is True
            assert body["tool_choice"]["type"] == ("tool" if len(commands) == 1 else "any")
            return {
                "action": next(turns),
                "inference": {
                    "model": MODEL,
                    "http_status": 200,
                    "tls_verified": True,
                    "follow_redirects": False,
                    "credential_in_agent": False,
                },
            }
        assert (
            "step56_jira_readJiraProject" in program
            and "project = SERVICE" in program
        )
        return {
            "read_passed": True,
            "events": [{"http_status": 200}],
            "verified_tool_result": {"jira_read": observation()},
        }

    flow = SimpleNamespace(
        project="SERVICE",
        submission={"request": "SERVICE-0001"},
        run_id="a" * 32,
        args=SimpleNamespace(output_dir=tmp_path, label="synthetic"),
        progress=lambda n, e: events.append((n, e)),
    )
    result = agent_runtime.report(
        flow,
        execute,
        "https://fixture-mcp-bound.example.svc.cluster.local/mcp",
        SimpleNamespace(sandbox_name="owned-sandbox"),
    )
    assert len(commands) == 3 and "SERVICE-1" in programs[-1]
    assert (
        result["agent"]["reads"] == 1
        and result["proposed_create"]["project"] == "SERVICE"
    )
    assert result["agent"]["writes_available"] is False and "approved" not in result
    assert result["inference"]["credential_in_agent"] is False
    read_event = next(e for n, e in events if n == "agent_read_complete")
    assert read_event["jira_issues"] == [
        {"key": "SERVICE-1", "summary": "Existing workspace request", "status": "Open"}
    ]
    assert "description" not in json.dumps(read_event)
    assert read_event["agent_read_count"] == 1  # Visible before a later draft succeeds.


def test_actual_generated_read_client_projects_only_bounded_issue_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("subject_token", raising=False)
    calls = []
    issue = {
        "key": "SERVICE-1",
        "fields": {
            "project": {"key": "SERVICE"},
            "summary": "Existing",
            "description": "Untrusted context",
            "status": {"name": "Open"},
            "reporter": {"emailAddress": "private@example.test"},
            "secret": "never-publish",
        },
    }

    class Reply:
        status = 200
        headers = {}

        def __init__(self, value: object) -> None:
            self.value = value

        def __enter__(self) -> object:
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def read(self, limit: int) -> bytes:
            return json.dumps(self.value).encode() if self.value is not None else b""

    class Client:
        def open(self, request: object, timeout: float) -> Reply:
            assert timeout == 15
            assert request.get_header("Authorization") is None
            body = json.loads(request.data)
            method = body["method"]
            calls.append(method)
            if method == "initialize":
                return Reply({"result": {"protocolVersion": "2025-11-25"}})
            if method == "notifications/initialized":
                return Reply(None)
            if method == "tools/list":
                return Reply(
                    {"result": {"tools": [{"name": "step56_jira_readJiraProject"}]}}
                )
            assert (
                method == "tools/call"
                and body["params"]["arguments"]["jql"] == "project = SERVICE"
            )
            value = {"project_scope": "SERVICE", "total": 1, "issues": [issue]}
            return Reply(
                {"result": {"content": [{"type": "text", "text": json.dumps(value)}]}}
            )

    monkeypatch.setattr(urllib.request, "build_opener", lambda *args: Client())
    program = native.read_program(
        "https://controlled.example/mcp",
        "step56_jira_readJiraProject",
        {"run_id": "a" * 32, "project": "SERVICE", "jql": "project = SERVICE"},
        "project_scope",
        include_issues=True,
        request_timeout=15,
    )
    output = StringIO()
    with redirect_stdout(output):
        exec(compile(program, "<generated-native-read>", "exec"), {})
    value = json.loads(output.getvalue())
    assert (
        value["read_passed"] is True
        and value["verified_tool_result"]["jira_read"]["issues"][0]["key"]
        == "SERVICE-1"
    )
    assert calls == [
        "initialize",
        "notifications/initialized",
        "tools/list",
        "tools/call",
    ]
    assert (
        "emailAddress" not in output.getvalue()
        and "never-publish" not in output.getvalue()
    )


def test_large_read_context_crosses_native_exec_without_an_oversized_argument() -> None:
    """Exercise actual Python decoding with quotes/unicode resembling untrusted issue text."""
    import subprocess
    import sys

    sample = "Synthetic issue data, quotes ' \", newline\nUnicode ✓ " * 1500
    program = (
        "import json\nvalue="
        + repr(sample)
        + '\nprint(json.dumps({"length":len(value),"tail":value[-20:]}))'
    )
    arguments = agent_runtime.program_arguments(program)
    assert (
        len(arguments) > 3
        and max(len(argument.encode()) for argument in arguments) <= 32768
    )
    completed = subprocess.run(
        [sys.executable, *arguments[1:]],
        capture_output=True,
        text=True,
        check=True,
        timeout=5,
    )
    assert json.loads(completed.stdout) == {"length": len(sample), "tail": sample[-20:]}
    with pytest.raises(agent_runtime.AgentRuntimeFailure, match="agent_context_limit"):
        agent_runtime.program_arguments("x" * 131073)


@pytest.mark.parametrize(
    "project,workflow,request_id",
    [
        ("SERVICE", "service-request", "SERVICE-0001"),
        ("OPS", "incident-triage", "OPS-0001"),
    ],
)
@pytest.mark.parametrize("reject_query", [False, True])
def test_agent_progress_contract_reaches_the_real_console_store(
    tmp_path, project: str, workflow: str, request_id: str, reject_query: bool
) -> None:
    """Run both adapters against actual persisted evidence validation, without live inference claims."""
    import base64
    from dataclasses import replace
    from types import MethodType
    from uuid import uuid4
    from checks.test_console import configured, operator
    from identity_demo_console_worker import AttachedFlow

    driver, client, context = configured(tmp_path)
    driver.config = replace(
        driver.config, contexts=({**context, "workflow": workflow, "project": project},)
    )
    worker = uuid4().hex
    driver.console.heartbeat(worker)
    response = client.post(
        "/submit",
        headers={"Origin": driver.config.origin},
        data={"csrf": "csrf-fixture", "role": "triage", "request": request_id},
        follow_redirects=False,
    )
    assert response.status_code == 303
    job = client.post(
        "/internal/operator/console/next",
        headers=operator(driver),
        json={"worker": worker},
    ).json()["job"]
    turns = iter(
        [
            {"kind": "read", "id": "r1", "jql": "project = " + project},
            *([{"kind": "read", "id": "invalid", "jql": "project = " + project + " AND key = " + project + "-0001"}] if reject_query else []),
            {
                "kind": "draft",
                "summary": "Synthetic investigation",
                "description": "Related to " + project + "-1.",
            },
        ]
    )
    programs = []

    def execute(words: list, **kwargs: object) -> dict:
        argv = words[words.index("--") + 1 :]
        program = (
            argv[2] if len(argv) == 3 else base64.b64decode("".join(argv[3:])).decode()
        )
        programs.append(program)
        if "from inference import request_messages" in program:
            return {
                "action": next(turns),
                "inference": {
                    "model": MODEL,
                    "http_status": 200,
                    "tls_verified": True,
                    "follow_redirects": False,
                    "credential_in_agent": False,
                },
            }
        if project == "OPS" and len(programs) == 2:
            assert "TEST" in program and "step56_jira_readJiraProject" in program
            return {
                "read_passed": False,
                "events": [
                    {
                        "method": "tools/call",
                        "http_status": 403,
                        "denial_reason": "project_permission",
                    }
                ],
            }
        return {
            "read_passed": True,
            "verified_tool_result": {"jira_read": observation(project)},
        }

    class LocalControl:
        preview = None

        def update(self, run: str, stage: str, evidence: dict) -> None:
            driver.console.update(run, worker, stage, evidence)

    flow = SimpleNamespace(
        project=project,
        workflow=workflow,
        submission={"request": request_id},
        run_id=job["run_id"],
        control=LocalControl(),
        args=SimpleNamespace(output_dir=tmp_path, label="offline-integration"),
    )
    if project == "OPS":
        flow.agent_scope_probe = "TEST"
    flow.progress = MethodType(AttachedFlow.progress, flow)
    result = agent_runtime.report(
        flow,
        execute,
        "https://fixture-bound.example.svc/mcp",
        SimpleNamespace(sandbox_name="owned-sandbox", workload=context["workload"]),
    )
    state = driver.console.describe(job["run_id"])
    assert result["agent"]["turns"] == (3 if reject_query else 2) and result["agent"]["reads"] == 1
    query_events = [json.loads(event["detail"]) for event in driver.store.describe(job["run_id"], job["user"])["audit"]
                    if event["event"] == "console_agent_query_rejected"]
    assert len(query_events) == int(reject_query)
    if reject_query:
        assert query_events[0]["agent_error_category"] == "invalid_jql"
        assert query_events[0]["agent_turn"] == 2 and "agent_query" not in query_events[0]
    assert (
        state["stage"] == "agent_draft_ready"
        and state["evidence"]["agent_read_count"] == 1
    )
    assert (
        state["evidence"]["model_inference"] is True
        and state["evidence"]["jira_project"] == project
    )
    assert driver.store.describe(job["run_id"], job["user"])["actions"] == []
    if project == "OPS":
        assert state["evidence"]["scope_probe_denied"] is True
        assert (
            "scope_check" in programs[-1]
            and "certificate_bound_gateway" in programs[-1]
        )


@pytest.mark.parametrize("category,expected", [
    ("incomplete_output", "incomplete_output"),
    ("model_output_limit", "model_output_limit"),
    ("draft_schema", "draft_schema"),
    ("private upstream text must never be shown", "model_output_invalid"),
])
def test_model_failure_keeps_only_fixed_parser_categories(tmp_path: Path, category: str, expected: str) -> None:
    """Preserve useful bounded diagnostics without forwarding arbitrary upstream strings."""
    flow = SimpleNamespace(project="SERVICE", args=SimpleNamespace(output_dir=tmp_path, label="parser-failure"),
                           progress=lambda *args: None)
    def execute(*args: object, **kwargs: object) -> dict:
        return {"agent_failed": True, "error_category": category}
    with pytest.raises(agent_runtime.AgentRuntimeFailure, match="^" + expected + "$"):
        agent_runtime.report(flow, execute, "https://bound.example.test/mcp", SimpleNamespace(sandbox_name="owned"))
