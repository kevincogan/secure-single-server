# SPDX-License-Identifier: Apache-2.0
"""Guarded tool tests; live gateway and backend proof remains a separate milestone."""

import asyncio
import json
import ssl
from types import SimpleNamespace

import pytest
from starlette.requests import Request

from identity_demo_jira_action_adapter import BODY_KEY, JiraTools, install_tools
from identity_demo_run_store import Denied


def context(
    tool: str = "createJiraIssue", project: str = "TEST", ticket: bool = True
) -> SimpleNamespace:
    """Supply a simulated actual SDK request without tokens or real backend access."""
    args = {"run_id": "a" * 32, "project": project}
    if tool == "createJiraIssue":
        args.update(
            action_id="b" * 32,
            summary="Synthetic",
            description="Synthetic finding",
            labels=["identity_demo_marker"],
            issue_type="Task",
        )
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool, "arguments": args},
        }
    ).encode()
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/mcp",
        "headers": [(b"x-demo-decision", b"opaque-reference-aaaaaaaaaaaaaaaaaaaaaa")]
        if ticket
        else [],
        BODY_KEY: body,
    }
    from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
    from mcp.server.auth.provider import AccessToken

    scope["user"] = AuthenticatedUser(
        AccessToken(
            token="synthetic",
            client_id="fixture-gateway-service",
            scopes=["mcp:read", "mcp:create"],
        )
    )
    return SimpleNamespace(request_context=SimpleNamespace(request=Request(scope)))


def instance(writes: bool = False) -> tuple[JiraTools, list, dict]:
    """Mock separately protected services; count every actual create dispatch."""
    tools = JiraTools.__new__(JiraTools)
    tools.writes = writes
    calls = []
    fields = {
        "project": {"key": "TEST"},
        "issuetype": {"name": "Task"},
        "summary": "Synthetic",
        "description": "Synthetic finding",
        "labels": ["identity_demo_marker"],
    }
    options = {"duplicate": False, "outage": False, "cross_project": False}

    async def driver(endpoint: str, value: dict) -> dict:
        calls.append((endpoint, value))
        if endpoint == "claim":
            return {
                "allowed": True,
                "dispatch": not options["duplicate"],
                "execution_id": "c" * 32,
                "issue_key": "TEST-123",
            }
        return {"allowed": True, "recorded": True}

    async def http(method: str, url: str, **kwargs: object) -> tuple:
        calls.append((method, url))
        if method == "POST":
            if options["outage"]:
                raise RuntimeError("dependency_unavailable")
            return 201, {"key": "TEST-123"}
        if "/project/" in url:
            return (404, {}) if options.get("missing_project") else (200, {"key": "OTHER" if options.get("project_metadata_mismatch") else "TEST"})
        if "/search" in url:
            return 200, {
                "total": 1,
                "issues": [
                    {
                        "key": "TEST-123",
                        "fields": {
                            **fields,
                            "project": {
                                "key": "OTHER" if options["cross_project"] else "TEST"
                            },
                        },
                    }
                ],
            }
        return 200, {"key": "TEST-123", "fields": fields}

    tools.driver, tools.http = driver, http
    return tools, calls, options


def test_disabled_create_only_previews_and_never_claims_or_dispatches() -> None:
    """The pre-write milestone must have no backend side effect."""
    tools, calls, _ = instance()
    result = asyncio.run(tools.create(context()))
    assert result["probe_passed"] and result["writes_enabled"] is False
    assert [c[0] for c in calls] == ["preview"]
    assert set(calls[0][1]) == {"decision_ticket", "actual_body"}


def test_create_claims_once_verifies_result_and_records_success() -> None:
    """A backend narrative is insufficient; verify persisted fields before success."""
    tools, calls, _ = instance(True)
    result = asyncio.run(tools.create(context()))
    assert result == {"key": "TEST-123", "duplicate": False}
    assert [c[0] for c in calls] == ["claim", "POST", "GET", "finish"]
    assert calls[-1][1]["state"] == "succeeded"


def test_successful_duplicate_never_reaches_jira() -> None:
    """The durable cached outcome must skip a second HTTP create."""
    tools, calls, options = instance(True)
    options["duplicate"] = True
    assert asyncio.run(tools.create(context()))["duplicate"]
    assert [c[0] for c in calls] == ["claim"]


def test_read_only_service_token_cannot_claim_a_real_create() -> None:
    """A read grant remains read-only even if a decision reference is present."""
    tools, calls, _ = instance(True)
    ctx = context()
    ctx.request_context.request.scope["user"].access_token.scopes = ["mcp:read"]
    with pytest.raises(Denied, match="adapter_scope"):
        asyncio.run(tools.create(ctx))
    assert calls == []


def test_dispatch_timeout_records_unknown_without_retry() -> None:
    """A lost create response cannot restore consent or trigger another POST."""
    tools, calls, options = instance(True)
    options["outage"] = True
    with pytest.raises(RuntimeError):
        asyncio.run(tools.create(context()))
    assert [c[0] for c in calls] == ["claim", "POST", "finish"]
    assert calls[-1][1]["state"] == "unknown" and calls[-1][1]["issue_key"] is None


def test_read_rechecks_current_project_and_rejects_backend_leakage() -> None:
    """No issue from another project can leave the adapter."""
    tools, calls, options = instance()
    result = asyncio.run(tools.read(context("readJiraProject")))
    assert result["total"] == 1 and [c[0] for c in calls] == ["read", "GET", "GET"]
    options["cross_project"] = True
    with pytest.raises(Denied, match="backend_project"):
        asyncio.run(tools.read(context("readJiraProject")))


def test_missing_decision_and_duplicate_headers_are_denied() -> None:
    """A valid adapter credential alone cannot execute a human-bound tool."""
    tools, calls, _ = instance(True)
    with pytest.raises(Denied, match="decision_required"):
        asyncio.run(tools.create(context(ticket=False)))
    ctx = context()
    ctx.request_context.request.scope["headers"].append(
        (b"x-demo-decision", b"another-decision")
    )
    with pytest.raises(Denied, match="decision_required"):
        asyncio.run(tools.create(ctx))
    assert calls == []


def test_sdk_schema_exposes_only_two_tools_and_hides_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Prove the installed SDK supports the actual Context injection contract."""
    from mcp.server.fastmcp import FastMCP

    monkeypatch.setattr(JiraTools, "__init__", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        "identity_demo_jira_action_adapter.Path.read_text", lambda _: "a" * 40
    )
    for key, value in {
        "DRIVER_ADAPTER_SECRET_FILE": "/private/key",
        "JIRA_USER": "synthetic",
        "JIRA_TOKEN": "synthetic",
        "DRIVER_CA_FILE": "/private/ca",
    }.items():
        monkeypatch.setenv(key, value)
    server = FastMCP("guarded-tools")
    install_tools(server)
    tools = asyncio.run(server.list_tools())
    assert {t.name for t in tools} == {"readJiraProject", "createJiraIssue"}
    assert all("ctx" not in t.inputSchema["properties"] for t in tools)


def test_fixed_tls_client_verifies_hostname_and_certificate(tmp_path) -> None:
    """The adapter cannot start with missing or invalid CA material."""
    ca = tmp_path / "ca.pem"
    ca.write_text("not a certificate")
    with pytest.raises(ssl.SSLError):
        JiraTools("a" * 40, "synthetic", "synthetic", str(ca))


def test_actual_sdk_http_request_preserves_body_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify the installed SDK passes the captured request to its tool Context."""
    import httpx
    from mcp.server.fastmcp import FastMCP
    from identity_demo_jira_action_adapter import ActualBody

    seen = []

    async def preview(self, ctx) -> dict:
        body, decision = JiraTools.context(ctx)
        seen.append(body)
        assert set(decision) == {"actual_body", "decision_ticket"}
        return {"writes_enabled": False, "probe_passed": True}

    monkeypatch.setattr(JiraTools, "__init__", lambda *args, **kwargs: None)
    monkeypatch.setattr(JiraTools, "create", preview)
    monkeypatch.setattr(
        "identity_demo_jira_action_adapter.Path.read_text", lambda _: "a" * 40
    )
    for key in (
        "DRIVER_ADAPTER_SECRET_FILE",
        "JIRA_USER",
        "JIRA_TOKEN",
        "DRIVER_CA_FILE",
    ):
        monkeypatch.setenv(key, "synthetic")
    server = FastMCP("context-proof", stateless_http=True, json_response=True)
    install_tools(server)
    app = server.streamable_http_app()
    payload = context().request_context.request.scope[BODY_KEY]

    async def run() -> None:
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=ActualBody(app)),
                base_url="http://127.0.0.1:8000",
            ) as client:
                response = await client.post(
                    "/mcp",
                    content=payload,
                    headers={
                        "Accept": "application/json, text/event-stream",
                        "Content-Type": "application/json",
                        "x-demo-decision": "opaque-reference-aaaaaaaaaaaaaaaaaaaaaa",
                    },
                )
                assert response.status_code == 200 and not response.json()[
                    "result"
                ].get("isError", False)

    asyncio.run(run())
    assert seen == [payload]


@pytest.mark.parametrize("matches", [0, 1, 2])
def test_reconciliation_requires_one_verified_original_issue_without_dispatch(
    matches: int,
) -> None:
    """A missing or ambiguous marker stays unknown; recovery never POSTs to Jira."""
    tools, calls, _ = instance()
    run, action = "a" * 32, "b" * 32
    args = {
        "project": "TEST",
        "issue_type": "Task",
        "summary": "Synthetic",
        "description": "Synthetic finding",
        "labels": ["demo-action-" + action],
    }

    async def driver(endpoint: str, value: dict) -> dict:
        calls.append((endpoint, value))
        if endpoint == "reconciliation":
            return {"allowed": True, "execution_id": "c" * 32, "arguments": args}
        assert endpoint == "reconcile"
        return {"recorded": True}

    async def http(method: str, url: str, **kwargs: object) -> tuple:
        assert method == "GET"
        calls.append((method, url))
        if "/search" in url:
            assert "demo-action-" + action in kwargs["params"]["jql"]
            return 200, {"total": matches, "issues": [{"key": "TEST-123"}] * matches}
        return 200, {
            "key": "TEST-123",
            "fields": {
                "project": {"key": "TEST"},
                "issuetype": {"name": "Task"},
                **{k: args[k] for k in ("summary", "description", "labels")},
            },
        }

    tools.driver, tools.http = driver, http
    result = asyncio.run(tools.reconcile(run, action))
    assert result["resolved"] is (matches == 1)
    assert [c[0] for c in calls] == (
        ["reconciliation", "GET", "GET", "reconcile"]
        if matches == 1
        else ["reconciliation", "GET"]
    )


@pytest.mark.parametrize("option", ["missing_project", "project_metadata_mismatch"])
def test_protected_read_rejects_absent_or_mismatched_project_before_search(option: str) -> None:
    """An empty search cannot disguise a missing project and lead to a create."""
    tools, calls, options = instance()
    options[option] = True
    with pytest.raises(Denied, match="backend_project"):
        asyncio.run(tools.read(context("readJiraProject")))
    assert [c[0] for c in calls] == ["read", "GET"]
    assert calls[-1][1].endswith("/rest/api/2/project/TEST")
    assert not any(c[0] in ("claim", "finish", "POST") for c in calls)
