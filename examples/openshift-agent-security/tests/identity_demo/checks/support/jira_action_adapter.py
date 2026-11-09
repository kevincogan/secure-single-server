# SPDX-License-Identifier: Apache-2.0
"""Shared jira action adapter test setup; contains no collected tests."""
import json
from types import SimpleNamespace
from starlette.requests import Request
from identity_demo_jira_action_adapter import BODY_KEY, JiraTools

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
