# SPDX-License-Identifier: Apache-2.0
"""Two guarded pilot tools on the existing SDK adapter; no automatic Jira retries."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
import ssl
from typing import Any

import httpx
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from identity_demo_run_store import Denied, create_call, read_call
from deployment_profile import active_profile

BODY_KEY = "identity_demo_actual_body"
DRIVER = "https://" + active_profile().service_host("fixture-identity-driver") + ":8443"
JIRA = "https://" + active_profile().service_host("fixture-jira") + ":8080"


class ActualBody:
    """Bound and preserve the exact forwarded HTTP body for the trusted tool hook."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Capture once, then replay once to the SDK; never log headers or body."""
        if (
            scope["type"] != "http"
            or scope["path"] != "/mcp"
            or scope["method"] != "POST"
        ):
            await self.app(scope, receive, send)
            return
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] != "http.request":
                return
            body.extend(message.get("body", b""))
            if len(body) > 65_536:
                await JSONResponse({"error": "request_size"}, 413)(scope, receive, send)
                return
            if not message.get("more_body", False):
                break
        scope = dict(scope, **{BODY_KEY: bytes(body)})
        delivered = False

        async def replay() -> dict:
            """Preserve disconnect handling after the single validated body."""
            nonlocal delivered
            if delivered:
                return await receive()
            delivered = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, replay, send)


class JiraTools:
    """Use separately held driver/Jira credentials and fixed verified TLS endpoints."""

    def __init__(
        self, secret: str, user: str, password: str, ca: str, *, writes: bool = False
    ) -> None:
        if len(secret) < 32 or not user or not password:
            raise ValueError("Separately held scoped credentials required")
        self.secret, self.user, self.password, self.writes = (
            secret,
            user,
            password,
            writes,
        )
        self.tls = ssl.create_default_context(cafile=ca)

    async def driver(self, endpoint: str, value: dict) -> dict:
        """Call only the scoped driver's fixed internal adapter APIs."""
        if endpoint not in (
            "read",
            "preview",
            "claim",
            "finish",
            "reconciliation",
            "reconcile",
            "history",
            "observation",
        ):
            raise ValueError("Fixed adapter endpoint required")
        result = await self.http(
            "POST",
            DRIVER + "/internal/adapter/" + endpoint,
            headers={"Authorization": "Bearer " + self.secret},
            value=value,
        )
        if result[0] != 200 or (
            endpoint not in ("finish", "reconcile")
            and result[1].get("allowed") is not True
        ):
            reason = result[1].get("reason", "driver_denied")
            raise Denied(
                reason
                if isinstance(reason, str) and reason.replace("_", "").isalnum()
                else "driver_denied"
            )
        return result[1]

    async def http(
        self,
        method: str,
        url: str,
        *,
        headers: dict | None = None,
        value: dict | None = None,
        params: dict | None = None,
        backend: bool = False,
    ) -> tuple[int, dict]:
        """Bound every TLS response; prohibit redirects and credential fallbacks."""
        try:
            async with httpx.AsyncClient(
                verify=self.tls, timeout=8, follow_redirects=False, trust_env=False
            ) as client:
                auth = httpx.BasicAuth(self.user, self.password) if backend else None
                async with client.stream(
                    method, url, headers=headers, json=value, params=params, auth=auth
                ) as response:
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > 1_048_576:
                            raise RuntimeError("dependency_response_size")
                    result = json.loads(body) if body else {}
                    if not isinstance(result, dict):
                        raise RuntimeError("dependency_response")
                    return response.status_code, result
        except (httpx.HTTPError, ValueError) as error:
            raise RuntimeError("dependency_unavailable") from error

    @staticmethod
    def context(ctx: Any) -> tuple[bytes, dict]:
        """Require one decision reference plus the exact actual SDK HTTP request."""
        request = ctx.request_context.request
        if request is None or BODY_KEY not in request.scope:
            raise Denied("complete_body_required")
        references = request.headers.getlist("x-demo-decision")
        if len(references) != 1 or not 32 <= len(references[0]) <= 128:
            raise Denied("decision_required")
        body = request.scope[BODY_KEY]
        return body, {"decision_ticket": references[0], "actual_body": body.decode()}

    async def read(self, ctx: Any) -> dict:
        """Return only project-scoped issues after a live driver permission recheck."""
        body, decision = self.context(ctx)
        _, project, issue = read_call(body, tool_name="readJiraProject")
        await self.driver("read", decision)
        # Search can return an empty list for an absent fixture project. Verify
        # its exact identity before treating that as usable assessment input.
        status, metadata = await self.http(
            "GET", JIRA + "/rest/api/2/project/" + project, backend=True
        )
        if status != 200 or metadata.get("key") != project:
            raise Denied("backend_project")
        if issue:
            status, result = await self.http(
                "GET", JIRA + "/rest/api/2/issue/" + issue, backend=True
            )
            if (
                status != 200
                or result.get("key") != issue
                or result.get("fields", {}).get("project", {}).get("key") != project
            ):
                raise Denied("backend_project")
            return {**result, "project_scope": project}
        status, result = await self.http(
            "GET",
            JIRA + "/rest/api/2/search",
            params={"jql": "project = " + project, "maxResults": 20},
            backend=True,
        )
        if status != 200 or not isinstance(result.get("issues"), list):
            raise RuntimeError("backend_read")
        if any(
            not isinstance(v, dict)
            or v.get("fields", {}).get("project", {}).get("key") != project
            for v in result["issues"]
        ):
            raise Denied("backend_project")
        return {**result, "project_scope": project}

    async def reconcile(self, run: str, action: str) -> dict:
        """Operator-only recovery: verify one original marker, never retry a create.

        This is deliberately not an MCP tool. Invoke from trusted coordination
        inside the adapter with its existing credentials; no browser/agent keys.
        """
        if any(
            not isinstance(v, str) or not re.fullmatch(r"[a-f0-9]{32}", v)
            for v in (run, action)
        ):
            raise Denied("invalid_action_reference")
        record = await self.driver(
            "reconciliation", {"run_id": run, "action_id": action}
        )
        arguments = record["arguments"]
        marker = "demo-action-" + action
        if marker not in arguments["labels"]:
            raise Denied("reconciliation_binding")
        status, result = await self.http(
            "GET",
            JIRA + "/rest/api/2/search",
            params={
                "jql": "project = "
                + arguments["project"]
                + ' AND labels = "'
                + marker
                + '"',
                "maxResults": 2,
            },
            backend=True,
        )
        issues = result.get("issues")
        if (
            status != 200
            or result.get("total") != 1
            or not isinstance(issues, list)
            or len(issues) != 1
        ):
            return {"resolved": False, "reason": "operator_resolution_required"}
        key = issues[0].get("key")
        if not isinstance(key, str) or not re.fullmatch(
            re.escape(arguments["project"]) + r"-[1-9][0-9]*", key
        ):
            raise Denied("backend_project")
        status, issue = await self.http(
            "GET", JIRA + "/rest/api/2/issue/" + key, backend=True
        )
        fields = issue.get("fields", {})
        if (
            status != 200
            or issue.get("key") != key
            or (
                fields.get("project", {}).get("key") != arguments["project"]
                or fields.get("issuetype", {}).get("name") != arguments["issue_type"]
                or fields.get("summary") != arguments["summary"]
                or fields.get("description") != arguments["description"]
                or sorted(fields.get("labels", [])) != sorted(arguments["labels"])
            )
        ):
            raise Denied("reconciliation_binding")
        await self.driver(
            "reconcile",
            {
                "run_id": run,
                "action_id": action,
                "execution_id": record["execution_id"],
                "issue_key": key,
                "arguments": arguments,
            },
        )
        return {"resolved": True, "issue_key": key}

    async def create(self, ctx: Any) -> dict:
        """Preview when disabled; claim once, dispatch once and record a bounded outcome."""
        body, decision = self.context(ctx)
        run, action, arguments = create_call(body, tool_name="createJiraIssue")
        if not self.writes:
            await self.driver("preview", decision)
            return {
                "writes_enabled": False,
                "probe_passed": True,
                "run_id": run,
                "action_id": action,
            }
        from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser

        user = ctx.request_context.request.scope.get("user")
        if (
            not isinstance(user, AuthenticatedUser)
            or user.access_token.client_id != "fixture-gateway-service"
            or "mcp:create" not in user.access_token.scopes
        ):
            raise Denied("adapter_scope")
        claim = await self.driver("claim", decision)
        if not claim["dispatch"]:
            return {"key": claim["issue_key"], "duplicate": True}
        execution = claim["execution_id"]
        fields = {
            "project": {"key": arguments["project"]},
            "issuetype": {"name": arguments["issue_type"]},
            "summary": arguments["summary"],
            "description": arguments["description"],
            "labels": arguments["labels"],
        }
        outcome = {
            "run_id": run,
            "action_id": action,
            "execution_id": execution,
            "state": "unknown",
            "issue_key": None,
        }
        try:
            status, result = await self.http(
                "POST",
                JIRA + "/rest/api/2/issue",
                value={"fields": fields},
                backend=True,
            )
            if status != 201:
                # Even an error may follow a dispatch: no automatic redispatch.
                raise RuntimeError("backend_outcome_unknown")
            key = result.get("key")
            if (
                not isinstance(key, str)
                or not key.startswith(arguments["project"] + "-")
                or not key.split("-", 1)[1].isdigit()
            ):
                raise RuntimeError("backend_outcome_unknown")
            verified_status, issue = await self.http(
                "GET", JIRA + "/rest/api/2/issue/" + key, backend=True
            )
            actual = issue.get("fields", {})
            if (
                verified_status != 200
                or issue.get("key") != key
                or any(
                    actual.get(k) != v
                    for k, v in fields.items()
                    if k not in ("project", "issuetype")
                )
                or actual.get("project", {}).get("key") != arguments["project"]
                or actual.get("issuetype", {}).get("name") != arguments["issue_type"]
            ):
                raise RuntimeError("backend_outcome_unknown")
            outcome.update(state="succeeded", issue_key=key)
        finally:
            # If persistence is unavailable the durable claim stays non-dispatchable.
            await self.driver("finish", outcome)
        return {"key": outcome["issue_key"], "duplicate": False}


def install_tools(server: Any) -> None:
    """Register exactly one scoped read and one create; use the installed MCP SDK."""
    from mcp.server.fastmcp import Context

    tools = JiraTools(
        Path(os.environ["DRIVER_ADAPTER_SECRET_FILE"]).read_text().strip(),
        os.environ["JIRA_USER"],
        os.environ["JIRA_TOKEN"],
        os.environ["DRIVER_CA_FILE"],
        writes=os.environ.get("JIRA_WRITES_ENABLED") == "1",
    )

    async def readJiraProject(
        run_id: str, project: str, ctx: Context, issue_key: str | None = None, jql: str | None = None
    ) -> dict:
        """Read this run's project using the independently validated bounded JQL grammar."""
        return await tools.read(ctx)

    async def createJiraIssue(
        run_id: str,
        action_id: str,
        project: str,
        summary: str,
        description: str,
        ctx: Context,
        issue_type: str = "Task",
        labels: list[str] | None = None,
    ) -> dict:
        """Create one approved issue; changed parameters require new consent."""
        return await tools.create(ctx)

    # Resolve the local SDK Context before FastMCP inspects deferred annotations.
    readJiraProject.__annotations__["ctx"] = Context
    createJiraIssue.__annotations__["ctx"] = Context
    server.add_tool(readJiraProject)
    server.add_tool(createJiraIssue)
    if os.environ.get('JIRA_HISTORY_VIEW_ENABLED') == '1':
        @server.custom_route('/internal/observed-state', methods=['POST'])
        async def observed_state(request):
            """Read a fixed run project and durable issue; never accept query/key input."""
            try:
                from identity_demo_run_store import strict_json
                from urllib.parse import urlencode
                body = bytearray()
                async for part in request.stream():
                    body.extend(part)
                    if len(body) > 1024:
                        raise Denied('observation_size')
                data = strict_json(bytes(body))
                if set(data) != {'decision_ticket'} or not isinstance(data['decision_ticket'], str):
                    raise Denied('observation_ticket')
                allowed = await tools.driver('observation', data)
                project = allowed.get('project')
                if project not in ('TEST', 'OPS', 'SERVICE'):
                    raise Denied('observation_project')
                status, search = await tools.http('GET', JIRA+'/rest/api/2/search?'+urlencode({
                    'jql': 'project = '+project, 'maxResults': 1}), backend=True)
                if status != 200 or type(search.get('total')) is not int or search['total'] < 0:
                    raise Denied('observation_count')
                key, issue = allowed.get('issue_key'), None
                if key is not None:
                    if not isinstance(key, str) or not re.fullmatch(re.escape(project)+r'-[1-9][0-9]*', key):
                        raise Denied('observation_key')
                    status, issue = await tools.http('GET', JIRA+'/rest/api/2/issue/'+key, backend=True)
                    if status != 200 or issue.get('key') != key:
                        raise Denied('observation_issue')
                    issue = {'key': key, 'fields': {k: issue['fields'].get(k) for k in
                        ('summary', 'description', 'project', 'issuetype', 'labels')}}
                return JSONResponse({'total': search['total'], 'issue': issue}, headers={'Cache-Control': 'no-store'})
            except Exception:
                return JSONResponse({'reason': 'observation_unavailable'}, status_code=403,
                                    headers={'Cache-Control': 'no-store'})

        @server.custom_route('/internal/verified-issue', methods=['POST'])
        async def verified_issue(request):
            """Redeem an owner-authorized single read; backend credentials stay here."""
            try:
                from identity_demo_run_store import strict_json
                body = bytearray()
                async for part in request.stream():
                    body.extend(part)
                    if len(body) > 1024:
                        raise Denied('history_size')
                data = strict_json(bytes(body))
                if set(data) != {'decision_ticket'} or not isinstance(data['decision_ticket'], str):
                    raise Denied('history_ticket')
                allowed = await tools.driver('history', data)
                key = allowed.get('issue_key')
                if not isinstance(key, str) or not re.fullmatch(r'(?:TEST|OPS|SERVICE)-[1-9][0-9]*', key):
                    raise Denied('history_key')
                status, issue = await tools.http('GET', JIRA + '/rest/api/2/issue/' + key, backend=True)
                if status != 200 or issue.get('key') != key or not isinstance(issue.get('fields'), dict):
                    raise Denied('history_backend')
                result = {'key': key, 'fields': {name: issue['fields'].get(name, '')
                          for name in ('summary', 'description')}}
                return JSONResponse(result, headers={'Cache-Control': 'no-store'})
            except Exception:
                return JSONResponse({'reason': 'verified_issue_unavailable'}, status_code=403,
                                    headers={'Cache-Control': 'no-store'})
