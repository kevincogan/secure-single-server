# SPDX-License-Identifier: Apache-2.0
"""Compare read-only native and deterministic clients without exposing payloads."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, build_opener

PROTOCOLS = {"2025-03-26", "2025-06-18", "2025-11-25"}
METHODS = {"initialize", "notifications/initialized", "tools/list", "tools/call"}
TOOL = "jira_searchJiraIssuesUsingJql"
ARGUMENTS = {"jql": "project = TEST", "maxResults": 1}


def error_shape(texts: list[str]) -> dict:
    """Expose only fixed vocabulary, JSON structure and bounded error codes."""
    value = " ".join(v[:4096] for v in texts[:4]).lower()
    words = set(re.findall(r"[a-z]+", value))
    vocabulary = {"error", "invalid", "unsupported", "found", "backend", "host",
        "route", "routing", "method", "client", "protocol", "version", "mcp",
        "argument", "parameter", "session", "token", "key", "deadline", "connection",
        "missing", "authorization", "credential", "not", "enabled", "disabled",
        "metadata", "tool", "server", "json", "parse", "syntax", "unknown", "empty",
        "scope", "request", "response", "permission", "denied", "initialized",
        "initialize", "dns", "jql", "unexpected", "headers", "header", "body",
        "content", "expired", "audience", "issuer", "timeout", "schema", "validation",
        "required", "null", "name", "type", "duplicate", "value", "id", "jira",
        "maxresults", "search", "eof", "result", "call", "blocked", "block", "policy",
        "execution", "failed", "failure", "rate", "limit", "limited", "quota", "exceeded",
        "throttle", "limiting", "cancelled", "canceled"}
    shapes = []
    for text in texts[:4]:
        try:
            obj = json.loads(text[:4096])
        except ValueError:
            shapes.append({"json": False, "text_length": len(text)})
            continue
        known = {"error", "message", "detail", "status", "code", "issues", "total", "data"}
        shape: dict = {"json": True, "object": isinstance(obj, dict)}
        if isinstance(obj, dict):
            shape["known_keys"] = sorted(set(obj) & known)
            code = obj.get("code")
            if isinstance(code, int) and (100 <= code <= 599 or -32768 <= code <= -32000):
                shape["reported_code"] = code
        shapes.append(shape)
    return {"text_items": len(texts), "fixed_vocabulary_present": sorted(words & vocabulary),
            "content_shapes": shapes}


async def native(credentials: dict, username: str, private_context: dict | None = None) -> dict:
    """Observe supported client calls without changing headers, bodies or policy."""
    import httpx
    from mcp import ClientSession
    from checks.test_gateway_oauth import _native_login_workflow
    import identity_demo_fixture_http as components

    events: list[dict] = []
    reads: list[dict] = []
    state: dict = {}
    diagnostics: dict = {}
    target = urlparse(credentials["gateway_url"])
    original_init = httpx.AsyncClient.__init__
    original_initialize = ClientSession.initialize
    original_call = ClientSession.call_tool
    original_verify = components.verify

    async def observe(response: httpx.Response) -> None:
        """Record only the owned MCP boundary and never record credential values."""
        req = response.request
        if req.url.host != target.hostname or req.url.path != "/mcp":
            return
        data: Any = {}
        if req.method == "POST":
            raw = await req.aread()
            if len(raw) > 2_000_000:
                raise RuntimeError("Diagnostic request size exceeded")
            try:
                data = json.loads(raw)
            except ValueError:
                data = {}
        method = data.get("method") if isinstance(data, dict) else None
        if not isinstance(method, str) or method not in METHODS:
            method = "other"
        if method == "initialize" and response.status_code == 200:
            state["session"] = response.headers.get("Mcp-Session-Id")
        protocol = req.headers.get("MCP-Protocol-Version")
        media = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        item = {"http_method": req.method, "rpc_method": method,
            "status": response.status_code,
            "media": media if media in {"application/json", "text/event-stream"} else "other",
            "protocol": protocol if protocol in PROTOCOLS else "other" if protocol else None,
            "authorization_present": bool(req.headers.get("Authorization")),
            "session_present": bool(req.headers.get("Mcp-Session-Id")),
            "session_matches_issued": bool(state.get("session"))
                and req.headers.get("Mcp-Session-Id") == state["session"]}
        if method == "tools/call":
            params = data.get("params", {})
            item.update(tool_matches=isinstance(params, dict) and params.get("name") == TOOL,
                arguments_match=isinstance(params, dict) and params.get("arguments") == ARGUMENTS,
                params_meta_present=isinstance(params, dict) and "_meta" in params,
                extra_params_count=len(set(params) - {"name", "arguments", "_meta"}) if isinstance(params, dict) else None,
                verified_token_matches=bool(state.get("verified_token"))
                    and req.headers.get("Authorization") == "Bearer " + state["verified_token"],
                verified_token_unexpired_at_response=state.get("claims", {}).get("exp", 0) > time.time(),
                verified_user_matches=state.get("claims", {}).get("preferred_username") == username)
        if len(events) < 40:
            events.append(item)

    def client_init(self: Any, *args: Any, **kwargs: Any) -> None:
        """Append a response observer to existing hooks without replacing them."""
        hooks = {k: list(v) for k, v in (kwargs.get("event_hooks") or {}).items()}
        hooks.setdefault("response", []).append(observe)
        kwargs["event_hooks"] = hooks
        original_init(self, *args, **kwargs)

    async def initialize(self: Any, *args: Any, **kwargs: Any) -> Any:
        """Record only the server's negotiated protocol version."""
        result = await original_initialize(self, *args, **kwargs)
        state["negotiated_protocol"] = result.protocolVersion if result.protocolVersion in PROTOCOLS else "other"
        return result

    async def call(self: Any, *args: Any, **kwargs: Any) -> Any:
        """Record error shape only; return the original result without alteration."""
        result = await original_call(self, *args, **kwargs)
        item: dict = {"is_error": result.isError}
        if result.isError:
            item["error_shape"] = error_shape([v.text for v in result.content if getattr(v, "type", "") == "text"])
        reads.append(item)
        return result

    def verify(token: str, audience: str, issuer: str = components.ISSUER) -> dict:
        """Retain verified context in memory solely for equality/expiry checks."""
        claims = original_verify(token, audience, issuer)
        if audience == credentials["gateway_url"]:
            state["verified_token"] = token
            state["claims"] = claims
        return claims

    with patch.object(httpx.AsyncClient, "__init__", client_init), \
            patch.object(ClientSession, "initialize", initialize), \
            patch.object(ClientSession, "call_tool", call), \
            patch.object(components, "verify", verify):
        try:
            await asyncio.wait_for(_native_login_workflow(credentials, username, refresh=False,
                diagnostics=diagnostics), timeout=120)
            passed = True
            failure = None
        except Exception as error:
            passed = False
            failure = type(error).__name__
    if private_context is not None and state.get("verified_token"):
        private_context.update(token=state["verified_token"], protocol=state.get("negotiated_protocol"))
    return {"client": "native-sdk", "user": username, "read_passed": passed,
        "failure_kind": failure, "negotiated_protocol": state.get("negotiated_protocol"),
        "events": events, "reads": reads}


def deterministic(credentials: dict, username: str, *, token: str | None = None,
                  protocol: str = "2025-03-26") -> dict:
    """Use the same HTTPS resource and fixture arguments with the simple client."""
    import identity_demo_fixture_http as components
    if protocol not in PROTOCOLS:
        raise ValueError("Supported diagnostic protocol required")
    supplied = token is not None
    if token is None:
        token = components.login(username, credentials[username])["access_token"]
    elif not token:
        raise ValueError("Explicitly empty token rejected; no credential fallback")
    components.verify(token, credentials["gateway_url"])
    identifier: str | None = None
    events: list[dict] = []
    client = build_opener(components.NoRedirect())

    def rpc(method: str, params: dict | None = None) -> dict:
        """Keep all tokens/session identifiers and response contents in memory."""
        nonlocal identifier
        payload: dict = {"jsonrpc": "2.0", "method": method}
        if method != "notifications/initialized":
            payload["id"] = 1
        if params is not None:
            payload["params"] = params
        headers = {"Authorization": "Bearer " + token, "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json", "MCP-Protocol-Version": protocol}
        if identifier:
            headers["Mcp-Session-Id"] = identifier
        try:
            response = client.open(Request(credentials["gateway_url"], data=json.dumps(payload).encode(),
                headers=headers), timeout=20)
        except HTTPError as error:
            response = error
        with response:
            body = response.read(2_000_001)
            if len(body) > 2_000_000:
                raise RuntimeError("Diagnostic response size exceeded")
            if method == "initialize" and response.status == 200:
                identifier = response.headers.get("Mcp-Session-Id")
            events.append({"rpc_method": method, "status": response.status,
                "session_present": bool(identifier), "protocol": protocol})
            if response.status not in (200, 202, 204):
                raise RuntimeError("Deterministic request failed")
            if not body:
                return {}
            values = [json.loads(line[5:].strip()) for line in body.decode().splitlines() if line.startswith("data:")]
            return values[-1] if values else json.loads(body)

    first = rpc("initialize", {"protocolVersion": protocol, "capabilities": {},
        "clientInfo": {"name": "identity-demo-interop", "version": "0.1"}})
    protocol = first.get("result", {}).get("protocolVersion")
    rpc("notifications/initialized")
    rpc("tools/list", {})
    value = rpc("tools/call", {"name": TOOL, "arguments": ARGUMENTS})
    result = value.get("result", {})
    passed = False
    if not result.get("isError", False):
        try:
            contents = [json.loads(v["text"]) for v in result.get("content", []) if v.get("type") == "text"]
            passed = any(isinstance(v, dict) and v.get("total") == 0 and v.get("issues") == [] for v in contents)
        except ValueError:
            pass
    read: dict = {"is_error": result.get("isError", False)}
    if read["is_error"]:
        read["error_shape"] = error_shape([v["text"] for v in result.get("content", []) if v.get("type") == "text"])
    return {"client": "deterministic-https", "user": username, "read_passed": passed,
        "negotiated_protocol": protocol if protocol in PROTOCOLS else "other",
        "used_native_verified_token": supplied, "events": events, "reads": [read]}


def main() -> None:
    """Guard fixture ownership, compare clients and report only sanitized evidence."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--expected-server", required=True)
    parser.add_argument("--credentials-file", required=True)
    parser.add_argument("--rounds", type=int, default=1, choices=(1, 2, 3, 4))
    parser.add_argument("--same-token-and-protocol", action="store_true")
    args = parser.parse_args()
    args.namespace = "demo-core"
    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root / "scripts" / "identity_demo"))
    from deployment_profile import in_source_checkout
    from identity_demo_lab import LABELS, oc
    server = oc(args, "config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}")
    if server.rstrip("/") != args.expected_server.rstrip("/"):
        raise ValueError("Expected fixture cluster required")
    hosts = {}
    for kind, name in (("namespace", args.namespace), ("deployment", "fixture-jira"),
                       ("route", "fixture-mcp"), ("route", "fixture-keycloak")):
        scope = [] if kind == "namespace" else ["-n", args.namespace]
        obj = json.loads(oc(args, "get", kind, name, *scope, "-o", "json"))
        if any(obj["metadata"].get("labels", {}).get(k) != v for k, v in LABELS.items()):
            raise ValueError("Owned fixture required")
        if kind == "route":
            hosts[name] = obj["spec"]["host"]
    private = Path(args.credentials_file)
    if private.stat().st_mode & 0o077 or in_source_checkout(private, root):
        raise ValueError("Private credentials outside repository required")
    credentials = json.loads(private.read_text())
    gateway = urlparse(credentials["gateway_url"])
    issuer = urlparse(credentials["keycloak_url"])
    if (gateway.scheme != "https" or gateway.path != "/mcp" or gateway.username or gateway.password
            or gateway.port not in (None, 443) or gateway.query or gateway.fragment
            or issuer.scheme != "https" or issuer.path or issuer.username or issuer.password
            or issuer.port not in (None, 443) or issuer.query or issuer.fragment):
        raise ValueError("Owned verified HTTPS endpoint contract required")
    if (credentials["namespace"] != args.namespace
            or urlparse(credentials["gateway_url"]).hostname != hosts["fixture-mcp"]
            or urlparse(credentials["keycloak_url"]).hostname != hosts["fixture-keycloak"]):
        raise ValueError("Owned fixture endpoints required")
    os.environ.update(IDENTITY_DEMO_CREDENTIALS_FILE=str(private),
        IDENTITY_DEMO_KEYCLOAK_URL=credentials["keycloak_url"])

    def count() -> int:
        """Send the synthetic credential over stdin; return only the backend count."""
        code = ("import base64,json,sys,urllib.request\n"
            "credential=json.load(sys.stdin)['credential']\n"
            "header=base64.b64encode(('admin:'+credential).encode()).decode()\n"
            "request=urllib.request.Request('http://127.0.0.1:8080/rest/api/2/search?jql=project%20%3D%20TEST&maxResults=1',headers={'Authorization':'Basic '+header})\n"
            "with urllib.request.urlopen(request,timeout=10) as response: print(json.load(response)['total'])\n")
        result = subprocess.run(["oc", "--kubeconfig=" + args.kubeconfig, "exec", "-i", "-n", args.namespace,
            "deployment/fixture-jira", "-c", "fixture-jira", "--", "python", "-c", code],
            input=json.dumps({"credential": credentials["jira_admin"]}), capture_output=True, text=True, timeout=30)
        if result.returncode or not result.stdout.strip().isdigit():
            raise RuntimeError("Owned backend count unavailable")
        return int(result.stdout.strip())

    before = count()
    if before != 0:
        raise ValueError("Empty synthetic fixture required")
    cases = []
    for round_number in range(1, args.rounds + 1):
        for username in ("analyst", "viewer"):
            private_context: dict = {}
            value = asyncio.run(native(credentials, username, private_context))
            value["round"] = round_number
            cases.append(value)
            try:
                if args.same_token_and_protocol:
                    if not private_context.get("token") or private_context.get("protocol") not in PROTOCOLS:
                        raise RuntimeError("Native verified context unavailable; no credential fallback")
                    value = deterministic(credentials, username, token=private_context["token"],
                        protocol=private_context["protocol"])
                else:
                    value = deterministic(credentials, username)
                value["round"] = round_number
                cases.append(value)
            except Exception as error:
                cases.append({"client": "deterministic-https", "user": username, "round": round_number,
                    "read_passed": False, "failure_kind": type(error).__name__})
    after = count()
    if after != before:
        raise RuntimeError("Synthetic backend state changed")
    print(json.dumps({"cases": cases, "issue_count_before": before, "issue_count_after": after,
        "same_token_and_protocol": args.same_token_and_protocol,
        "scope": "Initial read comparison only; no refresh, writes, key or policy changes",
        "all_reads_passed": all(c["read_passed"] for c in cases)}))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps({"diagnostic_completed": False, "failure_kind": type(error).__name__}), file=sys.stderr)
        raise SystemExit(1) from None
