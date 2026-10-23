# SPDX-License-Identifier: Apache-2.0
"""Native SDK discovery/PKCE tests against the owned HTTPS gateway, using read tools."""

from __future__ import annotations

import asyncio
from builtins import ExceptionGroup
from http.cookiejar import CookieJar
import importlib.metadata
import json
import logging
import os
import re
import time
from typing import Any
import unittest
from urllib.parse import parse_qs, urlparse
from urllib.request import HTTPCookieProcessor, Request, build_opener
from urllib.error import HTTPError

import httpx
from mcp import ClientSession
from mcp.client.auth import OAuthClientProvider
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthToken
from pydantic import AnyUrl
import pytest

import checks.test_components as components
from response_evidence import sanitized_error_result


class OAuthProofError(RuntimeError):
    """Represent a fixed, non-sensitive fixture assertion message."""


def classify_tool_error(texts: list[str]) -> dict:
    """Return bounded categories from error text without exposing any contents."""
    value = " ".join(text[:2048] for text in texts[:4]).lower()
    patterns = {
        "backend-initialization": ("initializ", "initialis"),
        "authentication": ("unauthorized", "forbidden", "missing token"),
        "session": ("session",),
        "timeout": ("timeout", "timed out", "deadline"),
        "connection": ("connection refused", "connection reset", "dial tcp"),
        "unknown-tool": ("unknown tool", "tool not found"),
        "transport": ("transport", "content-type", "content type"),
    }
    categories = [name for name, terms in patterns.items() if any(term in value for term in terms)]
    statuses = sorted(set(int(v) for v in re.findall(
        r"(?:http(?:/\d\.\d)?\s+|status(?: code)?[:= ]+)([1-5]\d\d)\b", value)))
    return {"categories": categories or ["unclassified"], "reported_http_statuses": statuses}


class MemoryTokens:
    """Keep synthetic tokens in memory and use the already registered public client."""

    def __init__(self) -> None:
        self.tokens: OAuthToken | None = None
        self.saved = 0
        self.client = OAuthClientInformationFull(client_id="identity-demo-ui",
            redirect_uris=[AnyUrl("http://127.0.0.1:18085/callback")], token_endpoint_auth_method="none")

    async def get_tokens(self) -> OAuthToken | None:
        """Return only the current in-memory credentials to the SDK."""
        return self.tokens

    async def set_tokens(self, tokens: OAuthToken) -> None:
        """Count issuance/refresh without logging or persisting token material."""
        self.tokens = tokens
        self.saved += 1

    async def get_client_info(self) -> OAuthClientInformationFull:
        """Use the approved client rather than enabling dynamic registration."""
        return self.client

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        """Reject replacement client identities in this bounded experiment."""
        if client_info.client_id != "identity-demo-ui":
            raise ValueError("Unexpected OAuth client registration")
        self.client = client_info


def gateway_request(url: str, path: str, *, method: str = "GET", payload: dict | None = None,
                    session: str | None = None) -> tuple[int, Any, dict]:
    """Make bounded public-route requests with verified HTTPS and no redirects."""
    parsed = urlparse(url)
    if (parsed.scheme != "https" or parsed.path != "/mcp" or parsed.username or parsed.password
            or not str(parsed.hostname).startswith("fixture-mcp-demo-core.")):
        raise ValueError("Owned HTTPS gateway URI required")
    if method == "POST" and payload is None:
        payload = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-03-26", "capabilities": {},
            "clientInfo": {"name": "identity-demo-https-denial-test", "version": "0.1"}}}
    headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json",
               "MCP-Protocol-Version": "2025-03-26"}
    if session:
        headers["Mcp-Session-Id"] = session
    req = Request(url.removesuffix("/mcp") + path, method=method, headers=headers,
                  data=json.dumps(payload).encode() if payload is not None else None)
    client = build_opener(components.NoRedirect())
    try:
        response = client.open(req, timeout=20)
    except HTTPError as error:
        response = error
    with response:
        body = response.read(1_000_001)
        if len(body) > 1_000_000:
            raise OAuthProofError("Gateway response exceeded the proof size bound")
        value = json.loads(body) if response.status == 200 else sanitized_error_result(body)
        return response.status, response.headers, value


async def _native_login_workflow(credentials: dict, username: str, *, refresh: bool,
                                 diagnostics: dict) -> dict:
    """Let the SDK discover OAuth and generate/validate state and PKCE itself."""
    # OAuth SDK errors may contain authorization URLs or response objects.
    logging.disable(logging.CRITICAL)
    url = credentials["gateway_url"]
    diagnostics["stage"] = "public-metadata"
    gateway_request(url, "/.well-known/oauth-protected-resource/mcp")  # checks the target boundary
    storage = MemoryTokens()
    callback: list[tuple[str, str | None]] = []
    observations = {"gateway_metadata_requests": 0, "issuer_metadata_requests": 0,
                    "token_requests": 0, "resource_parameter_present": False,
                    "pkce_s256": False, "challenge_seen": False}
    allowed = {urlparse(url).hostname, urlparse(components.ISSUER).hostname}

    async def inspect_request(request: httpx.Request) -> None:
        """Reject discovered destinations outside our two owned HTTPS routes."""
        if request.url.scheme != "https" or request.url.host not in allowed:
            raise ValueError("OAuth client attempted an unapproved destination")
        path = request.url.path
        if path.startswith("/.well-known/oauth-protected-resource"):
            observations["gateway_metadata_requests"] += 1
        elif "well-known" in path:
            observations["issuer_metadata_requests"] += 1
        elif path.endswith("/token"):
            observations["token_requests"] += 1
            fields = parse_qs((await request.aread()).decode())
            if fields.get("grant_type") == ["authorization_code"]:
                observations["resource_parameter_present"] = fields.get("resource") == [url]

    async def inspect_response(response: httpx.Response) -> None:
        """Record bounded status/type diagnostics without URLs, headers or bodies."""
        path = response.request.url.path
        boundary = ("resource-metadata" if path.startswith("/.well-known/oauth-protected-resource")
                    else "issuer-metadata" if "well-known" in path
                    else "token-endpoint" if path.endswith("/token") else "mcp")
        media = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if boundary == "mcp" and response.request.method == "DELETE":
            diagnostics["cleanup_http_status"] = response.status_code
            return
        diagnostics.update(boundary=boundary, http_status=response.status_code,
            http_method=response.request.method,
            media_type=media if media in {"application/json", "text/event-stream", "text/html"} else "other")
        if boundary == "mcp" and response.request.method == "POST":
            try:
                request = json.loads(await response.request.aread())
            except (ValueError, UnicodeDecodeError):
                request = {}
            method = request.get("method") if isinstance(request, dict) else None
            diagnostics["mcp_method"] = method if isinstance(method, str) and method in {
                "initialize", "notifications/initialized", "tools/list", "tools/call"} else "other"
        if response.status_code == 401 and "resource_metadata=" in response.headers.get("WWW-Authenticate", ""):
            observations["challenge_seen"] = True

    async def redirect_handler(auth_url: str) -> None:
        """Submit the synthetic user's real login form for the SDK authorization URL."""
        parsed = urlparse(auth_url)
        if (parsed.scheme != "https" or parsed.hostname != urlparse(components.ISSUER).hostname
                or parsed.path != "/realms/identity-demo/protocol/openid-connect/auth"):
            raise ValueError("Unexpected issuer authorization URL")
        query = parse_qs(parsed.query)
        if query.get("client_id") != ["identity-demo-ui"] or query.get("code_challenge_method") != ["S256"]:
            raise ValueError("Native authorization must use the approved client and S256")
        observations["pkce_s256"] = True
        client = build_opener(HTTPCookieProcessor(CookieJar()), components.NoRedirect())
        status, _, body = components.request(auth_url, opener=client)
        if status != 200:
            raise RuntimeError("Native authorization did not present the fixture login")
        form = components.LoginForm()
        form.feed(body.decode())
        if not form.action:
            raise RuntimeError("Expected login form missing")
        status, headers, _ = components.request(form.action, opener=client, fields={**form.fields,
            "username": username, "password": credentials[username], "credentialId": ""})
        location = headers.get("Location", "")
        if status != 302 or not location.startswith("http://127.0.0.1:18085/callback?"):
            raise RuntimeError("Native login did not return to the approved callback")
        values = parse_qs(urlparse(location).query)
        if not values.get("code") or values.get("state") != query.get("state"):
            raise RuntimeError("Authorization callback state/code mismatch")
        callback.append((values["code"][0], values["state"][0]))

    async def callback_handler() -> tuple[str, str | None]:
        """Return the captured code/state to the SDK without persisting them."""
        if len(callback) != 1:
            raise RuntimeError("Expected one native authorization callback")
        return callback.pop()

    metadata = OAuthClientMetadata(redirect_uris=[AnyUrl("http://127.0.0.1:18085/callback")],
        token_endpoint_auth_method="none", scope="openid", client_name="Synthetic identity demo test")
    provider = OAuthClientProvider(url, metadata, storage, redirect_handler=redirect_handler,
                                   callback_handler=callback_handler, timeout=60)

    def factory(headers: dict | None = None, timeout: httpx.Timeout | None = None,
                auth: httpx.Auth | None = None) -> httpx.AsyncClient:
        """Use native SDK authentication with strict HTTPS and destination hooks."""
        return httpx.AsyncClient(headers=headers, timeout=timeout or httpx.Timeout(20), auth=auth,
            follow_redirects=False, event_hooks={"request": [inspect_request], "response": [inspect_response]})

    def claims() -> dict:
        """Validate the real resource audience, human subject and expected role."""
        if storage.tokens is None:
            raise RuntimeError("Native OAuth client did not obtain tokens")
        value = components.verify(storage.tokens.access_token, url)
        if username not in value.get("realm_access", {}).get("roles", []) or value.get("azp") != "identity-demo-ui":
            raise RuntimeError("Native OAuth identity/role did not match its login")
        return value

    async def read(session: ClientSession) -> None:
        """Require a real backend read, not a successful HTTP error envelope."""
        result = await session.call_tool("jira_searchJiraIssuesUsingJql", {"jql": "project = TEST", "maxResults": 1})
        if result.isError:
            diagnostics["tool_error"] = classify_tool_error([
                item.text for item in result.content if getattr(item, "type", "") == "text"])
            raise OAuthProofError("Native MCP read returned an error result")
        try:
            values = [json.loads(item.text) for item in result.content if getattr(item, "type", "") == "text"]
        except json.JSONDecodeError:
            raise OAuthProofError("Native MCP read returned non-JSON text") from None
        if not any(isinstance(item, dict) and "issues" in item and "total" in item
                                    and not item.get("error", False) for item in values):
            raise RuntimeError("Native OAuth MCP read did not return a real backend result")

    async with factory(auth=provider) as client, streamable_http_client(url, http_client=client) as streams:
        async with ClientSession(streams[0], streams[1]) as session:
            diagnostics["stage"] = "initialize"
            await session.initialize()
            initial = claims()
            diagnostics["stage"] = "list-tools"
            tools = await session.list_tools()
            if {tool.name for tool in tools.tools} != {"jira_searchJiraIssuesUsingJql", "jira_getJiraIssue",
                                                      "discover_tools", "select_tools"}:
                raise OAuthProofError(f"Native OAuth discovery did not return the two permitted tools (count={len(tools.tools)})")
            diagnostics["stage"] = "backend-read"
            await read(session)
            if refresh:
                wait = initial["exp"] - time.time() + 2
                if not 0 < wait < 90:
                    raise RuntimeError("Unexpected fixture token lifetime")
                await asyncio.sleep(wait)
                diagnostics["stage"] = "refreshed-backend-read"
                await read(session)
                renewed = claims()
                if storage.saved < 2 or renewed["sub"] != initial["sub"] or renewed["exp"] <= initial["exp"]:
                    raise RuntimeError("Native refresh did not preserve the authenticated user")
    required = (observations["challenge_seen"], observations["pkce_s256"],
                observations["resource_parameter_present"], observations["gateway_metadata_requests"] > 0,
                observations["issuer_metadata_requests"] > 0)
    if not all(required):
        raise RuntimeError("Native discovery/PKCE/resource evidence incomplete")
    return {"sdk": importlib.metadata.version("mcp"), "user_role": username,
            "native_discovery_passed": True, "backend_read_passed": True,
            "refresh_preserved_user": refresh, **observations}


async def native_login(credentials: dict, username: str, *, refresh: bool) -> dict:
    """Suppress library exceptions that might include credentials or authorization URLs."""
    diagnostics: dict = {"stage": "starting"}
    try:
        return await _native_login_workflow(credentials, username, refresh=refresh, diagnostics=diagnostics)
    except Exception as error:
        def safe_names(value: Exception) -> list[str]:
            """Expose only fixed proof messages and exception class names."""
            if isinstance(value, ExceptionGroup):
                return [name for child in value.exceptions for name in safe_names(child)]
            if isinstance(value, OAuthProofError):
                return [str(value)]
            return [type(value).__name__]
        raise OAuthProofError("Native OAuth workflow failed (" + json.dumps(diagnostics, sort_keys=True)
                              + "): " + "; ".join(safe_names(error))) from None


@pytest.mark.integration
class GatewayOAuthTests(unittest.TestCase):
    """Prove discovery over the actual HTTPS URI without opening tool access."""

    @classmethod
    def setUpClass(cls) -> None:
        """Require explicit opt-in and private owned-fixture credentials."""
        if os.environ.get("IDENTITY_DEMO_GATEWAY_OAUTH") != "1":
            raise unittest.SkipTest("Gateway OAuth fixture not selected")
        components.ComponentTests.setUpClass()
        cls.credentials = components.ComponentTests.credentials
        if not cls.credentials.get("gateway_url"):
            raise RuntimeError("Owned gateway OAuth configuration missing")

    def test_metadata_is_public_and_matches_resource_and_issuer(self) -> None:
        """Unauthenticated GET returns only configured discovery metadata."""
        url = self.credentials["gateway_url"]
        for path in ("/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"):
            status, _, value = gateway_request(url, path)
            self.assertEqual(status, 200)
            self.assertEqual(value["resource"], url)
            self.assertEqual(value["authorization_servers"], [components.ISSUER])
            self.assertEqual(value["bearer_methods_supported"], ["header"])
            self.assertNotIn("tools", value)

    def test_public_metadata_exception_does_not_open_posts_or_tools(self) -> None:
        """MCP and metadata POST requests still require a valid access token."""
        for path in ("/mcp", "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"):
            status, headers, _ = gateway_request(self.credentials["gateway_url"], path, method="POST")
            self.assertEqual(status, 401)
            self.assertIn("resource_metadata=", headers.get("WWW-Authenticate", ""))
        self.assertEqual(gateway_request(self.credentials["gateway_url"], "/mcp")[0], 401)

    def test_metadata_get_rpc_body_with_session_reports_rejection(self) -> None:
        """An invalid metadata request must report rejection without executing a tool."""
        # Even possession of a valid session ID cannot turn a public metadata
        # GET into an unauthenticated tool call. A 400 is protocol rejection,
        # not evidence that JWT authorization was evaluated.
        from checks.test_gateway import initialize, rpc
        token = components.login("viewer", self.credentials["viewer"])["access_token"]
        status, headers, _ = initialize(token)
        self.assertEqual(status, 200)
        warm = headers.get("Mcp-Session-Id")
        rpc("notifications/initialized", token=token, session=warm)
        payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "jira_searchJiraIssuesUsingJql", "arguments": {"jql": "project = TEST", "maxResults": 1}}}
        status, _, value = rpc("tools/call", token=token, session=warm, params=payload["params"])
        self.assertEqual(status, 200)
        self.assertIn("result", value)
        self.assertFalse(value["result"].get("isError", False))
        status, headers, _ = initialize(token)
        self.assertEqual(status, 200)
        cold = headers.get("Mcp-Session-Id")
        rpc("notifications/initialized", token=token, session=cold)
        for case, session in (("established-backend", warm), ("no-backend-session", cold)):
            with self.subTest(case=case):
                status, _, value = gateway_request(self.credentials["gateway_url"],
                    "/.well-known/oauth-protected-resource/mcp", method="GET", payload=payload, session=session)
                self.assertNotIn("result", value)
                if status == 200:
                    self.assertEqual(value.get("resource"), self.credentials["gateway_url"])
                else:
                    self.assertIn(status, (400, 401, 403),
                                  f"Metadata GET/body rejection failed for {case}: HTTP {status}")

    def test_native_sdk_analyst_discovery_pkce_read_and_refresh(self) -> None:
        """The native client discovers OAuth, logs in and renews without known issuer injection."""
        result = asyncio.run(asyncio.wait_for(native_login(self.credentials, "analyst", refresh=True), timeout=150))
        self.assertTrue(result["native_discovery_passed"])
        self.assertTrue(result["refresh_preserved_user"])

    def test_native_sdk_viewer_discovery_pkce_and_read(self) -> None:
        """The second user completes the same native authentication/read workflow."""
        result = asyncio.run(asyncio.wait_for(native_login(self.credentials, "viewer", refresh=False), timeout=90))
        self.assertTrue(result["native_discovery_passed"])
