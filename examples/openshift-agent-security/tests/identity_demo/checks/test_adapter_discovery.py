# SPDX-License-Identifier: Apache-2.0
"""Exercise catalog separation through real MCP SDK authentication and dispatch."""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
import time

import httpx
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import AnyHttpUrl
import pytest

from adapter_discovery import CatalogTokenVerifier, install_catalog_guard
from adapter_auth import ADAPTER_ALLOWED_HOSTS

TOKEN_A = "discovery_" + "a" * 43
TOKEN_B = "discovery_" + "b" * 43
RESOURCE = "https://adapter.example/mcp"


class ServiceVerifier:
    """Use an explicitly trusted synthetic service identity in SDK HTTP tests."""

    async def verify_token(self, token: str) -> AccessToken | None:
        """Supply service scope independently of the catalog trust file."""
        if token not in {"service", "unscoped"}:
            return None
        return AccessToken(token=token, client_id="fixture-gateway-service",
            scopes=["mcp:read"] if token == "service" else [],
            expires_at=int(time.time()) + 30, resource=RESOURCE, subject="service-user")


def trust(path: Path, *tokens: str, expiry: int | None = None) -> None:
    """Write only trusted credential hashes for a rotation/revocation test."""
    path.write_text(json.dumps({hashlib.sha256(token.encode()).hexdigest():
        expiry if expiry is not None else int(time.time()) + 60 for token in tokens}))


def app(path: Path) -> tuple[object, list[str]]:
    """Construct the actual pinned stateless SDK server and permission guard."""
    calls: list[str] = []
    verifier = CatalogTokenVerifier(ServiceVerifier(), path, RESOURCE)
    server = FastMCP("catalog-test", stateless_http=True, json_response=True,
        log_level="CRITICAL", token_verifier=verifier,
        auth=AuthSettings(issuer_url=AnyHttpUrl("https://issuer.example"),
                         resource_server_url=AnyHttpUrl(RESOURCE), required_scopes=[]),
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=True,
                                                    allowed_hosts=["unit.local", *ADAPTER_ALLOWED_HOSTS]))

    @server.tool()
    def read_fixture() -> str:
        """Record real tool dispatch without accessing a backend."""
        calls.append("read")
        return "synthetic-read"

    instance = server.streamable_http_app()
    install_catalog_guard(instance)
    return instance, calls


async def request(instance: object, token: str | None, method: str | None = "tools/list",
                  *, http_method: str = "POST", body: bytes | None = None,
                  session: bool = False, host: str | None = None,
                  session_headers: list[str] | None = None) -> httpx.Response:
    """Exercise real SDK middleware and transports without an external listener."""
    headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if host:
        headers["Host"] = host
    if session:
        headers["Mcp-Session-Id"] = "another-credential-session"
    raw_headers = list(headers.items())
    raw_headers.extend(("Mcp-Session-Id", value) for value in session_headers or [])
    params = {"name": "read_fixture", "arguments": {}} if method == "tools/call" else {}
    if method == "initialize":
        params = {"protocolVersion": "2025-11-25", "capabilities": {},
                  "clientInfo": {"name": "guard-test", "version": "1"}}
    if body is None:
        payload = {"jsonrpc": "2.0", "method": method, "params": params}
        if method != "notifications/initialized":
            payload["id"] = 1
        body = json.dumps(payload).encode()
    async with instance.router.lifespan_context(instance):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=instance),
                                    base_url="http://unit.local", trust_env=False) as client:
            return await client.request(http_method, "/mcp", headers=raw_headers, content=body)


@pytest.mark.parametrize("token,method,status", [
    (TOKEN_A, "tools/list", 200), (TOKEN_A, "initialize", 200),
    (TOKEN_A, "tools/call", 403), ("service", "tools/call", 200),
])
def test_empty_gateway_session_header_keeps_stateless_permissions(
    tmp_path: Path, token: str, method: str, status: int,
) -> None:
    """An empty backend ID creates no session and grants no additional permission."""
    path = tmp_path / "digests.json"
    trust(path, TOKEN_A)
    instance, calls = app(path)
    response = asyncio.run(request(instance, token, method, session_headers=[""]))
    assert response.status_code == status
    assert "mcp-session-id" not in response.headers
    assert calls == (["read"] if token == "service" and status == 200 else [])


@pytest.mark.parametrize("values", [["nonempty"], [" "], ["nonempty", ""], ["", "nonempty"]])
@pytest.mark.parametrize("token", [TOKEN_A, "service"])
def test_any_nonempty_session_header_denied(
    tmp_path: Path, token: str, values: list[str],
) -> None:
    """Whitespace and duplicate headers cannot attach either credential to a session."""
    path = tmp_path / "digests.json"
    trust(path, TOKEN_A)
    instance, calls = app(path)
    response = asyncio.run(request(instance, token, "tools/call", session_headers=values))
    assert response.status_code == 403
    assert not calls


@pytest.mark.parametrize("method,status", [
    ("initialize", 200), ("tools/list", 200), ("ping", 200),
    ("prompts/list", 200), ("resources/list", 200), ("resources/templates/list", 200),
    ("notifications/initialized", 202), ("tools/call", 403), ("prompts/get", 403),
    ("resources/read", 403), ("logging/setLevel", 403), ("unknown", 403),
])
def test_catalog_methods_are_enforced_before_tool_dispatch(tmp_path: Path, method: str, status: int) -> None:
    """Catalog credentials expose schemas but cannot execute any tool."""
    path = tmp_path / "digests.json"
    trust(path, TOKEN_A)
    instance, calls = app(path)
    response = asyncio.run(request(instance, TOKEN_A, method))
    assert response.status_code == status
    assert not calls
    assert "mcp-session-id" not in response.headers


@pytest.mark.parametrize("http_method,session,body", [
    ("DELETE", False, None), ("POST", True, None),
    ("POST", False, b'[{"jsonrpc":"2.0","method":"tools/list","id":1}]'),
    ("POST", False, b'{"jsonrpc":"2.0","method":["tools/list"],"id":1}'),
    ("POST", False, b"malformed"),
])
def test_catalog_cannot_use_sessions_or_alternative_envelopes(
    tmp_path: Path, http_method: str, session: bool, body: bytes | None,
) -> None:
    """A catalog credential cannot attach to/delete sessions or hide a tool call."""
    path = tmp_path / "digests.json"
    trust(path, TOKEN_A)
    instance, calls = app(path)
    response = asyncio.run(request(instance, TOKEN_A, http_method=http_method, session=session, body=body))
    assert response.status_code == 403
    assert not calls


def test_service_tool_call_and_unscoped_denial(tmp_path: Path) -> None:
    """An independently authenticated read token still reaches the real tool handler."""
    path = tmp_path / "digests.json"
    trust(path, TOKEN_A)
    instance, calls = app(path)
    response = asyncio.run(request(instance, "service", "tools/call"))
    assert response.status_code == 200 and not response.json()["result"].get("isError", False)
    assert calls == ["read"]
    for token, session in (("unscoped", False), ("service", True)):
        instance, calls = app(path)
        assert asyncio.run(request(instance, token, "tools/call", session=session)).status_code == 403
        assert not calls


@pytest.mark.parametrize('token,status',[(TOKEN_A,405),(None,401),('unknown',401),('unscoped',403)])
def test_no_catalog_sse_stream_is_not_a_tool_permission(tmp_path,token,status):
    path=tmp_path/'digests.json';trust(path,TOKEN_A);instance,calls=app(path)
    response=asyncio.run(request(instance,token,http_method='GET'))
    assert response.status_code==status and not calls
    if status==405:
        assert response.headers['allow']=='POST' and 'mcp-session-id' not in response.headers
        instance,calls=app(path)
        assert asyncio.run(request(instance,token,'tools/call')).status_code==403
        assert not calls
        instance,calls=app(path)
        assert asyncio.run(request(instance,token,http_method='GET',session=True)).status_code==403
        assert not calls


@pytest.mark.parametrize("token", [None, "unknown", TOKEN_B])
def test_unauthenticated_catalog_denied(tmp_path: Path, token: str | None) -> None:
    """Tool schemas remain protected from missing and invalid credentials."""
    path = tmp_path / "digests.json"
    trust(path, TOKEN_A)
    instance, calls = app(path)
    assert asyncio.run(request(instance, token)).status_code == 401
    assert not calls


def test_live_digest_overlap_rotation_revocation_and_expiry(tmp_path: Path) -> None:
    """Trust-file changes take effect without rebuilding a verifier or extending TTL."""
    path = tmp_path / "digests.json"
    verifier = CatalogTokenVerifier(ServiceVerifier(), path, RESOURCE)
    trust(path, TOKEN_A)
    assert asyncio.run(verifier.verify_token(TOKEN_A)).scopes == ["mcp:catalog"]
    trust(path, TOKEN_A, TOKEN_B)
    assert asyncio.run(verifier.verify_token(TOKEN_B)) is not None
    trust(path, TOKEN_B)
    assert asyncio.run(verifier.verify_token(TOKEN_A)) is None
    trust(path, TOKEN_B, expiry=int(time.time()) - 1)
    assert asyncio.run(verifier.verify_token(TOKEN_B)) is None
    path.unlink()
    assert asyncio.run(verifier.verify_token(TOKEN_B)) is None
    assert asyncio.run(verifier.verify_token("service")) is not None


def test_oversized_body_rejected_without_dispatch(tmp_path: Path) -> None:
    """Discovery cannot force unbounded request buffering."""
    path = tmp_path / "digests.json"
    trust(path, TOKEN_A)
    instance, calls = app(path)
    assert asyncio.run(request(instance, TOKEN_A, body=b"x" * 65_537)).status_code == 413
    assert not calls


@pytest.mark.parametrize("value", ["not-json", "[]", "{}", '{"invalid":123}', "x" * 2_049])
def test_broken_discovery_trust_fails_closed(tmp_path: Path, value: str) -> None:
    """Malformed or absent catalog trust never affects service JWT validation."""
    path = tmp_path / "digests.json"
    path.write_text(value)
    verifier = CatalogTokenVerifier(ServiceVerifier(), path, RESOURCE)
    assert asyncio.run(verifier.verify_token(TOKEN_A)) is None
    assert asyncio.run(verifier.verify_token("service")) is not None


@pytest.mark.parametrize("host,status", [
    ("fixture-protected-adapter.demo-core.svc.cluster.local", 200),
    ("fixture-protected-adapter.demo-core.svc.cluster.local:8443", 200),
    ("fixture-protected-adapter.demo-core.svc.cluster.local.attacker.invalid", 421),
    ("attacker.invalid", 421),
])
def test_gateway_authority_is_exact_without_disabling_dns_protection(
    tmp_path: Path, host: str, status: int,
) -> None:
    """The gateway's no-port rewrite works, while other destinations are rejected."""
    path = tmp_path / "digests.json"
    trust(path, TOKEN_A)
    instance, calls = app(path)
    assert asyncio.run(request(instance, TOKEN_A, host=host)).status_code == status
    assert not calls
