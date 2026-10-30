# SPDX-License-Identifier: Apache-2.0
"""Separate broker catalog credentials from short-lived Jira service tokens.

Opt-in development integration using the pinned MCP SDK's authentication and
stateless HTTP transport. Catalog credentials never authorize a tool invocation.
Trust digests are read on each request so projected Secret rotation fails closed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
import time

from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken, TokenVerifier
from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

CATALOG_CLIENT = "fixture-broker-discovery"
CATALOG_SCOPE = "mcp:catalog"
SERVICE_CLIENT = "fixture-gateway-service"
MAX_BODY = 65_536
CATALOG_METHODS = frozenset({"initialize", "tools/list", "prompts/list", "resources/list",
                           "resources/templates/list", "ping", "notifications/initialized"})


class CatalogTokenVerifier:
    """Accept bounded discovery secrets or delegate standard service JWT checks."""

    def __init__(self, service: TokenVerifier, digests: Path, resource: str) -> None:
        self.service, self.digests, self.resource = service, digests, resource

    async def verify_token(self, token: str) -> AccessToken | None:
        """Never interpret a failed discovery credential as a service credential."""
        if not token.startswith("discovery_"):
            return await self.service.verify_token(token)
        if not 40 <= len(token) <= 128 or not token.isascii():
            return None
        try:
            raw = self.digests.read_bytes()
            if len(raw) > 2_048:
                return None
            keys = json.loads(raw)
            if not isinstance(keys, dict) or not 1 <= len(keys) <= 2:
                return None
            now = time.time()
            digest = hashlib.sha256(token.encode()).hexdigest()
            for expected, expiry in keys.items():
                if (not isinstance(expected, str) or len(expected) != 64
                        or any(c not in "0123456789abcdef" for c in expected)
                        or type(expiry) is not int):
                    return None
            for expected, expiry in keys.items():
                if hmac.compare_digest(digest, expected) and expiry > now:
                    return AccessToken(token=token, client_id=CATALOG_CLIENT,
                        scopes=[CATALOG_SCOPE], expires_at=expiry, resource=self.resource,
                        subject=CATALOG_CLIENT)
        except (OSError, ValueError, TypeError):
            return None
        return None


class CatalogMethodGuard:
    """Authorize catalog methods after SDK authentication and before dispatch."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Reject session reuse, batches and non-catalog operations for discovery."""
        if scope["type"] != "http" or scope["path"] != "/mcp":
            await self.app(scope, receive, send)
            return
        user = scope.get("user")
        # The SDK produces the normal unauthenticated challenge.
        if not isinstance(user, AuthenticatedUser):
            await self.app(scope, receive, send)
            return
        token = user.access_token
        headers = {k.lower(): v for k, v in scope.get("headers", [])}
        sessions = [v for k, v in scope.get("headers", []) if k.lower() == b"mcp-session-id"]
        if any(value != b"" for value in sessions):
            await JSONResponse({"error": "Sessions are disabled on this endpoint"}, 403)(scope, receive, send)
            return
        # The router can forward an empty backend session ID for stateless MCP.
        # Normalize only that empty value; duplicate/nonempty IDs cannot hide
        # behind a dictionary conversion. Authentication still runs per request.
        if sessions:
            scope = dict(scope, headers=[(k, v) for k, v in scope["headers"]
                                       if k.lower() != b"mcp-session-id"])
        if token.client_id == SERVICE_CLIENT and "mcp:read" in token.scopes:
            await self.app(scope, receive, send)
            return
        if token.client_id == CATALOG_CLIENT and token.scopes == [CATALOG_SCOPE] and scope['method']=='GET':
            # This stateless catalog offers no SSE stream. Authenticate first,
            # retain the session rejection above, then use the MCP transport's
            # explicit unsupported-stream response rather than an auth failure.
            await JSONResponse({'error':'SSE is not supported'},405,headers={'Allow':'POST'})(scope,receive,send)
            return
        if (token.client_id != CATALOG_CLIENT or token.scopes != [CATALOG_SCOPE]
                or scope["method"] != "POST"
                or headers.get(b"content-type", b"").split(b";", 1)[0].strip() != b"application/json"):
            await JSONResponse({"error": "Insufficient permission"}, 403)(scope, receive, send)
            return
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] != "http.request":
                return
            body.extend(message.get("body", b""))
            if len(body) > MAX_BODY:
                await JSONResponse({"error": "Request too large"}, 413)(scope, receive, send)
                return
            if not message.get("more_body", False):
                break
        try:
            request = json.loads(body)
            allowed = (isinstance(request, dict) and request.get("jsonrpc") == "2.0"
                       and request.get("method") in CATALOG_METHODS)
        except (ValueError, TypeError):
            allowed = False
        if not allowed:
            await JSONResponse({"error": "Catalog credential cannot invoke this method"}, 403)(scope, receive, send)
            return

        delivered = False

        async def replay() -> dict:
            """Pass the validated body once; preserve disconnect notification."""
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


def install_catalog_guard(app: ASGIApp) -> None:
    """Append the method guard inside the pinned SDK's authentication middleware."""
    from mcp.server.auth.middleware.auth_context import AuthContextMiddleware
    from starlette.middleware.authentication import AuthenticationMiddleware

    middleware = app.user_middleware
    if ([m.cls for m in middleware] != [AuthenticationMiddleware, AuthContextMiddleware]
            or app.middleware_stack is not None):
        raise ValueError("Expected pinned SDK authentication order before startup")
    middleware.append(Middleware(CatalogMethodGuard))
