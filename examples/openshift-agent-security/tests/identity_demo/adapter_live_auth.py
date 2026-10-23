# SPDX-License-Identifier: Apache-2.0
"""Fixture JWKS refresh over configured HTTPS, with bounded cache and retry rates.

This is a read-only boundary experiment, not proof of gateway credential delivery.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
import time
from urllib.parse import urlparse

import httpx
import jwt
from mcp.server.auth.provider import AccessToken

from adapter_auth import FixtureTokenVerifier
from deployment_profile import active_profile

FIXTURE_ISSUER_HOSTS = frozenset({
    urlparse(active_profile().origin("fixture-keycloak")).hostname,
    urlparse(active_profile().origin("fixture-keycloak-upstream")).hostname,
})


class LiveFixtureTokenVerifier(FixtureTokenVerifier):
    """Use standard JWT verification and fetch only the configured issuer's keys."""

    def __init__(self, issuer: str, audience: str, client: str,
                 cache_seconds: float = 30, retry_seconds: float = 2) -> None:
        super().__init__(issuer, audience, client, Path("/unused-live-jwks"))
        parsed = urlparse(issuer)
        if (parsed.scheme != "https" or parsed.username or parsed.password or parsed.query
                or parsed.fragment or parsed.port not in (None, 443)
                or parsed.hostname not in FIXTURE_ISSUER_HOSTS
                or parsed.path != "/realms/identity-demo"):
            raise ValueError("Configured owned HTTPS issuer required")
        if cache_seconds <= 0 or not 0 < retry_seconds <= cache_seconds:
            raise ValueError("Bounded positive fixture cache/retry intervals required")
        self.url = issuer + "/protocol/openid-connect/certs"
        self.cache_seconds, self.retry_seconds = cache_seconds, retry_seconds
        self.keys: dict | None = None
        self.expires = 0.0
        self.next_fetch = 0.0
        self.lock = asyncio.Lock()

    async def fetch_keys(self) -> dict:
        """Read bounded public JWKS over verified HTTPS; redirects are rejected."""
        async with httpx.AsyncClient(timeout=5, follow_redirects=False, trust_env=False) as client:
            async with client.stream("GET", self.url, headers={"Accept": "application/json"}) as response:
                if response.status_code != 200:
                    raise ValueError("Configured JWKS endpoint rejected request")
                data = bytearray()
                async for chunk in response.aiter_bytes():
                    data.extend(chunk)
                    if len(data) > 131_072:
                        raise ValueError("Fixture JWKS exceeds size limit")
        import json
        value = json.loads(data)
        jwt.PyJWKSet.from_dict(value)
        return value

    def has_key(self, kid: str) -> bool:
        """Inspect cached public key IDs without trusting token-supplied key URLs."""
        return bool(self.keys and any(isinstance(key, dict) and key.get("kid") == kid
                                     for key in self.keys.get("keys", [])))

    async def verify_token(self, token: str) -> AccessToken | None:
        """Reject unknown keys, invalid tokens and stale trust on fetch failure."""
        try:
            if len(token) > 16_384:
                return None
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
                return None
            kid = header["kid"]
            now = time.monotonic()
            if now >= self.expires or not self.has_key(kid):
                async with self.lock:
                    now = time.monotonic()
                    if now >= self.expires or not self.has_key(kid):
                        if now < self.next_fetch:
                            return None
                        self.next_fetch = now + self.retry_seconds
                        self.keys = await self.fetch_keys()
                        self.expires = time.monotonic() + self.cache_seconds
            if time.monotonic() >= self.expires or self.keys is None:
                return None
            return self.validate_with_keys(token, self.keys)
        except (jwt.PyJWTError, httpx.HTTPError, ValueError, KeyError, TypeError):
            return None
