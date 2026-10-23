# SPDX-License-Identifier: Apache-2.0
"""Fixture-only SDK token verifier using a trusted public JWKS snapshot.

This proves adapter ingress authentication, not live JWKS rotation, TLS,
gateway token delivery, user/workload binding or production readiness.
"""

from __future__ import annotations

import json
from pathlib import Path

import jwt
from mcp.server.auth.provider import AccessToken
from deployment_profile import active_profile

PROFILE = active_profile()
ADAPTER_ALLOWED_HOSTS = (
    "127.0.0.1:*", "fixture-protected-adapter:*",
    "fixture-protected-adapter." + PROFILE.core_namespace + ".svc:*",
    PROFILE.service_host("fixture-protected-adapter") + ":*",
    PROFILE.service_host("fixture-protected-adapter"),
)


class FixtureTokenVerifier:
    """Validate a Keycloak service access token for this adapter and client."""

    def __init__(self, issuer: str, audience: str, client: str, jwks: Path) -> None:
        self.issuer, self.audience, self.client, self.jwks = issuer, audience, client, jwks

    async def verify_token(self, token: str) -> AccessToken | None:
        """Reject untrusted token material without logging credentials or claims."""
        try:
            return self.validate_with_keys(token, json.loads(self.jwks.read_text()))
        except (OSError, ValueError):
            return None

    def validate_with_keys(self, token: str, public_keys: dict) -> AccessToken | None:
        """Apply the same standard JWT checks to a snapshot or configured live JWKS."""
        if len(token) > 16_384:
            return None
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
                return None
            # Never follow a token-supplied jku/x5u. This public snapshot was obtained
            # through the owned issuer's verified HTTPS endpoint during setup.
            keys = jwt.PyJWKSet.from_dict(public_keys)
            candidates = [key for key in keys.keys if key.key_id == header["kid"]
                          and key.algorithm_name == "RS256" and key.public_key_use in (None, "sig")]
            if len(candidates) != 1:
                return None
            claims = jwt.decode(token, candidates[0].key, algorithms=["RS256"],
                audience=self.audience, issuer=self.issuer,
                options={"require": ["iss", "aud", "sub", "exp", "iat", "azp", "typ"]})
            if claims["typ"] != "Bearer" or claims["azp"] != self.client:
                return None
            if not isinstance(claims["sub"], str) or not claims["sub"]:
                return None
            scope = claims.get("scope", "")
            if not isinstance(scope, str):
                return None
            return AccessToken(token=token, client_id=claims["azp"],
                scopes=scope.split(), expires_at=claims["exp"], resource=self.audience,
                subject=claims["sub"], claims=claims)
        except (jwt.PyJWTError, OSError, ValueError, KeyError, TypeError, StopIteration):
            # Unknown keys or broken configuration fail closed. The fixture is
            # intentionally small; production needs safe diagnostics/key refresh.
            return None
