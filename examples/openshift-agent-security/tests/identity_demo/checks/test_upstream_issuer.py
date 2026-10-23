# SPDX-License-Identifier: Apache-2.0
"""Read-only development issuer checks; these do not prove gateway enforcement."""

from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import unittest

import jwt
import pytest

import checks.test_components as components

AUDIENCE = "https://fixture-protected-adapter.demo-core.svc:8443/mcp"
CLIENT = "fixture-gateway-service"


@pytest.mark.integration
class UpstreamIssuerTests(unittest.TestCase):
    """Validate the selected scoped service grant without touching configuration."""

    @classmethod
    def setUpClass(cls) -> None:
        """Require an explicit upstream endpoint and private owned credentials."""
        filename = os.environ.get("IDENTITY_DEMO_CREDENTIALS_FILE")
        if not filename or not components.KEYCLOAK.startswith(
            "https://fixture-keycloak-upstream-demo-core."
        ):
            raise unittest.SkipTest("Explicit upstream development fixture required")
        path = Path(filename)
        if path.is_symlink() or path.stat().st_mode & 0o077:
            raise RuntimeError("Private fixture credential file required")
        cls.credentials = json.loads(path.read_text())
        if cls.credentials.get("namespace") != "demo-core":
            raise RuntimeError("Unexpected fixture namespace")

    def grant(
        self, *, scope: str | None = "mcp:read", secret: str | None = None
    ) -> tuple[int, dict]:
        """Issue one bounded service grant without exposing its credential."""
        fields = {
            "grant_type": "client_credentials",
            "client_id": CLIENT,
            "client_secret": secret
            if secret is not None
            else self.credentials["adapter_clients"][CLIENT],
        }
        if scope is not None:
            fields["scope"] = scope
        status, _, body = components.request(
            components.ISSUER + "/protocol/openid-connect/token", fields=fields
        )
        return status, json.loads(body)

    def claims(self, token: str) -> dict:
        """Verify the signature, selected issuer, expiry and adapter audience."""
        return components.verify(token, AUDIENCE, issuer=components.ISSUER)

    def test_scoped_short_lived_https_service_token(self) -> None:
        """The service grant has one HTTPS audience and only the read scope."""
        status, result = self.grant()
        self.assertEqual(status, 200)
        claims = self.claims(result["access_token"])
        audiences = claims["aud"]
        if isinstance(audiences, str):
            audiences = [audiences]
        self.assertTrue(audiences == [AUDIENCE])
        self.assertTrue(claims["azp"] == CLIENT)
        self.assertTrue(claims.get("scope", "").split() == ["mcp:read"])
        self.assertTrue(0 < claims["exp"] - claims["iat"] <= 30)
        self.assertEqual(result["token_type"], "Bearer")

    def test_wrong_service_secret_rejected(self) -> None:
        """An incorrect confidential client credential cannot obtain a token."""
        status, result = self.grant(secret=secrets.token_urlsafe(32))
        self.assertEqual(status, 401)
        self.assertNotIn("access_token", result)

    def test_write_scope_rejected(self) -> None:
        """The read service client cannot request the unconfigured write scope."""
        status, result = self.grant(scope="mcp:write")
        self.assertEqual(status, 400)
        self.assertNotIn("access_token", result)

    def test_read_scope_requires_explicit_request(self) -> None:
        """An unscoped service grant is not a read authorization credential."""
        status, result = self.grant(scope=None)
        self.assertEqual(status, 200)
        claims = self.claims(result["access_token"])
        self.assertNotIn("mcp:read", claims.get("scope", "").split())

    def test_independent_grants_have_distinct_identifiers(self) -> None:
        """Fresh grant issuance is distinct; this does not test gateway caching."""
        identifiers = []
        for _ in range(2):
            status, result = self.grant()
            self.assertEqual(status, 200)
            identifiers.append(self.claims(result["access_token"])["jti"])
        self.assertTrue(identifiers[0] != identifiers[1])

    def test_local_verifier_rejects_wrong_audience_and_issuer(self) -> None:
        """Verifier negatives are separate from actual adapter enforcement."""
        status, result = self.grant()
        self.assertEqual(status, 200)
        with self.assertRaises(jwt.InvalidAudienceError):
            components.verify(
                result["access_token"], "another-service", issuer=components.ISSUER
            )
        with self.assertRaises(jwt.InvalidIssuerError):
            components.verify(
                result["access_token"], AUDIENCE, issuer=components.ISSUER + "-wrong"
            )
