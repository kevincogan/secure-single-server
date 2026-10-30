# SPDX-License-Identifier: Apache-2.0
"""Explicitly enabled component checks; shared HTTP helpers are runtime code."""
from __future__ import annotations
import base64
import hashlib
from html.parser import HTMLParser
from http.cookiejar import CookieJar
import json
import os
from pathlib import Path
import secrets
import time
from typing import Any
import unittest
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, Request, build_opener
import jwt
import pytest
from deployment_profile import active_profile
from identity_demo_fixture_http import KEYCLOAK, JIRA, ISSUER, NoRedirect, LoginForm, request, login, verify

@pytest.mark.integration
class ComponentTests(unittest.TestCase):
    """Exercise real login and strict REST credentials on synthetic fixtures."""

    @classmethod
    def setUpClass(cls) -> None:
        """Load credentials from a private, explicitly supplied fixture file."""
        filename = os.environ.get("IDENTITY_DEMO_CREDENTIALS_FILE")
        if not filename:
            raise unittest.SkipTest("Explicit owned-fixture credentials required")
        path = Path(filename)
        if path.stat().st_mode & 0o077:
            raise RuntimeError("Fixture credential file is not private")
        cls.credentials = json.loads(path.read_text())
        if cls.credentials["namespace"] != "demo-core":
            raise RuntimeError("Unexpected fixture namespace")

    def jira_header(self, password: str | None = None) -> dict:
        """Build a fixture-only Basic credential without printing it."""
        value = password or self.credentials["jira_admin"]
        return {"Authorization": "Basic " + base64.b64encode(f"admin:{value}".encode()).decode()}

    def test_real_users_pkce_and_distinct_roles(self) -> None:
        """Two real users have distinct subjects and expected role claims."""
        subjects = []
        for username in ("analyst", "viewer"):
            tokens = login(username, self.credentials[username])
            claims = verify(tokens["access_token"], "identity-demo-mcp")
            self.assertEqual(claims["preferred_username"], username)
            self.assertEqual(claims["azp"], "identity-demo-ui")
            self.assertIn(username, claims["realm_access"]["roles"])
            other = "viewer" if username == "analyst" else "analyst"
            self.assertNotIn(other, claims["realm_access"]["roles"])
            identity = verify(tokens["id_token"], "identity-demo-ui")
            self.assertEqual(identity["nonce"], tokens["expected_nonce"])
            subjects.append(claims["sub"])
        self.assertNotEqual(subjects[0], subjects[1])

    def test_wrong_password_rejected(self) -> None:
        """Wrong human credentials never yield an authorization code."""
        with self.assertRaises(PermissionError):
            login("analyst", secrets.token_urlsafe(32))

    def test_direct_user_password_grant_disabled(self) -> None:
        """The demo UI does not offer Resource Owner Password Credentials grants."""
        status, _, _ = request(ISSUER + "/protocol/openid-connect/token", fields={
            "grant_type": "password", "client_id": "identity-demo-ui", "username": "analyst",
            "password": self.credentials["analyst"]})
        self.assertEqual(status, 400)

    def test_missing_pkce_rejected(self) -> None:
        """The public login client requires the configured S256 PKCE challenge."""
        query = urlencode({"client_id": "identity-demo-ui", "response_type": "code", "scope": "openid",
                           "redirect_uri": "http://127.0.0.1:18085/callback"})
        status, headers, _ = request(ISSUER + "/protocol/openid-connect/auth?" + query)
        # OAuth errors can be redirected to the validated callback URI.
        if status == 302:
            parameters = parse_qs(urlparse(headers.get("Location", "")).query)
            self.assertEqual(parameters.get("error"), ["invalid_request"])
            self.assertNotIn("code", parameters)
        else:
            self.assertEqual(status, 400)

    def test_local_verifier_rejects_wrong_audience_issuer_and_signature(self) -> None:
        """These are verifier tests, not evidence of gateway token enforcement."""
        tokens = login("analyst", self.credentials["analyst"])
        token = tokens["access_token"]
        with self.assertRaises(jwt.InvalidAudienceError):
            verify(token, "another-service")
        with self.assertRaises(jwt.InvalidIssuerError):
            verify(token, "identity-demo-mcp", ISSUER + "-wrong")
        parts = token.split(".")
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
        claims["preferred_username"] = "forged-user"
        parts[1] = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
        with self.assertRaises(jwt.InvalidSignatureError):
            verify(".".join(parts), "identity-demo-mcp")

    def test_refresh_preserves_user(self) -> None:
        """A real refresh stays with its authenticated user; run binding remains unproved."""
        original = login("viewer", self.credentials["viewer"])
        status, _, body = request(ISSUER + "/protocol/openid-connect/token", fields={
            "grant_type": "refresh_token", "client_id": "identity-demo-ui",
            "refresh_token": original["refresh_token"]})
        self.assertEqual(status, 200)
        renewed = json.loads(body)
        self.assertEqual(verify(original["access_token"], "identity-demo-mcp")["sub"],
                         verify(renewed["access_token"], "identity-demo-mcp")["sub"])

    def test_jira_missing_wrong_and_valid_credentials(self) -> None:
        """Strict REST authentication rejects absent/wrong passwords and accepts the fixture password."""
        for headers, expected in (({}, 401), (self.jira_header("incorrect-fixture-password"), 401),
                                  (self.jira_header(), 200)):
            status, _, _ = request(JIRA + "/rest/api/2/myself", headers=headers)
            self.assertEqual(status, expected)

    def test_jira_known_seed_token_rejected(self) -> None:
        """The image's predictable seed token must not remain usable in the fixture."""
        status, _, _ = request(JIRA + "/rest/api/2/myself", headers={
            "Authorization": "Bearer jira-emulator-default-token"})
        self.assertEqual(status, 401)

    def test_jira_read_is_non_mutating(self) -> None:
        """Two project-scoped search reads leave the synthetic issue count unchanged."""
        url = JIRA + "/rest/api/2/search?" + urlencode({"jql": "project = TEST", "maxResults": "1"})
        before_status, _, before = request(url, headers=self.jira_header())
        after_status, _, after = request(url, headers=self.jira_header())
        self.assertEqual(before_status, 200)
        self.assertEqual(after_status, 200)
        self.assertEqual(json.loads(before)["total"], json.loads(after)["total"])

    def test_zz_actual_token_expiry_rejected_locally(self) -> None:
        """Observe real expiry without inventing an expired issuer-signed token."""
        token = login("viewer", self.credentials["viewer"])["access_token"]
        claims = verify(token, "identity-demo-mcp")
        deadline = claims["exp"] + 1
        while time.time() < deadline:
            time.sleep(min(1, deadline - time.time()))
        with self.assertRaises(jwt.ExpiredSignatureError):
            verify(token, "identity-demo-mcp")


if __name__ == "__main__":
    unittest.main()
