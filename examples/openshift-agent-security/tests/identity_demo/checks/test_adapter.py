# SPDX-License-Identifier: Apache-2.0
"""Read-only integration tests of native SDK authentication, separate from G5 acceptance."""

from __future__ import annotations

import json
import os
import time
from typing import Any
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

import checks.test_components as components
from response_evidence import sanitized_error_result

ADAPTER = "http://127.0.0.1:18087"


def adapter_request(path: str, *, token: str | None = None,
                    payload: dict | None = None, session: str | None = None) -> tuple[int, Any, dict]:
    """Inspect denied responses locally, returning only an unexpected result marker."""
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
               "MCP-Protocol-Version": "2025-03-26"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if session:
        headers["Mcp-Session-Id"] = session
    req = Request(ADAPTER + path, headers=headers,
                  data=json.dumps(payload).encode() if payload is not None else None)
    try:
        response = urlopen(req, timeout=20)
    except HTTPError as error:
        response = error
    with response:
        body = response.read(2_000_001)
        if len(body) > 2_000_000:
            raise RuntimeError("Adapter response exceeded the proof size bound")
        if response.status != 200:
            return response.status, response.headers, sanitized_error_result(body)
        try:
            return response.status, response.headers, json.loads(body)
        except (ValueError, UnicodeDecodeError):
            raise RuntimeError("Adapter successful response was not JSON") from None


def rpc(method: str, token: str | None, *, params: dict | None = None,
        session: str | None = None) -> tuple[int, Any, dict]:
    """Submit native Streamable HTTP JSON-RPC without an intermediary gateway."""
    payload = {"jsonrpc": "2.0", "method": method}
    if method != "notifications/initialized":
        payload["id"] = 1
    if params is not None:
        payload["params"] = params
    return adapter_request("/mcp", token=token, payload=payload, session=session)


def initialize(token: str | None) -> tuple[int, Any, dict]:
    """Initialize a real MCP session, returning its server-issued session header."""
    return rpc("initialize", token, params={"protocolVersion": "2025-03-26", "capabilities": {},
        "clientInfo": {"name": "identity-demo-protected-adapter-test", "version": "0.1"}})


@pytest.mark.integration
class AdapterTests(unittest.TestCase):
    """Use actual Keycloak tokens; no adapter JWT is fabricated or printed."""

    @classmethod
    def setUpClass(cls) -> None:
        """Require explicit opt-in to the separately provisioned protected fixture."""
        if os.environ.get("IDENTITY_DEMO_PROTECTED_ADAPTER") != "1":
            raise unittest.SkipTest("Protected adapter fixture not selected")
        components.ComponentTests.setUpClass()
        cls.credentials = components.ComponentTests.credentials
        if "adapter_clients" not in cls.credentials:
            raise RuntimeError("Protected adapter fixture credentials missing")

    def service_token(self, client: str = "fixture-gateway-service", scope: str | None = "mcp:read") -> str:
        """Request a short-lived service token from the real fixture issuer."""
        fields = {"grant_type": "client_credentials", "client_id": client,
                  "client_secret": self.credentials["adapter_clients"][client]}
        if scope is not None:
            fields["scope"] = scope
        status, _, body = components.request(components.ISSUER + "/protocol/openid-connect/token", fields=fields)
        if status != 200:
            raise RuntimeError(f"Fixture service grant failed (HTTP {status})")
        return json.loads(body)["access_token"]

    def read(self, token: str | None, session: str) -> tuple[int, Any, dict]:
        """Perform one project-scoped read with the specified request credential."""
        return rpc("tools/call", token, session=session, params={"name": "searchJiraIssuesUsingJql",
            "arguments": {"jql": "project = TEST", "maxResults": 1}})

    def open_session(self, token: str) -> str:
        """Prove successful initialization and send its required notification."""
        status, headers, result = initialize(token)
        self.assertEqual(status, 200)
        self.assertIn("result", result)
        session = headers.get("Mcp-Session-Id")
        self.assertTrue(session)
        status, _, _ = rpc("notifications/initialized", token, session=session)
        self.assertIn(status, (200, 202))
        return session

    def assert_read(self, result: dict) -> None:
        """Require an actual backend result rather than a 200 error envelope."""
        self.assertIn("result", result)
        self.assertFalse(result["result"].get("isError", False))
        payloads = [json.loads(item["text"]) for item in result["result"]["content"]
                    if item.get("type") == "text"]
        self.assertTrue(any(isinstance(item, dict) and "issues" in item and "total" in item
                            and not item.get("error", False) for item in payloads))

    def test_missing_and_invalid_tokens_denied(self) -> None:
        """Unauthenticated direct initialization fails before exposing tools."""
        for token in (None, "not-a-token"):
            with self.subTest(case="missing" if token is None else "invalid"):
                self.assert_denied(initialize(token), 401)

    def test_human_gateway_token_wrong_audience_denied(self) -> None:
        """An authentic human gateway token is not accepted at the adapter."""
        token = components.login("analyst", self.credentials["analyst"])["access_token"]
        components.verify(token, "identity-demo-mcp")
        self.assert_denied(initialize(token), 401)

    def test_wrong_service_client_denied(self) -> None:
        """A signed token with the right audience/scope but wrong client is rejected."""
        token = self.service_token("fixture-other-service")
        claims = components.verify(token, self.credentials["adapter_resource"])
        self.assertEqual(claims["azp"], "fixture-other-service")
        self.assertIn("mcp:read", claims["scope"].split())
        self.assert_denied(initialize(token), 401)

    def test_required_scope_enforced(self) -> None:
        """The permitted client cannot access tools without the read scope."""
        token = self.service_token(scope=None)
        claims = components.verify(token, self.credentials["adapter_resource"])
        self.assertEqual(claims["azp"], "fixture-gateway-service")
        self.assertNotIn("mcp:read", claims.get("scope", "").split())
        self.assert_denied(initialize(token), 403)

    def test_valid_service_token_discovers_and_reads_without_mutation(self) -> None:
        """The adapter returns its two real read tools and leaves Jira unchanged."""
        counts = components.ComponentTests()
        counts.credentials = self.credentials
        status, _, before = components.request(components.JIRA +
            "/rest/api/2/search?jql=project%20%3D%20TEST&maxResults=1", headers=counts.jira_header())
        self.assertEqual(status, 200)
        token = self.service_token()
        claims = components.verify(token, self.credentials["adapter_resource"])
        self.assertEqual(claims["azp"], "fixture-gateway-service")
        session = self.open_session(token)
        status, _, listing = rpc("tools/list", token, session=session)
        self.assertEqual(status, 200)
        self.assertEqual({tool["name"] for tool in listing["result"]["tools"]},
                         {"searchJiraIssuesUsingJql", "getJiraIssue"})
        status, _, result = self.read(token, session)
        self.assertEqual(status, 200)
        self.assert_read(result)
        status, _, after = components.request(components.JIRA +
            "/rest/api/2/search?jql=project%20%3D%20TEST&maxResults=1", headers=counts.jira_header())
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(before)["total"], json.loads(after)["total"])

    def test_existing_session_reauthenticates_every_request(self) -> None:
        """A valid session ID cannot replace a token or increase its scope."""
        token = self.service_token()
        session = self.open_session(token)
        wrong_audience = components.login("viewer", self.credentials["viewer"])["access_token"]
        cases = ((None, 401), ("not-a-token", 401), (wrong_audience, 401),
                 (self.service_token("fixture-other-service"), 401), (self.service_token(scope=None), 403))
        for credential, expected in cases:
            with self.subTest(expected=expected):
                status, _, result = self.read(credential, session)
                self.assertEqual(status, expected)
                self.assertNotIn("result", result)
        status, _, result = self.read(token, session)
        self.assertEqual(status, 200)
        self.assert_read(result)

    def test_expiry_denied_and_new_token_works_on_session(self) -> None:
        """Real expiry is rejected; a renewed service token works without a new session."""
        token = self.service_token()
        claims = components.verify(token, self.credentials["adapter_resource"])
        session = self.open_session(token)
        status, _, result = self.read(token, session)
        self.assertEqual(status, 200)
        self.assert_read(result)
        wait = claims["exp"] - time.time() + 2
        if not 0 < wait < 90:
            raise RuntimeError("Unexpected fixture token lifetime")
        time.sleep(wait)
        self.assert_denied(self.read(token, session), 401)
        self.assert_denied(initialize(token), 401)
        status, _, result = self.read(self.service_token(), session)
        self.assertEqual(status, 200)
        self.assert_read(result)

    def test_resource_metadata_public_and_challenge_correct(self) -> None:
        """The SDK exposes only resource metadata publicly with the issuer and URI."""
        status, _, metadata = adapter_request("/.well-known/oauth-protected-resource/mcp")
        self.assertEqual(status, 200)
        self.assertEqual(metadata["resource"], self.credentials["adapter_resource"])
        self.assertEqual(metadata["authorization_servers"], [components.ISSUER])
        self.assertEqual(metadata["scopes_supported"], ["mcp:read"])
        self.assertNotIn("tools", metadata)
        response = initialize(None)
        self.assert_denied(response, 401)
        _, headers, _ = response
        self.assertIn("resource_metadata=", headers.get("WWW-Authenticate", ""))

    def assert_denied(self, response: tuple[int, Any, dict], expected: int) -> None:
        """Require the rejection status and absence of results in its actual body."""
        status, _, value = response
        self.assertEqual(status, expected)
        self.assertNotIn("result", value)
