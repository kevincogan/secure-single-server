# SPDX-License-Identifier: Apache-2.0
"""Read-only gateway integration tests; no workload attestation is claimed."""

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
from checks.test_components import login, verify
from response_evidence import sanitized_error_result

BROKER_HOST = os.environ.get("IDENTITY_DEMO_GATEWAY_HOST", "fixture-mcp.local")


def rpc(method: str, *, token: str | None = None, params: dict | None = None,
        session: str | None = None, extra: dict | None = None,
        host: str = BROKER_HOST) -> tuple[int, Any, dict]:
    """Send JSON-RPC locally, inspecting error bodies without returning contents."""
    headers = {"Host": host, "Content-Type": "application/json",
               "Accept": "application/json, text/event-stream",
               "MCP-Protocol-Version": "2025-03-26"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if session:
        headers["Mcp-Session-Id"] = session
    headers.update(extra or {})
    payload: dict = {"jsonrpc": "2.0", "method": method}
    if method != "notifications/initialized":
        payload["id"] = 1
    if params is not None:
        payload["params"] = params
    request = Request("http://127.0.0.1:18084/mcp", headers=headers,
                      data=json.dumps(payload).encode())
    try:
        response = urlopen(request, timeout=20)
    except HTTPError as error:
        response = error
    with response:
        body = response.read(2_000_001)
        if len(body) > 2_000_000:
            raise RuntimeError("Gateway response exceeded the proof size bound")
        if response.status != 200:
            return response.status, response.headers, sanitized_error_result(body)
        try:
            events = [json.loads(line[5:].strip()) for line in body.decode().splitlines()
                      if line.startswith("data:")]
            value = events[-1] if events else json.loads(body)
        except (ValueError, UnicodeDecodeError):
            raise RuntimeError("Gateway success response was not valid JSON-RPC") from None
        return response.status, response.headers, value


def initialize(token: str | None, *, extra: dict | None = None,
               host: str = BROKER_HOST) -> tuple[int, Any, dict]:
    """Initialize the deterministic MCP client through the real gateway."""
    return rpc("initialize", token=token, extra=extra, host=host, params={
        "protocolVersion": "2025-03-26", "capabilities": {},
        "clientInfo": {"name": "identity-demo-preflight", "version": "0.1"}})


@pytest.mark.integration
class GatewayTests(unittest.TestCase):
    """Exercise actual JWT enforcement and two permitted read-only tools."""

    @classmethod
    def setUpClass(cls) -> None:
        """Require the same private owned-fixture configuration as component tests."""
        components.ComponentTests.setUpClass()
        cls.credentials = components.ComponentTests.credentials

    def test_missing_and_invalid_credentials_denied(self) -> None:
        """Authentication failure is a 401/403, never a proxy outage."""
        for token in (None, "not-a-token"):
            with self.subTest(case="missing" if token is None else "invalid"):
                status, _, _ = initialize(token)
                self.assertIn(status, (401, 403))

    def test_valid_signature_wrong_audience_denied(self) -> None:
        """A real signed ID token cannot serve as the MCP access token."""
        tokens = login("analyst", self.credentials["analyst"])
        verify(tokens["id_token"], "identity-demo-ui")
        status, _, _ = initialize(tokens["id_token"])
        self.assertEqual(status, 403)

    def test_forged_internal_headers_without_token_denied(self) -> None:
        """Client-controlled internal routing headers do not bypass authentication."""
        cases = [
            {"router-key": "forged", "mcp-init-host": "jira.fixture-mcp.local"},
            {"x-mcp-toolname": "jira_searchJiraIssuesUsingJql",
             "x-mcp-method": "tools/call"},
        ]
        for headers in cases:
            with self.subTest(case=list(headers)):
                status, _, _ = initialize(None, extra=headers)
                self.assertIn(status, (400, 401, 403))

    def test_direct_backend_listener_without_token_denied(self) -> None:
        """JWT policy also protects the alternate backend listener."""
        status, _, _ = initialize(None, host="jira.fixture-mcp.local")
        self.assertIn(status, (401, 403))

    def test_catalogue_helpers_authenticate_each_request(self) -> None:
        """Built-in discovery/selection tools cannot bypass broker authentication."""
        tokens = login("viewer", self.credentials["viewer"])
        status, headers, _ = initialize(tokens["access_token"])
        self.assertEqual(status, 200)
        session = headers.get("Mcp-Session-Id")
        rpc("notifications/initialized", token=tokens["access_token"], session=session)
        for name, arguments in (("discover_tools", {}), ("select_tools", {"tools": []})):
            status, _, value = rpc("tools/call", token=tokens["access_token"], session=session,
                                  params={"name": name, "arguments": arguments})
            self.assertEqual(status, 200)
            self.assertIn("result", value)
            self.assertFalse(value["result"].get("isError", False))
            for case, token in (("missing", None), ("invalid", "not-a-token"),
                                ("wrong-audience", tokens["id_token"])):
                with self.subTest(tool=name, case=case):
                    status, _, value = rpc("tools/call", token=token, session=session,
                                          params={"name": name, "arguments": arguments})
                    self.assertIn(status, (401, 403))
                    self.assertNotIn("result", value)

    def test_tool_calls_reauthenticate_existing_session(self) -> None:
        """A session ID must not replace current access-token authentication."""
        tokens = login("analyst", self.credentials["analyst"])
        status, headers, _ = initialize(tokens["access_token"])
        self.assertEqual(status, 200)
        session = headers.get("Mcp-Session-Id")
        rpc("notifications/initialized", token=tokens["access_token"], session=session)
        self.prime_backend(tokens["access_token"], session)
        for case, token in (("missing", None), ("invalid", "not-a-token"),
                            ("wrong-audience", tokens["id_token"])):
            with self.subTest(case=case):
                status, _, _ = rpc("tools/call", token=token, session=session, params={
                    "name": "jira_searchJiraIssuesUsingJql",
                    "arguments": {"jql": "project = TEST", "maxResults": 1}})
                self.assertIn(status, (401, 403))

    def prime_backend(self, token: str, session: str | None) -> None:
        """Prove a real permitted read before testing an established backend session."""
        status, _, value = rpc("tools/call", token=token, session=session, params={
            "name": "jira_searchJiraIssuesUsingJql",
            "arguments": {"jql": "project = TEST", "maxResults": 1}})
        self.assertEqual(status, 200)
        self.assertIn("result", value)
        self.assertFalse(value["result"].get("isError", False))
        payloads = [json.loads(item["text"]) for item in value["result"].get("content", [])
                    if item.get("type") == "text"]
        self.assertTrue(any(isinstance(item, dict) and "issues" in item and "total" in item
                            and not item.get("error") for item in payloads))

    def test_bad_credentials_on_first_tool_call_report_denial(self) -> None:
        """Cold backend setup must preserve authentication errors as 401/403."""
        tokens = login("analyst", self.credentials["analyst"])
        status, headers, _ = initialize(tokens["access_token"])
        self.assertEqual(status, 200)
        session = headers.get("Mcp-Session-Id")
        rpc("notifications/initialized", token=tokens["access_token"], session=session)
        for case, token in (("missing", None), ("invalid", "not-a-token"),
                            ("wrong-audience", tokens["id_token"])):
            with self.subTest(case=case):
                status, _, value = rpc("tools/call", token=token, session=session, params={
                    "name": "jira_searchJiraIssuesUsingJql",
                    "arguments": {"jql": "project = TEST", "maxResults": 1}})
                self.assertNotIn("result", value)
                self.assertIn(status, (401, 403))

    def test_login_initialize_discover_read(self) -> None:
        """Both real users can discover and read; role-based writes remain untested."""
        counts = components.ComponentTests()
        counts.credentials = self.credentials
        # This is a REST read through our own tunnel, not a new issue.
        from checks.test_components import JIRA, request

        status, _, body = request(JIRA + "/rest/api/2/search?jql=project%20%3D%20TEST&maxResults=1",
                                  headers=counts.jira_header())
        self.assertEqual(status, 200)
        before = json.loads(body)["total"]
        for user in ("analyst", "viewer"):
            with self.subTest(user=user):
                token = login(user, self.credentials[user])["access_token"]
                status, headers, value = initialize(token)
                self.assertEqual(status, 200)
                self.assertIn("result", value)
                session = headers.get("Mcp-Session-Id")
                status, _, _ = rpc("notifications/initialized", token=token, session=session)
                self.assertIn(status, (200, 202, 204))
                status, _, value = rpc("tools/list", token=token, session=session, params={})
                self.assertEqual(status, 200)
                names = {tool["name"] for tool in value["result"]["tools"]}
                self.assertIn("jira_searchJiraIssuesUsingJql", names)
                self.assertIn("jira_getJiraIssue", names)
                self.assertFalse(any("create" in name.lower() for name in names))
                status, _, value = rpc("tools/call", token=token, session=session, params={
                    "name": "jira_searchJiraIssuesUsingJql",
                    "arguments": {"jql": "project = TEST", "maxResults": 1}})
                self.assertEqual(status, 200)
                result = value["result"]
                self.assertFalse(result.get("isError", False))
                payloads = [json.loads(item["text"]) for item in result.get("content", [])
                            if item.get("type") == "text"]
                self.assertTrue(any(isinstance(item, dict) and "issues" in item and "total" in item
                                    and not item.get("error") for item in payloads))
        status, _, body = request(JIRA + "/rest/api/2/search?jql=project%20%3D%20TEST&maxResults=1",
                                  headers=counts.jira_header())
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["total"], before)

    def test_expired_token_denied_on_existing_session(self) -> None:
        """An initialized session does not extend an expired access token."""
        token = login("analyst", self.credentials["analyst"])["access_token"]
        claims = verify(token, "identity-demo-mcp")
        status, headers, _ = initialize(token)
        self.assertEqual(status, 200)
        session = headers.get("Mcp-Session-Id")
        rpc("notifications/initialized", token=token, session=session)
        self.prime_backend(token, session)
        time.sleep(max(0, claims["exp"] - time.time()) + 3)
        status, _, _ = rpc("tools/list", token=token,
                           session=headers.get("Mcp-Session-Id"), params={})
        self.assertIn(status, (401, 403))
        status, _, _ = rpc("tools/call", token=token,
                           session=headers.get("Mcp-Session-Id"), params={
                               "name": "jira_searchJiraIssuesUsingJql",
                               "arguments": {"jql": "project = TEST", "maxResults": 1}})
        self.assertIn(status, (401, 403))
