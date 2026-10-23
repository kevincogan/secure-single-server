# SPDX-License-Identifier: Apache-2.0
"""Offline checks for the temporary issuer-only experiment configuration."""

from __future__ import annotations

import unittest

import probe_token_exchange as probe


class ExchangePreparationTests(unittest.TestCase):
    """Keep the diagnostic scoped and preserve standard issuer verification."""

    def test_public_client_requires_pkce_without_password_grants(self) -> None:
        """The new user client uses the existing real browser-login helper."""
        client = probe.configuration(probe.UI, "unused", probe.GATEWAY)
        self.assertTrue(client["publicClient"])
        self.assertTrue(client["standardFlowEnabled"])
        self.assertFalse(client["directAccessGrantsEnabled"])
        self.assertEqual(client["attributes"]["pkce.code.challenge.method"], "S256")

    def test_confidential_requester_has_no_service_account(self) -> None:
        """Issuer probing adds no generic service-account identity or broad scope."""
        client = probe.configuration(probe.GATEWAY, "synthetic", probe.SANDBOX)
        self.assertFalse(client["publicClient"])
        self.assertFalse(client["serviceAccountsEnabled"])
        self.assertFalse(client["fullScopeAllowed"])
        self.assertEqual(client["attributes"]["standard.token.exchange.enabled"], "true")

    def test_basic_scope_and_exact_next_recipient(self) -> None:
        """Retain human sub and map only the intended audience."""
        client = probe.configuration(probe.SANDBOX, "synthetic", probe.MCP)
        self.assertEqual(client["defaultClientScopes"], ["basic"])
        self.assertEqual(client["optionalClientScopes"], [])
        mappers = [v for v in client["protocolMappers"] if v["name"] == "next-recipient"]
        self.assertEqual(len(mappers), 1)
        self.assertEqual(mappers[0]["config"]["included.client.audience"], probe.MCP)

    def test_inventory_fingerprint_ignores_listing_order(self) -> None:
        """Cleanup can compare inventory without returning raw client details."""
        clients = [{"id": "b", "clientId": "two"}, {"id": "a", "clientId": "one"}]
        self.assertEqual(probe.fingerprint(clients), probe.fingerprint(list(reversed(clients))))

    def test_resources_have_no_exchange_grant(self) -> None:
        """A recipient is not automatically permitted to exchange tokens."""
        client = probe.configuration(probe.MCP, "synthetic")
        self.assertEqual(client["attributes"]["standard.token.exchange.enabled"], "false")
        self.assertEqual(client["attributes"]["identity-demo-experiment"], "step3-v2")
