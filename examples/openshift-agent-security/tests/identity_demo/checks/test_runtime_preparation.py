# SPDX-License-Identifier: Apache-2.0
"""Offline ownership and scope checks for runtime preparation; no cluster calls."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import unittest
import pytest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts" / "identity_demo"))
import identity_demo_runtime as runtime  # noqa: E402


class RuntimePreparationTests(unittest.TestCase):
    """Preparation must preserve isolation and avoid false permission evidence."""

    def test_unowned_denial_client_refused(self) -> None:
        """The optional role-denial fixture cannot overwrite another client."""
        with patch.object(runtime, "admin_token", return_value="offline-token"), \
                patch.object(runtime, "fixture_request", return_value=(200, [{"attributes": {}}])) as request, \
                patch.object(runtime, "save_private") as save:
            with self.assertRaises(ValueError):
                runtime.prepare_management_denial(Path("/private/fixture"), {}, "https://fixture.invalid")
        self.assertEqual(request.call_count, 1)
        save.assert_not_called()

    def test_denial_client_has_no_role_assignments(self) -> None:
        """Preparing negative-test credentials never grants a management role."""
        with patch.object(runtime, "admin_token", return_value="offline-token"), \
                patch.object(runtime, "fixture_request", side_effect=[(200, []), (201, {})]) as request, \
                patch.object(runtime, "save_private"):
            runtime.prepare_management_denial(Path("/private/fixture"), {}, "https://fixture.invalid")
        self.assertEqual(request.call_count, 2)
        config = request.call_args.kwargs["value"]
        self.assertEqual(config["clientId"], runtime.DENIED_CLIENT)
        self.assertFalse(config["fullScopeAllowed"])
        self.assertEqual(config["defaultClientScopes"], [])

    def test_wrong_cluster_refused_before_issuer_access(self) -> None:
        """The default or an unrelated kubeconfig cannot select the fixture."""
        args = argparse.Namespace(namespace=runtime.NAMESPACE, kubeconfig="/private/config",
                                  expected_server="https://expected.invalid")
        with patch.object(runtime, "oc", return_value="https://wrong.invalid"), \
                patch.object(runtime, "fixture_request") as issuer:
            with self.assertRaises(ValueError):
                runtime.guard(args)
        issuer.assert_not_called()

    def test_unowned_namespace_refused(self) -> None:
        """A matching namespace name alone does not establish ownership."""
        args = argparse.Namespace(namespace=runtime.NAMESPACE, kubeconfig="/private/config",
                                  expected_server="https://expected.invalid")
        with patch.object(runtime, "oc", side_effect=[args.expected_server,
                         json.dumps({"metadata": {"labels": {}}})]):
            with self.assertRaises(ValueError):
                runtime.guard(args)

    def test_unowned_role_refused_before_configuration(self) -> None:
        """No client/role writes may follow an unowned identity collision."""
        roles = [{"name": runtime.ADMIN_ROLE, "attributes": {}}]
        with patch.object(runtime, "admin_token", return_value="offline-token"), \
                patch.object(runtime, "fixture_request", side_effect=[(200, roles), (200, [])]) as request, \
                patch.object(runtime, "save_private") as save:
            with self.assertRaises(ValueError):
                runtime.prepare_management(Path("/private/fixture"), {}, "https://fixture.invalid")
        self.assertEqual(request.call_count, 2)
        self.assertFalse(any(c.kwargs.get("method") in ("POST", "PUT") for c in request.call_args_list))
        save.assert_not_called()

    def test_unowned_client_refused(self) -> None:
        """An existing client without our marker cannot be overwritten."""
        with patch.object(runtime, "fixture_request", side_effect=[(200, []),
                         (200, [{"id": "offline-id", "attributes": {}}])]):
            with self.assertRaises(ValueError):
                runtime.inventory("https://fixture.invalid", "offline-token")

    def test_role_inventory_requests_ownership_attributes(self) -> None:
        """Keycloak's brief role response must not hide our ownership marker."""
        role = {"name": runtime.ADMIN_ROLE, "attributes": {"identity-demo-owner": ["demo-team"]}}
        with patch.object(runtime, "fixture_request", side_effect=[(200, [role]), (200, [])]) as request:
            roles, _ = runtime.inventory("https://fixture.invalid", "offline-token")
        self.assertIn(runtime.ADMIN_ROLE, roles)
        self.assertTrue(request.call_args_list[0].args[1].endswith("?briefRepresentation=false"))

    def test_owned_client_without_retained_secret_refused(self) -> None:
        """Rerunning must not silently replace a retained operator secret."""
        client = {"id": "offline-id", "attributes": {"identity-demo-owner": "demo-team"}}
        with patch.object(runtime, "admin_token", return_value="offline-token"), \
                patch.object(runtime, "inventory", return_value=({}, [client])), \
                patch.object(runtime, "save_private") as save:
            with self.assertRaises(ValueError):
                runtime.prepare_management(Path("/private/fixture"), {}, "https://fixture.invalid")
        save.assert_not_called()

    def test_management_client_has_narrow_service_grant(self) -> None:
        """The operator client cannot become a human login or general MCP grant."""
        value = runtime.client_configuration("synthetic-offline-secret")
        self.assertTrue(value["serviceAccountsEnabled"])
        for key in ("publicClient", "standardFlowEnabled", "directAccessGrantsEnabled", "fullScopeAllowed"):
            self.assertFalse(value[key])
        self.assertEqual(value["defaultClientScopes"], [])
        self.assertEqual(value["optionalClientScopes"], [])
        mapper = value["protocolMappers"][0]
        self.assertEqual(mapper["config"]["included.custom.audience"], runtime.AUDIENCE)




@pytest.mark.parametrize('stdout,expected',[('no\n','no'),('','unknown')],ids=['explicit-denial','query-failure'])
def test_permission_query_preserves_denial_vs_unknown(stdout,expected):
    """An explicit no is distinct from failed/uncertain authorization queries."""
    args=argparse.Namespace(kubeconfig='/private/config')
    with patch.object(runtime.subprocess,'run',return_value=argparse.Namespace(returncode=1,stdout=stdout)):
        assert runtime.permission(args,'get','nodes') == expected
