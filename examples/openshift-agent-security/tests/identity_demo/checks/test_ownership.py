# SPDX-License-Identifier: Apache-2.0
"""Offline refusal tests for fixture setup; never contact a cluster."""

from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[3] / "scripts" / "identity_demo"
sys.path.insert(0, str(SCRIPTS))
import identity_demo_lab as lab  # noqa: E402 -- repository-local script, not an installed package
import identity_demo_adapter as adapter  # noqa: E402 -- repository-local script
import identity_demo_adapter_tls as adapter_tls  # noqa: E402 -- repository-local script


class OwnershipTests(unittest.TestCase):
    """Our helpers must refuse unowned resources and incorrectly selected targets."""

    def setUp(self) -> None:
        """Use synthetic parameters and stub every oc call."""
        self.args = argparse.Namespace(kubeconfig="/private/config", namespace="demo-core")

    def test_tls_setup_refuses_wrong_cluster_before_writes(self) -> None:
        """Certificate/JWKS experiments cannot select the user's default cluster."""
        self.args.expected_server = "https://expected.invalid"
        with patch.object(adapter_tls, "oc", return_value="https://wrong.invalid"), \
                patch.object(adapter_tls, "apply_owned") as write, \
                patch.object(adapter_tls, "fixture_request") as issuer:
            with self.assertRaises(ValueError):
                adapter_tls.setup(self.args)
        write.assert_not_called()
        issuer.assert_not_called()

    def test_tls_setup_refuses_unowned_resource(self) -> None:
        """A matching TLS fixture name is insufficient evidence of ownership."""
        with patch.object(adapter_tls, "oc", return_value=json.dumps({"metadata": {"labels": {}}})):
            with self.assertRaises(ValueError):
                adapter_tls.owned(self.args, "service", "fixture-protected-adapter")

    def test_tls_setup_refuses_certificate_secret_collision(self) -> None:
        """A generated certificate name must not overwrite another Service's Secret."""
        self.args.expected_server = "https://expected.invalid"
        base = "https://fixture-keycloak-demo-core.example.invalid"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.json"
            path.write_text(json.dumps({"namespace": self.args.namespace, "keycloak_url": base}))
            os.chmod(path, 0o600)
            self.args.credentials_file = str(path)

            def read(args: argparse.Namespace, kind: str, name: str) -> dict:
                """Supply only the owned inputs needed before the collision check."""
                if kind == "route":
                    return {"spec": {"host": base.removeprefix("https://")}}
                if kind == "service":
                    return {"metadata": {"uid": "our-service"}}
                return {}

            replies = [self.args.expected_server, json.dumps({"ownerReferences": [
                {"kind": "Service", "uid": "another-service"}]})]
            with patch.object(adapter_tls, "owned", side_effect=read), \
                    patch.object(adapter_tls, "oc", side_effect=replies), \
                    patch.object(adapter_tls, "apply_owned") as write, \
                    patch.object(adapter_tls, "fixture_request") as issuer:
                with self.assertRaises(ValueError):
                    adapter_tls.setup(self.args)
            write.assert_not_called()
            issuer.assert_not_called()

    def test_unowned_resource_is_never_applied(self) -> None:
        """An existing object without both ownership labels cannot be changed."""
        item = lab.resource("Service", "fixture-jira", self.args.namespace)
        with patch.object(lab, "oc", return_value=json.dumps({"metadata": {"labels": {}}})) as command:
            with self.assertRaises(ValueError):
                lab.apply_owned(self.args, item)
        self.assertEqual(command.call_count, 1)
        self.assertEqual(command.call_args.args[1], "get")

    def test_cross_namespace_mutation_refused(self) -> None:
        """Even our labels do not authorize writing into another namespace."""
        item = lab.resource("Service", "fixture-jira", "other-team")
        with patch.object(lab, "oc") as command:
            with self.assertRaises(ValueError):
                lab.apply_owned(self.args, item)
        command.assert_not_called()

    def test_crd_lookup_is_qualified(self) -> None:
        """Legacy and current MCP CRDs must not be confused in ownership checks."""
        item = lab.resource("MCPServerRegistration", "fixture-jira", self.args.namespace)
        item["apiVersion"] = "mcp.kuadrant.io/v1alpha1"
        with patch.object(lab, "oc", return_value="") as command:
            lab.apply_owned(self.args, item)
        self.assertEqual(command.call_args_list[0].args[2],
                         "mcpserverregistration.mcp.kuadrant.io")

    def test_wrong_cluster_is_never_set_up(self) -> None:
        """A successful login to another API cannot select it accidentally."""
        argv = ["setup", "--kubeconfig", "/private/config", "--expected-server", "https://expected.invalid",
                "--credentials-file", "/private/credentials", "--keycloak-image", "image@sha256:pinned",
                "--jira-image", "image@sha256:pinned"]
        with patch.object(sys, "argv", argv), patch.object(lab, "oc", return_value="https://wrong.invalid"), \
                patch.object(lab, "setup") as setup:
            with self.assertRaises(ValueError):
                lab.main()
        setup.assert_not_called()

    def test_shared_namespace_is_never_set_up(self) -> None:
        """Named shared namespaces are refused before any cluster operation."""
        argv = ["setup", "--namespace", "other-team", "--kubeconfig", "/private/config",
                "--expected-server", "https://expected.invalid", "--credentials-file", "/private/credentials",
                "--keycloak-image", "image@sha256:pinned", "--jira-image", "image@sha256:pinned"]
        with patch.object(sys, "argv", argv), patch.object(lab, "oc") as command:
            with self.assertRaises(ValueError):
                lab.main()
        command.assert_not_called()


    def test_protected_adapter_wrong_cluster_refused(self) -> None:
        """New authentication fixtures must also refuse the wrong target before writes."""
        self.args.expected_server = "https://expected.invalid"
        with patch.object(adapter, "oc", return_value="https://wrong.invalid") as command, \
                patch.object(adapter, "configure_clients") as configure:
            with self.assertRaises(ValueError):
                adapter.setup(self.args)
        self.assertEqual(command.call_count, 1)
        configure.assert_not_called()

    def test_unowned_fixture_idp_client_not_updated(self) -> None:
        """A matching client ID does not authorize replacing an unowned client."""
        replies = [(200, {"access_token": "synthetic-offline-admin-token"}),
                   (200, [{"name": "mcp:read", "attributes": {"identity-demo-owner": "demo-team"}}]),
                   (200, [{"id": "unowned-client", "attributes": {}}])]
        credentials = {"keycloak_admin": "synthetic", "adapter_resource": "https://fixture.invalid/mcp",
                       "adapter_clients": {"fixture-gateway-service": "synthetic"}}
        with patch.object(adapter, "fixture_request", side_effect=replies) as request:
            with self.assertRaises(ValueError):
                adapter.configure_clients("https://fixture.invalid", credentials)
        self.assertEqual(request.call_count, 3)
        self.assertFalse(any(call.kwargs.get("method") == "PUT" for call in request.call_args_list))
