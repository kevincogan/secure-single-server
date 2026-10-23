# SPDX-License-Identifier: Apache-2.0
"""Offline ownership and security checks for the disposable SVID experiment."""

from __future__ import annotations

import unittest

import probe_spiffe_exchange as probe


class SpiffeExchangePreparationTests(unittest.TestCase):
    """Prevent the issuer probe from becoming a privileged platform installation."""

    def test_pod_has_no_host_or_api_access(self) -> None:
        """Only ordinary bounded namespace containers may be created."""
        value = probe.pod("-agent", probe.AGENT_IMAGE, "/opt/spire/bin/spire-agent",
                          ["run"], [], [])
        spec = value["spec"]
        self.assertFalse(spec["automountServiceAccountToken"])
        self.assertEqual(spec["activeDeadlineSeconds"], 1800)
        self.assertFalse(spec.get("hostPID", False))
        self.assertFalse(spec.get("hostNetwork", False))
        self.assertEqual(spec["securityContext"]["seccompProfile"]["type"], "RuntimeDefault")
        container = spec["containers"][0]
        self.assertFalse(container["securityContext"]["allowPrivilegeEscalation"])
        self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
        self.assertEqual(container["securityContext"]["capabilities"]["drop"], ["ALL"])
        self.assertIn("limits", container["resources"])

    def test_objects_are_explicitly_owned(self) -> None:
        """Cleanup must distinguish this experiment from retained fixtures."""
        value = probe.item("ConfigMap", "-test")
        self.assertEqual(value["metadata"]["namespace"], "demo-core")
        self.assertEqual(value["metadata"]["labels"]["identity-demo-owner"], "demo-team")
        self.assertEqual(value["metadata"]["labels"]["identity-demo-experiment"], probe.EXPERIMENT)

    def test_federated_clients_have_no_secret_fallback(self) -> None:
        """Both requesting identities use built-in exact-subject SPIFFE authentication."""
        for subject in (probe.GATEWAY, probe.SANDBOX, probe.OTHER):
            value = probe.federated_client(subject, probe.MCP)
            self.assertEqual(value["clientAuthenticatorType"], "federated-jwt")
            self.assertNotIn("secret", value)
            self.assertFalse(value["serviceAccountsEnabled"])
            self.assertEqual(value["attributes"]["jwt.credential.sub"], subject)
            self.assertEqual(value["attributes"]["jwt.credential.issuer"], probe.PROVIDER)
            self.assertEqual(value["defaultClientScopes"], ["basic"])

    def test_login_stays_real_pkce(self) -> None:
        """Do not replace human login with service credentials or password grants."""
        value = probe.federated_client(probe.UI, probe.GATEWAY)
        self.assertTrue(value["publicClient"])
        self.assertTrue(value["standardFlowEnabled"])
        self.assertFalse(value["directAccessGrantsEnabled"])
        self.assertEqual(value["attributes"]["pkce.code.challenge.method"], "S256")

    def test_upstream_images_are_immutable(self) -> None:
        """A disposable upstream test is pinned, and is separate from vendor deployment."""
        for image in (probe.AGENT_IMAGE, probe.SERVER_IMAGE):
            self.assertIn("@sha256:", image)
            self.assertEqual(len(image.rsplit(":", 1)[1]), 64)

    def test_assertion_type_matches_keycloak(self) -> None:
        """Use the supported SPIFFE assertion type rather than generic self-signed JWT."""
        self.assertEqual(probe.ASSERTION_TYPE,
                         "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe")
