# SPDX-License-Identifier: Apache-2.0
"""Offline checks for the namespace-only installer; no Kubernetes calls."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts" / "identity_demo"))
import identity_demo_runtime_install as installer  # noqa: E402
import identity_demo_runtime as runtime  # noqa: E402


class RuntimeInstallTests(unittest.TestCase):
    """Scope and network guards must refuse expansion of the experiment."""

    def test_concatenated_and_list_json(self) -> None:
        """oc emits both forms depending on input representation."""
        value = {"kind": "Service", "metadata": {"name": "fixture-openshell"}}
        self.assertEqual(installer.decode_objects(json.dumps(value) + '\n' + json.dumps(value)), [value, value])
        self.assertEqual(installer.decode_objects(json.dumps({"kind": "List", "items": [value]})), [value])

    def test_cluster_resource_refused(self) -> None:
        """A render must never add a cluster-scoped resource."""
        with self.assertRaises(ValueError):
            installer.normalize([{"kind": "ClusterRole", "metadata": {"name": "fixture-openshell"}}],
                                "https://issuer.invalid", {})

    def test_cross_namespace_refused(self) -> None:
        """No rendered resource may escape the owned namespace."""
        with self.assertRaises(ValueError):
            installer.normalize([{"kind": "Service", "metadata": {"name": "fixture-openshell",
                                  "namespace": "shared"}}], "https://issuer.invalid", {})

    def test_exact_network_destinations_and_selected_pods(self) -> None:
        """API access is exact-address; router access is namespace AND selector."""
        value = installer.network_policy(["10.0.0.1"], [6443, 443], {"selector": {"router": "default"}})
        spec = value["spec"]
        self.assertEqual(spec["podSelector"]["matchLabels"]["identity-demo-owner"], "demo-team")
        self.assertEqual(spec["egress"][0]["to"], [{"ipBlock": {"cidr": "10.0.0.1/32"}}])
        peer = spec["egress"][1]["to"][0]
        self.assertIn("namespaceSelector", peer)
        self.assertIn("podSelector", peer)

    def test_missing_router_selector_refused(self) -> None:
        """Empty selectors must not broaden issuer egress."""
        with self.assertRaises(ValueError):
            installer.network_policy(["10.0.0.1"], [443], {"selector": {}})

    def test_required_grants_are_minimal(self) -> None:
        """CPU/default-class experiments need TokenReview and this namespace."""
        self.assertEqual(runtime.GRANTS, (("create", "tokenreviews.authentication.k8s.io"),
                                        ("get", "namespaces/demo-core")))


if __name__ == "__main__":
    unittest.main()
