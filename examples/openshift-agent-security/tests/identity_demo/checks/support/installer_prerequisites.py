# SPDX-License-Identifier: Apache-2.0
"""Shared installer prerequisites test setup; contains no collected tests."""
from deployment_profile import LEGACY
import identity_demo_setup as setup

def source():
    def item(kind, name, **fields):
        return {
            "apiVersion": setup.APIS[kind],
            "kind": kind,
            "metadata": {
                "name": name,
                "namespace": LEGACY.core_namespace,
                "labels": dict(LEGACY.labels),
            },
            **fields,
        }

    application = [
        item("ServiceAccount", "fixture-openshell", automountServiceAccountToken=False),
        item(
            "Role",
            "fixture-openshell-sandbox",
            rules=[
                {
                    "apiGroups": ["agents.x-k8s.io"],
                    "resources": ["sandboxes"],
                    "verbs": ["get", "create"],
                }
            ],
        ),
        item("Gateway", "fixture-mcp", spec={}),
        item("HTTPRoute", "fixture-jira", spec={}),
        item("HTTPRoute", "fixture-mcp-bound", spec={}),
        # A private application Secret may exist in the input bundle. It must
        # never appear in the public administrator review artifact.
        item("Secret", "fixture-private-input", data={"private": "SYNTHETIC"}),
    ]
    bundle = {
        "schema_version": 2,
        "expected_server": LEGACY.expected_server,
        "installation_profile": LEGACY.to_dict(),
        "objects": application,
        "native_build_contract_matches": True,
    }
    artifacts = {
        "schema_version": 1,
        "native_build_contract": LEGACY.native_build_contract,
        "images": {
            role: "registry.example/" + role + "@sha256:" + "a" * 64
            for role in (
                "jira_runtime",
                "keycloak_management",
                "keycloak_exchange",
                "openshell_gateway",
                "openshell_supervisor",
            )
        },
    }
    return bundle, artifacts
