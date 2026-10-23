#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Render the two fixed, pre-provisioned OpenShell operator workspaces.

Rendering is pure. Apply only after ownership/collision checks and retain exact
creation receipts; this module never changes an existing cluster resource.
"""

from __future__ import annotations

from copy import deepcopy
import json
import tomllib

from identity_demo_lab import LABELS
from deployment_profile import active_profile, LEGACY

PLATFORM = active_profile().core_namespace
WORKSPACES = (active_profile().triage_namespace, active_profile().reader_namespace)
ACCOUNT = "fixture-openshell-sandbox"
GATEWAY_SUBJECT = {
    "kind": "ServiceAccount",
    "name": "fixture-openshell",
    "namespace": PLATFORM,
}


def object_for(kind: str, name: str, namespace: str | None = None) -> dict:
    """Build only names within the agreed owned workspace scope."""
    api = {
        "Role": "rbac.authorization.k8s.io/v1",
        "RoleBinding": "rbac.authorization.k8s.io/v1",
        "ClusterRole": "rbac.authorization.k8s.io/v1",
        "ClusterRoleBinding": "rbac.authorization.k8s.io/v1",
        "NetworkPolicy": "networking.k8s.io/v1",
    }.get(kind, "v1")
    metadata = {"name": name, "labels": dict(LABELS)}
    if namespace:
        metadata["namespace"] = namespace
    return {"apiVersion": api, "kind": kind, "metadata": metadata}


def render(runtime_rules: list[dict]) -> list[dict]:
    """Reuse namespaced runtime rules; add no workload API privileges."""
    if any(
        "*" in rule.get(key, [])
        for rule in runtime_rules
        for key in ("apiGroups", "resources", "verbs")
    ):
        raise ValueError("Wildcard runtime privileges refused")
    if not runtime_rules or any(
        set(rule["apiGroups"]) - {"", "agents.x-k8s.io", "networking.k8s.io"}
        for rule in runtime_rules
    ):
        raise ValueError("Reviewed namespaced runtime rules required")
    items = []
    gateway_peer = {
        "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": PLATFORM}},
        "podSelector": {
            "matchLabels": {
                "app.kubernetes.io/instance": "fixture-openshell",
                "app.kubernetes.io/name": "openshell",
            }
        },
    }
    for namespace in WORKSPACES:
        ns = object_for("Namespace", namespace)
        ns["metadata"]["labels"].update(
            {
                "pod-security.kubernetes.io/enforce": "restricted",
                "pod-security.kubernetes.io/audit": "restricted",
                "pod-security.kubernetes.io/warn": "restricted",
            }
        )
        account = object_for("ServiceAccount", ACCOUNT, namespace)
        account["automountServiceAccountToken"] = False
        role = object_for("Role", "identity-demo-runtime", namespace)
        role["rules"] = deepcopy(runtime_rules)
        binding = object_for("RoleBinding", "identity-demo-runtime", namespace)
        binding.update(
            {
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "Role",
                    "name": "identity-demo-runtime",
                },
                "subjects": [deepcopy(GATEWAY_SUBJECT)],
            }
        )
        deny = object_for("NetworkPolicy", "identity-demo-default-deny", namespace)
        deny["spec"] = {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}
        ssh = object_for("NetworkPolicy", "identity-demo-gateway-ssh", namespace)
        ssh["spec"] = {
            "podSelector": {
                "matchLabels": {
                    "openshell.ai/boundary-role": "supervisor",
                    "openshell.ai/gateway-id": active_profile().gateway_id,
                }
            },
            "policyTypes": ["Ingress"],
            "ingress": [
                {"from": [gateway_peer], "ports": [{"port": 2222, "protocol": "TCP"}]}
            ],
        }
        # Cross-project pull access to the two owned patched image streams only.
        pull_role = object_for("Role", "identity-demo-pull-" + namespace, PLATFORM)
        pull_role["rules"] = [
            {
                "apiGroups": ["image.openshift.io"],
                "resources": ["imagestreams/layers"],
                "resourceNames": [
                    "fixture-openshell-sender",
                    "fixture-openshell-subject-fix",
                ],
                "verbs": ["get"],
            }
        ]
        pull = object_for("RoleBinding", "identity-demo-pull-" + namespace, PLATFORM)
        pull.update(
            {
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "Role",
                    "name": pull_role["metadata"]["name"],
                },
                "subjects": [
                    {"kind": "ServiceAccount", "name": ACCOUNT, "namespace": namespace}
                ],
            }
        )
        items.extend([ns, account, role, binding, deny, ssh])
        if active_profile() == LEGACY:
            items.extend([pull_role, pull])
        # Other installations supply registry access for their actual pinned
        # artifacts; legacy ImageStream names are not portable permissions.
    # Native operator mode uses a cluster-wide Sandbox lookup/watch. K8s RBAC
    # cannot constrain a list/watch to labels or a set of namespaces. This grant
    # contains no cross-namespace mutation, Pod access or Secret access.
    cluster_role = ("identity-demo-workspace-reader" if active_profile().installation_id == "identity-demo"
                    else "identity-demo-" + active_profile().installation_id + "-workspace-reader")
    role = object_for("ClusterRole", cluster_role)
    role["rules"] = [
        {
            "apiGroups": ["agents.x-k8s.io"],
            "resources": ["sandboxes"],
            "verbs": ["list", "watch"],
        },
        {
            "apiGroups": [""],
            "resources": ["namespaces"],
            "resourceNames": list(WORKSPACES),
            "verbs": ["get"],
        },
    ]
    binding = object_for("ClusterRoleBinding", cluster_role)
    binding.update(
        {
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": role["metadata"]["name"],
            },
            "subjects": [deepcopy(GATEWAY_SUBJECT)],
        }
    )
    ca_role = object_for("Role", "identity-demo-workspace-ca", PLATFORM)
    ca_role["rules"] = [
        {
            "apiGroups": [""],
            "resources": ["secrets"],
            "resourceNames": ["fixture-openshell-client-tls"],
            "verbs": ["get"],
        }
    ]
    ca_binding = object_for("RoleBinding", "identity-demo-workspace-ca", PLATFORM)
    ca_binding.update(
        {
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Role",
                "name": ca_role["metadata"]["name"],
            },
            "subjects": [deepcopy(GATEWAY_SUBJECT)],
        }
    )
    network = object_for("NetworkPolicy", "identity-demo-workspace-runtime", PLATFORM)
    peers = [
        {
            "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": ns}},
            "podSelector": {
                "matchLabels": {
                    "openshell.ai/gateway-id": active_profile().gateway_id,
                    "openshell.ai/boundary-role": "supervisor",
                }
            },
        }
        for ns in WORKSPACES
    ]
    network["spec"] = {
        "podSelector": gateway_peer["podSelector"],
        "policyTypes": ["Ingress", "Egress"],
        "egress": [{"to": peers, "ports": [{"port": 2222, "protocol": "TCP"}]}],
        "ingress": [{"from": peers, "ports": [{"port": 8080, "protocol": "TCP"}]}],
    }
    bound = object_for("NetworkPolicy", "identity-demo-workspace-mcp", PLATFORM)
    bound["spec"] = {
        "podSelector": {
            "matchLabels": {"gateway.networking.k8s.io/gateway-name": "fixture-mcp"}
        },
        "policyTypes": ["Ingress"],
        "ingress": [{"from": peers, "ports": [{"port": 8443, "protocol": "TCP"}]}],
    }
    issuer = object_for("NetworkPolicy", "identity-demo-workspace-issuer", PLATFORM)
    issuer["spec"] = {
        "podSelector": {"matchLabels": {"app": "fixture-keycloak-upstream"}},
        "policyTypes": ["Ingress"],
        "ingress": [{"from": peers, "ports": [{"port": 8443, "protocol": "TCP"}]}],
    }
    items.extend([role, binding, ca_role, ca_binding, network, bound, issuer])
    return items


def operator_config(config: dict, statefulset: dict) -> tuple[dict, dict]:
    """Prepare a guarded mode transition and explicit file-based allowlist."""
    if (
        config["metadata"]["name"] != "fixture-openshell-config"
        or statefulset["metadata"]["name"] != "fixture-openshell"
    ):
        raise ValueError("Exact owned gateway required")
    for value in (config, statefulset):
        if value["metadata"].get("namespace") != PLATFORM or any(
            value["metadata"].get("labels", {}).get(k) != v for k, v in LABELS.items()
        ):
            raise ValueError("Owned gateway boundary required")
    original = config["data"]["gateway.toml"]
    driver = tomllib.loads(original)["openshell"]["drivers"]["kubernetes"]
    if (
        driver["workspace_mode"] != "shared"
        or driver["service_account_name"] != ACCOUNT
        or driver.get("allow_driver_config") is not False
    ):
        raise ValueError("Accepted shared baseline required")
    start = original.index("[openshell.drivers.kubernetes]")
    end = original.find("\n[", start + 1)
    end = len(original) if end < 0 else end
    section = original[start:end]
    if section.count('workspace_mode = "shared"') != 1:
        raise ValueError("Exact workspace mode field required")
    section = section.replace(
        'workspace_mode = "shared"',
        'workspace_mode = "operator"\noperator_namespace_file = "/etc/openshell/workspaces/namespaces.json"',
    )
    desired = deepcopy(config)
    desired["data"]["gateway.toml"] = original[:start] + section + original[end:]
    desired["data"]["namespaces.json"] = json.dumps(list(WORKSPACES))
    parsed = tomllib.loads(desired["data"]["gateway.toml"])
    baseline = tomllib.loads(original)
    baseline["openshell"]["drivers"]["kubernetes"].update(
        {
            "workspace_mode": "operator",
            "operator_namespace_file": "/etc/openshell/workspaces/namespaces.json",
        }
    )
    if parsed != baseline:
        raise ValueError("Unexpected runtime configuration change")
    deployment = deepcopy(statefulset)
    mounts = deployment["spec"]["template"]["spec"]["containers"][0]["volumeMounts"]
    if any(m["mountPath"].startswith("/etc/openshell/workspaces") for m in mounts):
        raise ValueError("Workspace mount collision")
    mounts.append(
        {
            "name": "gateway-config",
            "mountPath": "/etc/openshell/workspaces",
            "readOnly": True,
        }
    )
    return desired, deployment
