#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Apply the explicitly authorized two-rule grant to our runtime SA only."""

from __future__ import annotations

import argparse
import json

from identity_demo_lab import LABELS, oc
from identity_demo_runtime import guard, NAMESPACE
from deployment_profile import active_profile

PROFILE = active_profile()
NAME = "fixture-openshell-node-reader-" + NAMESPACE
SERVER = PROFILE.expected_server
RULES = [{"apiGroups": ["authentication.k8s.io"], "resources": ["tokenreviews"], "verbs": ["create"]},
         {"apiGroups": [""], "resources": ["namespaces"], "resourceNames": [NAMESPACE], "verbs": ["get"]}]


def desired() -> tuple[dict, dict]:
    """Construct the exact reviewed role and one-ServiceAccount binding."""
    metadata = {"name": NAME, "labels": {**LABELS, "app.kubernetes.io/managed-by": "identity-demo-runtime"}}
    role = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
            "metadata": metadata, "rules": RULES}
    binding = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
        "metadata": metadata, "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": NAME},
        "subjects": [{"kind": "ServiceAccount", "name": "fixture-openshell", "namespace": NAMESPACE}]}
    return role, binding


def check_existing(value: dict, expected: dict) -> None:
    """Refuse ownership collisions and any existing broader or different grant."""
    if any(value["metadata"].get("labels", {}).get(k) != v for k, v in LABELS.items()):
        raise ValueError("Unowned cluster resource refused")
    for key in ("rules", "roleRef", "subjects"):
        if value.get(key) != expected.get(key):
            raise ValueError("Different existing grant refused")
    if value.get("aggregationRule"):
        raise ValueError("Aggregated permissions refused")


def run(args: argparse.Namespace) -> dict:
    """Create only absent exact grants, with live ownership checks and dry-run."""
    args.namespace = NAMESPACE
    if args.expected_server != SERVER:
        raise ValueError("Agreed development cluster required")
    guard(args)
    for kind, name in (("serviceaccount", "fixture-openshell"), ("statefulset", "fixture-openshell")):
        value = json.loads(oc(args, "get", kind, name, "-n", NAMESPACE, "-o", "json"))
        if any(value["metadata"].get("labels", {}).get(k) != v for k, v in LABELS.items()):
            raise ValueError("Owned runtime required")
    items = desired()
    existing = []
    # Inspect both names before creating either resource.
    for item in items:
        value = oc(args, "get", item["kind"], NAME, "--ignore-not-found", "-o", "json")
        current = json.loads(value) if value.strip() else None
        if current:
            check_existing(current, item)
        existing.append(current)
    created = []
    for item, current in zip(items, existing):
        if current:
            continue
        if item["kind"] == "ClusterRoleBinding" and not args.create and not existing[0]:
            continue  # The binding's role does not exist until explicitly created.
        oc(args, "create", "--dry-run=server", "-f", "-", payload=item)
        if args.create:
            result = json.loads(oc(args, "create", "--field-manager=identity-demo-runtime", "-f", "-", "-o", "json", payload=item))
            check_existing(result, item)
            created.append({"kind": item["kind"], "name": NAME, "uid": result["metadata"]["uid"]})
    return {"namespace": NAMESPACE, "created": created, "create_requested": args.create,
            "binding_validation_pending": not args.create and not existing[0],
            "rules": RULES, "subjects": items[1]["subjects"], "shared_resources_modified": False}


def main() -> None:
    """Print sanitized grant details, never raw credentials or API failures."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("kubeconfig", "expected-server", "credentials-file"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--create", action="store_true")
    try:
        print(json.dumps(run(parser.parse_args()), indent=2))
    except Exception as error:
        print(json.dumps({"completed": False, "failure_kind": type(error).__name__, "details_withheld": True}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
