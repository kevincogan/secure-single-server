#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Close alternate data paths only in the owned identity pilot namespace.

The old same-namespace allow is additive: exclude protected targets from it,
then give each target its required peers and ports. Preserve other fixtures.
Dry-run by default; before-state and creation receipts remain outside Git.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
import os
from pathlib import Path
from typing import Any

from deployment_profile import active_profile
from identity_demo_keycloak_recovery import command, resource, write_private
from identity_demo_lab import LABELS
from identity_demo_runtime import NAMESPACE, guard
from identity_demo_sender_trust import patch
from identity_demo_spire_network import SERVER
from deployment_profile import in_source_checkout

GATEWAY = {"gateway.networking.k8s.io/gateway-name": "fixture-mcp"}
BROKER = {"app.kubernetes.io/name": "mcp-gateway"}
ADAPTER = {"app": "fixture-protected-adapter"}
JIRA = {"app": "fixture-jira"}
SUPERVISOR = {"openshell.ai/boundary-role": "supervisor",
              "openshell.ai/gateway-id": active_profile().gateway_id}


def rule(peers: list[dict], ports: list[int], direction: str) -> dict:
    """Render same-namespace, exact Pod selectors and explicit TCP ports."""
    return {direction: [{"podSelector": {"matchLabels": p}} for p in peers],
            "ports": [{"protocol": "TCP", "port": p} for p in ports]}


def policies() -> list[dict]:
    """Allow the bound front door and private gateway/broker/adapter chain."""
    dns = {"to": [{"namespaceSelector": {"matchLabels": {
        "kubernetes.io/metadata.name": "openshift-dns"}}}],
           "ports": [{"protocol": protocol, "port": port}
                     for protocol in ("TCP", "UDP") for port in (53, 5353)]}
    matrix = [
        ("gateway", GATEWAY,
         [rule([SUPERVISOR], [8443], "from"), rule([BROKER], [8080], "from")],
         [rule([BROKER], [8080, 50051], "to"), rule([ADAPTER], [8443], "to")]),
        ("broker", BROKER, [rule([GATEWAY], [8080, 50051], "from")],
         [rule([GATEWAY], [8080], "to"), rule([ADAPTER], [8443], "to")]),
        ("adapter", ADAPTER, [rule([GATEWAY, BROKER], [8443], "from")],
         [rule([JIRA], [8080], "to")]),
        ("jira", JIRA, [rule([ADAPTER], [8080], "from")], []),
    ]
    values = []
    for name, selector, ingress, egress in matrix:
        value = resource("networking.k8s.io/v1", "NetworkPolicy", "fixture-step4-" + name + "-isolation")
        value["spec"] = {"podSelector": {"matchLabels": selector},
                         "policyTypes": ["Ingress", "Egress"],
                         "ingress": ingress, "egress": egress + [deepcopy(dns)]}
        values.append(value)
    return values


def exclude_protected(current: dict) -> dict:
    """Keep the existing fixture allowances only on their remaining targets."""
    spec = deepcopy(current["spec"])
    if spec["podSelector"] != {} or spec["ingress"] != [{"from": [{"podSelector": {}}]}]:
        raise ValueError("Unexpected namespace-wide fixture allow; review additive policy first")
    spec["podSelector"] = {"matchExpressions": [
        {"key": next(iter(GATEWAY)), "operator": "NotIn", "values": ["fixture-mcp"]},
        {"key": next(iter(BROKER)), "operator": "NotIn", "values": ["mcp-gateway"]},
        {"key": "app", "operator": "NotIn", "values": ["fixture-protected-adapter", "fixture-jira"]},
    ]}
    return spec


def apply(args: argparse.Namespace) -> dict[str, Any]:
    """Dry-run all changes before closing our namespace's broad data paths."""
    if args.expected_server != SERVER:
        raise ValueError("Exact approved lab required")
    guard(args)
    output = Path(args.output_dir)
    if (output.is_symlink() or not output.is_dir() or output.stat().st_mode & 0o077
            or in_source_checkout(output)):
        raise ValueError("Private output directory outside Git required")
    existing = []
    for name in ("fixture-isolation", "fixture-mcp-route-ingress"):
        value = json.loads(command(args, "get", "networkpolicy", name, "-n", NAMESPACE, "-o", "json"))
        if any(value["metadata"].get("labels", {}).get(k) != v for k, v in LABELS.items()):
            raise ValueError("Owned policy required")
        write_private(output / (name + ".before.private.json"), value)
        existing.append(value)
    changes = [(existing[0], exclude_protected(existing[0]))]
    route = deepcopy(existing[1]["spec"])
    if route["podSelector"] != {"matchLabels": GATEWAY}:
        raise ValueError("Exact owned gateway public ingress required")
    route["ingress"] = []
    changes.append((existing[1], route))
    for value in policies():
        name = value["metadata"]["name"]
        if command(args, "get", "networkpolicy", name, "-n", NAMESPACE,
                   "--ignore-not-found", "-o", "name").strip():
            raise ValueError("Existing isolation policy refused; review its receipt")
        command(args, "create", "--dry-run=server", "-f", "-", value=value)
    for current, desired in changes:
        command(args, "patch", "networkpolicy", current["metadata"]["name"], "-n", NAMESPACE,
                "--type=json", "--dry-run=server", "-p", json.dumps(patch(current, "spec", desired)))
    if args.apply:
        # Install permits first; then exclude targets and close router ingress.
        for value in policies():
            created = json.loads(command(args, "create", "-f", "-", "-o", "json", value=value))
            write_private(output / (value["metadata"]["name"] + ".created.private.json"), created)
        for current, desired in changes:
            command(args, "patch", "networkpolicy", current["metadata"]["name"], "-n", NAMESPACE,
                    "--type=json", "-p", json.dumps(patch(current, "spec", desired)))
    result = {"applied": args.apply, "owned_namespace_only": True,
              "broad_allow_excluded_for_protected_targets": args.apply,
              "alternate_public_http_ingress_closed": args.apply, "live_denials_required": True}
    write_private(output / "isolation.summary.json", result)
    return result


def main() -> None:
    """Apply only the bounded fixture policy changes after their server dry-run."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("kubeconfig", "expected-server", "credentials-file", "output-dir"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--namespace", default=NAMESPACE)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        print(json.dumps(apply(args)))
    except Exception as error:
        print(json.dumps({"passed": False, "failure_kind": type(error).__name__, "details_withheld": True}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
