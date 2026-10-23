#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Render namespace-only API/DNS networking from the selected lab's live endpoints."""

from __future__ import annotations

import argparse
from copy import deepcopy
from ipaddress import ip_address, ip_network
import json
import os
from pathlib import Path
import subprocess
from deployment_profile import active_profile


SERVER = active_profile().expected_server
NAMESPACE = active_profile().identity_namespace
LABELS = active_profile().labels


def command(kubeconfig: str, *parts: str) -> str:
    """Run a bounded read without exposing API errors or credentials."""
    result = subprocess.run(["oc", "--kubeconfig=" + kubeconfig, *parts],
                            capture_output=True, text=True, timeout=45)
    if result.returncode:
        raise RuntimeError("Required cluster read failed; details withheld")
    return result.stdout


def render(kubeconfig: str) -> dict:
    """Constrain policy generation to the owned namespace on the agreed lab."""
    server = command(kubeconfig, "config", "view", "--minify", "-o",
                     "jsonpath={.clusters[0].cluster.server}")
    if server != SERVER:
        raise ValueError("Unexpected API server")
    namespace = json.loads(command(kubeconfig, "get", "namespace", NAMESPACE,
                                   "-o", "json"))
    if any(namespace["metadata"].get("labels", {}).get(k) != v
           for k, v in LABELS.items()):
        raise ValueError("Owned namespace required")
    service = json.loads(command(kubeconfig, "get", "service", "kubernetes",
                                 "-n", "default", "-o", "json"))
    slices = json.loads(command(kubeconfig, "get", "endpointslices.discovery.k8s.io",
                                "-n", "default", "-l",
                                "kubernetes.io/service-name=kubernetes", "-o", "json"))
    addresses = set(service["spec"].get("clusterIPs", []))
    ports = {443}
    for item in slices["items"]:
        if item["addressType"] not in ("IPv4", "IPv6"):
            raise ValueError("IP API endpoints required")
        for endpoint in item["endpoints"]:
            if endpoint.get("conditions", {}).get("ready") is not False:
                addresses.update(endpoint["addresses"])
        ports.update(p["port"] for p in item["ports"] if p.get("port"))
    if not slices["items"] or not addresses or not ports <= {443, 6443}:
        raise ValueError("Recognized live API endpoints required")
    destinations = [{"ipBlock": {"cidr": str(ip_address(value)) +
                     ("/32" if ip_address(value).version == 4 else "/128")}}
                    for value in sorted(addresses)]
    return {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": "identity-demo-api-dns-egress",
                         "namespace": NAMESPACE, "labels": LABELS.copy()},
            "spec": {"podSelector": {}, "policyTypes": ["Egress"], "egress": [
                {"to": destinations, "ports": [{"port": p, "protocol": "TCP"}
                                                for p in sorted(ports)]},
                {"to": [{"namespaceSelector": {"matchLabels": {
                    "kubernetes.io/metadata.name": "openshift-dns"}}}],
                 "ports": [{"port": p, "protocol": protocol}
                           for p in (53, 5353) for protocol in ("UDP", "TCP")]},
                {"to": [{"podSelector": {}}]}
            ]}}


def render_operands(kubeconfig: str) -> dict:
    """Render the additional owned-namespace allowances for native operands."""
    render(kubeconfig)  # Validate the cluster, ownership and API endpoints first.
    nodes = json.loads(command(kubeconfig, "get", "nodes", "-l",
                               "node-role.kubernetes.io/worker", "-o", "json"))
    addresses = {a["address"] for n in nodes["items"]
                 for a in n["status"]["addresses"] if a["type"] == "InternalIP"}
    if not addresses:
        raise ValueError("Actual worker kubelet addresses required")
    destinations = [{"ipBlock": {"cidr": str(ip_address(value)) +
                     ("/32" if ip_address(value).version == 4 else "/128")}}
                    for value in sorted(addresses)]
    specs = [
        ("identity-demo-same-namespace-ingress", {"podSelector": {},
         "policyTypes": ["Ingress"], "ingress": [{"from": [{"podSelector": {}}]}]}),
        ("identity-demo-kubelet-egress", {"podSelector": {"matchLabels": {
         "app.kubernetes.io/name": "spire-agent"}}, "policyTypes": ["Egress"],
         "egress": [{"to": destinations, "ports": [{"port": 10250, "protocol": "TCP"}]}]}),
        # Hosted API server sources cannot be matched by a stable Pod selector.
        # This internal service exposes only the TLS admission webhook on 9443.
        ("identity-demo-webhook-ingress", {"podSelector": {"matchLabels": {
         "app.kubernetes.io/name": "spire-server"}}, "policyTypes": ["Ingress"],
         "ingress": [{"ports": [{"port": 9443, "protocol": "TCP"}]}]}),
    ]
    return {"apiVersion": "v1", "kind": "List", "items": [
        {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
         "metadata": {"name": name, "namespace": NAMESPACE, "labels": LABELS.copy()},
         "spec": spec} for name, spec in specs]}



def kubelet_policy_patch(current: dict, addresses: set[str], owner: str) -> list[dict]:
    """Add current worker IPs to one exact owned kubelet rule; never widen other traffic."""
    metadata = current["metadata"]
    labels = metadata.get("labels", {})
    if (metadata.get("name") != "identity-demo-kubelet-egress"
            or metadata.get("namespace") != NAMESPACE
            or labels.get("identity-demo-owner") != owner
            or labels.get("app.kubernetes.io/part-of") != "identity-demo-preflight"):
        raise ValueError("Exact owned SPIRE kubelet policy required")
    spec = current["spec"]
    if (set(spec) != {"podSelector", "policyTypes", "egress"}
            or spec["podSelector"] != {"matchLabels": {"app.kubernetes.io/name": "spire-agent"}}
            or spec["policyTypes"] != ["Egress"] or len(spec["egress"]) != 1):
        raise ValueError("Existing SPIRE-only egress contract required")
    rule = spec["egress"][0]
    if set(rule) != {"to", "ports"} or rule["ports"] != [{"port": 10250, "protocol": "TCP"}]:
        raise ValueError("Exact kubelet TCP port required")
    before = rule["to"]
    for target in before:
        if set(target) != {"ipBlock"} or set(target["ipBlock"]) != {"cidr"}:
            raise ValueError("Only exact existing IP destinations may be retained")
        network = ip_network(target["ipBlock"]["cidr"], strict=True)
        if network.prefixlen != network.max_prefixlen:
            raise ValueError("Host-only kubelet destinations required")
    if not addresses:
        raise ValueError("Current worker InternalIPs required")
    additions = [{"ipBlock": {"cidr": str(ip_address(value)) +
                  ("/32" if ip_address(value).version == 4 else "/128")}}
                 for value in sorted(addresses)]
    desired = deepcopy(before)
    desired.extend(target for target in additions if target not in before)
    if desired == before:
        return []
    return [{"op": "test", "path": "/metadata/uid", "value": metadata["uid"]},
            {"op": "test", "path": "/metadata/resourceVersion", "value": metadata["resourceVersion"]},
            {"op": "test", "path": "/spec", "value": spec},
            {"op": "replace", "path": "/spec/egress/0/to", "value": desired}]


def observe_kubelet_coverage(kubeconfig: str) -> tuple[dict, list[dict]]:
    """Read current node coverage only; never change policy during readiness checks."""
    if command(kubeconfig, "config", "view", "--minify", "-o",
               "jsonpath={.clusters[0].cluster.server}") != SERVER:
        raise ValueError("Unexpected API server")
    namespace = json.loads(command(kubeconfig, "get", "namespace", NAMESPACE, "-o", "json"))
    if namespace["metadata"].get("labels", {}).get("identity-demo-owner") != active_profile().owner:
        raise ValueError("Owned identity namespace required")
    current = json.loads(command(kubeconfig, "get", "networkpolicy", "identity-demo-kubelet-egress",
                                 "-n", NAMESPACE, "-o", "json"))
    nodes = json.loads(command(kubeconfig, "get", "nodes", "-l", "node-role.kubernetes.io/worker", "-o", "json"))
    addresses = {a["address"] for n in nodes["items"] for a in n["status"]["addresses"] if a["type"] == "InternalIP"}
    return current, kubelet_policy_patch(current, addresses, active_profile().owner)


def kubelet_coverage_current(kubeconfig: str) -> bool:
    """Report missing exact worker hosts without applying or broadening any rule."""
    _, patch = observe_kubelet_coverage(kubeconfig)
    return not patch


def reconcile_kubelets(kubeconfig: str, output: Path, *, apply: bool = False) -> dict:
    """Reconcile node churn with exact ownership, server admission and durable receipts."""
    current, patch = observe_kubelet_coverage(kubeconfig)
    if not patch:
        return {"applied": False, "coverage_current": True, "added_destinations": 0}
    with os.fdopen(os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
        json.dump({"before": current, "patch": patch, "purpose": "existing SPIRE kubelet dependency on current workers"}, stream)
    arguments = ["oc", "--kubeconfig=" + kubeconfig, "-n", NAMESPACE, "patch", "networkpolicy",
                 "identity-demo-kubelet-egress", "--type=json", "-p", json.dumps(patch), "-o", "json"]
    def execute(dry_run: bool) -> dict:
        result = subprocess.run(arguments + (["--dry-run=server"] if dry_run else []),
                                capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise RuntimeError("Owned kubelet reconciliation failed; preserve receipt and review")
        value = json.loads(result.stdout)
        if value["metadata"]["uid"] != current["metadata"]["uid"] or value["spec"]["egress"][0]["to"] != patch[-1]["value"]:
            raise RuntimeError("Kubelet policy update verification failed")
        return value
    execute(True)
    observed = execute(False) if apply else None
    result = {"applied": apply, "coverage_current": apply,
              "added_destinations": len(patch[-1]["value"]) - len(current["spec"]["egress"][0]["to"]),
              "tls_verification_preserved": True, "other_rules_changed": False}
    with os.fdopen(os.open(output.with_suffix('.result.json'), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
        json.dump({"summary": result, "observed": observed}, stream)
    return result


def main() -> None:
    """Write a private manifest without applying it or replacing an artifact."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--phase", choices=("bootstrap", "operands", "kubelet-reconcile"), default="bootstrap")
    parser.add_argument("--apply", action="store_true", help="Only reconcile the exact existing owned kubelet policy")
    args = parser.parse_args()
    try:
        if args.phase == "kubelet-reconcile":
            print(json.dumps(reconcile_kubelets(args.kubeconfig, args.output, apply=args.apply)))
            return
        if args.apply:
            raise ValueError("Apply is permitted only for exact kubelet reconciliation")
        value = render_operands(args.kubeconfig) if args.phase == "operands" else render(args.kubeconfig)
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, indent=2)
        print(json.dumps({"prepared": True, "namespace": NAMESPACE,
                          "applied": False, "credentials_in_output": False}))
    except Exception as error:
        print(json.dumps({"prepared": False, "failure_kind": type(error).__name__,
                          "details_withheld": True}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
