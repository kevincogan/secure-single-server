#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Render an exact discovery registration; never apply cluster resources."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from identity_demo_spire_network import command, LABELS, NAMESPACE, SERVER
from identity_demo_spire_registration import CLASS, read
from deployment_profile import active_profile
from deployment_profile import in_source_checkout

NAME = "identity-demo-oidc-discovery"
IMAGE = (
    "registry.redhat.io/zero-trust-workload-identity-manager/"
    "spiffe-spire-oidc-discovery-provider-rhel9@sha256:"
    "1be96c9a470d16f2300b45d1d826c37c235dc192ed6fe33ed934ea4661392378"
)
ISSUER = "https://spire-spiffe-oidc-discovery-provider." + NAMESPACE + ".svc:8443"


def prepare(kubeconfig: str) -> dict:
    """Match admitted Pod, owning controllers, image and actual PSAT parent."""
    if command(kubeconfig, "config", "view", "--minify", "-o",
               "jsonpath={.clusters[0].cluster.server}") != SERVER:
        raise ValueError("Unexpected API server")
    for kind, name, namespace in (
        ("namespace", NAMESPACE, None),
        ("deployment", NAME, NAMESPACE),
        ("serviceaccount", NAME, NAMESPACE),
    ):
        value = read(kubeconfig, kind, name, namespace)
        if any(value["metadata"].get("labels", {}).get(k) != v for k, v in LABELS.items()):
            raise ValueError("Owned discovery resources required")
        if kind == "deployment":
            deployment = value
    foundation = read(kubeconfig, "zerotrustworkloadidentitymanager", "cluster")
    server = read(kubeconfig, "spireserver", "cluster")
    if (any(v["metadata"].get("labels", {}).get("identity-demo-owner") != active_profile().owner
            for v in (foundation, server)) or server["spec"]["jwtIssuer"] != ISSUER):
        raise ValueError("Owned foundation and existing issuer contract required")
    # The operator operand would introduce a broad registration. Refuse mixing it
    # with this development deployment even if it uses the same trust domain.
    if json.loads(command(kubeconfig, "get", "spireoidcdiscoveryproviders", "-o", "json"))["items"]:
        raise ValueError("Operator discovery operand must remain absent")
    pods = json.loads(command(kubeconfig, "get", "pods", "-n", NAMESPACE,
                              "-l", "app=" + NAME, "-o", "json"))["items"]
    active = [p for p in pods if not p["metadata"].get("deletionTimestamp")]
    if len(active) != 1:
        raise ValueError("Exactly one current discovery Pod required")
    pod = active[0]
    if any(pod["metadata"].get("labels", {}).get(k) != v for k, v in LABELS.items()):
        raise ValueError("Owned discovery Pod required")
    references = [o for o in pod["metadata"].get("ownerReferences", [])
                  if o.get("controller") and o["kind"] == "ReplicaSet"]
    if len(references) != 1:
        raise ValueError("Deployment-owned Pod required")
    replica = read(kubeconfig, "replicaset", references[0]["name"], NAMESPACE)
    if (replica["metadata"]["uid"] != references[0]["uid"]
            or not any(o.get("controller") and o.get("kind") == "Deployment"
                       and o.get("uid") == deployment["metadata"]["uid"]
                       for o in replica["metadata"].get("ownerReferences", []))):
        raise ValueError("Discovery controller ownership mismatch")
    spec = pod["spec"]
    if (spec["serviceAccountName"] != NAME or spec.get("automountServiceAccountToken") is not False
            or len(spec["containers"]) != 1 or spec.get("initContainers")
            or spec["containers"][0]["name"] != "discovery"
            or spec["containers"][0]["image"] != IMAGE
            or pod["metadata"].get("annotations", {}).get("openshift.io/scc") != "restricted-v2"
            or not any(v.get("csi", {}).get("driver") == "csi.spiffe.io"
                       and v["csi"].get("readOnly") for v in spec["volumes"])):
        raise ValueError("Restricted standard-binary credential holder required")
    statuses = pod.get("status", {}).get("containerStatuses", [])
    if (len(statuses) != 1 or statuses[0]["name"] != "discovery"
            or "running" not in statuses[0].get("state", {})
            or "@sha256:" not in statuses[0].get("imageID", "")):
        raise ValueError("Running discovery binary with resolved image digest required")
    node = read(kubeconfig, "node", spec["nodeName"])
    domain = foundation["spec"]["trustDomain"]
    parent = (f"spiffe://{domain}/spire/agent/k8s_psat/"
              f"{foundation['spec']['clusterName']}/{node['metadata']['uid']}")
    agents = json.loads(command(kubeconfig, "-n", NAMESPACE, "exec", "spire-server-0",
                                "-c", "spire-server", "--", "/spire-server",
                                "agent", "list", "-output", "json"))["agents"]
    if not any("spiffe://" + a["id"]["trust_domain"] + a["id"]["path"] == parent
               and a["attestation_type"] == "k8s_psat" and not a["banned"] for a in agents):
        raise ValueError("Actual PSAT-attested discovery parent required")
    selectors = ["ns:" + NAMESPACE, "sa:" + NAME,
                 "pod-uid:" + pod["metadata"]["uid"], "container-name:discovery",
                 "container-image:" + statuses[0]["imageID"]]
    return {"apiVersion": "spire.spiffe.io/v1alpha1", "kind": "ClusterStaticEntry",
            "metadata": {"name": NAME, "labels": LABELS.copy()},
            "spec": {"className": CLASS, "spiffeID": f"spiffe://{domain}/oidc/discovery",
                     "parentID": parent, "selectors": ["k8s:" + s for s in selectors]}}


def main() -> None:
    """Write a private manifest without replacing artifacts or changing the lab."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        path = args.output
        if (path.is_symlink() or path.parent.stat().st_mode & 0o077
                or in_source_checkout(path)):
            raise ValueError("Private output directory outside repository required")
        value = prepare(args.kubeconfig)
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
            json.dump(value, stream, indent=2)
        print(json.dumps({"prepared": True, "registrations": 1, "applied": False}))
    except Exception as error:
        print(json.dumps({"prepared": False, "failure_kind": type(error).__name__,
                          "details_withheld": True}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
