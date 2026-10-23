#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Read-only SPIRE prerequisites on the exact owned development cluster."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import subprocess

from identity_demo_runtime import guard, NAMESPACE
from identity_demo_runtime_grants import SERVER


def query(args: argparse.Namespace, *command: str) -> dict:
    """Bound cluster reads and keep raw API errors out of the output."""
    result = subprocess.run(["oc", "--kubeconfig=" + args.kubeconfig, "get",
                             *command, "-o", "json"], capture_output=True, text=True, timeout=45)
    if result.returncode:
        raise RuntimeError("Read-only inventory unavailable")
    return json.loads(result.stdout)


def run(args: argparse.Namespace) -> dict:
    """Report availability, installed API surfaces and catalog image digests."""
    args.namespace = NAMESPACE
    if args.expected_server != SERVER:
        raise ValueError("Agreed development cluster required")
    guard(args)
    crds = query(args, "crds")["items"]
    drivers = query(args, "csidrivers")["items"]
    package = query(args, "packagemanifest", "openshift-zero-trust-workload-identity-manager",
                    "-n", "openshift-marketplace")["status"]
    channels = [{"name": c["name"], "csv": c["currentCSV"],
                 "version": c["currentCSVDesc"]["version"],
                 "related_images": c["currentCSVDesc"].get("relatedImages", [])}
                for c in package["channels"]]
    subscriptions = query(args, "subscriptions", "-A")["items"]
    namespace = query(args, "namespace", NAMESPACE)
    return {"checked_at_utc": datetime.now(timezone.utc).isoformat(), "namespace": NAMESPACE,
        "identity_crds": [v["metadata"]["name"] for v in crds
            if any(k in v["metadata"]["name"] for k in ("spire", "spiffe", "workloadidentity"))],
        "csi_drivers": [{"name": v["metadata"]["name"],
            "ephemeral_security_profile": v["metadata"].get("labels", {}).get(
                "security.openshift.io/csi-ephemeral-volume-profile"),
            "volume_lifecycle_modes": v["spec"].get("volumeLifecycleModes", [])} for v in drivers],
        "identity_subscriptions": [{"name": v["metadata"]["name"],
            "namespace": v["metadata"].get("namespace"), "package": v["spec"].get("name")}
            for v in subscriptions if any(k in v["spec"].get("name", "")
                for k in ("spire", "spiffe", "workload-identity"))],
        "catalog": {"source": package.get("catalogSource"),
                    "default_channel": package.get("defaultChannel"), "channels": channels},
        "namespace_uid_range": namespace["metadata"].get("annotations", {}).get("openshift.io/sa.scc.uid-range"),
        "namespace_pod_security_enforce": namespace["metadata"].get("labels", {}).get("pod-security.kubernetes.io/enforce"),
        "resource_quotas": [v["metadata"]["name"] for v in query(args, "resourcequota", "-n", NAMESPACE)["items"]],
        "limit_ranges": [v["metadata"]["name"] for v in query(args, "limitrange", "-n", NAMESPACE)["items"]],
        "cluster_resources_changed": False, "attestation_proven": False,
        "vendor_support_confirmed": False}


def main() -> None:
    """Print only selected public configuration and sanitized failure categories."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("kubeconfig", "expected-server", "credentials-file"):
        parser.add_argument("--" + name, required=True)
    try:
        print(json.dumps(run(parser.parse_args()), indent=2))
    except Exception as error:
        print(json.dumps({"completed": False, "failure_kind": type(error).__name__, "details_withheld": True}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
