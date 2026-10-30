#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prepare exact native Pod registrations for the owned lab; never apply them."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re

from identity_demo_spire_network import command, LABELS, NAMESPACE, SERVER
from deployment_profile import active_profile, LEGACY
from deployment_artifacts import configured_native_image


WORKLOAD_NAMESPACE = active_profile().core_namespace
from provider_contract import WORKLOAD_IMAGE as CVE_IMAGE
GATEWAY_IMAGE = "ghcr.io/nvidia/openshell/gateway@sha256:ea14aa4db0980fab4769fb6b5509ac42ae3dc8495e645b1ba1fe1ada49892fa6"
SUPERVISOR_IMAGE = "ghcr.io/nvidia/openshell/supervisor@sha256:4ab2b970cdb02c7518ba4ccbbadb4861ae9a8d0b8770e5b160697f0453b0a8e4"
CLASS = "zero-trust-workload-identity-manager-spire"


def read(kubeconfig: str, kind: str, name: str, namespace: str | None = None) -> dict:
    """Read an explicitly named resource from the private cluster context."""
    scope = ["-n", namespace] if namespace else []
    return json.loads(command(kubeconfig, "get", kind, name, *scope, "-o", "json"))


def prepare(kubeconfig: str, sandbox_id: str, sandbox_name: str,
            gateway_image: str = GATEWAY_IMAGE,
            supervisor_image: str = SUPERVISOR_IMAGE, *,
            registration_name: str = "identity-demo-openshell-cve-test",
            workload_service_account: str = "fixture-openshell-sandbox",
            workload_namespace: str = WORKLOAD_NAMESPACE) -> dict:
    """Verify native ownership and select the actual attested node and Pod UID."""
    if (registration_name != "identity-demo-openshell-cve-test" and not re.fullmatch(
            r"identity-demo-step56-[a-z0-9-]{1,40}", registration_name)):
        raise ValueError("Exact owned registration name required")
    if workload_service_account not in ("fixture-openshell-sandbox", "fixture-step56-triage", "fixture-step56-reader"):
        raise ValueError("Exact owned workload ServiceAccount required")
    if workload_namespace not in active_profile().application_namespaces:
        raise ValueError("Exact owned workload namespace required")
    if workload_namespace != WORKLOAD_NAMESPACE and workload_service_account != "fixture-openshell-sandbox":
        raise ValueError("Configured native namespace ServiceAccount required")
    locked_gateway = configured_native_image("openshell_gateway")
    locked_supervisor = configured_native_image("openshell_supervisor")
    if active_profile() != LEGACY and (gateway_image != locked_gateway or supervisor_image != locked_supervisor):
        raise ValueError("Matching explicit native artifact lock required for this installation")
    if gateway_image != locked_gateway and gateway_image != GATEWAY_IMAGE and not re.fullmatch(
        r"image-registry\.openshift-image-registry\.svc:5000/" + re.escape(WORKLOAD_NAMESPACE) + r"/"
        r"fixture-openshell-subject-fix@sha256:[a-f0-9]{64}", gateway_image
    ):
        raise ValueError("Only the official gateway or exact owned pinned candidate is allowed")
    if supervisor_image != locked_supervisor and supervisor_image != SUPERVISOR_IMAGE and not re.fullmatch(
        r"image-registry\.openshift-image-registry\.svc:5000/" + re.escape(WORKLOAD_NAMESPACE) + r"/"
        r"fixture-openshell-sender@sha256:[a-f0-9]{64}", supervisor_image
    ):
        raise ValueError("Only the official supervisor or exact owned pinned candidate is allowed")
    server = command(kubeconfig, "config", "view", "--minify", "-o",
                     "jsonpath={.clusters[0].cluster.server}")
    if server != SERVER:
        raise ValueError("Unexpected API server")
    for namespace in (NAMESPACE, WORKLOAD_NAMESPACE, workload_namespace):
        resource = read(kubeconfig, "namespace", namespace)
        if any(resource["metadata"].get("labels", {}).get(k) != v
               for k, v in LABELS.items()):
            raise ValueError("Owned namespaces required")
    foundation = read(kubeconfig, "zerotrustworkloadidentitymanager.operator.openshift.io", "cluster")
    if foundation["metadata"].get("labels", {}).get("identity-demo-owner") != active_profile().owner:
        raise ValueError("Owned foundation required")
    domain = foundation["spec"]["trustDomain"]
    if domain != active_profile().trust_domain or foundation["spec"]["clusterName"] != active_profile().cluster_name:
        raise ValueError("Configured foundation identity must match the actual platform")
    resource_name = "default--" + sandbox_name if workload_namespace == WORKLOAD_NAMESPACE else sandbox_name
    sandbox = read(kubeconfig, "sandboxes.agents.x-k8s.io", resource_name, workload_namespace)
    labels = sandbox["metadata"].get("labels", {})
    if (labels.get("openshell.ai/gateway-id") != active_profile().gateway_id
            or labels.get("openshell.ai/sandbox-id") != sandbox_id
            or labels.get("openshell.ai/managed-by") != "openshell"):
        raise ValueError("Verified native sandbox required")
    gateway = read(kubeconfig, "pod", "fixture-openshell-0", WORKLOAD_NAMESPACE)
    supervisor = read(kubeconfig, "pod", "os-supervisor-" + sandbox_id, workload_namespace)
    workload = read(kubeconfig, "pod", sandbox["metadata"]["name"], workload_namespace)
    if not any(o.get("uid") == sandbox["metadata"]["uid"] and o.get("kind") == "Sandbox"
               for o in supervisor["metadata"].get("ownerReferences", [])):
        raise ValueError("Supervisor owner mismatch")
    if not any(o.get("uid") == sandbox["metadata"]["uid"] and o.get("kind") == "Sandbox"
               for o in workload["metadata"].get("ownerReferences", [])):
        raise ValueError("Workload owner mismatch")
    if (workload["spec"]["containers"][0]["image"] != CVE_IMAGE
            or workload["spec"].get("serviceAccountName") != workload_service_account
            or workload["spec"].get("automountServiceAccountToken") is not False
            or supervisor["metadata"]["labels"].get("openshell.ai/boundary-pair") != sandbox_id
            or workload["metadata"]["labels"].get("openshell.ai/boundary-pair") != sandbox_id):
        raise ValueError("Reviewed CVE boundary required")
    agents = json.loads(command(kubeconfig, "-n", NAMESPACE, "exec", "spire-server-0",
                                "-c", "spire-server", "--", "/spire-server",
                                "agent", "list", "-output", "json"))["agents"]
    entries = []
    for pod, sa, container, image, name, path in (
        (gateway, "fixture-openshell", "openshell-gateway", gateway_image,
         active_profile().gateway_registration_name, "/openshell/gateway/" + active_profile().gateway_id),
        (supervisor, "fixture-openshell-sandbox", "supervisor", supervisor_image, registration_name, "/openshell/sandbox/" + sandbox_id),
    ):
        if (pod["spec"]["serviceAccountName"] != sa
                or len(pod["spec"]["containers"]) != 1
                or pod["spec"]["containers"][0]["name"] != container
                or pod["spec"]["containers"][0]["image"] != image):
            raise ValueError("Expected native credential holder required")
        if pod is gateway and any(pod["metadata"]["labels"].get(k) != v for k, v in LABELS.items()):
            raise ValueError("Owned gateway required")
        node = read(kubeconfig, "node", pod["spec"]["nodeName"])
        parent = f"spiffe://{domain}/spire/agent/k8s_psat/{foundation['spec']['clusterName']}/{node['metadata']['uid']}"
        if not any("spiffe://" + a["id"]["trust_domain"] + a["id"]["path"] == parent
                   and a["attestation_type"] == "k8s_psat" and not a["banned"] for a in agents):
            raise ValueError("Actual PSAT-attested parent required")
        status = next(s for s in pod["status"]["containerStatuses"] if s["name"] == container)
        if not status["ready"] or "@sha256:" not in status["imageID"]:
            raise ValueError("Ready native container with resolved image digest required")
        selectors = ["ns:" + pod["metadata"]["namespace"], "sa:" + sa,
                     "pod-uid:" + pod["metadata"]["uid"], "container-name:" + container,
                     "container-image:" + status["imageID"]]
        entries.append({"apiVersion": "spire.spiffe.io/v1alpha1", "kind": "ClusterStaticEntry",
            "metadata": {"name": name, "labels": LABELS.copy()},
            "spec": {"className": CLASS, "parentID": parent, "spiffeID": "spiffe://" + domain + path,
                     "selectors": ["k8s:" + v for v in selectors],
                     "x509SVIDTTL": "2m", "jwtSVIDTTL": "2m"}})
    return {"apiVersion": "v1", "kind": "List", "items": entries}


def main() -> None:
    """Write reviewable registrations outside Git without replacing an artifact."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--sandbox-id", required=True)
    parser.add_argument("--sandbox-name", required=True)
    parser.add_argument("--gateway-image", default=GATEWAY_IMAGE,
                        help="Explicit owned digest for the approved development candidate")
    parser.add_argument("--supervisor-image", default=SUPERVISOR_IMAGE,
                        help="Explicit owned digest for the approved sender candidate")
    parser.add_argument("--registration-name", default="identity-demo-openshell-cve-test")
    parser.add_argument("--workload-service-account", default="fixture-openshell-sandbox")
    parser.add_argument("--workload-namespace", choices=active_profile().application_namespaces,
                        default=WORKLOAD_NAMESPACE)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = prepare(args.kubeconfig, args.sandbox_id, args.sandbox_name,
                        args.gateway_image, args.supervisor_image,
                        registration_name=args.registration_name,
                        workload_service_account=args.workload_service_account,
                        workload_namespace=args.workload_namespace)
        with os.fdopen(os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
            json.dump(value, stream, indent=2)
        print(json.dumps({"prepared": True, "registrations": 2, "applied": False}))
    except Exception as error:
        print(json.dumps({"prepared": False, "failure_kind": type(error).__name__, "details_withheld": True}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
