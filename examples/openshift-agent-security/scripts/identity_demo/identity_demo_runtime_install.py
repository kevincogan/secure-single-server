#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Create only new, owned namespace resources from the pinned runtime render.

Development experiment, not a Helm-managed release or cluster-grant installer.
Default mode prepares private artifacts and server dry-runs them. --create is
explicit; collisions abort rather than patching or replacing existing resources.
"""

from __future__ import annotations

import argparse
import base64
from copy import deepcopy
from datetime import datetime
from ipaddress import ip_address
import json
import os
from pathlib import Path
import tomllib
from urllib.parse import urlparse

from identity_demo_lab import LABELS, oc
from identity_demo_runtime import guard, NAMESPACE
from deployment_profile import in_source_checkout

SERVER = "https://api.cluster.example.test:443"
NAME = "fixture-openshell"
KINDS = {"ServiceAccount", "Secret", "ConfigMap", "Role", "RoleBinding",
         "Service", "StatefulSet", "NetworkPolicy", "Job"}
GENERATED = ("fixture-openshell-server-tls", "fixture-openshell-client-tls",
             "fixture-openshell-jwt-keys")
GATEWAY_IMAGE = "sha256:ea14aa4db0980fab4769fb6b5509ac42ae3dc8495e645b1ba1fe1ada49892fa6"


def decode_objects(source: str) -> list[dict]:
    """Handle both oc's concatenated JSON and a Kubernetes List."""
    decoder, items = json.JSONDecoder(), []
    while source.strip():
        value, end = decoder.raw_decode(source.lstrip())
        source = source.lstrip()[end:]
        items.extend(value["items"] if value.get("kind") == "List" else [value])
    return items


def normalize(items: list[dict], issuer: str, router: dict) -> list[dict]:
    """Constrain scope, label resources and retain restricted SCC/TLS settings."""
    result = deepcopy(items)
    for item in result:
        meta = item["metadata"]
        if (item["kind"] not in KINDS or not meta["name"].startswith(NAME)
                or meta.get("namespace", NAMESPACE) != NAMESPACE):
            raise ValueError("Unexpected kind, name or namespace in runtime render")
        meta["namespace"] = NAMESPACE
        meta.setdefault("labels", {}).update(LABELS)
        meta["labels"]["app.kubernetes.io/managed-by"] = "identity-demo-runtime"
        if item["kind"] == "Service" and item["spec"].get("type", "ClusterIP") != "ClusterIP":
            raise ValueError("Only internal runtime Services are allowed")
        if item["kind"] == "RoleBinding":
            if (item["roleRef"]["kind"] != "Role"
                    or not item["roleRef"]["name"].startswith(NAME)
                    or any(s.get("kind") != "ServiceAccount" or s.get("namespace") != NAMESPACE
                           or not s.get("name", "").startswith(NAME) for s in item["subjects"])):
                raise ValueError("Only owned namespaced Role bindings are allowed")
        for key in list(meta.get("annotations", {})):
            if key.startswith("helm.sh/hook"):
                del meta["annotations"][key]
        if item["kind"] in ("StatefulSet", "Job"):
            template = item["spec"]["template"]
            template["metadata"].setdefault("labels", {}).update(LABELS)
            pod = template["spec"]
            pod.setdefault("securityContext", {}).update({
                "runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}})
            if item["kind"] == "StatefulSet":
                if item["spec"]["replicas"] != 1:
                    raise ValueError("One bounded gateway replica required")
                if pod["containers"][0]["image"].split("@")[-1] != GATEWAY_IMAGE:
                    raise ValueError("Pinned gateway image required")
                pod.setdefault("hostAliases", []).append({"ip": router["ip"],
                    "hostnames": [urlparse(issuer).hostname]})
                for claim in item["spec"]["volumeClaimTemplates"]:
                    claim["metadata"].setdefault("labels", {}).update(LABELS)
                    claim["spec"]["storageClassName"] = "gp3-csi"
            else:
                for container in pod["containers"]:
                    container["securityContext"]["runAsNonRoot"] = True
                    container["resources"] = {"requests": {"cpu": "100m", "memory": "128Mi"},
                                              "limits": {"cpu": "500m", "memory": "256Mi"}}
    configs = [x for x in result if x["kind"] == "ConfigMap" and x["metadata"]["name"] == NAME + "-config"]
    if len(configs) != 1:
        raise ValueError("Exact runtime configuration required")
    config = tomllib.loads(configs[0]["data"]["gateway.toml"])["openshell"]
    gateway = config["gateway"]
    if (gateway.get("disable_tls") is not False
            or gateway["auth"].get("allow_unauthenticated_users") is not False
            or gateway["oidc"].get("issuer") != issuer
            or gateway["oidc"].get("audience") != "identity-demo-runtime"):
        raise ValueError("Secured fixture management configuration required")
    return result


def network_policy(ips: list[str], ports: list[int], router: dict) -> dict:
    """Permit only runtime/certgen API traffic and HTTPS to the ingress router."""
    destinations = [{"ipBlock": {"cidr": str(ip_address(value)) +
                     ("/32" if ip_address(value).version == 4 else "/128")}} for value in ips]
    if not destinations or not router["selector"] or not set(ports) <= {443, 6443}:
        raise ValueError("Exact API destinations and router selector required")
    return {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": NAME + "-api-issuer-egress", "namespace": NAMESPACE,
                     "labels": LABELS.copy()},
        "spec": {"podSelector": {"matchLabels": {**LABELS,
                 "app.kubernetes.io/instance": NAME}}, "policyTypes": ["Egress"],
            "egress": [{"to": destinations,
                        "ports": [{"port": p, "protocol": "TCP"} for p in sorted(set(ports))]},
                       {"to": [{"namespaceSelector": {"matchLabels": {
                           "kubernetes.io/metadata.name": "openshift-ingress"}},
                           "podSelector": {"matchLabels": router["selector"]}}],
                        "ports": [{"port": 443, "protocol": "TCP"}]}]}}


def assert_absent(args: argparse.Namespace, kind: str, name: str) -> None:
    """Refuse any collision, including owned resources, before creation."""
    if oc(args, "get", kind, name, "-n", NAMESPACE, "--ignore-not-found", "-o", "name").strip():
        raise ValueError("Existing runtime resource: creation refused")


def private_json(path: Path, value: dict) -> None:
    """Write an artifact without overwriting existing keys or following symlinks."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream)


def finalize_certificates(args: argparse.Namespace, directory: Path) -> None:
    """Verify our successful generator and label only its newly created Secrets."""
    oc(args, "wait", "job/" + NAME + "-certgen", "-n", NAMESPACE,
       "--for=condition=complete", "--timeout=60s")
    job = json.loads(oc(args, "get", "job", NAME + "-certgen", "-n", NAMESPACE, "-o", "json"))
    if job.get("status", {}).get("succeeded") != 1 or any(
            job["metadata"].get("labels", {}).get(k) != v for k, v in LABELS.items()):
        raise ValueError("Successful owned certificate generator required")
    created = datetime.fromisoformat(job["metadata"]["creationTimestamp"].replace("Z", "+00:00"))
    values = []
    for name in GENERATED:
        secret = json.loads(oc(args, "get", "secret", name, "-n", NAMESPACE, "-o", "json"))
        meta = secret["metadata"]
        if (datetime.fromisoformat(meta["creationTimestamp"].replace("Z", "+00:00")) < created
                or any(meta.get("labels", {}).get(k) not in (None, v) for k, v in LABELS.items())):
            raise ValueError("Unexpected generated Secret ownership or creation time")
        values.append(secret)
    if values[0]["data"]["ca.crt"] != values[1]["data"]["ca.crt"]:
        raise ValueError("Matching generated CA chains required")
    for secret in values:
        meta = secret["metadata"]
        patch = [{"op": "test", "path": "/metadata/uid", "value": meta["uid"]},
                 {"op": "test", "path": "/metadata/resourceVersion", "value": meta["resourceVersion"]},
                 {"op": "add", "path": "/metadata/labels", "value": {**meta.get("labels", {}), **LABELS}}]
        oc(args, "patch", "secret", meta["name"], "-n", NAMESPACE, "--type=json", "-p", json.dumps(patch))
    fd = os.open(directory / "runtime-gateway-ca.crt", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(base64.b64decode(values[0]["data"]["ca.crt"]))


def run(args: argparse.Namespace) -> dict:
    """Prepare and optionally create only the explicitly selected namespace."""
    args.namespace = NAMESPACE
    if args.expected_server != SERVER:
        raise ValueError("Only the agreed configured development cluster is supported")
    _, credentials, base = guard(args)
    directory = Path(args.artifact_dir)
    source = Path(args.rendered_json)
    repo = Path(__file__).resolve().parents[2]
    for path in (directory, source):
        if path.is_symlink() or in_source_checkout(path, repo) or path.stat().st_mode & 0o077:
            raise ValueError("Private artifacts outside Git required")
    crd = json.loads(oc(args, "get", "crd", "sandboxes.agents.x-k8s.io", "-o", "json"))
    if not any(v["served"] and v["name"] == "v1beta1" for v in crd["spec"]["versions"]):
        raise ValueError("Supported Sandbox API required")
    oc(args, "get", "storageclass", "gp3-csi", "-o", "name")
    router_service = json.loads(oc(args, "get", "service", "router-internal-default",
                                    "-n", "openshift-ingress", "-o", "json"))
    router = {"ip": router_service["spec"]["clusterIP"],
              "selector": router_service["spec"]["selector"]}
    ip_address(router["ip"])
    api = json.loads(oc(args, "get", "service", "kubernetes", "-n", "default", "-o", "json"))
    endpoints = json.loads(oc(args, "get", "endpointslice", "-n", "default", "-l",
                              "kubernetes.io/service-name=kubernetes", "-o", "json"))
    ips = [api["spec"]["clusterIP"]] + [ip for s in endpoints["items"]
           for e in s["endpoints"] for ip in e["addresses"]]
    ports = [p["port"] for p in api["spec"]["ports"]] + [p["port"]
             for s in endpoints["items"] for p in s["ports"]]
    items = normalize(decode_objects(source.read_text()), base + "/realms/identity-demo", router)
    policy = network_policy(sorted(set(ips)), ports, router)
    items.insert(0, policy)
    for item in items:
        assert_absent(args, item["kind"], item["metadata"]["name"])
    for name in GENERATED:
        assert_absent(args, "secret", name)
    assert_absent(args, "pvc", "openshell-data-fixture-openshell-0")
    # Persist the reviewed render once: do not regenerate its encryption key on retries.
    artifact = directory / "runtime-owned-resources.json"
    payload = {"apiVersion": "v1", "kind": "List", "items": items}
    private_json(artifact, payload)
    # Creation dependencies: SAs before bindings; network access before certificate Job.
    order = {"NetworkPolicy": 0, "ServiceAccount": 1, "Role": 2, "RoleBinding": 3,
             "Secret": 4, "ConfigMap": 5, "Service": 6, "Job": 7, "StatefulSet": 8}
    items.sort(key=lambda x: order[x["kind"]])
    # Bindings cannot be checked against roles that dry-run has not persisted.
    for item in items:
        if item["kind"] != "RoleBinding":
            oc(args, "create", "--dry-run=server", "-n", NAMESPACE, "-f", "-", payload=item)
    if args.create:
        for item in items:
            if item["kind"] == "RoleBinding":
                oc(args, "create", "--dry-run=server", "-n", NAMESPACE, "-f", "-", payload=item)
            oc(args, "create", "--field-manager=identity-demo-runtime", "-n", NAMESPACE,
               "-f", "-", payload=item)
        finalize_certificates(args, directory)
    return {"namespace": NAMESPACE, "server_dry_run_nonbinding_objects_passed": True,
            "binding_validation_passed": args.create,
            "namespaced_objects_created": len(items) if args.create else 0,
            "cluster_resources_changed": False, "helm_managed_release": False,
            "artifact": str(artifact), "gateway_or_cve_acceptance_claimed": False}


def main() -> None:
    """Keep failure output free of rendered credentials or raw server bodies."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("kubeconfig", "expected-server", "credentials-file", "rendered-json", "artifact-dir"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--create", action="store_true")
    args = parser.parse_args()
    try:
        print(json.dumps(run(args), indent=2))
    except Exception as error:
        print(json.dumps({"completed": False, "failure_kind": type(error).__name__,
                          "details_withheld": True}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
