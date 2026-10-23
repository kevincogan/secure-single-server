#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Rehearse synthetic realm recovery before changing the owned Keycloak fixture.

Creates a temporary Pod with a dedicated persistent database and no public Route.
The TLS rehearsal uses an internal Service. Only the explicit promotion phase
changes the exact owned Keycloak Deployment, after the HTTPS recovery probe passes.
Private exports are not
production backups and do not preserve signing keys or existing sessions.
"""

from __future__ import annotations
from deployment_profile import active_profile

import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
import time
from typing import Any

from identity_demo_runtime import guard, NAMESPACE
from identity_demo_spire_network import LABELS, SERVER
from deployment_profile import in_source_checkout

PREFIX = "fixture-keycloak-recovery"
POD = PREFIX + "-probe"
CA = "fixture-keycloak-service-ca"
INFRA_NAMESPACE = "demo-identity"
IMAGE = ("registry.redhat.io/rhbk/keycloak-rhel9@sha256:"
         "b55a3fdf5c836cca9d6b754dd27adbd8de28a27ca46e7d205ceb6c0d7ae35ab9")
LOCAL_PORT = 18780
TLS_SERVICE = PREFIX + "-tls"
TLS_SECRET = PREFIX + "-tls"
TLS_HOST = TLS_SERVICE + "." + NAMESPACE + ".svc"


def command(args: argparse.Namespace, *parts: str, value: Any = None) -> str:
    """Bound cluster operations and withhold raw output/errors from tool logs."""
    from identity_demo_worker_lease import assert_current
    assert_current()
    result = subprocess.run(["oc", "--kubeconfig=" + args.kubeconfig, *parts],
        input=json.dumps(value) if value is not None else None,
        capture_output=True, text=True, timeout=45)
    if result.returncode:
        raise RuntimeError("Owned recovery operation failed: " + parts[0])
    return result.stdout


def write_private(path: Path, value: Any) -> None:
    """Create private state without replacing existing artifacts."""
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
        json.dump(value, stream, indent=2)


def inputs(args: argparse.Namespace) -> tuple[Path, dict, dict]:
    """Check cluster/resource ownership and require private prepared inputs."""
    args.namespace = NAMESPACE
    if args.expected_server != SERVER:
        raise ValueError("Agreed development cluster required")
    guard(args)
    directory = Path(args.workspace_dir)
    if (directory.is_symlink() or not directory.is_dir() or directory.stat().st_mode & 0o077
            or in_source_checkout(directory)):
        raise ValueError("Private recovery directory outside Git required")
    for name in ("keycloak-recovery-realm.private-json", "keycloak-recovery-summary.json"):
        path = directory / name
        if path.is_symlink() or path.stat().st_mode & 0o077:
            raise ValueError("Private prepared recovery inputs required")
    summary = json.loads((directory / "keycloak-recovery-summary.json").read_text())
    if (summary.get("prepared") is not True or summary.get("human_ids_and_passwords_verified") is not True
            or summary.get("masked_values_remaining") is not False):
        raise ValueError("Verified synthetic recovery input required")
    realm = json.loads((directory / "keycloak-recovery-realm.private-json").read_text())
    if realm["realm"] != "identity-demo" or "**********" in json.dumps(realm):
        raise ValueError("Unmasked owned synthetic realm required")
    namespace = json.loads(command(args, "get", "namespace", INFRA_NAMESPACE, "-o", "json"))
    if any(namespace["metadata"].get("labels", {}).get(k) != v for k, v in LABELS.items()):
        raise ValueError("Owned infrastructure namespace required")
    original = json.loads(command(args, "get", "deployment", "fixture-keycloak",
                                  "-n", NAMESPACE, "-o", "json"))
    if original["spec"]["template"]["spec"]["containers"][0]["image"] != IMAGE:
        raise ValueError("Pinned fixture image required")
    return directory, realm, original


def resource(api: str, kind: str, name: str, namespace: str = NAMESPACE) -> dict:
    """Identify only our new resources with deterministic names and labels."""
    return {"apiVersion": api, "kind": kind,
            "metadata": {"name": name, "namespace": namespace, "labels": LABELS.copy()}}


def manifests(realm: dict, original: dict) -> list[dict]:
    """Keep the rehearsal out of the existing Keycloak Service's selector."""
    ca = resource("v1", "ConfigMap", CA)
    ca["metadata"]["annotations"] = {"service.beta.openshift.io/inject-cabundle": "true"}
    secret = resource("v1", "Secret", PREFIX)
    secret.update(type="Opaque", stringData={"realm.json": json.dumps(realm)})
    pvc = resource("v1", "PersistentVolumeClaim", PREFIX + "-data")
    pvc["spec"] = {"accessModes": ["ReadWriteOnce"], "storageClassName": "gp3-csi",
                   "resources": {"requests": {"storage": "1Gi"}}}
    pod = resource("v1", "Pod", POD)
    pod["metadata"]["labels"]["app"] = POD
    pod["metadata"]["annotations"] = {"openshift.io/required-scc": "restricted-v2"}
    spec = copy.deepcopy(original["spec"]["template"]["spec"])
    spec.update(restartPolicy="Never", activeDeadlineSeconds=1800)
    container = spec["containers"][0]
    # The original public Route remains pointed at the original Deployment.
    for env in container["env"]:
        if env["name"] == "KC_HOSTNAME":
            env["value"] = f"http://127.0.0.1:{LOCAL_PORT}"
    container["env"].extend([
        {"name": "KC_TRUSTSTORE_PATHS", "value": "/etc/keycloak/service-ca/service-ca.crt"},
        {"name": "KC_TLS_HOSTNAME_VERIFIER", "value": "DEFAULT"},
        {"name": "KC_LOG_LEVEL", "value": "info,org.keycloak.broker.spiffe:debug,org.keycloak.keys:debug"},
    ])
    spec["volumes"] = [
        {"name": "realm", "secret": {"secretName": PREFIX,
                                     "items": [{"key": "realm.json", "path": "realm.json"}]}},
        {"name": "data", "persistentVolumeClaim": {"claimName": PREFIX + "-data"}},
        {"name": "service-ca", "configMap": {"name": CA}},
    ]
    container["volumeMounts"].append({"name": "service-ca",
                                    "mountPath": "/etc/keycloak/service-ca", "readOnly": True})
    pod["spec"] = spec
    # Both ends are narrow policies in owned namespaces; no Route or shared policy.
    ingress = resource("networking.k8s.io/v1", "NetworkPolicy", PREFIX + "-discovery-ingress", INFRA_NAMESPACE)
    ingress["spec"] = {"podSelector": {"matchLabels": {"app": "identity-demo-oidc-discovery"}},
        "policyTypes": ["Ingress"], "ingress": [{"from": [{
            "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": NAMESPACE}},
            "podSelector": {"matchLabels": {"app": POD, "identity-demo-owner": active_profile().owner}}}],
            "ports": [{"protocol": "TCP", "port": 8443}]}]}
    egress = resource("networking.k8s.io/v1", "NetworkPolicy", PREFIX + "-discovery-egress")
    egress["spec"] = {"podSelector": {"matchLabels": {"app": POD}},
        "policyTypes": ["Egress"], "egress": [{"to": [{
            "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": INFRA_NAMESPACE}},
            "podSelector": {"matchLabels": {"app": "identity-demo-oidc-discovery"}}}],
            "ports": [{"protocol": "TCP", "port": 8443}]}]}
    return [ca, secret, pvc, ingress, egress, pod]


def create(args: argparse.Namespace) -> dict:
    """Collision-check/dry-run all resources, then create and record each UID."""
    directory, realm, original = inputs(args)
    if (directory / "keycloak-recovery-created.private-json").exists():
        raise ValueError("Existing recovery ledger refused; inspect current state")
    values = manifests(realm, original)
    for value in values:
        metadata = value["metadata"]
        if command(args, "get", value["kind"], metadata["name"], "-n", metadata["namespace"],
                   "--ignore-not-found", "-o", "name").strip():
            raise ValueError("Existing recovery resource refused")
        command(args, "create", "--dry-run=server", "-f", "-", "-o", "name", value=value)
    write_private(directory / "keycloak-original-deployment.private-json", original)
    created = []
    try:
        for value in values:
            current = json.loads(command(args, "create", "-f", "-", "-o", "json", value=value))
            created.append({"kind": current["kind"], "name": current["metadata"]["name"],
                            "namespace": current["metadata"]["namespace"], "uid": current["metadata"]["uid"]})
            print(json.dumps({"created_owned_resource": created[-1]}), flush=True)
    finally:
        write_private(directory / "keycloak-recovery-created.private-json", created)
    return {"created": True, "resource_count": len(created),
            "original_deployment_changed": False, "public_route_created": False}


def ready(args: argparse.Namespace) -> dict:
    """Poll only the recorded current rehearsal Pod; never replace it on timeout."""
    directory, _, _ = inputs(args)
    entries = json.loads((directory / "keycloak-recovery-created.private-json").read_text())
    recorded = next(v for v in entries if v["kind"] == "Pod" and v["name"] == POD)
    deadline = time.monotonic() + 300
    last_notice = 0.0
    while time.monotonic() < deadline:
        current = json.loads(command(args, "get", "pod", POD, "-n", NAMESPACE, "-o", "json"))
        if (current["metadata"]["uid"] != recorded["uid"]
                or current["metadata"].get("labels", {}).get("identity-demo-owner") != active_profile().owner):
            raise ValueError("Recorded recovery Pod ownership mismatch")
        if any(c["type"] == "Ready" and c["status"] == "True"
               for c in current.get("status", {}).get("conditions", [])):
            return {"ready": True, "pod": POD, "pod_uid": recorded["uid"],
                    "scc": current["metadata"].get("annotations", {}).get("openshift.io/scc"),
                    "original_deployment_changed": False}
        states = current.get("status", {}).get("containerStatuses", [])
        if any("terminated" in s.get("state", {}) for s in states):
            raise RuntimeError("Recorded recovery process is terminal; inspect private diagnostics")
        if time.monotonic() - last_notice >= 30:
            print(json.dumps({"waiting_for_recorded_pod": POD,
                              "phase": current.get("status", {}).get("phase")}), flush=True)
            last_notice = time.monotonic()
        time.sleep(2)
    raise TimeoutError("Recovery Pod observation timed out; inspect same UID before any retry")


def tls_rehearsal(args: argparse.Namespace) -> dict:
    """Replace only a terminated recorded rehearsal with verified service TLS."""
    directory, realm, original = inputs(args)
    ledger_path = directory / "keycloak-recovery-created.private-json"
    entries = json.loads(ledger_path.read_text())
    recorded = next(v for v in entries if v["kind"] == "Pod" and v["name"] == POD)
    previous = json.loads(command(args, "get", "pod", POD, "-n", NAMESPACE, "-o", "json"))
    if (previous["metadata"]["uid"] != recorded["uid"]
            or previous["metadata"].get("labels", {}).get("identity-demo-owner") != active_profile().owner
            or previous.get("status", {}).get("phase") not in ("Failed", "Succeeded")
            or not all("terminated" in v.get("state", {})
                       for v in previous.get("status", {}).get("containerStatuses", []))):
        raise ValueError("Recorded rehearsal must be terminated before TLS replacement")
    if (directory / "keycloak-recovery-before-tls.private-json").exists():
        raise ValueError("TLS replacement already attempted; inspect ledger before retry")
    service = resource("v1", "Service", TLS_SERVICE)
    service["metadata"]["annotations"] = {
        "service.beta.openshift.io/serving-cert-secret-name": TLS_SECRET}
    service["spec"] = {"selector": {"app": POD}, "ports": [
        {"name": "https", "port": 8443, "targetPort": 8443}]}
    pod = next(v for v in manifests(realm, original) if v["kind"] == "Pod")
    container = pod["spec"]["containers"][0]
    for env in container["env"]:
        if env["name"] == "KC_HOSTNAME":
            env["value"] = f"https://{TLS_HOST}:8443"
    container["env"].extend([
        {"name": "KC_HTTPS_CERTIFICATE_FILE", "value": "/etc/keycloak/serving-tls/tls.crt"},
        {"name": "KC_HTTPS_CERTIFICATE_KEY_FILE", "value": "/etc/keycloak/serving-tls/tls.key"},
    ])
    pod["spec"]["volumes"].append({"name": "serving-tls", "secret": {"secretName": TLS_SECRET}})
    container["volumeMounts"].append({"name": "serving-tls", "mountPath": "/etc/keycloak/serving-tls",
                                    "readOnly": True})
    for kind, name in (("service", TLS_SERVICE), ("secret", TLS_SECRET)):
        if command(args, "get", kind, name, "-n", NAMESPACE, "--ignore-not-found", "-o", "name").strip():
            raise ValueError("Existing TLS rehearsal resource refused")
    admission_pod = copy.deepcopy(pod)
    del admission_pod["metadata"]["name"]
    admission_pod["metadata"]["generateName"] = POD + "-admission-"
    for value in (service, admission_pod):
        command(args, "create", "--dry-run=server", "-f", "-", "-o", "name", value=value)
    write_private(directory / "keycloak-recovery-before-tls.private-json", entries)
    created = json.loads(command(args, "create", "-f", "-", "-o", "json", value=service))
    entries.append({"kind": "Service", "name": TLS_SERVICE, "namespace": NAMESPACE,
                    "uid": created["metadata"]["uid"]})
    write_private(directory / "keycloak-recovery-tls-service.private-json", entries[-1])
    # Conditional DELETE cannot target a replacement with the same name.
    options = {"apiVersion": "v1", "kind": "DeleteOptions", "gracePeriodSeconds": 5,
               "preconditions": {"uid": recorded["uid"]}}
    command(args, "delete", "--raw", f"/api/v1/namespaces/{NAMESPACE}/pods/{POD}",
            "-f", "-", value=options)
    deadline = time.monotonic() + 60
    while command(args, "get", "pod", POD, "-n", NAMESPACE, "--ignore-not-found", "-o", "name").strip():
        if time.monotonic() > deadline:
            raise TimeoutError("Terminated rehearsal Pod deletion timed out")
        time.sleep(1)
    created = json.loads(command(args, "create", "-f", "-", "-o", "json", value=pod))
    recorded["uid"] = created["metadata"]["uid"]
    # Preserve the previous ledger above; atomically record the new exact Pod.
    temporary = directory / "keycloak-recovery-ledger-next.private-json"
    write_private(temporary, entries)
    os.replace(temporary, ledger_path)
    return {"tls_rehearsal_created": True, "pod_uid": recorded["uid"],
            "internal_service_only": True, "original_deployment_changed": False}


def promote(args: argparse.Namespace) -> dict:
    """Promote only a verified owned synthetic database and public CA mount."""
    directory, _, live = inputs(args)
    if Path(args.evidence_label).name != args.evidence_label:
        raise ValueError("Simple recovery evidence label required")
    evidence = json.loads((directory / (args.evidence_label + ".json")).read_text())
    required = {"client_inventory_and_ids", "management_client_grant",
                "management_service_identity_and_role", "actual_keycloak_internal_bundle_trust",
                "spiffe_response_signature_and_client", "pkce_identity_and_nonce:analyst",
                "pkce_identity_and_nonce:viewer", "human_permissions:analyst", "human_permissions:viewer"}
    passed = {v["case"] for v in evidence.get("cases", []) if v.get("passed") is True}
    original = json.loads((directory / "keycloak-original-deployment.private-json").read_text())
    if (not required.issubset(passed) or evidence.get("passed") is not True
            or evidence.get("rehearsal_browser_tls_verified") is not True
            or evidence.get("temporary_probe_objects_removed") is not True
            or evidence.get("original_deployment_changed") is not False
            or live["metadata"]["uid"] != original["metadata"]["uid"]
            or live["spec"] != original["spec"]):
        raise ValueError("Verified recovery and unchanged exact fixture required")
    if (directory / "keycloak-promotion-prepared.private-json").exists():
        raise ValueError("Promotion already attempted; inspect exact live state")
    ledger = json.loads((directory / "keycloak-recovery-created.private-json").read_text())
    recorded = next(v for v in ledger if v["kind"] == "Pod" and v["name"] == POD)
    rehearsal = json.loads(command(args, "get", "pod", POD, "-n", NAMESPACE, "-o", "json"))
    if (rehearsal["metadata"]["uid"] != recorded["uid"]
            or rehearsal["metadata"].get("labels", {}).get("identity-demo-owner") != active_profile().owner):
        raise ValueError("Exact owned rehearsal required")
    template = copy.deepcopy(original["spec"]["template"])
    spec = template["spec"]
    data = next(v for v in spec["volumes"] if v["name"] == "data")
    data.clear()
    data.update(name="data", persistentVolumeClaim={"claimName": PREFIX + "-data"})
    realm = next(v for v in spec["volumes"] if v["name"] == "realm")
    realm["secret"]["secretName"] = PREFIX
    spec["volumes"].append({"name": "service-ca", "configMap": {"name": CA}})
    container = spec["containers"][0]
    container["env"].extend([
        {"name": "KC_TRUSTSTORE_PATHS", "value": "/etc/keycloak/service-ca/service-ca.crt"},
        {"name": "KC_TLS_HOSTNAME_VERIFIER", "value": "DEFAULT"}])
    container["volumeMounts"].append({"name": "service-ca", "mountPath": "/etc/keycloak/service-ca",
                                    "readOnly": True})
    patch = [
        {"op": "test", "path": "/metadata/uid", "value": original["metadata"]["uid"]},
        {"op": "test", "path": "/metadata/resourceVersion", "value": live["metadata"]["resourceVersion"]},
        {"op": "test", "path": "/spec", "value": original["spec"]},
        {"op": "replace", "path": "/spec/template", "value": template},
        {"op": "add", "path": "/spec/strategy", "value": {"type": "Recreate"}},
    ]
    # Reuse only the exact already owned discovery paths. No new policy is
    # needed for this mount/storage update, and no existing policy is changed.
    policies = []
    for value in manifests({}, original):
        if value["kind"] != "NetworkPolicy":
            continue
        value = copy.deepcopy(value)
        value["metadata"]["name"] = ("identity-demo-oidc-keycloak-ingress"
            if value["metadata"]["namespace"] == INFRA_NAMESPACE else "fixture-keycloak-spire-discovery-egress")
        selector = {"app": "fixture-keycloak"}
        if value["metadata"]["namespace"] == INFRA_NAMESPACE:
            value["spec"]["ingress"][0]["from"][0]["podSelector"]["matchLabels"] = selector
        else:
            value["spec"]["podSelector"]["matchLabels"] = selector
        current = json.loads(command(args, "get", "networkpolicy", value["metadata"]["name"],
            "-n", value["metadata"]["namespace"], "-o", "json"))
        if (current["spec"] != value["spec"] or any(
                current["metadata"].get("labels", {}).get(k) != v for k, v in LABELS.items())):
            raise ValueError("Existing discovery policy ownership or contract mismatch")
        policies.append({"name": current["metadata"]["name"], "uid": current["metadata"]["uid"],
                         "namespace": current["metadata"]["namespace"], "changed": False})
    command(args, "patch", "deployment", "fixture-keycloak", "-n", NAMESPACE,
            "--dry-run=server", "--type=json", "-p", json.dumps(patch), "-o", "name")
    write_private(directory / "keycloak-promotion-prepared.private-json", {
        "original": original, "patch": patch, "verified_recovery_evidence": args.evidence_label,
        "signing_keys_and_sessions_reset": True, "synthetic_development_only": True})
    write_private(directory / "keycloak-promotion-policies.private-json", policies)
    options = {"apiVersion": "v1", "kind": "DeleteOptions", "gracePeriodSeconds": 30,
               "preconditions": {"uid": recorded["uid"]}}
    command(args, "delete", "--raw", f"/api/v1/namespaces/{NAMESPACE}/pods/{POD}", "-f", "-", value=options)
    deadline = time.monotonic() + 60
    while command(args, "get", "pod", POD, "-n", NAMESPACE, "--ignore-not-found", "-o", "name").strip():
        if time.monotonic() > deadline:
            raise TimeoutError("Rehearsal termination timed out; fixture promotion not performed")
        time.sleep(1)
    changed = json.loads(command(args, "patch", "deployment", "fixture-keycloak", "-n", NAMESPACE,
                                "--type=json", "-p", json.dumps(patch), "-o", "json"))
    write_private(directory / "keycloak-promotion-applied.private-json", {
        "deployment_uid": changed["metadata"]["uid"], "template": changed["spec"]["template"],
        "recovery_pvc": PREFIX + "-data", "signing_keys_and_sessions_reset": True})
    return {"owned_fixture_promotion_applied": True, "rehearsal_stopped": True,
            "persistent_recovery_data_retained": True, "signing_keys_and_sessions_reset": True,
            "ready_and_native_exchange_not_yet_proven": True}


def main() -> None:
    """Return only bounded status; retain credentials/exports outside Git."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("kubeconfig", "expected-server", "credentials-file", "workspace-dir"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("phase", choices=("create", "ready", "tls-rehearsal", "promote"))
    parser.add_argument("--evidence-label", default="")
    args = parser.parse_args()
    try:
        operations = {"create": create, "ready": ready, "tls-rehearsal": tls_rehearsal, "promote": promote}
        print(json.dumps(operations[args.phase](args)))
    except Exception as error:
        print(json.dumps({"completed": False, "failure_kind": type(error).__name__,
                          "details_withheld": True}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
