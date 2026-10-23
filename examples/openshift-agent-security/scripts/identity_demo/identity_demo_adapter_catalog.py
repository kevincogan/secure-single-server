#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Enable catalog-only credentials on the owned development HTTPS adapter.

Uses versioned code/trust resources, exact object preconditions and private
credential storage. Existing plain adapters, issuer, runtime and routes are not
reconfigured. Catalog rotation requires an explicit operator action; no automatic
renewal controller is introduced.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import time

from identity_demo_lab import LABELS
from identity_demo_runtime_cli import private_path
from identity_demo_runtime_grants import SERVER

from deployment_profile import active_profile

NS = active_profile().core_namespace
TRUST = "fixture-adapter-catalog-trust-v1"
DIRECTORY = Path(__file__).resolve().parents[2] / "tests/identity_demo"


def kube(args: argparse.Namespace, *words: str, payload: dict | list | None = None) -> dict:
    """Use an explicit cluster and withhold sensitive subprocess output."""
    result = subprocess.run(["oc", "--kubeconfig=" + args.kubeconfig,
        "--request-timeout=20s", *words], capture_output=True, text=True,
        input=json.dumps(payload) if payload is not None else None, timeout=30)
    if result.returncode:
        raise RuntimeError("Owned catalog configuration failed; response withheld")
    return json.loads(result.stdout) if result.stdout.strip() else {}


def owned(args: argparse.Namespace, kind: str, name: str) -> dict:
    """Require both established ownership labels before every existing-object use."""
    scope = [] if kind == "namespace" else ["-n", NS]
    value = kube(args, "get", kind, name, *scope, "-o", "json")
    if any(value["metadata"].get("labels", {}).get(k) != v for k, v in LABELS.items()):
        raise ValueError("Owned catalog resource required")
    return value


def fresh(args: argparse.Namespace, value: dict) -> dict:
    """Create unused owned names after server dry-run, never overwrite a collision."""
    meta = value["metadata"]
    existing = kube(args, "get", value["kind"], meta["name"], "-n", NS,
                    "--ignore-not-found", "-o", "json")
    if existing:
        raise ValueError("Versioned catalog resource already exists")
    kube(args, "create", "--dry-run=server", "-f", "-", "-o", "json", payload=value)
    return kube(args, "create", "-f", "-", "-o", "json", payload=value)


def resource(kind: str, name: str, data: dict) -> dict:
    """Construct a namespaced owned code or trust object."""
    return {"apiVersion": "v1", "kind": kind,
        "metadata": {"name": name, "namespace": NS, "labels": dict(LABELS)}, "data": data}


def configure(args: argparse.Namespace) -> dict:
    """Stage the opt-in adapter path without changing native identity requirements."""
    if args.expected_server != SERVER:
        raise ValueError("Exact authorized lab required")
    private_path(args.kubeconfig)
    actual = kube(args, "config", "view", "--minify", "-o", "json")
    if actual["clusters"][0]["cluster"]["server"] != SERVER:
        raise ValueError("Actual cluster mismatch")
    owned(args, "namespace", NS)
    dep = owned(args, "deployment", "fixture-protected-adapter")
    bootstrap = owned(args, "configmap", "fixture-protected-adapter")
    path = Path(args.catalog_credential_file)
    private_path(str(path.parent), directory=True)
    if path.exists() or path.is_symlink() or Path(args.receipt_file).exists():
        raise ValueError("Fresh private credential and receipt filenames required")
    private_path(str(Path(args.receipt_file).parent), directory=True)
    code = dict(bootstrap["data"])
    for name in ("start_protected_adapter.py", "adapter_auth.py", "adapter_live_auth.py", "adapter_discovery.py"):
        code[name] = (DIRECTORY / name).read_text()
    suffix = hashlib.sha256(json.dumps(code, sort_keys=True).encode()).hexdigest()[:12]
    cm_name = "fixture-adapter-catalog-code-" + suffix
    token = "discovery_" + secrets.token_urlsafe(32)
    expiry = int(time.time()) + 3_600
    digests = {hashlib.sha256(token.encode()).hexdigest(): expiry}
    trust = resource("Secret", TRUST, {"digests.json": base64.b64encode(json.dumps(digests).encode()).decode()})
    trust["type"] = "Opaque"
    # This script intentionally supports first adoption only. Rotation uses a
    # separate explicit Secret update plus bounded broker reconciliation checks.
    made: list[dict] = []
    receipt = {"namespace": NS, "deployment_before": dep, "created": made,
               "catalog_expires_at": expiry, "step4_complete": False}
    for filename, value in ((args.catalog_credential_file, {"token": token, "expires_at": expiry}),
                            (args.receipt_file, receipt)):
        with os.fdopen(os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
            json.dump(value, stream)
    for value in (resource("ConfigMap", cm_name, code), trust):
        created = fresh(args, value)
        made.append({"kind": created["kind"], "name": created["metadata"]["name"],
                     "uid": created["metadata"]["uid"]})
        Path(args.receipt_file).write_text(json.dumps(receipt))
    template = copy.deepcopy(dep["spec"]["template"])
    pod = template["spec"]
    container = next(c for c in pod["containers"] if c["name"] == "adapter-https")
    container["env"] = [e for e in container["env"] if e["name"] != "ADAPTER_DISCOVERY_DIGESTS_FILE"] + [
        {"name": "ADAPTER_DISCOVERY_DIGESTS_FILE", "value": "/catalog-trust/digests.json"}]
    for mount in container["volumeMounts"]:
        if mount["mountPath"] == "/fixtures":
            mount["name"] = "catalog-code"
    container["volumeMounts"].append({"name": "catalog-trust", "mountPath": "/catalog-trust", "readOnly": True})
    pod["volumes"] += [
        {"name": "catalog-code", "configMap": {"name": cm_name}},
        {"name": "catalog-trust", "secret": {"secretName": TRUST}},
    ]
    template["metadata"].setdefault("annotations", {})["identity-demo-catalog-code"] = suffix
    patch = [
        {"op": "test", "path": "/metadata/uid", "value": dep["metadata"]["uid"]},
        {"op": "test", "path": "/metadata/resourceVersion", "value": dep["metadata"]["resourceVersion"]},
        {"op": "test", "path": "/spec", "value": dep["spec"]},
        {"op": "replace", "path": "/spec/template", "value": template},
    ]
    kube(args, "patch", "deployment", "fixture-protected-adapter", "-n", NS,
         "--type=json", "--patch", json.dumps(patch), "--dry-run=server", "-o", "json")
    after = kube(args, "patch", "deployment", "fixture-protected-adapter", "-n", NS,
                 "--type=json", "--patch", json.dumps(patch), "-o", "json")
    receipt["deployment_after_spec"] = after["spec"]
    Path(args.receipt_file).write_text(json.dumps(receipt))
    return {"configured": True, "code_configmap": cm_name, "trust_secret": TRUST,
            "catalog_lifetime_seconds": 3_600, "automatic_rotation": False,
            "native_identity_binding_proven": False, "step4_complete": False}


class CatalogRotationDeferred(RuntimeError):
    """Both discovery slots are live; no credential or cluster mutation occurred."""

    def __init__(self, retry_at: int):
        self.retry_at = retry_at
        super().__init__('Discovery credential overlap is still active')


def rotate_or_revoke(args: argparse.Namespace) -> dict:
    """Rotate with overlap or revoke one exact credential without restarting Pods."""
    if args.expected_server != SERVER:
        raise ValueError("Exact authorized lab required")
    private_path(args.kubeconfig)
    actual = kube(args, "config", "view", "--minify", "-o", "json")
    if actual["clusters"][0]["cluster"]["server"] != SERVER:
        raise ValueError("Actual cluster mismatch")
    owned(args, "namespace", NS)
    before = owned(args, "secret", TRUST)
    keys = json.loads(base64.b64decode(before["data"]["digests.json"]))
    if not isinstance(keys, dict) or len(keys) > 2:
        raise ValueError("Bounded catalog trust required")
    receipt_path = Path(args.receipt_file)
    private_path(str(receipt_path.parent), directory=True)
    if receipt_path.exists() or receipt_path.is_symlink():
        raise ValueError("Fresh private receipt required")
    path = Path(args.catalog_credential_file)
    if args.action == "rotate":
        private_path(str(path.parent), directory=True)
        if path.exists() or path.is_symlink():
            raise ValueError("Fresh private credential filename required")
        keys = {k: v for k, v in keys.items() if type(v) is int and v > time.time()}
        if len(keys) >= 2:
            raise CatalogRotationDeferred(min(keys.values()))
        token = "discovery_" + secrets.token_urlsafe(32)
        expiry = int(time.time()) + 3_600
        keys[hashlib.sha256(token.encode()).hexdigest()] = expiry
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
            json.dump({"token": token, "expires_at": expiry}, stream)
    elif args.action == "revoke":
        credential = json.loads(private_path(str(path)).read_text())
        digest = hashlib.sha256(credential["token"].encode()).hexdigest()
        if digest not in keys:
            raise ValueError("Exact active discovery credential required for revocation")
        del keys[digest]
    else:
        raise ValueError("Explicit rotate or revoke action required")
    data = {"digests.json": base64.b64encode(json.dumps(keys).encode()).decode()}
    patch = [{"op": "test", "path": "/metadata/uid", "value": before["metadata"]["uid"]},
        {"op": "test", "path": "/metadata/resourceVersion", "value": before["metadata"]["resourceVersion"]},
        {"op": "test", "path": "/data", "value": before["data"]},
        {"op": "replace", "path": "/data", "value": data}]
    with os.fdopen(os.open(receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
        json.dump({"before": before, "action": args.action, "requested_data": data}, stream)
    after = kube(args, "patch", "secret", TRUST, "-n", NS, "--type=json",
                 "--patch", json.dumps(patch), "-o", "json")
    receipt_path.write_text(json.dumps({"before": before, "action": args.action, "after": after}))
    return {"action": args.action, "trust_updated": True, "active_credentials": len(keys),
            "projection_and_broker_reconciliation_proven": False, "automatic_rotation": False}


def update_code(args: argparse.Namespace) -> dict:
    """Replace only the opted-in HTTPS code reference using a new code snapshot."""
    if args.expected_server != SERVER:
        raise ValueError("Exact authorized lab required")
    private_path(args.kubeconfig)
    actual = kube(args, "config", "view", "--minify", "-o", "json")
    if actual["clusters"][0]["cluster"]["server"] != SERVER:
        raise ValueError("Actual cluster mismatch")
    owned(args, "namespace", NS)
    before = owned(args, "deployment", "fixture-protected-adapter")
    tls = next(c for c in before["spec"]["template"]["spec"]["containers"] if c["name"] == "adapter-https")
    if not any(e.get("name") == "ADAPTER_DISCOVERY_DIGESTS_FILE"
               and e.get("value") == "/catalog-trust/digests.json" for e in tls["env"]):
        raise ValueError("Existing opt-in catalog configuration required")
    volumes = before["spec"]["template"]["spec"]["volumes"]
    volume = next(v for v in volumes if v["name"] == "catalog-code")
    old = owned(args, "configmap", volume["configMap"]["name"])
    code = dict(old["data"])
    for name in ("start_protected_adapter.py", "adapter_auth.py", "adapter_live_auth.py", "adapter_discovery.py"):
        code[name] = (DIRECTORY / name).read_text()
    suffix = hashlib.sha256(json.dumps(code, sort_keys=True).encode()).hexdigest()[:12]
    name = "fixture-adapter-catalog-code-" + suffix
    if name == volume["configMap"]["name"]:
        return {"code_changed": False}
    receipt_path = Path(args.receipt_file)
    private_path(str(receipt_path.parent), directory=True)
    if receipt_path.exists() or receipt_path.is_symlink():
        raise ValueError("Fresh private receipt required")
    created = fresh(args, resource("ConfigMap", name, code))
    with os.fdopen(os.open(receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
        json.dump({"before": before, "created": created}, stream)
    patch = [{"op": "test", "path": "/metadata/uid", "value": before["metadata"]["uid"]},
        {"op": "test", "path": "/metadata/resourceVersion", "value": before["metadata"]["resourceVersion"]},
        {"op": "test", "path": "/spec", "value": before["spec"]},
        {"op": "replace", "path": f"/spec/template/spec/volumes/{volumes.index(volume)}/configMap/name", "value": name},
        {"op": "replace", "path": "/spec/template/metadata/annotations/identity-demo-catalog-code", "value": suffix}]
    after = kube(args, "patch", "deployment", "fixture-protected-adapter", "-n", NS,
                 "--type=json", "--patch", json.dumps(patch), "-o", "json")
    receipt_path.write_text(json.dumps({"before": before, "created": created, "after_spec": after["spec"]}))
    return {"code_changed": True, "code_configmap": name}


def main() -> None:
    """Require explicit private inputs and return only non-sensitive status."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("kubeconfig", "expected-server", "catalog-credential-file", "receipt-file"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--action", choices=("configure", "rotate", "revoke", "update-code"), default="configure")
    try:
        args = parser.parse_args()
        action = configure if args.action == "configure" else update_code if args.action == "update-code" else rotate_or_revoke
        print(json.dumps(action(args)))
    except Exception as error:
        print(json.dumps({"configured": False, "failure_kind": type(error).__name__}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
