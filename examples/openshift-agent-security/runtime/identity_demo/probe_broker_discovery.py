#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise disposable broker discovery with an owned HTTPS adapter credential.

This proves discovery configuration, not automatic OAuth refresh, user/workload
binding, tool-call credential injection or complete Step 4 acceptance. Tokens,
API responses and detailed status messages are retained only outside Git.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any

import jwt
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "identity_demo"))
from identity_demo_keycloak_upstream import BASE, issuer_request  # noqa: E402
from identity_demo_lab import LABELS  # noqa: E402
from identity_demo_runtime_cli import private_path  # noqa: E402
from identity_demo_runtime_grants import SERVER  # noqa: E402
from deployment_profile import active_profile  # noqa: E402

NS = active_profile().core_namespace
NAME = "fixture-credential-discovery"
AUDIENCE = "https://fixture-protected-adapter." + NS + ".svc:8443/mcp"


def write_private(path: Path, value: Any) -> None:
    """Keep private evidence immutable and refuse to overwrite a prior attempt."""
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
        stream.write(json.dumps(value, indent=2))


def kube(args: argparse.Namespace, *words: str, payload: Any = None, empty_output: Any = None, collect_dry_run: bool = False) -> dict:
    """Run bounded operations against one explicit kubeconfig without raw errors."""
    from identity_demo_worker_lease import assert_current
    assert_current()
    if collect_dry_run and '--dry-run=server' not in words:
        raise ValueError('Output collection is restricted to server dry-run')
    result = subprocess.run(
        ["oc", "--kubeconfig=" + args.kubeconfig, "--request-timeout=20s", *words],
        input=json.dumps(payload) if payload is not None else None,
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode:
        # Kubernetes error bodies can contain Secret data. Keep any diagnostic
        # only in the already validated private probe workspace.
        if getattr(args, "output_dir", None):
            directory = private_path(str(args.output_dir), directory=True)
            write_private(directory / ("kube-failure-" + str(time.time_ns()) + ".private.json"),
                          {"command": list(words), "exit": result.returncode,
                           "stdout": result.stdout, "stderr": result.stderr})
        raise RuntimeError("Discovery fixture operation failed; response withheld")
    if collect_dry_run:
        # oc create prints successive JSON objects for a multi-resource input,
        # rather than wrapping them in List. Decode every complete object;
        # malformed/trailing text must fail, never silently drop admission data.
        text, items, decoder = result.stdout.strip(), [], json.JSONDecoder()
        while text:
            value, end = decoder.raw_decode(text)
            if not isinstance(value, dict):
                raise ValueError('Structured dry-run result required')
            if value.get('kind') == 'List':
                if not isinstance(value.get('items'), list):
                    raise ValueError('Structured dry-run list required')
                items.extend(value['items'])
            else:
                items.append(value)
            text = text[end:].lstrip()
        return {'apiVersion': 'v1', 'kind': 'List', 'items': items}
    return json.loads(result.stdout) if result.stdout.strip() else (empty_output if empty_output is not None else {})


def owned(args: argparse.Namespace, kind: str, name: str) -> dict:
    """Require both ownership labels before using a fixture resource."""
    scope = [] if kind == "namespace" else ["-n", NS]
    item = kube(args, "get", kind, name, *scope, "-o", "json")
    return require_owned(item)


def require_owned(item: dict) -> dict:
    """Validate an already-read object without another cluster request."""
    if any(item["metadata"].get("labels", {}).get(k) != v for k, v in LABELS.items()):
        raise ValueError("Owned discovery fixture required")
    return item


def manifest(api: str, kind: str, name: str, spec: dict | None = None) -> dict:
    """Construct only namespaced resources within the disposable name boundary."""
    if name != NAME and not name.startswith(NAME + "-"):
        raise ValueError("Disposable discovery resource name required")
    item = {"apiVersion": api, "kind": kind,
            "metadata": {"name": name, "namespace": NS, "labels": dict(LABELS)}}
    if spec is not None:
        item["spec"] = spec
    return item


def broker_pod(args: argparse.Namespace) -> dict:
    """Follow controller UIDs from the owned extension to exactly one Ready Pod."""
    extension = owned(args, "mcpgatewayextension.mcp.kuadrant.io", "fixture-mcp")
    deployment = kube(args, "get", "deployment", "mcp-gateway", "-n", NS, "-o", "json")

    def controlled_by(item: dict, parent: dict) -> bool:
        return any(ref.get("controller") and ref.get("uid") == parent["metadata"]["uid"]
                   for ref in item["metadata"].get("ownerReferences", []))

    if not controlled_by(deployment, extension):
        raise ValueError("Broker must belong to the owned gateway extension")
    replicas = kube(args, "get", "replicasets", "-n", NS, "-o", "json")["items"]
    replica_uids = {r["metadata"]["uid"] for r in replicas if controlled_by(r, deployment)}
    pods = kube(args, "get", "pods", "-n", NS, "-o", "json")["items"]
    candidates = [p for p in pods if any(ref.get("controller")
                  and ref.get("uid") in replica_uids
                  for ref in p["metadata"].get("ownerReferences", []))
                  and not p["metadata"].get("deletionTimestamp")
                  and p.get("status", {}).get("phase") == "Running"
                  and p.get("status", {}).get("containerStatuses")
                  and all(c.get("ready") for c in p["status"]["containerStatuses"])]
    if len(candidates) != 1:
        raise ValueError("One Ready owned broker required")
    return candidates[0]


def effective_state(args: argparse.Namespace, pod: dict, output: Path, index: int) -> dict:
    """Retain raw state privately; expose only presence, timing and fixed error classes."""
    name = pod["metadata"]["name"]
    current = kube(args, "get", "pod", name, "-n", NS, "-o", "json")
    if current["metadata"]["uid"] != pod["metadata"]["uid"]:
        raise ValueError("Observed broker was replaced")
    response = subprocess.run(["oc", "--kubeconfig=" + args.kubeconfig,
        "--request-timeout=10s", "-n", NS, "exec", name, "--", "cat", "/config/config.yaml"],
        capture_output=True, text=True, timeout=20)
    if response.returncode:
        raise RuntimeError("Mounted broker configuration unavailable; response withheld")
    with os.fdopen(os.open(output / f"{args.label}.mounted-{index}.private-yaml",
                          os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
        stream.write(response.stdout)
    config = yaml.safe_load(response.stdout)
    matches = [s for s in config.get("servers", []) if NAME in s.get("name", "")]
    state: dict = {"mounted_registration_present": len(matches) == 1}
    if len(matches) == 1:
        token = matches[0].get("credential", "").removeprefix("Bearer ")
        if token:
            if token.startswith("discovery_"):
                import hmac
                expected = json.loads(private_path(args.catalog_credential_file).read_text())["token"]
                state["mounted_catalog_credential_matches"] = hmac.compare_digest(token, expected)
            else:
                state["mounted_token_remaining_seconds"] = round(
                    jwt.decode(token, options={"verify_signature": False})["exp"] - time.time(), 1)
    response = subprocess.run(["oc", "--kubeconfig=" + args.kubeconfig,
        "--request-timeout=5s", "get", "--raw",
        f"/api/v1/namespaces/{NS}/pods/{name}:8080/proxy/status"],
        capture_output=True, text=True, timeout=10)
    if response.returncode:
        write_private(output / f"{args.label}.effective-status-{index}.private-error",
                      {"stdout": response.stdout, "stderr": response.stderr})
        state["status_observation_failed"] = True
        state["status_error_categories"] = [word for word in (
            "timeout", "deadline", "Forbidden", "NotFound", "Unauthorized", "503",
        ) if word.lower() in response.stderr.lower()]
        return state
    status = json.loads(response.stdout)
    write_private(output / f"{args.label}.effective-status-{index}.private-json", status)
    matches = [s for s in status.get("servers", []) if NAME in s.get("name", "")]
    state["loaded_registration_present"] = len(matches) == 1
    if len(matches) == 1:
        server = matches[0]
        state.update(ready=server.get("ready"), tools=server.get("totalTools"))
        message = str(server.get("message", ""))
        state["error_categories"] = [word for word in (
            "401", "403", "400", "404", "TLS", "certificate", "expired", "dial",
            "deadline", "connect", "initialize", "unauthorized", "streamable", "SSE", "timeout",
        ) if word.lower() in message.lower()]
    return state
