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


def run(args: argparse.Namespace) -> dict:
    """Create a cold discovery registration, inspect it and remove exact objects."""
    if args.expected_server != SERVER or Path(args.label).name != args.label:
        raise ValueError("Exact lab and safe private evidence label required")
    if not 0 <= getattr(args, "observation_grace_seconds", 5) <= 120:
        raise ValueError("Observation grace must be bounded; token lifetime is unchanged")
    private_path(args.kubeconfig)
    output = private_path(str(args.output_dir), directory=True)
    if list(output.glob(args.label + ".*")):
        raise ValueError("Fresh private evidence label required")
    actual = kube(args, "config", "view", "--minify", "-o", "json")
    if actual["clusters"][0]["cluster"]["server"] != SERVER:
        raise ValueError("Actual cluster mismatch")
    credentials = json.loads(private_path(args.credentials_file).read_text())
    if credentials.get("namespace") != NS:
        raise ValueError("Owned fixture credentials required")
    owned(args, "namespace", NS)
    owned(args, "gateway.gateway.networking.k8s.io", "fixture-mcp")
    adapter = owned(args, "deployment", "fixture-protected-adapter")
    service = owned(args, "service", "fixture-protected-adapter")
    issuer = owned(args, "deployment", "fixture-keycloak-upstream")
    if issuer["spec"]["template"]["spec"]["containers"][0]["image"] != (
        "quay.io/keycloak/keycloak@sha256:27b3230fbabb8c9ff3c66c864cf09dcd8a41aca82e5100679d109ef0eeb05741"
    ):
        raise ValueError("Approved pinned issuer required")
    tls = next(c for c in adapter["spec"]["template"]["spec"]["containers"]
               if c["name"] == "adapter-https")
    env = {e["name"]: e.get("value") for e in tls["env"]}
    if (adapter.get("status", {}).get("readyReplicas") != 1
            or env.get("ADAPTER_ISSUER") != BASE + "/realms/identity-demo"
            or env.get("ADAPTER_RESOURCE") != AUDIENCE
            or not any(p["port"] == 8443 and p.get("name") == "https"
                       for p in service["spec"]["ports"])):
        raise ValueError("Ready approved HTTPS adapter required")
    baseline = owned(args, "mcpserverregistration.mcp.kuadrant.io", "fixture-jira")
    baseline_route = owned(args, "httproute.gateway.networking.k8s.io", "fixture-jira")
    pod = broker_pod(args)
    ca = owned(args, "configmap", "fixture-service-ca")["data"]["service-ca.crt"]
    ledger: list[dict] = []
    result: dict = {"checked_at_utc": datetime.now(timezone.utc).isoformat(),
                    "passed": False, "errors": [], "automatic_oauth_refresh_proven": False,
                    "actual_tool_credential_injection_proven": False,
                    "step4_complete": False, "step5_started": False}
    route = manifest("gateway.networking.k8s.io/v1", "HTTPRoute", NAME, {
        "parentRefs": [{"name": "fixture-mcp", "sectionName": "mcps"}],
        "hostnames": [NAME + ".fixture-mcp.local"],
        "rules": [{"matches": [{"path": {"type": "PathPrefix", "value": "/mcp"}}],
                   "backendRefs": [{"name": "fixture-protected-adapter", "port": 8443}]}],
    })
    ca_secret = manifest("v1", "Secret", NAME + "-ca")
    ca_secret["metadata"]["labels"]["mcp.kuadrant.io/secret"] = "true"
    ca_secret.update(type="Opaque", stringData={"ca.crt": ca})
    credential = manifest("v1", "Secret", NAME + "-grant")
    credential["metadata"]["labels"]["mcp.kuadrant.io/secret"] = "true"
    registration = manifest("mcp.kuadrant.io/v1alpha1", "MCPServerRegistration", NAME, {
        "targetRef": {"group": "gateway.networking.k8s.io", "kind": "HTTPRoute", "name": NAME},
        "path": "/mcp", "prefix": "credential_probe_", "state": "Enabled",
        "userSpecificList": "Disabled", "credentialRef": {"name": NAME + "-grant", "key": "token"},
        "caCertSecretRef": {"name": NAME + "-ca", "key": "ca.crt"},
        "hint": "Disposable authenticated discovery check; synthetic read-only tools",
    })

    def create(item: dict) -> dict:
        """Require an unused name and server dry-run, then retain a deletion receipt."""
        group = item["apiVersion"].split("/")[0] if "/" in item["apiVersion"] else ""
        kind = item["kind"].lower() + ("." + group if group else "")
        if kube(args, "get", kind, item["metadata"]["name"], "-n", NS,
                "--ignore-not-found", "-o", "json"):
            raise ValueError("Prior discovery object requires reconciliation")
        kube(args, "create", "--dry-run=server", "-f", "-", "-o", "json", payload=item)
        made = kube(args, "create", "-f", "-", "-o", "json", payload=item)
        ledger.append({"kind": kind, "name": made["metadata"]["name"],
                       "uid": made["metadata"]["uid"]})
        write_private(output / f"{args.label}.created-{len(ledger)}.json", made)
        return made

    try:
        # Prepare trust and routing before issuing the deliberately short-lived grant.
        create(ca_secret)
        create(route)
        started = time.time()
        catalog = getattr(args, "catalog_credential_file", None)
        if catalog:
            value = json.loads(private_path(catalog).read_text())
            token, expiry = value["token"], value["expires_at"]
            if not token.startswith("discovery_") or not 0 < expiry - time.time() <= 3_600:
                raise ValueError("Active bounded catalog-only credential required")
            result["credential_kind"] = "catalog-only"
        else:
            status, value = issuer_request(BASE, "/realms/identity-demo/protocol/openid-connect/token",
                method="POST", fields={"grant_type": "client_credentials",
                    "client_id": "fixture-gateway-service", "scope": "mcp:read",
                    "client_secret": credentials["adapter_clients"]["fixture-gateway-service"]})
            if status != 200:
                raise RuntimeError("Approved scoped discovery grant failed")
            token = value["access_token"]
            # The adapter verifies the signature. Unverified exp bounds observation only.
            expiry = jwt.decode(token, options={"verify_signature": False})["exp"]
            if not 0 < expiry - time.time() <= 31:
                raise ValueError("Expected 30-second development service grant")
            result["credential_kind"] = "short-lived service token"
        credential.update(type="Opaque", stringData={"token": "Bearer " + token})
        create(credential)
        registered = create(registration)
        observations = []
        deadline = min(expiry + args.observation_grace_seconds, started + 120) if catalog else (
            expiry + args.observation_grace_seconds)
        while time.time() < deadline:
            live = owned(args, "mcpserverregistration.mcp.kuadrant.io", NAME)
            if live["metadata"]["uid"] != registered["metadata"]["uid"]:
                raise ValueError("Discovery registration was replaced")
            state = live.get("status", {})
            tools = state.get("discoveredTools", 0)
            count = len(tools) if isinstance(tools, list) else tools
            conditions = [{k: c.get(k) for k in ("type", "status", "reason")}
                          for c in state.get("conditions", [])]
            effective = effective_state(args, pod, output, len(observations) + 1)
            observations.append({"elapsed_seconds": round(time.time() - started, 1),
                                 "tools": count, "conditions": conditions, **effective})
            write_private(output / f"{args.label}.status-{len(observations)}.json", live)
            if count == 2 and any(c.get("type") == "Ready" and c.get("status") == "True"
                                 for c in conditions):
                result["cold_discovery_proven"] = True
                break
            time.sleep(1)
        result["observations"] = observations
        generated = kube(args, "get", "secret", "mcp-gateway-config", "-n", NS, "-o", "json")
        write_private(output / (args.label + ".broker-config.private-json"), generated)
        config = yaml.safe_load(base64.b64decode(generated["data"]["config.yaml"]))
        matches = [s for s in config.get("servers", []) if NAME in s.get("name", "")]
        result["configuration_count"] = len(matches)
        if len(matches) == 1:
            server = matches[0]
            result["generated_endpoint"] = server.get("url")
            result["verified_https_url_configured"] = server.get("url") == (
                "https://" + active_profile().service_host("fixture-protected-adapter") + ":8443/mcp")
            result["ca_configured"] = bool(server.get("caCert") or server.get("ca_cert")
                                           or server.get("ca-cert") or server.get("caCertPEM"))
            result["credential_configured"] = bool(server.get("credential"))
        result["passed"] = bool(result.get("cold_discovery_proven")
                                and result.get("verified_https_url_configured")
                                and result.get("ca_configured")
                                and result.get("credential_configured"))
    except Exception as error:
        result["errors"].append({"stage": "discovery", "failure_kind": type(error).__name__})
    finally:
        for receipt in reversed(ledger):
            try:
                current = owned(args, receipt["kind"], receipt["name"])
                if current["metadata"]["uid"] != receipt["uid"]:
                    raise ValueError("Disposable cleanup UID mismatch")
                api = "/api/v1" if current["apiVersion"] == "v1" else "/apis/" + current["apiVersion"]
                plural = {"Secret": "secrets", "HTTPRoute": "httproutes",
                          "MCPServerRegistration": "mcpserverregistrations"}[current["kind"]]
                url = api + "/namespaces/" + NS + "/" + plural + "/" + receipt["name"]
                delete = {"apiVersion": "v1", "kind": "DeleteOptions",
                          "preconditions": {"uid": receipt["uid"]}}
                response = subprocess.run(["oc", "--kubeconfig=" + args.kubeconfig,
                    "--request-timeout=20s", "delete", "--raw", url, "-f", "-"],
                    input=json.dumps(delete), capture_output=True, text=True, timeout=30)
                if response.returncode:
                    raise RuntimeError("UID-preconditioned discovery cleanup failed")
            except Exception as error:
                result["errors"].append({"stage": "cleanup", "kind": receipt["kind"],
                                         "failure_kind": type(error).__name__})
        after = owned(args, "mcpserverregistration.mcp.kuadrant.io", "fixture-jira")
        route_after = owned(args, "httproute.gateway.networking.k8s.io", "fixture-jira")
        result["baseline_registration_preserved"] = (
            after["metadata"]["uid"] == baseline["metadata"]["uid"] and after["spec"] == baseline["spec"])
        result["baseline_backend_route_preserved"] = (
            route_after["metadata"]["uid"] == baseline_route["metadata"]["uid"]
            and route_after["spec"] == baseline_route["spec"])
        result["passed"] = bool(result["passed"] and not result["errors"]
                                and result["baseline_registration_preserved"]
                                and result["baseline_backend_route_preserved"])
        write_private(output / (args.label + ".summary.json"), result)
    return result


def main() -> None:
    """Require explicit private inputs and never emit raw credentials or statuses."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("kubeconfig", "expected-server", "credentials-file", "label"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--catalog-credential-file",
                        help="Private catalog-only credential; does not authorize tools/call")
    parser.add_argument("--observation-grace-seconds", type=int, default=5,
                        help="Observe after expiry (0–120s), without extending token validity")
    args = parser.parse_args()
    try:
        result = run(args)
    except Exception as error:
        print(json.dumps({"passed": False, "failure_kind": type(error).__name__}))
        raise SystemExit(1) from None
    print(json.dumps(result))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
