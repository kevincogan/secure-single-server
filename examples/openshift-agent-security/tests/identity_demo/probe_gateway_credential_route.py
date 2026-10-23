#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Test disposable private-route token mediation; not native binding or broker discovery.

All raw configuration, exceptions and tokens remain in an explicit private output
directory. Existing policies/routes are preserved; exact disposable objects are
removed on success or failure. The official runtime is never changed.
"""

from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import socket
import subprocess
import time
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
import httpx

import gateway_credential_route as candidate
import probe_broker_discovery as shared
import checks.test_components as human

PORT = 18982


def owned_gateway_deployment(deployment: dict, gateway: dict) -> bool:
    """Accept the installed controller's owner reference, requiring exact UID and labels."""
    # This vendor controller omits `controller` on its Gateway owner reference.
    # Do not infer ownership from a workload label or deployment name alone.
    return all(deployment["metadata"].get("labels", {}).get(key) == value
               for key, value in shared.LABELS.items()) and any(
        ref.get("uid") == gateway["metadata"]["uid"] and ref.get("kind") == "Gateway"
        and ref.get("name") == gateway["metadata"]["name"]
        for ref in deployment["metadata"].get("ownerReferences", []))


def nested(value: Any, key: str) -> list:
    """Find fields in the live Envoy dump without emitting its contents."""
    result = []
    if isinstance(value, dict):
        if key in value:
            result.append(value[key])
        for item in value.values():
            result.extend(nested(item, key))
    elif isinstance(value, list):
        for item in value:
            result.extend(nested(item, key))
    return result


def configuration_checks(dump: dict, ca: str, *, host: str = candidate.HOST,
                         filter_name: str = candidate.FILTER,
                         cluster_name: str = candidate.CLUSTER) -> dict[str, bool]:
    """Require route isolation, ordering and explicit TLS before sending a credential."""
    configs = [x for x in nested(dump, "route_config")
               if isinstance(x, dict) and x.get("name") == "http.8080"]
    filters = [x for x in nested(dump, "http_filters")
               if any(f.get("name") == filter_name for f in x)]
    checks = {"existing-hosts-disable-extra-filter": False,
              "diagnostic-host-enables-extra-filter": False,
              "filter-after-wasm-before-router": False,
              "adapter-explicit-ca-and-name-check": False,
              "authorino-explicit-ca-and-name-check": False}
    if configs and filters:
        hosts = configs[0]["virtual_hosts"]
        probe = next((v for v in hosts if host in v.get("domains", [])), None)
        others = [v for v in hosts if host not in v.get("domains", [])]
        checks["existing-hosts-disable-extra-filter"] = bool(others) and all(
            v.get("typed_per_filter_config", {}).get(filter_name, {}).get("disabled") is True
            for v in others)
        checks["diagnostic-host-enables-extra-filter"] = bool(probe) and (
            filter_name in probe.get("typed_per_filter_config", {})
            and not probe["typed_per_filter_config"][filter_name].get("disabled", False))
        names = [f["name"] for f in filters[0]]
        checks["filter-after-wasm-before-router"] = "envoy.filters.http.wasm" in names and (
            names.index("envoy.filters.http.wasm") < names.index(filter_name)
            < names.index("envoy.filters.http.router"))
        for name, server_name, check in (
            ("outbound|8443||" + candidate.ADAPTER, candidate.ADAPTER, "adapter-explicit-ca-and-name-check"),
            (cluster_name, candidate.AUTHORIZER, "authorino-explicit-ca-and-name-check"),
        ):
            clusters = [c for c in nested(dump, "cluster") if isinstance(c, dict) and c.get("name") == name]
            if len(clusters) == 1:
                tls = clusters[0].get("transport_socket", {}).get("typed_config", {})
                validation = tls.get("common_tls_context", {}).get("validation_context", {})
                checks[check] = validation.get("trusted_ca", {}).get("inline_string") == ca and (
                    validation.get("match_typed_subject_alt_names") == [
                        {"san_type": "DNS", "matcher": {"exact": server_name}}])
    return checks


async def read(token: str, evidence: Path, registered: bool = False) -> dict:
    """Require the intended catalog tools and a genuine protected backend result."""
    observations = []

    async def observe(response: httpx.Response) -> None:
        operation = None
        if response.request.method == "POST":
            try:
                operation = json.loads(response.request.content).get("method")
            except (ValueError, httpx.RequestNotRead):
                operation = "unparseable"
        observations.append({"method": response.request.method, "operation": operation,
            "http_status": response.status_code, "content_type": response.headers.get("content-type"),
            "response_headers": dict(response.headers)})
        # Retain bounded denial details privately. Never consume a successful
        # SSE stream here, or emit response bodies in the public summary.
        if response.status_code >= 400:
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk[:8_193 - len(body)])
                if len(body) > 8_192:
                    break
            observations[-1]["error_body"] = bytes(body[:8_192]).decode(errors="replace")
            observations[-1]["error_body_truncated"] = len(body) > 8_192

    def client_factory(headers: dict | None = None, timeout: httpx.Timeout | None = None,
                       auth: httpx.Auth | None = None) -> httpx.AsyncClient:
        return httpx.AsyncClient(headers=headers, timeout=timeout, auth=auth,
                                 trust_env=False, follow_redirects=False, event_hooks={"response": [observe]})

    try:
        async with streamablehttp_client(f"http://127.0.0.1:{PORT}/mcp", headers={
            "Host": candidate.HOST, "Authorization": "Bearer " + token,
        }, httpx_client_factory=client_factory) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                initialized = await session.initialize()
                expected = "Kuadrant MCP Gateway" if registered else "identity-demo-protected-jira"
                if initialized.serverInfo.name != expected:
                    raise RuntimeError("Unexpected MCP responder")
                tools = await session.list_tools()
                prefix = "grant_probe_" if registered else ""
                selected = [t for t in tools.tools if t.name.startswith(prefix)] if registered else tools.tools
                result = await session.call_tool(prefix + "searchJiraIssuesUsingJql", {
                    "jql": "project = TEST", "maxResults": 1})
                values = [json.loads(v.text) for v in result.content if getattr(v, "type", "") == "text"]
                if result.isError or len(selected) != 2 or not any(
                    isinstance(v, dict) and "issues" in v and "total" in v and not v.get("error")
                    for v in values
                ):
                    raise RuntimeError("Protected adapter did not return its real read result")
                return {"read_tools": len(selected), "actual_backend_result": True,
                        "registered_broker_tool": registered}
    finally:
        shared.write_private(evidence, observations)


def denial(credential: str | None) -> int:
    """Return an actual HTTP result; connection failures cannot prove denial."""
    headers = {"Host": candidate.HOST, "Content-Type": "application/json",
               "Accept": "application/json, text/event-stream"}
    if credential:
        headers["Authorization"] = "Bearer " + credential
    body = json.dumps({"jsonrpc": "2.0", "id": 91, "method": "initialize", "params": {
        "protocolVersion": "2025-11-25", "capabilities": {},
        "clientInfo": {"name": "credential-denial-probe", "version": "1"}}}).encode()
    request = Request(f"http://127.0.0.1:{PORT}/mcp", data=body, headers=headers)
    try:
        with urlopen(request, timeout=10) as response:
            return response.status
    except HTTPError as error:
        return error.code


def explicit_tool_denial(observations: list[dict]) -> bool:
    """Require rejection of the actual action, not initialization or an outage."""
    calls = [v for v in observations if v.get("operation") == "tools/call"]
    if len(calls) != 1 or calls[0].get("http_status") != 403:
        return False
    body = calls[0].get("error_body", "")
    if calls[0].get("error_body_truncated"):
        return False
    try:
        value = json.loads(body)
    except (ValueError, TypeError):
        return body.strip() in ("", "Forbidden", "forbidden")
    return isinstance(value, dict) and "result" not in value and "issues" not in value


def initialization_response(token: str) -> dict:
    """Capture the first actual HTTP boundary before interpreting SDK behavior."""
    request = Request(f"http://127.0.0.1:{PORT}/mcp", data=json.dumps({
        "jsonrpc": "2.0", "id": 44, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "owned-credential-route-probe", "version": "1"},
        }}).encode(), headers={"Host": candidate.HOST, "Authorization": "Bearer " + token,
            "Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
    try:
        response = urlopen(request, timeout=10)
    except HTTPError as error:
        response = error
    with response:
        body = response.read(131073)
        if len(body) > 131072:
            raise ValueError("Bounded MCP initialization response required")
        value = {"http_status": response.code, "headers": dict(response.headers),
                 "body": body.decode(errors="replace")}
        session = response.headers.get("mcp-session-id")
    if session and value["http_status"] == 200:
        cleanup = Request(f"http://127.0.0.1:{PORT}/mcp", method="DELETE", headers={
            "Host": candidate.HOST, "Authorization": "Bearer " + token, "Mcp-Session-Id": session})
        with urlopen(cleanup, timeout=10) as response:
            value["session_delete_status"] = response.code
    return value


def initialized_expected_adapter(response: dict) -> bool:
    """A valid broker initialization cannot count as reaching the protected adapter."""
    if response.get("http_status") != 200:
        return False
    try:
        body = json.loads(response["body"])
        return body.get("jsonrpc") == "2.0" and not body.get("error") and (
            body.get("result", {}).get("serverInfo", {}).get("name") == "identity-demo-protected-jira")
    except (ValueError, KeyError, TypeError, AttributeError):
        return False


def initialized_expected_broker(response: dict) -> bool:
    """Broker initialization is expected only for the explicitly registered probe."""
    try:
        value = json.loads(response["body"])
        return response.get("http_status") == 200 and not value.get("error") and (
            value.get("result", {}).get("serverInfo", {}).get("name") == "Kuadrant MCP Gateway")
    except (ValueError, KeyError, TypeError, AttributeError):
        return False


def run(args: argparse.Namespace) -> dict:
    """Apply only reviewed disposable candidates and verify exact cleanup."""
    if args.expected_server != shared.SERVER or Path(args.label).name != args.label:
        raise ValueError("Exact lab and safe evidence label required")
    shared.private_path(args.kubeconfig)
    root = shared.private_path(str(args.output_dir), directory=True)
    output = root / args.label
    output.mkdir(mode=0o700)  # A fresh run is mandatory.
    credentials = json.loads(shared.private_path(args.credentials_file).read_text())
    if credentials.get("namespace") != shared.NS:
        raise ValueError("Owned fixture credential required")

    def save(name: str, value: Any) -> None:
        shared.write_private(output / name, value)

    def kube(*words: str, payload: Any = None) -> dict:
        return shared.kube(args, *words, payload=payload)

    def dump(pod: str) -> dict:
        response = subprocess.run(["oc", "--kubeconfig=" + args.kubeconfig, "--request-timeout=15s",
            "-n", shared.NS, "exec", pod, "--", "pilot-agent", "request", "GET", "config_dump"],
            capture_output=True, text=True, timeout=25)
        if response.returncode:
            raise RuntimeError("Native gateway config reader failed; response withheld")
        value = json.loads(response.stdout)
        save("envoy-" + str(time.time_ns()) + ".private-json", value)
        return value

    ledger: list[dict] = []
    snapshots: dict = {}
    tunnel = None
    log = None
    result: dict = {"checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "passed": False, "checks": {}, "errors": [], "actual_broker_hairpin_proven": False,
        "native_binding_proven": False, "sender_binding_proven": False,
        "renewable_broker_discovery_proven": False, "step4_complete": False, "step5_started": False}
    try:
        actual = kube("config", "view", "--minify", "-o", "json")
        if actual["clusters"][0]["cluster"]["server"] != shared.SERVER:
            raise ValueError("Actual cluster mismatch")
        shared.owned(args, "namespace", shared.NS)
        gateway = shared.owned(args, "gateway.gateway.networking.k8s.io", "fixture-mcp")
        deployment = kube("get", "deployment", "fixture-mcp-openshift-ai-inference",
                          "-n", shared.NS, "-o", "json")
        if not owned_gateway_deployment(deployment, gateway):
            raise ValueError("Gateway Deployment controller mismatch")
        replica_uids = {r["metadata"]["uid"] for r in kube("get", "replicasets", "-n", shared.NS,
            "-o", "json")["items"] if any(ref.get("controller")
            and ref.get("uid") == deployment["metadata"]["uid"]
            for ref in r["metadata"].get("ownerReferences", []))}
        pods = [p for p in kube("get", "pods", "-n", shared.NS, "-o", "json")["items"]
                if any(ref.get("controller") and ref.get("uid") in replica_uids
                       for ref in p["metadata"].get("ownerReferences", []))
                and not p["metadata"].get("deletionTimestamp")]
        if len(pods) != 1 or not all(c.get("ready") for c in pods[0]["status"]["containerStatuses"]):
            raise ValueError("One Ready owned gateway required")
        pod = pods[0]["metadata"]["name"]
        dump(pod)
        for kind, name in (("authpolicy.kuadrant.io", "fixture-mcp-auth"),
                           ("authpolicy.kuadrant.io", "fixture-mcp-tools-auth"),
                           ("httproute.gateway.networking.k8s.io", "fixture-jira"),
                           ("mcpserverregistration.mcp.kuadrant.io", "fixture-jira")):
            snapshots[kind + "/" + name] = shared.owned(args, kind, name)
        save("baseline-before.private-json", snapshots)
        ca = shared.owned(args, "configmap", "fixture-service-ca")["data"]["service-ca.crt"]
        human.KEYCLOAK = credentials["keycloak_url"]
        human.ISSUER = candidate.HUMAN_ISSUER
        if human.KEYCLOAK + "/realms/identity-demo" != human.ISSUER:
            raise ValueError("Approved human issuer required")
        tokens = human.login("analyst", credentials["analyst"])
        human.verify(tokens["access_token"], "identity-demo-mcp", issuer=human.ISSUER)
        human.verify(tokens["access_token"], credentials["gateway_url"], issuer=human.ISSUER)
        save("analyst-token.private-json", tokens)
        for value in candidate.manifests(ca, credentials["adapter_clients"]["fixture-gateway-service"]):
            kind = value["kind"].lower() + "." + value["apiVersion"].split("/")[0]
            if value["apiVersion"] == "v1":
                kind = value["kind"].lower()
            if kube("get", kind, candidate.NAME, "-n", shared.NS, "--ignore-not-found", "-o", "json"):
                raise ValueError("Existing diagnostic object refused")
            kube("create", "--dry-run=server", "-f", "-", "-o", "json", payload=value)
            item = kube("create", "-f", "-", "-o", "json", payload=value)
            ledger.append({"kind": kind, "object": item})
            save("created-" + value["kind"] + ".private-json", item)
            if value["kind"] == "HTTPRoute":
                deadline = time.monotonic() + 45
                while time.monotonic() < deadline:
                    route = shared.owned(args, kind, candidate.NAME)
                    parents = [parent for parent in route.get("status", {}).get("parents", [])
                               if parent.get("parentRef", {}).get("name") == "fixture-mcp"]
                    conditions = [condition for parent in parents for condition in parent.get("conditions", [])]
                    if any(c.get("type") == "Accepted" and c.get("status") == "False"
                           and c.get("reason") == "NoMatchingListenerHostname" for c in conditions):
                        raise ValueError("Diagnostic hostname rejected by listener")
                    if all(any(c.get("type") == expected and c.get("status") == "True"
                               and c.get("observedGeneration") == route["metadata"]["generation"]
                               for c in conditions) for expected in ("Accepted", "ResolvedRefs")):
                        break
                    time.sleep(1)
                else:
                    raise RuntimeError("Diagnostic route not accepted/resolved")
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            checks = configuration_checks(dump(pod), ca)
            if all(checks.values()):
                result["checks"].update(checks)
                break
            time.sleep(2)
        else:
            raise RuntimeError("Effective diagnostic configuration guards not established")
        registered = bool(getattr(args, "catalog_credential_file", None))
        if registered:
            catalog = json.loads(shared.private_path(args.catalog_credential_file).read_text())
            if not catalog["token"].startswith("discovery_") or catalog["expires_at"] <= time.time():
                raise ValueError("Active catalog-only credential required")
            grant = shared.manifest("v1", "Secret", shared.NAME + "-route-grant")
            grant["metadata"]["labels"]["mcp.kuadrant.io/secret"] = "true"
            grant.update(type="Opaque", stringData={"token": "Bearer " + catalog["token"]})
            trust = shared.manifest("v1", "Secret", shared.NAME + "-route-ca")
            trust["metadata"]["labels"]["mcp.kuadrant.io/secret"] = "true"
            trust.update(type="Opaque", stringData={"ca.crt": ca})
            registration = candidate.resource("mcp.kuadrant.io/v1alpha1", "MCPServerRegistration", {
                "targetRef": {"group": "gateway.networking.k8s.io", "kind": "HTTPRoute", "name": candidate.NAME},
                "path": "/mcp", "prefix": "grant_probe_", "state": "Enabled", "userSpecificList": "Disabled",
                "credentialRef": {"name": grant["metadata"]["name"], "key": "token"},
                "caCertSecretRef": {"name": trust["metadata"]["name"], "key": "ca.crt"},
            })
            for value in (trust, grant, registration):
                name = value["metadata"]["name"]
                kind = "secret" if value["apiVersion"] == "v1" else "mcpserverregistration.mcp.kuadrant.io"
                if kube("get", kind, name, "-n", shared.NS, "--ignore-not-found", "-o", "json"):
                    raise ValueError("Existing catalog-route diagnostic refused")
                kube("create", "--dry-run=server", "-f", "-", "-o", "json", payload=value)
                item = kube("create", "-f", "-", "-o", "json", payload=value)
                ledger.append({"kind": kind, "object": item})
                save("created-" + name + ".private-json", item)
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                live = shared.owned(args, "mcpserverregistration.mcp.kuadrant.io", candidate.NAME)
                if live.get("status", {}).get("discoveredTools") == 2 and any(
                    c.get("type") == "Ready" and c.get("status") == "True"
                    for c in live.get("status", {}).get("conditions", [])):
                    result["checks"]["protected-backend-cold-discovery"] = True
                    break
                time.sleep(1)
            else:
                raise RuntimeError("Protected backend discovery not ready")
            # Reconciliation must not consume the real human's token lifetime.
            tokens = human.login("analyst", credentials["analyst"])
            human.verify(tokens["access_token"], credentials["gateway_url"], issuer=human.ISSUER)
        with socket.socket() as connection:
            if connection.connect_ex(("127.0.0.1", PORT)) == 0:
                raise ValueError("Existing loopback listener refused")
        log = open(output / "tunnel.private-log", "x")
        os.chmod(output / "tunnel.private-log", 0o600)
        tunnel = subprocess.Popen(["oc", "--kubeconfig=" + args.kubeconfig, "-n", shared.NS,
            "port-forward", "pod/" + pod, f"{PORT}:8080", "--address=127.0.0.1"], stdout=log, stderr=log)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if tunnel.poll() is not None:
                raise RuntimeError("Owned tunnel stopped")
            with socket.socket() as connection:
                if connection.connect_ex(("127.0.0.1", PORT)) == 0:
                    break
            time.sleep(.2)
        else:
            raise TimeoutError("Owned tunnel not ready")
        initial = initialization_response(tokens["access_token"])
        save("first-http-response.private-json", initial)
        result["first_initialize_http_status"] = initial["http_status"]
        if initial["http_status"] != 200:
            raise RuntimeError("Initial HTTP boundary rejected request; response retained privately")
        if not (initialized_expected_broker(initial) if registered else initialized_expected_adapter(initial)):
            raise RuntimeError("Initialization did not reach the protected adapter; registered broker path required")
        save("first-read.summary.json", asyncio.run(asyncio.wait_for(
            read(tokens["access_token"], output / "first-sdk-exchanges.private-json", registered), 40)))
        result["checks"]["actual-protected-adapter-read"] = True
        result["actual_broker_hairpin_proven"] = registered
        for name, token in (("missing", None), ("malformed", "not-a-token")):
            if denial(token) not in (401, 403):
                raise RuntimeError("Explicit authentication denial absent")
            result["checks"][name + "-denied"] = True
        viewer = human.login("viewer", credentials["viewer"])
        human.verify(viewer["access_token"], credentials["gateway_url"], issuer=human.ISSUER)
        if registered:
            # The public broker permits viewer initialization. Its catalog is
            # distinct from the analyst-only diagnostic backend's action policy.
            evidence = output / "viewer-sdk-exchanges.private-json"
            try:
                asyncio.run(asyncio.wait_for(read(viewer["access_token"], evidence, True), 40))
            except Exception:
                observations = json.loads(evidence.read_text()) if evidence.exists() else []
                denied = explicit_tool_denial(observations)
                result["viewer_tool_http_statuses"] = [v.get("http_status") for v in observations
                                                       if v.get("operation") == "tools/call"]
                if not denied:
                    result["errors"].append({"stage": "viewer-denial", "kind": "ExplicitToolDenialUnproven"})
            else:
                raise RuntimeError("Viewer reached the analyst-only protected tool")
            result["checks"]["viewer-protected-tool-denied"] = denied
        else:
            if denial(viewer["access_token"]) != 403:
                raise RuntimeError("Explicit viewer denial absent")
            result["checks"]["viewer-denied"] = True
        time.sleep(35)
        save("renewed-read.summary.json", asyncio.run(asyncio.wait_for(
            read(tokens["access_token"], output / "renewed-sdk-exchanges.private-json", registered), 40)))
        result["checks"]["read-after-service-token-lifetime"] = True
        result["passed"] = True
    except Exception as error:
        result["errors"].append({"stage": "probe", "kind": type(error).__name__})
        save("error.private-json", {"type": type(error).__name__, "message": str(error)})
        if "pod" in locals():
            response = subprocess.run(["oc", "--kubeconfig=" + args.kubeconfig,
                "--request-timeout=15s", "-n", shared.NS, "exec", pod, "--", "pilot-agent", "request",
                "GET", "stats?filter=identity_demo_adapter|identity-demo.adapter-authorino|ssl.fail_verify"],
                capture_output=True, text=True, timeout=25)
            save("failure-stats.private-json", {"stdout": response.stdout, "stderr": response.stderr,
                                               "returncode": response.returncode})
    finally:
        if tunnel:
            tunnel.terminate()
            try:
                tunnel.wait(timeout=10)
            except subprocess.TimeoutExpired:
                tunnel.kill()
                tunnel.wait(timeout=5)
        if log:
            log.close()
        for receipt in reversed(ledger):
            try:
                item = receipt["object"]
                name = item["metadata"]["name"]
                current = shared.owned(args, receipt["kind"], name)
                if current["metadata"]["uid"] != item["metadata"]["uid"]:
                    raise ValueError("Diagnostic cleanup UID mismatch")
                api = "/api/v1" if current["apiVersion"] == "v1" else "/apis/" + current["apiVersion"]
                plural = {"Secret": "secrets", "AuthConfig": "authconfigs",
                          "HTTPRoute": "httproutes", "EnvoyFilter": "envoyfilters",
                          "MCPServerRegistration": "mcpserverregistrations"}[current["kind"]]
                endpoint = api + "/namespaces/" + shared.NS + "/" + plural + "/" + name
                response = subprocess.run(["oc", "--kubeconfig=" + args.kubeconfig,
                    "--request-timeout=15s", "delete", "--raw", endpoint, "-f", "-"],
                    input=json.dumps({"apiVersion": "v1", "kind": "DeleteOptions",
                        "preconditions": {"uid": item["metadata"]["uid"]}}),
                    capture_output=True, text=True, timeout=25)
                if response.returncode:
                    raise RuntimeError("UID cleanup failed")
            except Exception as error:
                result["errors"].append({"stage": "cleanup", "kind": type(error).__name__})
        try:
            result["checks"]["baseline-specs-and-uids-preserved"] = bool(snapshots) and all(
                (after := shared.owned(args, key.split("/")[0], key.split("/")[1]))["metadata"]["uid"]
                == value["metadata"]["uid"] and after["spec"] == value["spec"]
                for key, value in snapshots.items())
            result["checks"]["temporary-objects-absent"] = all(not kube("get", x["kind"], x["object"]["metadata"]["name"],
                "-n", shared.NS, "--ignore-not-found", "-o", "json") for x in ledger)
        except Exception as error:
            result["errors"].append({"stage": "preservation", "kind": type(error).__name__})
        result["passed"] = result["passed"] and not result["errors"] and all(result["checks"].values())
        save("summary.json", result)
    return result


def main() -> None:
    """Require private inputs and print only a sanitized summary."""
    parser = argparse.ArgumentParser(description=__doc__)
    logging.getLogger("mcp").setLevel(logging.CRITICAL)
    for name in ("kubeconfig", "expected-server", "credentials-file", "label"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--catalog-credential-file", help="Prove the registered broker path with a catalog-only credential")
    try:
        result = run(parser.parse_args())
    except Exception as error:
        print(json.dumps({"passed": False, "failure_kind": type(error).__name__}))
        raise SystemExit(1) from None
    print(json.dumps(result))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
