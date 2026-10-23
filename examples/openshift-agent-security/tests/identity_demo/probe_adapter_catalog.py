#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prove catalog-only access and independent service reads on the owned adapter."""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any
from urllib.request import Request, urlopen


async def worker(values: dict) -> dict:
    """Use verified internal HTTPS and assert denials before backend dispatch."""
    import httpx

    url = "https://fixture-protected-adapter.demo-core.svc.cluster.local:8443/mcp"
    checks: dict[str, bool] = {}
    call = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
        "name": "searchJiraIssuesUsingJql", "arguments": {"jql": "project = TEST", "maxResults": 1}}}

    def count() -> int:
        """Read the synthetic issue count with fixture credentials kept in the Pod."""
        basic = base64.b64encode(("admin:" + os.environ["JIRA_TOKEN"]).encode()).decode()
        request = Request("http://fixture-jira:8080/rest/api/2/search?jql=project%20%3D%20TEST&maxResults=1",
                          headers={"Authorization": "Basic " + basic})
        with urlopen(request, timeout=10) as response:
            return json.load(response)["total"]

    before = count()
    async with httpx.AsyncClient(verify="/service-ca/service-ca.crt", timeout=10,
                                 follow_redirects=False, trust_env=False) as client:
        async def request(token: str | None, payload: Any, *, method: str = "POST", session: bool = False) -> Any:
            """Return bounded responses without logging credentials."""
            headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
            if token:
                headers["Authorization"] = "Bearer " + token
            if session:
                headers["Mcp-Session-Id"] = "untrusted-session"
            response = await client.request(method, url, headers=headers, json=payload)
            if len(response.content) > 131_072:
                raise ValueError("Bounded adapter response required")
            return response

        catalog = values["catalog"]
        # Secret projection is asynchronous. Do not restart the adapter to pass rotation.
        deadline = time.monotonic() + 90
        while True:
            response = await request(catalog, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            if response.status_code == 200:
                break
            if response.status_code != 401 or time.monotonic() >= deadline:
                raise RuntimeError("Catalog credential not active after bounded projection wait")
            await asyncio.sleep(1)
        checks["catalog-lists-two-tools"] = len(response.json()["result"]["tools"]) == 2
        checks["no-backend-session-id"] = "mcp-session-id" not in response.headers
        initialized = await request(catalog, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                       "clientInfo": {"name": "catalog-probe", "version": "1"}}})
        checks["catalog-initialize"] = initialized.status_code == 200 and (
            initialized.json()["result"]["serverInfo"]["name"] == "identity-demo-protected-jira")
        for name, token, payload, method, session, expected in (
            ("catalog-tool-denied", catalog, call, "POST", False, 403),
            ("catalog-session-attach-denied", catalog, call, "POST", True, 403),
            ("catalog-session-delete-denied", catalog, None, "DELETE", True, 403),
            ("catalog-get-denied", catalog, None, "GET", False, 403),
            ("catalog-batch-denied", catalog, [call], "POST", False, 403),
            ("missing-credential-denied", None, call, "POST", False, 401),
            ("unknown-credential-denied", "discovery_" + "x" * 43, call, "POST", False, 401),
            ("unscoped-service-denied", values["unscoped"], call, "POST", False, 403),
            ("service-session-header-denied", values["service"], call, "POST", True, 403),
        ):
            checks[name] = (await request(token, payload, method=method, session=session)).status_code == expected
        if values.get("revoked"):
            checks["revoked-catalog-denied"] = (await request(values["revoked"], call)).status_code == 401
        response = await request(values["service"], call)
        if response.status_code == 200:
            tool = response.json().get("result", {})
            content = [json.loads(v["text"]) for v in tool.get("content", []) if v.get("type") == "text"]
            checks["independent-service-backend-read"] = not tool.get("isError") and any(
                isinstance(v, dict) and "issues" in v and "total" in v and not v.get("error") for v in content)
        else:
            checks["independent-service-backend-read"] = False
    checks["backend-unchanged"] = count() == before
    return {"passed": all(checks.values()), "checks": checks,
            "native_binding_proven": False, "sender_binding_proven": False, "step4_complete": False}


def driver(args: argparse.Namespace) -> dict:
    """Send credentials over stdin only to the owned HTTPS container."""
    import probe_broker_discovery as shared
    from identity_demo_keycloak_upstream import BASE, issuer_request

    if args.expected_server != shared.SERVER or Path(args.label).name != args.label:
        raise ValueError("Exact authorized cluster required")
    shared.private_path(args.kubeconfig)
    config = shared.kube(args, "config", "view", "--minify", "-o", "json")
    if config["clusters"][0]["cluster"]["server"] != shared.SERVER:
        raise ValueError("Actual cluster mismatch")
    shared.owned(args, "namespace", shared.NS)
    dep = shared.owned(args, "deployment", "fixture-protected-adapter")
    if dep.get("status", {}).get("readyReplicas") != 1:
        raise ValueError("One Ready owned adapter required")
    credentials = json.loads(shared.private_path(args.credentials_file).read_text())
    if credentials.get("namespace") != shared.NS:
        raise ValueError("Owned development credentials required")
    catalog = json.loads(shared.private_path(args.catalog_credential_file).read_text())
    values = {"catalog": catalog["token"]}
    # Wait for public trust-digest projection before issuing 30-second service
    # tokens, so a rotation wait cannot itself invalidate the read control.
    expected = hashlib.sha256(catalog["token"].encode()).hexdigest()
    deadline = time.monotonic() + 90
    while True:
        response = subprocess.run(["oc", "--kubeconfig=" + args.kubeconfig, "--request-timeout=10s",
            "-n", shared.NS, "exec", "deployment/fixture-protected-adapter", "-c", "adapter-https",
            "--", "cat", "/catalog-trust/digests.json"], capture_output=True, text=True, timeout=15)
        if response.returncode == 0 and expected in json.loads(response.stdout):
            break
        if time.monotonic() >= deadline:
            raise RuntimeError("Owned catalog trust projection not observed")
        time.sleep(1)
    for name, scope in (("service", "mcp:read"), ("unscoped", "")):
        fields = {"grant_type": "client_credentials", "client_id": "fixture-gateway-service",
                  "client_secret": credentials["adapter_clients"]["fixture-gateway-service"]}
        if scope:
            fields["scope"] = scope
        _, grant = issuer_request(BASE, "/realms/identity-demo/protocol/openid-connect/token",
                                  method="POST", fields=fields)
        values[name] = grant["access_token"]
    if args.revoked_credential_file:
        values["revoked"] = json.loads(shared.private_path(args.revoked_credential_file).read_text())["token"]
    source = Path(__file__).read_text()
    response = subprocess.run(["oc", "--kubeconfig=" + args.kubeconfig, "--request-timeout=15s",
        "-n", shared.NS, "exec", "-i", "deployment/fixture-protected-adapter", "-c", "adapter-https",
        "--", "python", "-c", source, "--in-pod"],
        input=json.dumps(values), capture_output=True, text=True, timeout=120)
    output = shared.private_path(args.output_dir, directory=True)
    shared.write_private(output / (args.label + ".private-json"),
                         {"stdout": response.stdout, "stderr": response.stderr, "returncode": response.returncode})
    if response.returncode:
        raise RuntimeError("Owned catalog probe failed; details retained privately")
    return json.loads(response.stdout)


def main() -> None:
    """Choose local driver or in-Pod execution without disclosing credentials."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--in-pod", action="store_true")
    for name in ("kubeconfig", "expected-server", "credentials-file", "catalog-credential-file",
                 "revoked-credential-file", "output-dir", "label"):
        parser.add_argument("--" + name)
    args = parser.parse_args()
    try:
        result = asyncio.run(worker(json.load(sys.stdin))) if args.in_pod else driver(args)
        print(json.dumps(result))
        raise SystemExit(0 if result["passed"] else 1)
    except Exception as error:
        print(json.dumps({"passed": False, "failure_kind": type(error).__name__}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
