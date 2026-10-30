# SPDX-License-Identifier: Apache-2.0
"""Prove both protected MCP transports with a real token supplied only over stdin."""

from __future__ import annotations

import argparse
import asyncio
import base64
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys
from urllib.request import Request, urlopen


async def native_probe(token: str) -> dict:
    """Use the pinned SDK inside the owned pod to initialize, discover and read."""
    from mcp import ClientSession
    from mcp.client.sse import sse_client
    from mcp.client.streamable_http import streamablehttp_client
    import httpx

    def count() -> int:
        """Fetch only the synthetic backend count for the no-mutation invariant."""
        credential = base64.b64encode(f"admin:{os.environ['JIRA_TOKEN']}".encode()).decode()
        req = Request("http://fixture-jira:8080/rest/api/2/search?jql=project%20%3D%20TEST&maxResults=1",
                      headers={"Authorization": "Basic " + credential})
        with urlopen(req, timeout=10) as response:
            return json.load(response)["total"]

    before = count()
    output = {"mcp_sdk": importlib.metadata.version("mcp"), "transports": []}
    output["sse_denials"] = {}
    async with httpx.AsyncClient(timeout=10) as client:
        for case, credential in (("missing_token", None), ("invalid_token", "not-a-token")):
            headers = {"Accept": "text/event-stream"}
            if credential:
                headers["Authorization"] = "Bearer " + credential
            response = await client.get("http://127.0.0.1:8084/sse", headers=headers)
            output["sse_denials"][case] = response.status_code
            if response.status_code != 401:
                raise RuntimeError("Protected SSE endpoint accepted unauthenticated access")
    for mode, url in (("streamable-http", "http://127.0.0.1:8083/mcp"),
                      ("sse", "http://127.0.0.1:8084/sse")):
        headers = {"Authorization": "Bearer " + token}
        client = sse_client(url, headers=headers) if mode == "sse" else streamablehttp_client(url, headers=headers)
        async with client as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                tools = await session.list_tools()
                result = await session.call_tool("searchJiraIssuesUsingJql", {
                    "jql": "project = TEST", "maxResults": 1})
                values = [json.loads(item.text) for item in result.content if getattr(item, "type", "") == "text"]
                ok = not result.isError and any(isinstance(item, dict) and "issues" in item and "total" in item
                                               and not item.get("error", False) for item in values)
                if not ok or len(tools.tools) != 2:
                    raise RuntimeError("Protected adapter did not return its real read result")
                output["transports"].append({"transport": mode, "authenticated": True,
                    "initialized": True, "read_tools": len(tools.tools), "backend_read_ok": ok})
    after = count()
    if before != after:
        raise RuntimeError("Protected read probe changed backend state")
    output.update({"issue_count_before": before, "issue_count_after": after, "backend_unchanged": True})
    return output


def driver(args: argparse.Namespace) -> None:
    """Send a short-lived fixture token to only the explicitly verified owned pod."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "identity_demo"))
    from deployment_profile import in_source_checkout
    from identity_demo_adapter import fixture_request
    from identity_demo_lab import LABELS, oc

    if not args.kubeconfig or not args.expected_server:
        raise ValueError("Explicit kubeconfig and expected server required")
    args.namespace = "demo-core"
    server = oc(args, "config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}")
    if server.rstrip("/") != args.expected_server.rstrip("/"):
        raise ValueError("Target cluster mismatch")
    for kind, name in (("namespace", args.namespace), ("deployment", "fixture-protected-adapter")):
        scope = [] if kind == "namespace" else ["-n", args.namespace]
        item = json.loads(oc(args, "get", kind, name, *scope, "-o", "json"))
        if any(item["metadata"].get("labels", {}).get(k) != v for k, v in LABELS.items()):
            raise ValueError("Owned fixture required")
    path = Path(os.environ["IDENTITY_DEMO_CREDENTIALS_FILE"])
    if path.stat().st_mode & 0o077 or in_source_checkout(path):
        raise ValueError("Private credentials outside repository required")
    credentials = json.loads(path.read_text())
    if credentials["namespace"] != args.namespace:
        raise ValueError("Credential namespace mismatch")
    _, tokens = fixture_request(credentials["keycloak_url"],
        "/realms/identity-demo/protocol/openid-connect/token", method="POST", fields={
            "grant_type": "client_credentials", "client_id": "fixture-gateway-service", "scope": "mcp:read",
            "client_secret": credentials["adapter_clients"]["fixture-gateway-service"]})
    result = subprocess.run(["oc", f"--kubeconfig={args.kubeconfig}", "exec", "-i", "-n", args.namespace,
        "deployment/fixture-protected-adapter", "-c", "fixture-protected-adapter", "--", "python",
        "/fixtures/probe_protected_adapter.py", "--in-pod"],
        input=json.dumps({"token": tokens["access_token"]}), text=True, capture_output=True, timeout=60)
    if result.returncode:
        # SDK exceptions can contain HTTP headers. Do not print stderr or input.
        raise RuntimeError("Protected transport probe failed; inspect sanitized fixture diagnostics")
    value = json.loads(result.stdout)
    print(json.dumps(value))


def main() -> None:
    """Run either the guarded driver or the in-pod native probe."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig")
    parser.add_argument("--expected-server")
    parser.add_argument("--in-pod", action="store_true")
    args = parser.parse_args()
    if args.in_pod:
        try:
            output = asyncio.run(asyncio.wait_for(native_probe(json.load(sys.stdin)["token"]), timeout=45))
            print(json.dumps(output))
        except Exception:
            print("Protected transport probe failed", file=sys.stderr)
            raise SystemExit(1) from None
    else:
        driver(args)


if __name__ == "__main__":
    main()
