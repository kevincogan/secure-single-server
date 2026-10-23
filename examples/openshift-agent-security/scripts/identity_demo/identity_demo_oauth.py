#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Configure native OAuth discovery only on our synthetic HTTPS gateway route."""

from __future__ import annotations
from deployment_profile import active_profile

import argparse
import json
from pathlib import Path
import subprocess
import sys
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from identity_demo_adapter import fixture_request
from identity_demo_lab import LABELS, apply_owned, oc, resource
from deployment_profile import in_source_checkout


def owned(args: argparse.Namespace, kind: str, name: str) -> dict:
    """Read an object and refuse to operate unless both ownership labels match."""
    scope = [] if kind == "namespace" else ["-n", args.namespace]
    item = json.loads(oc(args, "get", kind, name, *scope, "-o", "json"))
    if any(item["metadata"].get("labels", {}).get(k) != v for k, v in LABELS.items()):
        raise ValueError("Owned fixture resource required")
    return item


def configure_audience(base: str, credentials: dict, audience: str) -> None:
    """Add the real gateway audience only to our pre-existing public PKCE client."""
    _, grant = fixture_request(base, "/realms/master/protocol/openid-connect/token", method="POST", fields={
        "grant_type": "password", "client_id": "admin-cli", "username": "fixture-admin",
        "password": credentials["keycloak_admin"]})
    token = grant["access_token"]
    prefix = "/admin/realms/identity-demo/clients"
    _, clients = fixture_request(base, prefix + "?clientId=identity-demo-ui", token=token)
    if len(clients) != 1:
        raise ValueError("Expected exactly one fixture UI client")
    client = clients[0]
    if (not client.get("publicClient") or client.get("directAccessGrantsEnabled")
            or client.get("redirectUris") != ["http://127.0.0.1:18085/callback"]
            or client.get("attributes", {}).get("pkce.code.challenge.method") != "S256"):
        raise ValueError("Expected the fixture's original PKCE-only client")
    attributes = client.setdefault("attributes", {})
    if attributes.get("identity-demo-owner", active_profile().owner) != active_profile().owner:
        raise ValueError("Unowned UI client refused")
    attributes["identity-demo-owner"] = active_profile().owner
    mappers = client.setdefault("protocolMappers", [])
    original = [mapper for mapper in mappers if mapper.get("name") == "mcp-audience"]
    if len(original) != 1 or original[0].get("config", {}).get("included.custom.audience") != "identity-demo-mcp":
        raise ValueError("Fixture client fingerprint mismatch")
    matches = [mapper for mapper in mappers if mapper.get("name") == "gateway-resource-audience"]
    if len(matches) > 1:
        raise ValueError("Ambiguous fixture resource mapper")
    mapper = matches[0] if matches else {"name": "gateway-resource-audience"}
    mapper.update({"protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper", "config": {
        "included.custom.audience": audience, "access.token.claim": "true", "id.token.claim": "false"}})
    if not matches:
        mappers.append(mapper)
    fixture_request(base, prefix + "/" + client["id"], method="PUT", token=token, value=client)


def loopback_request(host: str, path: str, payload: dict | None = None) -> tuple[int, object, dict]:
    """Inspect only our fixed tunnel before permitting router ingress."""
    headers = {"Host": host, "Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    req = Request("http://127.0.0.1:18084" + path, headers=headers,
                  data=json.dumps(payload).encode() if payload is not None else None)
    try:
        response = urlopen(req, timeout=15)
    except HTTPError as error:
        response = error
    with response:
        body = response.read(1_000_000)
        return response.status, response.headers, json.loads(body) if response.status == 200 else {}


def expose(args: argparse.Namespace, url: str, issuer: str) -> None:
    """Permit HTTPS ingress only after actual discovery and rejection tests pass."""
    host = url.removeprefix("https://").removesuffix("/mcp")
    status, _, metadata = loopback_request(host, "/.well-known/oauth-protected-resource/mcp")
    if status != 200 or metadata.get("resource") != url or metadata.get("authorization_servers") != [issuer]:
        raise ValueError("Correct public resource metadata must pass before route exposure")
    payload = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-03-26", "capabilities": {},
        "clientInfo": {"name": "identity-demo-ingress-preflight", "version": "0.1"}}}
    for path in ("/mcp", "/.well-known/oauth-protected-resource/mcp"):
        status, headers, _ = loopback_request(host, path, payload)
        if status != 401 or "resource_metadata=" not in headers.get("WWW-Authenticate", ""):
            raise ValueError("Unauthenticated POST must return 401 and a discovery challenge")
    # Protect the internal listener too; public metadata is a broker exception.
    if loopback_request("jira.fixture-mcp.local", "/mcp", payload)[0] != 401:
        raise ValueError("Backend listener must still reject unauthenticated calls")
    policy = resource("NetworkPolicy", "fixture-mcp-route-ingress", args.namespace)
    policy["apiVersion"] = "networking.k8s.io/v1"
    policy["spec"] = {"podSelector": {"matchLabels": {"gateway.networking.k8s.io/gateway-name": "fixture-mcp"}},
        "policyTypes": ["Ingress"], "ingress": [{"from": [{"namespaceSelector": {
            "matchLabels": {"kubernetes.io/metadata.name": "openshift-ingress"}}}],
            "ports": [{"port": 8080, "protocol": "TCP"}]}]}
    apply_owned(args, policy)
    print("Owned HTTPS gateway ingress enabled after rejection/metadata checks")


def setup(args: argparse.Namespace) -> None:
    """Validate our cluster/realm and configure or expose only the owned route."""
    server = oc(args, "config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}")
    if server.rstrip("/") != args.expected_server.rstrip("/") or args.namespace != "demo-core":
        raise ValueError("Expected cluster and exact fixture namespace required")
    owned(args, "namespace", args.namespace)
    owned(args, "deployment", "fixture-keycloak")
    owned(args, "service", "fixture-mcp-openshift-ai-inference")
    private = Path(args.credentials_file)
    if private.stat().st_mode & 0o077 or in_source_checkout(private):
        raise ValueError("Private credentials outside repository required")
    credentials = json.loads(private.read_text())
    if credentials["namespace"] != args.namespace:
        raise ValueError("Credential namespace mismatch")
    base = "https://" + owned(args, "route", "fixture-keycloak")["spec"]["host"]
    if base != credentials["keycloak_url"]:
        raise ValueError("Owned issuer mismatch")
    if args.expose:
        route = owned(args, "route", "fixture-mcp")
        url = "https://" + route["spec"]["host"] + "/mcp"
        if url != credentials.get("gateway_url"):
            raise ValueError("Recorded gateway URI mismatch")
        expose(args, url, base + "/realms/identity-demo")
        return
    route = resource("Route", "fixture-mcp", args.namespace, {
        "to": {"kind": "Service", "name": "fixture-mcp-openshift-ai-inference"},
        "port": {"targetPort": 8080}, "tls": {"termination": "edge", "insecureEdgeTerminationPolicy": "Redirect"}})
    apply_owned(args, route)
    host = owned(args, "route", "fixture-mcp")["spec"]["host"]
    url = "https://" + host + "/mcp"
    configure_audience(base, credentials, url)
    command = [sys.executable, str(Path(__file__).with_name("identity_demo_gateway.py")),
        "--kubeconfig", args.kubeconfig, "--expected-server", args.expected_server,
        "--namespace", args.namespace, "--extend-mcp", "--keycloak-url", base,
        "--oauth-resource-url", url]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError("Owned gateway discovery setup failed; request details suppressed")
    credentials["gateway_url"] = url
    private.write_text(json.dumps(credentials))
    print("Owned gateway discovery configured. Verify via loopback, then rerun with --expose.")


def main() -> None:
    """Require explicit cluster/credential inputs for both stages."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--expected-server", required=True)
    parser.add_argument("--namespace", default="demo-core")
    parser.add_argument("--credentials-file", required=True)
    parser.add_argument("--expose", action="store_true")
    setup(parser.parse_args())


if __name__ == "__main__":
    main()
