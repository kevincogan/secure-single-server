#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Provision an independent, read-only protected adapter in our fixture namespace."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import secrets
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlencode, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from identity_demo_lab import LABELS, apply_owned, deployment, oc, resource, service
from deployment_profile import active_profile
from deployment_profile import in_source_checkout


class NoFixtureRedirect(HTTPRedirectHandler):
    """Never forward an administrative credential through an HTTP redirect."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:
        """Administrative/JWKS APIs must respond at the configured issuer URL."""
        return None


def fixture_request(base: str, path: str, *, method: str = "GET", token: str | None = None,
                    fields: dict | None = None, value: dict | None = None,
                    include_location: bool = False) -> tuple[int, object]:
    """Call only the owned fixture issuer, without exposing credentials on failure."""
    parsed = urlparse(base)
    if (parsed.scheme != "https" or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment
            or base != active_profile().origin("fixture-keycloak")):
        raise ValueError("Owned HTTPS Keycloak route required")
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = None
    if fields is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        data = urlencode(fields).encode()
    if value is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(value).encode()
    try:
        client = build_opener(NoFixtureRedirect())
        with client.open(Request(base + path, data=data, headers=headers, method=method), timeout=20) as response:
            body = response.read(2_000_000)
            result = json.loads(body) if body else None
            if include_location:
                result = {"value": result, "location": response.headers.get("Location", "")}
            return response.status, result
    except HTTPError as error:
        # Do not print the body or token-bearing request on error.
        raise RuntimeError(f"Owned fixture API rejected {method} (HTTP {error.code})") from None


def configure_clients(base: str, credentials: dict) -> None:
    """Configure owned service clients without modifying human login or shared IdPs."""
    _, admin = fixture_request(base, "/realms/master/protocol/openid-connect/token", method="POST",
        fields={"grant_type": "password", "client_id": "admin-cli", "username": "fixture-admin",
                "password": credentials["keycloak_admin"]})
    token = admin["access_token"]
    prefix = "/admin/realms/identity-demo"
    _, scopes = fixture_request(base, prefix + "/client-scopes", token=token)
    matching = [scope for scope in scopes if scope["name"] == "mcp:read"]
    if matching:
        if matching[0].get("attributes", {}).get("identity-demo-owner") != active_profile().owner:
            raise ValueError("Unowned fixture client scope refused")
    else:
        fixture_request(base, prefix + "/client-scopes", method="POST", token=token, value={
            "name": "mcp:read", "protocol": "openid-connect", "attributes": {
                "include.in.token.scope": "true", "display.on.consent.screen": "false",
                "identity-demo-owner": active_profile().owner}})
    for name in ("fixture-gateway-service", "fixture-other-service"):
        _, existing = fixture_request(base, prefix + "/clients?" + urlencode({"clientId": name}), token=token)
        value = {"clientId": name, "enabled": True, "publicClient": False,
            "clientAuthenticatorType": "client-secret", "secret": credentials["adapter_clients"][name],
            "serviceAccountsEnabled": True, "standardFlowEnabled": False,
            "directAccessGrantsEnabled": False, "fullScopeAllowed": False,
            "defaultClientScopes": [], "optionalClientScopes": ["mcp:read"],
            "attributes": {"identity-demo-owner": active_profile().owner},
            "protocolMappers": [{"name": "adapter-audience", "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper", "config": {
                    "included.custom.audience": credentials["adapter_resource"],
                    "access.token.claim": "true", "id.token.claim": "false"}}]}
        if existing:
            if len(existing) != 1 or existing[0].get("attributes", {}).get("identity-demo-owner") != active_profile().owner:
                raise ValueError("Unowned or ambiguous fixture client refused")
            fixture_request(base, prefix + "/clients/" + existing[0]["id"], method="PUT", token=token, value=value)
        else:
            fixture_request(base, prefix + "/clients", method="POST", token=token, value=value)


def setup(args: argparse.Namespace) -> None:
    """Apply only owned adapter resources after checking the cluster and realm."""
    server = oc(args, "config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}")
    if server.rstrip("/") != args.expected_server.rstrip("/"):
        raise ValueError("Target cluster mismatch")
    if args.namespace != "demo-core" or "@sha256:" not in args.jira_image:
        raise ValueError("Exact owned fixture namespace and pinned image required")
    namespace = json.loads(oc(args, "get", "namespace", args.namespace, "-o", "json"))
    if any(namespace["metadata"].get("labels", {}).get(k) != v for k, v in LABELS.items()):
        raise ValueError("Owned fixture namespace required")
    private = Path(args.credentials_file)
    if in_source_checkout(private) or private.stat().st_mode & 0o077:
        raise ValueError("Private credential file outside repository required")
    credentials = json.loads(private.read_text())
    if credentials["namespace"] != args.namespace:
        raise ValueError("Credential namespace mismatch")
    route = json.loads(oc(args, "get", "route", "fixture-keycloak", "-n", args.namespace, "-o", "json"))
    if any(route["metadata"].get("labels", {}).get(k) != v for k, v in LABELS.items()):
        raise ValueError("Owned issuer route required")
    base = "https://" + route["spec"]["host"]
    if base != credentials["keycloak_url"]:
        raise ValueError("Fixture issuer mismatch")
    secret_labels = json.loads(oc(args, "get", "secret", "fixture-credentials", "-n", args.namespace,
                                 "-o", "jsonpath={.metadata.labels}"))
    if any(secret_labels.get(k) != v for k, v in LABELS.items()):
        raise ValueError("Owned fixture backend credential required")
    credentials["adapter_resource"] = f"http://fixture-protected-adapter.{args.namespace}.svc:8083/mcp"
    credentials.setdefault("adapter_clients", {name: secrets.token_urlsafe(32) for name in (
        "fixture-gateway-service", "fixture-other-service")})
    # Persist before administration so reruns reuse credentials if setup is interrupted.
    private.write_text(json.dumps(credentials))
    configure_clients(base, credentials)
    _, jwks = fixture_request(base, "/realms/identity-demo/protocol/openid-connect/certs")
    bootstrap = resource("ConfigMap", "fixture-protected-adapter", args.namespace)
    directory = Path(__file__).resolve().parents[2] / "runtime/identity_demo"
    bootstrap["data"] = {name: (directory / name).read_text() for name in (
        "adapter_auth.py", "adapter_live_auth.py", "start_protected_adapter.py", "probe_protected_adapter.py")}
    bootstrap["data"]["jwks.json"] = json.dumps(jwks)
    apply_owned(args, bootstrap)
    containers = []
    for mode, port in (("streamable-http", 8083), ("sse", 8084)):
        container = {"command": ["python", "/fixtures/start_protected_adapter.py"], "env": [
            {"name": "ADAPTER_ISSUER", "value": base + "/realms/identity-demo"},
            {"name": "ADAPTER_RESOURCE", "value": credentials["adapter_resource"]},
            {"name": "MCP_TRANSPORT", "value": mode}, {"name": "MCP_PORT", "value": str(port)},
            {"name": "JIRA_SERVER", "value": "http://fixture-jira:8080"},
            {"name": "JIRA_USER", "value": "admin"}, {"name": "JIRA_TOKEN", "valueFrom": {
                "secretKeyRef": {"name": "fixture-credentials", "key": "jira-admin"}}},
            {"name": "PYTHONDONTWRITEBYTECODE", "value": "1"},
            {"name": "PYTHONPATH", "value": "/app:/app/src:/fixtures"}],
            "ports": [{"containerPort": port}],
            "volumeMounts": [{"name": "bootstrap", "mountPath": "/fixtures", "readOnly": True}],
            "resources": {"requests": {"cpu": "50m", "memory": "128Mi"},
                          "limits": {"cpu": "300m", "memory": "256Mi"}},
            "readinessProbe": {"tcpSocket": {"port": port}, "initialDelaySeconds": 5}}
        containers.append(container)
    item = deployment(args, "fixture-protected-adapter", args.jira_image, containers[0], [
        {"name": "bootstrap", "configMap": {"name": "fixture-protected-adapter"}}])
    item["spec"]["template"]["metadata"]["annotations"] = {"identity-demo-fixture-config":
        hashlib.sha256(json.dumps(bootstrap["data"], sort_keys=True).encode()).hexdigest()}
    containers[1].update({"name": "adapter-sse", "image": args.jira_image, "imagePullPolicy": "IfNotPresent",
                         "securityContext": {"allowPrivilegeEscalation": False,
                                             "capabilities": {"drop": ["ALL"]}}})
    item["spec"]["template"]["spec"]["containers"].append(containers[1])
    apply_owned(args, item)
    apply_owned(args, service(args, "fixture-protected-adapter", [("streamable", 8083), ("sse", 8084)]))
    print("Owned protected read adapter configured; gateway route unchanged. Public JWKS is a fixture snapshot.")


def main() -> None:
    """Parse explicit fixture inputs without defaulting to the user's cluster."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--expected-server", required=True)
    parser.add_argument("--namespace", default="demo-core")
    parser.add_argument("--credentials-file", required=True)
    parser.add_argument("--jira-image", required=True)
    setup(parser.parse_args())


if __name__ == "__main__":
    main()
