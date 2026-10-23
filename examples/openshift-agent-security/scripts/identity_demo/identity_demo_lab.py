#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Provision owned, isolated component-test fixtures without changing shared services."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess

from deployment_profile import active_profile
from deployment_profile import in_source_checkout

PROFILE = active_profile()
OWNER = PROFILE.owner
LABELS = PROFILE.labels


def oc(args: argparse.Namespace, *command: str, payload: dict | None = None) -> str:
    """Run oc against an explicitly supplied kubeconfig; redact failure bodies."""
    from identity_demo_worker_lease import assert_current
    assert_current()
    completed = subprocess.run(
        ["oc", f"--kubeconfig={args.kubeconfig}", *command],
        input=json.dumps(payload) if payload else None,
        text=True, capture_output=True, check=False,
    )
    if completed.returncode:
        # Secret manifests and HTTP responses must never enter exception output.
        raise RuntimeError(f"oc {command[0]} failed (exit {completed.returncode})")
    return completed.stdout


def resource(kind: str, name: str, namespace: str, spec: dict | None = None) -> dict:
    """Construct a labelled Kubernetes resource for the fixture namespace."""
    api = {"Deployment": "apps/v1", "Route": "route.openshift.io/v1"}.get(kind, "v1")
    metadata = {"name": name, "labels": LABELS.copy()}
    if kind != "Namespace":
        metadata["namespace"] = namespace
    result = {"apiVersion": api, "kind": kind, "metadata": metadata}
    if spec is not None:
        result["spec"] = spec
    return result


def apply_owned(args: argparse.Namespace, item: dict) -> None:
    """Create, or update only resources bearing this fixture's ownership labels."""
    meta = item["metadata"]
    scope = [] if item["kind"] == "Namespace" else ["-n", args.namespace]
    if item["kind"] != "Namespace" and meta["namespace"] != args.namespace:
        raise ValueError("Cross-namespace mutation refused")
    # Both legacy mcp.kagenti.com and current mcp.kuadrant.io CRDs are installed.
    # Always qualify the lookup so ownership is checked against the intended API.
    group = item["apiVersion"].rsplit("/", 1)[0] if "/" in item["apiVersion"] else ""
    query = item["kind"].lower() + ("." + group if group else "")
    current = oc(args, "get", query, meta["name"], *scope, "--ignore-not-found", "-o", "json")
    if current.strip():
        labels = json.loads(current)["metadata"].get("labels", {})
        if any(labels.get(key) != value for key, value in LABELS.items()):
            raise ValueError(f"Refusing unowned {item['kind']}/{meta['name']}")
        oc(args, "apply", "--server-side", "--force-conflicts", "--field-manager=identity-demo-preflight", "-f", "-", payload=item)
    else:
        oc(args, "create", "--field-manager=identity-demo-preflight", "-f", "-", payload=item)
    print(f"Owned {item['kind']}/{meta['name']} ready for reconciliation")


def deployment(args: argparse.Namespace, name: str, image: str, container: dict, volumes: list) -> dict:
    """Construct a single-replica fixture with bounded resource requests."""
    labels = {**LABELS, "app": name}
    container.update({"name": name, "image": image, "imagePullPolicy": "IfNotPresent",
                      "securityContext": {"allowPrivilegeEscalation": False,
                                          "capabilities": {"drop": ["ALL"]}}})
    return resource("Deployment", name, args.namespace, {
        "replicas": 1, "strategy": {"type": "Recreate"},
        "selector": {"matchLabels": {"app": name}},
        "template": {"metadata": {"labels": labels}, "spec": {
            "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [container], "volumes": volumes}},
    })


def service(args: argparse.Namespace, name: str, ports: list[tuple[str, int]]) -> dict:
    """Expose a fixture only as a ClusterIP service."""
    return resource("Service", name, args.namespace, {
        "selector": {"app": name}, "type": "ClusterIP",
        "ports": [{"name": label, "port": number, "targetPort": number} for label, number in ports],
    })


def setup(args: argparse.Namespace) -> None:
    """Create independent Keycloak and strict Jira fixtures using pinned images."""
    for image in (args.keycloak_image, args.jira_image):
        if "@sha256:" not in image:
            raise ValueError("Fixture images must be digest-pinned")
    private = Path(args.credentials_file)
    if in_source_checkout(private):
        raise ValueError("Credential file must be outside the repository")
    if private.exists():
        credentials = json.loads(private.read_text())
        if credentials["namespace"] != args.namespace:
            raise ValueError("Credential namespace mismatch")
    else:
        credentials = {"namespace": args.namespace, **{
            key: secrets.token_urlsafe(32) for key in ("keycloak_admin", "analyst", "viewer", "jira_admin")}}
        fd = os.open(private, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(credentials, stream)
    if private.stat().st_mode & 0o077:
        raise ValueError("Credential file must be private (mode 0600)")
    apply_owned(args, resource("Namespace", args.namespace, args.namespace))
    network = resource("NetworkPolicy", "fixture-isolation", args.namespace)
    network["apiVersion"] = "networking.k8s.io/v1"
    network["spec"] = {
        "podSelector": {}, "policyTypes": ["Ingress", "Egress"],
        "ingress": [{"from": [{"podSelector": {}}]}],
        "egress": [
            {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": args.namespace}}}]},
            {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "openshift-dns"}}}],
             "ports": [{"port": port, "protocol": protocol}
                       for port in (53, 5353) for protocol in ("UDP", "TCP")]},
        ],
    }
    apply_owned(args, network)
    router_ingress = resource("NetworkPolicy", "keycloak-route-ingress", args.namespace)
    router_ingress["apiVersion"] = "networking.k8s.io/v1"
    router_ingress["spec"] = {"podSelector": {"matchLabels": {"app": "fixture-keycloak"}},
        "policyTypes": ["Ingress"], "ingress": [{"from": [{"namespaceSelector": {
            "matchLabels": {"kubernetes.io/metadata.name": "openshift-ingress"}}}],
            "ports": [{"port": 8080, "protocol": "TCP"}]}]}
    apply_owned(args, router_ingress)
    apply_owned(args, service(args, "fixture-keycloak", [("http", 8080)]))
    apply_owned(args, resource("Route", "fixture-keycloak", args.namespace, {
        "to": {"kind": "Service", "name": "fixture-keycloak"}, "port": {"targetPort": "http"},
        "tls": {"termination": "edge", "insecureEdgeTerminationPolicy": "Redirect"}}))
    host = oc(args, "get", "route", "fixture-keycloak", "-n", args.namespace,
              "-o", "jsonpath={.spec.host}").strip()
    if not host:
        raise RuntimeError("Owned Keycloak route has no assigned hostname")
    credentials["keycloak_url"] = "https://" + host
    private.write_text(json.dumps(credentials))
    realm = {"realm": "identity-demo", "enabled": True, "sslRequired": "external",
             "registrationAllowed": False, "resetPasswordAllowed": False,
             "accessTokenLifespan": 60, "roles": {"realm": [{"name": "analyst"}, {"name": "viewer"}]},
             "users": [{"username": name, "enabled": True, "emailVerified": True,
                        "email": f"{name}@example.invalid", "firstName": name, "lastName": "Synthetic",
                        "realmRoles": [name], "credentials": [{"type": "password", "temporary": False,
                                                               "value": credentials[name]}]}
                       for name in ("analyst", "viewer")],
             "clients": [{"clientId": "identity-demo-ui", "enabled": True, "publicClient": True,
                          "standardFlowEnabled": True, "directAccessGrantsEnabled": False,
                          "redirectUris": ["http://127.0.0.1:18085/callback"],
                          "attributes": {"pkce.code.challenge.method": "S256"},
                          "protocolMappers": [{"name": "mcp-audience", "protocol": "openid-connect",
                              "protocolMapper": "oidc-audience-mapper", "config": {
                                  "included.custom.audience": "identity-demo-mcp",
                                  "access.token.claim": "true", "id.token.claim": "false"}}]}]}
    secret = resource("Secret", "fixture-credentials", args.namespace)
    secret.update({"type": "Opaque", "stringData": {"keycloak-admin": credentials["keycloak_admin"],
        "jira-admin": credentials["jira_admin"], "realm.json": json.dumps(realm)}})
    apply_owned(args, secret)
    def env(name: str, value: str) -> dict:
        return {"name": name, "value": value}
    def secret_env(name: str, key: str) -> dict:
        return {"name": name, "valueFrom": {"secretKeyRef": {"name": "fixture-credentials", "key": key}}}
    keycloak = {
        "args": ["start-dev", "--import-realm"],
        "env": [env("KC_BOOTSTRAP_ADMIN_USERNAME", "fixture-admin"),
                secret_env("KC_BOOTSTRAP_ADMIN_PASSWORD", "keycloak-admin"),
                env("KC_HTTP_PORT", "8080"), env("KC_HOSTNAME_STRICT", "false"),
                env("KC_HOSTNAME", credentials["keycloak_url"]), env("KC_PROXY_HEADERS", "xforwarded"),
                env("KC_FEATURES", "spiffe"),
                env("KC_HEALTH_ENABLED", "true"), env("JAVA_OPTS_APPEND", "-Xms128m -Xmx512m")],
        "ports": [{"containerPort": 8080}],
        "resources": {"requests": {"cpu": "150m", "memory": "768Mi"},
                      "limits": {"cpu": "1", "memory": "1Gi"}},
        "volumeMounts": [{"name": "realm", "mountPath": "/opt/keycloak/data/import", "readOnly": True},
                         {"name": "data", "mountPath": "/opt/keycloak/data"}],
        "readinessProbe": {"httpGet": {"path": "/realms/identity-demo/.well-known/openid-configuration", "port": 8080},
                           "initialDelaySeconds": 20, "periodSeconds": 10},
    }
    apply_owned(args, deployment(args, "fixture-keycloak", args.keycloak_image, keycloak, [
        {"name": "realm", "secret": {"secretName": "fixture-credentials", "items": [{"key": "realm.json", "path": "realm.json"}]}},
        {"name": "data", "emptyDir": {}}]))
    apply_owned(args, service(args, "fixture-keycloak", [("http", 8080)]))
    bootstrap = resource("ConfigMap", "jira-fixture-bootstrap", args.namespace)
    bootstrap["data"] = {"start_jira_fixture.py": (
        Path(__file__).resolve().parents[2] / "tests/identity_demo/start_jira_fixture.py").read_text()}
    apply_owned(args, bootstrap)
    jira = {"env": [env("AUTH_MODE", "strict"), secret_env("ADMIN_PASSWORD", "jira-admin"),
                    env("JIRA_SERVER", "http://127.0.0.1:8080"), env("JIRA_USER", "admin"),
                    secret_env("JIRA_TOKEN", "jira-admin"),
                    env("SEED_DATA", "true"), env("BASE_URL", "http://fixture-jira:8080"),
                    env("PYTHONDONTWRITEBYTECODE", "1"), env("WEBHOOKS_ENABLED", "false"),
                    env("LOG_LEVEL", "WARNING"), env("PYTHONPATH", "/app:/app/src")],
            "command": ["python", "/fixtures/start_jira_fixture.py"],
            "ports": [{"containerPort": 8080}, {"containerPort": 8081}],
            "resources": {"requests": {"cpu": "100m", "memory": "256Mi"},
                          "limits": {"cpu": "500m", "memory": "512Mi"}},
            "volumeMounts": [{"name": "data", "mountPath": "/data"},
                             {"name": "bootstrap", "mountPath": "/fixtures", "readOnly": True}],
            "readinessProbe": {"tcpSocket": {"port": 8080}, "initialDelaySeconds": 10}}
    jira_deployment = deployment(args, "fixture-jira", args.jira_image, jira, [
        {"name": "data", "emptyDir": {}}, {"name": "bootstrap", "configMap": {"name": "jira-fixture-bootstrap"}}])
    for transport, port in (("sse", 8081), ("streamable-http", 8082)):
        jira_deployment["spec"]["template"]["spec"]["containers"].append({
            "name": f"adapter-{transport}", "image": args.jira_image,
            "command": ["python", "-c", (
                'import asyncio; from mcp_servers.atlassian_jira import mcp; '
                'tools=asyncio.run(mcp.list_tools()); '
                '[mcp.remove_tool(t.name) for t in tools if t.name not in '
                '("searchJiraIssuesUsingJql", "getJiraIssue")]; '
                f'mcp.run(transport="{transport}")')],
            "env": [env("JIRA_SERVER", "http://127.0.0.1:8080"), env("JIRA_USER", "admin"),
                    secret_env("JIRA_TOKEN", "jira-admin"), env("MCP_HOST", "0.0.0.0"), env("MCP_PORT", str(port)),
                    env("PYTHONDONTWRITEBYTECODE", "1")],
            "ports": [{"containerPort": port}],
            "resources": {"requests": {"cpu": "50m", "memory": "128Mi"},
                          "limits": {"cpu": "300m", "memory": "256Mi"}},
            "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
        })
    apply_owned(args, jira_deployment)
    apply_owned(args, service(args, "fixture-jira", [("rest", 8080), ("sse", 8081), ("streamable", 8082)]))
    print("Fixtures created. Synthetic and ephemeral; Keycloak has an owned HTTPS route, Jira is ClusterIP-only.")


def main() -> None:
    """Validate the target cluster and provision only the owned namespace."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--expected-server", required=True)
    parser.add_argument("--namespace", default="demo-core")
    parser.add_argument("--credentials-file", required=True)
    parser.add_argument("--keycloak-image", required=True)
    parser.add_argument("--jira-image", required=True)
    args = parser.parse_args()
    if args.namespace in ("default", "other-team", "keycloak", "openshell", "mcp-system", "openshift-operators"):
        raise ValueError("Shared namespace refused")
    server = oc(args, "config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}")
    if server.rstrip("/") != args.expected_server.rstrip("/"):
        raise ValueError("Target cluster mismatch")
    setup(args)


if __name__ == "__main__":
    main()
