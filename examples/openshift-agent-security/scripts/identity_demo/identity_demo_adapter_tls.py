#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Add a service-certified read-only adapter experiment within our namespace."""

from __future__ import annotations
from deployment_profile import active_profile

import argparse
import copy
import hashlib
import json
from pathlib import Path
from urllib.parse import urlparse

from identity_demo_adapter import fixture_request
from identity_demo_lab import LABELS, apply_owned, oc, resource
from deployment_profile import in_source_checkout


def owned(args: argparse.Namespace, kind: str, name: str) -> dict:
    """Read a fixture object and refuse an unowned namespace or resource."""
    scope = [] if kind == "namespace" else ["-n", args.namespace]
    item = json.loads(oc(args, "get", kind, name, *scope, "-o", "json"))
    if any(item["metadata"].get("labels", {}).get(k) != v for k, v in LABELS.items()):
        raise ValueError("Owned fixture resource required")
    return item


def setup(args: argparse.Namespace) -> None:
    """Leave Keycloak, shared resources and the gateway backend route intact."""
    actual = oc(args, "config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}")
    if actual.rstrip("/") != args.expected_server.rstrip("/") or args.namespace != "demo-core":
        raise ValueError("Expected cluster and exact owned namespace required")
    owned(args, "namespace", args.namespace)
    dep = owned(args, "deployment", "fixture-protected-adapter")
    svc = owned(args, "service", "fixture-protected-adapter")
    bootstrap = owned(args, "configmap", "fixture-protected-adapter")
    issuer_route = owned(args, "route", "fixture-keycloak")
    path = Path(args.credentials_file)
    if path.stat().st_mode & 0o077 or in_source_checkout(path):
        raise ValueError("Private credential file outside repository required")
    credentials = json.loads(path.read_text())
    base = credentials["keycloak_url"]
    if credentials["namespace"] != args.namespace or urlparse(base).hostname != issuer_route["spec"]["host"]:
        raise ValueError("Owned fixture issuer mismatch")
    cert_name = "fixture-protected-adapter-tls"
    # Only metadata is fetched: certificate private keys never enter diagnostics.
    certificate = oc(args, "get", "secret", cert_name, "-n", args.namespace, "--ignore-not-found",
                     "-o", "jsonpath={.metadata}")
    if certificate.strip():
        refs = json.loads(certificate).get("ownerReferences", [])
        if not any(ref.get("uid") == svc["metadata"]["uid"] and ref.get("kind") == "Service" for ref in refs):
            raise ValueError("Existing serving certificate is not owned by our Service")
    router = json.loads(oc(args, "get", "service", "router-internal-default", "-n", "openshift-ingress",
                           "-o", "json"))
    if not router["spec"].get("clusterIP") or router["spec"]["clusterIP"] == "None":
        raise ValueError("Internal router ClusterIP required")
    audience = f"https://fixture-protected-adapter.{args.namespace}.svc:8443/mcp"
    _, admin = fixture_request(base, "/realms/master/protocol/openid-connect/token", method="POST", fields={
        "grant_type": "password", "client_id": "admin-cli", "username": "fixture-admin",
        "password": credentials["keycloak_admin"]})
    for client in ("fixture-gateway-service", "fixture-other-service"):
        _, items = fixture_request(base, "/admin/realms/identity-demo/clients?clientId=" + client,
                                   token=admin["access_token"])
        if len(items) != 1 or items[0].get("attributes", {}).get("identity-demo-owner") != active_profile().owner:
            raise ValueError("Owned service client required")
        value = items[0]
        maps = [m for m in value.get("protocolMappers", []) if m.get("name") != "adapter-https-audience"]
        maps.append({"name": "adapter-https-audience", "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper", "config": {"included.custom.audience": audience,
                "access.token.claim": "true", "id.token.claim": "false"}})
        value["protocolMappers"] = maps
        fixture_request(base, "/admin/realms/identity-demo/clients/" + value["id"],
                        method="PUT", token=admin["access_token"], value=value)
    credentials["adapter_tls_resource"] = audience
    path.write_text(json.dumps(credentials))
    serving = resource("Service", "fixture-protected-adapter", args.namespace)
    serving["metadata"]["annotations"] = {"service.beta.openshift.io/serving-cert-secret-name": cert_name}
    serving["spec"] = {"type": "ClusterIP", "selector": svc["spec"]["selector"],
        "ports": [p for p in svc["spec"]["ports"] if p.get("name") != "https"] +
                 [{"name": "https", "port": 8443, "targetPort": 8443}]}
    apply_owned(args, serving)
    ca = resource("ConfigMap", "fixture-service-ca", args.namespace)
    ca["metadata"]["annotations"] = {"service.beta.openshift.io/inject-cabundle": "true"}
    apply_owned(args, ca)
    egress = resource("NetworkPolicy", "fixture-adapter-jwks", args.namespace)
    egress["apiVersion"] = "networking.k8s.io/v1"
    egress["spec"] = {"podSelector": {"matchLabels": {"app": "fixture-protected-adapter"}},
        "policyTypes": ["Egress"], "egress": [{"to": [{
            "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "openshift-ingress"}},
            "podSelector": {"matchLabels": router["spec"]["selector"]}}],
            "ports": [{"port": 443, "protocol": "TCP"}]}]}
    apply_owned(args, egress)
    directory = Path(__file__).resolve().parents[2] / "runtime/identity_demo"
    cm = resource("ConfigMap", "fixture-protected-adapter", args.namespace)
    cm["data"] = dict(bootstrap["data"])
    for name in ("adapter_auth.py", "adapter_live_auth.py", "start_protected_adapter.py",
                 "probe_adapter_tls.py", "response_evidence.py"):
        cm["data"][name] = (directory / name).read_text()
    apply_owned(args, cm)
    item = resource("Deployment", "fixture-protected-adapter", args.namespace)
    item["spec"] = copy.deepcopy(dep["spec"])
    pod = item["spec"]["template"]["spec"]
    original = next(c for c in pod["containers"] if c["name"] == "fixture-protected-adapter")
    tls = copy.deepcopy(original)
    tls["name"] = "adapter-https"
    values = {"ADAPTER_RESOURCE": audience, "MCP_TRANSPORT": "streamable-http", "MCP_PORT": "8443",
              "ADAPTER_LIVE_JWKS": "1", "MCP_TLS_CERTFILE": "/tls/tls.crt", "MCP_TLS_KEYFILE": "/tls/tls.key"}
    tls["env"] = [v for v in tls["env"] if v["name"] not in values] + [
        {"name": name, "value": value} for name, value in values.items()]
    tls["ports"] = [{"containerPort": 8443}]
    tls["readinessProbe"] = {"tcpSocket": {"port": 8443}, "initialDelaySeconds": 5}
    tls["volumeMounts"] += [{"name": "tls", "mountPath": "/tls", "readOnly": True},
                            {"name": "service-ca", "mountPath": "/service-ca", "readOnly": True}]
    pod["containers"] = [c for c in pod["containers"] if c["name"] != "adapter-https"] + [tls]
    pod["volumes"] = [v for v in pod["volumes"] if v["name"] not in ("tls", "service-ca")] + [
        {"name": "tls", "secret": {"secretName": cert_name}},
        {"name": "service-ca", "configMap": {"name": "fixture-service-ca"}}]
    aliases = [a for a in pod.get("hostAliases", []) if base.removeprefix("https://") not in a["hostnames"]]
    pod["hostAliases"] = aliases + [{"ip": router["spec"]["clusterIP"], "hostnames": [urlparse(base).hostname]}]
    item["spec"]["template"]["metadata"].setdefault("annotations", {})["identity-demo-fixture-config"] = (
        hashlib.sha256(json.dumps(cm["data"], sort_keys=True).encode()).hexdigest())
    apply_owned(args, item)
    print("Owned adapter HTTPS/live-JWKS experiment configured; baseline gateway route unchanged")


def main() -> None:
    """Require explicit context; no shared-resource mutation is supported."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--expected-server", required=True)
    parser.add_argument("--namespace", default="demo-core")
    parser.add_argument("--credentials-file", required=True)
    setup(parser.parse_args())


if __name__ == "__main__":
    main()
