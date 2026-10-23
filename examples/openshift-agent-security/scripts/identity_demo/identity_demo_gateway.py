#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Create only an owned Gateway for compatibility tests using the installed class."""

from __future__ import annotations

import argparse
import copy
import json
from urllib.parse import urlparse

from identity_demo_lab import LABELS, apply_owned, oc, resource


def main() -> None:
    """Create an internal Gateway and its narrowly scoped network dependencies."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--expected-server", required=True)
    parser.add_argument("--namespace", default="demo-core")
    parser.add_argument("--extend-mcp", action="store_true")
    parser.add_argument("--keycloak-url")
    parser.add_argument("--oauth-resource-url", help="Owned HTTPS gateway URI for discovery tests")
    args = parser.parse_args()
    server = oc(args, "config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}")
    if server != args.expected_server:
        raise ValueError("Target cluster mismatch")
    namespace = json.loads(oc(args, "get", "namespace", args.namespace, "-o", "json"))
    if any(namespace["metadata"].get("labels", {}).get(k) != v for k, v in LABELS.items()):
        raise ValueError("Owned fixture namespace required")
    audience = "identity-demo-mcp"
    broker_host = "fixture-mcp.local"
    if args.oauth_resource_url:
        parsed = urlparse(args.oauth_resource_url)
        if (not args.extend_mcp or not args.keycloak_url or parsed.scheme != "https"
                or parsed.path != "/mcp" or parsed.query or parsed.fragment or parsed.username
                or parsed.password or parsed.port not in (None, 443)):
            raise ValueError("Owned HTTPS MCP resource and issuer required")
        route = json.loads(oc(args, "get", "route", "fixture-mcp", "-n", args.namespace, "-o", "json"))
        if (route["spec"]["host"] != parsed.hostname or any(
                route["metadata"].get("labels", {}).get(k) != v for k, v in LABELS.items())):
            raise ValueError("OAuth resource must match the owned gateway route")
        audience, broker_host = args.oauth_resource_url, parsed.hostname
    network = resource("NetworkPolicy", "fixture-gateway-control-plane", args.namespace)
    network["apiVersion"] = "networking.k8s.io/v1"
    network["spec"] = {"podSelector": {"matchLabels": {"gateway.networking.k8s.io/gateway-name": "fixture-mcp"}},
        "policyTypes": ["Egress"], "egress": [
            {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "openshift-ingress"}}}],
             "ports": [{"port": 15012, "protocol": "TCP"}]},
            {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kuadrant-system"}},
                     "podSelector": {"matchLabels": {"authorino-resource": "authorino"}}}],
             "ports": [{"port": 50051, "protocol": "TCP"}, {"port": 50052, "protocol": "TCP"}]},
            {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "openshift-operators"}},
                     "podSelector": {"matchLabels": {"app": "kuadrant", "control-plane": "controller-manager"}}}],
             "ports": [{"port": 8082, "protocol": "TCP"}]},
        ]}
    apply_owned(args, network)
    health = resource("NetworkPolicy", "fixture-mcp-controller-health", args.namespace)
    health["apiVersion"] = "networking.k8s.io/v1"
    health["spec"] = {"podSelector": {"matchLabels": {"app.kubernetes.io/name": "mcp-gateway"}},
        "policyTypes": ["Ingress"], "ingress": [{"from": [{
            "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "openshift-operators"}},
            "podSelector": {"matchLabels": {"app": "mcp-controller", "component": "controller"}}}],
            "ports": [{"port": 8080, "protocol": "TCP"}]}]}
    apply_owned(args, health)
    gateway = resource("Gateway", "fixture-mcp", args.namespace)
    gateway["apiVersion"] = "gateway.networking.k8s.io/v1"
    gateway["metadata"]["labels"]["istio.io/rev"] = "openshift-gateway"
    gateway["metadata"]["annotations"] = {"networking.istio.io/service-type": "ClusterIP",
        "opendatahub.io/managed": "false",
        "security.opendatahub.io/authorino-tls-bootstrap": "true"}
    gateway["spec"] = {"gatewayClassName": "openshift-ai-inference",
        "infrastructure": {"labels": LABELS,
                           "annotations": {"networking.istio.io/service-type": "ClusterIP"}},
        "listeners": [
            {"name": "mcp", "protocol": "HTTP", "port": 8080,
             "allowedRoutes": {"namespaces": {"from": "Same"}}},
            {"name": "mcps", "protocol": "HTTP", "port": 8080, "hostname": "*.fixture-mcp.local",
             "allowedRoutes": {"namespaces": {"from": "Same"}}},
        ]}
    apply_owned(args, gateway)
    if args.extend_mcp:
        generated = json.loads(oc(args, "get", "service", "fixture-mcp-openshift-ai-inference",
                                  "-n", args.namespace, "-o", "json"))
        if generated["spec"]["type"] != "ClusterIP":
            raise ValueError("Gateway must remain internal before MCP extension")
        extension = resource("MCPGatewayExtension", "fixture-mcp", args.namespace)
        extension["apiVersion"] = "mcp.kuadrant.io/v1alpha1"
        extension["spec"] = {"targetRef": {"group": "gateway.networking.k8s.io", "kind": "Gateway",
            "name": "fixture-mcp", "namespace": args.namespace, "sectionName": "mcp"},
            "privateHost": f"fixture-mcp-openshift-ai-inference.{args.namespace}.svc.cluster.local:8080",
            "publicHost": broker_host, "httpRouteManagement": "Enabled",
            "backendPingIntervalSeconds": 60, "urlElicitation": "Disabled"}
        if args.oauth_resource_url:
            extension["spec"]["oauthProtectedResource"] = {
                "resource": args.oauth_resource_url,
                "authorizationServers": [args.keycloak_url + "/realms/identity-demo"],
                "scopesSupported": ["openid"], "bearerMethodsSupported": ["header"],
                "resourceName": "Synthetic identity demo MCP Gateway"}
        apply_owned(args, extension)
        route = resource("HTTPRoute", "fixture-jira", args.namespace)
        route["apiVersion"] = "gateway.networking.k8s.io/v1"
        route["spec"] = {"parentRefs": [{"name": "fixture-mcp", "sectionName": "mcps"}],
            "hostnames": ["jira.fixture-mcp.local"], "rules": [{
                "matches": [{"path": {"type": "PathPrefix", "value": "/mcp"}}],
                "backendRefs": [{"name": "fixture-jira", "port": 8082}]}]}
        apply_owned(args, route)
        registration = resource("MCPServerRegistration", "fixture-jira", args.namespace)
        registration["apiVersion"] = "mcp.kuadrant.io/v1alpha1"
        registration["spec"] = {"targetRef": {"group": "gateway.networking.k8s.io", "kind": "HTTPRoute",
            "name": "fixture-jira"}, "path": "/mcp", "prefix": "jira_", "userSpecificList": "Disabled",
            "hint": "Synthetic read-only Jira tools for identity preflight"}
        apply_owned(args, registration)
    if args.keycloak_url:
        if not args.keycloak_url.startswith("https://fixture-keycloak-demo-core."):
            raise ValueError("Expected the owned Keycloak HTTPS route")
        policy = resource("AuthPolicy", "fixture-mcp-auth", args.namespace)
        policy["apiVersion"] = "kuadrant.io/v1"
        policy["spec"] = {"targetRef": {"group": "gateway.networking.k8s.io", "kind": "Gateway",
            "name": "fixture-mcp", "sectionName": "mcp"}, "rules": {
            "authentication": {"keycloak": {"jwt": {"issuerUrl": args.keycloak_url + "/realms/identity-demo"}}},
            "authorization": {
                "issuer": {"patternMatching": {"patterns": [{"predicate":
                    "has(auth.identity.iss) && auth.identity.iss == " +
                    json.dumps(args.keycloak_url + "/realms/identity-demo")}]}},
                "audience": {"patternMatching": {"patterns": [{"predicate":
                    "has(auth.identity.aud) && (auth.identity.aud == " + json.dumps(audience) + " || "
                    "(type(auth.identity.aud) == list && " + json.dumps(audience) + " in auth.identity.aud))"}]}},
                "request-inspection": {"opa": {"allValues": True, "rego": (
                    'allow = true\n'
                    'body_present := object.get(input.context.request.http, "body", "") != ""\n'
                    'raw_body_present := object.get(input.context.request.http, "raw_body", "") != ""\n'
                    'raw_body_camel_present := object.get(input.context.request.http, "rawBody", "") != ""\n'
                    'tool_name := object.get(input.context.request.http.headers, "x-mcp-toolname", "")\n')}, "priority": 1},
            },
            "response": {"success": {"headers": {
                "x-identity-demo-body-present": {"plain": {"expression":
                    "string(auth.authorization['request-inspection'].body_present)"}},
                "x-identity-demo-tool": {"plain": {"expression":
                    "auth.authorization['request-inspection'].tool_name"}},
            }}},
        }}
        if args.oauth_resource_url:
            # Public GET metadata only. This exception must never reach the
            # backend listener or allow POST/DELETE/tool requests.
            policy["spec"]["when"] = [{"predicate": (
                "!(request.method == 'GET' && request.path in "
                "['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp'])")}]
            policy["spec"]["rules"]["response"]["unauthenticated"] = {"code": 401, "headers": {
                "WWW-Authenticate": {"value": "Bearer resource_metadata=" +
                    args.oauth_resource_url.removesuffix("/mcp") + "/.well-known/oauth-protected-resource/mcp"}}}
        apply_owned(args, policy)
        tools_policy = copy.deepcopy(policy)
        tools_policy["metadata"]["name"] = "fixture-mcp-tools-auth"
        tools_policy["spec"]["targetRef"]["sectionName"] = "mcps"
        tools_policy["spec"].pop("when", None)
        apply_owned(args, tools_policy)
    print("Gateway created for reconciliation; verify its generated Service type before adding an MCP extension.")


if __name__ == "__main__":
    main()
