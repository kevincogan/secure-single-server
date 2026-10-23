#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stage an owned upstream development issuer without changing the current issuer.

Realm exports, passwords, logs and creation ledgers remain in a private directory.
The retained RHBK deployment, PVC and public Route are never patched here.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import unquote, urlencode
from urllib.parse import urlparse
from urllib.request import ProxyHandler, Request, build_opener

from identity_demo_adapter import NoFixtureRedirect, fixture_request
from identity_demo_keycloak_recovery import command, resource, write_private
from identity_demo_lab import LABELS
from identity_demo_runtime import NAMESPACE, admin_token, guard
from identity_demo_spire_network import NAMESPACE as INFRA_NAMESPACE
from deployment_profile import active_profile
from deployment_profile import in_source_checkout

NAME = "fixture-keycloak-upstream"
IMAGE = "quay.io/keycloak/keycloak@sha256:27b3230fbabb8c9ff3c66c864cf09dcd8a41aca82e5100679d109ef0eeb05741"
BASE = active_profile().origin("fixture-keycloak-upstream")


def issuer_request(
    base: str,
    path: str,
    *,
    method: str = "GET",
    token: str | None = None,
    fields: dict | None = None,
    value: Any = None,
) -> tuple[int, Any]:
    """Call only the approved parallel issuer with verified TLS and no redirects."""
    parsed_path = urlparse(path)
    if (
        base != BASE
        or parsed_path.scheme
        or parsed_path.netloc
        or parsed_path.fragment
        or "\\" in parsed_path.path
        or ".." in unquote(parsed_path.path).split("/")
        or not path.startswith(
            ("/admin/realms/identity-demo/", "/realms/identity-demo/")
        )
        and path not in ("/realms/master/protocol/openid-connect/token", "/realms/identity-demo/protocol/openid-connect/token")
        or method not in ("GET", "POST", "PUT", "DELETE")
    ):
        raise ValueError("Exact approved development issuer and realm required")
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
    client = build_opener(ProxyHandler({}), NoFixtureRedirect())
    try:
        with client.open(
            Request(base + path, data=data, headers=headers, method=method), timeout=20
        ) as response:
            body = response.read(2_000_001)
            if len(body) > 2_000_000:
                raise ValueError("Bounded issuer response required")
            return response.status, json.loads(body) if body else None
    except HTTPError as error:
        raise RuntimeError(
            f"Approved development issuer rejected request (HTTP {error.code})"
        ) from None


def workspace(args: argparse.Namespace) -> Path:
    """Refuse public, shared or symlinked storage for credential artifacts."""
    guard(args)
    owned(json.loads(command(args, "get", "namespace", INFRA_NAMESPACE, "-o", "json")))
    path = Path(args.workspace_dir)
    if (
        path.is_symlink()
        or not path.is_dir()
        or path.stat().st_mode & 0o077
        or in_source_checkout(path)
    ):
        raise ValueError("Private owned workspace outside repository required")
    return path


def owned(value: dict[str, Any]) -> None:
    """Require the established labels before reading a dependency or operand."""
    if any(value["metadata"].get("labels", {}).get(k) != v for k, v in LABELS.items()):
        raise ValueError("Owned resource required")


def prepare(args: argparse.Namespace) -> dict[str, Any]:
    """Prepare a fresh synthetic realm and independent deployment for review."""
    directory = workspace(args)
    _, credentials, base = guard(args)
    old = json.loads(
        command(
            args, "get", "deployment", "fixture-keycloak", "-n", NAMESPACE, "-o", "json"
        )
    )
    old_route = json.loads(
        command(args, "get", "route", "fixture-keycloak", "-n", NAMESPACE, "-o", "json")
    )
    owned(old)
    owned(old_route)
    recovery = Path(args.recovery_realm)
    if (
        recovery.is_symlink()
        or recovery.stat().st_mode & 0o077
        or in_source_checkout(recovery)
    ):
        raise ValueError("Private verified recovery realm required")
    original = json.loads(recovery.read_text())
    if original.get("realm") != "identity-demo":
        raise ValueError("Owned synthetic realm required")
    token = admin_token(base, credentials)
    prefix = "/admin/realms/identity-demo"
    _, exported = fixture_request(
        base,
        prefix + "/partial-export?exportClients=true&exportGroupsAndRoles=true",
        method="POST",
        token=token,
    )
    _, clients = fixture_request(base, prefix + "/clients", token=token)
    if {c["clientId"] for c in clients} != {
        c["clientId"] for c in original["clients"]
    } or exported["realm"] != "identity-demo":
        raise ValueError("Current realm differs from the reviewed identity inventory")
    original_clients = {c["clientId"]: c for c in original["clients"]}
    for client in exported["clients"]:
        source = original_clients[client["clientId"]]
        if client["id"] != source["id"]:
            raise ValueError("A recorded client identity changed")
        if client.get("secret") == "**********":
            _, current = fixture_request(
                base,
                prefix + "/clients/" + client["id"] + "/client-secret",
                token=token,
            )
            if not isinstance(current.get("value"), str) or not current["value"]:
                raise ValueError("Current service secret unavailable")
            client["secret"] = current["value"]
    exported["users"] = copy.deepcopy(original["users"])
    for user in exported["users"]:
        _, current = fixture_request(base, prefix + "/users/" + user["id"], token=token)
        if current["username"] != user["username"]:
            raise ValueError("Recorded user identity changed")
        _, mappings = fixture_request(
            base, prefix + "/users/" + user["id"] + "/role-mappings", token=token
        )
        user["realmRoles"] = [
            role["name"] for role in mappings.get("realmMappings", [])
        ]
        user["clientRoles"] = {
            name: [role["name"] for role in entry.get("mappings", [])]
            for name, entry in mappings.get("clientMappings", {}).items()
        }
    if "**********" in json.dumps(exported):
        raise ValueError("Masked export cannot be used for recovery")
    # A separate issuer has a distinct origin; the original remains intact.
    parsed = urlparse(base)
    original_host = str(parsed.hostname)
    if not original_host.startswith("fixture-keycloak-" + NAMESPACE + "."):
        raise ValueError("Exact current owned issuer host required")
    host = NAME + "-" + NAMESPACE + "." + original_host.split(".", 1)[1]
    new_base = "https://" + host
    original_ca_name = next(
        v["configMap"]["name"]
        for v in old["spec"]["template"]["spec"]["volumes"]
        if v["name"] == "service-ca"
    )
    ca_value = json.loads(
        command(
            args, "get", "configmap", original_ca_name, "-n", NAMESPACE, "-o", "json"
        )
    )
    root = ca_value["data"]["service-ca.crt"]
    if "BEGIN CERTIFICATE" not in root:
        raise ValueError("Current service CA unavailable")

    secret = resource("v1", "Secret", NAME + "-realm")
    secret.update(type="Opaque", stringData={"realm.json": json.dumps(exported)})
    ca = resource("v1", "ConfigMap", NAME + "-service-ca")
    ca["metadata"]["annotations"] = {
        "service.beta.openshift.io/inject-cabundle": "true"
    }
    pvc = resource("v1", "PersistentVolumeClaim", NAME + "-data")
    pvc["spec"] = {
        "accessModes": ["ReadWriteOnce"],
        "storageClassName": "gp3-csi",
        "resources": {"requests": {"storage": "1Gi"}},
    }
    service = resource("v1", "Service", NAME)
    service["metadata"]["annotations"] = {
        "service.beta.openshift.io/serving-cert-secret-name": NAME + "-tls"
    }
    service["spec"] = {
        "selector": {"app": NAME},
        "ports": [{"name": "https", "port": 8443, "targetPort": 8443}],
    }
    deploy = resource("apps/v1", "Deployment", NAME)
    spec = copy.deepcopy(old["spec"]["template"]["spec"])
    spec.update(automountServiceAccountToken=False)
    container = spec["containers"][0]
    container["image"] = IMAGE
    replaced = {
        "KC_HTTP_PORT",
        "KC_HOSTNAME",
        "KC_HOSTNAME_STRICT",
        "KC_HTTP_ENABLED",
        "KC_PROXY_HEADERS",
        "KC_HTTPS_CERTIFICATE_FILE",
        "KC_HTTPS_CERTIFICATE_KEY_FILE",
        "KC_HEALTH_ENABLED",
    }
    container["env"] = [env for env in container["env"] if env["name"] not in replaced]
    container["env"].extend(
        [
            {"name": name, "value": value}
            for name, value in {
                "KC_HOSTNAME": new_base,
                "KC_HOSTNAME_STRICT": "true",
                "KC_HTTP_ENABLED": "false",
                "KC_PROXY_HEADERS": "xforwarded",
                "KC_HTTPS_CERTIFICATE_FILE": "/etc/keycloak/serving-tls/tls.crt",
                "KC_HTTPS_CERTIFICATE_KEY_FILE": "/etc/keycloak/serving-tls/tls.key",
            }.items()
        ]
    )
    container["ports"] = [{"name": "https", "containerPort": 8443}]
    container["readinessProbe"] = {
        "tcpSocket": {"port": 8443},
        "periodSeconds": 5,
        "timeoutSeconds": 1,
    }
    container.pop("livenessProbe", None)
    container["volumeMounts"] = [
        {"name": "realm", "mountPath": "/opt/keycloak/data/import", "readOnly": True},
        {"name": "data", "mountPath": "/opt/keycloak/data"},
        {
            "name": "service-ca",
            "mountPath": "/etc/keycloak/service-ca",
            "readOnly": True,
        },
        {
            "name": "serving-tls",
            "mountPath": "/etc/keycloak/serving-tls",
            "readOnly": True,
        },
    ]
    spec["volumes"] = [
        {
            "name": "realm",
            "secret": {
                "secretName": NAME + "-realm",
                "items": [{"key": "realm.json", "path": "realm.json"}],
            },
        },
        {"name": "data", "persistentVolumeClaim": {"claimName": NAME + "-data"}},
        {"name": "service-ca", "configMap": {"name": NAME + "-service-ca"}},
        {"name": "serving-tls", "secret": {"secretName": NAME + "-tls"}},
    ]
    template_meta = {
        "labels": {**LABELS, "app": NAME},
        "annotations": {
            "openshift.io/required-scc": "restricted-v2",
            "identity-demo-realm-sha256": hashlib.sha256(
                json.dumps(exported, sort_keys=True).encode()
            ).hexdigest(),
        },
    }
    deploy["spec"] = {
        "replicas": 1,
        "strategy": {"type": "Recreate"},
        "selector": {"matchLabels": {"app": NAME}},
        "template": {"metadata": template_meta, "spec": spec},
    }
    route = resource("route.openshift.io/v1", "Route", NAME)
    route["spec"] = {
        "host": host,
        "to": {"kind": "Service", "name": NAME},
        "port": {"targetPort": "https"},
        "tls": {
            "termination": "reencrypt",
            "insecureEdgeTerminationPolicy": "Redirect",
            "destinationCACertificate": root,
        },
    }
    ingress = resource(
        "networking.k8s.io/v1",
        "NetworkPolicy",
        NAME + "-discovery-ingress",
        INFRA_NAMESPACE,
    )
    ingress["spec"] = {
        "podSelector": {"matchLabels": {"app": "identity-demo-oidc-discovery"}},
        "policyTypes": ["Ingress"],
        "ingress": [
            {
                "from": [
                    {
                        "namespaceSelector": {
                            "matchLabels": {"kubernetes.io/metadata.name": NAMESPACE}
                        },
                        "podSelector": {
                            "matchLabels": {
                                "app": NAME,
                                "identity-demo-owner": active_profile().owner,
                            }
                        },
                    }
                ],
                "ports": [{"protocol": "TCP", "port": 8443}],
            }
        ],
    }
    egress = resource("networking.k8s.io/v1", "NetworkPolicy", NAME + "-egress")
    egress["spec"] = {
        "podSelector": {"matchLabels": {"app": NAME}},
        "policyTypes": ["Ingress", "Egress"],
        "ingress": [
            {
                "from": [
                    {
                        "namespaceSelector": {
                            "matchLabels": {
                                "kubernetes.io/metadata.name": "openshift-ingress"
                            }
                        }
                    }
                ],
                "ports": [{"protocol": "TCP", "port": 8443}],
            }
        ],
        "egress": [
            {
                "to": [
                    {
                        "namespaceSelector": {
                            "matchLabels": {
                                "kubernetes.io/metadata.name": INFRA_NAMESPACE
                            }
                        },
                        "podSelector": {
                            "matchLabels": {"app": "identity-demo-oidc-discovery"}
                        },
                    }
                ],
                "ports": [{"protocol": "TCP", "port": 8443}],
            }
        ],
    }
    values = [ca, secret, pvc, service, ingress, egress, deploy, route]
    write_private(directory / "upstream-original-deployment.private-json", old)
    write_private(directory / "upstream-original-route.private-json", old_route)
    write_private(directory / "upstream-realm.private-json", exported)
    write_private(directory / "upstream-manifests.private-json", values)
    summary = {
        "prepared": True,
        "image": IMAGE,
        "realm": "identity-demo",
        "client_count": len(exported["clients"]),
        "user_count": len(exported["users"]),
        "issuer_base": new_base,
        "separate_pvc": True,
        "original_issuer_changed": False,
        "production_storage_acceptance": False,
    }
    write_private(directory / "upstream-preparation.summary.json", summary)
    return summary


def create(args: argparse.Namespace) -> dict[str, Any]:
    """Dry-run all owned creations; retain an exact UID ledger even on failure."""
    directory = workspace(args)
    ledger = directory / "upstream-created.private-json"
    if ledger.exists():
        raise ValueError("Existing creation ledger requires inspection")
    values = json.loads((directory / "upstream-manifests.private-json").read_text())
    for value in values:
        owned(value)
        metadata = value["metadata"]
        if metadata["namespace"] not in (NAMESPACE, INFRA_NAMESPACE):
            raise ValueError("Owned namespaces only")
        if command(
            args,
            "get",
            value["kind"],
            metadata["name"],
            "-n",
            metadata["namespace"],
            "--ignore-not-found",
            "-o",
            "name",
        ).strip():
            raise ValueError("Existing resource collision")
        command(
            args, "create", "--dry-run=server", "-f", "-", "-o", "name", value=value
        )
    created = []
    write_private(ledger, created)
    for value in values:
        current = json.loads(
            command(args, "create", "-f", "-", "-o", "json", value=value)
        )
        created.append(
            {
                "kind": current["kind"],
                "name": current["metadata"]["name"],
                "namespace": current["metadata"]["namespace"],
                "uid": current["metadata"]["uid"],
            }
        )
        ledger.write_text(json.dumps(created, indent=2))
    return {
        "created": True,
        "object_count": len(created),
        "original_issuer_changed": False,
    }


def status(args: argparse.Namespace) -> dict[str, Any]:
    """Inspect the recorded deployment and preserve original issuer resources."""
    directory = workspace(args)
    ledger = json.loads((directory / "upstream-created.private-json").read_text())
    recorded = next(v for v in ledger if v["kind"] == "Deployment")
    deploy = json.loads(
        command(args, "get", "deployment", NAME, "-n", NAMESPACE, "-o", "json")
    )
    owned(deploy)
    if deploy["metadata"]["uid"] != recorded["uid"]:
        raise ValueError("Recorded deployment identity changed")
    pods = json.loads(
        command(args, "get", "pods", "-n", NAMESPACE, "-l", "app=" + NAME, "-o", "json")
    )["items"]
    preservation = {}
    for kind in ("deployment", "route"):
        before = json.loads(
            (directory / ("upstream-original-" + kind + ".private-json")).read_text()
        )
        current = json.loads(
            command(
                args, "get", kind, "fixture-keycloak", "-n", NAMESPACE, "-o", "json"
            )
        )
        preservation[kind] = (
            current["metadata"]["uid"] == before["metadata"]["uid"]
            and current["spec"] == before["spec"]
        )
    if not all(preservation.values()):
        raise ValueError("Original issuer preservation check failed")
    return {
        "ready_replicas": deploy.get("status", {}).get("readyReplicas", 0),
        "pods": [
            {
                "name": p["metadata"]["name"],
                "uid": p["metadata"]["uid"],
                "phase": p.get("status", {}).get("phase"),
                "ready": any(
                    c["type"] == "Ready" and c["status"] == "True"
                    for c in p.get("status", {}).get("conditions", [])
                ),
                "scc": p["metadata"].get("annotations", {}).get("openshift.io/scc"),
            }
            for p in pods
        ],
        "original_issuer_unchanged": all(preservation.values()),
    }


def main() -> None:
    """Require explicit cluster and private inputs for every staging operation."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "create", "status"))
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--expected-server", required=True)
    parser.add_argument("--namespace", default=NAMESPACE)
    parser.add_argument("--credentials-file", required=True)
    parser.add_argument("--workspace-dir", required=True)
    parser.add_argument("--recovery-realm")
    args = parser.parse_args()
    if args.mode == "prepare" and not args.recovery_realm:
        parser.error("prepare requires --recovery-realm")
    try:
        print(json.dumps(globals()[args.mode](args)))
    except Exception as exc:
        # Never stringify API exceptions that might contain exports or tokens.
        print(
            json.dumps(
                {
                    "mode": args.mode,
                    "failure_kind": type(exc).__name__,
                    "details_withheld": True,
                }
            )
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
