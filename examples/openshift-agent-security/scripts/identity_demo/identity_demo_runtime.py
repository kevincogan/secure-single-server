#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check isolated runtime prerequisites; optionally prepare our management client.

This helper never installs OpenShell, changes Kubernetes resources or grants
cluster permissions. Management preparation changes only labelled objects in
the already owned Keycloak fixture. Service credentials stay outside Git.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
from typing import Any
from urllib.parse import urlencode

from identity_demo_adapter import fixture_request
from identity_demo_lab import LABELS, oc
from deployment_profile import active_profile
from deployment_profile import in_source_checkout

PROFILE = active_profile()
NAMESPACE = PROFILE.core_namespace
CLIENT = "fixture-runtime-operator"
AUDIENCE = "identity-demo-runtime"
ADMIN_ROLE = "identity-demo-runtime-admin"
USER_ROLE = "identity-demo-runtime-user"
DENIED_CLIENT = "fixture-runtime-denied"
PREFIX = "/admin/realms/identity-demo"
GRANTS = (
    ("create", "tokenreviews.authentication.k8s.io"),
    ("get", "namespaces/" + NAMESPACE),
)
# These code paths apply only to GPU or caller-selected class configurations.
CONDITIONAL_GRANTS = (
    ("list", "nodes"), ("get", "runtimeclasses.node.k8s.io"),
    ("get", "priorityclasses.scheduling.k8s.io"),
)


def guard(args: argparse.Namespace) -> tuple[Path, dict[str, Any], str]:
    """Verify the selected cluster, owned resources and private credential path."""
    if args.namespace != NAMESPACE:
        raise ValueError("Exact fixture namespace required")
    server = oc(args, "config", "view", "--minify", "-o",
                "jsonpath={.clusters[0].cluster.server}")
    if server.rstrip("/") != args.expected_server.rstrip("/"):
        raise ValueError("Expected private cluster required")
    for kind, name in (("namespace", NAMESPACE),
                       ("deployment", "fixture-keycloak"),
                       ("route", "fixture-keycloak")):
        scope = [] if kind == "namespace" else ["-n", NAMESPACE]
        item = json.loads(oc(args, "get", kind, name, *scope, "-o", "json"))
        if any(item["metadata"].get("labels", {}).get(k) != v for k, v in LABELS.items()):
            raise ValueError("Owned fixture required")
        if kind == "route":
            base = "https://" + item["spec"]["host"]
    path = Path(args.credentials_file)
    if (path.is_symlink() or path.stat().st_mode & 0o077
            or in_source_checkout(path)):
        raise ValueError("Private credentials outside repository required")
    credentials = json.loads(path.read_text())
    if credentials.get("namespace") != NAMESPACE or credentials["keycloak_url"] != base:
        raise ValueError("Owned fixture endpoint contract required")
    return path, credentials, base


def admin_token(base: str, credentials: dict[str, Any]) -> str:
    """Authenticate the existing fixture administrator without returning logs."""
    from identity_demo_realm_access import realm_token
    return realm_token(fixture_request, base, credentials)


def owned_identity(value: dict[str, Any]) -> bool:
    """Accept only our client/role ownership marker, in Keycloak's native forms."""
    return value.get("attributes", {}).get("identity-demo-owner") in (PROFILE.owner, [PROFILE.owner])


def inventory(base: str, token: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Read runtime identities and reject existing names with different owners."""
    # Keycloak's default brief role list omits ownership attributes.
    _, roles = fixture_request(base, PREFIX + "/roles?briefRepresentation=false", token=token)
    selected = {v["name"]: v for v in roles if v["name"] in (ADMIN_ROLE, USER_ROLE)}
    _, clients = fixture_request(base, PREFIX + "/clients?" + urlencode({"clientId": CLIENT}), token=token)
    if len(clients) > 1 or any(not owned_identity(v) for v in [*selected.values(), *clients]):
        raise ValueError("Unowned or ambiguous runtime identity refused")
    return selected, clients


def save_private(path: Path, credentials: dict[str, Any]) -> None:
    """Persist credentials atomically with restrictive permissions."""
    fd, temporary = tempfile.mkstemp(prefix="runtime-credentials-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(credentials, stream)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def client_configuration(secret: str) -> dict[str, Any]:
    """Give the trusted operator a dedicated client and resource audience."""
    return {"clientId": CLIENT, "enabled": True, "publicClient": False,
        "clientAuthenticatorType": "client-secret", "secret": secret,
        "serviceAccountsEnabled": True, "standardFlowEnabled": False,
        "directAccessGrantsEnabled": False, "fullScopeAllowed": False,
        "defaultClientScopes": [], "optionalClientScopes": [],
        "attributes": {"identity-demo-owner": PROFILE.owner}, "protocolMappers": [
            {"name": "runtime-audience", "protocol": "openid-connect",
             "protocolMapper": "oidc-audience-mapper", "config": {
                 "included.custom.audience": AUDIENCE,
                 "access.token.claim": "true", "id.token.claim": "false"}},
            {"name": "runtime-role", "protocol": "openid-connect",
             "protocolMapper": "oidc-usermodel-realm-role-mapper", "config": {
                 "multivalued": "true", "claim.name": "realm_access.roles",
                 "jsonType.label": "String", "access.token.claim": "true",
                 "id.token.claim": "false", "userinfo.token.claim": "false"}}]}


def prepare_management(path: Path, credentials: dict[str, Any], base: str) -> None:
    """Provision only owned fixture roles/client; preserve human users and grants."""
    token = admin_token(base, credentials)
    roles, clients = inventory(base, token)
    if clients and not credentials.get("runtime_management"):
        raise ValueError("Existing client needs its retained private credential")
    management = credentials.setdefault("runtime_management", {
        "client_id": CLIENT, "audience": AUDIENCE, "client_secret": secrets.token_urlsafe(32)})
    if management["client_id"] != CLIENT or management["audience"] != AUDIENCE:
        raise ValueError("Private runtime credential contract mismatch")
    if not isinstance(management.get("client_secret"), str) or not management["client_secret"]:
        raise ValueError("Nonempty private runtime credential required")
    save_private(path, credentials)
    for name in (ADMIN_ROLE, USER_ROLE):
        if name not in roles:
            fixture_request(base, PREFIX + "/roles", method="POST", token=token,
                value={"name": name, "attributes": {"identity-demo-owner": [PROFILE.owner]}})
    value = client_configuration(management["client_secret"])
    if clients:
        fixture_request(base, PREFIX + "/clients/" + clients[0]["id"],
                        method="PUT", token=token, value=value)
    else:
        fixture_request(base, PREFIX + "/clients", method="POST", token=token, value=value)
    token = admin_token(base, credentials)
    roles, clients = inventory(base, token)
    if len(clients) != 1 or ADMIN_ROLE not in roles:
        raise RuntimeError("Runtime identity reconciliation incomplete")
    identifier = clients[0]["id"]
    _, account = fixture_request(base, PREFIX + "/clients/" + identifier + "/service-account-user", token=token)
    role = {"id": roles[ADMIN_ROLE]["id"], "name": ADMIN_ROLE}
    fixture_request(base, PREFIX + "/clients/" + identifier + "/scope-mappings/realm",
                    method="POST", token=token, value=[role])
    fixture_request(base, PREFIX + "/users/" + account["id"] + "/role-mappings/realm",
                    method="POST", token=token, value=[role])


def verify_management(base: str, credentials: dict[str, Any], token: str) -> dict[str, Any]:
    """Verify the operator grant and that demo humans have no management role."""
    import jwt
    management = credentials["runtime_management"]
    _, grant = fixture_request(base, "/realms/identity-demo/protocol/openid-connect/token",
        method="POST", fields={"grant_type": "client_credentials", "client_id": CLIENT,
        "client_secret": management["client_secret"]})
    _, jwks = fixture_request(base, "/realms/identity-demo/protocol/openid-connect/certs")
    access = grant["access_token"]
    header = jwt.get_unverified_header(access)
    keys = [k for k in jwks["keys"] if k.get("kid") == header.get("kid")]
    if header.get("alg") != "RS256" or len(keys) != 1:
        raise ValueError("Approved issuer signing key required")
    claims = jwt.decode(access, jwt.PyJWK.from_dict(keys[0]).key, algorithms=["RS256"],
        issuer=base + "/realms/identity-demo", audience=AUDIENCE,
        options={"require": ["exp", "iat", "iss", "sub", "aud", "azp"]})
    if claims["azp"] != CLIENT or claims.get("realm_access", {}).get("roles") != [ADMIN_ROLE]:
        raise ValueError("Narrow runtime operator grant required")
    for name in ("analyst", "viewer"):
        _, users = fixture_request(base, PREFIX + "/users?" + urlencode({"username": name, "exact": "true"}), token=token)
        if len(users) != 1:
            raise ValueError("Exact synthetic user required")
        _, roles = fixture_request(base, PREFIX + "/users/" + users[0]["id"] + "/role-mappings/realm/composite", token=token)
        if any(r["name"] in (ADMIN_ROLE, USER_ROLE) for r in roles):
            raise ValueError("Demo human has unexpected direct management access")
    return {"operator_token_verified": True, "resource_audience_verified": True,
            "only_runtime_admin_role": True, "demo_humans_have_no_management_roles": True}


def prepare_management_denial(path: Path, credentials: dict[str, Any], base: str) -> None:
    """Create an owned negative-test client with runtime audience but no roles."""
    token = admin_token(base, credentials)
    _, clients = fixture_request(base, PREFIX + "/clients?" + urlencode({"clientId": DENIED_CLIENT}), token=token)
    if len(clients) > 1 or any(not owned_identity(v) for v in clients):
        raise ValueError("Unowned negative-test identity refused")
    if clients and not credentials.get("runtime_denial"):
        raise ValueError("Existing negative-test identity needs its retained credential")
    denied = credentials.setdefault("runtime_denial", {
        "client_id": DENIED_CLIENT, "client_secret": secrets.token_urlsafe(32)})
    if denied["client_id"] != DENIED_CLIENT:
        raise ValueError("Negative-test client contract mismatch")
    value = client_configuration(denied["client_secret"])
    value["clientId"] = DENIED_CLIENT
    save_private(path, credentials)
    if not clients:
        fixture_request(base, PREFIX + "/clients", method="POST", token=token, value=value)
    # Do not reconcile an existing client's mappings: the live probe must fail
    # if unexpected management roles were granted to this denial identity.


def permission(args: argparse.Namespace, verb: str, resource: str) -> str:
    """Distinguish a real 'no' from an unavailable authorization query."""
    result = subprocess.run(["oc", "--kubeconfig=" + args.kubeconfig, "auth", "can-i",
        verb, resource, "--as=system:serviceaccount:" + NAMESPACE + ":fixture-openshell"],
        capture_output=True, text=True, timeout=30)
    answer = result.stdout.strip()
    return answer if (answer == "yes" and result.returncode == 0) or (
        answer == "no" and result.returncode == 1) else "unknown"


def run(args: argparse.Namespace) -> dict[str, Any]:
    """Check prerequisites without treating preparation as runtime acceptance."""
    path, credentials, base = guard(args)
    if args.prepare_management:
        prepare_management(path, credentials, base)
    if getattr(args, "prepare_management_denial", False):
        prepare_management_denial(path, credentials, base)
    token = admin_token(base, credentials)
    roles, clients = inventory(base, token)
    management = {"client_present": len(clients) == 1,
                  "roles_present": all(name in roles for name in (ADMIN_ROLE, USER_ROLE))}
    if clients and credentials.get("runtime_management"):
        management.update(verify_management(base, credentials, token))
    grants = [{"verb": verb, "resource": resource, "decision": permission(args, verb, resource)}
              for verb, resource in GRANTS]
    conditional = [{"verb": verb, "resource": resource,
                    "decision": permission(args, verb, resource)}
                   for verb, resource in CONDITIONAL_GRANTS]
    api = json.loads(oc(args, "get", "crd", "sandboxes.agents.x-k8s.io", "-o", "json"))
    supported = any(v["served"] and v["name"] in ("v1alpha1", "v1beta1") for v in api["spec"]["versions"])
    storage = json.loads(oc(args, "get", "storageclass", "-o", "json"))
    defaults = [c["metadata"]["name"] for c in storage["items"] if c["metadata"].get(
        "annotations", {}).get("storageclass.kubernetes.io/is-default-class") == "true"]
    return {"scope": "Owned configured runtime prerequisites; this helper does not install",
        "namespace": NAMESPACE, "management_prepared_this_run": args.prepare_management,
        "management_denial_prepared_this_run": getattr(args, "prepare_management_denial", False),
        "management": management, "runtime_service_account_permissions": grants,
        "conditional_permissions_not_required_for_cpu_default_classes": conditional,
        "supported_sandbox_api_served": supported, "default_storage_classes": defaults,
        "requires_owner_decisions": ["Approved RHOAI installation path and cluster grants",
            "Issuer CA/egress and sandbox capacity", "Pinned actual CVE image and non-mutating fixture"],
        "kubernetes_resources_changed": False, "runtime_acceptance_passed": False,
        "install_ready": False, "tokens_or_secret_values_returned": False}


def main() -> None:
    """Run a read-only check or explicitly prepare owned management identities."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--expected-server", required=True)
    parser.add_argument("--credentials-file", required=True)
    parser.add_argument("--prepare-management", action="store_true")
    parser.add_argument("--prepare-management-denial", action="store_true")
    args = parser.parse_args()
    args.namespace = NAMESPACE
    print(json.dumps(run(args), indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps({"completed": False, "failure_kind": type(error).__name__,
                          "error_body_withheld": True}))
        raise SystemExit(1) from None
