#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Package and create the reviewed owned stack using private configuration.

Never replay historical bootstrap migrations over a running installation.
Snapshot is a read-only export; install is create-only with an immutable bundle
hash and a creation ledger. Platform stages prepare reviewed controllers separately; application stages require them. Ordinary
execution identities and tests use the existing execution/rehearsal helpers.
"""

from __future__ import annotations

import argparse
import base64
from copy import deepcopy
import hashlib
from importlib import import_module
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib
import uuid

from identity_demo_lab import LABELS
from deployment_profile import DeploymentProfile, LEGACY, in_source_checkout

ROOT = Path(__file__).resolve().parents[2]
SERVER = "https://api.cluster.example.test:443"
NAMESPACES = ("demo-core", "demo-triage", "demo-reader")
RESOURCES = {
    "Namespace": "namespaces", "ServiceAccount": "serviceaccounts", "Secret": "secrets",
    "ConfigMap": "configmaps", "PersistentVolumeClaim": "persistentvolumeclaims",
    "Role": "roles.rbac.authorization.k8s.io", "RoleBinding": "rolebindings.rbac.authorization.k8s.io",
    "NetworkPolicy": "networkpolicies.networking.k8s.io", "Service": "services",
    "Certificate": "certificates.cert-manager.io",
    "Deployment": "deployments.apps", "StatefulSet": "statefulsets.apps",
    "Route": "routes.route.openshift.io", "Gateway": "gateways.gateway.networking.k8s.io",
    "HTTPRoute": "httproutes.gateway.networking.k8s.io", "AuthPolicy": "authpolicies.kuadrant.io",
    "MCPGatewayExtension": "mcpgatewayextensions.mcp.kuadrant.io",
    "MCPServerRegistration": "mcpserverregistrations.mcp.kuadrant.io",
    "EnvoyFilter": "envoyfilters.networking.istio.io",
}
ORDER = {kind: i for i, kind in enumerate(RESOURCES)}
CONTROLLERS = ("Deployment", "StatefulSet")
PRESERVE = {"Namespace", "Secret", "PersistentVolumeClaim", "Certificate"}
EXACT_NAMES = {("NetworkPolicy", NAMESPACES[0], "keycloak-route-ingress"),
               ("ConfigMap", NAMESPACES[0], "jira-fixture-bootstrap")}
APIS = {kind: "v1" for kind in RESOURCES}
APIS.update({"Role": "rbac.authorization.k8s.io/v1", "RoleBinding": "rbac.authorization.k8s.io/v1",
    "NetworkPolicy": "networking.k8s.io/v1", "Deployment": "apps/v1", "StatefulSet": "apps/v1",
    "Route": "route.openshift.io/v1", "Gateway": "gateway.networking.k8s.io/v1",
    "HTTPRoute": "gateway.networking.k8s.io/v1", "AuthPolicy": "kuadrant.io/v1",
    "MCPGatewayExtension": "mcp.kuadrant.io/v1alpha1",
    "MCPServerRegistration": "mcp.kuadrant.io/v1alpha1", "EnvoyFilter": "networking.istio.io/v1alpha3"})
APIS['Certificate'] = 'cert-manager.io/v1'


def in_checkout(path: Path) -> bool:
    """Keep private material out of this repository and other Git worktrees."""
    return in_source_checkout(path, ROOT)


def sha(path: Path) -> str:
    """Hash a file without loading binaries/media into memory."""
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def private_file(value: str) -> Path:
    """Require a real private file outside Git; canonicalize macOS /tmp alias."""
    raw = Path(value).expanduser()
    if raw.is_symlink() or not raw.is_absolute():
        raise ValueError("Absolute non-symlink private file required")
    path = raw.resolve()
    if in_checkout(path) or not path.is_file() or path.stat().st_mode & 0o077:
        raise ValueError("Private file outside checkout required")
    return path


def write(path: Path, value: object) -> None:
    """Create a private exclusive artifact; never overwrite a receipt."""
    with path.open("x") as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream, indent=2)
        stream.write("\n")


def kube(args: argparse.Namespace, *words: str, value: dict | list | None = None) -> dict:
    """Keep API bodies, Secrets and failure details out of stdout/stderr."""
    result = subprocess.run([args.oc, "--kubeconfig", args.kubeconfig,
        "--request-timeout=20s", *words], input=json.dumps(value) if value else None,
        text=True, capture_output=True, timeout=45)
    if result.returncode:
        raise RuntimeError("Kubernetes operation failed; response withheld")
    if not result.stdout.strip():
        return {}
    return json.loads(result.stdout)


def owned(obj: dict, profile: DeploymentProfile = LEGACY) -> None:
    """Require the established demo owner labels, not merely a familiar name."""
    if any(obj.get("metadata", {}).get("labels", {}).get(k) != v for k, v in profile.labels.items()):
        raise ValueError("Owned demo resource required")


def clean(obj: dict) -> dict:
    """Strip runtime metadata; retain the desired configuration privately."""
    value = deepcopy(obj)
    meta = value["metadata"]
    annotations = {k: v for k, v in meta.get("annotations", {}).items()
        if not k.startswith(("kubectl.kubernetes.io/", "deployment.kubernetes.io/",
                             "openshift.io/sa.scc."))}
    value["metadata"] = {"name": meta["name"], "labels": meta.get("labels", {}),
                         "annotations": annotations}
    if meta.get("namespace"):
        value["metadata"]["namespace"] = meta["namespace"]
    value.pop("status", None)
    if value["kind"] == "Service":
        for key in ("clusterIP", "clusterIPs", "ipFamilies", "ipFamilyPolicy", "healthCheckNodePort"):
            value["spec"].pop(key, None)
        for port in value["spec"].get("ports", []):
            port.pop("nodePort", None)
    if value["kind"] == "PersistentVolumeClaim":
        value["spec"].pop("volumeName", None)
        value["metadata"]["annotations"] = {}
    return value


def identity(obj: dict, profile: DeploymentProfile = LEGACY) -> tuple:
    """Validate group, scope, name and ownership before forming any API path."""
    kind, meta = obj["kind"], obj["metadata"]
    if kind not in RESOURCES or obj.get("apiVersion") != APIS[kind]:
        raise ValueError("Exact reviewed resource API required")
    namespace, name = meta.get("namespace"), meta["name"]
    if kind == "Namespace":
        if namespace or name not in profile.application_namespaces:
            raise ValueError("Only the three owned namespaces are installable")
    elif (namespace not in profile.application_namespaces or (not re.fullmatch(
            r"(?:fixture-|identity-demo-|openshell-|demo-)[a-z0-9.-]+", name)
            and (kind, namespace, name) not in {
                ("NetworkPolicy", profile.core_namespace, "keycloak-route-ingress"),
                ("ConfigMap", profile.core_namespace, "jira-fixture-bootstrap")})):
        raise ValueError("Reviewed namespace/resource name required")
    owned(obj, profile)
    return kind, namespace, name


def fingerprint(obj: dict) -> str:
    """Hash configuration excluding mutable metadata/status for cleanup drift checks."""
    value = clean(obj)
    value.pop("metadata")
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def controller_projection(args: argparse.Namespace, current: dict, desired: dict) -> dict:
    """Validate narrowly defined OpenShift updates before comparing configuration.

    Never ignore arbitrary Secret references or CA material. Generated registry
    credentials must belong to this exact ServiceAccount UID; injected trust
    must equal the namespace's platform service CA. All other fields survive.
    """
    result = deepcopy(current)
    meta = current["metadata"]
    if current["kind"] == "ServiceAccount":
        for field in ("secrets", "imagePullSecrets"):
            if field in desired or field not in current:
                continue
            for reference in current[field]:
                name = reference.get("name", "")
                if set(reference) != {"name"} or not name.startswith(meta["name"] + "-dockercfg-"):
                    raise ValueError("Unexpected ServiceAccount credential reference")
                secret = kube(args, "get", "secret", name, "-n", meta["namespace"], "-o", "json")
                owners = secret["metadata"].get("ownerReferences", [])
                if (secret.get("type") != "kubernetes.io/dockercfg"
                        or len(owners) != 1 or owners[0].get("kind") != "ServiceAccount"
                        or owners[0].get("name") != meta["name"]
                        or owners[0].get("uid") != meta["uid"]):
                    raise ValueError("Generated credential owner or type mismatch")
            result.pop(field, None)
    if (current["kind"] == "ConfigMap"
            and desired["metadata"].get("annotations", {}).get("service.beta.openshift.io/inject-cabundle") == "true"
            and not desired.get("data") and not desired.get("binaryData")):
        if meta.get("annotations", {}).get("service.beta.openshift.io/inject-cabundle") != "true":
            raise ValueError("Platform CA injection annotation changed")
        authority = kube(args, "get", "configmap", "openshift-service-ca.crt",
                         "-n", meta["namespace"], "-o", "json")
        if (not authority.get("data", {}).get("service-ca.crt")
                or current.get("data") != {"service-ca.crt": authority["data"]["service-ca.crt"]}
                or current.get("binaryData")):
            raise ValueError("Injected service CA does not match platform authority")
        result.pop("data", None)
    return result


def recorded_configuration_matches(args: argparse.Namespace, current: dict,
                                   desired: dict, recorded: str) -> bool:
    """Accept exact receipts or independently verified controller-only additions."""
    if fingerprint(current) == recorded:
        return True
    projected = controller_projection(args, current, desired)
    if fingerprint(projected) == recorded:
        return True
    # API servers can preserve or omit an explicitly empty ConfigMap data map.
    if (current["kind"] == "ConfigMap" and "data" not in projected
            and desired["metadata"].get("annotations", {}).get("service.beta.openshift.io/inject-cabundle") == "true"
            and not desired.get("data")):
        projected["data"] = {}
        return fingerprint(projected) == recorded
    return False


def validate(bundle: dict) -> list[dict]:
    """Keep installation namespaced, digest-pinned and inside the reviewed scope."""
    version = bundle.get("schema_version")
    profile = (DeploymentProfile.from_dict(bundle["installation_profile"])
               if version == 2 else LEGACY)
    if type(version) is not int or version not in (1, 2) or bundle.get("expected_server") != profile.expected_server:
        raise ValueError("Reviewed bundle schema/server required")
    objects = bundle.get("objects")
    if not isinstance(objects, list) or not 1 <= len(objects) <= 300:
        raise ValueError("Bounded nonempty bundle required")
    seen = set()
    contract = bundle.get('certificate_management', {'mode': 'legacy'})
    certificates = [o for o in objects if o.get('kind') == 'Certificate']
    if contract != {'mode': 'legacy'}:
        from managed_certificates import validate_contract, resources, SECRETS
        validate_contract(contract, bundle['certificate_authority_pem'])
        if certificates != resources(profile, contract) or any(o.get('kind') == 'Secret'
                and o.get('metadata', {}).get('name') in SECRETS for o in objects):
            raise ValueError('Exact three managed leaf resources without generated leaf Secrets required')
    elif certificates:
        raise ValueError('Certificate resources require explicit managed mode')
    for obj in objects:
        item_id = identity(obj, profile)
        kind, namespace, name = item_id
        meta = obj["metadata"]
        if item_id in seen or meta.get("ownerReferences"):
            raise ValueError("Duplicate or controller-owned resource refused")
        seen.add(item_id)
        if kind == "Service" and obj.get("spec", {}).get("type", "ClusterIP") != "ClusterIP":
            raise ValueError("Only internal Services permitted")
        if kind == "ConfigMap" and name == "fixture-openshell-config":
            gateway = tomllib.loads(obj["data"]["gateway.toml"])["openshell"]["gateway"]
            if (gateway.get("disable_tls") is not False
                    or gateway["auth"].get("allow_unauthenticated_users") is not False):
                raise ValueError("Authenticated TLS runtime configuration required")
        if kind in CONTROLLERS:
            pod = obj["spec"]["template"]["spec"]
            if any(pod.get(k) for k in ("hostNetwork", "hostPID", "hostIPC")):
                raise ValueError("Host namespace access refused")
            for container in [*pod.get("containers", []), *pod.get("initContainers", [])]:
                if (not re.fullmatch(r"[^\s]+@sha256:[a-f0-9]{64}", container["image"])
                        or container.get("securityContext", {}).get("privileged")):
                    raise ValueError("Pinned nonprivileged container required")
            if any("hostPath" in v for v in pod.get("volumes", [])):
                raise ValueError("Host paths refused")
    return sorted(objects, key=lambda o: ORDER[o["kind"]])


def target(args: argparse.Namespace) -> dict:
    """Verify exact API, TLS and existing platform APIs without granting access."""
    args.kubeconfig = str(private_file(args.kubeconfig))
    config = kube(args, "config", "view", "--minify", "-o", "json")
    selected = config["clusters"][0]["cluster"]
    profile = getattr(args, "profile", LEGACY)
    if (args.expected_server != profile.expected_server or selected["server"].rstrip("/") != profile.expected_server
            or selected.get("insecure-skip-tls-verify")):
        raise ValueError("Exact approved API with TLS verification required")
    foundation = kube(args, "get", "namespace", profile.identity_namespace, "-o", "json")
    owned(foundation, profile)
    for name, version in {
            "sandboxes.agents.x-k8s.io": "v1beta1", "clusterstaticentries.spire.spiffe.io": "v1alpha1",
            "gateways.gateway.networking.k8s.io": "v1", "httproutes.gateway.networking.k8s.io": "v1",
            "authpolicies.kuadrant.io": "v1", "mcpgatewayextensions.mcp.kuadrant.io": "v1alpha1",
            "mcpserverregistrations.mcp.kuadrant.io": "v1alpha1",
            "envoyfilters.networking.istio.io": "v1alpha3"}.items():
        definition = kube(args, "get", "crd", name, "-o", "json")
        if (not any(v["name"] == version and v.get("served") for v in definition["spec"]["versions"])
                or not any(c["type"] == "Established" and c["status"] == "True"
                           for c in definition.get("status", {}).get("conditions", []))):
            raise ValueError("Required established and served API version unavailable")
    manager = kube(args, "get", "zerotrustworkloadidentitymanager.operator.openshift.io", "cluster", "-o", "json")
    if (manager.get("metadata", {}).get("labels", {}).get("identity-demo-owner") != profile.owner
            or manager["spec"]["trustDomain"] != profile.trust_domain
            or manager["spec"]["clusterName"] != profile.cluster_name):
        raise ValueError("Installation profile does not match the existing identity foundation")
    kube(args, "get", "storageclass", profile.storage_class, "-o", "json")
    for name in profile.application_namespaces:
        ns = kube(args, "get", "namespace", name, "--ignore-not-found", "-o", "json")
        if ns:
            owned(ns, profile)
    return {"expected_api_verified": True, "tls_verify": True,
            "identity_and_sandbox_api_prerequisites_present": True,
            "permissions_granted": False, "cluster_changed": False}


def realm_export(base: str, credentials: dict) -> dict:
    """Export synthetic realm configuration with usable client/user credentials.

    Partial export omits users and can mask client secrets; hydrate only the two
    known synthetic users and service accounts. Master admin stays a bootstrap
    input. No database or existing run/action history is imported on fresh install.
    """
    from identity_demo_adapter import fixture_request
    from identity_demo_keycloak_upstream import BASE, issuer_request

    call = issuer_request if base == BASE else fixture_request
    token = call(base, "/realms/master/protocol/openid-connect/token", method="POST",
                fields={"grant_type": "password", "client_id": "admin-cli",
                        "username": "fixture-admin", "password": credentials["keycloak_admin"]})[1]["access_token"]
    prefix = "/admin/realms/identity-demo"
    def request(path: str, **kwargs: object) -> object:
        return call(base, prefix + path, token=token, **kwargs)[1]
    realm = request("/partial-export?exportClients=true&exportGroupsAndRoles=true", method="POST")
    users = []
    for username in ("analyst", "viewer"):
        found = request("/users?username=" + username + "&exact=true")
        if len(found) != 1:
            raise ValueError("Exact synthetic realm user required")
        user = found[0]
        mappings = request("/users/" + user["id"] + "/role-mappings")
        user["realmRoles"] = [r["name"] for r in mappings.get("realmMappings", [])]
        user["clientRoles"] = {v["client"]: [r["name"] for r in v["mappings"]]
                               for v in mappings.get("clientMappings", {}).values()}
        user["credentials"] = [{"type": "password", "value": credentials[username], "temporary": False}]
        users.append(user)
    for client in realm.get("clients", []):
        if (client.get("clientAuthenticatorType") == "client-secret"
                and not client.get("publicClient") and not client.get("bearerOnly")):
            client["secret"] = request("/clients/" + client["id"] + "/client-secret")["value"]
        if client.get("serviceAccountsEnabled"):
            user = request("/clients/" + client["id"] + "/service-account-user")
            mappings = request("/users/" + user["id"] + "/role-mappings")
            user["serviceAccountClientId"] = client["clientId"]
            user["realmRoles"] = [r["name"] for r in mappings.get("realmMappings", [])]
            user["clientRoles"] = {v["client"]: [r["name"] for r in v["mappings"]]
                                   for v in mappings.get("clientMappings", {}).values()}
            users.append(user)
    realm["users"] = users
    return realm


def snapshot(args: argparse.Namespace) -> dict:
    """Capture owner-controlled desired objects and complete realm imports privately."""
    from identity_demo_runtime import guard
    from identity_demo_execution_setup import inspect_state

    args.namespace = NAMESPACES[0]
    _, credentials, original = guard(args)
    state = inspect_state(args)
    if not state["rollback_quiescent"]:
        raise ValueError("Quiescent run/action state required")
    all_objects = []
    uid_ranges = {}
    for namespace in NAMESPACES:
        ns = kube(args, "get", "namespace", namespace, "-o", "json")
        owned(ns)
        uid_ranges[namespace] = ns["metadata"].get("annotations", {}).get("openshift.io/sa.scc.uid-range", "")
        all_objects.append(clean(ns))
        resources = ",".join(r for k, r in RESOURCES.items() if k != "Namespace"
            and (k != 'Certificate' or getattr(args, 'certificate_management', {}).get('mode') == 'managed'))
        items = kube(args, "get", resources, "-n", namespace, "-o", "json")["items"]
        for obj in items:
            meta, kind = obj["metadata"], obj["kind"]
            if (any(meta.get("labels", {}).get(k) != v for k, v in LABELS.items())
                    or meta.get("ownerReferences")):
                continue
            # Retired worker PVCs are evidence, not fresh-install claims.
            if namespace != NAMESPACES[0] and kind in (*CONTROLLERS, "PersistentVolumeClaim"):
                continue
            all_objects.append(clean(obj))
    # Only currently referenced code/config maps are deployment inputs.
    referenced = set()
    for obj in all_objects:
        if obj["kind"] in CONTROLLERS:
            pod = obj["spec"]["template"]["spec"]
            for volume in pod.get("volumes", []):
                if "configMap" in volume:
                    referenced.add((obj["metadata"]["namespace"], volume["configMap"]["name"]))
            for container in [*pod.get("containers", []), *pod.get("initContainers", [])]:
                for env in container.get("env", []):
                    ref = env.get("valueFrom", {}).get("configMapKeyRef")
                    if ref:
                        referenced.add((obj["metadata"]["namespace"], ref["name"]))
    all_objects = [o for o in all_objects if o["kind"] != "ConfigMap" or
        (o["metadata"].get("namespace"), o["metadata"]["name"]) in referenced or
        o["metadata"]["name"] == "fixture-service-ca"]
    for secret_name, base in (("fixture-keycloak-recovery", original),
        ("fixture-keycloak-upstream-realm", "https://fixture-keycloak-upstream-demo-core.apps.cluster.example.test")):
        selected = [o for o in all_objects if o["kind"] == "Secret" and o["metadata"]["name"] == secret_name]
        if len(selected) != 1 or "realm.json" not in selected[0].get("data", {}):
            raise ValueError("Expected private realm import Secret required")
        selected[0]["data"]["realm.json"] = base64.b64encode(json.dumps(
            realm_export(base, credentials)).encode()).decode()
    renamed = {}
    for obj in all_objects:
        if obj["kind"] == "ConfigMap" and obj["metadata"]["name"].startswith("fixture-identity-driver-code-"):
            for key, text in list(obj.get("data", {}).items()):
                if key.endswith(".json"):
                    config = json.loads(text)
                    if isinstance(config, dict) and "contexts" in config:
                        config["contexts"] = []
                        obj["data"][key] = json.dumps(config)
            old = obj["metadata"]["name"]
            new = "fixture-identity-driver-code-" + hashlib.sha256(
                json.dumps(obj["data"], sort_keys=True).encode()).hexdigest()[:10]
            obj["metadata"]["name"] = new
            renamed[old] = new
    for obj in all_objects:
        if obj["kind"] in CONTROLLERS:
            for volume in obj["spec"]["template"]["spec"].get("volumes", []):
                config = volume.get("configMap")
                if config and config["name"] in renamed:
                    config["name"] = renamed[config["name"]]
    sources = [*ROOT.glob("scripts/identity_demo/identity_demo_*.py"),
               *ROOT.glob("tests/identity_demo/requirements*.txt"),
               *ROOT.glob("infra/openshell/patches/*.patch")]
    pins = {str(p.relative_to(ROOT)): sha(p) for p in sources}
    bundle = {"schema_version": 1, "expected_server": SERVER, "objects": all_objects,
              "source_pins": pins, "fresh_driver_contexts": True,
              "namespace_uid_ranges": uid_ranges,
              "database_contents_included": False, "shared_platform_reinstalled": False}
    validate(bundle)
    path = args.output_dir / "stack.private.json"
    write(path, bundle)
    return {"snapshot_created": True, "objects": len(all_objects), "bundle_sha256": sha(path),
            "private_bundle": str(path), "cluster_changed": False,
            "fresh_installation_proven": False}


def get(args: argparse.Namespace, obj: dict) -> dict:
    """Read one exact scoped object; optional means absence, not an API error."""
    meta = obj["metadata"]
    return kube(args, "get", RESOURCES[obj["kind"]], meta["name"],
        *(["-n", meta["namespace"]] if meta.get("namespace") else []),
        "--ignore-not-found", "-o", "json")


def permissions(args: argparse.Namespace, objects: list[dict]) -> dict:
    """Check the caller's create privileges without creating application state.

    SelfSubjectAccessReview is an authorization query, not a stored resource or
    a grant. Admission, collision checks and runtime ServiceAccount grants are
    separate gates. Namespace-local bindings must exist before they can pass.
    """
    checked, denied = set(), []
    for obj in objects:
        group = obj['apiVersion'].split('/')[0] if '/' in obj['apiVersion'] else ''
        resource = RESOURCES[obj['kind']].split('.')[0]
        namespace = obj['metadata'].get('namespace', '')
        key = group, resource, namespace
        if key in checked:
            continue
        checked.add(key)
        attributes = {'group': group, 'resource': resource, 'verb': 'create'}
        if namespace:
            attributes['namespace'] = namespace
        review = kube(args, 'create', '-f', '-', '-o', 'json', value={
            'apiVersion': 'authorization.k8s.io/v1', 'kind': 'SelfSubjectAccessReview',
            'spec': {'resourceAttributes': attributes}})
        status = review.get('status', {})
        if status.get('allowed') is not True or status.get('evaluationError'):
            denied.append(attributes)
    return {'ready': not denied, 'create_scopes_checked': len(checked),
            'missing_create_permissions': denied, 'cluster_changed': False,
            'admission_and_read_permissions_proven': False}


def prepare_access(args: argparse.Namespace, objects: list[dict]) -> dict:
    """Prepare owned namespaces and explicit caller access to application routes.

    Never grants an agent access, changes an existing grant or uses admin
    fallback. API authorization and RBAC escalation/binding checks still apply.
    Keep these prerequisite receipts separate from application rollback.
    """
    profile = getattr(args, "profile", LEGACY)
    user = getattr(args, "installer_user", None)
    if (not isinstance(user, str) or not re.fullmatch(r"[A-Za-z0-9@._-]{1,128}", user)
            or user in ("admin", "kubeadmin", "cluster-admin")):
        raise ValueError("Explicit non-admin installer username required")
    authenticated = kube(args, "create", "-f", "-", "-o", "json", value={
        "apiVersion": "authentication.k8s.io/v1", "kind": "SelfSubjectReview"})
    if authenticated.get("status", {}).get("userInfo", {}).get("username") != user:
        raise ValueError("Authenticated installer username mismatch")
    namespaces = [deepcopy(obj) for obj in objects if obj["kind"] == "Namespace"]
    if {o["metadata"]["name"] for o in namespaces} != set(profile.application_namespaces):
        raise ValueError("Exact three application namespaces required")
    rules = []
    for kind in ("Gateway", "HTTPRoute"):
        selected = [o for o in objects if o["kind"] == kind]
        if not selected or any(o["metadata"].get("namespace") != profile.core_namespace for o in selected):
            raise ValueError("Exact core-namespace routing objects required")
        resource = RESOURCES[kind].split(".")[0]
        rules.extend([
            {"apiGroups": ["gateway.networking.k8s.io"], "resources": [resource], "verbs": ["create"]},
            {"apiGroups": ["gateway.networking.k8s.io"], "resources": [resource],
             "resourceNames": sorted(o["metadata"]["name"] for o in selected),
             "verbs": ["get", "update", "patch", "delete"]}])
    name = "fixture-installer-gateway-access"
    meta = {"name": name, "namespace": profile.core_namespace, "labels": dict(profile.labels)}
    role = {"apiVersion": APIS["Role"], "kind": "Role", "metadata": deepcopy(meta), "rules": rules}
    binding = {"apiVersion": APIS["RoleBinding"], "kind": "RoleBinding", "metadata": deepcopy(meta),
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": name},
        "subjects": [{"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": user}]}
    desired = validate({"schema_version": 2, "expected_server": profile.expected_server,
                       "installation_profile": profile.to_dict(), "objects": [*namespaces, role, binding]})
    inspected = []
    for obj in desired:
        current = get(args, obj)
        if current:
            owned(current, profile)
            if current["metadata"].get("deletionTimestamp"):
                raise ValueError("Terminating installer prerequisite requires recovery")
            fields = {"Namespace": (), "Role": ("rules",), "RoleBinding": ("roleRef", "subjects")}[obj["kind"]]
            if any(current.get(field) != obj.get(field) for field in fields):
                raise ValueError("Installer prerequisite collision; existing grants are never rewritten")
        inspected.append((obj, current))
    write(args.output_dir / "access.plan.private.json", {"objects": desired, "installer_user": user,
        "create_permission_cannot_be_resource_name_restricted": True})
    permission_result = permissions(args, [obj for obj, current in inspected if not current])
    write(args.output_dir / "access.permissions.json", permission_result)
    if not permission_result["ready"]:
        return {**permission_result, "applied": False, "prerequisites_present": False}
    created, deferred = [], 0
    missing_namespaces = {obj["metadata"]["name"] for obj, current in inspected
                          if obj["kind"] == "Namespace" and not current}
    missing_role = any(obj["kind"] == "Role" and not current for obj, current in inspected)
    for index, (obj, current) in enumerate(inspected):
        if current:
            continue
        if not args.apply and (obj["metadata"].get("namespace") in missing_namespaces
                               or obj["kind"] == "RoleBinding" and missing_role):
            deferred += 1
            continue
        kube(args, "create", "--dry-run=server", "-f", "-", "-o", "json", value=obj)
        if args.apply:
            write(args.output_dir / f"access-{index}.pending.json", obj)
            made = kube(args, "create", "-f", "-", "-o", "json", value=obj)
            receipt = {"kind": made["kind"], "name": made["metadata"]["name"],
                       "namespace": made["metadata"].get("namespace"), "uid": made["metadata"]["uid"],
                       "fingerprint": fingerprint(made)}
            write(args.output_dir / f"access-{index}.created.json", receipt)
            created.append(receipt)
    return {"applied": args.apply, "prerequisites_present": args.apply or all(c for _, c in inspected),
            "created": created, "admission_deferred": deferred, "installer_user": user,
            "existing_resources_modified": False, "shared_foundation_modified": False,
            "runtime_permissions_and_functional_acceptance_proven": False}


def plan(args: argparse.Namespace, objects: list[dict]) -> dict:
    """Report collisions; only absent objects can have a create admission check."""
    collisions = []
    admitted = 0
    deferred = 0
    namespace_exists = {}
    if getattr(args, 'certificate_management', {}).get('mode') == 'managed':
        from certificate_operations import preflight
        preflight(args, fresh=getattr(args, 'action', None) != 'resume')
    for obj in objects:
        current = get(args, obj)
        if current:
            owned(current, getattr(args, "profile", LEGACY))
            if obj["kind"] != "Namespace":
                collisions.append({"kind": obj["kind"], "name": obj["metadata"]["name"],
                                   "namespace": obj["metadata"].get("namespace")})
        if args.server_dry_run and not current:
            namespace = obj["metadata"].get("namespace")
            if namespace and namespace not in namespace_exists:
                namespace_exists[namespace] = bool(kube(args, "get", "namespace", namespace,
                    "--ignore-not-found", "-o", "json"))
            if namespace and not namespace_exists[namespace]:
                # Dry-run cannot create a namespace for a later admission call.
                # Installation checks each object after its namespace exists.
                deferred += 1
                continue
            kube(args, "create", "--dry-run=server", "-f", "-", "-o", "json", value=obj)
            admitted += 1
    native_ready = (getattr(args, "bundle_version", 1) != 2
                    or getattr(args, "native_build_contract_matches", False))
    return {"planned_objects": len(objects), "collisions": collisions,
            "ready_for_create": not collisions and native_ready and getattr(args, "ingress_aliases_configured", None) is not False,
            "native_artifacts_ready": native_ready, "cluster_changed": False,
            "server_dry_run_requested": args.server_dry_run,
            "admission_checked_absent_objects": admitted,
            "admission_deferred_missing_namespace": deferred,
            "admission_blocked_occupied_objects": len(collisions) if args.server_dry_run else 0}


def install(args: argparse.Namespace, objects: list[dict]) -> dict:
    """Create absent resources only; journal each exact new UID immediately."""
    if not args.apply:
        raise ValueError("Installation requires explicit --apply")
    profile = getattr(args, "profile", LEGACY)
    if getattr(args, "bundle_version", 1) == 2 and not getattr(args, "native_build_contract_matches", False):
        raise ValueError("Native images must have matching recorded sender build inputs")
    if getattr(args, "ingress_aliases_configured", None) is False:
        raise ValueError("Resolve retained ingress through connected-install or explicit render input before creation")
    resuming = getattr(args, "action", "install") == "resume"
    previous = None
    if resuming:
        previous = reconcile_creation(args, objects)
        recorded = {(entry["kind"], entry.get("namespace"), entry["metadata"]["name"])
                    for entry in previous["created"]}
        remaining = [obj for obj in objects if identity(obj, profile) not in recorded]
    else:
        remaining = objects
    checked = plan(args, remaining)
    if checked["collisions"]:
        raise ValueError("Occupied installation; no adoption or overwrite permitted")
    # Admission is deferred for absent namespaces. Query all remaining create
    # scopes before the first persisted write, rather than discovering a missing
    # Gateway/API grant after credentials and controllers have been created.
    # Existing owned namespaces are retained, not recreated or adopted.
    permission_objects = [obj for obj in remaining
                          if obj["kind"] != "Namespace" or not get(args, obj)]
    permission_result = permissions(args, permission_objects)
    write(args.output_dir / "installation-permissions.json", permission_result)
    if not permission_result["ready"]:
        raise ValueError("Missing application create permissions; no resources created")
    for namespace in profile.application_namespaces[1:]:
        if kube(args, "get", "namespace", namespace, "--ignore-not-found", "-o", "json"):
            if kube(args, "get", "sandboxes.agents.x-k8s.io", "-n", namespace, "-o", "json")["items"]:
                raise ValueError("Retire native execution contexts before replacing their gateway")
    marker = previous["installation_marker"] if previous else uuid.uuid4().hex
    ledger = previous or {"schema_version": 1, "expected_server": profile.expected_server,
              "installation_profile": profile.to_dict(),
              "installation_marker": marker,
              "bundle_sha256": args.bundle_sha256, "created": [], "pending": None, "completed": False}
    ledger["completed"] = False
    # The ledger is updated atomically; desired Secrets never appear in it.
    def save() -> None:
        path = args.output_dir / "creation-ledger.private.json"
        temporary = path.with_suffix(".new")
        temporary.write_text(json.dumps(ledger, indent=2) + "\n")
        temporary.chmod(0o600)
        os.replace(temporary, path)
    save()
    for obj in remaining:
        if obj["kind"] == "Namespace" and get(args, obj):
            continue
        desired = deepcopy(obj)
        if desired['kind'] in CONTROLLERS and getattr(args, 'certificate_management', {}).get('mode') == 'managed':
            from certificate_operations import wait_issued
            wait_issued(args)
        desired["metadata"]["labels"]["identity-demo-installation"] = marker
        if desired["kind"] in CONTROLLERS:
            # A newly recreated namespace can have a different restricted SCC UID range.
            ns = kube(args, "get", "namespace", desired["metadata"]["namespace"], "-o", "json")
            current_range = ns["metadata"]["annotations"]["openshift.io/sa.scc.uid-range"]
            source_range = args.namespace_uid_ranges.get(desired["metadata"]["namespace"], current_range)
            old_base, size = map(int, source_range.split("/"))
            new_base, new_size = map(int, current_range.split("/"))
            if size != new_size:
                raise ValueError("Reviewed SCC range size required")
            pod = desired["spec"]["template"]["spec"]
            for context in [pod.get("securityContext", {}), *[
                    c.get("securityContext", {}) for c in pod.get("containers", []) + pod.get("initContainers", [])]]:
                for key in ("runAsUser", "runAsGroup", "fsGroup"):
                    if isinstance(context.get(key), int) and old_base <= context[key] < old_base + size:
                        context[key] = context[key] - old_base + new_base
        admitted = kube(args, "create", "--dry-run=server", "-f", "-", "-o", "json", value=desired)
        ledger["pending"] = {"kind": desired["kind"], "apiVersion": desired["apiVersion"],
                             "metadata": desired["metadata"], "fingerprint": fingerprint(admitted)}
        save()
        created = kube(args, "create", "-f", "-", "-o", "json", value=desired)
        ledger["created"].append({"apiVersion": created["apiVersion"], "kind": created["kind"],
            "metadata": {k: created["metadata"][k] for k in ("name", "uid", "labels")},
            "namespace": created["metadata"].get("namespace"), "fingerprint": fingerprint(created)})
        ledger["pending"] = None
        save()
    ledger["completed"] = True
    save()
    return {"created_objects": len(ledger["created"]), "completed": True,
            "readiness_and_scenario_acceptance_proven": False}


def reconcile_creation(args: argparse.Namespace, objects: list[dict]) -> dict:
    """Resolve only a journaled creation; never adopt arbitrary existing objects.

    The original receipt is immutable. A resumed invocation writes a new ledger.
    Missing, replaced or changed recorded objects require explicit recovery.
    """
    ledger = json.loads(private_file(args.ledger).read_text())
    profile = getattr(args, "profile", LEGACY)
    marker = ledger.get("installation_marker", "")
    if (ledger.get("schema_version") != 1
            or ledger.get("expected_server") != profile.expected_server
            or ledger.get("installation_profile") != profile.to_dict()
            or ledger.get("bundle_sha256") != args.bundle_sha256
            or not re.fullmatch(r"[a-f0-9]{32}", marker)):
        raise ValueError("Exact resumable installation ledger and bundle required")
    desired_by_id = {identity(obj, profile): obj for obj in objects}
    desired_ids = set(desired_by_id)
    seen = set()
    entries = ledger.get("created", []) + ([ledger["pending"]] if ledger.get("pending") else [])
    for entry in entries:
        obj = {"apiVersion": entry["apiVersion"], "kind": entry["kind"],
               "metadata": deepcopy(entry["metadata"])}
        if entry.get("namespace"):
            obj["metadata"]["namespace"] = entry["namespace"]
        item = identity(obj, profile)
        if item not in desired_ids or item in seen:
            raise ValueError("Unknown or duplicate ledger entry refused")
        seen.add(item)
        current = get(args, obj)
        pending = entry is ledger.get("pending")
        if not current and pending:
            ledger["pending"] = None
            continue
        if not current:
            raise ValueError("Previously created resource is missing; recovery required")
        owned(current, profile)
        if (current["metadata"]["labels"].get("identity-demo-installation") != marker
                or entry["metadata"]["labels"].get("identity-demo-installation") != marker
                or (not pending and current["metadata"]["uid"] != entry["metadata"]["uid"])
                or not entry.get("fingerprint")
                or not recorded_configuration_matches(args, current, desired_by_id[item], entry["fingerprint"])):
            raise ValueError("Uncertain creation has replacement, drift or ownership mismatch")
        if pending:
            ledger["created"].append({"apiVersion": current["apiVersion"], "kind": current["kind"],
                "metadata": {key: current["metadata"][key] for key in ("name", "uid", "labels")},
                "namespace": current["metadata"].get("namespace"), "fingerprint": fingerprint(current)})
            ledger["pending"] = None
    return ledger


def verify(args: argparse.Namespace, objects: list[dict]) -> dict:
    """Verify owner, pinned running templates and readiness, not tool acceptance."""
    failures = []
    if getattr(args, 'certificate_management', {}).get('mode') == 'managed':
        from certificate_operations import observe
        if not observe(args)['ready']:
            failures.append('managed-certificates')
    for obj in objects:
        current = get(args, obj)
        if not current:
            failures.append(obj["kind"] + "/" + obj["metadata"]["name"])
            continue
        owned(current, getattr(args, "profile", LEGACY))
        kind = obj["kind"]
        compared = controller_projection(args, current, obj) if kind == "ConfigMap" else current
        if kind in ("ConfigMap", "Secret") and any(
                compared.get(field, {}) != obj.get(field, {}) for field in ("data", "binaryData")):
            failures.append(kind + "/" + obj["metadata"]["name"])
        # Ready Pods and familiar owner labels do not establish isolation.
        # These namespaced enforcement fields have no controller reconciliation
        # allowance: extra grants or broadened egress must fail verification.
        enforcement_fields = {"Role": ("rules",), "RoleBinding": ("roleRef", "subjects"),
                              "NetworkPolicy": ("spec",)}
        if kind == 'Certificate':
            from certificate_operations import matches
            if not matches(current, obj):
                failures.append(kind + '/' + obj['metadata']['name'])
        if kind in enforcement_fields and any(
                current.get(field) != obj.get(field) for field in enforcement_fields[kind]):
            failures.append(kind + "/" + obj["metadata"]["name"])
        if obj["kind"] in CONTROLLERS:
            desired_pod = obj["spec"]["template"]["spec"]
            actual_pod = current["spec"]["template"]["spec"]
            desired = desired_pod["containers"] + desired_pod.get("initContainers", [])
            actual = actual_pod["containers"] + actual_pod.get("initContainers", [])
            if (current["spec"].get("replicas", 1) != obj["spec"].get("replicas", 1)
                    or {v["name"]: v["image"] for v in desired} != {v["name"]: v["image"] for v in actual}
                    or current.get("status", {}).get("readyReplicas", 0) < current["spec"].get("replicas", 1)
                    or current.get("status", {}).get("observedGeneration", 0) < current["metadata"].get("generation", 1)):
                failures.append(obj["kind"] + "/" + obj["metadata"]["name"])
        if not reconciled(current):
            failures.append(kind + "/" + obj["metadata"]["name"])
    return {"ready": not failures, "failures": failures, "checked_objects": len(objects),
            "functional_scenarios_proven": False, "cluster_changed": False}


def reconciled(obj: dict) -> bool:
    """Check current controller conditions using the selected APIs' status shapes."""
    kind = obj["kind"]
    required = {"Gateway": {"Accepted", "Programmed"},
                "HTTPRoute": {"Accepted", "ResolvedRefs"},
                "AuthPolicy": {"Accepted", "Enforced"},
                "MCPGatewayExtension": {"Ready"}, "Certificate": {"Ready"}}
    if kind not in required:
        return True
    status = obj.get("status", {})
    generation = obj["metadata"].get("generation", 1)
    def accepted(conditions: list[dict]) -> bool:
        return all(any(c.get("type") == name and c.get("status") == "True"
                       and c.get("observedGeneration", status.get("observedGeneration", 0)) == generation
                       for c in conditions) for name in required[kind])
    if kind == "HTTPRoute":
        expected = obj["spec"].get("parentRefs", [])
        return bool(expected) and all(any(
            parent.get("parentRef", {}).get("name") == reference["name"]
            and parent["parentRef"].get("namespace", obj["metadata"]["namespace"])
                == reference.get("namespace", obj["metadata"]["namespace"])
            and parent["parentRef"].get("sectionName") == reference.get("sectionName")
            and accepted(parent.get("conditions", []))
            for parent in status.get("parents", [])) for reference in expected)
    return accepted(status.get("conditions", []))


def runtime_image_grants(profile: DeploymentProfile, objects: list[dict]) -> list[dict]:
    """Grant only exact local supervisor repository pulls to owned workspace SAs.

    The internal registry authenticates the kubelet separately from workload
    token mounting. Never copy registry credentials or bind all namespace SAs.
    External repositories require their separately approved pull configuration.
    """
    config = next((o for o in objects if o['kind'] == 'ConfigMap'
                   and o['metadata']['namespace'] == profile.core_namespace
                   and o['metadata']['name'] == 'fixture-openshell-config'), None)
    if config is None:
        return []
    image = tomllib.loads(config['data']['gateway.toml'])['openshell']['drivers']['kubernetes']['supervisor_image']
    registry = 'image-registry.openshift-image-registry.svc:5000/'
    if not image.startswith(registry):
        return []
    from deployment_artifacts import IMAGE_REFERENCE
    if not IMAGE_REFERENCE.fullmatch(image):
        raise ValueError('Digest-pinned native supervisor image required')
    repository = image[len(registry):].split('@', 1)[0]
    parts = repository.split('/')
    if len(parts) != 2 or parts[0] != profile.core_namespace:
        raise ValueError('Internal native image must be published in the owned core namespace')
    name = 'identity-demo-native-image-pull'
    metadata = {'name': name, 'namespace': profile.core_namespace, 'labels': profile.labels}
    return [{'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'Role',
             'metadata': deepcopy(metadata), 'rules': [{'apiGroups': ['image.openshift.io'],
                 'resources': ['imagestreams/layers'], 'resourceNames': [parts[1]], 'verbs': ['get']}]},
            {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'RoleBinding',
             'metadata': deepcopy(metadata),
             'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'Role', 'name': name},
             'subjects': [{'kind': 'ServiceAccount', 'name': 'fixture-openshell-sandbox',
                           'namespace': namespace} for namespace in profile.application_namespaces[1:]]}]


def runtime_permissions(args: argparse.Namespace, objects: list[dict]) -> dict:
    """Prepare exact native runtime and optional internal-repository pull grants.

    These are separate from application installation because their scope is
    cluster-wide. Repository pulls use a namespaced resource-name-scoped Role.
    No shared role, SCC, operator or existing grant is changed.
    """
    from deployment_profile import active_profile
    from identity_demo_runtime_grants import desired, check_existing
    from identity_demo_workspaces import render

    profile = getattr(args, 'profile', LEGACY)
    if active_profile() != profile:
        raise ValueError('Explicit operator profile must match the application bundle')
    for kind in ('serviceaccount', 'statefulset'):
        current = kube(args, 'get', kind, 'fixture-openshell', '-n', profile.core_namespace, '-o', 'json')
        owned(current, profile)
    rules = next(o['rules'] for o in objects if o['kind'] == 'Role'
                 and o['metadata']['namespace'] == profile.core_namespace
                 and o['metadata']['name'] == 'fixture-openshell-sandbox')
    grants = [*desired(), *[o for o in render(rules)
                           if o['kind'] in ('ClusterRole', 'ClusterRoleBinding')]]
    if len(grants) != 4:
        raise ValueError('Exact native prerequisite grants required')
    image_grants = runtime_image_grants(profile, objects)
    if image_grants:
        for namespace in profile.application_namespaces[1:]:
            owned(kube(args, 'get', 'namespace', namespace, '-o', 'json'), profile)
            owned(kube(args, 'get', 'serviceaccount', 'fixture-openshell-sandbox',
                       '-n', namespace, '-o', 'json'), profile)
        stream_name = image_grants[0]['rules'][0]['resourceNames'][0]
        stream = kube(args, 'get', 'imagestream', stream_name, '-n', profile.core_namespace, '-o', 'json')
        owned(stream, profile)
        expected_repository = 'image-registry.openshift-image-registry.svc:5000/' + profile.core_namespace + '/' + stream_name
        if stream.get('status', {}).get('dockerImageRepository') != expected_repository:
            raise ValueError('Exact owned native image repository required')
        grants.extend(image_grants)
    inspected = []
    # Check every collision before creating anything; broad or unowned grants
    # cannot be silently adopted or narrowed by this operation.
    for grant in grants:
        current = kube(args, 'get', grant['kind'], grant['metadata']['name'],
                       *(['-n', grant['metadata']['namespace']] if grant['metadata'].get('namespace') else []),
                       '--ignore-not-found', '-o', 'json')
        if current:
            if (current.get('kind') != grant['kind']
                    or current['metadata'].get('namespace') != grant['metadata'].get('namespace')):
                raise ValueError('Exact runtime grant kind and scope required')
            check_existing(current, grant)
        inspected.append((grant, current))
    write(args.output_dir / 'runtime-permissions.plan.json', {
        'grants': grants, 'existing': [{'kind': o['kind'], 'name': o['metadata']['name'],
            'uid': current['metadata']['uid']} for o, current in inspected if current]})
    created, admitted, deferred = [], 0, 0
    missing_roles = {(o['kind'], o['metadata'].get('namespace'), o['metadata']['name'])
                     for o, current in inspected if o['kind'] in ('Role', 'ClusterRole') and not current}
    for grant, current in inspected:
        if current:
            continue
        role_key = (grant.get('roleRef', {}).get('kind'), grant['metadata'].get('namespace'),
                    grant.get('roleRef', {}).get('name'))
        if not args.apply and grant['kind'] in ('RoleBinding', 'ClusterRoleBinding') and role_key in missing_roles:
            deferred += 1
            continue
        kube(args, 'create', '--dry-run=server', '-f', '-', '-o', 'json', value=grant)
        admitted += 1
        if args.apply:
            # Preserve each planned operation before sending it; an interrupted
            # response requires inspection, never an automatic mutation retry.
            index = len(created) + 1
            write(args.output_dir / f'runtime-permission-{index}.pending.json', grant)
            result = kube(args, 'create', '-f', '-', '-o', 'json', value=grant)
            check_existing(result, grant)
            receipt = {'kind': result['kind'], 'name': result['metadata']['name'],
                       'namespace': result['metadata'].get('namespace'),
                       'uid': result['metadata']['uid'], 'fingerprint': fingerprint(result)}
            write(args.output_dir / f'runtime-permission-{index}.created.json', receipt)
            created.append(receipt)
    return {'applied': args.apply, 'required_grants': len(grants),
            'exact_repository_pull_grants': len(image_grants),
            'existing_exact_grants': sum(bool(current) for _, current in inspected),
            'admission_checked': admitted, 'bindings_deferred_until_role_exists': deferred,
            'created': created, 'existing_resources_modified': False,
            'shared_foundation_modified': False}


def discovery_access(args: argparse.Namespace, objects: list[dict]) -> dict:
    """Connect an owned issuer to owned discovery with a new exact ingress rule.

    This changes no existing foundation policy, controller, trust or identity.
    Retain separate receipts: application cleanup does not own this attachment.
    """
    profile = getattr(args, "profile", LEGACY)
    for namespace in (profile.core_namespace, profile.identity_namespace):
        owned(kube(args, "get", "namespace", namespace, "-o", "json"), profile)
    discovery = kube(args, "get", "deployment.apps", "identity-demo-oidc-discovery",
                     "-n", profile.identity_namespace, "-o", "json")
    owned(discovery, profile)
    if discovery["spec"]["template"]["metadata"]["labels"].get("app") != "identity-demo-oidc-discovery":
        raise ValueError("Exact owned discovery target required")
    issuer = kube(args, "get", "deployment.apps", "fixture-keycloak-upstream",
                  "-n", profile.core_namespace, "-o", "json")
    owned(issuer, profile)
    selector = {"app": "fixture-keycloak-upstream", "identity-demo-owner": profile.owner}
    if any(issuer["spec"]["template"]["metadata"]["labels"].get(k) != v for k, v in selector.items()):
        raise ValueError("Exact owned issuer source required")
    policy = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {
        "name": "identity-demo-" + profile.installation_id + "-discovery-access",
        "namespace": profile.identity_namespace,
        "labels": {**profile.labels, "identity-demo-installation": profile.installation_id}},
        "spec": {"podSelector": {"matchLabels": {"app": "identity-demo-oidc-discovery"}},
                 "policyTypes": ["Ingress"], "ingress": [{"from": [{
                     "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": profile.core_namespace}},
                     "podSelector": {"matchLabels": selector}}],
                     "ports": [{"protocol": "TCP", "port": 8443}]}]}}
    current = kube(args, "get", "networkpolicy", policy["metadata"]["name"],
                   "-n", profile.identity_namespace, "--ignore-not-found", "-o", "json")
    write(args.output_dir / "discovery-access.plan.json", policy)
    if current:
        owned(current, profile)
        if (current["spec"] != policy["spec"] or current["metadata"]["labels"].get(
                "identity-demo-installation") != profile.installation_id):
            raise ValueError("Discovery access collision; existing policy is never rewritten")
        write(args.output_dir / "discovery-access.existing.json", current)
    else:
        kube(args, "create", "--dry-run=server", "-f", "-", "-o", "json", value=policy)
        if args.apply:
            write(args.output_dir / "discovery-access.pending.json", policy)
            current = kube(args, "create", "-f", "-", "-o", "json", value=policy)
            write(args.output_dir / "discovery-access.created.json", current)
    return {"applied": args.apply, "policy_present": bool(current),
            "policy_name": policy["metadata"]["name"],
            "existing_foundation_resources_modified": False,
            "live_discovery_and_delegation_validation_required": True}


def cleanup(args: argparse.Namespace) -> dict:
    """Rollback only unchanged ledger-created objects; retain state and Jira."""
    ledger = json.loads(private_file(args.ledger).read_text())
    profile = DeploymentProfile.from_dict(ledger["installation_profile"]) if ledger.get("installation_profile") else LEGACY
    if ledger.get("schema_version") != 1 or ledger.get("expected_server") != profile.expected_server:
        raise ValueError("Reviewed creation ledger required")
    if profile != getattr(args, "profile", LEGACY):
        raise ValueError("Ledger installation scope mismatch")
    if ledger.get("pending"):
        raise ValueError("Uncertain creation must be reconciled before rollback")
    objects = []
    for entry in reversed(ledger["created"]):
        obj = {"apiVersion": entry["apiVersion"], "kind": entry["kind"],
               "metadata": {**entry["metadata"]}}
        if entry.get("namespace"):
            obj["metadata"]["namespace"] = entry["namespace"]
        identity(obj, profile)
        if obj["kind"] in PRESERVE or obj["metadata"]["name"] == "fixture-jira":
            continue
        current = get(args, obj)
        if not current:
            continue
        owned(current, profile)
        if (current["metadata"]["uid"] != entry["metadata"]["uid"]
                or not entry["metadata"]["labels"].get("identity-demo-installation")
                or current["metadata"]["labels"].get("identity-demo-installation") != entry["metadata"]["labels"]["identity-demo-installation"]
                or fingerprint(current) != entry["fingerprint"]):
            raise ValueError("Replacement, drift or unrelated object refused")
        objects.append((obj, current))
    if any(o["kind"] == "StatefulSet" and o["metadata"]["name"] == "fixture-openshell" for o, _ in objects):
        for namespace in profile.application_namespaces[1:]:
            if kube(args, "get", "namespace", namespace, "--ignore-not-found", "-o", "json"):
                if kube(args, "get", "sandboxes.agents.x-k8s.io", "-n", namespace, "-o", "json")["items"]:
                    raise ValueError("Retire native contexts before removing their gateway")
    # Do not tear down a driver with an active/uncertain action.
    if any(o["metadata"]["name"] == "fixture-identity-driver" for o, _ in objects):
        from identity_demo_execution_setup import inspect_state
        args.namespace = profile.core_namespace
        if profile == LEGACY:
            quiescent = inspect_state(args)["rollback_quiescent"]
        else:
            program = """import sqlite3,os,json
d=sqlite3.connect('file:'+os.environ['DRIVER_DATABASE']+'?mode=ro',uri=True)
d.execute('BEGIN')
tables={r[0] for r in d.execute("SELECT name FROM sqlite_master WHERE type='table'")}
jobs=d.execute("SELECT count(*) FROM console_jobs WHERE state IN ('queued','running')").fetchone()[0] if 'console_jobs' in tables else 0
preparing=d.execute("SELECT count(*) FROM console_preparations WHERE state IN ('preparing','blocked')").fetchone()[0] if 'console_preparations' in tables else 0
recovery=any(json.loads(r[0]).get('failure_code')=='recovery_required' and json.loads(r[0]).get('cleanup_verified') is not True for r in d.execute("SELECT evidence FROM console_jobs WHERE state='failed'")) if 'console_jobs' in tables else False
print(json.dumps({'safe':d.execute('SELECT count(*) FROM runs WHERE active<>0').fetchone()[0]==0 and d.execute("SELECT count(*) FROM actions WHERE state IN ('executing','unknown')").fetchone()[0]==0 and jobs==0 and preparing==0 and not recovery}))"""
            quiescent = kube(args, "exec", "-n", profile.core_namespace,
                             "deployment/fixture-identity-driver", "--", "python", "-c", program)["safe"]
        if not quiescent:
            raise ValueError("Quiescent state required for rollback")
    if args.apply:
        for obj, current in objects:
            # DeleteOptions enforce UID and current version; never use name-only deletion.
            group = obj["apiVersion"].split("/")[0] if "/" in obj["apiVersion"] else ""
            version = obj["apiVersion"].split("/")[-1]
            resource = RESOURCES[obj["kind"]].split(".")[0]
            uri = ("/apis/" + group + "/" + version if group else "/api/" + version)
            uri += "/namespaces/" + obj["metadata"]["namespace"] + "/" + resource + "/" + obj["metadata"]["name"]
            kube(args, "delete", "--raw", uri, "-f", "-", value={"apiVersion": "v1",
                "kind": "DeleteOptions", "preconditions": {"uid": current["metadata"]["uid"],
                "resourceVersion": current["metadata"]["resourceVersion"]}})
    return {"eligible_objects": len(objects), "applied": args.apply,
            "namespaces_secrets_pvcs_and_jira_retained": True,
            "shared_infrastructure_changed": False}


def main() -> None:
    """All inputs/outputs are paths or sanitized status; no shell/config execution."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("certificate-status", "console-runtime-prepare", "console-runtime-publish", "native-repackage", "console-runtime-build", "cluster-runtime-plan", "security-plan", "security-check", "security-tls-plan", "runtime-check", "connected-install", "render", "native-build", "native-publish", "native-publish-resume", "native-publication-status", "diagnostic-build", "preflight", "snapshot", "prepare-access", "permissions", "plan", "install", "resume", "verify", "runtime-permissions", "discovery-access", "backup-data", "verify-backup", "restart-data", "cleanup"))
    parser.add_argument("--security-network", help="Private API/worker host-CIDR JSON for guided security rendering")
    parser.add_argument("--oc-archive", help="Exact pinned public Linux oc archive for console-runtime-build")
    parser.add_argument("--cli-archive", help="Exact pinned public Linux OpenShell archive for console-runtime-build")
    parser.add_argument("--console-runtime-stage", choices=("permissions", "policies", "realm-permissions", "configure", "trust-observation", "gateway-observation", "workloads", "update-workloads", "status", "automatic-enable", "automatic-disable"), default="permissions")
    parser.add_argument("--console-worker-receipt", help="Completed scoped worker creation summary for initial automatic pool activation")
    parser.add_argument("--console-worker-sha256", help="Exact scoped worker creation summary hash")
    parser.add_argument("--console-configuration-receipt", help="Completed private-listener configuration summary")
    parser.add_argument("--console-configuration-sha256", help="Exact private-listener configuration summary hash")
    parser.add_argument("--runtime-publication-receipt", help="Completed cluster console image publication receipt")
    parser.add_argument("--runtime-publication-sha256", help="Exact console image publication receipt hash")
    parser.add_argument("--runtime-gateway-receipt", help="Current verified persistent gateway receipt")
    parser.add_argument("--enable-public-trust-refresh", action="store_true", help="Idle update: enable scoped public-CA reconciliation and native issuer/SDS reload")
    parser.add_argument('--managed-certificate-config', help='Approved issuer UID/public CA configuration; explicit idle migration during update-workloads')
    parser.add_argument('--verify-certificate-loading', action='store_true', help='Read-only strict TLS listener/projection comparison for certificate-status')
    parser.add_argument("--refresh-sender-trust", action="store_true", help="Installer-only idle worker update: reconcile recorded owned trust copies and replace their public observation")
    parser.add_argument("--isolate-private-authorizer", action="store_true", help="Installer-only idle worker update: repair the recorded legacy private-host collision")
    parser.add_argument("--resume-worker-update", help="Pinned private manifest for an interrupted host repair before worker activation")
    parser.add_argument("--resume-worker-update-sha256", help="Exact reviewed worker recovery manifest hash")
    parser.add_argument("--refresh-adapter-code", action="store_true", help="Idle worker update: replace only the fixed catalog/action modules on the recorded protected adapter")
    parser.add_argument("--console-trust-observation-receipt", help="Installer-created public trust observation reference; no serving keys")
    parser.add_argument("--console-management-ca", help="Public target-specific native management CA")
    parser.add_argument("--console-catalog-credential", help="Current private discovery catalog credential")
    parser.add_argument("--console-ledger-sha256", help="Exact application creation ledger hash for private console configuration")
    parser.add_argument("--console-web-code-receipt", help="Configure: exact ConfigMap creation object from a later immutable UI update")
    parser.add_argument("--console-web-code-sha256", help="Required hash of the later web-code creation receipt")
    parser.add_argument("--resume-retired-pool", action="store_true", help="Automatic-enable: preserve reviewed history after every old context is durably retired")
    parser.add_argument("--namespace-creation-receipt", help="Exact namespace creation receipt from prepare-access")
    parser.add_argument("--namespace-creation-sha256", help="Hash of namespace creation receipt")
    parser.add_argument("--runtime-build-receipt", help="Completed console image build receipt")
    parser.add_argument("--runtime-build-sha256", help="Exact console build receipt hash")
    parser.add_argument("--runtime-configuration-receipt", help="Completed fixed-provider source configuration receipt for console-runtime-build")
    parser.add_argument("--runtime-check-target", choices=("local", "cluster"), default="local")
    parser.add_argument("--workload-image", help="Approved digest-pinned CVE workload image for runtime-check")
    parser.add_argument("--kubeconfig")
    parser.add_argument("--expected-server")
    parser.add_argument("--installation-config", help="Private source-render configuration; never executable code")
    parser.add_argument("--installation-profile", help="Rendered profile for a local target-bound native build")
    parser.add_argument("--native-cache-receipt", help="Optional completed build receipt for private dependency cache; workspace binaries are discarded")
    parser.add_argument("--native-cache-sha256", help="Explicit hash of prior dependency cache receipt")
    parser.add_argument("--compiler-cache-receipt", help="Optional completed private compiler build receipt; native binaries are still rebuilt")
    parser.add_argument("--compiler-cache-sha256", help="Explicit hash of prior compiler receipt")
    parser.add_argument("--source-archive", help="Exact pinned OpenShell source archive; local file only")
    parser.add_argument("--spire-archive", help="Exact pinned public SPIRE diagnostic archive; local file only")
    parser.add_argument("--native-ca-bundle", help="Rendered canonical public CA bundle; never private keys")
    parser.add_argument("--native-build-receipt", help="Completed local native build receipt outside Git")
    parser.add_argument("--native-build-sha256", help="Explicit expected native build receipt hash")
    parser.add_argument("--publication-network", help="Reviewed private build-only API/HTTPS destination CIDRs")
    parser.add_argument("--publication-id", help="Optional distinct attempt ID; failed build history is retained")
    parser.add_argument("--publication-plan", help="Exact prior binary-build publication plan for status/cleanup")
    parser.add_argument("--publication-plan-sha256", help="Explicit expected publication plan hash")
    parser.add_argument("--artifacts-file", help="Existing five-role private artifact lock for publication output")
    parser.add_argument("--cli", help="Pinned OpenShell CLI for connected installation")
    parser.add_argument("--readiness-timeout", type=int, default=600)
    parser.add_argument("--engine", choices=("docker", "podman"), default="podman")
    parser.add_argument("--state-file", help="Existing private generated keys; omit only for a fresh render")
    parser.add_argument("--resume-installation", help="Previous connected-install output; only a failed read-only discovery-plan checkpoint is resumable")
    parser.add_argument("--inference-config", help="Optional private model configuration to validate and retain by path for console handoff")
    parser.add_argument("--credentials-file")
    parser.add_argument("--installer-user", help="Exact authenticated non-admin user for explicit prepare-access only")
    parser.add_argument("--oc", default="oc")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--bundle")
    parser.add_argument("--bundle-sha256")
    parser.add_argument("--ledger")
    parser.add_argument("--allow-idle-heartbeat", action="store_true", help="Backup: allow only coordinator/preparer heartbeat timestamp changes between quiescent snapshots")
    parser.add_argument("--backup-manifest", help="Private application-data backup manifest; offline verification only")
    parser.add_argument("--backup-sha256", help="Required manifest hash from a separate backup receipt")
    parser.add_argument("--server-dry-run", action="store_true")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        out = args.output_dir.expanduser()
        if (not out.is_absolute() or out.is_symlink() or out.exists()
                or in_checkout(out.resolve()) or out.parent.stat().st_mode & 0o077):
            raise ValueError("New output directory in private external parent required")
        out.mkdir(mode=0o700)
        args.output_dir = out
        args.profile = LEGACY
        bundle = None
        if args.action == "connected-install":
            from connected_install import connected_install
            result = connected_install(args)
            write(out / "setup.summary.json", result)
            print(json.dumps(result))
            if not result.get("ready", False):
                raise SystemExit(1)
            return
        if args.action in ("native-publish", "native-publish-resume", "native-publication-status"):
            from native_publication import publication, publication_status, resume_publication
            if not args.kubeconfig or not args.expected_server:
                raise ValueError("Explicit kubeconfig and expected server required")
            result = {"native-publish": publication, "native-publish-resume": resume_publication,
                      "native-publication-status": publication_status}[args.action](args)
            write(out / "setup.summary.json", result)
            print(json.dumps(result))
            return
        local_actions = {
            "cluster-runtime-plan": ("cluster_console_plan", "run"),
            "console-runtime-build": ("console_runtime_build", "run"),
            "console-runtime-prepare": ("cluster_console_install", "run"),
            "console-runtime-publish": ("native_publication", "console_publication"),
            "security-plan": ("security_setup", "run"),
            "security-tls-plan": ("security_setup", "run"),
            "security-check": ("security_setup", "run"),
            "runtime-check": ("runtime_delivery", "run"),
            "diagnostic-build": ("diagnostic_build", "diagnostic_build"),
            "native-build": ("native_build", "native_build"),
            "native-repackage": ("native_build", "repackage"),
            "verify-backup": ("deployment_backup", "verify_backup"),
            "certificate-status": ("certificate_operations", "run"),
        }
        if args.action in local_actions:
            module, function = local_actions[args.action]
            result = getattr(import_module(module), function)(args)
            write(out / "setup.summary.json", result)
            print(json.dumps(result))
            if result.get("runtime_interface_checks_passed") is False:
                raise SystemExit(1)
            return
        if args.action == "render":
            from source_render import read_json, render
            config = private_file(args.installation_config)
            state = read_json(private_file(args.state_file)) if args.state_file else None
            bundle, state, credentials = render(config, state)
            validate(bundle)
            write(out / "installation-state.private.json", state)
            write(out / "fixture-credentials.private.json", credentials)
            write(out / "installation-profile.json", bundle["installation_profile"])
            with (out / "native-public-trust.pem").open("x") as stream:
                os.chmod(stream.name, 0o600)
                stream.write(bundle["native_ca_bundle_pem"])
            with (out / "runtime-gateway-ca.pem").open("x") as stream:
                os.chmod(stream.name, 0o600)
                stream.write(state["application_ca"])
            write(out / "native-build-contract.json", {
                "native_build_contract": bundle["native_build_contract"],
                "native_ca_bundle_sha256": bundle["native_ca_bundle_sha256"]})
            bundle_path = out / "stack.private.json"
            write(bundle_path, bundle)
            result = {"source_rendered": True, "objects": len(bundle["objects"]),
                      "bundle_sha256": sha(bundle_path), "private_bundle": str(bundle_path),
                      "fresh_keys_generated": not bool(args.state_file),
                      "native_build_contract_matches": bundle["native_build_contract_matches"],
                      "cluster_changed": False, "fresh_installation_proven": False}
            write(out / "setup.summary.json", result)
            print(json.dumps(result))
            return
        if not args.kubeconfig or not args.expected_server:
            raise ValueError("Explicit kubeconfig and expected server required")
        if args.installation_config:
            from source_render import read_json
            config = read_json(private_file(args.installation_config))
            args.profile = DeploymentProfile.from_dict(config["profile"])
            from managed_certificates import configuration
            args.certificate_management, args.certificate_authority_pem = configuration(config)
        if args.action in ("prepare-access", "permissions", "plan", "install", "resume", "verify", "runtime-permissions", "discovery-access", "backup-data", "restart-data"):
            path = private_file(args.bundle)
            if not args.bundle_sha256 or sha(path) != args.bundle_sha256:
                raise ValueError("Explicit matching bundle hash required")
            bundle = json.loads(path.read_text())
            args.profile = DeploymentProfile.from_dict(bundle["installation_profile"]) if bundle.get("schema_version") == 2 else LEGACY
            args.certificate_management = bundle.get('certificate_management', {'mode': 'legacy'})
            args.certificate_authority_pem = bundle.get('certificate_authority_pem')
        if args.action == "cleanup":
            ledger = json.loads(private_file(args.ledger).read_text())
            if ledger.get("installation_profile"):
                args.profile = DeploymentProfile.from_dict(ledger["installation_profile"])
        prerequisites = target(args)
        if getattr(args, 'certificate_management', {}).get('mode') == 'managed':
            from certificate_operations import preflight as certificate_preflight
            prerequisites['certificates'] = certificate_preflight(args)
        if args.action == "preflight":
            result = prerequisites
        elif args.action == "snapshot":
            args.credentials_file = str(private_file(args.credentials_file))
            result = snapshot(args)
        elif args.action == "cleanup":
            args.credentials_file = str(private_file(args.credentials_file))
            result = cleanup(args)
        elif args.action in ("backup-data", "restart-data"):
            from deployment_backup import backup_data, restart_data
            validate(bundle)
            result = backup_data(args) if args.action == "backup-data" else restart_data(args)
        else:
            args.bundle_version = bundle["schema_version"]
            args.native_build_contract_matches = bundle.get("native_build_contract_matches", False)
            args.ingress_aliases_configured = bundle.get("ingress_aliases_configured")
            args.namespace_uid_ranges = bundle.get("namespace_uid_ranges", {})
            args.certificate_management = bundle.get('certificate_management', {'mode': 'legacy'})
            args.certificate_authority_pem = bundle.get('certificate_authority_pem')
            objects = validate(bundle)
            for name, expected in bundle.get("source_pins", {}).items():
                source = ROOT / name
                if not source.resolve().is_relative_to(ROOT) or sha(source) != expected:
                    raise ValueError("Source changed since bundle capture; recapture required")
            result = {"prepare-access": prepare_access, "permissions": permissions, "plan": plan, "install": install, "resume": install, "verify": verify,
                      "runtime-permissions": runtime_permissions, "discovery-access": discovery_access}[args.action](args, objects)
        write(out / "setup.summary.json", result)
        print(json.dumps(result))
        if result.get("ready") is False:
            raise SystemExit(1)
    except Exception as error:
        print(json.dumps({"completed": False, "failure_kind": type(error).__name__,
                          "details_withheld": True}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
