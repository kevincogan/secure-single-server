#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Repeat the accepted first-lab context preparation with private operator inputs.

This adopts the tested native-create and additive driver-update recipes. It does
not bootstrap a new cluster, grant privileges, reset run state or change an issuer.
Plan mode is the default; --apply changes only the named owned pilot resources.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "identity_demo"))

from execution_context import ExecutionContext, resolve_context, context_identity  # noqa: E402
import probe_native_exchange as native  # noqa: E402
from identity_demo_lab import LABELS  # noqa: E402
from identity_demo_runtime import guard  # noqa: E402
from identity_demo_spire_registration import CVE_IMAGE, prepare  # noqa: E402
from identity_demo_runtime_cli import private_path  # noqa: E402
from probe_native_identity import probe  # noqa: E402
from deployment_profile import active_profile  # noqa: E402


SANDBOX_CPU = "50m"
SANDBOX_MEMORY = "128Mi"


def require(condition: bool, reason: str) -> None:
    """Stop on an ownership or contract mismatch without exposing API contents."""
    if not condition:
        raise ValueError(reason)


def context_template(role: str, suffix: str) -> ExecutionContext:
    """Select only the existing allowlisted workspace and native naming contract."""
    require(role in ("triage", "reader") and isinstance(suffix, str)
            and bool(re.fullmatch(r"[a-z0-9]{1,3}", suffix)),
            "Reviewed role and short unique suffix required")
    name = "demo-s56-" + role + "-" + suffix
    require(len(name) <= 19, "Native name exceeds 19 characters")
    namespace = active_profile().namespace_for(role)
    registration = "identity-demo-step56-" + (
        "" if active_profile().installation_id == "identity-demo" else active_profile().installation_id + "-")
    return ExecutionContext(name, "00000000-0000-0000-0000-000000000000", role,
        "fixture-openshell-sandbox", registration + role + "-" + suffix,
        name + "-exchange", namespace, namespace)


def owned(value: dict) -> None:
    """Require the existing repository owner labels before any update."""
    require(all(value["metadata"].get("labels", {}).get(k) == v for k, v in LABELS.items()),
            "Owned pilot resource required")


def read(args: argparse.Namespace, kind: str, name: str,
         namespace: str | None = None, *, optional: bool = False) -> dict:
    """Read one exact resource through an explicit private kubeconfig."""
    return native.kube(args, "get", kind, name, *(["-n", namespace] if namespace else []),
        *(["--ignore-not-found"] if optional else []), "-o", "json")


def prepare_workspaces(args: argparse.Namespace) -> dict:
    """Create absent owner-labelled native records for the two owned namespaces."""
    _, credentials, _ = guard(args)
    profile = active_profile()
    for namespace in profile.application_namespaces[1:]:
        owned(read(args, 'namespace', namespace))
    config = read(args, 'configmap', 'fixture-openshell-config', native.NAMESPACE)
    owned(config)
    require(json.loads(config['data']['namespaces.json']) == list(profile.application_namespaces[1:]),
            'Exact owned namespace allowlist required')
    require(isinstance(args.ca_file, str), 'Explicit fresh gateway CA file required')
    private_path(args.ca_file)
    with native.native_session(args, credentials, initialize_profile=True) as execute:
        records = native.inventory(execute(['workspace', 'list', '--output', 'json'], json_output=True), 'workspaces')
        names = profile.application_namespaces[1:]
        for name in names:
            existing = [w for w in records if w.get('name') == name]
            require(len(existing) <= 1, 'Ambiguous native workspace refused')
            if existing:
                labels = existing[0].get('labels', {})
                require(labels.get('identity-demo-owner') == profile.owner
                    and labels.get('identity-demo-installation') == profile.installation_id,
                    'Native workspace ownership collision refused')
        absent = [n for n in names if not any(w.get('name') == n for w in records)]
        if args.apply:
            for name in absent:
                native.private_write(args.output_dir / (name + '.pending.json'), {'workspace': name})
                execute(['workspace', 'create', '--name', name,
                         '--label', 'identity-demo-owner=' + profile.owner,
                         '--label', 'identity-demo-installation=' + profile.installation_id])
            after = native.inventory(execute(['workspace', 'list', '--output', 'json'], json_output=True), 'workspaces')
            native.private_write(args.output_dir / 'native-workspaces.private.json', after)
            require(all(any(w.get('name') == n
                    and w.get('labels', {}).get('identity-demo-owner') == profile.owner
                    and w.get('labels', {}).get('identity-demo-installation') == profile.installation_id
                    for w in after) for n in names), 'Native workspace creation unconfirmed')
    return {'applied': args.apply, 'workspaces': list(names), 'absent_before': absent,
            'native_workspace_records_ready': args.apply or not absent,
            'kubernetes_namespaces_modified': False, 'sandbox_created': False}


def provision(args: argparse.Namespace) -> dict:
    """Create one native sandbox and its exact registration; never reuse an ID."""
    context = context_template(args.role, args.suffix)
    contract = getattr(args,'pool_profile',None)
    workload_image = contract['workload_image'] if contract else CVE_IMAGE
    policy_path = ROOT / 'tests/identity_demo/cve-runtime-policy.yaml'
    if contract:
        import yaml
        from identity_demo_pool_profiles import fingerprint
        require(contract['role']==args.role and contract['namespace']==context.namespace,
                'Compatible approved preparation profile required')
        policy_path = args.output_dir/'profile-policy.yaml'
        native.private_write(policy_path,contract['policy'])
        # The native CLI accepts JSON as YAML; retain the exact trusted payload.
    args.execution_context = context
    _, credentials, _ = guard(args)
    owned(read(args, "namespace", context.namespace))
    existing = read(args, "sandboxes.agents.x-k8s.io", context.sandbox_name,
                    context.namespace, optional=True)
    recovering = args.action == "recover-provision"
    require(bool(existing) if recovering else not existing,
            "Recovery requires existing owned sandbox; creation requires unused name")
    if recovering:
        labels = existing["metadata"].get("labels", {})
        spec = existing["spec"]["podTemplate"]["spec"]
        require(labels.get("openshell.ai/gateway-id") == active_profile().gateway_id
            and labels.get("openshell.ai/managed-by") == "openshell"
            and spec.get("serviceAccountName") == context.service_account
            and len(spec["containers"]) == 1 and spec["containers"][0]["image"] == workload_image,
            "Existing sandbox is not the reviewed owned execution")
    from identity_demo_controller_identity import enabled as controller_identities
    if not controller_identities():
        require(not read(args, "clusterstaticentries.spire.spiffe.io", context.registration_name,
                         optional=True), "Registration name already occupied")
    if not args.apply:
        return {"planned": True, "applied": False, "namespace": context.namespace,
                "sandbox_name": context.sandbox_name, "image": workload_image,
                "cpu": SANDBOX_CPU, "memory": SANDBOX_MEMORY}
    with native.native_session(args, credentials) as execute:
        if not recovering:
            made = execute(["sandbox", "create", "--name", context.sandbox_name, "--from", workload_image,
                "--cpu", SANDBOX_CPU, "--memory", SANDBOX_MEMORY, "--policy",
                str(policy_path), "--detach",
                "--restart-policy", "always", "--no-tty", "--output", "json", "--",
                "python", "-u", "-c", "import time; time.sleep(86400)"], json_output=True)
            native.private_write(args.output_dir / "native-create.private.json", made)
        else:
            native.private_write(args.output_dir / "native-existing.private.json", existing)
        state = execute(["sandbox", "get", context.sandbox_name, "--output", "json"],
                        json_output=True)
        require(state["phase"] == "Ready", "Native sandbox did not become Ready")
        if recovering:
            require(state["id"] == existing["metadata"]["labels"]["openshell.ai/sandbox-id"],
                    "Native recovery identity mismatch")
        context = replace(context, sandbox_id=state["id"])
        args.execution_context = context
    native.private_write(args.output_dir / "native-context.pending.private.json", asdict(context))
    gateway = read(args, "statefulset", "fixture-openshell", native.NAMESPACE)
    owned(gateway)
    supervisor = read(args, "pod", "os-supervisor-" + context.sandbox_id, context.namespace)
    if controller_identities():
        from identity_demo_controller_identity import wait_ready, verify_gateway
        verify_gateway(lambda k, n, ns=None: read(args, k, n, ns))
        policy = wait_ready(context, lambda k, n, ns=None: read(args, k, n, ns))
        native.private_write(args.output_dir / "controller-policy.private.json", policy)
        location = args.output_dir / "context.private.json"
        native.private_write(location, asdict(context))
        require(resolve_context(str(location), lambda k, n, ns=None: read(args, k, n, ns), contract=contract) == context,
                "Fresh controller-derived context validation failed")
        return {"applied": True, "native_ready": True, "registration_exact": True,
                "registration_mode": "controller", "namespace": context.namespace,
                "sandbox_name": context.sandbox_name,
                "identity_delivery_and_protected_read_unproved": True}
    objects = prepare(args.kubeconfig, context.sandbox_id, context.sandbox_name,
        gateway["spec"]["template"]["spec"]["containers"][0]["image"],
        supervisor["spec"]["containers"][0]["image"],
        registration_name=context.registration_name, workload_namespace=context.namespace)["items"]
    for obj in objects:
        name = obj["metadata"]["name"]
        before = read(args, "clusterstaticentries.spire.spiffe.io", name, optional=True)
        if before:
            owned(before)
            if getattr(args, 'isolated_preparation', False):
                require(name == active_profile().gateway_registration_name and before['spec'] == obj['spec'],
                        'Shared gateway registration repair requires idle maintenance')
                continue
            require(name == active_profile().gateway_registration_name
                and before["spec"]["spiffeID"] == obj["spec"]["spiffeID"]
                and before["spec"]["className"] == obj["spec"]["className"],
                "Only the existing gateway's exact registration may refresh")
            native.private_write(args.output_dir / "gateway-registration-before.private.json", before)
            if before["spec"] == obj["spec"]:
                continue
            operations = [
                {"op": "test", "path": "/metadata/uid", "value": before["metadata"]["uid"]},
                {"op": "test", "path": "/metadata/resourceVersion", "value": before["metadata"]["resourceVersion"]},
                {"op": "test", "path": "/spec", "value": before["spec"]},
                {"op": "replace", "path": "/spec", "value": obj["spec"]}]
            made = native.kube(args, "patch", "clusterstaticentries.spire.spiffe.io", name,
                               "--type=json", "-p", json.dumps(operations), "-o", "json")
        else:
            require(not getattr(args, 'isolated_preparation', False) or name == context.registration_name,
                    'Missing shared gateway registration requires idle maintenance')
            native.kube(args, "create", "--dry-run=server", "-f", "-", "-o", "json", payload=obj)
            made = native.kube(args, "create", "-f", "-", "-o", "json", payload=obj)
        native.private_write(args.output_dir / (name + ".private.json"), made)
    location = args.output_dir / "context.private.json"
    native.private_write(location, asdict(context))
    require(resolve_context(str(location), lambda k, n, ns=None: read(args, k, n, ns), contract=contract) == context,
            "Fresh native context validation failed")
    return {"applied": True, "native_ready": True, "registration_exact": True,
            "namespace": context.namespace, "sandbox_name": context.sandbox_name,
            "identity_delivery_and_protected_read_unproved": True}


def append_contexts(config: dict, contexts: list[ExecutionContext],
                    workflow: str, project: str) -> dict:
    """Add trusted mappings without removing a retired identity or permission."""
    require(workflow in ("cve", "service-request", "incident-triage") and bool(re.fullmatch(r"[A-Z][A-Z0-9]{1,15}", project)),
            "Reviewed workflow and project required")
    require(workflow == "cve" or project != config.get("project", "TEST"),
            "Service requests need a separate synthetic project")
    require(workflow != "incident-triage" or project == "OPS", "Incident triage requires the dedicated OPS project")
    result = json.loads(json.dumps(config))
    for context in contexts:
        require(not any(c["workload"] == context.workload for c in result["contexts"]),
                "Context already mapped; no reassignment permitted")
        require(workflow == "cve" or context.role == "triage",
                "Service-request prototype uses the existing triage permission role")
        result["contexts"].append({**asdict(context), "workload": context.workload,
                                   "workflow": workflow, "project": project})
    return result


def diagnostic_container(uid: int) -> dict:
    """Stage tools into the shared run volume without mounting tokens or SVIDs."""
    require(type(uid) is int and uid > 0, "Non-root native UID required")
    return {"name": "step56-diagnostic-stage",
        "image": "registry.example.test/demo/jira-runtime@sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "imagePullPolicy": "IfNotPresent",
        "command": ["python", "-c", "import time; time.sleep(180)"],
        "securityContext": {"runAsUser": uid, "runAsNonRoot": True,
            "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]},
            "seccompProfile": {"type": "RuntimeDefault"}},
        "volumeMounts": [{"name": "run", "mountPath": "/run/openshell"}]}


def diagnostic_payload(pod: dict, container: dict) -> dict:
    """Preserve the admitted Pod security context for ephemeral SCC admission.

    The subresource only permits ephemeral-container changes, but OpenShift
    admission still needs the original Pod's SCC annotations and security spec.
    """
    result = json.loads(json.dumps(pod))
    result.pop('status', None)
    result['metadata'].pop('managedFields', None)
    result['spec']['ephemeralContainers'] = [*pod['spec'].get('ephemeralContainers', []), container]
    return result


def diagnostic_access(args: argparse.Namespace) -> dict:
    """Explicitly create/remove one operator's exact supervisor diagnostic grant.

    This is separate from staging: no implicit privilege grant, administrator
    login, shared role change or permission on another Pod is permitted.
    """
    require(len(args.context_file) == 1, 'Exactly one live context required')
    guard(args)
    context = resolve_context(args.context_file[0], lambda k, n, ns=None: read(args, k, n, ns))
    profile = active_profile()
    user = getattr(args, 'installer_user', None)
    require(isinstance(user, str) and bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9@._-]{0,127}', user))
            and user not in ('admin', 'kubeadmin', 'cluster-admin'),
            'Explicit non-admin installer username required')
    actual = subprocess.run(['oc', '--kubeconfig', args.kubeconfig, '--request-timeout=15s', 'whoami'],
                            capture_output=True, text=True, timeout=20)
    require(actual.returncode == 0 and actual.stdout.strip() == user,
            'Diagnostic grant recipient must be the authenticated installer')
    owned(read(args, 'namespace', context.namespace))
    pod_name = 'os-supervisor-' + context.sandbox_id
    pod = read(args, 'pod', pod_name, context.namespace)
    require(not pod['metadata'].get('deletionTimestamp')
        and pod['metadata'].get('labels', {}).get('openshell.ai/sandbox-id') == context.sandbox_id
        and pod['metadata'].get('labels', {}).get('openshell.ai/gateway-id') == profile.gateway_id,
        'Exact live owned supervisor required')
    name = 'identity-demo-diagnostic-' + context.sandbox_id
    metadata = {'name': name, 'namespace': context.namespace, 'labels': dict(LABELS),
        'annotations': {'identity-demo-supervisor-uid': pod['metadata']['uid']}}
    grants = [{'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'Role',
        'metadata': json.loads(json.dumps(metadata)), 'rules': [{'apiGroups': [''],
            'resources': ['pods/ephemeralcontainers'], 'resourceNames': [pod_name], 'verbs': ['update']}]},
        {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'RoleBinding',
         'metadata': metadata, 'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'Role', 'name': name},
         'subjects': [{'kind': 'User', 'apiGroup': 'rbac.authorization.k8s.io', 'name': user}]}]
    inspected = []
    for grant in grants:
        current = read(args, grant['kind'], name, context.namespace, optional=True)
        if current:
            owned(current)
            require(current['metadata'].get('namespace') == context.namespace
                and current['metadata'].get('annotations', {}).get('identity-demo-supervisor-uid') == pod['metadata']['uid']
                and not current['metadata'].get('deletionTimestamp')
                and not current.get('aggregationRule')
                and all(current.get(k) == grant.get(k) for k in ('rules', 'roleRef', 'subjects')),
                'Different existing diagnostic grant refused')
        inspected.append((grant, current))
    native.private_write(args.output_dir / 'diagnostic-access.plan.private.json',
        {'grants': grants, 'existing': [v for _, v in inspected if v]})
    removing = args.action == 'retire-diagnostic-access'
    changed, deferred = [], 0
    for index, (grant, current) in enumerate(inspected):
        if removing:
            if not current or not args.apply:
                continue
            uri = '/apis/rbac.authorization.k8s.io/v1/namespaces/' + context.namespace + '/' + (
                'roles/' if grant['kind'] == 'Role' else 'rolebindings/') + name
            native.private_write(args.output_dir / (grant['kind'] + '.delete.pending.json'), current)
            native.kube(args, 'delete', '--raw', uri, '-f', '-', payload={'apiVersion': 'v1',
                'kind': 'DeleteOptions', 'preconditions': {'uid': current['metadata']['uid'],
                    'resourceVersion': current['metadata']['resourceVersion']}})
            changed.append({'kind': grant['kind'], 'uid': current['metadata']['uid']})
        elif not current:
            if index == 1 and not args.apply and not inspected[0][1]:
                deferred += 1
                continue
            native.kube(args, 'create', '--dry-run=server', '-f', '-', '-o', 'json', payload=grant)
            if args.apply:
                native.private_write(args.output_dir / (grant['kind'] + '.create.pending.json'), grant)
                created = native.kube(args, 'create', '-f', '-', '-o', 'json', payload=grant)
                native.private_write(args.output_dir / (grant['kind'] + '.created.private.json'), created)
                changed.append({'kind': grant['kind'], 'uid': created['metadata']['uid']})
    return {'applied': args.apply, 'removal_requested': removing, 'changed': changed,
            'namespace': context.namespace, 'pod_name': pod_name, 'installer_user': user,
            'binding_admission_deferred': deferred, 'other_pods_or_serviceaccounts_granted': False,
            'shared_resources_modified': False}


def stage(args: argparse.Namespace) -> dict:
    """Repeat accepted tool staging, then verify the actual supervisor's SVID."""
    require(len(args.context_file) == 1, "Exactly one fresh context receipt required")
    guard(args)
    context = resolve_context(args.context_file[0], lambda k, n, ns=None: read(args, k, n, ns))
    files = []
    for supplied, destination in [(args.spire_agent_binary, "step4-spire-agent"),
                                  (args.mcp_client_binary, "step4-read-native-projection")]:
        require(isinstance(supplied, str), "Both reviewed Linux diagnostic binaries required")
        path = Path(supplied)
        require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size < 50_000_000,
                "Bounded regular diagnostic binary required")
        data = path.read_bytes()
        require(data[:4] == b"\x7fELF", "Linux ELF diagnostic binary required")
        files.append((destination, data))
    pod_name = "os-supervisor-" + context.sandbox_id
    pod = read(args, "pod", pod_name, context.namespace)
    item = diagnostic_container(pod["spec"]["containers"][0]["securityContext"]["runAsUser"])
    require(not any(c["name"] == item["name"] for c in pod["spec"].get("ephemeralContainers", [])),
            "Diagnostic already staged; do not repeat or overwrite it")
    if not args.apply:
        return {"planned": True, "applied": False, "shared_run_volume_only": True,
                "diagnostic_hashes": {name: hashlib.sha256(data).hexdigest() for name, data in files}}
    native.private_write(args.output_dir / "pod-before.private.json", pod)
    payload = diagnostic_payload(pod, item)
    uri = "/api/v1/namespaces/" + context.namespace + "/pods/" + pod_name + "/ephemeralcontainers"
    native.kube(args, "replace", "--raw", uri + "?dryRun=All", "-f", "-", payload=payload)
    native.kube(args, "replace", "--raw", uri, "-f", "-", payload=payload)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        current = read(args, "pod", pod_name, context.namespace)
        require(current["metadata"]["uid"] == pod["metadata"]["uid"], "Supervisor replaced during staging")
        status = next((v for v in current["status"].get("ephemeralContainerStatuses", [])
                       if v["name"] == item["name"]), {})
        if "running" in status.get("state", {}):
            break
        time.sleep(0.5)
    else:
        raise TimeoutError("Diagnostic staging did not start")
    for destination, data in files:
        program = ("import os,sys;data=sys.stdin.buffer.read(50000000);assert len(data)<50000000;"
            "fd=os.open('/run/openshell/" + destination + "',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o555);"
            "f=os.fdopen(fd,'wb');f.write(data);f.close()")
        result = subprocess.run(["oc", "--kubeconfig", args.kubeconfig, "-n", context.namespace,
            "exec", "-i", pod_name, "-c", item["name"], "--", "python", "-c", program],
            input=data, capture_output=True, timeout=45)
        native.private_write(args.output_dir / (destination + ".transfer.private.json"), {
            "exit": result.returncode, "stderr": result.stderr.decode(errors="replace")})
        require(result.returncode == 0, "Diagnostic transfer failed")
    evidence = probe(argparse.Namespace(kubeconfig=args.kubeconfig, namespace=context.namespace,
        pod=pod_name, container="supervisor", binary="/run/openshell/step4-spire-agent",
        expected_spiffe_id=context.workload, output_dir=args.output_dir, label="staged-native"))
    require(evidence["passed"], "Native attested SVID chain verification failed")
    return {"applied": True, "shared_run_volume_only": True, "attested_svid_chain_verified": True,
            "diagnostic_hashes": {name: hashlib.sha256(data).hexdigest() for name, data in files},
            "protected_read_unproved": True}


def console_audience_mapper(client: dict, owner: str, audience: str) -> dict:
    """Pin the intended signed audience independently of temporary client existence."""
    require(client.get("clientId") == "identity-demo-driver" and client.get("publicClient") is True
        and client.get("standardFlowEnabled") is True
        and client.get("attributes", {}).get("identity-demo-owner") == owner
        and client.get("attributes", {}).get("pkce.code.challenge.method") == "S256",
        "Exact owned PKCE driver client required")
    matches = [m for m in client.get("protocolMappers", []) if m.get("name") == "next-recipient"]
    require(len(matches) == 1 and matches[0].get("protocolMapper") == "oidc-audience-mapper",
            "Exact driver audience mapper required")
    mapper = json.loads(json.dumps(matches[0]))
    config = mapper["config"]
    require(config.get("access.token.claim") == "true" and config.get("id.token.claim") == "false"
        and ((config.get("included.client.audience") == audience and "included.custom.audience" not in config)
             or (config.get("included.custom.audience") == audience and "included.client.audience" not in config)),
        "Existing exact gateway audience contract required")
    config.pop("included.client.audience", None)
    config["included.custom.audience"] = audience
    return mapper


def prepare_console(args: argparse.Namespace) -> dict:
    """Reconcile one owned login mapper; never loosen token recipients or recreate a realm."""
    from identity_demo_keycloak_upstream import BASE, IMAGE, issuer_request
    from urllib.parse import urlencode
    _, credentials, _ = guard(args)
    require(inspect_state(args)["rollback_quiescent"], "Console preparation requires a quiescent driver")
    deployment = read(args, "deployment", "fixture-keycloak-upstream", native.NAMESPACE)
    owned(deployment)
    require(deployment["spec"]["template"]["spec"]["containers"][0]["image"] == IMAGE,
            "Pinned owned exchange issuer required")
    token = issuer_request(BASE, "/realms/master/protocol/openid-connect/token", method="POST",
        fields={"grant_type": "password", "client_id": "admin-cli", "username": "fixture-admin",
                "password": credentials["keycloak_admin"]})[1]["access_token"]
    clients = issuer_request(BASE, "/admin/realms/identity-demo/clients?" + urlencode({"clientId": "identity-demo-driver"}), token=token)[1]
    require(len(clients) == 1, "One owned driver client required")
    current = clients[0]
    candidates = [m for m in current.get("protocolMappers", []) if m.get("name") == "next-recipient"]
    require(len(candidates) == 1, "Exact driver mapper required")
    mapper_path = "/admin/realms/identity-demo/clients/" + current["id"] + "/protocol-mappers/models/" + candidates[0]["id"]
    authoritative = issuer_request(BASE, mapper_path, token=token)[1]
    current["protocolMappers"] = [authoritative if m.get("id") == authoritative["id"] else m for m in current["protocolMappers"]]
    audience = "spiffe://" + active_profile().trust_domain + "/openshell/gateway/" + active_profile().gateway_id
    desired = console_audience_mapper(current, active_profile().owner, audience)
    before = next(m for m in current["protocolMappers"] if m["id"] == desired["id"])
    native.private_write(args.output_dir / "driver-audience-before.private.json", before)
    native.private_write(args.output_dir / "driver-audience-desired.private.json", desired)
    changed = before != desired
    if args.apply and changed:
        path = "/admin/realms/identity-demo/clients/" + current["id"] + "/protocol-mappers/models/" + desired["id"]
        observed = issuer_request(BASE, path, token=token)[1]
        require(observed == before, "Driver audience mapper changed during preparation")
        issuer_request(BASE, path, token=token, method="PUT", value=desired)
        require(issuer_request(BASE, path, token=token)[1] == desired, "Driver audience update verification failed")
    return {"applied": args.apply, "mapper_changed": changed,
            "signed_gateway_audience_preserved": True, "fresh_login_required": changed,
            "realm_recreated": False}


def console_model_contract(source: str) -> str:
    """Read the fixed evidence-model contract without executing installed code."""
    import ast
    tree = ast.parse(source)
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'safe_evidence']
    models = []
    if len(functions) == 1:
        for node in ast.walk(functions[0]):
            if not (isinstance(node, ast.If) and isinstance(node.test, ast.BoolOp)
                    and isinstance(node.test.op, ast.And)):
                continue
            values = {}
            for part in node.test.values:
                if (isinstance(part, ast.Compare) and len(part.ops) == 1 and isinstance(part.ops[0], ast.Eq)
                        and isinstance(part.left, ast.Name) and len(part.comparators) == 1
                        and isinstance(part.comparators[0], ast.Constant)
                        and isinstance(part.comparators[0].value, str)):
                    values[part.left.id] = part.comparators[0].value
            if values.get('key') == 'model' and 'item' in values:
                models.append(values['item'])
    require(len(models) == 1 and bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}', models[0])),
            'One reviewed console model contract required')
    return models[0]


def project_driver_artifacts(deployment: dict, data: dict) -> None:
    """Migrate an old driver using only the explicit reviewed public image lock."""
    filename = os.environ.get('IDENTITY_DEMO_ARTIFACTS')
    if not filename:
        return  # Legacy code-only updates do not opt into a new pool contract.
    from deployment_artifacts import configured_native_image, validate_artifacts
    approved = {role: configured_native_image(role)
                for role in ('openshell_gateway', 'openshell_supervisor')}
    value = validate_artifacts(json.loads(Path(filename).read_text()))
    require(all(value['images'][role] == image for role, image in approved.items()),
            'Native artifact lock changed during validation')
    # Never copy extra delivery metadata or credentials into a public ConfigMap.
    public = json.dumps({key: value[key] for key in ('schema_version', 'images',
        'native_build_contract', 'native_ca_bundle_sha256')}, sort_keys=True)
    pod = deployment['spec']['template']['spec']
    require(len(pod['containers']) == 1, 'One exact driver container required')
    container = pod['containers'][0]
    environment = container.setdefault('env', [])
    found = [v for v in environment if v['name'] == 'IDENTITY_DEMO_ARTIFACTS']
    mounts = container.setdefault('volumeMounts', [])
    projected = [v for v in mounts if v['mountPath'] == '/configuration/artifacts.json']
    if found:
        require(found == [{'name': 'IDENTITY_DEMO_ARTIFACTS',
                          'value': '/configuration/artifacts.json'}]
                and len(projected) == 1 and projected[0].get('readOnly') is True
                and projected[0].get('subPath') == 'artifacts.json'
                and any(v['name'] == projected[0]['name'] and 'configMap' in v
                        for v in pod['volumes']), 'Exact read-only artifact projection required')
        if projected[0]['name'] == 'code':
            require(data.get('artifacts.json') == public,
                    'Existing native lock differs; explicit artifact migration required')
        return
    require(not projected, 'Unbound artifact mount requires operator review')
    data['artifacts.json'] = public
    environment.append({'name': 'IDENTITY_DEMO_ARTIFACTS',
                        'value': '/configuration/artifacts.json'})
    mounts.append({'name': 'code', 'mountPath': '/configuration/artifacts.json',
                   'subPath': 'artifacts.json', 'readOnly': True})


def register_driver(args: argparse.Namespace) -> dict:
    """Version the sole driver's code/config while retaining its PVC and Secrets."""
    refresh = getattr(args, "action", None) == "update-console"
    require(not args.context_file if refresh else bool(args.context_file),
            "Console update accepts no new contexts; registration requires fresh receipts")
    guard(args)
    require(inspect_state(args)["rollback_quiescent"], "Driver update requires no active runs, console jobs or executing/unknown actions")
    contexts = [resolve_context(p, lambda k, n, ns=None: read(args, k, n, ns))
                for p in args.context_file]
    deployment = read(args, "deployment", "fixture-identity-driver", native.NAMESPACE)
    owned(deployment)
    before = next(v["configMap"]["name"] for v in deployment["spec"]["template"]["spec"]["volumes"]
                  if v["name"] == "code")
    current = read(args, "configmap", before, native.NAMESPACE)
    owned(current)
    native.private_write(args.output_dir / "deployment-before.private.json", deployment)
    existing_config = json.loads(current["data"]["config.json"])
    config = existing_config if refresh else append_contexts(existing_config, contexts, args.workflow, args.project)
    # Preserve installed support modules and profile files when adding mappings.
    # Dropping deployment_profile.py breaks source-rendered driver startup.
    data = dict(current['data'])
    updates = {name: (ROOT / "scripts" / "identity_demo" / name).read_text()
               for name in ("identity_demo_driver.py", "identity_demo_run_store.py", "deployment_profile.py",
                            "identity_demo_console.py", "identity_demo_console_store.py", "identity_demo_console_visuals.py", "identity_demo_warm_pool.py", 'identity_demo_connector.py', 'identity_demo_jira_contract.py', 'identity_demo_pool_profiles.py', 'deployment_artifacts.py')}
    require('identity_demo_console_store.py' in data
            and console_model_contract(data['identity_demo_console_store.py'])
                == console_model_contract(updates['identity_demo_console_store.py']),
            'Provider-configured source matching the installed console is required; do not deploy pristine templates')
    data.update(updates)
    if getattr(args, "console_enabled", False):
        config["coordinator_enabled"] = True
        selected = {c.workload for c in contexts}
        for entry in config["contexts"]:
            if entry["workload"] in selected:
                entry["console_prepared"] = True
    if getattr(args, "console_disabled", False):
        config["coordinator_enabled"] = False
    if getattr(args, 'presenter_subject', None):
        config['presenter_subjects'] = list(args.presenter_subject)
    data["config.json"] = json.dumps(config)
    desired = json.loads(json.dumps(deployment))
    desired.pop("status", None)
    if refresh:
        project_driver_artifacts(desired, data)
    name = "fixture-identity-driver-code-" + hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:10]
    obj = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {
        "name": name, "namespace": native.NAMESPACE, "labels": dict(LABELS)},
        "data": data, "immutable": True}
    if refresh and name == current["metadata"]["name"]:
        return {"applied": False, "code_changed": False, "new_contexts": 0}
    require(not read(args, "configmap", name, native.NAMESPACE, optional=True),
            "Versioned driver configuration already exists")
    for volume in desired["spec"]["template"]["spec"]["volumes"]:
        if volume["name"] == "code":
            volume["configMap"]["name"] = name
    native.kube(args, "create", "--dry-run=server", "-f", "-", "-o", "json", payload=obj)
    native.kube(args, "replace", "--dry-run=server", "-f", "-", "-o", "json", payload=desired)
    native.private_write(args.output_dir / "configmap-desired.private.json", obj)
    native.private_write(args.output_dir / "deployment-desired.private.json", desired)
    if args.apply:
        made = native.kube(args, "create", "-f", "-", "-o", "json", payload=obj)
        native.private_write(args.output_dir / "configmap-created.private.json", made)
        changed = native.kube(args, "replace", "-f", "-", "-o", "json", payload=desired)
        native.private_write(args.output_dir / "deployment-changed.private.json", changed)
        result = subprocess.run(["oc", "--kubeconfig", args.kubeconfig, "-n", native.NAMESPACE,
            "rollout", "status", "deployment/fixture-identity-driver", "--timeout=90s"],
            capture_output=True, text=True, timeout=100)
        native.private_write(args.output_dir / "rollout.private.json", {
            "exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
        require(result.returncode == 0, "Owned driver rollout failed; preserve rollback receipt")
    return {"applied": args.apply, "code_configmap": name, "new_contexts": len(contexts),
            "workflow": args.workflow, "project": args.project,
            "persistent_state_and_credentials_preserved": True, "live_permission_flow_unproved": True}



def update_adapter(args: argparse.Namespace) -> dict:
    """Version owned tool validation code, preserving credentials and every other mount."""
    guard(args)
    require(inspect_state(args)["rollback_quiescent"], "Adapter update requires a quiescent driver")
    deployment = read(args, "deployment", "fixture-protected-adapter", native.NAMESPACE)
    owned(deployment)
    volumes = deployment["spec"]["template"]["spec"]["volumes"]
    selected = [v for v in volumes if v["name"] == "catalog-code" and "configMap" in v]
    require(len(selected) == 1, "One existing action-code mount required")
    current = read(args, "configmap", selected[0]["configMap"]["name"], native.NAMESPACE)
    owned(current)
    data = dict(current["data"])
    modules = ("identity_demo_jira_action_adapter.py", "identity_demo_run_store.py", "deployment_profile.py", "identity_demo_warm_pool.py", 'identity_demo_connector.py', 'identity_demo_jira_contract.py', 'identity_demo_pool_profiles.py', 'deployment_artifacts.py')
    require(all(name in data for name in modules if name not in ('identity_demo_connector.py', 'identity_demo_jira_contract.py', 'identity_demo_pool_profiles.py', 'deployment_artifacts.py', 'identity_demo_warm_pool.py')), "Existing guarded adapter modules required")
    data.update({name: (ROOT / "scripts" / "identity_demo" / name).read_text() for name in modules})
    if data == current["data"]:
        return {"applied": False, "code_changed": False}
    name = "fixture-adapter-action-code-" + hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:10]
    require(not read(args, "configmap", name, native.NAMESPACE, optional=True), "Versioned adapter code already exists")
    obj = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {
        "name": name, "namespace": native.NAMESPACE, "labels": dict(current["metadata"]["labels"])},
        "data": data, "immutable": True}
    desired = json.loads(json.dumps(deployment))
    desired.pop("status", None)
    next(v for v in desired["spec"]["template"]["spec"]["volumes"] if v["name"] == "catalog-code")["configMap"]["name"] = name
    for filename, value in (("deployment-before.private.json", deployment),
                            ("code-before.private.json", current), ("code-desired.private.json", obj),
                            ("deployment-desired.private.json", desired)):
        native.private_write(args.output_dir / filename, value)
    native.kube(args, "create", "--dry-run=server", "-f", "-", "-o", "json", payload=obj)
    native.kube(args, "replace", "--dry-run=server", "-f", "-", "-o", "json", payload=desired)
    if args.apply:
        native.private_write(args.output_dir / "code-created.private.json",
                             native.kube(args, "create", "-f", "-", "-o", "json", payload=obj))
        native.private_write(args.output_dir / "deployment-changed.private.json",
                             native.kube(args, "replace", "-f", "-", "-o", "json", payload=desired))
        result = subprocess.run(["oc", "--kubeconfig", args.kubeconfig, "-n", native.NAMESPACE,
            "rollout", "status", "deployment/fixture-protected-adapter", "--timeout=90s"],
            capture_output=True, text=True, timeout=100)
        native.private_write(args.output_dir / "rollout.private.json", {
            "exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
        require(result.returncode == 0, "Owned adapter rollout failed; retain rollback receipt")
    return {"applied": args.apply, "code_configmap": name, "credentials_and_mounts_preserved": True}


def provision_project(args: argparse.Namespace) -> dict:
    """Create only the synthetic reuse project through the fixture's supported API."""
    guard(args)
    require(args.project in ("SERVICE", "OPS"), "Only dedicated synthetic reuse projects are permitted")
    require(inspect_state(args)["rollback_quiescent"], "Synthetic fixture preparation requires a quiescent driver")
    for name in ("fixture-jira", "fixture-protected-adapter"):
        owned(read(args, "deployment", name, native.NAMESPACE))
    program = '''import asyncio,json,os,ssl,hashlib,sys,httpx
async def run():
 settings=json.load(sys.stdin)
 apply=settings['apply'];project=settings['project'];project_name={'SERVICE':'Synthetic service requests','OPS':'Synthetic operations incidents'}[project]
 async with httpx.AsyncClient(verify=ssl.create_default_context(cafile='/service-ca/service-ca.crt'),timeout=8,follow_redirects=False,trust_env=False,auth=httpx.BasicAuth(os.environ['JIRA_USER'],os.environ['JIRA_TOKEN'])) as client:
  base=settings['jira_origin']
  async def baseline():
   values={}
   for protected_project in ('TEST','SERVICE','OPS'):
    if protected_project==project:continue
    response=await client.get(base+'/rest/api/2/search',params={'jql':'project = '+protected_project,'maxResults':100})
    assert response.status_code in (200,404)
    value=response.json();assert response.status_code==404 or value['total']<=100
    values[protected_project]={'status':response.status_code,'data':value}
   return hashlib.sha256(json.dumps(values,sort_keys=True).encode()).hexdigest()
  before=await baseline()
  result=await client.get(base+'/rest/api/2/project/'+project)
  assert result.status_code in (200,404)
  created=False
  if result.status_code==200:
   assert result.json()['name']==project_name, 'Existing project ownership is ambiguous'
  elif apply:
   result=await client.post(base+'/api/admin/projects',json={'key':project,'name':project_name,'description':'Owned identity-demo synthetic reuse fixture; no confidential data.'})
   assert result.status_code==201
   created=True
  seeded=[]
  if result.status_code in (200,201):
   response=await client.get(base+'/rest/api/2/search',params={'jql':'project = '+project,'maxResults':100})
   assert response.status_code==200
   inventory=response.json();assert inventory['total']<=100
   original={item['key']:item for item in inventory['issues']}
   for seed in settings['reuse_seeds']:
    fields={'project':{'key':project},'issuetype':{'name':'Task'},'summary':seed['summary'],
            'description':seed['description'],'labels':[settings['seed_label'],'identity-demo-owner-'+settings['owner']]}
    matches=[item for item in inventory['issues'] if item['fields']['summary']==fields['summary']]
    assert len(matches)<=1, 'Seed collision requires review'
    if matches:
     assert all(matches[0]['fields'].get(key)==value for key,value in fields.items() if key not in ('project','issuetype')), 'Existing seed ownership/content differs'
     seeded.append(matches[0]['key'])
    elif apply:
     response=await client.post(base+'/rest/api/2/issue',json={'fields':fields})
     assert response.status_code==201, 'Seed create is never retried automatically'
     seeded.append(response.json()['key'])
   response=await client.get(base+'/rest/api/2/search',params={'jql':'project = '+project,'maxResults':100})
   assert response.status_code==200
   after={item['key']:item for item in response.json()['issues']}
   assert all(after.get(key)==item for key,item in original.items()), 'Existing target issues changed'
  assert before==await baseline(), 'Other project data changed'
  print(json.dumps({'applied':apply,'project':project,'created':created,'baseline_preserved':True,'project_available':result.status_code in (200,201),
    'incident_seed_keys':seeded if project=='OPS' else [],'remediation_seed_keys':seeded if project=='SERVICE' else [],
    'project_seed_mode':'synthetic' if settings['reuse_seeds'] else 'none'}))
asyncio.run(run())'''
    result = subprocess.run(["oc", "--kubeconfig", args.kubeconfig, "-n", native.NAMESPACE,
        "exec", "-i", "deployment/fixture-protected-adapter", "-c", "adapter-https", "--",
        "python", "-c", program], input=json.dumps({"apply": args.apply, "project": args.project, "owner": active_profile().owner,
            "seed_label": "synthetic-remediation-seed" if args.project == "SERVICE" else "synthetic-incident-seed",
            "reuse_seeds": [] if getattr(args, "project_only", False) else (json.loads((ROOT / "workloads/agents/service-request-demo/src/remediation.json").read_text())["seeds"] if args.project == "SERVICE" else [
                {"summary": "Synthetic checkout timeouts after deployment", "description": "Synthetic training observation: checkout timeout rate increased after a demo deployment. No production traffic or customer data. Investigation is open; cause has not been established."},
                {"summary": "Synthetic checkout connection pool saturation", "description": "Synthetic training observation: the checkout connection pool reached its configured limit during a load exercise. This may be related to the timeout investigation; correlation is not proof of cause."},
                {"summary": "Synthetic checkout investigation runbook", "description": "Existing synthetic follow-up: inspect deployment changes, request timings and connection-pool limits. Record observed evidence before proposing remediation. Do not change any production service."}]),
            "jira_origin": "https://" + active_profile().service_host("fixture-jira") + ":8080"}),
        capture_output=True, text=True, timeout=35)
    native.private_write(args.output_dir / "project-provision.private.json", {
        "exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
    require(result.returncode == 0, "Synthetic project provisioning failed; private receipt retained")
    return json.loads(result.stdout)


def inspect_state(args: argparse.Namespace) -> dict:
    """Report counts and hashes for safe rollback checks without exposing rows."""
    guard(args)
    owned(read(args, "deployment", "fixture-identity-driver", native.NAMESPACE))
    program = '''import sqlite3,os,json,hashlib
d=sqlite3.connect('file:'+os.environ['DRIVER_DATABASE']+'?mode=ro',uri=True)
d.execute('BEGIN')
tables={}
for table in ('runs','actions','audit'):
 rows=list(d.execute('SELECT * FROM '+table+' ORDER BY rowid'))
 tables[table]={'count':len(rows),'sha256':hashlib.sha256(json.dumps(rows,sort_keys=True).encode()).hexdigest()}
active=d.execute('SELECT count(*) FROM runs WHERE active<>0').fetchone()[0]
uncertain=d.execute("SELECT count(*) FROM actions WHERE state IN ('executing','unknown')").fetchone()[0]
has_console=d.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='console_jobs'").fetchone()[0]
has_preparation=d.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='console_preparations'").fetchone()[0]
preparing=d.execute("SELECT count(*) FROM console_preparations WHERE state IN ('preparing','blocked')").fetchone()[0] if has_preparation else 0
has_pool=d.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='console_pool_items'").fetchone()[0]
pool_items=d.execute('SELECT count(*) FROM console_pool_items').fetchone()[0] if has_pool else 0
non_retired=d.execute("SELECT count(*) FROM console_pool_items WHERE state<>'retired'").fetchone()[0] if has_pool else 0
console_jobs=d.execute("SELECT count(*) FROM console_jobs WHERE state IN ('queued','running')").fetchone()[0] if has_console else 0
recovery=any(json.loads(r[0]).get('failure_code')=='recovery_required' and json.loads(r[0]).get('cleanup_verified') is not True for r in d.execute("SELECT evidence FROM console_jobs WHERE state='failed'")) if has_console else False
print(json.dumps({'recovery_required':recovery,'tables':tables,'active_runs':active,'active_console_jobs':console_jobs,'executing_or_unknown_actions':uncertain,'active_preparations':preparing,'pool_items':pool_items,'non_retired_pool_items':non_retired,'rollback_quiescent':active==0 and uncertain==0 and console_jobs==0 and preparing==0 and not recovery}))'''
    result = subprocess.run(["oc", "--kubeconfig", args.kubeconfig, "-n", native.NAMESPACE,
        "exec", "deployment/fixture-identity-driver", "--", "python", "-c", program],
        capture_output=True, text=True, timeout=30)
    require(result.returncode == 0, "Read-only durable-state inventory unavailable")
    return {"read_only": True, **json.loads(result.stdout)}


def review_dispatch_rejection(args: argparse.Namespace) -> dict:
    """Record a trusted installer decision, never infer non-commit from a search.

    No HTTP/runtime interface exposes this operation. The operator reviews the
    terminal response and the exact backend's no-commit contract beforehand.
    Cleanup review remains a separate existing operation.
    """
    import inspect
    import textwrap
    from identity_demo_run_store import RunStore
    require(os.environ.get('IDENTITY_DEMO_RUNTIME') != 'cluster',
            'Installer-only dispatch review required')
    guard(args)
    path = private_path(args.review_receipt)
    contents = path.read_bytes()
    require(bool(re.fullmatch(r'[a-f0-9]{64}', args.review_sha256 or ''))
            and hashlib.sha256(contents).hexdigest() == args.review_sha256,
            'Exact reviewed rejection receipt hash required')
    value = json.loads(contents)
    profile = active_profile()
    require(set(value) == {'schema_version', 'decision', 'installation_id', 'owner',
            'expected_server', 'reviewed_by', 'run_id', 'action_id', 'execution_id',
            'action_digest', 'driver_uid', 'jira_uid', 'jira_image', 'evidence'},
            'Exact private rejection review schema required')
    require(value['schema_version'] == 1 and value['decision'] == 'rejected_without_commit'
            and value['installation_id'] == profile.installation_id
            and value['owner'] == profile.owner and value['expected_server'] == profile.expected_server,
            'Exact installation rejection review required')
    evidence = value['evidence']
    require(set(evidence) == {'terminal_rejection', 'no_commit_contract', 'backend_snapshot', 'credential_cleanup'},
            'Terminal response, no-commit contract, backend and cleanup evidence required')
    for record in evidence.values():
        require(isinstance(record, dict) and set(record) == {'path', 'sha256'}, 'Pinned private evidence required')
        evidence_path = private_path(record['path'])
        require(bool(re.fullmatch(r'[a-f0-9]{64}', record['sha256']))
                and hashlib.sha256(evidence_path.read_bytes()).hexdigest() == record['sha256'],
                'Rejection review evidence changed')
    require(not args.apply or args.confirm_rejected_without_commit is True,
            'Explicit reviewed non-commit confirmation required; an empty search is insufficient')
    actor = subprocess.run(['oc', '--kubeconfig', args.kubeconfig, 'whoami'],
                           capture_output=True, text=True, timeout=20)
    require(actor.returncode == 0 and actor.stdout.strip() == value['reviewed_by']
            and not value['reviewed_by'].startswith('system:serviceaccount:'),
            'Exact human installer review identity required')
    for name, key in (('fixture-identity-driver', 'driver_uid'), ('fixture-jira', 'jira_uid')):
        deployment = read(args, 'deployment', name, native.NAMESPACE)
        owned(deployment)
        require(deployment['metadata']['uid'] == value[key]
                and not deployment['metadata'].get('deletionTimestamp'), 'Reviewed resource identity changed')
        if name == 'fixture-jira':
            containers = deployment['spec']['template']['spec']['containers']
            require({c['name'] for c in containers} == {'fixture-jira','adapter-sse','adapter-streamable-http'}
                    and len(containers) == 3 and all(c['image'] == value['jira_image'] for c in containers)
                    and '@sha256:' in value['jira_image'], 'Exact reviewed fixture digest required')
    method = textwrap.dedent(inspect.getsource(RunStore.review_dispatch_rejection))
    program = """import os,json,re,sqlite3,sys
from pathlib import Path
from identity_demo_run_store import RunStore,Denied,canonical
value=json.load(sys.stdin)
profile=json.loads(Path(os.environ['IDENTITY_DEMO_CONFIG']).read_text())
assert all(profile[k]==v for k,v in value['installation'].items())
store=RunStore.__new__(RunStore);store.path=Path(os.environ['DRIVER_DATABASE']);store.connector=getattr(__import__('identity_demo_run_store'),'JIRA',None)
with store.read_transaction() as db:
 row=db.execute('SELECT a.*,r.active FROM actions a JOIN runs r ON r.id=a.run_id WHERE a.id=? AND a.run_id=?',(value['action_id'],value['run_id'])).fetchone()
 job=db.execute('SELECT state,evidence FROM console_jobs WHERE run_id=?',(value['run_id'],)).fetchone()
 assert row and row['state']=='unknown' and row['active']==0 and row['issue_key'] is None
 assert row['execution_id']==value['execution_id'] and row['digest']==value['action_digest']
 assert job and job['state']=='failed' and json.loads(job['evidence']).get('failure_code')=='recovery_required'
 assert not db.execute("SELECT 1 FROM console_jobs WHERE state IN ('queued','running')").fetchone()
result={'review_planned':True,'state':'unknown','mutation_replayed':False,'console_recovery_cleared':False}
if value['apply']:
 result=review_dispatch_rejection(store,value['run_id'],value['action_id'],value['execution_id'],value['action_digest'],value['receipt_sha256'])
print(json.dumps(result))
"""
    # This is the tested store operation from this package, executed solely with
    # the installer's existing Pod-exec authority; no runtime grant is added.
    program = program.replace('value=json.load(sys.stdin)', method + '\nvalue=json.load(sys.stdin)', 1)
    settings = {k: value[k] for k in ('run_id','action_id','execution_id','action_digest')}
    settings.update(apply=args.apply, receipt_sha256=args.review_sha256,
                    installation={k: getattr(profile,k) for k in ('installation_id','owner','core_namespace','expected_server')})
    result = subprocess.run(['oc', '--kubeconfig', args.kubeconfig, '-n', native.NAMESPACE,
        'exec', '-i', 'deployment/fixture-identity-driver', '--', 'python', '-c', program],
        input=json.dumps(settings), capture_output=True, text=True, timeout=30)
    require(result.returncode == 0, 'Dispatch review did not complete; inspect state, never replay it')
    return json.loads(result.stdout)


def retire_registration(args: argparse.Namespace, context: ExecutionContext) -> dict:
    """Remove only an exact retired identity using UID/RV guarded deletion.

    Callers must first verify the closed durable run and remove native execution.
    Re-reading absence is idempotent; a replacement or uncertain API result stops
    the caller and remains visible in its existing private failure checkpoint.
    """
    for kind, name, namespace in (
        ("sandboxes.agents.x-k8s.io", context.resource_name, context.namespace),
        ("pod", context.resource_name, context.namespace),
        ("pod", "os-supervisor-" + context.sandbox_id, context.namespace),
    ):
        deadline = time.monotonic() + 30
        while read(args, kind, name, namespace, optional=True):
            require(time.monotonic() < deadline, "Retirement incomplete: native execution still present")
            time.sleep(1)
    kind = "clusterstaticentries.spire.spiffe.io"
    from identity_demo_controller_identity import enabled as controller_identities, verify
    if controller_identities():
        # The controller removes the Pod-derived registration; runtime has no
        # direct SPIRE registration permission. No selector can match the absent
        # Pod UID, and durable run authorization was already closed by the caller.
        verify(context, lambda k, n, ns=None: read(args, k, n, ns), require_status=False)
        return {"registration_absent": False, "registration_inactive": True,
                "controller_managed": True, "pod_absence_verified": True,
                "server_entry_deletion_observed": False}
    registration = read(args, kind, context.registration_name, optional=True)
    if not registration:
        return {"registration_absent": True}
    owned(registration)
    selectors = registration["spec"].get("selectors", [])
    require(registration["spec"].get("spiffeID") == context.workload
            and registration["spec"].get("className") == "zero-trust-workload-identity-manager-spire"
            and "k8s:ns:" + context.namespace in selectors
            and "k8s:sa:" + context.service_account in selectors
            and "k8s:container-name:supervisor" in selectors,
            "Exact retired supervisor registration required")
    native.private_write(args.output_dir / "registration-before.private.json", registration)
    current = read(args, kind, context.registration_name, optional=True)
    if not current:
        return {"registration_absent": True}
    owned(current)
    require(current["metadata"]["uid"] == registration["metadata"]["uid"]
            and current["spec"] == registration["spec"], "Registration changed during retirement")
    native.kube(args, "delete", "--raw", "/apis/spire.spiffe.io/v1alpha1/clusterstaticentries/" + context.registration_name,
                "-f", "-", payload={"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {
                    "uid": current["metadata"]["uid"], "resourceVersion": current["metadata"]["resourceVersion"]}})
    require(not read(args, kind, context.registration_name, optional=True),
            "Registration cleanup incomplete; inspect private receipt and retry retirement in a fresh output directory")
    return {"registration_absent": True}


def retire(args: argparse.Namespace) -> dict:
    """Retire one closed identity and registration, preserving workspace and durable history."""
    require(len(args.context_file) == 1, "Exactly one retired context receipt required")
    _, credentials, _ = guard(args)
    context = context_identity(json.loads(private_path(args.context_file[0]).read_text()))
    args.execution_context = context
    owned(read(args, "namespace", context.namespace))
    sandbox = read(args, "sandboxes.agents.x-k8s.io", context.resource_name, context.namespace, optional=True)
    if sandbox:
        require(resolve_context(args.context_file[0], lambda k, n, ns=None: read(args, k, n, ns)) == context,
                "Exact live retirement context required")
    owned(read(args, "deployment", "fixture-identity-driver", native.NAMESPACE))
    program = (
        "import sqlite3,os,json,sys;w=json.load(sys.stdin)['workload'];"
        "d=sqlite3.connect('file:'+os.environ['DRIVER_DATABASE']+'?mode=ro',uri=True);"
        "r=list(d.execute('SELECT id,active FROM runs WHERE workload=?',(w,)));"
        "assert len(r)==1 and r[0][1]==0;"
        "assert d.execute(\"SELECT count(*) FROM actions WHERE run_id=? AND state IN ('executing','unknown')\","
        "(r[0][0],)).fetchone()[0]==0;"
        "has=d.execute(\"SELECT count(*) FROM sqlite_master WHERE type='table' AND name='console_jobs'\").fetchone()[0];"
        "jobs=list(d.execute('SELECT state,evidence FROM console_jobs WHERE run_id=?',(r[0][0],))) if has else [];"
        "assert all(j[0] in ('completed','failed') and json.loads(j[1]).get('cleanup_verified') is True for j in jobs);"
        "print(json.dumps({'eligible':True}))")
    from identity_demo_controller_identity import enabled as controller_identities
    if getattr(args, 'unused_retirement', False):
        from unused_context_retirement import eligible
        state = eligible(args, context)
        native.private_write(args.output_dir / 'retirement-state.private.json', state)
        eligible = state.get('eligible') is True
    elif controller_identities() and os.environ.get('IDENTITY_DEMO_RUNTIME') == 'cluster':
        # Runtime has no Pod exec grant. Installer CLI retains its existing
        # read-only durable-state check, also when controller identities are
        # selected; direct CLI runs intentionally have no console job.
        from identity_demo_console_worker import Control
        keys = json.loads(private_path(args.driver_credentials_file).read_text())
        state = Control(keys['operator_secret']).request('prepare/retirement-check', {'workload': context.workload})
        native.private_write(args.output_dir / 'retirement-state.private.json', state)
        eligible = state.get('eligible') is True
    else:
        result = subprocess.run(["oc", "--kubeconfig", args.kubeconfig, "-n", native.NAMESPACE,
            "exec", "-i", "deployment/fixture-identity-driver", "--", "python", "-c", program],
            input=json.dumps({"workload": context.workload}), capture_output=True, text=True, timeout=30)
        native.private_write(args.output_dir / "retirement-state.private.json", {
            "exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
        eligible = result.returncode == 0 and json.loads(result.stdout).get('eligible')
    require(eligible,
            "Run must be closed with verified console cleanup and no executing/unknown action")
    disposable = []
    if args.apply and sandbox:
        if getattr(args, 'disposable_workspace_receipt', None):
            from identity_demo_workspace_retention import verify
            disposable = verify(args, context, sandbox, read)
        native.private_write(args.output_dir / "sandbox-before.private.json", sandbox)
        with native.native_session(args, credentials) as execute:
            state = execute(["sandbox", "get", context.sandbox_name, "-o", "json"], json_output=True)
            require(state["id"] == context.sandbox_id, "Native deletion identity mismatch")
            providers = execute(["sandbox", "provider", "list", context.sandbox_name, "-o", "json"],
                                json_output=True)
            require(providers["providers"] == [], "Attached provider prevents retirement")
            # Native Sandbox deletion otherwise garbage-collects its workspace.
            # Retain only exact referenced PVCs, guarded by their current UID/RV.
            worker = read(args, "pod", context.resource_name, context.namespace)
            require(any(r.get("uid") == sandbox["metadata"]["uid"]
                        for r in worker["metadata"].get("ownerReferences", [])),
                    "Exact Sandbox worker required for workspace retention")
            # Claim templates are materialized only on the actual worker Pod.
            volumes = worker["spec"].get("volumes", [])
            claims = {v["persistentVolumeClaim"]["claimName"] for v in volumes
                      if "persistentVolumeClaim" in v}
            require(len(claims) >= len(sandbox["spec"].get("volumeClaimTemplates", [])),
                    "All generated workspace claims must be accounted for")
            retained = []
            for name in sorted(claims) if not disposable else []:
                pvc = read(args, "pvc", name, context.namespace)
                refs = pvc["metadata"].get("ownerReferences", [])
                matching = [r for r in refs if r.get("uid") == sandbox["metadata"]["uid"]
                            and r.get("kind") == "Sandbox" and r.get("name") == context.resource_name]
                if not refs:
                    # Resume only a claim whose exact UID was preserved by an earlier attempt.
                    prior = [json.loads(f.read_text()) for f in Path(args.output_dir).parent.glob(
                        "*/" + name + ".pvc-before.private.json") if not f.is_symlink() and not f.stat().st_mode & 0o077]
                    require(any(v["metadata"]["uid"] == pvc["metadata"]["uid"]
                        and v["metadata"].get("ownerReferences") == [{**r}] for v in prior
                        for r in v["metadata"].get("ownerReferences", []) if r.get("uid") == sandbox["metadata"]["uid"]),
                        "Unowned workspace requires exact prior preservation evidence")
                    retained.append({"name": name, "uid": pvc["metadata"]["uid"]})
                    continue
                require(len(matching) == 1 and len(refs) == 1,
                        "Workspace requires exactly this Sandbox owner before preservation")
                native.private_write(args.output_dir / (name + ".pvc-before.private.json"), pvc)
                patch = [
                    {"op": "test", "path": "/metadata/uid", "value": pvc["metadata"]["uid"]},
                    {"op": "test", "path": "/metadata/resourceVersion", "value": pvc["metadata"]["resourceVersion"]},
                    {"op": "test", "path": "/metadata/ownerReferences", "value": refs},
                    {"op": "remove", "path": "/metadata/ownerReferences"}]
                after = native.kube(args, "patch", "pvc", name, "-n", context.namespace,
                                    "--type=json", "-p", json.dumps(patch), "-o", "json")
                require(not after["metadata"].get("ownerReferences"), "Workspace retention failed")
                retained.append({"name": name, "uid": pvc["metadata"]["uid"]})
            native.private_write(args.output_dir / "retained-workspaces.private.json", retained)
            execute(["sandbox", "delete", context.sandbox_name])
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            left = read(args, "sandboxes.agents.x-k8s.io", context.resource_name,
                        context.namespace, optional=True)
            if not left:
                break
            require(left["metadata"]["uid"] == sandbox["metadata"]["uid"], "Deletion target replaced")
            time.sleep(1)
        else:
            raise TimeoutError("Native retirement still pending; do not repeat deletion")
        for item in retained:
            current = read(args, "pvc", item["name"], context.namespace)
            require(current["metadata"]["uid"] == item["uid"]
                    and not current["metadata"].get("deletionTimestamp")
                    and current["status"]["phase"] == "Bound",
                    "Retired workspace preservation not established")
    registration_result = {'registration_absent': False}
    if args.apply:
        registration_result = retire_registration(args, context)
        if disposable:
            from identity_demo_workspace_retention import verify_absent
            verify_absent(args, context, disposable, read)
    return {"disposable_scratch_removed": bool(disposable), "applied": args.apply, **registration_result, "retired_sandbox": context.sandbox_name,
            "durable_run_audit_and_tombstones_preserved": True,
            "referenced_workspaces_preserved": bool(args.apply and not disposable), "other_namespaces_changed": False}


def main() -> None:
    """Keep private evidence out of Git and publish only bounded classifications."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("kubeconfig", "expected-server", "credentials-file", "cli", "cli-config-dir", "output-dir"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--action", choices=("prepare-workspaces", "provision", "recover-provision", "diagnostic-access", "retire-diagnostic-access", "stage", "register-driver", "update-console", "update-adapter", "prepare-console", "provision-project", "inspect-state", "review-dispatch-rejection", "retire", "retire-unused", "gateway-install", "gateway-remove"), required=True)
    parser.add_argument('--presenter-subject', action='append', help='Explicit IdP subject allowed to request the fixed presentation batch')
    parser.add_argument('--installer-user', help='Exact authenticated non-admin user for explicit diagnostic access only')
    parser.add_argument('--ca-file')
    parser.add_argument('--catalog-credential-file', help='Private current gateway discovery credential')
    parser.add_argument('--gateway-receipt', help='Private exact persistent gateway installation receipt')
    parser.add_argument("--role", choices=("triage", "reader"), default="triage")
    parser.add_argument("--suffix")
    parser.add_argument("--context-file", action="append", default=[])
    parser.add_argument("--workflow", choices=("cve", "service-request", "incident-triage"), default="cve")
    parser.add_argument("--project", default="TEST")
    parser.add_argument("--project-only", action="store_true", help="Provision only the synthetic project; create no seed issues")
    parser.add_argument("--spire-agent-binary")
    parser.add_argument("--projection-reader-binary", "--mcp-client-binary", dest="mcp_client_binary",
                        help="Reviewed static native-projection reader; legacy flag retained")
    console_mode = parser.add_mutually_exclusive_group()
    console_mode.add_argument("--console-enabled", action="store_true",
                             help="Enable authenticated background console execution")
    console_mode.add_argument("--console-disabled", action="store_true",
                             help="Return to the original operator-driven rehearsal mode")
    parser.add_argument("--review-receipt", help="Pinned private installer rejection adjudication")
    parser.add_argument("--review-sha256")
    parser.add_argument("--confirm-rejected-without-commit", action="store_true")
    parser.add_argument("--unused-retirement", action="store_true", help="Retire: use an existing exact installer quarantine instead of a closed business run")
    parser.add_argument("--resume-unused-retirement", action="store_true", help="Retire-unused: reconcile resource absence only; never repeat native deletion")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    args.namespace = native.NAMESPACE
    args.label = "execution-setup"
    os.umask(0o077)
    parent = private_path(str(Path(args.output_dir).parent), directory=True)
    args.output_dir = parent / Path(args.output_dir).name
    args.output_dir.mkdir(mode=0o700)
    try:
        require(not args.unused_retirement or args.action == 'retire', 'Unused proof applies only to explicit native retirement')
        require(not args.resume_unused_retirement or args.action == 'retire-unused', 'Unused reconciliation applies only to installer maintenance')
        from identity_demo_gateway_persistence import install as gateway_install, remove as gateway_remove
        from unused_context_retirement import run as retire_unused
        result = {"gateway-install": gateway_install, "gateway-remove": gateway_remove, "prepare-workspaces": prepare_workspaces,
                  "provision": provision, "recover-provision": provision, "stage": stage,
                  "diagnostic-access": diagnostic_access, "retire-diagnostic-access": diagnostic_access,
                  "register-driver": register_driver, "update-console": register_driver, "prepare-console": prepare_console, "provision-project": provision_project,
                  "inspect-state": inspect_state, "review-dispatch-rejection": review_dispatch_rejection, "update-adapter": update_adapter, "retire": retire, "retire-unused": retire_unused}[args.action](args)
        native.private_write(args.output_dir / "setup.summary.json", result)
        print(json.dumps(result))
    except Exception as error:
        import traceback

        native.private_write(args.output_dir / "failure.private.json", {
            "kind": type(error).__name__, "traceback": traceback.format_exc()})
        print(json.dumps({"passed": False, "kind": type(error).__name__, "details_withheld": True}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
