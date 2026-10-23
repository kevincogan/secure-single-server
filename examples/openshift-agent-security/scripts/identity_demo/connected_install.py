# SPDX-License-Identifier: Apache-2.0
"""Order existing guarded installation helpers; never bootstrap shared operators."""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

import identity_demo_setup as setup
from source_render import load_inputs, read_json


class Stages:
    """Keep exclusive stage receipts and private logs; never retry a mutation."""

    def __init__(self, args: argparse.Namespace, env: dict[str, str]) -> None:
        self.args = args
        self.env = env

    def run(self, name: str, script: str, words: list[str], *,
            allow_failure: bool = False, create_output: bool = False,
            summary_name: str = "setup.summary.json") -> tuple[dict, Path]:
        """Run one existing helper with argv paths, withholding all raw output."""
        out = self.args.output_dir / name
        log = self.args.output_dir / (name + ".private.log")
        setup.write(self.args.output_dir / (name + ".pending.json"), {"stage": name})
        command = [sys.executable, str(setup.ROOT / script), *words]
        if create_output:
            out.mkdir(mode=0o700)
        with log.open("x") as stream:
            os.chmod(log, 0o600)
            result = subprocess.run(command, cwd=setup.ROOT, env=self.env,
                                    stdout=stream, stderr=subprocess.STDOUT, timeout=1800)
        setup.write(self.args.output_dir / (name + ".receipt.json"), {
            "stage": name, "exit": result.returncode, "log_sha256": setup.sha(log)})
        if result.returncode and not allow_failure:
            raise RuntimeError("Connected setup stopped; inspect private stage receipt")
        summary = out / summary_name
        value = read_json(summary) if summary.is_file() else {}
        if not value and result.returncode == 0:
            # Catalog rotation emits only a sanitized JSON result on stdout;
            # its detailed Secret receipt remains private and is never printed.
            try:
                value = json.loads(log.read_text())
            except (ValueError, UnicodeError):
                value = {}
            if not isinstance(value, dict):
                value = {}
        if not value and not allow_failure:
            raise RuntimeError("Helper did not produce a completion summary")
        return value, out


def inactive_catalog_policy(args: argparse.Namespace, objects: list[dict], result: dict) -> bool:
    """Recognise only the unchanged base policy awaiting a catalog registration.

    Retain the failed strict verifier receipt. This exception reports a dormant
    policy, never claims functional enforcement or alters the policy itself.
    """
    if result.get("failures") != ["AuthPolicy/fixture-mcp-auth"]:
        return False
    desired = next(o for o in objects if o["kind"] == "AuthPolicy"
                   and o["metadata"]["name"] == "fixture-mcp-auth")
    current = setup.get(args, desired)
    setup.owned(current, args.profile)
    if current.get("spec") != desired.get("spec"):
        return False
    status = current.get("status", {})
    if not any(c.get("type") == "Accepted" and c.get("status") == "True"
               for c in status.get("conditions", [])):
        return False
    return any(c.get("type") == "Enforced" and c.get("status") == "False" and c.get("message") ==
               "AuthPolicy is not in the path to any existing routes"
               and c.get("observedGeneration", status.get("observedGeneration"))
                   == current["metadata"].get("generation", 1)
               for c in status.get("conditions", []))


def wait_controllers(args: argparse.Namespace, objects: list[dict]) -> None:
    """Wait boundedly for exact owned controllers without writing cluster state."""
    deadline = time.monotonic() + args.readiness_timeout
    controllers = [o for o in objects if o["kind"] in setup.CONTROLLERS]
    while True:
        pending = []
        for desired in controllers:
            current = setup.get(args, desired)
            if not current:
                raise ValueError("Installed controller disappeared")
            setup.owned(current, args.profile)
            status = current.get("status", {})
            if (status.get("observedGeneration", 0) < current["metadata"].get("generation", 1)
                    or status.get("readyReplicas", 0) < current["spec"].get("replicas", 1)):
                pending.append(current["metadata"]["name"])
        if not pending:
            return
        if time.monotonic() >= deadline:
            setup.write(args.output_dir / "readiness-timeout.json", {"pending": pending})
            raise TimeoutError("Owned controllers did not become Ready")
        time.sleep(5)


def presenter_subject(objects: list[dict]) -> str:
    """Expose only the synthetic Analyst ID from the fresh exchange-realm import.

    This is setup metadata, not an authorization grant. The caller still must
    explicitly configure the presenter allowlist during console registration.
    """
    from uuid import UUID
    realms = [o for o in objects if o["kind"] == "Secret"
              and o["metadata"]["name"] == "fixture-keycloak-upstream-realm"]
    if len(realms) != 1:
        raise ValueError("Exactly one fresh exchange-realm import required")
    realm = json.loads(base64.b64decode(realms[0]["data"]["realm.json"], validate=True))
    users = [u for u in realm.get("users", []) if u.get("username") == "analyst"]
    if (len(users) != 1 or users[0].get("enabled") is not True
            or "analyst" not in users[0].get("realmRoles", [])):
        raise ValueError("Exact enabled synthetic Analyst required")
    subject = users[0].get("id", "")
    if not isinstance(subject, str) or str(UUID(subject)) != subject:
        raise ValueError("Canonical fresh Analyst subject required")
    return subject


def connected_install(args: argparse.Namespace) -> dict:
    """Prepare a connected application using existing create-only mechanisms.

    Matching target-bound native images remain a prerequisite. Absent operators
    and native build mismatches stop before the first cluster write. Interrupted
    installs use the existing explicit ledger recovery; no implicit adoption.
    """
    config_path = setup.private_file(args.installation_config)
    profile, _, _, _ = load_inputs(config_path)
    args.profile = profile
    if (args.expected_server != profile.expected_server
            or not isinstance(args.readiness_timeout, int)
            or not 30 <= args.readiness_timeout <= 1800):
        raise ValueError("Exact server and bounded readiness timeout required")
    if not isinstance(args.installer_user, str) or args.installer_user in (
            "admin", "kubeadmin", "cluster-admin"):
        raise ValueError("Explicit non-admin installer user required")
    setup.private_file(args.kubeconfig)
    cli = None
    if args.apply or getattr(args, "resume_installation", None):
        cli = setup.private_file(args.cli)
        if not os.access(cli, os.X_OK):
            raise ValueError("Executable pinned private OpenShell CLI required")
    inference_path = getattr(args, "inference_config", None)
    if inference_path:
        inference_path = str(setup.private_file(inference_path))
    env = dict(os.environ)
    # Never allow an inherited lab profile to redirect a customer installation.
    env.pop("IDENTITY_DEMO_CONFIG", None)
    env.pop("IDENTITY_DEMO_ARTIFACTS", None)
    env["PYTHONPATH"] = os.pathsep.join(str(setup.ROOT / p) for p in (
        "scripts/identity_demo", "tests/identity_demo"))
    if inference_path:
        checked = subprocess.run([sys.executable, "-c",
            "import sys; from enmaas_flow import private_inference; private_inference(sys.argv[1])",
            inference_path], env=env, cwd=setup.ROOT, capture_output=True, timeout=60)
        setup.write(args.output_dir / "inference-reference-check.json", {
            "passed": checked.returncode == 0, "credential_bytes_read": False,
            "model_request_made": False, "inherited_profile_removed": True})
        if checked.returncode:
            raise ValueError("Configured inference references invalid; no cluster changes made")
    stages = Stages(args, env)
    common = ["--kubeconfig", args.kubeconfig, "--expected-server", args.expected_server,
              "--oc", args.oc]
    installer = "scripts/identity_demo/identity_demo_setup.py"

    def run(name: str, action: str, extra: list[str], *, allow_failure: bool = False) -> tuple[dict, Path]:
        return stages.run(name, installer, [action, *common, *extra,
                          "--output-dir", str(args.output_dir / name)], allow_failure=allow_failure)

    if getattr(args, "resume_installation", None):
        return resume_discovery(args, env, stages, run, config_path, cli, inference_path)
    run("01-preflight", "preflight", ["--installation-config", str(config_path)])
    config_path = resolve_ingress(args, config_path)
    _, rendered = run("02-render", "render", ["--installation-config", str(config_path),
        *(["--state-file", args.state_file] if args.state_file else [])])
    bundle_path = rendered / "stack.private.json"
    bundle = read_json(bundle_path)
    objects = setup.validate(bundle)
    suggested_presenter = presenter_subject(objects)
    if not bundle["native_build_contract_matches"]:
        return {"ready": False, "cluster_changed": False, "native_artifacts_ready": False,
                "next_action": "Build/publish target-bound native images; retain 02-render state and trust",
                "render_directory": str(rendered)}
    env["IDENTITY_DEMO_CONFIG"] = str(rendered / "installation-profile.json")
    env["IDENTITY_DEMO_ARTIFACTS"] = str(setup.private_file(read_json(config_path)["artifacts_file"]))
    pinned = ["--bundle", str(bundle_path), "--bundle-sha256", setup.sha(bundle_path)]
    run("03-access-plan", "prepare-access", [*pinned, "--installer-user", args.installer_user])
    if not args.apply:
        planned, _ = run("04-application-plan", "plan", [*pinned, "--server-dry-run"])
        return {"ready": planned["ready_for_create"], "applied": False, "cluster_changed": False,
                "access_preparation_required_before_admission": True,
                "render_directory": str(rendered), "functional_scenarios_proven": False}
    run("04-access-apply", "prepare-access", [*pinned, "--installer-user", args.installer_user, "--apply"])
    permissions, _ = run("05-permissions", "permissions", pinned)
    if not permissions.get("ready"):
        raise ValueError("Missing application permissions")
    planned, _ = run("06-admission", "plan", [*pinned, "--server-dry-run"])
    if not planned.get("ready_for_create") or planned.get("admission_deferred_missing_namespace"):
        raise ValueError("Collision or deferred admission; no application objects created")
    run("07-install", "install", [*pinned, "--apply"])
    for name, action in (("08-runtime", "runtime-permissions"), ("09-discovery", "discovery-access")):
        run(name + "-plan", action, pinned)
        run(name + "-apply", action, [*pinned, "--apply"])
    return finish_installation(args, env, stages, run, rendered, objects, cli,
                               suggested_presenter, inference_path)


def finish_installation(args, env, stages, run, rendered, objects, cli,
                        suggested_presenter, inference_path, *, creation_ledger=None):
    """Complete verified installation stages; never replay application creation."""
    profile = args.profile
    bundle_path = rendered / "stack.private.json"
    pinned = ["--bundle", str(bundle_path), "--bundle-sha256", setup.sha(bundle_path)]
    wait_controllers(args, objects)
    verified, _ = run("10-verify", "verify", pinned, allow_failure=True)
    dormant = inactive_catalog_policy(args, objects, verified)
    if not verified.get("ready") and not dormant:
        raise ValueError("Strict installed configuration/readiness verification failed")
    credentials_path = str(rendered / "fixture-credentials.private.json")
    trust_name = "11-trust"
    if read_json(bundle_path).get('certificate_management', {}).get('mode') == 'managed':
        run(trust_name, 'certificate-status', ['--installation-profile', str(rendered/'installation-profile.json'),
            '--managed-certificate-config', args.installation_config, '--verify-certificate-loading'])
    else:
        stages.run(trust_name, "scripts/identity_demo/identity_demo_sender_trust.py", [
            "--kubeconfig", args.kubeconfig, "--expected-server", args.expected_server,
            "--credentials-file", credentials_path, "--apply",
            "--output-dir", str(args.output_dir / trust_name)], create_output=True,
            summary_name="sender-trust.summary.json")
    wait_controllers(args, objects)
    return finish_execution_setup(args, env, stages, rendered, objects, cli,
        suggested_presenter, inference_path, dormant=dormant, creation_ledger=creation_ledger)


def finish_execution_setup(args, env, stages, rendered, objects, cli,
                           suggested_presenter, inference_path, *, dormant, creation_ledger=None):
    """Initialize execution and write the handoff after verified application/trust setup.

    The normal installer calls this only after readiness and trust verification.
    Individual execution helpers retain their own target/ownership/quiescence gates.
    """
    profile = args.profile
    credentials_path = str(rendered / "fixture-credentials.private.json")
    if not (args.output_dir / "cli-config").exists():
        (args.output_dir / "cli-config").mkdir(mode=0o700)
    execution = ["--kubeconfig", args.kubeconfig, "--expected-server", args.expected_server,
        "--credentials-file", credentials_path,
        "--cli", str(cli), "--cli-config-dir", str(args.output_dir / "cli-config"),
        "--ca-file", str(rendered / "runtime-gateway-ca.pem")]
    for name, action, extra in (("12-workspaces", "prepare-workspaces", []),
                               ("13-project", "provision-project", ["--project", "SERVICE"]),
                               ("13-incident-project", "provision-project", ["--project", "OPS"])):
        stages.run(name, "scripts/identity_demo/identity_demo_execution_setup.py",
            ["--action", action, *execution, *extra, "--apply",
             "--output-dir", str(args.output_dir / name)])
    stages.run("14-catalog", "scripts/identity_demo/identity_demo_adapter_catalog.py", [
        "--action", "rotate", "--kubeconfig", args.kubeconfig,
        "--expected-server", args.expected_server,
        "--catalog-credential-file", str(args.output_dir / "catalog-credential.private.json"),
        "--receipt-file", str(args.output_dir / "14-catalog/rotation.private.json")],
        create_output=True)
    # Export only freshly generated installation keys, never a live-stack Secret.
    secret = next(o for o in objects if o["kind"] == "Secret"
                  and o["metadata"]["name"] == "fixture-identity-driver-credentials")
    setup.write(args.output_dir / "driver-credentials.private.json",
                {k: base64.b64decode(v).decode() for k, v in secret["data"].items()})
    setup.write(args.output_dir / "operator-paths.private.json", {
        "profile": env["IDENTITY_DEMO_CONFIG"], "artifacts": env["IDENTITY_DEMO_ARTIFACTS"],
        "fixture_credentials": str(rendered / "fixture-credentials.private.json"),
        "driver_credentials": str(args.output_dir / "driver-credentials.private.json"),
        "cli_config": str(args.output_dir / "cli-config"),
        "gateway_ca": str(rendered / "runtime-gateway-ca.pem"),
        "catalog_credential": str(args.output_dir / "catalog-credential.private.json"),
        "creation_ledger": str(creation_ledger or args.output_dir / "07-install/creation-ledger.private.json"),
        "suggested_presenter_subject": suggested_presenter,
        "inference_config": inference_path})
    paths = {
        "IDENTITY_DEMO_CONFIG": env["IDENTITY_DEMO_CONFIG"],
        "IDENTITY_DEMO_ARTIFACTS": env["IDENTITY_DEMO_ARTIFACTS"],
        "DEMO_PRIVATE_ROOT": str(args.output_dir), "DEMO_PRIVATE_STORAGE": str(args.output_dir),
        "DEMO_PYTHON": sys.executable, "DEMO_KUBECONFIG": args.kubeconfig,
        "DEMO_SERVER": args.expected_server, "DEMO_OPENSHELL_CLI": str(cli),
        "DEMO_FIXTURE_CREDENTIALS": credentials_path,
        "DEMO_DRIVER_CREDENTIALS": str(args.output_dir / "driver-credentials.private.json"),
        "DEMO_CATALOG_CREDENTIAL": str(args.output_dir / "catalog-credential.private.json"),
        "DEMO_CLI_CONFIG": str(args.output_dir / "cli-config"),
        "DEMO_CORE_NAMESPACE": profile.core_namespace,
        "DEMO_RUNTIME_CA": str(rendered / "runtime-gateway-ca.pem"),
        "DEMO_PRESENTER_SUBJECT": suggested_presenter,
    }
    if inference_path:
        paths["DEMO_INFERENCE_CONFIG"] = inference_path
    with (args.output_dir / "operator-inputs.env").open("x") as stream:
        os.chmod(stream.name, 0o600)
        stream.write("# Generated paths only; inspect before sourcing. No credential values.\n")
        for key, value in paths.items():
            stream.write("export " + key + "=" + shlex.quote(value) + "\n")
    return {"ready": True, "applied": True, "application_installation_completed": True,
            "base_catalog_policy_dormant": dormant, "functional_scenarios_proven": False,
            "next_action": "Provision fresh execution contexts and run five acceptance scenarios",
            "shared_platform_installed": False, "production_approved": False}


CHECKPOINT_STAGES = ("01-preflight", "02-render", "03-access-plan", "04-access-apply",
    "05-permissions", "06-admission", "07-install", "08-runtime-plan", "08-runtime-apply")


def read_checkpoint(path):
    """Accept only an immutable completed creation followed by a failed read plan."""
    previous = Path(path).expanduser()
    if (not previous.is_absolute() or previous.is_symlink() or not previous.is_dir()
            or previous.stat().st_mode & 0o077 or previous.stat().st_uid != os.getuid()
            or setup.in_checkout(previous)):
        raise ValueError("Private external previous installation directory required")
    for name in (*CHECKPOINT_STAGES, "09-discovery-plan"):
        receipt = read_json(setup.private_file(str(previous / (name + ".receipt.json"))))
        log = setup.private_file(str(previous / (name + ".private.log")))
        if (receipt.get("stage") != name or type(receipt.get("exit")) is not int
                or receipt.get("log_sha256") != setup.sha(log)
                or (receipt.get("exit") != 0 if name in CHECKPOINT_STAGES else receipt.get("exit") == 0)):
            raise ValueError("Only the recorded failed read-only discovery plan can resume")
    for name in ("09-discovery-apply", "10-verify", "11-trust", "12-workspaces", "13-project", "14-catalog"):
        if (previous / name).exists() or any(previous.glob(name + ".*")):
            raise ValueError("Later mutation started or uncertain; explicit operator recovery required")
    ledger_path = setup.private_file(str(previous / "07-install/creation-ledger.private.json"))
    ledger = read_json(ledger_path)
    if ledger.get("completed") is not True or ledger.get("pending") is not None:
        raise ValueError("Fully completed application creation ledger required")
    return previous, ledger_path


def resume_discovery(args, env, stages, run, config_path, cli, inference_path):
    """Resume this one safe checkpoint after fresh identity/configuration checks."""
    from source_render import render
    previous, ledger_path = read_checkpoint(args.resume_installation)
    rendered = previous / "02-render"
    bundle_path = setup.private_file(str(rendered / "stack.private.json"))
    bundle = read_json(bundle_path)
    state = read_json(setup.private_file(str(rendered / "installation-state.private.json")))
    expected, _, _ = render(config_path, state)
    if (expected["installation_profile"] != bundle.get("installation_profile")
            or expected["objects"] != bundle.get("objects")
            or expected["native_ca_bundle_sha256"] != bundle.get("native_ca_bundle_sha256")
            or not expected["native_build_contract_matches"] or not bundle.get("native_build_contract_matches")):
        raise ValueError("Source/configuration changed since creation; resume refused")
    objects = setup.validate(bundle)
    args.ledger = str(ledger_path)
    args.bundle_sha256 = setup.sha(bundle_path)
    verified = setup.reconcile_creation(args, objects)  # Reads and verifies exact UIDs/fingerprints.
    if len(verified["created"]) != sum(o["kind"] != "Namespace" for o in objects):
        raise ValueError("Incomplete or changed creation ledger")
    env["IDENTITY_DEMO_CONFIG"] = str(rendered / "installation-profile.json")
    env["IDENTITY_DEMO_ARTIFACTS"] = str(setup.private_file(read_json(config_path)["artifacts_file"]))
    pinned = ["--bundle", str(bundle_path), "--bundle-sha256", setup.sha(bundle_path)]
    runtime, _ = run("00-runtime-recheck", "runtime-permissions", pinned)
    if runtime.get("existing_exact_grants") != runtime.get("required_grants") or runtime.get("created"):
        raise ValueError("Runtime grants changed; resume refused")
    (args.output_dir / "cli-config").mkdir(mode=0o700)
    state_result, _ = stages.run("00-quiescence", "scripts/identity_demo/identity_demo_execution_setup.py", [
        "--action", "inspect-state", "--kubeconfig", args.kubeconfig,
        "--expected-server", args.expected_server, "--credentials-file", str(rendered / "fixture-credentials.private.json"),
        "--cli", str(cli), "--cli-config-dir", str(args.output_dir / "cli-config"),
        "--output-dir", str(args.output_dir / "00-quiescence")])
    if state_result.get("rollback_quiescent") is not True:
        raise ValueError("Active or uncertain run state; resume refused")
    setup.write(args.output_dir / "resumed-checkpoint.json", {
        "previous_directory": str(previous), "creation_ledger_sha256": setup.sha(ledger_path),
        "bundle_sha256": setup.sha(bundle_path), "completed_mutations_replayed": False,
        "source_and_configuration_unchanged": True, "created_resource_uids_verified": True,
        "runtime_grants_verified": True, "quiescence_verified": True})
    run("09-discovery-plan", "discovery-access", pinned)
    if not args.apply:
        return {"ready": True, "resume_checkpoint_verified": True, "applied": False,
                "cluster_changed": False, "functional_scenarios_proven": False}
    run("09-discovery-apply", "discovery-access", [*pinned, "--apply"])
    result = finish_installation(args, env, stages, run, rendered, objects, cli,
        presenter_subject(objects), inference_path, creation_ledger=ledger_path)
    return {**result, "resumed_after_read_only_failure": True, "completed_mutations_replayed": False}


def resolve_ingress(args, config_path):
    """Discover one retained public router Service; never adopt or alter it."""
    from ipaddress import ip_address
    service = setup.kube(args,'get','service','router-default','-n','openshift-ingress','-o','json')
    if (service['metadata'].get('namespace')!='openshift-ingress'
            or service['metadata'].get('name')!='router-default' or not service['metadata'].get('uid')
            or service.get('spec',{}).get('selector',{}).get('ingresscontroller.operator.openshift.io/deployment-ingresscontroller')!='default'):
        raise ValueError('Compatible retained default ingress Service required')
    address=service['spec']['clusterIP'];parsed=ip_address(address)
    if parsed.is_unspecified or parsed.is_loopback or parsed.is_multicast:
        raise ValueError('Usable internal ingress Service address required')
    value=read_json(config_path)
    if value.get('ingress_cluster_ip') not in (None,address):
        raise ValueError('Configured ingress address differs from retained Service')
    resolved=args.output_dir/'resolved-installation-config.private.json'
    setup.write(resolved,{**value,'ingress_cluster_ip':address})
    setup.write(args.output_dir/'ingress-prerequisite.receipt.json',{
        'uid':service['metadata']['uid'],'namespace':'openshift-ingress','name':'router-default',
        'cluster_ip':address,'retained':True,'resource_changed':False})
    return resolved
