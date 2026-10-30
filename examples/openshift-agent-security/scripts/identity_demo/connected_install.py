# SPDX-License-Identifier: Apache-2.0
"""Order existing guarded installation helpers; never bootstrap shared operators."""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import shlex
import signal
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
            summary_name: str = "setup.summary.json", timeout: int = 1800) -> tuple[dict, Path]:
        """Run one existing helper with argv paths, withholding all raw output."""
        out = self.args.output_dir / name
        log = self.args.output_dir / (name + ".private.log")
        setup.write(self.args.output_dir / (name + ".pending.json"), {"stage": name})
        source_root = getattr(self.args, 'stage_root', setup.ROOT)
        command = [sys.executable, str(source_root / script), *words]
        if create_output:
            out.mkdir(mode=0o700)
        with log.open("x") as stream:
            os.chmod(log, 0o600)
            fence=getattr(self.args,'stage_fence',None)
            if fence is None:
                result = subprocess.run(command, cwd=source_root, env=self.env,
                                        stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
            else:
                # Only the installer parent owns/renews the lease. It fences the
                # entire helper group on loss; pending writes remain uncertain.
                fence()
                process=subprocess.Popen(command,cwd=source_root,env=self.env,stdout=stream,
                    stderr=subprocess.STDOUT,start_new_session=True)
                deadline=time.monotonic()+timeout
                try:
                    while process.poll() is None:
                        fence()
                        if time.monotonic()>=deadline:raise TimeoutError('Installer stage deadline reached')
                        time.sleep(.5)
                    fence()
                except BaseException:
                    if process.poll() is None:
                        os.killpg(process.pid,signal.SIGTERM)
                        try:process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=5)
                    raise
                result=subprocess.CompletedProcess(command,process.returncode)
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
    """Recognise exact unchanged bootstrap policies awaiting catalog routes.

    Retain the failed strict verifier receipt. This exception reports a dormant
    policy, never claims functional enforcement or alters the policy itself.
    """
    failures = result.get("failures")
    pending = {"AuthPolicy/fixture-mcp-auth", "AuthPolicy/fixture-mcp-tools-auth"}
    if (not isinstance(failures, list) or not failures
            or any(not isinstance(value, str) for value in failures)
            or len(failures) != len(set(failures)) or not set(failures) <= pending):
        return False
    for failure in failures:
        matches = [o for o in objects if o["kind"] == "AuthPolicy"
                   and o["metadata"]["name"] == failure.split("/", 1)[1]]
        if len(matches) != 1:
            return False
        desired = matches[0]
        current = setup.get(args, desired)
        setup.owned(current, args.profile)
        if current.get("spec") != desired.get("spec"):
            return False
        status = current.get("status", {})
        conditions = status.get("conditions", [])
        def current_condition(condition):
            return condition.get("observedGeneration", status.get("observedGeneration")) == current["metadata"].get("generation", 1)
        if not any(c.get("type") == "Accepted" and c.get("status") == "True"
                   and current_condition(c) for c in conditions):
            return False
        if not any(c.get("type") == "Enforced" and c.get("status") == "False"
                   and c.get("message") == "AuthPolicy is not in the path to any existing routes"
                   and current_condition(c) for c in conditions):
            return False
    return True


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
            replicas = current["spec"].get("replicas", 1)
            if (status.get("observedGeneration", 0) < current["metadata"].get("generation", 1)
                    or status.get("readyReplicas", 0) < replicas
                    or (current["kind"] == "Deployment"
                        and status.get("updatedReplicas", 0) < replicas)):
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
    if getattr(args, 'activate_cluster_runtime', False):
        cluster_runtime_inputs(args)
    if (args.expected_server != profile.expected_server
            or not isinstance(args.readiness_timeout, int)
            or not 30 <= args.readiness_timeout <= 1800):
        raise ValueError("Exact server and bounded readiness timeout required")
    setup.installer_subject(args, profile)
    identity_args = (['--installer-service-account',args.installer_service_account]
                     if getattr(args,'installer_service_account',None) else ['--installer-user',args.installer_user])
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
    if getattr(args, 'activate_cluster_runtime', False):
        env['IDENTITY_DEMO_REGISTRATION_MODE'] = 'controller'
    env["PYTHONPATH"] = os.pathsep.join(str(setup.ROOT / p) for p in (
        "runtime", "runtime/identity_demo", "scripts/identity_demo"))
    if inference_path:
        checked = subprocess.run([sys.executable, "-c",
            "import sys; from model_execution import private_inference; private_inference(sys.argv[1])",
            inference_path], env=env, cwd=setup.ROOT, capture_output=True, timeout=60)
        setup.write(args.output_dir / "inference-reference-check.json", {
            "passed": checked.returncode == 0, "credential_bytes_read": False,
            "model_request_made": False, "inherited_profile_removed": True})
        if checked.returncode:
            raise ValueError("Configured inference references invalid; no cluster changes made")
    stages = Stages(args, env)
    common = ["--kubeconfig", args.kubeconfig, "--expected-server", args.expected_server,
              "--oc", args.oc]
    if getattr(args, 'administrator_receipt', None):
        common += ['--administrator-receipt', args.administrator_receipt,
                   '--administrator-receipt-sha256', args.administrator_receipt_sha256]
    if getattr(args,'installer_service_account',None):
        common += ['--installer-service-account',args.installer_service_account]
    installer = "scripts/identity_demo/identity_demo_setup.py"

    def run(name: str, action: str, extra: list[str], *, allow_failure: bool = False) -> tuple[dict, Path]:
        return stages.run(name, installer, [action, *common, *extra,
                          "--output-dir", str(args.output_dir / name)], allow_failure=allow_failure)

    if getattr(args, "resume_installation", None):
        result = resume_discovery(args, env, stages, run, config_path, cli, inference_path)
        if getattr(args, 'activate_cluster_runtime', False) and args.apply:
            handoff = read_json(args.output_dir/'operator-paths.private.json')
            return activate_cluster_services(args, env, stages, Path(handoff['profile']).parent,
                                             cli, inference_path, result)
        return result
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
    run("03-access-plan", "prepare-access", [*pinned, *identity_args])
    if not args.apply:
        planned, _ = run("04-application-plan", "plan", [*pinned, "--server-dry-run"])
        return {"ready": planned["ready_for_create"], "applied": False, "cluster_changed": False,
                "access_preparation_required_before_admission": True,
                "render_directory": str(rendered), "functional_scenarios_proven": False}
    run("04-access-apply", "prepare-access", [*pinned, *identity_args, "--apply"])
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
    result = finish_installation(args, env, stages, run, rendered, objects, cli,
                                 suggested_presenter, inference_path)
    if getattr(args, 'activate_cluster_runtime', False):
        return activate_cluster_services(args, env, stages, rendered, cli, inference_path, result)
    return result


def finish_installation(args, env, stages, run, rendered, objects, cli,
                        suggested_presenter, inference_path, *, creation_ledger=None):
    """Complete verified installation stages; never replay application creation."""
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
    seed_mode = read_json(setup.private_file(args.installation_config)).get("fixture_seed_mode", "synthetic")
    if seed_mode not in ("synthetic", "none"):
        raise ValueError("Explicit synthetic or none fixture seed mode required")
    project_options = ["--project-only"] if seed_mode == "none" else []
    for name, action, extra in (("12-workspaces", "prepare-workspaces", []),
                               ("13-project", "provision-project", ["--project", "SERVICE", *project_options]),
                               ("13-incident-project", "provision-project", ["--project", "OPS", *project_options])):
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
    if len(verified["created"]) + len(verified.get('retained_prerequisites', [])) != sum(o["kind"] != "Namespace" for o in objects):
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


def activate_cluster_services(args, env, stages, rendered, cli, inference_path, application):
    """Join existing console/gateway helpers after the application is installed.

    Public prerequisite grants stay outside this operation. Each child keeps its
    original admission, ownership, idle and exact-receipt checks. No readiness
    claim here substitutes for subsequent workflow/security acceptance.
    """
    if not args.apply or application.get('application_installation_completed') is not True:
        raise ValueError('Successful applied application installation required before worker activation')
    if not inference_path:
        raise ValueError('Explicit private inference configuration required for cluster operation')
    for field in ('namespace_creation_receipt', 'namespace_creation_sha256',
                  'runtime_publication_receipt', 'runtime_publication_sha256'):
        if not getattr(args, field, None):
            raise ValueError('Original namespace and completed runtime publication receipts required')
    publication_path = setup.private_file(args.runtime_publication_receipt)
    publication = read_json(publication_path)
    if (setup.sha(publication_path) != args.runtime_publication_sha256
            or publication.get('published') is not True
            or publication.get('build_phases') != {'runtime': 'Complete'}):
        raise ValueError('Exact completed immutable runtime publication required')
    root = args.output_dir
    common = ['--kubeconfig', args.kubeconfig, '--expected-server', args.expected_server, '--oc', args.oc]
    if getattr(args, 'administrator_receipt', None):
        common += ['--administrator-receipt', args.administrator_receipt,
                   '--administrator-receipt-sha256', args.administrator_receipt_sha256]
    if getattr(args,'installer_service_account',None):
        common += ['--installer-service-account', args.installer_service_account]
    installer = 'scripts/identity_demo/identity_demo_setup.py'
    prerequisites = ['--installation-profile', str(rendered/'installation-profile.json'),
        '--namespace-creation-receipt', args.namespace_creation_receipt,
        '--namespace-creation-sha256', args.namespace_creation_sha256]
    ledger = setup.private_file(read_json(root/'operator-paths.private.json')['creation_ledger'])
    ledger_args = ['--ledger', str(ledger), '--console-ledger-sha256', setup.sha(ledger)]
    credentials = rendered/'fixture-credentials.private.json'
    certificate = (['--managed-certificate-config', args.installation_config]
        if read_json(rendered/'stack.private.json').get('certificate_management', {}).get('mode') == 'managed' else [])

    def console(name, stage, extra=()):
        result, out = stages.run(name, installer, ['console-runtime-prepare', *common,
            *prerequisites, '--credentials-file', str(credentials), '--console-runtime-stage', stage, *extra,
            '--output-dir', str(root/name), '--apply'])
        return result, out

    console('20-runtime-permissions', 'permissions')
    console('21-workload-policies', 'policies', ['--artifacts-file', env['IDENTITY_DEMO_ARTIFACTS']])
    console('22-realm-permissions', 'realm-permissions', [*ledger_args])
    _, configuration = console('23-console-configuration', 'configure', [*ledger_args,
        '--bundle', str(rendered/'stack.private.json'), '--bundle-sha256', setup.sha(rendered/'stack.private.json')])
    # Configuration replaces the driver/adapter Pods. Observe that rollout
    # before the next helper reads durable idle state through the driver.
    wait_controllers(args, [o for o in read_json(rendered/'stack.private.json').get('objects', [])
        if o['kind'] == 'Deployment' and o['metadata']['name'] in (
            'fixture-identity-driver', 'fixture-protected-adapter')])
    # Long builds can span SPIRE CA overlap changes. Reconcile only the owned
    # public copies while the execution lane is still closed, before observing.
    ca_args = []
    if certificate:
        from managed_certificates import SPIRE_TRUST
        records = [v for v in read_json(ledger)['created'] if v['kind'] == 'Secret'
            and v.get('namespace') == args.profile.core_namespace
            and v['metadata']['name'] == SPIRE_TRUST]
        if len(records) != 1:
            raise ValueError('Original separate public SPIRE trust identity required')
        ca_args = ['--public-trust-ca-uid', records[0]['metadata']['uid']]
    stages.run('23a-public-trust-reconcile', 'scripts/identity_demo/identity_demo_sender_trust.py', [
        '--kubeconfig', args.kubeconfig, '--expected-server', args.expected_server,
        '--namespace', args.profile.core_namespace, '--credentials-file', str(credentials),
        *ca_args, '--output-dir', str(root/'23a-public-trust-reconcile'), '--apply'],
        create_output=True, summary_name='sender-trust.summary.json')
    wait_controllers(args, [o for o in read_json(rendered/'stack.private.json').get('objects', [])
        if o['kind'] == 'Deployment' and o['metadata']['name'] == 'fixture-keycloak-upstream'])
    _, trust = console('24-trust-observation', 'trust-observation', [*ledger_args, *certificate])
    configuration_args = ['--console-configuration-receipt', str(configuration/'setup.summary.json'),
        '--console-configuration-sha256', setup.sha(configuration/'setup.summary.json')]
    _, gateway = stages.run('25-persistent-gateway', 'scripts/identity_demo/identity_demo_execution_setup.py', [
        '--action', 'gateway-install', '--kubeconfig', args.kubeconfig,
        '--expected-server', args.expected_server, '--credentials-file', str(credentials),
        '--cli', str(cli), '--cli-config-dir', str(root/'cli-config'),
        '--ca-file', str(rendered/'runtime-gateway-ca.pem'),
        '--catalog-credential-file', str(root/'catalog-credential.private.json'),
        '--output-dir', str(root/'25-persistent-gateway'), '--apply'])
    _, observation = console('26-gateway-observation', 'gateway-observation', [
        '--runtime-gateway-receipt', str(gateway/'persistent-gateway.receipt.private.json')])
    gateway_args = ['--runtime-gateway-receipt', str(observation/'persistent-gateway.receipt.private.json')]
    publication_args = ['--runtime-publication-receipt', str(publication_path),
                        '--runtime-publication-sha256', args.runtime_publication_sha256]
    _, workers = console('27-cluster-workers', 'workloads', [*certificate, *configuration_args,
        *publication_args, *gateway_args, '--installation-config', args.installation_config,
        '--artifacts-file', env['IDENTITY_DEMO_ARTIFACTS'],
        '--console-management-ca', str(rendered/'runtime-gateway-ca.pem'),
        '--console-catalog-credential', str(root/'catalog-credential.private.json'),
        '--console-trust-observation-receipt', str(trust/'sender-trust.receipt.json'),
        '--inference-config', inference_path])
    wait_controllers(args, read_json(workers/'runtime-workloads.plan.private.json')['objects'])
    worker_args = ['--console-worker-receipt', str(workers/'setup.summary.json'),
                   '--console-worker-sha256', setup.sha(workers/'setup.summary.json')]
    _, refreshed = console('28-public-trust-refresh', 'update-workloads', [*ledger_args,
        *configuration_args, *worker_args, *publication_args, *gateway_args,
        '--refresh-sender-trust', '--enable-public-trust-refresh'])
    # Trust refresh replaces both workers. Observe the replacement Pods before
    # their exact management-profile and lease checks authorize scheduling.
    wait_controllers(args, read_json(workers/'runtime-workloads.plan.private.json')['objects'])
    _, enabled = console('29-automatic-preparation', 'automatic-enable', [*configuration_args,
        '--console-worker-receipt', str(refreshed/'setup.summary.json'),
        '--console-worker-sha256', setup.sha(refreshed/'setup.summary.json'),
        '--pool-mode', args.pool_mode,
        *(['--workload-image', args.workload_image] if getattr(args, 'workload_image', None) else []),
        *(['--pool-profile-configuration', args.pool_profile_configuration]
          if getattr(args, 'pool_profile_configuration', None) else [])])
    return {**application, 'cluster_runtime_activated': True, 'pool_mode': args.pool_mode,
        'automatic_preparation_receipt': str(enabled/'setup.summary.json'),
        'functional_scenarios_proven': False,
        'next_action': 'Wait for verified capacity; perform browser and security acceptance before migration'}


def cluster_runtime_inputs(args):
    """Reject missing cluster handoff inputs before any application mutation."""
    for name, digest_name in (
            ('namespace_creation_receipt', 'namespace_creation_sha256'),
            ('administrator_receipt', 'administrator_receipt_sha256'),
            ('runtime_publication_receipt', 'runtime_publication_sha256')):
        path, expected = getattr(args, name, None), getattr(args, digest_name, None)
        if not path or not expected or setup.sha(setup.private_file(path)) != expected:
            raise ValueError('Exact namespace, administrator and runtime-publication handoffs required')
    publication = read_json(Path(args.runtime_publication_receipt))
    image = publication.get('images', {}).get('console_runtime', '')
    from deployment_artifacts import IMAGE_REFERENCE
    if (publication.get('published') is not True
            or publication.get('build_phases') != {'runtime': 'Complete'}
            or publication.get('packaged_checks_passed') is not True
            or not IMAGE_REFERENCE.fullmatch(image)
            or not image.startswith('image-registry.openshift-image-registry.svc:5000/' + args.profile.core_namespace + '/')):
        raise ValueError('Verified owned cluster runtime publication required')
    if (getattr(args, 'pool_mode', 'legacy') == 'profiles'
            and not getattr(args, 'pool_profile_configuration', None)
            and (not isinstance(getattr(args, 'workload_image', None), str)
                 or not IMAGE_REFERENCE.fullmatch(args.workload_image)
                 or args.workload_image.endswith('0' * 64))):
        raise ValueError('Reviewed digest-pinned workload image required for default profiles')
    if not getattr(args, 'inference_config', None):
        raise ValueError('Private inference configuration required for cluster operation')
