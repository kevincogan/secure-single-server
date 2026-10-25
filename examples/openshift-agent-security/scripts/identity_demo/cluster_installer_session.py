# SPDX-License-Identifier: Apache-2.0
"""Durable phase orchestration around the existing guarded installation helpers.

Only the fixed mounted configuration is accepted. The parent owns the installer
lease and fences child process groups; children never carry a human kubeconfig.
An uncertain stage requires recovery rather than an automatic mutation replay.
"""

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import shutil

from connected_install import Stages
from deployment_artifacts import validate_artifacts
from deployment_profile import DeploymentProfile
from identity_demo_cluster_bootstrap import mounted
from source_render import canonical_hash, read_json
import identity_demo_setup as setup

FIELDS = {
    "schema_version",
    "profile",
    "artifacts",
    "application",
    "public_trust",
    "kubernetes_api_cidrs",
    "certificate_management",
    "credentials",
}
APPLICATION_FIELDS = {
    "chat_request_url",
    "chat_model",
    "workload_image",
    "diagnostic_runtime_image",
}
TRUST_FILES = {
    "service_ca": "service-ca.pem",
    "spire_ca": "spire-ca.pem",
    "upstream_ca_bundle": "upstream-ca.pem",
    "kubernetes_ca": "kubernetes-ca.pem",
}
CREDENTIALS = {
    "inference": {"secret_name": "fixture-installer-inference", "key": "api-key"}
}


def configuration(value):
    """Validate one versioned public contract; accept references, never passwords."""
    if (
        not isinstance(value, dict)
        or not FIELDS <= set(value)
        or set(value) - FIELDS - {"native_builder_image", "fixture_seed_mode"}
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["credentials"] != CREDENTIALS
        or not isinstance(value["application"], dict)
        or set(value["application"]) != APPLICATION_FIELDS
        or not isinstance(value["public_trust"], dict)
        or set(value["public_trust"])
        != {"service_ca", "spire_ca", "upstream_ca_bundle", "kubernetes_ca"}
    ):
        raise ValueError(
            "Exact installer configuration with fixed credential references required"
        )
    if any(
        value["public_trust"][name] != filename
        and not (name == "kubernetes_ca" and value["public_trust"][name] == "system")
        for name, filename in TRUST_FILES.items()
    ):
        raise ValueError(
            "Fixed public trust file references required; never embed authority keys"
        )
    if value.get("fixture_seed_mode", "synthetic") not in ("synthetic", "none"):
        raise ValueError("Explicit synthetic or none fixture seed mode required")
    profile = DeploymentProfile.from_dict(value["profile"])
    if "native_builder_image" in value:
        from native_build import verified_builder_image, RECIPES

        mirror = verified_builder_image(
            value["native_builder_image"], read_json(RECIPES / "inputs.lock.json")
        )
        internal = "image-registry.openshift-image-registry.svc:5000/"
        if mirror.startswith(internal) and not mirror.startswith(
            internal + profile.core_namespace + "-build/fixture-native-builder-base@"
        ):
            raise ValueError(
                "Internal builder mirror must belong to this bootstrap namespace"
            )
    validate_artifacts(value["artifacts"])
    from source_render import api_addresses

    api_addresses(value["kubernetes_api_cidrs"])
    policy = value["certificate_management"]
    if policy != {"mode": "legacy"} and (
        not isinstance(policy, dict)
        or set(policy) != {"mode", "issuer_ref", "issuer_uid", "ca_file_ref"}
        or policy["mode"] != "managed"
    ):
        raise ValueError(
            "Explicit legacy mode or approved managed certificate issuer required"
        )
    if policy["mode"] == "managed" and policy["ca_file_ref"] != "application-ca.pem":
        raise ValueError(
            "Fixed approved public application authority reference required"
        )
    return value


@contextmanager
def ownership(root):
    """A PVC file lock complements, but never replaces, the API lease fence."""
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.is_symlink() or root.stat().st_mode & 0o077:
        raise ValueError("Private regular installer state required")
    fd = os.open(root / "installer.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


class CompletedStages:
    """Reuse proved completions; retain every interrupted stage as uncertain."""

    def __init__(self, args, env):
        self.args = args
        self.stages = Stages(args, env)

    def run(self, name, script, words, **options):
        self.args.stage_fence()
        path = self.args.output_dir / (name + ".completed.json")
        identity = canonical_hash(
            {"script": script, "arguments": words, "options": options}
        )
        if path.exists():
            done = read_json(setup.private_file(str(path)))
            stage_receipt = self.args.output_dir / (name + ".receipt.json")
            log = self.args.output_dir / (name + ".private.log")
            receipt = read_json(setup.private_file(str(stage_receipt)))
            if (
                done.get("identity") != identity
                or done.get("receipt_sha256") != setup.sha(stage_receipt)
                or receipt.get("exit") != 0
                or receipt.get("log_sha256") != setup.sha(log)
            ):
                raise ValueError(
                    "Installer completion changed; explicit recovery required"
                )
            return done["result"], self.args.output_dir / name
        if (self.args.output_dir / (name + ".pending.json")).exists():
            raise ValueError(
                "Interrupted installer stage; inspect its original receipts without replay"
            )
        result, out = self.stages.run(name, script, words, **options)
        self.args.stage_fence()
        setup.write(
            path,
            {
                "identity": identity,
                "result": result,
                "receipt_sha256": setup.sha(
                    self.args.output_dir / (name + ".receipt.json")
                ),
            },
        )
        return result, out


def prepare_inputs(
    value,
    root,
    *,
    source,
    credential_root,
    token_root,
    public_trust_root=Path("/public-trust"),
):
    """Freeze public inputs and private source separately from generated history."""
    value = configuration(value)
    inputs = root / "inputs"
    inputs.mkdir(mode=0o700, exist_ok=True)
    expected = {
        "configuration_sha256": canonical_hash(value),
        "source_manifest_sha256": setup.sha(source / "export-manifest.json"),
    }
    marker = root / "inputs.completed.json"
    if marker.exists():
        recorded = read_json(setup.private_file(str(marker)))
        if any(recorded.get(k) != v for k, v in expected.items()):
            raise ValueError(
                "Installer source/configuration changed; review a new migration"
            )
        hashes = recorded.get("inputs_sha256", {})
        if (
            not hashes
            or set(hashes) != {p.name for p in inputs.iterdir()}
            or any(
                p.is_symlink() or not p.is_file() or setup.sha(p) != hashes[p.name]
                for p in inputs.iterdir()
            )
        ):
            raise ValueError(
                "Frozen installer inputs changed; explicit recovery required"
            )
        if (
            mounted(credential_root, "inference.key", maximum=8192)
            != (inputs / "inference.key").read_bytes()
        ):
            raise ValueError(
                "Referenced inference credential changed during installation"
            )
        return inputs
    if any(inputs.iterdir()):
        raise ValueError(
            "Interrupted input preparation; preserve state and reconcile without overwriting"
        )

    def save(name, content):
        path = inputs / name
        with path.open("xb") as stream:
            os.chmod(path, 0o600)
            stream.write(content)
        return path

    def json_file(name, data):
        return save(name, json.dumps(data, sort_keys=True).encode())

    profile = DeploymentProfile.from_dict(value["profile"])
    json_file("installation-profile.json", profile.to_dict())
    json_file("artifacts.json", value["artifacts"])
    trust = {}
    for name, filename in value["public_trust"].items():
        if name == "kubernetes_ca" and filename == "system":
            import ssl

            pem = "".join(
                ssl.DER_cert_to_PEM_cert(v)
                for v in ssl.create_default_context().get_ca_certs(binary_form=True)
            ).encode()
        else:
            pem = mounted(public_trust_root, filename)
        trust[name] = str(save(name + ".pem", pem))
    policy = dict(value["certificate_management"])
    if policy["mode"] == "managed":
        policy["ca_file"] = str(
            save(
                "application-ca.pem",
                mounted(public_trust_root, policy.pop("ca_file_ref")),
            )
        )
    install = {
        "schema_version": 1,
        "profile": profile.to_dict(),
        "artifacts_file": str(inputs / "artifacts.json"),
        "public_trust": {
            name: path for name, path in trust.items() if name != "kubernetes_ca"
        },
        "kubernetes_api_cidrs": value["kubernetes_api_cidrs"],
        "certificate_management": policy,
        "native_management_scope": "workspaces-only",
        "fixture_seed_mode": value.get("fixture_seed_mode", "synthetic"),
    }
    install_path = json_file("installation.json", install)
    # Reuse the existing complete certificate/image/network validation before
    # invoking a compiler, creating cluster resources or trusting model inputs.
    from source_render import load_inputs

    load_inputs(install_path)
    key = mounted(credential_root, "inference.key", maximum=8192)
    if not key.strip():
        raise ValueError("Nonempty referenced inference credential required")
    save("inference.key", key)
    application = dict(
        value["application"],
        schema_version=1,
        credential_file=str(inputs / "inference.key"),
    )
    json_file("application.json", application)
    from source_render import certificate_bundle

    # The external API hostname can use a different CA from kubernetes.default.
    # Use explicitly approved public API roots; never assume the token-volume
    # CA authenticates that hostname or weaken TLS to make a connection work.
    public_api = (
        Path(trust["kubernetes_ca"]).read_bytes()
        if value["public_trust"]["kubernetes_ca"] == "system"
        else certificate_bundle(Path(trust["kubernetes_ca"])).encode()
    )
    ca = save("kubernetes-ca.crt", public_api)
    json_file(
        "kubeconfig.json",
        {
            "apiVersion": "v1",
            "kind": "Config",
            "current-context": "installer",
            "clusters": [
                {
                    "name": "installation",
                    "cluster": {
                        "server": profile.expected_server,
                        "certificate-authority": str(ca),
                    },
                }
            ],
            "users": [
                {"name": "installer", "user": {"tokenFile": str(token_root / "token")}}
            ],
            "contexts": [
                {
                    "name": "installer",
                    "context": {
                        "cluster": "installation",
                        "user": "installer",
                        "namespace": profile.core_namespace,
                    },
                }
            ],
        },
    )
    target = root / "source"
    target.mkdir(mode=0o700)
    manifest = read_json(source / "export-manifest.json")
    for entry in manifest["files"]:
        original = source / entry["path"]
        if (
            ".." in Path(entry["path"]).parts
            or Path(entry["path"]).is_absolute()
            or original.is_symlink()
            or not original.resolve().is_relative_to(source.resolve())
            or not original.is_file()
            or setup.sha(original) != entry["sha256"]
        ):
            raise ValueError("Reviewed regular source inventory required")
        destination = target / entry["path"]
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(original, destination)
    shutil.copyfile(source / "export-manifest.json", target / "export-manifest.json")
    setup.write(
        marker,
        {**expected, "inputs_sha256": {p.name: setup.sha(p) for p in inputs.iterdir()}},
    )
    return inputs


def immutable_json(path, value):
    """An interrupted phase may reuse identical local output, never replace it."""
    if path.exists():
        if read_json(setup.private_file(str(path))) != value:
            raise ValueError(
                "Generated installer input changed; explicit recovery required"
            )
    else:
        setup.write(path, value)
    return path


def namespace_receipt(args, profile, original, destination):
    """Verify all three original namespace UIDs before a scoped build operation."""
    entries = original.get("items", [])
    if (
        original.get("kind") != "List"
        or len(entries) != 3
        or {o.get("metadata", {}).get("name") for o in entries}
        != set(profile.application_namespaces)
    ):
        raise ValueError(
            "Original creation responses for three exact namespaces required"
        )
    created = []
    for recorded in entries:
        if recorded.get("kind") != "Namespace" or not recorded["metadata"].get("uid"):
            raise ValueError("Original namespace identity required")
        setup.owned(recorded, profile)
        name = recorded["metadata"]["name"]
        current = setup.kube(args, "get", "namespace", name, "-o", "json")
        setup.owned(current, profile)
        if current["metadata"]["uid"] != recorded["metadata"]["uid"] or current[
            "metadata"
        ].get("deletionTimestamp"):
            raise ValueError(
                "Namespace replaced or terminating; no operation permitted"
            )
        created.append(
            {"kind": "Namespace", "name": name, "uid": recorded["metadata"]["uid"]}
        )
    return immutable_json(destination, {"created": created})


def build_session(args):
    """Run in the scoped installer Job; stop at the public administrator handoff."""
    import base64
    from types import SimpleNamespace
    from identity_demo_operator_access import ensure_access
    from identity_demo_worker_lease import install as acquire_lease

    if not args.apply:
        raise ValueError(
            "Scoped build session requires explicit --apply inside its Job"
        )
    received = args.output_dir / "received.configuration.private.json"
    with received.open("xb") as stream:
        os.chmod(received, 0o600)
        stream.write(mounted(Path("/inputs"), "installation.json"))
    value = configuration(read_json(received))
    profile = DeploymentProfile.from_dict(value["profile"])
    if os.environ.get("POD_NAMESPACE") != profile.core_namespace or not os.environ.get(
        "POD_UID"
    ):
        raise ValueError("Owned installer Pod identity required")
    root = Path("/state/private")
    with ownership(root):
        token_root = Path("/var/run/secrets/kubernetes.io/serviceaccount")
        public_config_path = immutable_json(
            root / "installer.configuration.json", value
        )
        inputs = prepare_inputs(
            value,
            root,
            source=setup.ROOT,
            credential_root=Path("/credentials"),
            token_root=token_root,
        )
        os.environ.update(
            IDENTITY_DEMO_CONFIG=str(inputs / "installation-profile.json"),
            IDENTITY_DEMO_KUBERNETES_CA=str(inputs / "kubernetes-ca.crt"),
            IDENTITY_DEMO_RUNTIME="cluster",
        )
        stage_root = root / "stages"
        stage_root.mkdir(mode=0o700, exist_ok=True)
        control = SimpleNamespace(
            profile=profile,
            output_dir=stage_root,
            kubeconfig=str(inputs / "kubeconfig.json"),
            expected_server=profile.expected_server,
            oc="/usr/local/bin/oc",
            service_account_token_file=str(token_root / "token"),
            service_account_token_root=str(token_root),
            service_account_namespace=profile.core_namespace,
            service_account_name="fixture-installer"
            if getattr(args, "installer_application", False)
            else "fixture-installer-build-operator",
            pod_uid=os.environ["POD_UID"],
            operator_login_file=None,
        )
        ensure_access(control)
        lease = acquire_lease(
            control,
            "installer"
            if getattr(args, "installer_application", False)
            else "installer-build",
        )
        try:
            setup.target(control)
            raw_namespace = args.output_dir / "received.namespaces.private.json"
            with raw_namespace.open("xb") as stream:
                os.chmod(raw_namespace, 0o600)
                stream.write(mounted(Path("/receipts"), "namespaces.json"))
            receipt = namespace_receipt(
                control,
                profile,
                read_json(raw_namespace),
                root / "namespace-receipt.json",
            )
            ingress = setup.kube(
                control,
                "get",
                "service",
                "router-default",
                "-n",
                "openshift-ingress",
                "-o",
                "json",
            )
            if (
                ingress.get("metadata", {}).get("namespace") != "openshift-ingress"
                or ingress["metadata"].get("name") != "router-default"
                or not ingress["metadata"].get("uid")
                or ingress.get("spec", {})
                .get("selector", {})
                .get(
                    "ingresscontroller.operator.openshift.io/deployment-ingresscontroller"
                )
                != "default"
            ):
                raise ValueError("Exact retained default ingress Service required")
            address = ingress["spec"]["clusterIP"]
            immutable_json(
                root / "ingress-target.json",
                {"uid": ingress["metadata"]["uid"], "address": address},
            )
            routed = immutable_json(
                root / "routing-installation.json",
                dict(
                    read_json(inputs / "installation.json"), ingress_cluster_ip=address
                ),
            )
            own = setup.kube(
                control,
                "get",
                "pod",
                os.environ["POD_NAME"],
                "-n",
                profile.core_namespace,
                "-o",
                "json",
            )
            if (
                own["metadata"]["uid"] != os.environ["POD_UID"]
                or own["spec"]["serviceAccountName"] != control.service_account_name
            ):
                raise ValueError("Exact current installer Pod required")
            installer_image = own["spec"]["containers"][0]["image"]
            immutable_json(root / "installer-image.json", {"image": installer_image})
            control.stage_fence = lease.assert_current
            control.stage_root = root / "source"
            environment = {
                **os.environ,
                "HOME": str(root),
                "IDENTITY_DEMO_RUNTIME": "local",
                "IDENTITY_DEMO_REGISTRATION_MODE": "controller",
                "PYTHONPATH": os.pathsep.join(
                    str(control.stage_root / p)
                    for p in ("scripts/identity_demo", "tests/identity_demo")
                ),
            }
            # Only this parent changes the lease. The existing stage runner kills
            # the complete child group if that ownership stops being fresh.
            stages = CompletedStages(control, environment)
            installer = "scripts/identity_demo/identity_demo_setup.py"
            common = [
                "--kubeconfig",
                control.kubeconfig,
                "--expected-server",
                profile.expected_server,
                "--oc",
                control.oc,
            ]

            def run(name, action, extra, timeout=1800):
                return stages.run(
                    name,
                    installer,
                    [action, *common, *extra, "--output-dir", str(stage_root / name)],
                    timeout=timeout,
                )

            _, configured = stages.run(
                "01-configuration",
                "scripts/configure-demo.py",
                [
                    "--config",
                    str(inputs / "application.json"),
                    "--output-dir",
                    str(stage_root / "01-configuration"),
                    "--apply",
                ],
            )
            run(
                "02-preflight",
                "preflight",
                ["--installation-config", str(routed)],
            )
            _, rendered = run(
                "03-render",
                "render",
                ["--installation-config", str(routed)],
            )
            _, native = run(
                "04-native",
                "native-cluster-build",
                [
                    "--installation-profile",
                    str(inputs / "installation-profile.json"),
                    "--source-archive",
                    "/usr/share/installer-inputs/openshell-source.tar.gz",
                    "--native-ca-bundle",
                    str(rendered / "native-public-trust.pem"),
                    "--namespace-creation-receipt",
                    str(receipt),
                    "--namespace-creation-sha256",
                    setup.sha(receipt),
                    "--apply",
                ]
                + (
                    ["--native-builder-image", value["native_builder_image"]]
                    if "native_builder_image" in value
                    else []
                ),
                timeout=7200,
            )
            built = read_json(native / "native-cluster-build.receipt.json")
            first = read_json(rendered / "stack.private.json")
            if (
                built.get("offline_compilation_passed") is not True
                or built.get("native_build_contract") != profile.native_build_contract
                or built.get("native_ca_bundle_sha256")
                != first["native_ca_bundle_sha256"]
            ):
                raise ValueError(
                    "Completed native build does not match the original private render"
                )
            artifacts = dict(
                value["artifacts"],
                images=dict(value["artifacts"]["images"]),
                native_build_contract=profile.native_build_contract,
                native_ca_bundle_sha256=built["native_ca_bundle_sha256"],
            )
            for role in ("gateway", "supervisor"):
                result = built.get("runtime_checks", {}).get(role, {})
                if (
                    result.get("packaged_binary_matches") is not True
                    or result.get("offline_help_and_version_passed") is not True
                ):
                    raise ValueError("Native packaged-byte and offline checks required")
                artifacts["images"]["openshell_" + role] = result["image"]
            validate_artifacts(artifacts)
            generated = root / "generated"
            generated.mkdir(mode=0o700, exist_ok=True)
            artifact_path = immutable_json(generated / "artifacts.json", artifacts)
            install = dict(
                read_json(routed),
                artifacts_file=str(artifact_path),
            )
            install_path = immutable_json(generated / "installation.json", install)
            _, final = run(
                "05-final-render",
                "render",
                [
                    "--installation-config",
                    str(install_path),
                    "--state-file",
                    str(rendered / "installation-state.private.json"),
                ],
            )
            if not read_json(final / "stack.private.json").get(
                "native_build_contract_matches"
            ):
                raise ValueError(
                    "Final rendered trust differs from verified native artifacts"
                )
            _, runtime = run(
                "06-worker-image",
                "console-runtime-cluster-build",
                [
                    "--installation-profile",
                    str(inputs / "installation-profile.json"),
                    "--runtime-configuration-receipt",
                    str(configured / "configuration.receipt.json"),
                    "--apply",
                ],
            )
            environment["IDENTITY_DEMO_ARTIFACTS"] = str(artifact_path)
            _, administrator = run(
                "07-administrator-handoff",
                "installer-prerequisites",
                [
                    "--bundle",
                    str(final / "stack.private.json"),
                    "--bundle-sha256",
                    setup.sha(final / "stack.private.json"),
                    "--artifacts-file",
                    str(artifact_path),
                    "--installer-configuration",
                    str(public_config_path),
                    "--installer-ingress-address",
                    address,
                    "--runtime-publication-receipt",
                    str(runtime / "publication.receipt.json"),
                ],
            )
            plan = read_json(administrator / "administrator-prerequisites.json")
            if getattr(args, "installer_application", False):
                # The build-only authority and quota must be retired before
                # the installer receives application Pod/exec authority.
                if setup.kube(
                    control,
                    "get",
                    "resourcequota",
                    "fixture-installer-build-budget",
                    "-n",
                    profile.core_namespace,
                    "--ignore-not-found",
                    "-o",
                    "json",
                ):
                    raise ValueError(
                        "Retire the exact temporary build budget before application activation"
                    )
                build_binding = (
                    "identity-demo-" + profile.installation_id + "-installer-build"
                )
                if setup.kube(
                    control,
                    "get",
                    "rolebinding",
                    build_binding,
                    "-n",
                    profile.core_namespace,
                    "--ignore-not-found",
                    "-o",
                    "json",
                ):
                    raise ValueError(
                        "Revoke build-stage write authority before application activation"
                    )
                raw = args.output_dir / "received.administrator.private.json"
                with raw.open("xb") as stream:
                    os.chmod(raw, 0o600)
                    stream.write(
                        mounted(Path("/receipts"), "administrator.receipt.json")
                    )
                approved = read_json(raw)
                if (
                    approved.get("schema_version") != 1
                    or approved.get("installation_profile") != profile.to_dict()
                    or approved.get("expected_server") != profile.expected_server
                    or approved.get("plan_sha256")
                    != setup.sha(administrator / "administrator-prerequisites.json")
                ):
                    raise ValueError(
                        "Exact administrator approval/creation receipt required"
                    )
                approved_path = immutable_json(
                    root / "administrator.receipt.json", approved
                )
                from installer_tools import private_cli

                cli = private_cli(root / "tools")
                result, connected = run(
                    "08-application",
                    "connected-install",
                    [
                        "--installation-config",
                        str(install_path),
                        "--state-file",
                        str(rendered / "installation-state.private.json"),
                        "--installer-service-account",
                        profile.core_namespace + ":fixture-installer",
                        "--administrator-receipt",
                        str(approved_path),
                        "--administrator-receipt-sha256",
                        setup.sha(approved_path),
                        "--namespace-creation-receipt",
                        str(receipt),
                        "--namespace-creation-sha256",
                        setup.sha(receipt),
                        "--runtime-publication-receipt",
                        str(runtime / "publication.receipt.json"),
                        "--runtime-publication-sha256",
                        setup.sha(runtime / "publication.receipt.json"),
                        "--inference-config",
                        str(configured / "inference-config.private.json"),
                        "--cli",
                        str(cli),
                        "--workload-image",
                        value["application"]["workload_image"],
                        "--activate-cluster-runtime",
                        "--pool-mode",
                        "profiles",
                        "--apply",
                    ],
                    timeout=7200,
                )
                return {
                    **result,
                    "installer_session_completed": True,
                    "application_receipts": str(connected),
                    "customer_acceptance_pending": True,
                }
            from cluster_installer_resources import build_job

            app_job = build_job(
                value, installer_image, phase="application", ingress_address=address
            )
            print(
                "APPLICATION_JOB="
                + base64.b64encode(
                    json.dumps(app_job, sort_keys=True).encode()
                ).decode(),
                flush=True,
            )
            print(
                "ADMIN_PLAN="
                + base64.b64encode(
                    (administrator / "administrator-prerequisites.json").read_bytes()
                ).decode(),
                flush=True,
            )
            for index, obj in enumerate(plan["items"]):
                if obj["kind"] == "Secret":
                    raise ValueError(
                        "Private data cannot enter the administrator handoff"
                    )
                encoded = base64.b64encode(
                    json.dumps(obj, sort_keys=True).encode()
                ).decode()
                print("ADMIN_RESOURCE=" + str(index) + ":" + encoded, flush=True)
            return {
                "build_session_completed": True,
                "application_installed": False,
                "administrator_review_required": True,
                "source_manifest_sha256": setup.sha(
                    setup.ROOT / "export-manifest.json"
                ),
                "administrator_plan_sha256": setup.sha(
                    administrator / "administrator-prerequisites.json"
                ),
                "runtime_publication": str(runtime / "publication.receipt.json"),
                "state_root": str(root),
                "functional_scenarios_proven": False,
            }
        finally:
            lease.close()


def application_session(args):
    """Reuse verified build checkpoints; only an explicit phase can activate."""
    args.installer_application = True
    return build_session(args)
