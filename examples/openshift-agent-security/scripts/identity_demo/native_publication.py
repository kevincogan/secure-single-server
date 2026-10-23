# SPDX-License-Identifier: Apache-2.0
"""Publish verified native contexts through owned OpenShift binary builds.

No shared registry configuration, credential export, image pull grant, mutation
retry or broad runtime egress is introduced. Publication is development evidence;
scans, provenance review and actual runtime acceptance remain separate gates.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
from ipaddress import ip_network
import json
from pathlib import Path
import re
import subprocess

from deployment_profile import DeploymentProfile
from native_build import RECIPES, digest, runtime_recipe
from source_render import read_json


def inputs(args: argparse.Namespace) -> tuple[dict, DeploymentProfile, dict]:
    """Bind publication to a completed build, exact profile and public contexts."""
    from identity_demo_setup import private_file

    path = private_file(args.native_build_receipt)
    if digest(path) != args.native_build_sha256:
        raise ValueError("Exact native build receipt hash required")
    receipt = read_json(path)
    profile = DeploymentProfile.from_dict(read_json(private_file(args.installation_profile)))
    lock = read_json(RECIPES / "inputs.lock.json")
    if (receipt.get("applied") is not True or receipt.get("offline_compilation_passed") is not True
            or receipt.get("native_build_contract") != profile.native_build_contract
            or any(receipt.get(k) != lock[k] for k in
                   ("source_commit", "source_archive_sha256", "cargo_lock_sha256", "patches", "target"))):
        raise ValueError("Completed reviewed target-bound build required")
    contexts = {}
    for role in ("gateway", "supervisor"):
        directory = path.parent / role
        library = "libz3.so.4" if role == "gateway" else "libgcc_s.so.1"
        licence = "libz3-4.copyright" if role == "gateway" else "libgcc-s1.copyright"
        names = {"Containerfile", "openshell-" + role, library, licence,
                 "native-public-trust.pem", "supplied-library.spdx.json"}
        hashes = read_json(private_file(str(path.parent / (role + "-context.json"))))
        if (directory.is_symlink() or not directory.is_dir()
                or set(p.name for p in directory.iterdir()) != names or set(hashes) != names):
            raise ValueError("Exact allowlisted public build context required")
        for name, expected in hashes.items():
            item = directory / name
            if item.is_symlink() or not item.is_file() or digest(item) != expected:
                raise ValueError("Native context changed after build")
        if (hashes["openshell-" + role] != receipt["outputs"][role]["binary_sha256"]
                or hashes["native-public-trust.pem"] != receipt["native_ca_bundle_sha256"]
                or not receipt["outputs"][role].get("packaged_binary_matches")
                or not receipt["outputs"][role].get("offline_help_and_version_passed")):
            raise ValueError("Native executable/public trust evidence mismatch")
        recipe = (directory / "Containerfile").read_text()
        if recipe != runtime_recipe(lock, receipt, role):
            raise ValueError("Exact reviewed runtime recipe required")
        contexts[role] = {"path": str(directory), "sha256": hashes}
    return receipt, profile, contexts


def network_policy(profile: DeploymentProfile, configuration: dict, names: list[str]) -> dict:
    """Limit temporary build egress to reviewed destinations, DNS and registry."""
    if (set(configuration) != {"schema_version", "api_cidrs", "https_cidrs"}
            or type(configuration["schema_version"]) is not int or configuration["schema_version"] != 1):
        raise ValueError("Exact publication network configuration required")
    for key in ("api_cidrs", "https_cidrs"):
        values = configuration[key]
        if not isinstance(values, list) or not 1 <= len(values) <= 512 or len(set(values)) != len(values):
            raise ValueError("Bounded distinct explicit publication destinations required")
        for value in values:
            net = ip_network(value, strict=True)
            if (str(net) != value or net.prefixlen == 0
                    or key == "api_cidrs" and net.prefixlen != net.max_prefixlen):
                raise ValueError("Canonical bounded build destinations; exact API hosts required")
    def cidrs(key: str) -> list[dict]:
        return [{"ipBlock": {"cidr": value}} for value in configuration[key]]
    return {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {
        "name": "fixture-" + profile.installation_id + "-native-build-egress",
        "namespace": profile.core_namespace, "labels": dict(profile.labels)}, "spec": {
        "podSelector": {"matchExpressions": [{"key": "openshift.io/build.name", "operator": "In", "values": names}]},
        "policyTypes": ["Egress"], "egress": [
            {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "openshift-dns"}}}],
             "ports": [{"protocol": proto, "port": port} for proto in ("TCP", "UDP") for port in (53, 5353)]},
            {"to": cidrs("api_cidrs"), "ports": [{"protocol": "TCP", "port": p} for p in (443, 6443)]},
            {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "openshift-image-registry"}}}],
             "ports": [{"protocol": "TCP", "port": 5000}]},
            {"to": cidrs("https_cidrs"), "ports": [{"protocol": "TCP", "port": 443}]}]}}


def publication(args: argparse.Namespace) -> dict:
    """Plan or submit new binary builds once; uncertain submissions stop for inspection."""
    from identity_demo_setup import kube, owned, private_file, target, write

    receipt, profile, contexts = inputs(args)
    return publish_contexts(args, receipt, profile, contexts)


def console_publication(args: argparse.Namespace) -> dict:
    """Reuse the same guarded binary-build path for the thin console image."""
    from identity_demo_setup import private_file
    path = private_file(args.runtime_build_receipt)
    if digest(path) != args.runtime_build_sha256:
        raise ValueError('Exact completed console build receipt hash required')
    receipt = read_json(path)
    profile = DeploymentProfile.from_dict(read_json(private_file(args.installation_profile)))
    if receipt.get('built') is not True or receipt.get('credentials_included') is not False:
        raise ValueError('Verified credential-free console build required')
    lock = read_json(Path(__file__).resolve().parents[2]/'infra/identity-demo/console-runtime.lock.json')
    if receipt.get('inputs') != lock:
        raise ValueError('Exact pinned console runtime build inputs required')
    directory = path.parent/'context'
    if (directory/'Containerfile').read_bytes() != (Path(__file__).resolve().parents[2]/'infra/identity-demo/console-runtime.Containerfile').read_bytes():
        raise ValueError('Exact reviewed console Containerfile required')
    hashes = receipt['context_sha256']
    actual = {str(p.relative_to(directory)) for p in directory.rglob('*') if p.is_file()}
    if actual != set(hashes) or len(actual) > 1000:
        raise ValueError('Exact recorded console build context required')
    for name, expected in hashes.items():
        item = directory/name
        if not item.resolve().is_relative_to(directory) or item.is_symlink() or digest(item) != expected:
            raise ValueError('Console context changed after verification')
        parts = item.relative_to(directory).parts
        if parts[0] not in {'scripts', 'tests', 'workloads', 'infra', 'tools', 'requirements-lock.txt', 'Containerfile'}:
            raise ValueError('Unreviewed console build input')
    args.native_build_receipt = str(path)
    args.native_build_sha256 = args.runtime_build_sha256
    receipt = {**receipt, 'native_build_contract': profile.native_build_contract,
               'native_ca_bundle_sha256': None, 'publication_kind': 'console-runtime'}
    return publish_contexts(args, receipt, profile, {'runtime': {'path': str(directory), 'sha256': hashes}})


def publish_contexts(args, receipt, profile, contexts):
    from identity_demo_setup import kube, owned, private_file, target, write
    args.profile = profile
    target(args)
    owned(kube(args, "get", "namespace", profile.core_namespace, "-o", "json"), profile)
    network = read_json(private_file(args.publication_network))
    attempt = getattr(args, "publication_id", None)
    if attempt is not None and (not isinstance(attempt, str) or not re.fullmatch(r"[a-z][a-z0-9]{0,7}", attempt)):
        raise ValueError("Short canonical publication attempt ID required")
    suffix = "-" + attempt if attempt else ""
    family = 'console' if receipt.get('publication_kind') == 'console-runtime' else 'native'
    names = {role: "fixture-" + profile.installation_id + "-"+family+"-" + role + suffix for role in contexts}
    policy = network_policy(profile, network, [name + "-1" for name in names.values()])
    policy["metadata"]["name"] += suffix
    docker_strategy = {'dockerfilePath': 'Containerfile'}
    if receipt.get('publication_kind') == 'console-runtime':
        lock = read_json(Path(__file__).resolve().parents[2]/'infra/identity-demo/console-runtime.lock.json')
        if receipt.get('inputs') != lock:
            raise ValueError('Exact pinned console runtime build inputs required')
        docker_strategy['buildArgs'] = [{'name': 'PYTHON_BASE', 'value': lock['python_base']},
            {'name': 'PYTHON_RPMS', 'value': ' '.join(lock['python_rpms'])},
            {'name': 'RPM_MANIFEST_SHA256', 'value': lock['rpm_manifest_sha256']}]
    objects = [policy]
    for role, name in names.items():
        meta = {"name": name, "namespace": profile.core_namespace, "labels": dict(profile.labels)}
        objects.extend([
            {"apiVersion": "image.openshift.io/v1", "kind": "ImageStream", "metadata": deepcopy(meta)},
            {"apiVersion": "build.openshift.io/v1", "kind": "BuildConfig", "metadata": deepcopy(meta), "spec": {
                "runPolicy": "Serial", "source": {"type": "Binary", "binary": {}, "contextDir": "."},
                "strategy": {"type": "Docker", "dockerStrategy": deepcopy(docker_strategy)},
                "output": {"to": {"kind": "ImageStreamTag", "name": name + ":candidate"}},
                "resources": {"requests": {"cpu": "100m", "memory": "256Mi"},
                              "limits": {"cpu": "1", "memory": "2Gi"}},
                "successfulBuildsHistoryLimit": 1, "failedBuildsHistoryLimit": 1, "triggers": []}}])
    # Refuse every collision before the first write, including prior submissions.
    for obj in objects:
        if kube(args, "get", obj["kind"], obj["metadata"]["name"], "-n", profile.core_namespace,
                "--ignore-not-found", "-o", "json"):
            raise ValueError("Publication collision; inspect previous receipts instead of retrying")
        kube(args, "create", "--dry-run=server", "-f", "-", "-o", "json", value=obj)
    plan = {"schema_version": 1, "installation_profile": profile.to_dict(), "contexts": contexts,
        "publication_kind": receipt.get('publication_kind', 'native'),
        "native_build_receipt": str(private_file(args.native_build_receipt)),
        "native_build_sha256": args.native_build_sha256, "native_build_contract": receipt["native_build_contract"],
        "native_ca_bundle_sha256": receipt["native_ca_bundle_sha256"], "objects": objects, "names": names,
        "publication_helper_sha256": digest(Path(__file__)), "publication_id": attempt}
    write(args.output_dir / "publication.plan.private.json", plan)
    if not args.apply:
        return {"publication_prepared": True, "applied": False, "cluster_changed": False,
                "submitted_builds": 0, "published": False}
    for index, obj in enumerate(objects):
        write(args.output_dir / f"object-{index}.pending.json", obj)
        created = kube(args, "create", "-f", "-", "-o", "json", value=obj)
        write(args.output_dir / f"object-{index}.created.json", created)
    for role, name in names.items():
        submit(args, profile, contexts[role], role, name)
    return {"publication_prepared": True, "applied": True, "submitted_builds": len(contexts),
            "published": False, "status_and_network_cleanup_required": True,
            "existing_resources_modified": False, "shared_foundation_modified": False}


def submit(args: argparse.Namespace, profile: DeploymentProfile, context: dict, role: str, name: str) -> None:
    """Upload once using the binary API's supported name output, then read its exact Build."""
    from identity_demo_setup import kube, owned, write

        # Never upload from an unverified directory after intervening preparation.
    for file, expected in context["sha256"].items():
        item = Path(context["path"]) / file
        if item.is_symlink() or digest(item) != expected:
            raise ValueError("Publication context changed before upload")
    write(args.output_dir / (role + ".submission.pending.json"), {"build_config": name, "expected_build": name + "-1"})
    print(json.dumps({"native_publication_stage": "submit-" + role}), flush=True)
    result = subprocess.run([args.oc, "--kubeconfig", args.kubeconfig, "--request-timeout=240s",
        "start-build", name, "-n", profile.core_namespace, "--from-dir", context["path"], "-o", "name"],
        capture_output=True, text=True, timeout=300)
    write(args.output_dir / (role + ".submission.response.private.json"), {
        "exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
    if result.returncode:
        raise RuntimeError("Build submission uncertain or failed; inspect exact build, never retry blindly")
    if result.stdout.strip() != "build.build.openshift.io/" + name + "-1":
        raise ValueError("Unexpected build response; stop for inspection")
    build = kube(args, "get", "build", name + "-1", "-n", profile.core_namespace, "-o", "json")
    owned(build, profile)
    write(args.output_dir / (role + ".submitted.json"), build)


def resume_publication(args: argparse.Namespace) -> dict:
    """Resume confirmed unsent uploads; uncertain network failures require investigation."""
    from identity_demo_setup import kube, owned, private_file, target, write, fingerprint

    path = private_file(args.publication_plan)
    if digest(path) != args.publication_plan_sha256:
        raise ValueError("Exact publication plan hash required")
    plan = read_json(path)
    profile = DeploymentProfile.from_dict(plan["installation_profile"])
    args.profile = profile
    target(args)
    current_by_name = {}
    for index, obj in enumerate(plan["objects"]):
        made = read_json(private_file(str(path.parent / f"object-{index}.created.json")))
        current = kube(args, "get", obj["kind"], obj["metadata"]["name"], "-n", profile.core_namespace, "-o", "json")
        owned(current, profile)
        if (current["metadata"]["uid"] != made["metadata"]["uid"]
                or current["kind"] != "ImageStream" and fingerprint(current) != fingerprint(made)):
            raise ValueError("Publication prerequisite replaced or changed")
        current_by_name[(obj["kind"], obj["metadata"]["name"])] = current
        write(args.output_dir / f"object-{index}.created.json", made)
    unsent = []
    for role, name in plan["names"].items():
        build = kube(args, "get", "build", name + "-1", "-n", profile.core_namespace, "--ignore-not-found", "-o", "json")
        prior = path.parent / (role + ".submitted.json")
        if build:
            if not prior.is_file():
                raise ValueError("Uncertain upload exists without a confirmed submission; investigate")
            recorded = read_json(private_file(str(prior)))
            owned(build, profile)
            if (build["metadata"]["uid"] != recorded["metadata"]["uid"] or build["spec"] != recorded["spec"]):
                raise ValueError("Previously submitted build replaced or changed")
            write(args.output_dir / prior.name, recorded)
            continue
        config = current_by_name[("BuildConfig", name)]
        if prior.exists() or config.get("status", {}).get("lastVersion", 0) != 0:
            raise ValueError("Previous build missing; never recreate a prior submission")
        if (path.parent / (role + ".submission.pending.json")).exists():
            response = read_json(private_file(str(path.parent / (role + ".submission.response.private.json"))))
            # This exact CLI parser failure occurs before a binary API request.
            if (response.get("exit_code") != 1 or response.get("stdout")
                    or response.get("stderr") != "error: Unsupported output format: json\nSee 'oc start-build -h' for help and examples\n"):
                raise ValueError("Uncertain prior transport outcome; no automatic upload retry")
        unsent.append((role, name))
    updated = {**plan, "resumed_from_plan_sha256": digest(path), "publication_helper_sha256": digest(Path(__file__))}
    write(args.output_dir / "publication.plan.private.json", updated)
    if args.apply:
        for role, name in unsent:
            submit(args, profile, plan["contexts"][role], role, name)
    return {"applied": args.apply, "confirmed_unsent_builds": len(unsent),
            "newly_submitted_builds": len(unsent) if args.apply else 0,
            "published": False, "existing_resources_modified": False,
            "shared_foundation_modified": False}


def publication_status(args: argparse.Namespace) -> dict:
    """Read exact submitted builds, record immutable image digests and retire build egress."""
    from identity_demo_setup import kube, owned, private_file, target, write, fingerprint

    path = private_file(args.publication_plan)
    if digest(path) != args.publication_plan_sha256:
        raise ValueError("Exact publication plan hash required")
    plan = read_json(path)
    profile = DeploymentProfile.from_dict(plan["installation_profile"])
    args.profile = profile
    target(args)
    policy_current = None
    for index, obj in enumerate(plan["objects"]):
        made = read_json(private_file(str(path.parent / f"object-{index}.created.json")))
        current = kube(args, "get", obj["kind"], obj["metadata"]["name"], "-n", profile.core_namespace, "-o", "json")
        owned(current, profile)
        if (current["metadata"]["uid"] != made["metadata"]["uid"]
                or current["kind"] != "ImageStream" and fingerprint(current) != fingerprint(made)):
            raise ValueError("Publication object replaced or changed")
        if obj["kind"] == "NetworkPolicy":
            policy_current = current
    builds, images = {}, {}
    for role, name in plan["names"].items():
        config_index = next(i for i, o in enumerate(plan["objects"])
                            if o["kind"] == "BuildConfig" and o["metadata"]["name"] == name)
        config = read_json(private_file(str(path.parent / f"object-{config_index}.created.json")))
        build = kube(args, "get", "build", name + "-1", "-n", profile.core_namespace, "-o", "json")
        owned(build, profile)
        submitted = read_json(private_file(str(path.parent / (role + ".submitted.json"))))
        if (build["metadata"]["uid"] != submitted["metadata"]["uid"]
                or build["spec"] != submitted["spec"]):
            raise ValueError("Submitted build replaced or changed")
        owners = build["metadata"].get("ownerReferences", [])
        if not any(o.get("kind") == "BuildConfig" and o.get("name") == name
                   and o.get("uid") == config["metadata"]["uid"] for o in owners):
            raise ValueError("Build does not belong to recorded configuration")
        write(args.output_dir / (role + ".observed.private.json"), build)
        status = build.get("status", {})
        builds[role] = status.get("phase", "Unknown")
        if builds[role] == "Complete":
            image_digest = status.get("output", {}).get("to", {}).get("imageDigest", "")
            repository = status.get("outputDockerImageReference", "").rsplit(":", 1)[0]
            if (not re.fullmatch(r"sha256:[a-f0-9]{64}", image_digest)
                    or not repository.endswith("/" + profile.core_namespace + "/" + name)):
                raise ValueError("Exact published image digest/repository required")
            image_role = 'console_runtime' if plan.get('publication_kind') == 'console-runtime' else 'openshell_'+role
            images[image_role] = repository + "@" + image_digest
    complete = len(images) == len(plan['names'])
    terminal = all(phase in ("Complete", "Failed", "Error", "Cancelled") for phase in builds.values())
    artifact_lock = None
    if complete and getattr(args, "artifacts_file", None) and plan.get('publication_kind', 'native') == 'native':
        from deployment_artifacts import validate_artifacts
        base_path = private_file(args.artifacts_file)
        base = validate_artifacts(read_json(base_path))
        artifact_lock = {"schema_version": 1, "images": {**base["images"], **images},
            "native_build_contract": plan["native_build_contract"],
            "native_ca_bundle_sha256": plan["native_ca_bundle_sha256"],
            "base_artifacts_sha256": digest(base_path), "native_build_receipt_sha256": plan["native_build_sha256"],
            "native_publication_plan_sha256": digest(path)}
        validate_artifacts(artifact_lock)
    network_removed = False
    if terminal and args.apply:
        current = policy_current
        uri = ("/apis/networking.k8s.io/v1/namespaces/" + profile.core_namespace
               + "/networkpolicies/" + current["metadata"]["name"])
        kube(args, "delete", "--raw", uri, "-f", "-", value={"apiVersion": "v1", "kind": "DeleteOptions",
            "preconditions": {"uid": current["metadata"]["uid"], "resourceVersion": current["metadata"]["resourceVersion"]}})
        network_removed = True
    result = {"build_phases": builds, "published": complete, "images": images,
              "native_build_contract": plan["native_build_contract"],
              "native_ca_bundle_sha256": plan["native_ca_bundle_sha256"],
              "temporary_network_removed": network_removed, "live_acceptance_proven": False,
              "sbom_and_scans_approved": False, "shared_foundation_modified": False,
              "artifact_lock_written": artifact_lock is not None}
    write(args.output_dir / "publication.receipt.json", result)
    if artifact_lock:
        artifact_lock["native_publication_receipt_sha256"] = digest(args.output_dir / "publication.receipt.json")
        write(args.output_dir / "artifacts.private.json", artifact_lock)
    return result
