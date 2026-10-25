# SPDX-License-Identifier: Apache-2.0
"""Build the existing thin worker image through standard owned OpenShift Builds."""

from types import SimpleNamespace
import re

from console_runtime_build import prepare_context
from deployment_profile import DeploymentProfile
from identity_demo_cluster_build import (
    OwnedOperations,
    docker_objects,
    submit_build,
    exact,
)
from source_render import read_json
import identity_demo_setup as setup


def retire_build_network(args, operations, name, record):
    """Remove only recorded temporary egress after this exact build is terminal."""
    proof = args.output_dir / (name + ".build.private.json")
    if not proof.exists():
        return False  # Submission may be uncertain; retain evidence and the policy.
    build = read_json(proof)
    if build["object"]["metadata"]["name"] != name + "-1":
        raise ValueError("Exact maintenance build receipt required")
    current = exact(args, operations.profile, build)
    if current.get("status", {}).get("phase") not in (
        "Complete",
        "Failed",
        "Error",
        "Cancelled",
    ):
        return False
    deleted = operations.delete(record)
    setup.write(
        args.output_dir / "build-network-cleanup.receipt.json",
        {
            "build_uid": build["uid"],
            "phase": current["status"]["phase"],
            "policy_uid": record["uid"],
            "deleted": deleted,
        },
    )
    return deleted


def run(args):
    profile = DeploymentProfile.from_dict(
        read_json(setup.private_file(args.installation_profile))
    )
    args.profile = profile
    setup.target(args)
    # These fixed image-build inputs are unavailable in ordinary local mode.
    # Archive-based preparation remains compatible with the existing helper.
    args.packaged_installer_tools = not (args.oc_archive or args.cli_archive)
    if bool(args.oc_archive) != bool(args.cli_archive):
        raise ValueError(
            "Both public CLI archives or the packaged installer tools are required"
        )
    lock, cli_lock, plan, context = prepare_context(args)
    attempt = getattr(args, "publication_id", None)
    if attempt is not None and (
        not isinstance(attempt, str) or not re.fullmatch(r"[a-z][a-z0-9]{0,7}", attempt)
    ):
        raise ValueError("Short canonical publication attempt ID required")
    name = "fixture-console-runtime" + ("-" + attempt if attempt else "")
    proposed = docker_objects(profile, name)
    proposed[-1]["spec"]["strategy"]["dockerStrategy"]["buildArgs"] = [
        {"name": "PYTHON_BASE", "value": lock["python_base"]},
        {"name": "PYTHON_RPMS", "value": " ".join(lock["python_rpms"])},
        {"name": "RPM_MANIFEST_SHA256", "value": lock["rpm_manifest_sha256"]},
    ]
    network = getattr(args, "publication_network", None)
    if network:
        from native_publication import network_policy

        policy = network_policy(
            profile, read_json(setup.private_file(network)), [name + "-1"]
        )
        policy["metadata"]["name"] = name + "-egress"
        policy["metadata"]["labels"]["identity-demo-installation"] = (
            profile.installation_id
        )
        proposed.insert(0, policy)
    setup.write(
        args.output_dir / "cluster-runtime-build.plan.private.json",
        {
            "objects": proposed,
            "source_digest": plan["source_digest"],
            "credentials_included": False,
        },
    )
    if not args.apply:
        return {
            "runtime_build_prepared": True,
            "cluster_changed": False,
            "published": False,
        }
    operations = OwnedOperations(args, profile, args.output_dir / "objects")
    for obj in proposed:
        operations.create(obj)
    try:
        image = submit_build(args, operations, name, context)
    finally:
        if network:
            retire_build_network(args, operations, name, operations.records[0])
    # Exercise delivered bytes in a separate credential-free Job.
    from cluster_runtime_delivery import run as probe

    out = args.output_dir / "packaged-check"
    out.mkdir(mode=0o700)
    checks = SimpleNamespace(**vars(args))
    checks.output_dir = out
    code = """import json, subprocess
from console_runtime_build import verify_versions
import identity_demo_driver, identity_demo_console_worker, identity_demo_console_preparer
versions = verify_versions(
    subprocess.check_output(['oc','version','--client=true','-o','json'], text=True),
    subprocess.check_output(['openshell','--version'], text=True), OC_VERSION, CLI_VERSION)
print(json.dumps({'runtime_imports': True, 'packaged_tool_versions': versions}), flush=True)
""".replace("OC_VERSION", repr(lock["oc_version"])).replace(
        "CLI_VERSION", repr(cli_lock["version"])
    )
    result = probe(checks, {"console_runtime": image}, {"console_runtime": code})
    setup.write(out / "setup.summary.json", result)
    if result.get("runtime_interface_checks_passed") is not True:
        raise ValueError("Published runtime failed its packaged-binary/import checks")
    receipt = {
        **plan,
        "published": True,
        "build_phases": {"runtime": "Complete"},
        "images": {"console_runtime": image},
        "packaged_checks_passed": True,
        "functional_scenarios_proven": False,
        "security_and_distribution_approved": False,
    }
    setup.write(args.output_dir / "publication.receipt.json", receipt)
    return {
        "published": True,
        "runtime_image": image,
        "packaged_checks_passed": True,
        "functional_scenarios_proven": False,
    }
