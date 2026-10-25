# SPDX-License-Identifier: Apache-2.0
"""Public administrator handoff rendered from the existing reviewed helpers.

No arbitrary manifests, grants, Secret data or caller-selected cluster policies
are accepted. This stage only renders; administrators apply and retain exact UID
receipts separately before the scoped installer can verify these prerequisites.
"""

from copy import deepcopy

from cluster_console_resources import permissions, capacity
from cluster_console_public_trust import resources as public_trust
from deployment_artifacts import validate_artifacts
from deployment_profile import active_profile
from identity_demo_controller_identity import policy, gateway_policy
import identity_demo_setup as setup
from source_render import read_json


def objects(profile, bundle, artifacts):
    """Compose fixed generators rather than duplicate security-sensitive grants."""
    if (
        active_profile() != profile
        or bundle.get("installation_profile") != profile.to_dict()
        or artifacts.get("native_build_contract") != profile.native_build_contract
        or bundle.get("native_build_contract_matches") is not True
    ):
        raise ValueError("Matching reviewed installation and native artifacts required")
    application = setup.validate(bundle)
    artifacts = validate_artifacts(artifacts)
    from identity_demo_runtime_grants import desired
    from identity_demo_workspaces import render
    from gateway_credential_route import READ_NAME

    runtime_rules = setup.runtime_rules(profile, application)
    result = [
        deepcopy(o)
        for o in application
        if o["kind"] in {"ServiceAccount", "Role", "RoleBinding"}
        or (o["kind"] == "NetworkPolicy"
            and o["metadata"].get("namespace") in profile.application_namespaces[1:])
    ]
    result += setup.installer_routing_grants(
        profile,
        application,
        {
            "kind": "ServiceAccount",
            "namespace": profile.core_namespace,
            "name": "fixture-installer",
        },
    )
    result += [
        *desired(),
        *[
            o
            for o in render(runtime_rules)
            if o["kind"] in {"ClusterRole", "ClusterRoleBinding"}
        ],
    ]
    result += setup.runtime_image_grants(profile, application)
    result += permissions(profile, READ_NAME + "-catalog")
    quotas, _ = capacity(profile)
    result += quotas
    result += [
        policy(profile, role, artifacts["images"]["openshell_supervisor"])
        for role in ("triage", "reader")
    ]
    result.append(gateway_policy(profile, artifacts["images"]["openshell_gateway"]))
    result.append(setup.discovery_policy(profile))
    # The first entry is the public CA Secret, already created by application
    # installation. Only the existing fixed admission/RBAC prerequisites belong
    # in this administrator handoff. Issuer/signing keys never appear here.
    result += [o for o in public_trust(profile, "") if o["kind"] != "Secret"]
    identities = [
        (o["kind"], o["metadata"].get("namespace"), o["metadata"]["name"])
        for o in result
    ]
    if len(identities) != len(set(identities)) or any(
        o["kind"] == "Secret" for o in result
    ):
        raise ValueError("Unique public prerequisite identities required")
    return result


def run(args):
    """Produce a public review artifact; never confer authority or adopt state."""
    if args.apply:
        raise ValueError(
            "Administrator handoff is review-only; no automatic privilege escalation"
        )
    bundle_path = setup.private_file(args.bundle)
    if setup.sha(bundle_path) != args.bundle_sha256:
        raise ValueError("Exact reviewed application bundle hash required")
    bundle = read_json(bundle_path)
    profile = active_profile()
    artifacts = read_json(setup.private_file(args.artifacts_file))
    proposed = objects(profile, bundle, artifacts)
    if getattr(args, "installer_configuration", None):
        from cluster_installer_application import authority
        from cluster_installer_session import configuration

        value = configuration(
            read_json(setup.private_file(args.installer_configuration))
        )
        publication = read_json(setup.private_file(args.runtime_publication_receipt))
        if (
            publication.get("packaged_checks_passed") is not True
            or value["profile"] != profile.to_dict()
            or publication.get("published") is not True
            or publication.get("build_phases") != {"runtime": "Complete"}
            or not publication.get("images", {})
            .get("console_runtime", "")
            .startswith(
                "image-registry.openshift-image-registry.svc:5000/"
                + profile.core_namespace
                + "/"
            )
        ):
            raise ValueError(
                "Exact verified worker publication required before application authority"
            )
        proposed += authority(
            profile,
            setup.validate(bundle),
            proposed,
            artifacts,
            publication["images"]["console_runtime"],
            value,
            ingress_address=getattr(args, "installer_ingress_address", None),
        )
    setup.write(
        args.output_dir / "administrator-prerequisites.json",
        {"apiVersion": "v1", "kind": "List", "items": proposed},
    )
    return {
        "administrator_handoff_rendered": True,
        "objects": len(proposed),
        "cluster_changed": False,
        "credentials_included": False,
        "administrator_receipts_required": True,
        "installation_accepted": False,
    }
