# SPDX-License-Identifier: Apache-2.0
"""Normalize original administrator receipts without transferring an API token.

Runs tokenless in the reviewed installer image. Namespace identities and every
created prerequisite must match original responses and current observations.
"""

from copy import deepcopy
import base64
from pathlib import Path

from deployment_profile import DeploymentProfile
from source_render import read_json
import identity_demo_setup as setup


def key(obj):
    return obj["kind"], obj["metadata"].get("namespace"), obj["metadata"]["name"]


def index(items):
    result = {}
    for obj in items:
        identity = key(obj)
        if identity in result:
            raise ValueError("Duplicate administrator resource identity")
        result[identity] = obj
    return result


def projection(obj, desired, owners):
    """Accept only verified controller registry references and benign API defaults."""
    value = deepcopy(obj)
    if value["kind"] == "ServiceAccount":
        for field in ("secrets", "imagePullSecrets"):
            if field in desired or field not in value:
                continue
            for reference in value[field]:
                if set(reference) != {"name"}:
                    raise ValueError("Exact generated registry reference required")
                name = reference["name"]
                meta = value["metadata"]
                secret = owners.get(("Secret", meta.get("namespace"), name), {})
                refs = secret.get("metadata", {}).get("ownerReferences", [])
                if (
                    not name.startswith(meta["name"] + "-dockercfg-")
                    or secret.get("type") != "kubernetes.io/dockercfg"
                    or len(refs) != 1
                    or refs[0].get("kind") != "ServiceAccount"
                    or refs[0].get("name") != meta["name"]
                    or refs[0].get("uid") != meta["uid"]
                ):
                    raise ValueError("Generated registry credential owner mismatch")
            value.pop(field, None)
    if value["kind"] == "ValidatingAdmissionPolicy":
        constraints = value.get("spec", {}).get("matchConstraints", {})
        expected = desired.get("spec", {}).get("matchConstraints", {})
        if (
            "matchPolicy" not in expected
            and constraints.get("matchPolicy") == "Equivalent"
        ):
            constraints.pop("matchPolicy")
        for field in ("namespaceSelector", "objectSelector"):
            if field not in expected and constraints.get(field) == {}:
                constraints.pop(field)
        for actual, declared in zip(
            constraints.get("resourceRules", []), expected.get("resourceRules", [])
        ):
            if "scope" not in declared and actual.get("scope") == "*":
                actual.pop("scope")
    if value["kind"] == "ValidatingAdmissionPolicyBinding":
        if "matchResources" not in desired.get("spec", {}) and value.get(
            "spec", {}
        ).get("matchResources") == {"matchPolicy": "Equivalent"}:
            value["spec"].pop("matchResources")
    return value


def normalize(profile, planned, evidence, namespaces, *, plan_sha256):
    from cluster_installer_resources import namespace_objects

    if (
        set(evidence) != {"created", "current", "registry_owners"}
        or namespaces.get("kind") != "List"
    ):
        raise ValueError("Original and current public administrator evidence required")
    owners = index(evidence["registry_owners"])
    for secret in owners.values():
        if (
            secret.get("kind") != "Secret"
            or set(secret) - {"apiVersion", "kind", "metadata", "type"}
            or secret.get("type") != "kubernetes.io/dockercfg"
        ):
            raise ValueError("Registry ownership metadata only; no Secret values")
    originals = index([*evidence["created"], *namespaces["items"]])
    current = index(evidence["current"])
    desired = index([*namespace_objects(profile), *planned["items"]])
    allowed = {
        "Namespace",
        "ServiceAccount",
        "Role",
        "RoleBinding",
        "ClusterRole",
        "ClusterRoleBinding",
        "Lease",
        "LimitRange",
        "ResourceQuota",
        "NetworkPolicy",
        "ClusterSPIFFEID",
        "ValidatingAdmissionPolicy",
        "ValidatingAdmissionPolicyBinding",
    }
    if set(originals) != set(desired) or set(current) != set(desired):
        raise ValueError(
            "Exact complete original/current prerequisite inventory required"
        )
    created = []
    for identity, obj in desired.items():
        if obj["kind"] not in allowed:
            raise ValueError("Only public administrator prerequisites may be retained")
        original, live = originals[identity], current[identity]
        setup.owned(original, profile)
        setup.owned(live, profile)
        if (
            not original["metadata"].get("uid")
            or live["metadata"].get("uid") != original["metadata"]["uid"]
            or live["metadata"].get("deletionTimestamp")
        ):
            raise ValueError("Administrator resource was replaced or is terminating")
        declared = setup.fingerprint(obj)
        if (
            setup.fingerprint(projection(original, obj, owners)) != declared
            or setup.fingerprint(projection(live, obj, owners)) != declared
        ):
            raise ValueError(
                "Administrator resource configuration differs from reviewed plan"
            )
        created.append(
            {
                "object": live,
                "uid": live["metadata"]["uid"],
                "fingerprint": setup.fingerprint(live),
                "declared_fingerprint": declared,
            }
        )
    import time

    return {
        "verified_at": int(time.time()),
        "schema_version": 1,
        "installation_profile": profile.to_dict(),
        "expected_server": profile.expected_server,
        "plan_sha256": plan_sha256,
        "created": created,
    }


def run(args):
    """Fixed public mounts; print only a credential-free normalized receipt."""
    from identity_demo_cluster_bootstrap import mounted
    from cluster_installer_session import configuration

    if args.apply:
        raise ValueError("Receipt normalization cannot perform cluster writes")
    data = {}
    for name in ("configuration", "plan", "evidence", "namespaces"):
        path = args.output_dir / (name + ".received.json")
        with path.open("xb") as stream:
            import os

            os.chmod(path, 0o600)
            stream.write(mounted(Path("/receipts"), name + ".json", maximum=2_000_000))
        data[name] = read_json(path)
    value = configuration(data["configuration"])
    digest = setup.sha(args.output_dir / "plan.received.json")
    if digest != args.administrator_plan_sha256:
        raise ValueError("Original administrator plan hash required")
    result = normalize(
        DeploymentProfile.from_dict(value["profile"]),
        data["plan"],
        data["evidence"],
        data["namespaces"],
        plan_sha256=digest,
    )
    path = args.output_dir / "administrator.receipt.json"
    setup.write(path, result)
    print("ADMIN_RECEIPT=" + base64.b64encode(path.read_bytes()).decode(), flush=True)
    return {
        "administrator_receipt_verified": True,
        "objects": len(result["created"]),
        "cluster_changed": False,
        "credentials_transferred": False,
    }
