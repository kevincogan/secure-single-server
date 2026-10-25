# SPDX-License-Identifier: Apache-2.0
"""Shared administrator evidence does not silently expand installer RBAC."""

from copy import deepcopy
import json
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

import identity_demo_setup as setup
from cluster_console_install import prerequisite_observation
from cluster_console_resources import permissions
from cluster_installer_application import authority
from checks.test_installer_prerequisites import source
from checks.test_cluster_installer_session import config
from deployment_profile import LEGACY


def shared_role():
    return next(
        o
        for o in permissions(LEGACY, "fixture-step4-read-route-catalog")
        if o["kind"] == "Role"
        and o["metadata"].get("namespace") == LEGACY.identity_namespace
    )


def original(args, tmp_path, desired, *, age=0):
    live = deepcopy(desired)
    live["metadata"]["uid"] = str(uuid4())
    receipt = {
        "schema_version": 1,
        "installation_profile": LEGACY.to_dict(),
        "expected_server": LEGACY.expected_server,
        "verified_at": int(time.time()) - age,
        "created": [
            {
                "object": live,
                "uid": live["metadata"]["uid"],
                "fingerprint": setup.fingerprint(live),
                "declared_fingerprint": setup.fingerprint(desired),
            }
        ],
    }
    path = tmp_path / "administrator.json"
    setup.write(path, receipt)
    args.administrator_receipt = str(path)
    args.administrator_receipt_sha256 = setup.sha(path)
    return live


@pytest.mark.parametrize(
    "fault", [None, "expired", "future", "changed-rules", "different-identity"]
)
def test_scoped_installer_uses_only_recent_exact_administrator_observation(
    tmp_path, monkeypatch, fault
):
    obj = shared_role()
    args = SimpleNamespace(
        profile=LEGACY,
        installer_service_account=LEGACY.core_namespace + ":fixture-installer",
    )
    live = original(
        args,
        tmp_path,
        obj,
        age=7300 if fault == "expired" else -120 if fault == "future" else 0,
    )
    monkeypatch.setattr(
        setup,
        "kube",
        lambda *a, **k: pytest.fail("No shared RBAC API access is granted"),
    )
    if fault == "changed-rules":
        obj["rules"][0]["verbs"].append("create")
    elif fault == "different-identity":
        obj["metadata"]["name"] = "foreign-role"
    if fault:
        with pytest.raises(ValueError):
            prerequisite_observation(args, LEGACY, obj)
    else:
        assert prerequisite_observation(args, LEGACY, obj) == live


def test_legacy_administrator_still_observes_live_configuration(monkeypatch):
    obj = shared_role()
    called = []
    monkeypatch.setattr(
        setup, "kube", lambda *a, **k: called.append(a) or {"live": True}
    )
    assert prerequisite_observation(SimpleNamespace(), LEGACY, obj) == {"live": True}
    assert called and "get" in called[0]


def test_installer_shared_spire_role_has_exact_approved_public_read():
    bundle, artifacts = source()
    obj = shared_role()
    resources = authority(
        LEGACY,
        bundle["objects"],
        [obj],
        artifacts,
        "registry.example/worker@sha256:" + "a" * 64,
        config(),
    )
    role = next(
        o
        for o in resources
        if o["kind"] == "Role"
        and o["metadata"].get("namespace") == LEGACY.identity_namespace
    )
    assert role["rules"] == [
        {
            "apiGroups": [""],
            "resources": ["configmaps"],
            "resourceNames": ["spire-bundle"],
            "verbs": ["get"],
        }
    ]


def test_prerequisite_handoff_accepts_actual_runtime_publication_format(tmp_path):
    from cluster_installer_prerequisites import run

    bundle, artifacts = source()
    value = config()
    value["artifacts"] = artifacts
    inputs = {}
    for name, data in [
        ("bundle", bundle),
        ("artifacts", artifacts),
        ("configuration", value),
        (
            "publication",
            {
                "published": True,
                "packaged_checks_passed": True,
                "build_phases": {"runtime": "Complete"},
                "images": {
                    "console_runtime": "image-registry.openshift-image-registry.svc:5000/"
                    + LEGACY.core_namespace
                    + "/fixture-console-runtime@sha256:"
                    + "b" * 64
                },
            },
        ),
    ]:
        path = tmp_path / (name + ".json")
        setup.write(path, data)
        inputs[name] = path
    out = tmp_path / "out"
    out.mkdir()
    args = SimpleNamespace(
        apply=False,
        bundle=str(inputs["bundle"]),
        bundle_sha256=setup.sha(inputs["bundle"]),
        artifacts_file=str(inputs["artifacts"]),
        installer_configuration=str(inputs["configuration"]),
        runtime_publication_receipt=str(inputs["publication"]),
        installer_ingress_address="192.0.2.2",
        output_dir=out,
    )
    assert run(args)["administrator_handoff_rendered"]
    proposed = json.loads((out / "administrator-prerequisites.json").read_text())[
        "items"
    ]
    assert any(
        o["kind"] == "ServiceAccount" and o["metadata"]["name"] == "fixture-installer"
        for o in proposed
    )
