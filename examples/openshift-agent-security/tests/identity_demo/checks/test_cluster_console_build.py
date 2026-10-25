# SPDX-License-Identifier: Apache-2.0
"""Publication needs completed build and real packaged-image checks, not a tag."""

import json
from types import SimpleNamespace

import pytest

import cluster_console_build as tool
import cluster_runtime_delivery as delivery
from deployment_profile import LEGACY


def prepared(tmp_path, monkeypatch, *, apply=True):
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps(LEGACY.to_dict()))
    profile.chmod(0o600)
    out = tmp_path / "output"
    out.mkdir()
    context = tmp_path / "context"
    context.mkdir()
    lock = {
        "python_base": "registry.example/base@sha256:" + "a" * 64,
        "python_rpms": ["python3.12-reviewed"],
        "rpm_manifest_sha256": "b" * 64,
        "oc_version": "4.21.36",
    }
    monkeypatch.setattr(tool.setup, "target", lambda args: None)
    monkeypatch.setattr(
        tool,
        "prepare_context",
        lambda args: (lock, {"version": "0.1.3"}, {"source_digest": "c" * 64}, context),
    )
    args = SimpleNamespace(
        installation_profile=str(profile),
        output_dir=out,
        apply=apply,
        oc_archive="reviewed-archive",
        cli_archive="reviewed-cli-archive",
    )
    return args


def test_runtime_plan_does_not_build_or_publish(tmp_path, monkeypatch):
    args = prepared(tmp_path, monkeypatch, apply=False)
    monkeypatch.setattr(
        tool, "OwnedOperations", lambda *args: pytest.fail("plan mutated cluster")
    )
    result = tool.run(args)
    assert result["published"] is False and result["cluster_changed"] is False
    plan = json.loads(
        (args.output_dir / "cluster-runtime-build.plan.private.json").read_text()
    )
    config = plan["objects"][-1]
    assert config["spec"]["strategy"]["type"] == "Docker"
    assert config["spec"]["serviceAccount"] == "builder"
    assert not config["spec"]["triggers"]


@pytest.mark.parametrize("packaged_passed", [False, True])
def test_completed_build_cannot_pass_without_packaged_checks(
    tmp_path, monkeypatch, packaged_passed
):
    args = prepared(tmp_path, monkeypatch)
    created = []

    class Operations:
        def __init__(self, *unused):
            pass

        def create(self, obj):
            created.append(obj)

    image = "registry.example/runtime@sha256:" + "d" * 64
    monkeypatch.setattr(tool, "OwnedOperations", Operations)
    monkeypatch.setattr(tool, "submit_build", lambda *unused: image)

    def probe(options, images, programs):
        assert images == {"console_runtime": image}
        assert "'4.21.36'" in programs["console_runtime"]
        assert "verify_versions(" in programs["console_runtime"]
        return {"runtime_interface_checks_passed": packaged_passed}

    monkeypatch.setattr(delivery, "run", probe)
    if not packaged_passed:
        with pytest.raises(ValueError, match="packaged-binary/import"):
            tool.run(args)
        assert not (args.output_dir / "publication.receipt.json").exists()
    else:
        assert tool.run(args)["packaged_checks_passed"]
        receipt = json.loads((args.output_dir / "publication.receipt.json").read_text())
        assert receipt["images"] == {"console_runtime": image}
        assert receipt["published"] and receipt["build_phases"] == {
            "runtime": "Complete"
        }
        assert receipt["functional_scenarios_proven"] is False
        assert receipt["security_and_distribution_approved"] is False
    assert [o["kind"] for o in created] == ["ImageStream", "BuildConfig"]


def test_runtime_probe_requests_deny_policy_and_mounts_no_credentials():
    image = "registry.example/runtime@sha256:" + "d" * 64
    policy, job = delivery.probe_objects(
        LEGACY, {"console_runtime": image}, {"console_runtime": "pass"}, "synthetic"
    )
    assert policy["spec"]["egress"] == []
    pod = job["spec"]["template"]["spec"]
    assert not pod["automountServiceAccountToken"]
    assert pod["containers"][0]["command"][0] == "python3.12"
    assert pod["containers"][0]["securityContext"]["readOnlyRootFilesystem"]
    assert all(
        "secret" not in volume and "projected" not in volume
        for volume in pod["volumes"]
    )


@pytest.mark.parametrize("attempt", ["r2", "../foreign", "UPPER", False])
def test_maintenance_publication_is_distinct_without_overwriting_prior_builds(
    tmp_path, monkeypatch, attempt
):
    args = prepared(tmp_path, monkeypatch, apply=False)
    args.publication_id = attempt
    if attempt != "r2":
        with pytest.raises(ValueError, match="attempt ID"):
            tool.run(args)
        return
    assert tool.run(args)["published"] is False
    plan = json.loads(
        (args.output_dir / "cluster-runtime-build.plan.private.json").read_text()
    )
    assert {v["metadata"]["name"] for v in plan["objects"]} == {
        "fixture-console-runtime-r2"
    }


def test_maintenance_network_is_exact_bounded_and_plan_only(tmp_path, monkeypatch):
    args = prepared(tmp_path, monkeypatch, apply=False)
    args.publication_id = "r5"
    network = tmp_path / "network.json"
    network.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "api_cidrs": ["192.0.2.1/32"],
                "https_cidrs": ["198.51.100.1/32"],
            }
        )
    )
    network.chmod(0o600)
    args.publication_network = str(network)
    tool.run(args)
    objects = json.loads(
        (args.output_dir / "cluster-runtime-build.plan.private.json").read_text()
    )["objects"]
    policy = objects[0]
    assert policy["kind"] == "NetworkPolicy"
    assert policy["spec"]["podSelector"] == {
        "matchExpressions": [
            {
                "key": "openshift.io/build.name",
                "operator": "In",
                "values": ["fixture-console-runtime-r5-1"],
            }
        ]
    }
    assert policy["metadata"]["name"] == "fixture-console-runtime-r5-egress"
    assert policy["spec"]["egress"][-1]["to"] == [
        {"ipBlock": {"cidr": "198.51.100.1/32"}}
    ]
    network.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "api_cidrs": ["192.0.2.1/32"],
                "https_cidrs": ["0.0.0.0/0"],
            }
        )
    )
    with pytest.raises(ValueError, match="bounded"):
        tool.run(args)


@pytest.mark.parametrize(
    "phase", [None, "Running", "Complete", "Failed", "Error", "Cancelled"]
)
def test_build_network_cleanup_requires_recorded_terminal_identity(
    tmp_path, monkeypatch, phase
):
    args = SimpleNamespace(output_dir=tmp_path)
    record = {"uid": "policy-uid"}
    deletes = []
    operations = SimpleNamespace(
        profile=LEGACY, delete=lambda value: deletes.append(value) or True
    )
    name = "fixture-console-runtime-r5"
    monkeypatch.setattr(tool, "exact", lambda *unused: {"status": {"phase": phase}})
    if phase is not None:
        (tmp_path / (name + ".build.private.json")).write_text(
            json.dumps(
                {"uid": "build-uid", "object": {"metadata": {"name": name + "-1"}}}
            )
        )
    terminal = phase in {"Complete", "Failed", "Error", "Cancelled"}
    assert tool.retire_build_network(args, operations, name, record) is terminal
    assert deletes == ([record] if terminal else [])
    assert (tmp_path / "build-network-cleanup.receipt.json").exists() is terminal


def test_replaced_build_never_authorizes_policy_cleanup(tmp_path, monkeypatch):
    args = SimpleNamespace(output_dir=tmp_path)
    name = "fixture-console-runtime-r5"
    (tmp_path / (name + ".build.private.json")).write_text(
        json.dumps({"uid": "original", "object": {"metadata": {"name": name + "-1"}}})
    )

    def replaced(*unused):
        raise ValueError("Recorded build identity replaced")

    monkeypatch.setattr(tool, "exact", replaced)
    operations = SimpleNamespace(
        profile=LEGACY, delete=lambda value: pytest.fail("replacement deleted policy")
    )
    with pytest.raises(ValueError, match="replaced"):
        tool.retire_build_network(args, operations, name, {"uid": "policy"})
