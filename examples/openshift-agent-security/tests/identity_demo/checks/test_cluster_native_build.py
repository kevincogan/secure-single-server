# SPDX-License-Identifier: Apache-2.0
"""Build transport rejects adoption/drift and compiles without credentials or egress."""

from copy import deepcopy
from types import SimpleNamespace
from uuid import uuid4
import pytest
from deployment_profile import active_profile
from identity_demo_cluster_build import OwnedOperations, object_for, compile_objects
import identity_demo_setup as setup


def transport(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    objects = {}
    calls = []

    def kube(args, *words, value=None):
        calls.append((words, value))
        if words[0] == "get":
            return deepcopy(objects.get((words[1], words[2])))
        if words[0] == "create":
            made = deepcopy(value)
            made["metadata"].update(uid=str(uuid4()), resourceVersion="1")
            if "--dry-run=server" not in words:
                objects[(made["kind"], made["metadata"]["name"])] = made
            return made
        if words[0] == "delete":
            return {"status": "Success"}
        raise AssertionError(words)

    monkeypatch.setattr(setup, "kube", kube)
    return (
        OwnedOperations(SimpleNamespace(), active_profile(), tmp_path / "operations"),
        objects,
        calls,
    )


def test_create_only_records_uid_and_refuses_existing_resources(tmp_path, monkeypatch):
    op, objects, calls = transport(tmp_path, monkeypatch)
    obj = object_for(active_profile(), "ServiceAccount", "fixture-build")
    created = op.create(obj)
    assert op.records[0]["uid"] == created["metadata"]["uid"]
    assert (op.directory / "creation-ledger.private.json").is_file()
    with pytest.raises(ValueError, match="collision"):
        op.create(obj)


def test_foreign_namespace_labels_or_cluster_scope_are_refused(tmp_path, monkeypatch):
    op, objects, calls = transport(tmp_path, monkeypatch)
    base = object_for(active_profile(), "ServiceAccount", "fixture-build")
    bad = deepcopy(base)
    bad["metadata"]["namespace"] = "someone-else"
    other = deepcopy(base)
    other["metadata"]["labels"]["identity-demo-installation"] = "other"
    for obj in (
        bad,
        other,
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {"name": "fixture-build"},
        },
    ):
        with pytest.raises(ValueError, match="scope"):
            op.create(obj)
    assert not calls


@pytest.mark.parametrize("kind", ["ServiceAccount", "Job"])
def test_delete_has_server_uid_preconditions_and_refuses_replacement(
    tmp_path, monkeypatch, kind
):
    op, objects, calls = transport(tmp_path, monkeypatch)
    obj = (compile_objects(active_profile(), "registry.example.test/compiler@sha256:" + "a" * 64, {"CARGO_BUILD_JOBS": "2"})[-1]
           if kind == "Job" else object_for(active_profile(), kind, "fixture-build"))
    op.create(obj)
    assert op.delete(op.records[0])
    words, body = calls[-1]
    assert words[0:2] == ("delete", "--raw")
    assert body["preconditions"] == {
        "uid": op.records[0]["uid"],
        "resourceVersion": "1",
    }
    assert body.get("propagationPolicy") == ("Foreground" if kind == "Job" else None)
    objects[(kind, obj["metadata"]["name"])]["metadata"]["uid"] = str(uuid4())
    with pytest.raises(ValueError, match="Replacement"):
        op.delete(op.records[0])


def test_offline_compilation_job_has_no_api_token_no_retry_and_bounded_resources():
    result = compile_objects(
        active_profile(),
        "registry.example.test/compiler@sha256:" + "a" * 64,
        {"CARGO_BUILD_JOBS": "2"},
    )
    policy, pvc, job = result
    assert policy["spec"]["egress"] == [] and policy["spec"]["policyTypes"] == [
        "Egress"
    ]
    assert job["spec"]["backoffLimit"] == 0
    spec = job["spec"]["template"]["spec"]
    assert (
        spec["automountServiceAccountToken"] is False
        and spec["restartPolicy"] == "Never"
    )
    assert spec["securityContext"]["runAsNonRoot"]
    for c in spec["initContainers"] + spec["containers"]:
        assert c["securityContext"]["allowPrivilegeEscalation"] is False
        assert c["securityContext"]["readOnlyRootFilesystem"] is True
        assert c["securityContext"]["capabilities"]["drop"] == ["ALL"]
        assert c["resources"]["requests"] and c["resources"]["limits"]
    assert pvc["spec"]["resources"]["requests"]["storage"] == "30Gi"


def test_compile_outputs_use_existing_recipe_writable_destination():
    job = compile_objects(
        active_profile(), "registry.example.test/compiler@sha256:" + "a" * 64, {}
    )[-1]
    spec = job["spec"]["template"]["spec"]
    assert {"name": "state", "mountPath": "/work/output", "subPath": "output"} in spec[
        "containers"
    ][0]["volumeMounts"]
    assert spec["serviceAccountName"] == "fixture-installer-build"


def test_installer_account_is_typed_and_cannot_select_another_namespace():
    p = active_profile()
    identity, subject = setup.installer_subject(
        SimpleNamespace(
            installer_service_account=p.core_namespace + ":fixture-installer"
        ),
        p,
    )
    assert (
        identity == "system:serviceaccount:" + p.core_namespace + ":fixture-installer"
    )
    assert subject == {
        "kind": "ServiceAccount",
        "name": "fixture-installer",
        "namespace": p.core_namespace,
    }
    for arguments in (
        SimpleNamespace(installer_service_account="foreign:fixture-installer"),
        SimpleNamespace(
            installer_service_account=p.core_namespace + ":fixture-installer",
            installer_user="operator",
        ),
        SimpleNamespace(installer_user=identity),
        SimpleNamespace(installer_user="admin"),
    ):
        with pytest.raises(ValueError):
            setup.installer_subject(arguments, p)


def test_packaged_runtime_checks_use_actual_image_without_api_access():
    from identity_demo_cluster_build import (
        packaged_probe,
        export_object,
        docker_objects,
    )

    image = "registry.example.test/compiler@sha256:" + "a" * 64
    p = active_profile()
    for role in ("gateway", "supervisor"):
        spec = packaged_probe(p, role, image)["spec"]["template"]["spec"]
        assert spec["automountServiceAccountToken"] is False
        assert spec["containers"][0]["image"] == image
        assert spec["initContainers"][0]["command"][-1] == "--version"
        assert spec["containers"][0]["command"][-1] == "--help"
    pod = export_object(p, image)["spec"]
    assert pod["automountServiceAccountToken"] is False
    assert pod["containers"][0]["volumeMounts"][0]["readOnly"]
    assert (
        docker_objects(p, "fixture-example")[1]["spec"]["serviceAccount"] == "builder"
    )


def test_cluster_recipe_requires_the_verified_prepared_source(tmp_path):
    import json
    import hashlib
    from identity_demo_cluster_build import compiler_context
    from native_build import RECIPES

    lock = json.loads((RECIPES / "inputs.lock.json").read_text())
    source = tmp_path / "upstream"
    source.mkdir()
    (source / "Cargo.lock").write_text("synthetic prepared source")
    args = SimpleNamespace(output_dir=tmp_path)
    with pytest.raises(ValueError, match="Verified prepared source"):
        compiler_context(args, lock, {"source": str(source)})
    lock["cargo_lock_sha256"] = hashlib.sha256(
        (source / "Cargo.lock").read_bytes()
    ).hexdigest()
    context = compiler_context(args, lock, {"source": str(source)})
    recipe = (context / "Containerfile").read_text()
    assert lock["cargo_lock_sha256"] in recipe and "build-native fetch" in recipe
    assert "git apply" not in recipe


def test_export_cleanup_allows_scheduler_assignment_but_rejects_image_changes(
    tmp_path, monkeypatch
):
    op, objects, calls = transport(tmp_path, monkeypatch)
    pod = object_for(
        active_profile(),
        "Pod",
        "fixture-native-export",
        spec={"containers": [{"name": "export", "image": "approved"}]},
    )
    op.create(pod)
    objects[("Pod", "fixture-native-export")]["spec"]["nodeName"] = "scheduled-worker"
    assert op.delete(op.records[-1])
    objects[("Pod", "fixture-native-export")]["spec"]["containers"][0]["image"] = (
        "substituted"
    )
    with pytest.raises(ValueError, match="configuration drift"):
        op.delete(op.records[-1])
