# SPDX-License-Identifier: Apache-2.0
"""Portable native builds retain pins, trust and least-privilege boundaries."""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
from pathlib import Path
import tarfile
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import pytest

from deployment_profile import LEGACY
import native_build as build


def test_checked_in_lock_matches_all_patches() -> None:
    """No patch edit or package selection can silently change the build contract."""
    value = json.loads((build.RECIPES / "inputs.lock.json").read_text())
    assert [p["file"] for p in value["patches"]] == [
        "v0.1.3-sandbox-subject-comparison.patch", "v0.1.3-pilot-sender-transport.patch",
        "v0.1.3-sender-installation-domain.patch", "v0.1.3-sender-x509-feature.patch",
        "v0.1.3-bounded-oauth-response.patch"]
    for entry in value["patches"]:
        assert build.digest(build.PATCHES / entry["file"]) == entry["sha256"]
    script = (build.RECIPES / "build-native.sh").read_text()
    assert "cargo auditable build --frozen" in script and "--release" in script
    assert "-p openshell-gateway -p openshell-supervisor" in script
    assert 'rustc --version' in script and value["rust_version"] in script
    assert all("@sha256:" in image for image in value["runtime_bases"].values())
    recipe = (build.RECIPES / "Builder.Containerfile").read_text()
    assert "rustup component add rustfmt rust-src rust-analyzer" in recipe


@pytest.fixture
def inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[argparse.Namespace, dict]:
    """Synthetic archive and short-lived CA; no private operator state is read."""
    tmp_path.chmod(0o700)
    recipe = tmp_path / "recipe"
    recipe.mkdir()
    for name in ("Builder.Containerfile", "build-native.sh"):
        (recipe / name).write_text("synthetic recipe\n")
    patches = tmp_path / "patches"
    patches.mkdir()
    patch = patches / "change.patch"
    patch.write_text("diff --git a/example b/example\n--- a/example\n+++ b/example\n@@ -1 +1 @@\n-original\n+patched\n")
    archive = tmp_path / "source.tar.gz"
    with tarfile.open(archive, "w:gz") as packed:
        for name, value in (("Cargo.lock", b"synthetic-lock\n"), ("example", b"original\n")):
            member = tarfile.TarInfo("upstream/" + name)
            member.size = len(value)
            packed.addfile(member, io.BytesIO(value))
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps(LEGACY.to_dict()))
    ca = tmp_path / "public.pem"
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic native build CA")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(key, hashes.SHA256()))
    ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    for path in (archive, profile, ca):
        path.chmod(0o600)
    lock = {"source_commit": "a" * 40, "source_archive_sha256": build.digest(archive),
            "upstream_cargo_lock_sha256": hashlib.sha256(b"synthetic-lock\n").hexdigest(),
            "cargo_lock_sha256": hashlib.sha256(b"synthetic-lock\n").hexdigest(),
            "target": "x86_64-unknown-linux-gnu", "patches": [{"file": patch.name, "sha256": build.digest(patch)}]}
    (recipe / "inputs.lock.json").write_text(json.dumps(lock))
    monkeypatch.setattr(build, "RECIPES", recipe)
    monkeypatch.setattr(build, "PATCHES", patches)
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    return argparse.Namespace(source_archive=str(archive), installation_profile=str(profile),
        native_ca_bundle=str(ca), engine="podman", output_dir=output, apply=False), lock


@pytest.mark.parametrize("mode", ["valid", "archive", "patch", "dependency-lock", "private-trust", "traversal"])
def test_preparation_checks_every_input(inputs: tuple, mode: str) -> None:
    """No engine/network operation occurs for preparation or invalid source."""
    args, lock = inputs
    if mode == "archive":
        Path(args.source_archive).write_bytes(b"different-source")
    elif mode == "patch":
        (build.PATCHES / "change.patch").write_text("changed")
    elif mode == "dependency-lock":
        lock["cargo_lock_sha256"] = "f" * 64
    elif mode == "private-trust":
        with Path(args.native_ca_bundle).open("ab") as stream:
            stream.write(b"PRIVATE KEY")
    elif mode == "traversal":
        with tarfile.open(args.source_archive, "w:gz") as archive:
            item = tarfile.TarInfo("upstream/../../escaped")
            item.size = 4
            archive.addfile(item, io.BytesIO(b"oops"))
        lock["source_archive_sha256"] = build.digest(Path(args.source_archive))
    (build.RECIPES / "inputs.lock.json").write_text(json.dumps(lock))
    if mode == "valid":
        Path(args.source_archive).chmod(0o644)  # Public source needs no private-file restriction.
        result = build.native_build(args)
        assert result["native_build_prepared"] and not result["applied"]
        plan = json.loads((args.output_dir / "native-build.plan.json").read_text())
        assert plan["native_build_contract"] == LEGACY.native_build_contract
        assert (Path(plan["source"]) / "example").read_text() == "patched\n"
        assert (args.output_dir / "native-build.env").stat().st_mode & 0o077 == 0
        assert build.digest(args.output_dir / "native_build.executed.py") == plan["recipe_sha256"]["native_build.py"]
        assert build.digest(args.output_dir / "inputs.lock.executed.json") == plan["recipe_sha256"]["inputs.lock.json"]
        assert not (args.output_dir / "native-build.receipt.json").exists()
    else:
        with pytest.raises((ValueError, tarfile.FilterError)):
            build.native_build(args)
        assert not (args.output_dir / "native-build.plan.json").exists()
        assert not (args.output_dir.parent / "escaped").exists()


@pytest.mark.parametrize("role", ["gateway", "supervisor"])
def test_runtime_context_copies_only_allowed_files(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str) -> None:
    """The installed supervisor path is exact and no generated secrets are copied."""
    compiled = tmp_path / "compiled"
    compiled.mkdir()
    binary = compiled / ("openshell-" + role)
    binary.write_bytes(b"\x7fELF\x02\x01" + b"\x00" * 12 + b"\x3e\x00synthetic")
    (tmp_path / "native-public-trust.pem").write_text("synthetic public CA")
    (compiled / "builder-packages.txt").write_text("libz3-4:amd64\t4.13.3-1\nlibgcc-s1:amd64\t14.2.0-19\n")
    def run(words: list[str], **kwargs: object) -> SimpleNamespace:
        assert "--network=none" in words and "--read-only" in words
        kwargs["stdout"].write(b"synthetic target library")
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(build.subprocess, "run", run)
    lock = json.loads((build.RECIPES / "inputs.lock.json").read_text())
    plan = {"native_build_contract": LEGACY.native_build_contract, "native_ca_bundle_sha256": "a" * 64}
    context = build.runtime_context(argparse.Namespace(output_dir=tmp_path, engine="podman"), lock, plan, role, "builder-id")
    assert set(p.name for p in context.iterdir()) == {
        "openshell-" + role, "libz3.so.4" if role == "gateway" else "libgcc_s.so.1", "native-public-trust.pem", "Containerfile",
        "supplied-library.spdx.json", "libz3-4.copyright" if role == "gateway" else "libgcc-s1.copyright"}
    text = (context / "Containerfile").read_text()
    assert "USER 1000:1000" in text and "@sha256:" in text
    destination = "/openshell-supervisor" if role == "supervisor" else "/usr/local/bin/openshell-gateway"
    assert "COPY --chmod=0555 openshell-" + role + " " + destination in text
    provenance = json.loads((context / "supplied-library.spdx.json").read_text())
    assert provenance["packages"][0]["versionInfo"] in ("4.13.3-1", "14.2.0-19")
    assert provenance["packages"][0]["licenseConcluded"] == "NOASSERTION"


def test_compile_is_offline_and_mounts_only_build_inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Fetching and offline compilation stay separate; no cluster or push command."""
    lock = json.loads((build.RECIPES / "inputs.lock.json").read_text())
    (tmp_path / "Cargo.lock").write_bytes(b"synthetic-lock")
    lock["cargo_lock_sha256"] = build.digest(tmp_path / "Cargo.lock")
    plan = {"source": str(tmp_path), "images": {r: "localhost/synthetic-" + r for r in ("builder", "gateway", "supervisor")}}
    monkeypatch.setattr(build, "prepare", lambda args: (lock, plan))
    events = []
    monkeypatch.setattr(build, "command", lambda words, *a, **kw: events.append(words))
    monkeypatch.setattr(build, "capture", lambda words: "sha256:" + "a" * 64)
    monkeypatch.setattr(build, "runtime_context", lambda *a: tmp_path)
    monkeypatch.setattr(build, "validate_runtime", lambda *a: {"packaged_binary_matches": True})
    args = argparse.Namespace(output_dir=tmp_path, engine="podman", apply=True)
    result = build.native_build(args)
    assert result["offline_compilation_passed"] and not result["published"]
    fetch = next(e for e in events if e[-1] == "fetch")
    compile_command = next(e for e in events if e[-1] == "compile")
    assert "--network=none" not in fetch and "--network=none" in compile_command
    assert "--read-only" in compile_command and "--cap-drop=ALL" in compile_command
    assert not any(word in ("push", "oc", "kubectl", "--privileged") for e in events for word in e)


@pytest.mark.parametrize("mode", ["valid", "binary-mismatch", "wrong-architecture", "copy-failure"])
def test_packaged_executable_is_verified_and_temporary_container_removed(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    """A startup check cannot conceal an old executable at the real entrypoint."""
    compiled = tmp_path / "compiled"
    compiled.mkdir()
    original = b"synthetic executable"
    (compiled / "openshell-supervisor").write_bytes(original)
    events = []
    def metadata(words: list[str]) -> str:
        events.append(words)
        if "inspect" in words:
            return "arm64 linux" if mode == "wrong-architecture" else "amd64 linux"
        return "a" * 64
    def command(words: list[str], *unused: object, **kwargs: object) -> None:
        events.append(words)
        if words[1] == "cp":
            assert words[2].endswith(":/openshell-supervisor")
            if mode == "copy-failure":
                raise RuntimeError("synthetic copy failure")
            Path(words[3]).write_bytes(b"old executable" if mode == "binary-mismatch" else original)
    monkeypatch.setattr(build, "capture", metadata)
    monkeypatch.setattr(build, "command", command)
    args = argparse.Namespace(output_dir=tmp_path, engine="podman")
    if mode == "valid":
        result = build.validate_runtime(args, "supervisor", "image-id")
        assert result["packaged_binary_matches"] and result["installed_path"] == "/openshell-supervisor"
        run = [e for e in events if e[1] == "run"]
        assert len(run) == 2 and all("--network=none" in e for e in run)
    else:
        with pytest.raises((ValueError, RuntimeError)):
            build.validate_runtime(args, "supervisor", "image-id")
        assert not any(e[1] == "run" for e in events)
    assert any(e[1] == "rm" for e in events) == (mode != "wrong-architecture")
