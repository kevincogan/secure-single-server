# SPDX-License-Identifier: Apache-2.0
"""Diagnostic builds are pinned, local and independent of private lab binaries."""

import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile
from types import SimpleNamespace

import pytest

import diagnostic_build as build


ELF = b"\x7fELF\x02\x01" + b"\x00" * 12 + b"\x3e\x00synthetic"


@pytest.fixture
def inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> argparse.Namespace:
    """Keep all credentials, compilers and real container operations out of tests."""
    tools = tmp_path / "tools"
    tools.mkdir()
    for name in ("read_native_projection.go", "read_native_projection_test.go"):
        (tools / name).write_text("// SPDX-License-Identifier: Apache-2.0\npackage main\n")
    archive = tmp_path / "spire.tar.gz"
    with tarfile.open(archive, "w:gz") as packed:
        for name, data in (("spire/bin/spire-agent", ELF), ("spire/LICENSE", b"synthetic license")):
            member = tarfile.TarInfo(name)
            member.size = len(data)
            packed.addfile(member, io.BytesIO(data))
    lock = {"schema_version": 1, "go_version": "go1.27.2", "spire_version": "1.14.7",
            "builder_image": "example.org/builder@sha256:" + "a" * 64,
            "validation_image": "example.org/runtime@sha256:" + "b" * 64,
            "spire_archive_sha256": build.digest(archive),
            "spire_agent_member": "spire/bin/spire-agent", "spire_license_member": "spire/LICENSE",
            "spire_agent_sha256": hashlib.sha256(ELF).hexdigest()}
    (tools / "inputs.lock.json").write_text(json.dumps(lock))
    monkeypatch.setattr(build, "TOOLS", tools)
    output = tmp_path / "result"
    output.mkdir(mode=0o700)
    return argparse.Namespace(spire_archive=str(archive), engine="docker", output_dir=output, apply=False)


def test_preparation_never_executes_engine(inputs: argparse.Namespace, monkeypatch: pytest.MonkeyPatch) -> None:
    """Public archive extraction and source snapshots require no network/cluster."""
    monkeypatch.setattr(build, "command", lambda *a, **kw: pytest.fail("Engine must not run"))
    result = build.diagnostic_build(inputs)
    assert result == {"diagnostic_build_prepared": True, "applied": False, "cluster_contacted": False}
    plan = json.loads((inputs.output_dir / "diagnostic-build.plan.json").read_text())
    assert plan["helper_sha256"] == build.digest(inputs.output_dir / "diagnostic_build.executed.py")
    assert build.digest(inputs.output_dir / "binaries/spire-agent") == plan["inputs"]["spire_agent_sha256"]


@pytest.mark.parametrize("mode", ["archive-hash", "archive-symlink", "binary-hash", "missing", "duplicate", "member-symlink"])
def test_preparation_refuses_changed_or_unsafe_inputs(
        inputs: argparse.Namespace, mode: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """No changed archive, duplicate, symlink or unmatched executable is accepted."""
    monkeypatch.setattr(build, "command", lambda *a, **kw: pytest.fail("Engine must not run"))
    path = Path(inputs.spire_archive)
    lock_path = build.TOOLS / "inputs.lock.json"
    lock = json.loads(lock_path.read_text())
    if mode == "archive-hash":
        path.write_bytes(b"changed")
    elif mode == "archive-symlink":
        link = path.with_name("link.tar.gz")
        link.symlink_to(path)
        inputs.spire_archive = str(link)
    elif mode == "binary-hash":
        lock["spire_agent_sha256"] = "f" * 64
    else:
        with tarfile.open(path, "w:gz") as packed:
            for index in range(2 if mode == "duplicate" else 1):
                member = tarfile.TarInfo("absent" if mode == "missing" else lock["spire_agent_member"])
                member.size = len(ELF)
                if mode == "member-symlink":
                    member.type, member.linkname = tarfile.SYMTYPE, "/outside"
                packed.addfile(member, io.BytesIO(ELF))
        lock["spire_archive_sha256"] = build.digest(path)
    lock_path.write_text(json.dumps(lock))
    with pytest.raises(ValueError):
        build.diagnostic_build(inputs)
    assert not (inputs.output_dir / "diagnostic-build.receipt.json").exists()


@pytest.mark.parametrize("failure", [None, "compiler", "spire", "architecture", "stdout", "exit"])
def test_apply_compiles_offline_and_checks_refusals(
        inputs: argparse.Namespace, monkeypatch: pytest.MonkeyPatch, failure: str | None) -> None:
    """Synthetic command execution covers isolation and fail-closed acceptance."""
    inputs.apply = True
    commands = []

    def command(words: list[str], log: Path) -> None:
        commands.append(words)
        text = ""
        if log.name == "compiler-version.log":
            text = "go version " + ("go0.0.0" if failure == "compiler" else "go1.27.2") + " linux/arm64\n"
        elif log.name == "spire-version.log":
            text = "0.0.0" if failure == "spire" else "1.14.7\n"
        elif log.name == "projection-build.log":
            (inputs.output_dir / "binaries/read-native-projection").write_bytes(
                b"invalid" if failure == "architecture" else ELF)
        log.write_text(text)

    monkeypatch.setattr(build, "command", command)
    monkeypatch.setattr(build, "capture", lambda words: "sha256:" + "a" * 64)
    calls = []

    def runtime(words: list[str], **kwargs: object) -> SimpleNamespace:
        calls.append(words)
        return SimpleNamespace(returncode=0 if failure == "exit" else 2 if words[-1] == "--arbitrary-path" else 1,
                               stdout=b"synthetic unexpected output" if failure == "stdout" else b"", stderr=b"")

    monkeypatch.setattr(build.subprocess, "run", runtime)
    if failure:
        with pytest.raises(ValueError):
            build.diagnostic_build(inputs)
        assert not (inputs.output_dir / "diagnostic-build.receipt.json").exists()
    else:
        result = build.diagnostic_build(inputs)
        assert result["diagnostics_built_and_verified"] and not result["cluster_contacted"]
        receipt = json.loads((inputs.output_dir / "diagnostic-build.receipt.json").read_text())
        assert receipt["synthetic_unit_tests_passed"] and len(receipt["runtime_refusal_controls"]) == 2
        assert not receipt["credential_or_cluster_accessed"]
        for words in commands[2:] + calls:
            assert "--network=none" in words and "--read-only" in words and "--cap-drop=ALL" in words
            assert "--security-opt=no-new-privileges" in words
        compiler = next(w for w in commands if "build" in w)
        assert "--env=GOARCH=amd64" in compiler and "-trimpath" in compiler
        assert "--env" in compiler and "GOPROXY=off" in compiler and "GOTOOLCHAIN=local" in compiler


def test_reader_has_no_configurable_path() -> None:
    """The operator reader cannot be redirected to another mounted secret."""
    source = (build.TOOLS / "read_native_projection.go").read_text()
    assert 'const projectionPath = "/var/run/secrets/openshell/token"' in source
    assert "len(os.Args) != 1" in source and "io.LimitReader(source, maximumBytes+1)" in source
    assert "os.Getenv" not in source
