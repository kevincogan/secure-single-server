# SPDX-License-Identifier: Apache-2.0
"""Reproduce the two operator diagnostics without cluster or credential access."""

from __future__ import annotations

import argparse
from pathlib import Path
import os
import shutil
import subprocess
import tarfile

from native_build import capture, command, digest
from source_render import read_json

TOOLS = Path(__file__).resolve().parents[2] / "tests/identity_demo/tools"


def diagnostic_build(args: argparse.Namespace) -> dict:
    """Prepare pinned public inputs; optionally compile and validate offline."""
    from identity_demo_setup import write

    lock = read_json(TOOLS / "inputs.lock.json")
    archive = Path(args.spire_archive).expanduser()
    if (not archive.is_absolute() or archive.is_symlink() or not archive.is_file()
            or archive.stat().st_size > 100_000_000 or digest(archive) != lock["spire_archive_sha256"]):
        raise ValueError("Exact pinned public SPIRE archive required")
    source = args.output_dir / "source"
    source.mkdir(mode=0o700)
    for name in ("read_native_projection.go", "read_native_projection_test.go", "inputs.lock.json"):
        shutil.copyfile(TOOLS / name, source / name)
    output = args.output_dir / "binaries"
    output.mkdir(mode=0o700)
    with tarfile.open(archive) as packed:
        for key, name, maximum in (("spire_agent_member", "spire-agent", 50_000_000),
                                   ("spire_license_member", "SPIRE-LICENSE", 100_000)):
            matches = [m for m in packed.getmembers() if m.name == lock[key]]
            if len(matches) != 1 or not matches[0].isfile() or not 0 < matches[0].size <= maximum:
                raise ValueError("Exact bounded regular archive members required")
            with packed.extractfile(matches[0]) as stream:
                (output / name).write_bytes(stream.read(maximum + 1))
    if digest(output / "spire-agent") != lock["spire_agent_sha256"]:
        raise ValueError("Reviewed upstream SPIRE executable hash required")
    plan = {"schema_version": 1, "inputs": lock, "engine": args.engine,
            "source_sha256": {p.name: digest(p) for p in source.iterdir()},
            "helper_sha256": digest(Path(__file__)),
            "target": "linux/amd64", "applied": False, "cluster_contacted": False}
    shutil.copyfile(__file__, args.output_dir / "diagnostic_build.executed.py")
    write(args.output_dir / "diagnostic-build.plan.json", plan)
    if not args.apply:
        return {"diagnostic_build_prepared": True, "applied": False, "cluster_contacted": False}
    for role in ("builder_image", "validation_image"):
        command([args.engine, "pull", *(["--platform=linux/amd64"] if role == "validation_image" else []),
                 lock[role]], args.output_dir / (role + "-pull.log"))
    for folder in ("cache", "temporary"):
        (args.output_dir / folder).mkdir(mode=0o700)
    run = [args.engine, "run", "--rm", "--network=none", "--read-only", "--cap-drop=ALL",
           "--security-opt=no-new-privileges", "--user", str(os.getuid()) + ":" + str(os.getgid()),
           "--workdir=/source"]
    for folder, target, readonly in ((source, "/source", True), (output, "/output", False),
            (args.output_dir / "cache", "/cache", False), (args.output_dir / "temporary", "/tmp", False)):
        run.extend(["--mount", "type=bind,src=" + str(folder) + ",dst=" + target + (",readonly" if readonly else "")])
    for name, value in {"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off",
                        "GO111MODULE": "off", "GOCACHE": "/cache", "GOTMPDIR": "/tmp",
                        "CGO_ENABLED": "0", "GOOS": "linux"}.items():
        run.extend(["--env", name + "=" + value])
    builder = [*run, "--entrypoint=go", lock["builder_image"]]
    command([*builder, "version"], args.output_dir / "compiler-version.log")
    if lock["go_version"] not in (args.output_dir / "compiler-version.log").read_text().split():
        raise ValueError("Pinned Go compiler version required")
    command([*builder, "test", "-v", "read_native_projection.go", "read_native_projection_test.go"],
            args.output_dir / "projection-tests.log")
    command([*run, "--env=GOARCH=amd64", "--env=GOAMD64=v1", "--entrypoint=go", lock["builder_image"],
             "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid=",
             "-o", "/output/read-native-projection", "read_native_projection.go"],
            args.output_dir / "projection-build.log")
    for name in ("spire-agent", "read-native-projection"):
        path = output / name
        header = path.read_bytes()[:20]
        if not (header[:6] == b"\x7fELF\x02\x01" and header[18:20] == b"\x3e\x00"):
            raise ValueError("Linux AMD64 ELF executable required")
        path.chmod(0o500)
    runtime = [args.engine, "run", "--rm", "--platform=linux/amd64", "--network=none",
               "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
               "--user", str(os.getuid()) + ":" + str(os.getgid()),
               "--mount", "type=bind,src=" + str(output) + ",dst=/tools,readonly"]
    command([*runtime, "--entrypoint=/tools/spire-agent", lock["validation_image"], "--version"],
            args.output_dir / "spire-version.log")
    if lock["spire_version"] not in (args.output_dir / "spire-version.log").read_text().split():
        raise ValueError("Pinned SPIRE diagnostic version required")
    controls = []
    for arguments, expected in (([], 1), (["--arbitrary-path"], 2)):
        result = subprocess.run([*runtime, "--entrypoint=/tools/read-native-projection",
            lock["validation_image"], *arguments], capture_output=True, timeout=60)
        if result.returncode != expected or result.stdout:
            raise ValueError("Diagnostic refusal control failed")
        controls.append({"extra_arguments": bool(arguments), "exit_code": result.returncode,
                         "stdout_empty": True})
    receipt = {**plan, "applied": True, "offline_compilation_passed": True,
        "synthetic_unit_tests_passed": True, "runtime_refusal_controls": controls,
        "builder_image_id": capture([args.engine, "image", "inspect", lock["builder_image"], "--format", "{{.Id}}"]),
        "binary_sha256": {name: digest(output / name) for name in ("spire-agent", "read-native-projection")},
        "credential_or_cluster_accessed": False, "live_acceptance_proven": False}
    write(args.output_dir / "diagnostic-build.receipt.json", receipt)
    return {"diagnostics_built_and_verified": True, "applied": True,
            "cluster_contacted": False, "live_acceptance_proven": False}
