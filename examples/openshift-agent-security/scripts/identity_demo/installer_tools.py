# SPDX-License-Identifier: Apache-2.0
"""Bundle reviewed public tools/source; installation Jobs need no download access."""

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from urllib.parse import urlsplit
from urllib.request import urlopen

from console_runtime_build import unpack, verify_versions
from native_build import ROOT
from source_render import read_json


def fetch(url, expected, destination, limit):
    """Bound HTTPS downloads and verify bytes before any extraction or execution."""
    if urlsplit(url).scheme != "https":
        raise ValueError("Pinned HTTPS archive required")
    with urlopen(url, timeout=120) as response, destination.open("xb") as output:
        if urlsplit(response.geturl()).scheme != "https":
            raise ValueError("HTTPS redirects only")
        count = 0
        while block := response.read(1024 * 1024):
            count += len(block)
            if count > limit:
                raise ValueError("Bounded archive required")
            output.write(block)
    with destination.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    if actual != expected:
        raise ValueError("Archive does not match the reviewed lock")
    return actual


def private_cli(
    directory,
    *,
    tool_root=Path("/usr/local/bin"),
    receipt_path=Path("/usr/share/installer-tools.json"),
):
    """Materialize the verified public executable for existing private CLI guards."""
    runtime = read_json(ROOT / "infra/identity-demo/console-runtime.lock.json")
    native = read_json(ROOT / runtime["cli_lock"])
    receipt = read_json(receipt_path)
    expected = native["assets"]["linux-amd64"]["sha256"]
    source = tool_root / "openshell"
    if (
        source.is_symlink()
        or not source.is_file()
        or not 0 < source.stat().st_size <= 250_000_000
        or receipt.get("versions")
        != {
            "oc": runtime["oc_version"],
            "openshell": native["version"],
            "platform": "linux/amd64",
        }
        or receipt.get("openshell", {}).get("archive_sha256") != expected
    ):
        raise ValueError("Verified packaged CLI identity required")
    with source.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != receipt["openshell"].get("binary_sha256"):
        raise ValueError("Packaged CLI bytes changed")
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.is_symlink() or directory.stat().st_mode & 0o077:
        raise ValueError("Private regular CLI directory required")
    target = directory / "openshell"
    if target.exists() or target.is_symlink():
        if (
            target.is_symlink()
            or not target.is_file()
            or target.stat().st_mode & 0o077
            or not target.stat().st_mode & 0o100
        ):
            raise ValueError("Existing private CLI changed; explicit recovery required")
        with target.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
                raise ValueError("Existing private CLI bytes changed")
    else:
        import os
        import shutil

        with source.open("rb") as original, target.open("xb") as copy:
            os.fchmod(copy.fileno(), 0o700)
            shutil.copyfileobj(original, copy)
            copy.flush()
            os.fsync(copy.fileno())
        with target.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
                raise ValueError("Private CLI copy verification failed")
    return target


def install(destination, source_directory):
    runtime = read_json(ROOT / "infra/identity-demo/console-runtime.lock.json")
    native = read_json(ROOT / runtime["cli_lock"])
    inputs = {
        "oc": (runtime["oc_archive_url"], runtime["oc_archive_sha256"], "oc"),
        "openshell": (
            native["assets"]["linux-amd64"]["url"],
            native["assets"]["linux-amd64"]["sha256"],
            native["assets"]["linux-amd64"]["archive_member"],
        ),
    }
    destination.mkdir(parents=True, exist_ok=True)
    receipts = {}
    for name, (url, expected, member) in inputs.items():
        with tempfile.TemporaryDirectory() as work:
            archive = Path(work) / "archive.tar.gz"
            fetch(url, expected, archive, 300_000_000)
            unpack(archive, expected, member, destination / name)
            with (destination / name).open("rb") as binary:
                binary_hash = hashlib.file_digest(binary, "sha256").hexdigest()
            receipts[name] = {"archive_sha256": expected, "binary_sha256": binary_hash}
    receipts["versions"] = verify_versions(
        subprocess.check_output(
            [str(destination / "oc"), "version", "--client=true", "-o", "json"],
            text=True,
            timeout=30,
        ),
        subprocess.check_output(
            [str(destination / "openshell"), "--version"], text=True, timeout=30
        ),
        runtime["oc_version"],
        native["version"],
    )
    # Public source is fetched in the credential-free image build. Native
    # compilation still checks the original archive, patchset and Cargo lock.
    lock = read_json(ROOT / "infra/openshell/native-build/inputs.lock.json")
    source_directory.mkdir(parents=True, exist_ok=True)
    archive = source_directory / "openshell-source.tar.gz"
    receipts["native_source"] = {
        "sha256": fetch(
            lock["source_url"], lock["source_archive_sha256"], archive, 32_000_000
        ),
        "path": str(archive),
    }
    archive.chmod(0o444)
    return receipts


if __name__ == "__main__":
    print(
        json.dumps(
            install(Path("/usr/local/bin"), Path("/usr/share/installer-inputs")),
            sort_keys=True,
        )
    )
