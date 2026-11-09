# SPDX-License-Identifier: Apache-2.0
"""Private operator artifacts, independent of installer and runtime entrypoints."""

import hashlib
import json
import os
from pathlib import Path

from deployment_profile import in_source_checkout


def sha256_file(path: Path) -> str:
    """Hash a file without loading binaries or media into memory."""
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def require_private_file(value: str, *, source_root: Path | None = None) -> Path:
    """Require an absolute, private regular file outside any source checkout."""
    raw = Path(value).expanduser()
    if raw.is_symlink() or not raw.is_absolute():
        raise ValueError("Absolute non-symlink private file required")
    path = raw.resolve()
    if in_source_checkout(path, source_root) or not path.is_file() or path.stat().st_mode & 0o077:
        raise ValueError("Private file outside checkout required")
    return path


def _write_private(path: Path, text: str) -> None:
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
        stream.write(text)


def write_json_receipt(path: Path, value: object) -> None:
    """Create a private installer receipt with a terminating newline."""
    _write_private(path, json.dumps(value, indent=2) + "\n")


def write_evidence(path: Path, value: object) -> None:
    """Retain native evidence verbatim, without replacing earlier evidence."""
    _write_private(path, value if isinstance(value, str) else json.dumps(value, indent=2))
