# SPDX-License-Identifier: Apache-2.0
"""Atomic private checkpoints; immutable receipts continue using exclusive writes."""

import json
import os
from pathlib import Path
from uuid import uuid4


def checkpoint(path: Path, value: dict) -> None:
    if (
        path.is_symlink()
        or path.parent.is_symlink()
        or not path.parent.is_dir()
        or path.parent.stat().st_mode & 0o077
        or path.exists()
        and path.stat().st_mode & 0o077
    ):
        raise ValueError("Private regular checkpoint required")
    temporary = path.with_name("." + path.name + "." + uuid4().hex + ".pending")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()
