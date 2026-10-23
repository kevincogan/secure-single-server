# SPDX-License-Identifier: Apache-2.0
"""Inspect synthetic response evidence without returning confidential contents."""

from __future__ import annotations

import json


def sanitized_error_result(body: bytes) -> dict:
    """Inspect every JSON/SSE event and return only unexpected result presence."""
    def has_result(data: bytes) -> bool:
        """Discard all decoded content except the top-level result-key presence."""
        try:
            value = json.loads(data)
        except (ValueError, UnicodeDecodeError):
            return False
        return isinstance(value, dict) and "result" in value

    if has_result(body):
        return {"result": True}
    event: list[bytes] = []
    for line in body.splitlines() + [b""]:
        if not line:
            if event and has_result(b"\n".join(event)):
                return {"result": True}
            event = []
        elif line.startswith(b"data:"):
            event.append(line[5:].lstrip(b" "))
    return {}
