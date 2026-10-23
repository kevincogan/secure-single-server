#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""A deterministic non-CVE proposal, used with the shared native MCP transport.

The operator submits this report to the existing trusted driver. The user then
approves the normalized action, and the same run invokes the existing create
tool. This code cannot authenticate users, approve actions or call Jira directly.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


def proposal() -> dict:
    """Produce a repeatable synthetic request for the dedicated SERVICE project."""
    return {
        "request_id": "SERVICE-0001",
        "assessment": "Synthetic service request: provision a read-only workspace.",
        "proposed_create": {
            "project": "SERVICE",
            "issue_type": "Task",
            "summary": "SERVICE-0001: provision a synthetic read-only workspace",
            "description": "Synthetic service-request fixture; no CVE analysis or live model.",
            "labels": ["synthetic-service-request"],
        },
        "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }


def main() -> None:
    """Emit a proposal only; execution and consent are separate trusted operations."""
    print(json.dumps(proposal()))


if __name__ == "__main__":
    main()
