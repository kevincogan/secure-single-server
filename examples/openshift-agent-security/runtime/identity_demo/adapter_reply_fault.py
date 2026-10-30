# SPDX-License-Identifier: Apache-2.0
"""Owned fixture only: discard one selected real Jira create's successful reply.

The operator creates/removes a private selector file inside the adapter. There
is no HTTP control endpoint. All TLS, authentication and backend effects remain
in the original adapter; no backend restart or database replacement is needed.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from identity_demo_jira_action_adapter import JIRA, JiraTools

SELECTOR = Path("/tmp/identity-demo-lost-reply-action")


class ReplyLossTools(JiraTools):
    """Keep the normal request but lose its selected successful response."""

    async def http(self, method: str, url: str, **kwargs: Any) -> tuple[int, dict]:
        """Apply a default-disabled exact-action fault after the real HTTP call."""
        action = SELECTOR.read_text().strip() if SELECTOR.exists() else None
        if action is not None and not re.fullmatch(r"[a-f0-9]{32}", action):
            raise RuntimeError("invalid_fixture_fault_selector")
        result = await super().http(method, url, **kwargs)
        labels = kwargs.get("value", {}).get("fields", {}).get("labels", [])
        if (
            action is not None
            and method == "POST"
            and url == JIRA + "/rest/api/2/issue"
            and kwargs.get("backend") is True
            and isinstance(labels, list)
            and "demo-action-" + action in labels
            and result[0] == 201
        ):
            return 503, {"error": "synthetic_create_reply_lost"}
        return result
