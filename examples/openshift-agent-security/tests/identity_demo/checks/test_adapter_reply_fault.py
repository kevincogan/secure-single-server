# SPDX-License-Identifier: Apache-2.0
"""Prove reply-loss scoping without claiming live recovery acceptance."""

import asyncio

import pytest

import adapter_reply_fault as fault
from identity_demo_jira_action_adapter import JIRA, JiraTools


@pytest.mark.parametrize("enabled,matching,status,backend,method,expected", [
    (False, True, 201, True, "POST", 201),
    (True, False, 201, True, "POST", 201),
    (True, True, 401, True, "POST", 401),
    (True, True, 201, False, "POST", 201),
    (True, True, 201, True, "GET", 201),
    (True, True, 201, True, "POST", 503),
])
def test_scoped_after_real_request(tmp_path, monkeypatch, enabled, matching,
                                   status, backend, method, expected) -> None:
    """The original TLS/backend method receives the unmodified request once."""
    selector = tmp_path / "selector"
    monkeypatch.setattr(fault, "SELECTOR", selector)
    if enabled:
        selector.write_text("a" * 32)
    calls = []

    async def original(self, method, url, **kwargs):
        calls.append((method, url, kwargs))
        return status, {"key": "TEST-1"}

    monkeypatch.setattr(JiraTools, "http", original)
    tools = object.__new__(fault.ReplyLossTools)
    kwargs = {"backend": backend, "value": {"fields": {"labels": [
        "demo-action-" + ("a" if matching else "b") * 32]}}}
    result = asyncio.run(tools.http(method, JIRA + "/rest/api/2/issue", **kwargs))
    assert calls == [(method, JIRA + "/rest/api/2/issue", kwargs)]
    assert result[0] == expected
    if expected == 503:
        assert "key" not in result[1]


def test_invalid_selector_fails_before_dispatch(tmp_path, monkeypatch) -> None:
    """A malformed operator selector cannot broaden the fault scope."""
    selector = tmp_path / "selector"
    selector.write_text("*")
    monkeypatch.setattr(fault, "SELECTOR", selector)
    with pytest.raises(RuntimeError, match="invalid_fixture_fault_selector"):
        asyncio.run(object.__new__(fault.ReplyLossTools).http("POST", JIRA))
