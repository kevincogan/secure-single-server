# SPDX-License-Identifier: Apache-2.0
"""Offline data-path policy guards; direct-path live denials remain mandatory."""

from __future__ import annotations

from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts" / "identity_demo"))
import identity_demo_step4_isolation as isolation  # noqa: E402


def test_protected_targets_leave_the_additive_namespace_allow() -> None:
    """All protected targets are excluded while ordinary fixtures retain allowance."""
    before = {"spec": {"podSelector": {}, "ingress": [{"from": [{"podSelector": {}}]}],
                       "egress": [{"to": [{"podSelector": {}}]}]}}
    after = isolation.exclude_protected(before)
    expressions = after["podSelector"]["matchExpressions"]
    for labels in (isolation.GATEWAY, isolation.BROKER, isolation.ADAPTER, isolation.JIRA):
        assert any(labels.get(e["key"]) in e["values"] for e in expressions)
    assert after["egress"] == before["spec"]["egress"]
    assert before["spec"]["podSelector"] == {}


def test_bound_gateway_accepts_only_native_supervisor_or_private_broker() -> None:
    """Workloads and arbitrary same-namespace Pods cannot reach either listener."""
    gateway = isolation.policies()[0]
    assert gateway["metadata"]["namespace"] == isolation.NAMESPACE
    ingress = gateway["spec"]["ingress"]
    assert ingress == [isolation.rule([isolation.SUPERVISOR], [8443], "from"),
                       isolation.rule([isolation.BROKER], [8080], "from")]
    for rule in ingress:
        assert all(v["podSelector"]["matchLabels"] for v in rule["from"])


def test_protected_jira_rest_accepts_only_the_protected_adapter() -> None:
    """A broker's catalog access cannot authorize direct Jira REST."""
    jira = isolation.policies()[-1]
    assert jira["spec"]["ingress"][0] == isolation.rule([isolation.ADAPTER], [8080], "from")
    assert len(jira["spec"]["ingress"]) == 1
    assert jira["spec"]["policyTypes"] == ["Ingress", "Egress"]


def test_legacy_adapter_not_reachable_by_gateway_or_broker() -> None:
    """Unused catalog removal must be backed by closed legacy network paths."""
    for value in isolation.policies():
        for direction in ("ingress", "egress"):
            for rule in value["spec"][direction]:
                assert all(port["port"] != 8082 for port in rule["ports"])


def test_unknown_base_policy_is_not_rewritten() -> None:
    """A changed ownership-boundary design requires review rather than overwrite."""
    with pytest.raises(ValueError):
        isolation.exclude_protected({"spec": {"podSelector": {"matchLabels": {"app": "other"}},
                                             "ingress": []}})
