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


@pytest.mark.parametrize("mode", ["legacy", "cluster"])
def test_native_gateway_accepts_exact_supported_isolation_modes(monkeypatch, mode):
    from types import SimpleNamespace
    from copy import deepcopy
    import native_backend
    from cluster_console_resources import private_network
    from deployment_profile import active_profile
    from identity_demo_step4_isolation import policies, exclude_protected

    broad = {
        "metadata": {
            "name": "fixture-isolation",
            "namespace": active_profile().core_namespace,
        },
        "spec": {"podSelector": {}, "ingress": [{"from": [{"podSelector": {}}]}]},
    }
    broad["spec"] = exclude_protected(broad)
    expected = {v["metadata"]["name"]: v for v in policies()}
    if mode == "cluster":
        resources, broad = private_network(active_profile(), broad)
        expected.update(
            {
                v["metadata"]["name"]: v
                for v in resources
                if v["kind"] == "NetworkPolicy"
            }
        )
    expected["fixture-isolation"] = broad
    expected["fixture-mcp-route-ingress"] = {"spec": {"ingress": []}}
    monkeypatch.setattr(
        native_backend.shared,
        "owned",
        lambda args, kind, name: deepcopy(expected[name]),
    )
    native_backend.require_isolation(SimpleNamespace())


@pytest.mark.parametrize(
    "fault",
    [
        "operator_port",
        "operator_peer",
        "business_peer",
        "extra_app",
        "public_gateway",
        "extra_selector",
    ],
)
def test_native_gateway_refuses_drift_before_any_backend_write(monkeypatch, fault):
    from types import SimpleNamespace
    from copy import deepcopy
    import native_backend
    from cluster_console_resources import private_network
    from deployment_profile import active_profile
    from identity_demo_step4_isolation import policies, exclude_protected

    broad = {
        "metadata": {
            "name": "fixture-isolation",
            "namespace": active_profile().core_namespace,
        },
        "spec": {"podSelector": {}, "ingress": [{"from": [{"podSelector": {}}]}]},
    }
    broad["spec"] = exclude_protected(broad)
    resources, broad = private_network(active_profile(), broad)
    expected = {
        v["metadata"]["name"]: v
        for v in policies() + resources
        if v["kind"] == "NetworkPolicy"
    }
    expected["fixture-isolation"] = broad
    expected["fixture-mcp-route-ingress"] = {"spec": {"ingress": []}}
    if fault == "operator_port":
        expected["fixture-identity-operator"]["spec"]["ingress"][0]["ports"][0][
            "port"
        ] = 8443
    if fault == "operator_peer":
        expected["fixture-identity-operator"]["spec"]["ingress"][0]["from"] = [
            {"podSelector": {}}
        ]
    if fault == "business_peer":
        expected["fixture-driver-business"]["spec"]["ingress"][0]["from"] = [
            {"podSelector": {}}
        ]
    if fault == "extra_app":
        broad["spec"]["podSelector"]["matchExpressions"][2]["values"].append(
            "another-app"
        )
    if fault == "public_gateway":
        expected["fixture-mcp-route-ingress"]["spec"]["ingress"] = [
            {"from": [{"podSelector": {}}]}
        ]
    if fault == "extra_selector":
        broad["spec"]["podSelector"]["matchLabels"] = {"app": "unexpected"}
    monkeypatch.setattr(
        native_backend.shared,
        "owned",
        lambda args, kind, name: deepcopy(expected[name]),
    )
    backend = native_backend.NativeBackend(SimpleNamespace())
    with pytest.raises(ValueError):
        backend.prepare("unused-ca", "unused-secret", None, "must-not-read-credential")
    assert backend.ledger == []
