# SPDX-License-Identifier: Apache-2.0
"""Node churn must not require broad egress or weaken identity verification."""

from copy import deepcopy
import pytest
import identity_demo_spire_network as network


def policy() -> dict:
    """Represent the original owner-scoped host-only rule."""
    return {
        "metadata": {
            "name": "identity-demo-kubelet-egress",
            "namespace": network.NAMESPACE,
            "uid": "fixed-uid",
            "resourceVersion": "7",
            "labels": {
                "identity-demo-owner": "fixture-owner",
                "app.kubernetes.io/part-of": "identity-demo-preflight",
            },
        },
        "spec": {
            "podSelector": {"matchLabels": {"app.kubernetes.io/name": "spire-agent"}},
            "policyTypes": ["Egress"],
            "egress": [
                {
                    "ports": [{"port": 10250, "protocol": "TCP"}],
                    "to": [{"ipBlock": {"cidr": "10.0.1.128/32"}}],
                }
            ],
        },
    }


def test_node_addition_preserves_old_targets_selector_and_port() -> None:
    value = policy()
    before = deepcopy(value)
    patch = network.kubelet_policy_patch(
        value, {"10.0.1.128", "10.0.1.16"}, "fixture-owner"
    )
    assert value == before
    assert patch[:2] == [
        {"op": "test", "path": "/metadata/uid", "value": "fixed-uid"},
        {"op": "test", "path": "/metadata/resourceVersion", "value": "7"},
    ]
    assert patch[2] == {"op": "test", "path": "/spec", "value": before["spec"]}
    assert patch[3] == {
        "op": "replace",
        "path": "/spec/egress/0/to",
        "value": [
            {"ipBlock": {"cidr": "10.0.1.128/32"}},
            {"ipBlock": {"cidr": "10.0.1.16/32"}},
        ],
    }
    assert network.kubelet_policy_patch(value, {"10.0.1.128"}, "fixture-owner") == []


@pytest.mark.parametrize(
    "change", ["owner", "namespace", "selector", "port", "cidr", "destination"]
)
def test_reconcile_refuses_unowned_or_widened_contracts(change: str) -> None:
    value = policy()
    if change == "owner":
        value["metadata"]["labels"]["identity-demo-owner"] = "someone-else"
    elif change == "namespace":
        value["metadata"]["namespace"] = "someone-else"
    elif change == "selector":
        value["spec"]["podSelector"] = {}
    elif change == "port":
        value["spec"]["egress"][0]["ports"][0]["port"] = 443
    elif change == "cidr":
        value["spec"]["egress"][0]["to"][0]["ipBlock"]["cidr"] = "10.0.0.0/8"
    else:
        value["spec"]["egress"][0]["to"] = [{"namespaceSelector": {}}]
    with pytest.raises(ValueError):
        network.kubelet_policy_patch(value, {"10.0.1.16"}, "fixture-owner")
