# SPDX-License-Identifier: Apache-2.0
"""Operator workspace rendering preserves ownership and bounded permissions."""

from copy import deepcopy
import tomllib

import pytest
from identity_demo_lab import LABELS
from identity_demo_workspaces import (
    ACCOUNT,
    PLATFORM,
    WORKSPACES,
    operator_config,
    render,
)


def baseline() -> tuple[dict, dict]:
    """Return an inert synthetic baseline with no credentials."""
    meta = {
        "name": "fixture-openshell-config",
        "namespace": PLATFORM,
        "labels": dict(LABELS),
    }
    cm = {
        "metadata": meta,
        "data": {
            "gateway.toml": '[openshell.drivers.kubernetes]\nworkspace_mode = "shared"\nservice_account_name = "fixture-openshell-sandbox"\nallow_driver_config = false\n[openshell.gateway]\ndisable_tls = false\n'
        },
    }
    st = {
        "metadata": {**deepcopy(meta), "name": "fixture-openshell"},
        "spec": {"template": {"spec": {"containers": [{"volumeMounts": []}]}}},
    }
    return cm, st


def test_namespace_accounts_have_no_rbac() -> None:
    """Runtime mutation and image-pull grants belong to separate principals."""
    items = render(
        [
            {
                "apiGroups": ["agents.x-k8s.io"],
                "resources": ["sandboxes"],
                "verbs": ["create"],
            }
        ]
    )
    accounts = [v for v in items if v["kind"] == "ServiceAccount"]
    assert [(v["metadata"]["namespace"], v["metadata"]["name"]) for v in accounts] == [
        (n, ACCOUNT) for n in WORKSPACES
    ]
    assert all(v["automountServiceAccountToken"] is False for v in accounts)
    cluster = next(v for v in items if v["kind"] == "ClusterRole")
    assert cluster["rules"][0] == {
        "apiGroups": ["agents.x-k8s.io"],
        "resources": ["sandboxes"],
        "verbs": ["list", "watch"],
    }
    assert all(
        set(v["metadata"].get("namespace", PLATFORM) for v in items)
        <= {*WORKSPACES, PLATFORM}
        for _ in [0]
    )
    for v in items:
        if v["kind"] == "RoleBinding" and v["metadata"]["namespace"] in WORKSPACES:
            assert v["subjects"] == [
                {
                    "kind": "ServiceAccount",
                    "name": "fixture-openshell",
                    "namespace": PLATFORM,
                }
            ]


def test_config_preserves_baseline() -> None:
    """The selected supported mode does not enable untrusted driver overrides."""
    cm, st = baseline()
    before = deepcopy((cm, st))
    new, deployment = operator_config(cm, st)
    cfg = tomllib.loads(new["data"]["gateway.toml"])["openshell"]
    assert cfg["drivers"]["kubernetes"]["workspace_mode"] == "operator"
    assert cfg["drivers"]["kubernetes"]["allow_driver_config"] is False
    assert cfg["gateway"]["disable_tls"] is False
    assert (cm, st) == before
    assert (
        deployment["spec"]["template"]["spec"]["containers"][0]["volumeMounts"][0][
            "readOnly"
        ]
        is True
    )


@pytest.mark.parametrize("change", ["owner", "namespace", "mode", "override", "mount"])
def test_config_refuses_drift(change: str) -> None:
    """Do not repurpose another owner's gateway or weaken its baseline."""
    cm, st = baseline()
    if change == "owner":
        cm["metadata"]["labels"]["identity-demo-owner"] = "other"
    if change == "namespace":
        st["metadata"]["namespace"] = "other"
    if change == "mode":
        cm["data"]["gateway.toml"] = cm["data"]["gateway.toml"].replace(
            '"shared"', '"managed"'
        )
    if change == "override":
        cm["data"]["gateway.toml"] = cm["data"]["gateway.toml"].replace("false", "true")
    if change == "mount":
        st["spec"]["template"]["spec"]["containers"][0]["volumeMounts"] = [
            {"mountPath": "/etc/openshell/workspaces"}
        ]
    with pytest.raises(ValueError):
        operator_config(cm, st)


def test_wildcard_grants_refused() -> None:
    """No wildcard role can enter the workspace render."""
    with pytest.raises(ValueError):
        render([{"apiGroups": [""], "resources": ["*"], "verbs": ["get"]}])


def test_internal_issuer_ingress_is_only_the_two_supervisor_peers() -> None:
    """The final native exchange must reach Keycloak without opening unrelated ingress."""
    items = render(
        [
            {
                "apiGroups": ["agents.x-k8s.io"],
                "resources": ["sandboxes"],
                "verbs": ["create"],
            }
        ]
    )
    policy = next(
        v for v in items if v["metadata"]["name"] == "identity-demo-workspace-issuer"
    )
    assert policy["metadata"]["namespace"] == PLATFORM
    assert policy["spec"]["podSelector"] == {
        "matchLabels": {"app": "fixture-keycloak-upstream"}
    }
    ingress = policy["spec"]["ingress"][0]
    assert ingress["ports"] == [{"port": 8443, "protocol": "TCP"}]
    assert {
        p["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"]
        for p in ingress["from"]
    } == set(WORKSPACES)
    assert all(
        p["podSelector"]["matchLabels"]["openshell.ai/boundary-role"] == "supervisor"
        for p in ingress["from"]
    )
