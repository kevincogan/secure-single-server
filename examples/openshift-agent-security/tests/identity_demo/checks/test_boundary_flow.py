# SPDX-License-Identifier: Apache-2.0
"""Constrain the temporary negative probe without loosening agent policies."""

import pytest

from boundary_flow import manifests, TARGETS, IMAGE
import probe_native_exchange as native


def services() -> dict:
    """Model fixed owned targets; no live credentials or cluster objects."""
    return {key: {"spec": {"selector": {"app": key}}} for key in TARGETS}


@pytest.mark.parametrize("namespace", ["demo-triage", "demo-reader"])
def test_credential_free_probe_scope_and_restricted_security(namespace: str) -> None:
    """Only the new labeled probe gets target egress; no token or secret is mounted."""
    policy, pod = manifests(namespace, "fixture-probe", "nonce", services(), 1000500000)
    assert policy["spec"]["podSelector"] == {"matchLabels": {"identity-demo-boundary-probe": "nonce"}}
    assert policy["spec"]["policyTypes"] == ["Egress"]
    assert pod["spec"]["automountServiceAccountToken"] is False
    assert pod["spec"]["serviceAccountName"] == "fixture-openshell-sandbox"
    assert pod["spec"]["securityContext"]["runAsUser"] == 1000500000
    assert pod["spec"]["securityContext"]["runAsNonRoot"] is True
    assert not pod["spec"].get("hostNetwork")
    assert not pod["spec"].get("hostPID")
    assert pod["spec"]["containers"][0]["image"] == IMAGE
    assert pod["spec"]["containers"][0]["securityContext"]["capabilities"] == {"drop": ["ALL"]}
    assert pod["spec"]["volumes"] == [{"name": "socket", "csi": {"driver": "csi.spiffe.io", "readOnly": True}}]
    assert "openshell.ai/sandbox-id" not in pod["metadata"]["labels"]
    for rule in policy["spec"]["egress"]:
        for peer in rule["to"]:
            assert peer["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"] in (native.NAMESPACE, "openshift-dns")
            assert "ipBlock" not in peer


@pytest.mark.parametrize("namespace", ["default", "openshift-dns", native.NAMESPACE])
def test_unapproved_namespaces_rejected(namespace: str) -> None:
    """The negative harness cannot create infrastructure outside its two owned workspaces."""
    with pytest.raises(ValueError, match="Exact owned boundary scope"):
        manifests(namespace, "fixture-probe", "nonce", services(), 1000500000)


@pytest.mark.parametrize("uid", [0, -1, True, "1000500000"])
def test_invalid_or_privileged_identity_rejected(uid: object) -> None:
    """No root or user-selected privileged numeric identity."""
    with pytest.raises(ValueError):
        manifests("demo-triage", "fixture-probe", "nonce", services(), uid)
