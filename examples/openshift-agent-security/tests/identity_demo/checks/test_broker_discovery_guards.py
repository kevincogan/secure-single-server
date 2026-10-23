# SPDX-License-Identifier: Apache-2.0
"""Offline boundaries for the disposable discovery probe; no cluster access."""

from __future__ import annotations

import argparse
import subprocess
from unittest.mock import patch

import pytest

import probe_broker_discovery as probe


def test_discovery_manifest_is_exactly_namespaced_and_owned() -> None:
    """All probe objects belong to the recorded owned namespace."""
    item = probe.manifest("v1", "Secret", probe.NAME + "-grant")
    assert item["metadata"]["namespace"] == probe.NS
    assert item["metadata"]["labels"] == probe.LABELS


@pytest.mark.parametrize("name", ["fixture-jira", probe.NAME + "evil", "other-owner"])
def test_other_resource_names_rejected(name: str) -> None:
    """The diagnostic cannot repurpose another fixture name."""
    with pytest.raises(ValueError):
        probe.manifest("v1", "Secret", name)


@pytest.mark.parametrize("server,label", [
    ("https://other.invalid", "owned-check"),
    (probe.SERVER, "../escape"),
])
def test_invalid_inputs_rejected_before_any_cluster_operation(server: str, label: str) -> None:
    """Wrong cluster or an escaping evidence label cannot reach Kubernetes."""
    args = argparse.Namespace(expected_server=server, label=label)
    with patch.object(probe, "kube", side_effect=AssertionError("Cluster reached")):
        with pytest.raises(ValueError):
            probe.run(args)


def test_cluster_error_withholds_response_and_credential() -> None:
    """Subprocess responses cannot disclose a credential in probe exceptions."""
    args = argparse.Namespace(kubeconfig="/private/kubeconfig")
    response = subprocess.CompletedProcess([], 1, "synthetic-private-response",
                                           "synthetic-private-credential")
    with patch.object(probe.subprocess, "run", return_value=response):
        with pytest.raises(RuntimeError) as failure:
            probe.kube(args, "create", "-f", "-", payload={"token": "synthetic-private-token"})
    assert "synthetic-private" not in str(failure.value)


@pytest.mark.parametrize("grace", [-1, 121])
def test_observation_window_cannot_be_unbounded(grace: int) -> None:
    """Extended observation changes no token lifetime and remains bounded."""
    args = argparse.Namespace(expected_server=probe.SERVER, label="owned-check",
                              observation_grace_seconds=grace)
    with patch.object(probe, "kube", side_effect=AssertionError("Cluster reached")):
        with pytest.raises(ValueError):
            probe.run(args)


@pytest.mark.parametrize("wrong_parent,ready", [(False, True), (True, True), (False, False)])
def test_broker_observation_requires_owned_controller_chain(wrong_parent: bool, ready: bool) -> None:
    """A Pod label alone cannot authorize reading another broker's configuration."""
    extension = {"metadata": {"uid": "owned-extension"}}
    deployment = {"metadata": {"uid": "deployment", "ownerReferences": [
        {"controller": True, "uid": "different-owner" if wrong_parent else "owned-extension"}]}}
    replicas = {"items": [{"metadata": {"uid": "replica", "ownerReferences": [
        {"controller": True, "uid": "deployment"}]}}]}
    pod = {"metadata": {"name": "broker", "uid": "pod", "ownerReferences": [
        {"controller": True, "uid": "replica"}]}, "status": {
            "phase": "Running", "containerStatuses": [{"ready": ready}]}}
    with patch.object(probe, "owned", return_value=extension), patch.object(
        probe, "kube", side_effect=[deployment, replicas, {"items": [pod]}],
    ):
        if wrong_parent or not ready:
            with pytest.raises(ValueError):
                probe.broker_pod(argparse.Namespace())
        else:
            assert probe.broker_pod(argparse.Namespace())["metadata"]["uid"] == "pod"
