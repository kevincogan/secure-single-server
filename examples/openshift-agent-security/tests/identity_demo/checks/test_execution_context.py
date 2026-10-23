# SPDX-License-Identifier: Apache-2.0
"""Fresh run contexts cannot reuse or silently redirect attested identities."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path

import pytest

from execution_context import (
    CVE_IMAGE,
    SUPERVISOR_IMAGES,
    ExecutionContext,
    RETIRED_ID,
    context_of,
    resolve_context,
)


def fixture(tmp_path: Path) -> tuple[ExecutionContext, Path, dict]:
    """Construct synthetic owner records, with no tokens or signing material."""
    context = ExecutionContext(
        "demo-s56-triage-a",
        "761ec75a-a6b0-48a0-af3f-d1e3c3a73415",
        "triage",
        "fixture-openshell-sandbox",
        "identity-demo-step56-triage-a",
        "demo-s56-triage-a-exchange",
        "demo-triage",
        "demo-triage",
    )
    path = tmp_path / "context.json"
    path.write_text(json.dumps(asdict(context)))
    path.chmod(0o600)
    sandbox = {
        "metadata": {
            "name": context.resource_name,
            "uid": "sandbox",
            "labels": {
                "openshell.ai/gateway-id": "fixture-openshell",
                "openshell.ai/managed-by": "openshell",
                "openshell.ai/sandbox-id": context.sandbox_id,
            },
        },
        "spec": {
            "podTemplate": {"spec": {"serviceAccountName": context.service_account}}
        },
    }
    workload = {
        "metadata": {"ownerReferences": [{"uid": "sandbox"}]},
        "spec": {
            "serviceAccountName": context.service_account,
            "automountServiceAccountToken": False,
            "containers": [{"image": CVE_IMAGE}],
        },
    }
    supervisor = {
        "metadata": {"uid": "supervisor", "ownerReferences": [{"uid": "sandbox"}]},
        "spec": {
            "serviceAccountName": context.service_account,
            "automountServiceAccountToken": False,
            "containers": [
                {"name": "supervisor", "image": sorted(SUPERVISOR_IMAGES)[0]}
            ],
        },
        "status": {
            "containerStatuses": [
                {"ready": True, "imageID": "registry/supervisor@sha256:" + "a" * 64}
            ]
        },
    }
    registration = {
        "metadata": {"labels": {"identity-demo-owner": "demo-team"}},
        "spec": {
            "spiffeID": context.workload,
            "className": "zero-trust-workload-identity-manager-spire",
            "selectors": [
                "k8s:pod-uid:supervisor",
                "k8s:sa:fixture-openshell-sandbox",
                "k8s:container-name:supervisor",
                "k8s:ns:demo-triage",
                "k8s:container-image:registry/supervisor@sha256:" + "a" * 64,
            ],
        },
    }
    records = {
        ("namespace", "demo-triage"): {
            "metadata": {"labels": {"identity-demo-owner": "demo-team"}}
        },
        ("sandboxes.agents.x-k8s.io", sandbox["metadata"]["name"]): sandbox,
        ("pod", sandbox["metadata"]["name"]): workload,
        ("pod", "os-supervisor-" + context.sandbox_id): supervisor,
        (
            "clusterstaticentries.spire.spiffe.io",
            context.registration_name,
        ): registration,
    }
    return context, path, records


def test_two_contexts_remain_local_and_do_not_mutate_globals(tmp_path: Path) -> None:
    """Independent worker arguments cannot overwrite another user's context."""
    context, path, records = fixture(tmp_path)
    result = resolve_context(
        str(path), lambda kind, name, namespace=None: records[(kind, name)]
    )
    assert result == context
    first, second = argparse.Namespace(execution_context=result), argparse.Namespace()
    assert context_of(first).sandbox_id != context_of(second).sandbox_id
    assert context_of(second).sandbox_id == RETIRED_ID


@pytest.mark.parametrize(
    "change",
    [
        "retired",
        "role",
        "sa",
        "token",
        "owner",
        "registration",
        "pod_uid",
        "mode",
        "namespace",
        "namespace_selector",
        "image",
        "image_selector",
        "class",
        "supervisor_sa",
    ],
)
def test_fresh_context_rejects_untrusted_or_changed_binding(
    change: str, tmp_path: Path
) -> None:
    """Drift is denied before attaching any provider or changing policy."""
    context, path, records = fixture(tmp_path)
    value = asdict(context)
    if change == "retired":
        value["sandbox_id"] = RETIRED_ID
    if change == "role":
        value["role"] = "admin"
    if change == "namespace":
        value["namespace"] = "another"
    if change == "sa":
        value["service_account"] = "another"
    path.write_text(json.dumps(value))
    worker = records[("pod", context.resource_name)]
    registration = records[
        ("clusterstaticentries.spire.spiffe.io", context.registration_name)
    ]
    if change == "image":
        worker["spec"]["containers"][0]["image"] = "unreviewed/image"
    if change == "image_selector":
        registration["spec"]["selectors"].pop()
    if change == "class":
        registration["spec"]["className"] = "another"
    if change == "supervisor_sa":
        records[("pod", "os-supervisor-" + context.sandbox_id)]["spec"][
            "serviceAccountName"
        ] = "another"
    if change == "token":
        worker["spec"]["automountServiceAccountToken"] = True
    if change == "owner":
        worker["metadata"]["ownerReferences"] = [{"uid": "another"}]
    if change == "registration":
        registration["spec"]["spiffeID"] = "spiffe://another/workload"
    if change == "pod_uid":
        registration["spec"]["selectors"][0] = "k8s:pod-uid:old"
    if change == "namespace_selector":
        registration["spec"]["selectors"].remove("k8s:ns:demo-triage")
    if change == "mode":
        path.chmod(0o644)
    with pytest.raises(ValueError):
        resolve_context(
            str(path), lambda kind, name, namespace=None: records[(kind, name)]
        )
