# SPDX-License-Identifier: Apache-2.0
"""Fresh run contexts cannot reuse or silently redirect attested identities."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path

import pytest

from execution_context import RETIRED_ID, context_of, resolve_context

from checks.support.execution_context import fixture






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
