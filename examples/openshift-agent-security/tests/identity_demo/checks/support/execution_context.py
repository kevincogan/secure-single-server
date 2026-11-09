# SPDX-License-Identifier: Apache-2.0
"""Shared execution context test setup; contains no collected tests."""
from __future__ import annotations
from dataclasses import asdict
import json
from pathlib import Path
from execution_context import CVE_IMAGE, SUPERVISOR_IMAGES, ExecutionContext

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
