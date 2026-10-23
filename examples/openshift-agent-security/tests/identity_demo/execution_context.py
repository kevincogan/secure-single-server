# SPDX-License-Identifier: Apache-2.0
"""Exact execution contexts, supplied by the trusted deployment owner."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Callable
from uuid import UUID
from deployment_profile import active_profile, LEGACY
from deployment_artifacts import configured_native_image

RETIRED_ID = "00000000-0000-4000-8000-000000000001"
DOMAIN = active_profile().trust_domain
from identity_demo_spire_registration import CVE_IMAGE
from deployment_profile import in_source_checkout
SUPERVISOR_IMAGES = {
    "ghcr.io/nvidia/openshell/supervisor@sha256:4ab2b970cdb02c7518ba4ccbbadb4861ae9a8d0b8770e5b160697f0453b0a8e4",
    "image-registry.openshift-image-registry.svc:5000/demo-core/fixture-openshell-sender@sha256:ad582fdc34c8aa1389345e0c110cc16bfdef86853e7401067ba9cb43b5d8f007",
} if active_profile() == LEGACY else set()
if configured_native_image("openshell_supervisor"):
    SUPERVISOR_IMAGES.add(configured_native_image("openshell_supervisor"))


@dataclass(frozen=True)
class ExecutionContext:
    """One immutable native sandbox identity and its controlled role mapping."""

    sandbox_name: str
    sandbox_id: str
    role: str
    service_account: str
    registration_name: str
    provider_prefix: str
    namespace: str = active_profile().core_namespace
    workspace: str = "default"

    @property
    def resource_name(self) -> str:
        """Use the resource naming contract of the selected namespace mode."""
        return (
            "default--" + self.sandbox_name
            if self.workspace == "default"
            else self.sandbox_name
        )

    @property
    def workload(self) -> str:
        """Return the canonical identity checked by the patched native gateway."""
        return f"spiffe://{DOMAIN}/openshell/sandbox/{self.sandbox_id}"


def legacy_context() -> ExecutionContext:
    """Describe the historical context without waiving its retirement guard."""
    return ExecutionContext(
        "fixture-cve-spiffe",
        RETIRED_ID,
        "triage",
        "fixture-openshell-sandbox",
        "identity-demo-openshell-cve-test",
        "fixture-native-exchange-step4",
    )


def context_of(args: object) -> ExecutionContext:
    """Keep diagnostic context local to its arguments, never process globals."""
    return getattr(args, "execution_context", None) or legacy_context()


def resolve_context(path: str, read: Callable[..., dict]) -> ExecutionContext:
    """Validate a private fresh context against native ownership and registration."""
    location = Path(path)
    if (
        location.is_symlink()
        or location.stat().st_mode & 0o077
        or in_source_checkout(location)
    ):
        raise ValueError("Private owner-supplied context required")
    value = json.loads(location.read_text())
    return validate_context(value, read)


def context_identity(value: dict) -> ExecutionContext:
    """Validate immutable context fields even after its native resources are retired."""
    context = ExecutionContext(**value)
    if (
        str(UUID(context.sandbox_id)) != context.sandbox_id
        or context.sandbox_id == RETIRED_ID
        or context.role not in ("triage", "reader")
        or context.service_account != "fixture-openshell-sandbox"
        or context.namespace != active_profile().namespace_for(context.role)
        or context.workspace != context.namespace
        or not re.fullmatch(
            r"demo-s56-(triage|reader)-[a-z0-9-]{1,3}", context.sandbox_name
        )
        or not context.sandbox_name.startswith("demo-s56-" + context.role + "-")
        or not re.fullmatch(
            r"identity-demo-step56-[a-z0-9-]{1,40}", context.registration_name
        )
        or context.provider_prefix != context.sandbox_name + "-exchange"
    ):
        raise ValueError("Exact fresh execution identity and role required")
    return context


def validate_context(value: dict, read: Callable[..., dict]) -> ExecutionContext:
    """Validate an operator-supplied mapping against the same exact native resources."""
    context = context_identity(value)
    namespace = read("namespace", context.namespace, None)
    if namespace["metadata"].get("labels", {}).get("identity-demo-owner") != active_profile().owner:
        raise ValueError("Owned execution namespace required")
    sandbox = read(
        "sandboxes.agents.x-k8s.io", context.resource_name, context.namespace
    )
    labels = sandbox["metadata"].get("labels", {})
    if (
        labels.get("openshell.ai/gateway-id") != active_profile().gateway_id
        or labels.get("openshell.ai/managed-by") != "openshell"
        or labels.get("openshell.ai/sandbox-id") != context.sandbox_id
        or sandbox["spec"]["podTemplate"]["spec"].get("serviceAccountName")
        != context.service_account
    ):
        raise ValueError("Native workload association mismatch")
    workload = read("pod", sandbox["metadata"]["name"], context.namespace)
    if (
        workload["spec"].get("serviceAccountName") != context.service_account
        or workload["spec"].get("automountServiceAccountToken") is not False
        or len(workload["spec"].get("containers", [])) != 1
        or workload["spec"]["containers"][0].get("image") != CVE_IMAGE
        or not any(
            v.get("uid") == sandbox["metadata"]["uid"]
            for v in workload["metadata"].get("ownerReferences", [])
        )
    ):
        raise ValueError("Separate tokenless workload ServiceAccount required")
    supervisor = read("pod", "os-supervisor-" + context.sandbox_id, context.namespace)
    statuses = supervisor.get("status", {}).get("containerStatuses", [])
    if (
        supervisor["spec"].get("serviceAccountName") != context.service_account
        or supervisor["spec"].get("automountServiceAccountToken") is not False
        or len(supervisor["spec"].get("containers", [])) != 1
        or supervisor["spec"]["containers"][0].get("name") != "supervisor"
        or supervisor["spec"]["containers"][0].get("image") not in SUPERVISOR_IMAGES
        or len(statuses) != 1
        or not statuses[0].get("ready")
        or "@sha256:" not in statuses[0].get("imageID", "")
    ):
        raise ValueError("Reviewed ready native supervisor required")
    if not any(v.get("uid") == sandbox["metadata"]["uid"]
               for v in supervisor["metadata"].get("ownerReferences", [])):
        raise ValueError("Exact native supervisor owner required")
    from identity_demo_controller_identity import enabled, verify
    if enabled():
        labels = supervisor['metadata'].get('labels', {})
        if (labels.get('openshell.ai/sandbox-id') != context.sandbox_id
                or labels.get('openshell.ai/boundary-pair') != context.sandbox_id
                or labels.get('openshell.ai/boundary-role') != 'supervisor'
                or labels.get('openshell.ai/gateway-id') != active_profile().gateway_id
                or labels.get('openshell.ai/managed-by') != 'openshell'
                or statuses[0]['imageID'] != supervisor['spec']['containers'][0]['image']):
            raise ValueError('Exact controller-selected supervisor association required')
        verify(context, read)
        return context
    registration = read(
        "clusterstaticentries.spire.spiffe.io", context.registration_name, None
    )
    selectors = registration["spec"]["selectors"]
    expected_selectors = {
        "k8s:ns:" + context.namespace,
        "k8s:sa:" + context.service_account,
        "k8s:pod-uid:" + supervisor["metadata"]["uid"],
        "k8s:container-name:supervisor",
        "k8s:container-image:" + statuses[0]["imageID"],
    }
    if (
        registration["metadata"].get("labels", {}).get("identity-demo-owner")
        != active_profile().owner
        or registration["spec"]["spiffeID"] != context.workload
        or registration["spec"].get("className")
        != "zero-trust-workload-identity-manager-spire"
        or len(selectors) != len(expected_selectors)
        or set(selectors) != expected_selectors
        or "k8s:pod-uid:" + supervisor["metadata"]["uid"] not in selectors
        or "k8s:sa:fixture-openshell-sandbox" not in selectors
        or "k8s:ns:" + context.namespace not in selectors
        or "k8s:container-name:supervisor" not in selectors
        or not any(
            v.get("uid") == sandbox["metadata"]["uid"]
            for v in supervisor["metadata"].get("ownerReferences", [])
        )
    ):
        raise ValueError("Exact controlled supervisor registration required")
    return context
