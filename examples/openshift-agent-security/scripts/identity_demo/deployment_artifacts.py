# SPDX-License-Identifier: Apache-2.0
"""Validate explicit image locks without permitting arbitrary candidate images."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re

from deployment_profile import active_profile, LEGACY

IMAGE_ROLES = {"jira_runtime", "keycloak_management", "keycloak_exchange",
               "openshell_gateway", "openshell_supervisor"}
IMAGE_REFERENCE = re.compile(
    r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?/"
    r"[a-z0-9]+(?:[._/-][a-z0-9]+)*@sha256:[a-f0-9]{64}")


def validate_artifacts(value: dict) -> dict:
    """Require every image role and canonical digest references, never tags/URLs."""
    if (not isinstance(value, dict) or type(value.get("schema_version")) is not int or value["schema_version"] != 1
            or not isinstance(value.get("images"), dict) or set(value["images"]) != IMAGE_ROLES):
        raise ValueError("All reviewed image roles required")
    for image in value["images"].values():
        if (not isinstance(image, str) or len(image) > 512 or not IMAGE_REFERENCE.fullmatch(image)
                or image.endswith("@sha256:" + "0" * 64)):
            raise ValueError("Canonical digest-pinned image required")
    return value


def configured_native_image(role: str) -> str | None:
    """Allow only an exact image from the operator's target-matching lock file."""
    if role not in {"openshell_gateway", "openshell_supervisor"}:
        raise ValueError("Known native artifact role required")
    filename = os.environ.get("IDENTITY_DEMO_ARTIFACTS")
    if not filename:
        return None
    path = Path(filename)
    if (not path.is_absolute() or path.is_symlink() or not path.is_file()
            or path.stat().st_size > 16_384 or path.stat().st_mode & 0o022):
        raise ValueError("Bounded protected artifact lock required")
    def pairs(values: list[tuple]) -> dict:
        result = {}
        for name, value in values:
            if name in result:
                raise ValueError("Duplicate artifact field")
            result[name] = value
        return result
    value = validate_artifacts(json.loads(path.read_text(), object_pairs_hook=pairs))
    if value.get("native_build_contract") != active_profile().native_build_contract:
        raise ValueError("Artifact lock belongs to a different native build contract")
    if not re.fullmatch(r"[a-f0-9]{64}", value.get("native_ca_bundle_sha256", "")):
        raise ValueError("Recorded native public CA hash required")
    return value["images"][role]


def native_supervisor_images() -> set[str]:
    """One approved image set shared by pool admission and native verification."""
    values={
        'ghcr.io/nvidia/openshell/supervisor@sha256:4ab2b970cdb02c7518ba4ccbbadb4861ae9a8d0b8770e5b160697f0453b0a8e4',
        'image-registry.openshift-image-registry.svc:5000/demo-core/fixture-openshell-sender@sha256:ad582fdc34c8aa1389345e0c110cc16bfdef86853e7401067ba9cb43b5d8f007',
    } if active_profile()==LEGACY else set()
    configured=configured_native_image('openshell_supervisor')
    if configured:values.add(configured)
    return values
