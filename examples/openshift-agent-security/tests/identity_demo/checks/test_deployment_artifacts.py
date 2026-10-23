# SPDX-License-Identifier: Apache-2.0
"""An operator-supplied artifact lock cannot expand a native image allowlist."""

import json
from pathlib import Path

import pytest

from deployment_artifacts import IMAGE_ROLES, configured_native_image, validate_artifacts
from deployment_profile import LEGACY


def artifact_lock() -> dict:
    """Return only synthetic public artifact references and native endpoints."""
    return {"schema_version": 1,
            "images": {role: "registry.example/" + role + "@sha256:" + "a" * 64
                       for role in IMAGE_ROLES},
            "native_build_contract": LEGACY.native_build_contract,
            "native_ca_bundle_sha256": "b" * 64}


@pytest.mark.parametrize("image", ["registry.example/app:latest", "https://registry.example/app@sha256:" + "a" * 64,
    "user:password@registry.example/app@sha256:" + "a" * 64, "registry.example/app@sha256:bad",
    "registry.example/app\n@sha256:" + "a" * 64, "registry.example/../app@sha256:" + "a" * 64])
def test_ambiguous_image_inputs_refused(image: str) -> None:
    """Tags, credential-bearing URLs and noncanonical references are rejected."""
    value = artifact_lock()
    value["images"]["openshell_gateway"] = image
    with pytest.raises(ValueError):
        validate_artifacts(value)


def test_exact_artifact_contract_required(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Native helpers permit only the locked digest for their current installation."""
    path = tmp_path / "artifacts.json"
    value = artifact_lock()
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    monkeypatch.setenv("IDENTITY_DEMO_ARTIFACTS", str(path))
    assert configured_native_image("openshell_gateway") == value["images"]["openshell_gateway"]
    value["native_build_contract"]["OPENSHELL_DEMO_TRUST_DOMAIN"] = "other.example.org"
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="different native build contract"):
        configured_native_image("openshell_gateway")


def test_unsafe_or_duplicate_lock_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A writable or ambiguous lock cannot authorize new native images."""
    path = tmp_path / "artifacts.json"
    path.write_text(json.dumps(artifact_lock()))
    path.chmod(0o666)
    monkeypatch.setenv("IDENTITY_DEMO_ARTIFACTS", str(path))
    with pytest.raises(ValueError):
        configured_native_image("openshell_supervisor")
    path.chmod(0o600)
    path.write_text('{"schema_version":1,"schema_version":2}')
    with pytest.raises(ValueError, match="Duplicate"):
        configured_native_image("openshell_supervisor")


def test_no_lock_adds_no_allowed_image(monkeypatch: pytest.MonkeyPatch) -> None:
    """A missing native build does not create an implicit arbitrary-image fallback."""
    monkeypatch.delenv("IDENTITY_DEMO_ARTIFACTS", raising=False)
    assert configured_native_image("openshell_gateway") is None
