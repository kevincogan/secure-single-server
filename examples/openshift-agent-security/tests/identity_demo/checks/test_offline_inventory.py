# SPDX-License-Identifier: Apache-2.0
"""Inventory fields cannot expose environment/Secret data or claim offline proof."""

import json

import pytest

from identity_demo_offline_inventory import endpoints, image_inventory


def test_source_inventory_contains_complete_pinned_build_inputs() -> None:
    """A Python-only inventory must not omit native recipes or Go diagnostics."""
    import identity_demo_offline_inventory as inventory

    sources = inventory.source_inventory()
    paths = [value["path"] for value in sources]
    assert set(inventory.BUILD_INPUTS) <= set(paths)
    assert len(paths) == len(set(paths))
    assert all(len(value["sha256"]) == 64 for value in sources)


@pytest.mark.parametrize("fault", ["missing", "symlink"])
def test_source_inventory_refuses_incomplete_or_external_build_input(tmp_path, monkeypatch, fault) -> None:
    """Incomplete packaging cannot silently claim to inventory the full build."""
    import identity_demo_offline_inventory as inventory

    monkeypatch.setattr(inventory, "ROOT", tmp_path)
    for name in inventory.BUILD_INPUTS:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic")
    target = tmp_path / inventory.BUILD_INPUTS[0]
    target.unlink()
    if fault == "symlink":
        target.symlink_to(tmp_path / inventory.BUILD_INPUTS[1])
    with pytest.raises(ValueError, match="build inputs"):
        inventory.source_inventory()


def test_image_inventory_excludes_env_and_identifies_unpinned_references() -> None:
    """Keep only image/pull-policy references, not credentials from pod specs."""
    pod = {"kind": "Pod", "metadata": {"name": "owned", "namespace": "demo-triage"},
        "spec": {"containers": [{"name": "client", "image": "example/client:latest",
            "env": [{"name": "SECRET", "value": "must-not-appear"}]}]}}
    result = image_inventory([pod])
    assert not result[0]["digest_pinned"]
    assert "must-not-appear" not in json.dumps(result)


def test_unowned_namespace_inventory_rejected() -> None:
    """Do not widen the read/export contract to shared application namespaces."""
    with pytest.raises(ValueError):
        image_inventory([{"kind": "Pod", "metadata": {"name": "other", "namespace": "other-team"}, "spec": {}}])


@pytest.mark.parametrize("url", ["http://service.local", "https://user:password@service.local",
    "https://service.local?token=secret", "https://service.local#secret"])
def test_inline_credentials_or_non_https_endpoint_rejected(url: str) -> None:
    """The private endpoint file is a URL inventory, not a secret transport."""
    with pytest.raises(ValueError):
        endpoints({"chat": url})


def test_fixed_private_endpoints_accepted_without_inventing_approval() -> None:
    """Validation establishes shape only, not reachability or bank approval."""
    assert endpoints({"chat": "https://inference.example.test/v1"}) == {"chat": "https://inference.example.test/v1"}
