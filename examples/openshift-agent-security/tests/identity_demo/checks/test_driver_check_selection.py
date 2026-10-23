# SPDX-License-Identifier: Apache-2.0
"""Live driver security checks must be explicitly selectable and cannot write."""

import argparse
from pathlib import Path

import pytest

import probe_native_exchange as native


@pytest.mark.parametrize("selection", ["permission", "read-security", "native-renewal"])
def test_driver_gate_selection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, selection: str) -> None:
    """The CLI chooses the actual requested gate before cluster operations."""
    path = tmp_path / "private.json"
    path.write_text("{}")
    path.chmod(0o600)
    args = argparse.Namespace(driver_credentials_file=path, driver_check=selection,
                              demo_user="analyst", enable_create=False)
    import permission_flow
    import read_security_flow
    import native_renewal_flow

    selected = []

    def construct(args: argparse.Namespace, path: Path, *, username: str) -> str:
        """Record the selected class without reading credentials or making calls."""
        selected.append((path, username))
        return selection

    module, name = {"permission": (permission_flow, "PermissionFlow"),
                    "read-security": (read_security_flow, "ReadSecurityFlow"),
                    "native-renewal": (native_renewal_flow, "NativeRenewalFlow")}[selection]
    monkeypatch.setattr(module, name, construct)
    assert native.driver_flow(args) == selection
    assert selected == [(path, "analyst")]


@pytest.mark.parametrize("mode", ["no-credentials", "write", "viewer"])
@pytest.mark.parametrize("selection", ["read-security", "native-renewal"])
def test_read_security_refuses_invalid_configuration(mode: str, selection: str) -> None:
    """A read-only suite cannot silently run write acceptance or another user."""
    args = argparse.Namespace(driver_credentials_file=None if mode == "no-credentials" else Path("unused"),
        driver_check=selection, enable_create=mode == "write",
        demo_user="viewer" if mode == "viewer" else "analyst")
    with pytest.raises(ValueError):
        native.driver_flow(args)


def test_legacy_nondriver_gate_still_has_no_flow() -> None:
    """The historical native gate remains unchanged without driver inputs."""
    assert native.driver_flow(argparse.Namespace(driver_credentials_file=None)) is None
