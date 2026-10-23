# SPDX-License-Identifier: Apache-2.0
"""Offline origin/path guards for the approved development issuer helper."""

from pathlib import Path
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts" / "identity_demo"))
import identity_demo_keycloak_upstream as upstream  # noqa: E402


@pytest.mark.parametrize(
    "base,path,method",
    [
        ("https://other.example.invalid", "/admin/realms/identity-demo/clients", "GET"),
        (
            upstream.BASE.replace("https://", "http://"),
            "/admin/realms/identity-demo/clients",
            "GET",
        ),
        (upstream.BASE + ":443", "/admin/realms/identity-demo/clients", "GET"),
        (upstream.BASE, "/admin/realms/other/clients", "GET"),
        (upstream.BASE, "/admin/realms/identity-demo/../other", "GET"),
        (upstream.BASE, "/admin/realms/identity-demo/%2e%2e/other", "GET"),
        (
            upstream.BASE,
            "//other.example.invalid/admin/realms/identity-demo/clients",
            "GET",
        ),
        (upstream.BASE, "/admin/realms/identity-demo/clients#fragment", "GET"),
        (upstream.BASE, "/admin/realms/identity-demo/clients", "PATCH"),
    ],
)
def test_issuer_guard_rejects_before_network(base: str, path: str, method: str) -> None:
    """Unapproved origins, realms, traversal and methods cannot reach HTTP."""
    with patch.object(
        upstream, "build_opener", side_effect=AssertionError("Network reached")
    ):
        with pytest.raises(ValueError):
            upstream.issuer_request(base, path, method=method)
