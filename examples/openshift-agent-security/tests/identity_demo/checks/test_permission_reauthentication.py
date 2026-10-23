# SPDX-License-Identifier: Apache-2.0
"""Browser harness accepts Keycloak SSO redirects without bypassing callbacks."""

import pytest

from identity_demo_action_policy import DRIVER
from identity_demo_keycloak_upstream import BASE
from permission_flow import PermissionFlow


def test_existing_sso_session_completes_driver_callback() -> None:
    """A restart loses driver state but need not lose the browser's issuer session."""
    flow = object.__new__(PermissionFlow)
    calls = []
    replies = iter([
        (302, {"Location": BASE + "/protocol/openid-connect/auth"}, b""),
        (302, {"Location": DRIVER + "/callback?code=opaque&state=opaque"}, b""),
        (303, {}, b""),
        (200, {}, b'<form><input type="hidden" name="csrf" value="new-session-csrf"></form>'),
    ])

    def http(url, **kwargs):
        calls.append(url)
        return next(replies)

    flow.http = http
    flow.authenticate()
    assert flow.csrf == "new-session-csrf"
    assert calls[2].startswith(DRIVER + "/callback?") and calls[-1] == DRIVER + "/"


def test_sso_requires_exact_driver_callback() -> None:
    """An unexpected issuer redirect cannot skip the driver's state/nonce validation."""
    flow = object.__new__(PermissionFlow)
    replies = iter([
        (302, {"Location": BASE + "/protocol/openid-connect/auth"}, b""),
        (302, {"Location": "https://untrusted.example/callback?code=opaque"}, b""),
    ])
    flow.http = lambda *args, **kwargs: next(replies)
    with pytest.raises(AssertionError):
        flow.authenticate()
