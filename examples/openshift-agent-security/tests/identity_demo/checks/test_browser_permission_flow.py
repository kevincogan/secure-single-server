# SPDX-License-Identifier: Apache-2.0
"""Guard private operator browser evidence and session custody."""

from http.cookiejar import CookieJar
from types import SimpleNamespace

import pytest

from browser_permission_flow import BrowserPermissionFlow
from permission_flow import PermissionFlow
from identity_demo_action_policy import DRIVER
from urllib.parse import urlparse


def flow(cookie: dict) -> BrowserPermissionFlow:
    """Construct a credential-free browser model without starting Chrome."""
    value = object.__new__(BrowserPermissionFlow)
    value.client = SimpleNamespace(handlers=[SimpleNamespace(cookiejar=CookieJar())])
    value.browser_context = SimpleNamespace(cookies=lambda urls: [cookie])
    return value


def cookie() -> dict:
    """Model the driver's protected session, never a real token."""
    return {"name": "session", "value": "synthetic", "domain": urlparse(DRIVER).hostname,
            "secure": True, "httpOnly": True, "path": "/", "expires": -1}


def test_cookie_remains_private_and_exact_host() -> None:
    """Only the real driver session is shared with trusted operator calls."""
    value = flow(cookie())
    value.sync_cookies()
    retained = list(value.client.handlers[0].cookiejar)
    assert len(retained) == 1 and retained[0].secure and retained[0].discard
    assert retained[0].domain == urlparse(DRIVER).hostname


@pytest.mark.parametrize("change", [{"domain": "other.invalid"}, {"secure": False}, {"httpOnly": False}])
def test_wrong_or_unprotected_cookie_rejected(change: dict) -> None:
    """The UI helper never broadens operator credential transport."""
    value = flow({**cookie(), **change})
    with pytest.raises(AssertionError):
        value.sync_cookies()


@pytest.mark.parametrize("url", ["https://other.invalid/", DRIVER + "/callback?code=synthetic"])
def test_login_callback_and_external_screenshots_rejected(url: str) -> None:
    """Do not retain login credentials or callback codes in visual evidence."""
    value = object.__new__(BrowserPermissionFlow)
    value.page = SimpleNamespace(url=url)
    with pytest.raises(AssertionError):
        value.capture("invalid")


def test_presentation_failure_does_not_skip_security_acceptance(tmp_path: object, monkeypatch: object) -> None:
    """A schema-display failure is recorded independently from live permissions."""
    import gateway_overview

    value = object.__new__(BrowserPermissionFlow)
    value.args = SimpleNamespace(output_dir=tmp_path, label="walkthrough-test")
    stages = []
    value.progress = lambda stage, evidence=None: stages.append(stage)

    def unavailable(args: object) -> dict:
        raise RuntimeError("synthetic presentation failure")

    monkeypatch.setattr(gateway_overview, "overview", unavailable)
    monkeypatch.setattr(PermissionFlow, "accept", lambda *args: {"passed": True})
    result = value.accept(None, "synthetic-resource", None)
    assert result["passed"] and not result["gateway_introduction"]["passed"]
    assert result["gateway_introduction"]["failure_kind"] == "RuntimeError"
    assert stages == ["discovering_tools"]  # Failed observation cannot claim tools were discovered.
