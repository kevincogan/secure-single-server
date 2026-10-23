# SPDX-License-Identifier: Apache-2.0
"""Replay diagnostics use explicit installation trust without skipping TLS."""

from pathlib import Path
from types import SimpleNamespace

import pytest

import native_sender_acceptance as sender


@pytest.mark.parametrize("port", [19443, 19444])
def test_bound_listener_adds_only_explicit_application_ca(
        monkeypatch: pytest.MonkeyPatch, port: int) -> None:
    """Both historical service trust and fresh application trust remain usable."""
    calls = []
    context = SimpleNamespace(
        load_verify_locations=lambda **kw: calls.append(("application", kw)),
        set_alpn_protocols=lambda values: calls.append(("alpn", values)),
    )

    def ssl_context(**kwargs: object) -> SimpleNamespace:
        """Record public roots without creating a permissive SSL context."""
        calls.append(("platform", kwargs))
        return context

    def stop(*args: object, **kwargs: object) -> None:
        """No actual socket or test credential is used by this regression."""
        raise RuntimeError("stop-before-network")

    monkeypatch.setattr(sender.ssl, "create_default_context", ssl_context)
    monkeypatch.setattr(sender.socket, "create_connection", stop)
    probe = sender.SenderAcceptance.__new__(sender.SenderAcceptance)
    probe.ca, probe.native_ca = Path("/private/platform.pem"), Path("/private/application.pem")
    with pytest.raises(RuntimeError, match="stop-before-network"):
        probe._request_once(port, "owned.example", "/mcp", b"{}", None, {})
    assert ("platform", {"cafile": "/private/platform.pem"}) in calls
    extra = [(kind, value) for kind, value in calls if kind == "application"]
    assert extra == ([("application", {"cafile": "/private/application.pem"})] if port == 19444 else [])
