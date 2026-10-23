# SPDX-License-Identifier: Apache-2.0
"""Prevent credential-bearing native grant errors from entering safe results."""

from types import SimpleNamespace
from urllib.parse import quote

import pytest

from native_grant_diagnostic import classify, diagnose


@pytest.mark.parametrize("status,message,expected", [
    (9, "provider profile not found", "profile_missing"),
    (9, quote("subject token credential is not configured"), "subject_not_configured"),
    (9, "subject token credential has expired", "subject_expired"),
    (9, "failed to fetch gateway JWT-SVID: secret", "gateway_svid_unavailable"),
    (9, "SPIFFE Workload API unavailable: secret", "gateway_workload_api_unavailable"),
    (9, "provider profile not found secret", "unclassified"),
    (9, "issuer echoed secret", "unclassified"),
    (7, "subject token credential has expired", "unclassified"),
    (0, "secret", "grant_succeeded"),
])
def test_only_known_status_and_static_message_are_classified(
    status: int, message: str, expected: str,
) -> None:
    """Unknown content remains withheld, even when it resembles a known error."""
    assert classify(status, message) == expected


def test_diagnostic_uses_one_real_assertion_and_keeps_raw_error_private(monkeypatch) -> None:
    """Diagnose the native grant once, without retrying a tool or changing state."""
    from contextlib import contextmanager

    context = SimpleNamespace(sandbox_id="exact-sandbox", provider_prefix="exact-provider")
    saved, exchanges = [], []

    class Diagnostic:
        """Supply only the credential diagnostics needed by the helper."""

        native_ca, bootstrap = "trusted-ca", "private-bootstrap"

        def __init__(self, args: object, human: dict) -> None:
            assert human == {"sub": "verified-user"}

        def fetch(self, kind: str) -> dict:
            assert kind == "jwt"
            return {"token": "real-supervisor-assertion"}

        @contextmanager
        def tunnel(self, service: str, port: int, remote: int):
            assert (service, port, remote) == ("fixture-openshell", 19445, 8080)
            yield

        def save(self, name: str, value: dict) -> None:
            saved.append(value)

    def exchange(*args: object, **kwargs: object) -> tuple[int, bytes, str]:
        exchanges.append((args, kwargs))
        return 9, b"private-response", "issuer echoed private-token"

    monkeypatch.setattr("native_grant_diagnostic.SenderAcceptance", Diagnostic)
    monkeypatch.setattr("native_grant_diagnostic.subject.exchange", exchange)
    result = diagnose(SimpleNamespace(execution_context=context), {"sub": "verified-user"})
    assert len(exchanges) == 1
    assert exchanges[0][0][2:] == (
        "exact-sandbox", "exact-provider", "real-supervisor-assertion",
    )
    assert saved[0]["grpc_message"] == "issuer echoed private-token"
    assert result == {
        "grpc_status": 9, "category": "unclassified",
        "tool_call_retried": False, "raw_response_withheld": True,
    }
