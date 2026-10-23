# SPDX-License-Identifier: Apache-2.0
"""Failure diagnostics are exact-context and never store raw credentials/log messages."""

from argparse import Namespace
from types import SimpleNamespace

import native_read_diagnostics as diag
from execution_context import legacy_context


def test_summary_discards_credentials_and_unknown_log_text():
    result = diag.categories(
        "private-password-fixture token exchange failed\nCONNECTION REFUSED\narbitrary user text"
    )
    assert result["exchange_failed"] == 1 and result["upstream_unavailable"] == 1
    assert "private-password" not in str(result) and "arbitrary" not in str(result)


def test_changed_context_is_not_read(monkeypatch):
    monkeypatch.setattr(diag, "resolve_context", lambda *a: object())
    monkeypatch.setattr(
        diag.subprocess,
        "run",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("must not read")),
    )
    result = diag.capture(Namespace(context_file="private"), lambda *a: None)
    assert not result["captured"] and result["failure_kind"] == "ValueError"


def test_verified_supervisor_read_is_bounded_and_only_categories_survive(monkeypatch):
    monkeypatch.setattr(diag, "resolve_context", lambda *a: legacy_context())
    commands = []

    def run(words, **kwargs):
        commands.append(words)
        assert kwargs["timeout"] == 15 and "--limit-bytes=32768" in words
        return SimpleNamespace(
            returncode=0, stdout="private-token-fixture timed out", stderr=""
        )

    monkeypatch.setattr(diag.subprocess, "run", run)
    result = diag.capture(
        Namespace(context_file="private", kubeconfig="private"), lambda *a: None
    )
    assert (
        result["captured"]
        and result["categories"]["timeout"] == 1
        and not result["raw_logs_retained"]
    )
    assert "private-token" not in str(result) and len(commands) == 1


def test_diagnostic_failure_cannot_mask_failure_or_block_cleanup(monkeypatch):
    monkeypatch.setattr(
        diag,
        "resolve_context",
        lambda *a: (_ for _ in ()).throw(RuntimeError("private-fixture-secret")),
    )
    result = diag.capture(Namespace(context_file="private"), lambda *a: None)
    assert not result["captured"] and "private-fixture-secret" not in str(result)



def test_sender_false_flags_do_not_claim_timeout_and_fixed_causes_survive():
    result = diag.categories('Pilot sender HTTP failure: timeout=false request=true\n'
        'Pilot sender grant rejected: final_exchange_failed\n'
        'Pilot sender TLS failure: category=peer_alert\n'
        'Pilot sender IO failure: kind=InvalidData')
    assert result['timeout'] == 0 and result['exchange_failed'] == 1
    assert result['certificate_rejected'] == 1 and result['sender_io_failure'] == 1
    assert result['sender_request_failure'] == 1
