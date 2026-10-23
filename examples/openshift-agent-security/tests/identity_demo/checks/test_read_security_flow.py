# SPDX-License-Identifier: Apache-2.0
"""Check live acceptance assertions using synthetic boundaries only."""

from __future__ import annotations

import argparse
import json
import time
from types import SimpleNamespace

import pytest

import read_security_flow as security


@pytest.mark.parametrize("fault", [None, "revocation_allowed", "expired_token", "expired_leaf", "parser_allowed"])
def test_security_gate_requires_real_denials_and_unexpired_control(
    tmp_path, monkeypatch, fault: str | None
) -> None:
    """Expired credentials or an accepted malicious call cannot prove revocation."""
    flow = security.ReadSecurityFlow.__new__(security.ReadSecurityFlow)
    flow.args = argparse.Namespace(label="synthetic", output_dir=tmp_path, driver_credentials_file="private")
    flow.run_id, flow.user = "a" * 32, "user"
    flow.backend_count = lambda: 1
    closed = []
    flow.close = lambda: closed.append(True)
    context = SimpleNamespace(workload="controlled-workload")
    revoked = False
    report = ""
    certificate_names = []

    def http(url: str, **kwargs: object) -> tuple[int, dict, bytes]:
        nonlocal revoked, report
        if "/credentials/" in url:
            return (403, {}, b"{}") if revoked else (200, {}, b'{"access_token":"synthetic"}')
        if url.endswith("/report"):
            report = kwargs["value"]["assessment"]
            return 200, {}, b"{}"
        if url.endswith("/revoke"):
            revoked = True
            return 200, {}, b'{"revoked_runs":1}'
        return 200, {}, report.encode()

    flow.http = http

    class Sender:
        """Emulate only assertion boundaries; never issue real credentials."""

        def __init__(self, *args: object) -> None:
            pass

        def run(self) -> dict:
            return {"passed": True}

        def certificate(self, name: str) -> object:
            certificate_names.append(name)
            return SimpleNamespace(expires_at=time.time() + (
                -1 if fault == "expired_leaf" and name == "revocation-control" else 300))

        def final(self, leaf: object) -> tuple[str, dict]:
            return "synthetic", {"exp": time.time() + (-1 if fault == "expired_token" else 30)}

        def initialize_session(self, *args: object) -> dict:
            return {}

        def request(self, port: int, host: str, path: str, body: bytes, *args: object) -> tuple[int, bytes]:
            return (200 if fault == "parser_allowed" else 413 if len(body) > 65_536 else 403), b"{}"

        def gateway(self, name: str, *args: object) -> dict:
            return {"http_status": 200 if name == "before_operator_revocation" or fault == "revocation_allowed" else 403}

    class Viewer:
        """Model a second authenticated session which cannot view the first run."""

        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def authenticate(self) -> None:
            pass

        def http(self, url: str) -> tuple[int, dict, bytes]:
            return 403, {}, b'{"reason":"run_binding"}'

    monkeypatch.setattr(security, "SenderAcceptance", Sender)
    monkeypatch.setattr(security, "PermissionFlow", Viewer)
    if fault:
        with pytest.raises(AssertionError):
            flow.accept(None, "controlled-resource", context)
        assert not closed
    else:
        result = flow.accept(None, "controlled-resource", context)
        assert result["passed"] and len(result["cases"]) == 7
        assert closed == [True]
        saved = json.loads((tmp_path / "synthetic.read-security.summary.json").read_text())
        assert saved["backend_before"] == saved["backend_after"] == 1
        assert not saved["steps5_and6_complete"]
        assert certificate_names == ["parser-controls", "parser-duplicate_json_key", "parser-malformed_json",
            "parser-unsupported_batch", "parser-oversized_body", "parser-unregistered_mutation_tool",
            "revocation-control"]
