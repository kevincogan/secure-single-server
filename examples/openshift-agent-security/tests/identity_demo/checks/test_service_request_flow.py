# SPDX-License-Identifier: Apache-2.0
"""Focused guards for reuse hooks; these are not live security acceptance."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from permission_flow import PermissionFlow
from service_request_flow import ServiceRequestFlow


def test_service_executes_actual_workload_source() -> None:
    """The non-CVE hook executes the proposal, with no fake CVE acceptance flag."""
    flow = object.__new__(ServiceRequestFlow)
    result = subprocess.run([sys.executable, "-c", flow.proposal_program()],
                            capture_output=True, text=True, check=True, timeout=10)
    report = json.loads(result.stdout)
    flow.validate_report(report)
    source = Path(__file__).resolve().parents[3] / "workloads/agents/service-request-demo/src/client.py"
    assert report["source_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert "assessment_preserved_after_local_denial" not in report
    assert flow.project == "SERVICE" and flow.submission == {"request": "SERVICE-0001"}


@pytest.mark.parametrize("change", [{"user": "forged"}, {"request_id": "CVE-2099-0001"},
                                    {"proposed_create": {"project": "TEST"}}])
def test_untrusted_or_wrong_workflow_report_denied(change: dict) -> None:
    """Proposal fields cannot supply security context or select the CVE project."""
    flow = object.__new__(ServiceRequestFlow)
    valid = {"request_id": "SERVICE-0001", "proposed_create": {"project": "SERVICE"},
             "source_sha256": "a" * 64}
    with pytest.raises(AssertionError):
        flow.validate_report({**valid, **change})


def test_read_and_default_cve_hooks(monkeypatch: object) -> None:
    """Only the workflow/project changes; all requests use the shared transport."""
    import probe_native_exchange as native

    monkeypatch.setattr(native, "read_program", lambda resource, tool, arguments, field: arguments)
    service = object.__new__(ServiceRequestFlow)
    service.run_id = "synthetic-run"
    assert service.read_program("resource")["project"] == "SERVICE"
    cve = object.__new__(PermissionFlow)
    cve.run_id = "synthetic-run"
    assert cve.read_program("resource")["project"] == "TEST"
    assert cve.submission == {"cve": "CVE-2099-0001"}
