# SPDX-License-Identifier: Apache-2.0
"""Validate safe live audit metadata for the complete protected read."""

from __future__ import annotations

import base64
import json
import re
import subprocess
import time

from native_backend import NativeBackend
from run_binding import ReadRun
from deployment_profile import active_profile


class AuditPending(ValueError):
    """A successful streamed request has not yet emitted its access log."""


def assess(lines: str, run: ReadRun) -> dict:
    """Require a successful real TLS hop with matching verified cnf and run."""
    matched = []
    for line in lines.splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        metadata = value.get("verified")
        if value.get("event") != "step4-private-read" or not isinstance(metadata, dict):
            continue
        if metadata.get("run") != run.run_id:
            continue
        if set(value) - {"event", "status", "detail", "upstream", "request", "peer_hash", "verified",
                         "denied_identity", "denied_peer", "denied_grant"}:
            raise ValueError("Unexpected fields in scoped audit record")
        if set(metadata) != {"cnf", "expiry", "policy", "run", "user", "workload"}:
            raise ValueError("Unexpected verified metadata; refuse credential leakage")
        if (metadata["user"] != run.user_subject or metadata["workload"] != run.workload
                or metadata["policy"] != "step4-protected-read" or metadata["expiry"] > run.expires_at
                or not re.fullmatch(r"[A-Za-z0-9_-]{43}", metadata["cnf"])):
            raise ValueError("Audit identity does not match the trusted run")
        expected_hash = base64.urlsafe_b64decode(metadata["cnf"] + "=").hex()
        if value.get("peer_hash"):
            if value["peer_hash"].replace(":", "").lower() != expected_hash:
                raise ValueError("Signed certificate binding does not match the actual TLS peer")
            if str(value.get("status")) == "200" and value.get("request"):
                matched.append(value)
    if not matched:
        raise AuditPending("No successful native TLS read with correlated verified metadata")
    return {"passed": True, "successful_bound_read_records": len(matched),
            "actual_tls_peer_equals_signed_cnf": True, "verified_user_workload_run_correlated": True,
            "request_identifiers_present": True, "allowlisted_fields_only": True,
            "credential_or_body_fields_logged": False}


def check(backend: NativeBackend, run: ReadRun) -> dict:
    """Read only the owned gateway logs and retain raw evidence privately."""
    deadline, attempt = time.monotonic() + 30, 0
    while time.monotonic() < deadline:
        attempt += 1
        result = subprocess.run(["oc", "--kubeconfig=" + backend.args.kubeconfig, "--request-timeout=10s",
            "-n", active_profile().core_namespace, "logs", "deployment/fixture-mcp-openshift-ai-inference",
            "-c", "istio-proxy", "--since=15m", "--tail=2000"], capture_output=True, text=True, timeout=15)
        backend.save("audit-" + str(attempt) + ".private.json", {
            "exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
        if result.returncode:
            raise RuntimeError("Owned gateway audit read failed")
        try:
            summary = assess(result.stdout, run)
        except AuditPending:
            time.sleep(1)
            continue
        summary["log_read_attempts"] = attempt
        backend.save("audit.summary.json", summary)
        return summary
    raise AuditPending("Correlated bound access log did not arrive within the bounded wait")
