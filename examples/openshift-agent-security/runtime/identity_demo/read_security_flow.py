# SPDX-License-Identifier: Apache-2.0
"""Live read/replay/revocation acceptance on the existing protected native path.

No backend mutation is approved or dispatched. Replay credentials stay in the private
operator workspace; these probes do not claim unprivileged access to SVID keys.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import time

from identity_demo_action_policy import DRIVER
from native_delegation_acceptance import DelegationAcceptance
from permission_flow import PermissionFlow
from openshift_security.artifacts import write_evidence
from protected_listener import HOST


class ReadSecurityFlow(PermissionFlow):
    """Check controls without repeating the already accepted Jira create."""

    def accept(self, execute: object, resource: str, context: object) -> dict:
        """Exercise real replay, parser, report privacy and live operator revocation."""
        before = self.backend_count()
        status, _, body = self.http(
            DRIVER + "/internal/operator/credentials/" + self.run_id, operator=True
        )
        assert status == 200
        human = {"sub": self.user, "access_token": json.loads(body)["access_token"]}
        sender = DelegationAcceptance(
            argparse.Namespace(**{**vars(self.args), "label": self.args.label + "-security"}),
            human,
        )
        replay = sender.run()
        assert replay["passed"] and self.backend_count() == before

        token, _ = sender.final()
        sessions = sender.initialize_session("parser-controls", token)
        cases = []
        for name, payload, statuses in (
            ("duplicate_json_key", b'{"jsonrpc":"2.0","method":"tools/list","method":"tools/call","id":1}', {403}),
            ("malformed_json", b'{"jsonrpc":', {403}),
            ("unsupported_batch", b'[{"jsonrpc":"2.0","method":"tools/list","id":1}]', {403}),
            ("oversized_body", b" " * 65_537, {413}),
            ("unregistered_mutation_tool", json.dumps({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "step56_jira_updateJiraIssue", "arguments": {"run_id": self.run_id}},
            }).encode(), {403}),
        ):
            # These controls exercise parsing, not token expiry. Real
            # short-lived grants can expire while the previous cases execute.
            token, _ = sender.final()
            status, _ = sender.request(
                19444, HOST, "/mcp", payload,
                {"Authorization": "Bearer " + token, "Content-Type": "application/json",
                 "Accept": "application/json, text/event-stream", **sessions},
            )
            assert status in statuses and self.backend_count() == before
            cases.append({"case": name, "http_status": status, "passed": True, "backend_unchanged": True})

        report = "Synthetic retained assessment; no confidential inputs."
        status, _, _ = self.http(
            DRIVER + "/internal/operator/report", operator=True,
            value={"run_id": self.run_id, "user": self.user, "workload": context.workload,
                   "assessment": report, "arguments": {
                       "project": "TEST", "issue_type": "Task", "summary": "Unapproved security fixture",
                       "description": report, "labels": ["synthetic"],
                   }},
        )
        assert status == 200
        viewer = PermissionFlow(self.args, Path(self.args.driver_credentials_file), username="viewer")
        viewer.authenticate()
        status, _, response = viewer.http(DRIVER + "/runs/" + self.run_id)
        assert status == 403 and report.encode() not in response
        cases.append({"case": "cross_user_report_denied", "http_status": status, "passed": True})

        # Prove live revocation with a current delegated grant. Reusing
        # the parser snapshot can turn this into an unrelated expiry failure.
        token, claims = sender.final()
        positive = sender.gateway("before_operator_revocation", token)
        assert positive.get("http_status") == 200
        started = time.monotonic()
        status, _, response = self.http(
            DRIVER + "/internal/operator/revoke", operator=True, value={"run_id": self.run_id}
        )
        assert status == 200 and json.loads(response)["revoked_runs"] == 1
        revoked = sender.gateway("revoked_run_still_valid_delegation", token)
        assert (
            revoked.get("http_status") == 403
            and claims["exp"] > time.time()

        )
        elapsed = time.monotonic() - started
        status, _, _ = self.http(
            DRIVER + "/internal/operator/credentials/" + self.run_id, operator=True
        )
        assert status == 403
        status, _, response = self.http(DRIVER + "/runs/" + self.run_id)
        assert status == 200 and report.encode() in response
        assert self.backend_count() == before
        cases.append({"case": "operator_revocation", "passed": True,
                      "protected_gateway_denied": True, "coordination_credential_release_denied": True,
                      "credential_still_valid_at_denial": True,
                      "assessment_retained": True, "observed_seconds": round(elapsed, 3),
                      "backend_unchanged": True})
        self.close()
        result = {"passed": True, "cases": cases, "delegation_replay": replay,
                  "backend_before": before, "backend_after": self.backend_count(),
                  "writes_exercised": False, "keycloak_role_propagation_proven": False,
                  "concurrency_proven": False, "steps5_and6_complete": False}
        write_evidence(
            self.args.output_dir / (self.args.label + ".read-security.summary.json"), result
        )
        return result
