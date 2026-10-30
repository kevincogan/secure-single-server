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
from native_sender_acceptance import SenderAcceptance
from permission_flow import PermissionFlow
import probe_native_exchange as native
from sender_listener import HOST


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
        sender = SenderAcceptance(
            argparse.Namespace(**{**vars(self.args), "label": self.args.label + "-security"}),
            human,
        )
        replay = sender.run()
        assert replay["passed"] and self.backend_count() == before

        leaf = sender.certificate("parser-controls")
        token, _ = sender.final(leaf)
        sessions = sender.initialize_session("parser-controls", token, leaf)
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
            # These controls exercise parsing, not certificate expiry. Real
            # two-minute SVIDs can rotate while the previous cases execute.
            leaf = sender.certificate("parser-" + name)
            token, _ = sender.final(leaf)
            status, _ = sender.request(
                19444, HOST, "/mcp", payload, leaf,
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

        # Prove live revocation with a current certificate and grant. Reusing
        # the parser snapshot can turn this into an unrelated expiry failure.
        leaf = sender.certificate("revocation-control")
        token, claims = sender.final(leaf)
        positive = sender.gateway("before_operator_revocation", token, leaf)
        assert positive.get("http_status") == 200
        started = time.monotonic()
        status, _, response = self.http(
            DRIVER + "/internal/operator/revoke", operator=True, value={"run_id": self.run_id}
        )
        assert status == 200 and json.loads(response)["revoked_runs"] == 1
        revoked = sender.gateway("revoked_run_still_valid_bound_token", token, leaf)
        assert (
            revoked.get("http_status") == 403
            and claims["exp"] > time.time()
            and leaf.expires_at > time.time()
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
                      "bound_gateway_denied": True, "coordination_credential_release_denied": True,
                      "credential_still_valid_at_denial": True,
                      "assessment_retained": True, "observed_seconds": round(elapsed, 3),
                      "backend_unchanged": True})
        self.close()
        result = {"passed": True, "cases": cases, "sender_replay": replay,
                  "backend_before": before, "backend_after": self.backend_count(),
                  "writes_exercised": False, "keycloak_role_propagation_proven": False,
                  "concurrency_proven": False, "steps5_and6_complete": False}
        native.private_write(
            self.args.output_dir / (self.args.label + ".read-security.summary.json"), result
        )
        return result
