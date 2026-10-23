# SPDX-License-Identifier: Apache-2.0
"""Supported Keycloak RSA overlap/refresh on the actual protected native path."""

import argparse
from contextlib import contextmanager
from copy import deepcopy
import json
import time
from typing import Callable, Iterator
from uuid import uuid4

import jwt

from identity_demo_action_policy import DRIVER
from lifecycle_flow import LifecycleFlow
from native_sender_acceptance import SenderAcceptance
from permission_flow import PermissionFlow
import probe_native_exchange as native

KEYS = "/components?type=org.keycloak.keys.KeyProvider"


class RealmKeyProbe:
    """Add/delete only one named temporary key provider; keep original keys intact."""

    def __init__(self, admin: Callable) -> None:
        self.admin = admin
        self.before = admin(KEYS)
        if not self.before or len({c["parentId"] for c in self.before}) != 1:
            raise ValueError("Exact one-realm key inventory required")
        priorities = [int(c.get("config", {}).get("priority", ["0"])[0]) for c in self.before]
        self.model = {"name": "identity-demo-demo-team-rotation-" + str(uuid4()),
            "parentId": self.before[0]["parentId"], "providerId": "rsa-generated",
            "providerType": "org.keycloak.keys.KeyProvider",
            "config": {"priority": [str(max(priorities) + 1)], "enabled": ["true"],
                "active": ["true"], "algorithm": ["RS256"], "keySize": ["2048"]}}
        self.created = None

    def same_originals(self, values: list) -> bool:
        """Compare exact original provider configurations by immutable ID."""
        return {v["id"]: v for v in values if v["name"] != self.model["name"]} == {
            v["id"]: v for v in self.before}

    def matches_model(self, value: dict) -> bool:
        """Allow server-generated material, while fixing every requested setting."""
        return (all(value.get(k) == v for k, v in self.model.items() if k != "config")
                and all(value.get("config", {}).get(k) == v for k, v in self.model["config"].items())
                and set(value.get("config", {})) - set(self.model["config"])
                <= {"privateKey", "certificate", "kid"})

    @contextmanager
    def active(self) -> Iterator[dict]:
        """Observe a lost POST response and delete only an exact unchanged new provider."""
        if {v["id"]: v for v in self.admin(KEYS)} != {v["id"]: v for v in self.before}:
            raise ValueError("Original realm key inventory changed")
        try:
            self.admin("/components", "POST", deepcopy(self.model))
            values = self.admin(KEYS)
            matches = [v for v in values if v["name"] == self.model["name"]]
            if len(matches) != 1 or not self.same_originals(values):
                raise ValueError("New key provider inventory not established")
            self.created = matches[0]
            if not self.matches_model(self.created):
                raise ValueError("Exact temporary key provider required")
            yield self.created
        finally:
            values = self.admin(KEYS)
            matches = [v for v in values if v["name"] == self.model["name"]]
            if not self.same_originals(values):
                raise ValueError("Original key inventory changed; refuse cleanup")
            if matches:
                if len(matches) != 1:
                    raise ValueError("Ambiguous temporary key provider; refuse cleanup")
                current = matches[0]
                if (not self.matches_model(current)
                        or self.created is not None and current != self.created):
                    raise ValueError("Temporary key changed independently; refuse cleanup")
                self.admin("/components/" + current["id"], "DELETE")
            if {v["id"]: v for v in self.admin(KEYS)} != {v["id"]: v for v in self.before}:
                raise ValueError("Original key provider inventory not restored")


class KeyRotationFlow(PermissionFlow):
    """Prove old-key overlap, live new-key refresh and renewed-session approval."""

    def accept(self, execute: Callable, resource: str, context: object) -> dict:
        """Use real keys/tokens and reads; no Jira mutation is dispatched."""
        before = self.backend_count()
        sender = SenderAcceptance(argparse.Namespace(**{**vars(self.args), "label": self.args.label + "-keys"}), {"sub": self.user})
        leaf = sender.certificate("key-overlap")
        token, claims = sender.final(leaf)
        old_kid = jwt.get_unverified_header(token)["kid"]
        assert sender.gateway("before_realm_key_change", token, leaf)["http_status"] == 200
        probe = RealmKeyProbe(self.issuer_admin)
        native.private_write(self.args.output_dir / "realm-keys-before.private.json", probe.before)
        # Fresh old-key token immediately before the administrative transition.
        token, claims = sender.final(leaf)
        with probe.active() as created:
            native.private_write(self.args.output_dir / "temporary-key-provider.private.json", created)
            active = self.issuer_admin("/keys")["active"]["RS256"]
            assert active != old_kid
            overlap = sender.gateway("published_old_key_overlap", token, leaf)
            assert overlap["http_status"] == 200 and claims["exp"] > time.time()
            fresh, _ = sender.final(leaf)
            assert jwt.get_unverified_header(fresh)["kid"] == active
            assert sender.gateway("unknown_kid_live_refresh", fresh, leaf)["http_status"] == 200
            recovered = execute(["sandbox", "exec", "--name", context.sandbox_name,
                "--no-login-shell", "--timeout", "90", "--no-tty", "--", "python", "-c",
                self.read_program(resource)], json_output=True)
            assert recovered["read_passed"] and self.backend_count() == before
            original_deadline = native.components.verify(
                json.loads(self.http(DRIVER + "/internal/operator/credentials/" + self.run_id, operator=True)[2])["access_token"],
                native.GATEWAY, issuer=native.components.ISSUER)["exp"]
            status, _, body = self.http(DRIVER + "/internal/operator/report", operator=True,
                value={"run_id": self.run_id, "user": self.user, "workload": context.workload,
                    "assessment": "Synthetic retained key-rotation assessment.", "arguments": {
                        "project": "TEST", "summary": "No create dispatched", "description": "Key refresh fixture"}})
            assert status == 200
            proposal = json.loads(body)
            self.proposal = proposal
            self.authenticate()
            status, _, _ = self.http(DRIVER + "/runs/" + self.run_id + "/approve", fields={
                "csrf": self.csrf, "action": proposal["action_id"], "digest": proposal["digest"]})
            assert status == 303
            record = LifecycleFlow.action_record(self)
            assert record["run_expires"] == record["approval_expires"] == original_deadline
            assert record["dispatch_claims"] == 0 and record["state"] == "approved"
            # Retire before removing this test key, including tokens retained by a browser.
            self.close()
        assert self.issuer_admin("/keys")["active"]["RS256"] == old_kid
        summary = {"passed": True, "original_keys_preserved": True,
            "old_signed_bound_token_accepted_during_published_overlap": True,
            "new_final_token_signed_by_new_active_key": True,
            "new_key_gateway_and_driver_refresh_passed": True,
            "actual_cve_protected_read_with_new_service_signatures_passed": True,
            "real_browser_login_after_rotation_passed": True,
            "reauthenticated_approval_passed": True, "original_run_deadline": original_deadline,
            "approval_did_not_extend_original_run": True, "dispatch_claims": 0,
            "original_key_authority_restored": True, "run_retired_before_test_key_removal": True,
            "backend_before": before, "backend_after": self.backend_count(), "steps5_and6_complete": False}
        native.private_write(self.args.output_dir / (self.args.label + ".key-rotation.summary.json"), summary)
        return summary
