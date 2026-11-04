# SPDX-License-Identifier: Apache-2.0
"""Verify native protected reads across real SVID expiry, without replay clients."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import time
from typing import Callable

from deployment_profile import active_profile
from native_delegation_acceptance import DelegationAcceptance
from permission_flow import PermissionFlow
import probe_native_exchange as native


def read_body_hash(run_id: str, project: str) -> str:
    """Match the broker-normalized read body evaluated by the driver policy.

    The broker removes the registered server prefix and serializes the JSON
    map with sorted keys and no extra whitespace. Gateway tool-policy audit
    records bind that normalized body, rather than the original client bytes.
    """
    body = {"jsonrpc": "2.0", "method": "tools/call", "id": 4,
            "params": {"name": "readJiraProject",
                       "arguments": {"run_id": run_id, "project": project}}}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def delegated_reads(lines: str, *, run: str, user: str, workload: str, body_hash: str) -> dict[str, int]:
    """Return signed token issuance times for attributed successful native reads.

    This proves delegated identity/run/body attribution, without claiming that a
    bearer token proves possession of a workload private key on every request.
    """
    matches = {}
    for line in lines.splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if not isinstance(record, dict) or record.get("event") != "step4-private-read":
            continue
        verified = record.get("verified")
        if not isinstance(verified, dict) or verified.get("run") != run:
            continue
        if str(record.get("status")) != "200" or verified.get("actual_body_sha256") != body_hash:
            continue
        if (set(record) - {"event", "status", "detail", "upstream", "request", "tls_version", "verified",
                           "denied_identity", "denied_grant"}
                or set(verified) != {"user", "workload", "delegation", "issued", "expiry", "run", "policy", "actual_body_sha256"}
                or verified.get("user") != user or verified.get("workload") != workload
                or verified.get("policy") != "step56-live-action-v1"
                or verified.get("delegation") != "short-lived-bearer"):
            raise ValueError("Unexpected native renewal audit contract")
        issued, expiry, request = verified["issued"], verified["expiry"], record.get("request")
        if (type(issued) is not int or type(expiry) is not int or not 0 < expiry - issued <= 30
                or not isinstance(request, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", request)):
            raise ValueError("Bounded signed delegation and safe request correlation required")
        if request in matches and matches[request] != issued:
            raise ValueError("Conflicting native renewal audit request")
        matches[request] = issued
    return matches


class NativeRenewalFlow(PermissionFlow):
    """Keep the actual native proxy alive across JWT-SVID and token expiry."""

    def supervisor_state(self, context: object) -> dict:
        """Verify exact native Pod/process identity before and after renewal."""
        pod = native.kube(self.args, "get", "pod", "os-supervisor-" + context.sandbox_id,
                          "-n", context.namespace, "-o", "json")
        labels = pod["metadata"].get("labels", {})
        if (labels.get("openshell.ai/gateway-id") != active_profile().gateway_id
                or labels.get("openshell.ai/sandbox-id") != context.sandbox_id
                or pod["metadata"].get("deletionTimestamp")):
            raise ValueError("Exact live native supervisor required")
        statuses = [item for item in pod.get("status", {}).get("containerStatuses", [])
                    if item.get("name") == "supervisor"]
        if (len(statuses) != 1 or not statuses[0].get("ready") or not statuses[0].get("containerID")
                or "running" not in statuses[0].get("state", {})):
            raise ValueError("Ready running native supervisor required")
        return {"pod_uid": pod["metadata"]["uid"], "container_id": statuses[0]["containerID"],
                "restart_count": statuses[0]["restartCount"]}

    def audit_reads(self, context: object) -> dict[str, int]:
        """Capture only the verified owned data plane's logs into private receipts."""
        profile = active_profile()
        deployment = native.kube(self.args, "get", "deployment", "fixture-mcp-openshift-ai-inference",
                                 "-n", profile.core_namespace, "-o", "json")
        if any(deployment["metadata"].get("labels", {}).get(k) != v for k, v in profile.labels.items()):
            raise ValueError("Owned native data plane required")
        # The API's streaming log channel can time out independently of the
        # application. Retrying this bounded read is safe; native tool calls and
        # mutations are never replayed by this diagnostic retry.
        for attempt in range(3):
            response = subprocess.run(["oc", "--kubeconfig=" + self.args.kubeconfig,
                "--request-timeout=10s", "-n", profile.core_namespace,
                "logs", "deployment/fixture-mcp-openshift-ai-inference", "-c", "istio-proxy",
                "--since=10m", "--tail=2000"], capture_output=True, text=True, timeout=20)
            self.renewal_audit_sequence += 1
            native.private_write(self.args.output_dir / (
                self.args.label + f".renewal-audit-{self.renewal_audit_sequence}.private.json"),
                {"exit": response.returncode, "stdout": response.stdout, "stderr": response.stderr})
            if not response.returncode:
                break
            if attempt == 2:
                raise RuntimeError("Native renewal audit capture failed; details withheld")
            time.sleep(1)
        return delegated_reads(response.stdout, run=self.run_id, user=self.user, workload=context.workload,
                           body_hash=read_body_hash(self.run_id, self.project))

    def wait_read(self, context: object, excluded: set[str], *, issued_after: int | None = None) -> dict[str, int]:
        """Wait only for audit delivery, never retry an unsuccessful tool call."""
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            found = {request: issued for request, issued in self.audit_reads(context).items()
                     if request not in excluded and (issued_after is None or issued > issued_after)}
            if found:
                return found
            time.sleep(1)
        raise TimeoutError("Fresh correlated native delegated read was not observed")

    def accept(self, execute: Callable, resource: str, context: object) -> dict:
        """Read across real identity expiry without restarting the supervisor."""
        self.renewal_audit_sequence = 0
        before = self.backend_count()
        supervisor_before = self.supervisor_state(context)
        sender = DelegationAcceptance(argparse.Namespace(**{
            **vars(self.args), "label": self.args.label + "-renewal"}), {"sub": self.user})
        first = sender.identity_snapshot()
        # Existing demo registrations use short SVIDs. Refuse a long unexplained
        # wait rather than changing the identity TTL or the platform foundation.
        remaining = first["expires_at"] - time.time() + 2
        if not 0 < remaining <= 185:
            raise ValueError("Native renewal test requires the existing short SVID lifetime")
        existing = set(self.audit_reads(context))

        def read() -> dict:
            result = execute(["sandbox", "exec", "--name", context.sandbox_name,
                "--no-login-shell", "--timeout", "90", "--no-tty", "--", "python", "-c",
                self.read_program(resource)], json_output=True)
            if result.get("read_passed") is not True or self.backend_count() != before:
                raise ValueError("Native renewal protected read failed or backend changed")
            return result

        read()
        baseline = self.wait_read(context, existing)
        print(json.dumps({"stage": "waiting_for_native_jwt_expiry"}), flush=True)
        deadline = time.monotonic() + 220
        while time.time() <= first["expires_at"] + 32:
            if time.monotonic() > deadline:
                raise TimeoutError("Native identity expiry wait exceeded")
            time.sleep(min(5, max(0.1, first["expires_at"] + 32 - time.time())))
        current = sender.identity_snapshot()
        if current["sha256"] == first["sha256"]:
            raise ValueError("Native JWT-SVID did not renew")
        # Exclude every pre-read request, including any operator requests. Only
        # the following credential-free sandbox execution can close this gate.
        previous = set(self.audit_reads(context))
        read()
        renewed = self.wait_read(context, previous, issued_after=first["expires_at"])
        if self.supervisor_state(context) != supervisor_before:
            raise ValueError("Native supervisor changed during renewal; uninterrupted proxy not proven")
        result = {"passed": True, "native_read_before_and_after_real_jwt_expiry": True,
            "old_jwt_expired_before_second_read": first["expires_at"] < time.time(),
            "baseline_requests": sorted(baseline), "renewed_requests": sorted(renewed),
            "old_jwt_sha256": first["sha256"], "renewed_delegation_issued_at": sorted(set(renewed.values())),
            "signed_delegation_issued_after_original_jwt_expiry": True, "same_user_workload_run_and_read_body": True,
            "supervisor_restarted": False, "operator_replay_used_as_native_proof": False,
            "backend_before": before, "backend_after": self.backend_count(), "writes_exercised": False,
            "scope": "Fresh native MCP sessions after JWT-SVID and access-token expiry; uninterrupted long-lived streams are unproven"}
        native.private_write(self.args.output_dir / (self.args.label + ".native-renewal.summary.json"), result)
        self.close()
        return result
