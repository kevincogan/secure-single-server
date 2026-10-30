# SPDX-License-Identifier: Apache-2.0
"""Verify native protected reads across real SVID expiry, without replay clients."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import subprocess
import time
from typing import Callable

from deployment_profile import active_profile
from native_sender_acceptance import SenderAcceptance
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


def bound_reads(lines: str, *, run: str, user: str, workload: str, body_hash: str) -> dict[str, str]:
    """Extract only attributed successful reads whose signed cnf equals TLS peer.

    Return safe request IDs and public fingerprints, never arbitrary log fields.
    Other runs and non-tool requests cannot satisfy the renewal proof.
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
        if (set(record) - {"event", "status", "detail", "upstream", "request", "peer_hash", "verified",
                           "denied_identity", "denied_peer", "denied_grant"}
                or set(verified) != {"user", "workload", "cnf", "run", "policy", "actual_body_sha256"}
                or verified.get("user") != user or verified.get("workload") != workload
                or verified.get("policy") != "step56-live-action-v1"):
            raise ValueError("Unexpected native renewal audit contract")
        fingerprint = verified.get("cnf")
        request = record.get("request")
        peer = record.get("peer_hash")
        if (not isinstance(fingerprint, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", fingerprint)
                or not isinstance(request, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", request)
                or not isinstance(peer, str)
                or peer.replace(":", "").lower() != base64.urlsafe_b64decode(fingerprint + "=").hex()):
            raise ValueError("Native renewal read requires exact TLS peer/cnf correlation")
        if request in matches and matches[request] != fingerprint:
            raise ValueError("Conflicting native renewal audit request")
        matches[request] = fingerprint
    return matches


class NativeRenewalFlow(PermissionFlow):
    """Keep the actual native proxy alive while its original leaf expires."""

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

    def audit_reads(self, context: object) -> dict[str, str]:
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
        return bound_reads(response.stdout, run=self.run_id, user=self.user, workload=context.workload,
                           body_hash=read_body_hash(self.run_id, self.project))

    def wait_read(self, context: object, excluded: set[str], *, fingerprint: str | None = None,
                  different_from: str | None = None) -> dict[str, str]:
        """Wait only for log delivery; never retry an unsuccessful native operation."""
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            found = {request: leaf for request, leaf in self.audit_reads(context).items()
                     if request not in excluded and (fingerprint is None or leaf == fingerprint)
                     and (different_from is None or leaf != different_from)}
            if found:
                return found
            time.sleep(1)
        raise TimeoutError("Fresh correlated native bound read was not observed")

    def accept(self, execute: Callable, resource: str, context: object) -> dict:
        """Read before/after real leaf expiry with no supervisor restart or key injection."""
        self.renewal_audit_sequence = 0
        before = self.backend_count()
        supervisor_before = self.supervisor_state(context)
        sender = SenderAcceptance(argparse.Namespace(**{
            **vars(self.args), "label": self.args.label + "-renewal"}), {"sub": self.user})
        first = sender.certificate("native-baseline")
        # Existing demo registrations use short SVIDs. Refuse a long unexplained
        # wait rather than changing the identity TTL or the platform foundation.
        remaining = first.expires_at - time.time() + 2
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
        baseline = self.wait_read(context, existing, fingerprint=first.fingerprint)
        print(json.dumps({"stage": "waiting_for_native_leaf_expiry"}), flush=True)
        deadline = time.monotonic() + 185
        while time.time() <= first.expires_at + 2:
            if time.monotonic() > deadline:
                raise TimeoutError("Native leaf expiry wait exceeded")
            time.sleep(min(5, max(0.1, first.expires_at + 2 - time.time())))
        current = sender.certificate("native-after-expiry")
        if current.fingerprint == first.fingerprint:
            raise ValueError("Native SVID did not renew")
        # Exclude every pre-read request, including any operator requests. Only
        # the following credential-free sandbox execution can close this gate.
        previous = set(self.audit_reads(context))
        read()
        renewed = self.wait_read(context, previous, different_from=first.fingerprint)
        if self.supervisor_state(context) != supervisor_before:
            raise ValueError("Native supervisor changed during renewal; uninterrupted proxy not proven")
        result = {"passed": True, "native_read_before_and_after_real_leaf_expiry": True,
            "old_leaf_expired_before_second_read": first.expires_at < time.time(),
            "baseline_requests": sorted(baseline), "renewed_requests": sorted(renewed),
            "old_leaf_fingerprint": first.fingerprint, "renewed_peer_fingerprints": sorted(set(renewed.values())),
            "actual_tls_peer_equals_signed_cnf": True, "same_user_workload_run_and_read_body": True,
            "supervisor_restarted": False, "operator_replay_used_as_native_proof": False,
            "backend_before": before, "backend_after": self.backend_count(), "writes_exercised": False,
            "scope": "Fresh native MCP sessions after leaf expiry; uninterrupted long-lived streams are unproven"}
        native.private_write(self.args.output_dir / (self.args.label + ".native-renewal.summary.json"), result)
        self.close()
        return result
