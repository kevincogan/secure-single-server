# SPDX-License-Identifier: Apache-2.0
"""Minimal run cancellation and native release checks; full approvals are Step 5."""

from __future__ import annotations

import argparse
from dataclasses import asdict, replace
import json
import time
from typing import Callable

import probe_native_exchange as native
from native_sender_acceptance import SenderAcceptance
from run_binding import ReadRun, authorization
from execution_context import context_of

LEDGER = "fixture-step4-retired-runs"


class RetiredIdentityError(ValueError):
    """An exact valid retained record forbids another run for this identity."""


def require_unused_identity(args: argparse.Namespace, workload: str) -> None:
    """A persisted retired sandbox identity cannot be assigned to another run."""
    ledger = native.kube(args, "get", "configmap", LEDGER, "-n", native.NAMESPACE,
                         "--ignore-not-found", "-o", "json")
    if not ledger:
        return
    if any(ledger["metadata"].get("labels", {}).get(k) != v for k, v in native.LABELS.items()):
        raise ValueError("Owned run ledger required")
    records = json.loads(ledger["data"]["runs.json"])
    if not isinstance(records, list) or len(records) > 16:
        raise ValueError("Bounded retained run ledger required")
    if any(r["workload"] == workload for r in records):
        raise RetiredIdentityError("Retired execution identity cannot be reused; provision a fresh sandbox")


def retire(args: argparse.Namespace, run: ReadRun, provider_id: str) -> dict:
    """Persist the verified cancelled association without tokens or private keys."""
    require_unused_identity(args, run.workload)
    if run.active:
        raise ValueError("Only a denied, detached run can be retired")
    before = native.kube(args, "get", "configmap", LEDGER, "-n", native.NAMESPACE,
                         "--ignore-not-found", "-o", "json")
    records = json.loads(before["data"]["runs.json"]) if before else []
    record = {**asdict(run), "sandbox_id": context_of(args).sandbox_id,
              "provider_id": provider_id, "provider_detached": True,
              "retired_at": int(time.time()), "step5_started": False}
    records.append(record)
    data = {"runs.json": json.dumps(records, separators=(",", ":"))}
    if before:
        operations = [{"op": "test", "path": "/metadata/uid", "value": before["metadata"]["uid"]},
                      {"op": "test", "path": "/metadata/resourceVersion", "value": before["metadata"]["resourceVersion"]},
                      {"op": "test", "path": "/data", "value": before["data"]},
                      {"op": "replace", "path": "/data", "value": data}]
        saved = native.kube(args, "patch", "configmap", LEDGER, "-n", native.NAMESPACE,
            "--type=json", "-p", json.dumps(operations), "-o", "json")
    else:
        manifest = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {
            "name": LEDGER, "namespace": native.NAMESPACE, "labels": dict(native.LABELS)}, "data": data}
        native.kube(args, "create", "--dry-run=server", "-f", "-", "-o", "json", payload=manifest)
        saved = native.kube(args, "create", "-f", "-", "-o", "json", payload=manifest)
    native.private_write(args.output_dir / (args.label + ".retired-ledger.private.json"), saved)
    try:
        require_unused_identity(args, run.workload)
    except RetiredIdentityError:
        return {"retained_cancelled_association": True, "identity_reassignment_denied": True,
                "run_id": run.run_id, "ledger_uid": saved["metadata"]["uid"]}
    raise ValueError("Identity retirement did not persist")


def check(args: argparse.Namespace, execute: Callable, human: dict, login: dict, run: ReadRun,
          frontend: str, before: dict, spec: dict, backend: object, provider_id: str) -> tuple[dict, dict]:
    """Expire at native release, cancel at gateway first, detach, then persist retirement."""
    sender_args = argparse.Namespace(**{**vars(args), "label": args.label + "-lifecycle"})
    sender = SenderAcceptance(sender_args, human)
    cases = []
    execute(["provider", "update", context_of(args).provider_prefix, "--credential", "subject_token", "--credential-expires-at",
             "subject_token=" + str(run.expires_at * 1000), "--wait", "--timeout", "30"], subject=login["access_token"])
    status, data = sender.intermediate()
    if status != 0 or not data:
        raise ValueError("Native lifecycle positive release control failed")
    execute(["provider", "update", context_of(args).provider_prefix, "--credential-expires-at",
             "subject_token=" + str((int(time.time()) - 1) * 1000)])
    # An intentionally expired credential cannot be required to become Ready.
    # Its actual native release must return the precise denial below.
    status, data = sender.intermediate()
    cases.append({"case": "expired_subject_denied_before_release", "grpc_status": status,
                  "response_message_present": bool(data), "passed": status == 9 and not data})
    if not cases[-1]["passed"]:
        raise ValueError("Expired native credential was not explicitly denied")
    execute(["provider", "update", context_of(args).provider_prefix, "--credential-expires-at",
             "subject_token=" + str(run.expires_at * 1000), "--wait", "--timeout", "30"])
    cancelled = replace(run, active=False)
    current = native.kube(args, "get", "authpolicy", frontend, "-n", native.NAMESPACE, "-o", "json")
    desired = json.loads(json.dumps(spec))
    desired["rules"]["authorization"]["native-step4-run"] = authorization([cancelled])
    operations = [{"op": "test", "path": "/metadata/uid", "value": before["metadata"]["uid"]},
                  {"op": "test", "path": "/metadata/resourceVersion", "value": current["metadata"]["resourceVersion"]},
                  {"op": "test", "path": "/spec", "value": spec},
                  {"op": "replace", "path": "/spec", "value": desired}]
    made = native.kube(args, "patch", "authpolicy", frontend, "-n", native.NAMESPACE,
        "--type=json", "-p", json.dumps(operations), "-o", "json")
    # Track the new expected state immediately so a later failure can restore
    # exactly our own cancellation rather than leave an ambiguous live patch.
    spec.clear()
    spec.update(made["spec"])
    native.wait_authorizer(args, made["spec"])
    backend.set_run(cancelled)
    denied = execute(["sandbox", "exec", "--name", context_of(args).sandbox_name, "--no-login-shell", "--timeout", "90",
        "--no-tty", "--", "python", "-c", native.read_program(run.audience, "step4_read_searchJiraIssuesUsingJql")], json_output=True)
    passed = denied.get("read_passed") is False and denied.get("events", [{}])[0].get("http_status") == 403
    cases.append({"case": "cancelled_run_denied_before_detach", "passed": passed})
    if not passed:
        raise ValueError("Cancellation must reach the gateway before detachment")
    execute(["sandbox", "provider", "detach", context_of(args).sandbox_name, context_of(args).provider_prefix])
    status, data = sender.intermediate()
    cases.append({"case": "detached_provider_denied_before_release", "grpc_status": status,
                  "response_message_present": bool(data), "passed": status == 7 and not data})
    if not cases[-1]["passed"]:
        raise ValueError("Detached native provider was not explicitly denied")
    summary = {"passed": True, "cases": cases, **retire(args, cancelled, provider_id),
               "full_submission_and_approval_app": False}
    native.private_write(args.output_dir / (args.label + ".lifecycle.summary.json"), summary)
    return summary, made["spec"]
