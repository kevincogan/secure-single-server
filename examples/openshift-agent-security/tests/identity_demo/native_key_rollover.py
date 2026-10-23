# SPDX-License-Identifier: Apache-2.0
"""Validate supported SPIRE JWT authority rotation through the native client."""

from __future__ import annotations
from deployment_profile import active_profile

import argparse
import json
import subprocess
import time
from typing import Callable

import jwt

import probe_native_exchange as native
from native_sender_acceptance import SenderAcceptance
from probe_discovery import run as discovery_run


def check(args: argparse.Namespace, execute: Callable, human: dict, resource: str, tool: str) -> dict:
    """Publish before activation; retain old overlap and require a real CVE read.

    Only the dedicated owned SPIRE server is changed. Do not restart Keycloak,
    revoke an authority, mint workload assertions administratively, or alter any
    other trust domain. A prepared or activated key is left for normal SPIRE
    lifecycle management, including on a failed acceptance.
    """
    for ns in (native.NAMESPACE, "demo-identity"):
        namespace = native.kube(args, "get", "namespace", ns, "-o", "json")
        if any(namespace["metadata"].get("labels", {}).get(k) != v for k, v in native.LABELS.items()):
            raise ValueError("Exact owned rotation namespace required")
    entries = native.kube(args, "get", "clusterstaticentry", "-o", "json")["items"]
    if len(entries) != 3 or any(
        e["metadata"].get("labels", {}).get("identity-demo-owner") != active_profile().owner
        or not e["spec"]["spiffeID"].startswith("spiffe://agents.example.test/") for e in entries
    ):
        raise ValueError("Dedicated owned signing authority required")
    for kind in ("clusterspiffeid", "spireoidcdiscoveryprovider"):
        if native.kube(args, "get", kind, "-o", "json")["items"]:
            raise ValueError("Broad registrations present; refuse signing rotation")
    server = native.kube(args, "get", "pod", "spire-server-0", "-n", "demo-identity", "-o", "json")
    if server["metadata"].get("labels", {}).get("identity-demo-owner") != active_profile().owner:
        raise ValueError("Exact owned SPIRE server required")
    issuer_before = native.kube(args, "get", "pods", "-n", native.NAMESPACE,
        "-l", "app=fixture-keycloak-upstream", "-o", "json")
    before_uids = sorted(p["metadata"]["uid"] for p in issuer_before["items"])
    sender = SenderAcceptance(argparse.Namespace(**{**vars(args), "label": args.label + "-rollover"}), human)

    def authority(operation: str, *parts: str) -> dict:
        result = subprocess.run(["oc", "--kubeconfig=" + args.kubeconfig, "--request-timeout=20s",
            "-n", "demo-identity", "exec", "spire-server-0", "-c", "spire-server", "--",
            "/spire-server", "localauthority", "jwt", operation, *parts, "-output", "json"],
            capture_output=True, text=True, timeout=30)
        sender.count += 1
        sender.save("authority-" + str(sender.count) + ".private.json", {
            "exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
        if result.returncode:
            raise RuntimeError("Owned signing authority operation failed")
        return json.loads(result.stdout)

    before = authority("show")
    old_id = before["active"]["authority_id"]
    old_assertion = sender.fetch("jwt")["token"]
    if jwt.get_unverified_header(old_assertion)["kid"] != old_id:
        raise ValueError("Warm native assertion must use the active authority")
    # SPIRE normally maintains a prepared standby. On this exclusively owned
    # foundation, validate and use that supported standby rather than replacing
    # it or treating normal authority management as a runtime failure.
    if before.get("prepared"):
        prepared = before["prepared"]
        prepared_source = "existing_owned_standby"
    else:
        prepared = authority("prepare")["prepared_authority"]
        prepared_source = "explicit_prepare"
    new_id = prepared["authority_id"]
    if new_id == old_id or int(prepared["expires_at"]) <= time.time() + 120:
        raise ValueError("Distinct signing authority required")
    deadline, poll = time.monotonic() + 60, 0
    while time.monotonic() < deadline:
        poll += 1
        discovered = discovery_run(argparse.Namespace(kubeconfig=args.kubeconfig,
            output_dir=args.output_dir, label=args.label + "-key-publication-" + str(poll)))
        if {old_id, new_id}.issubset(set(discovered["jwt_key_ids"])):
            break
        time.sleep(2)
    else:
        raise TimeoutError("Prepared public key not published; authority not activated")
    active = authority("activate", "-authorityID", new_id)
    if active["activated_authority"]["authority_id"] != new_id:
        raise ValueError("Unexpected activated authority")
    from sender_listener import NAME
    with sender.tunnel("fixture-keycloak-upstream", 19443, 8443), sender.tunnel(NAME, 19444, 443):
        leaf = sender.certificate("old-key-overlap")
        token, _ = sender.final(leaf, old_assertion)
        overlap = sender.gateway("old_native_assertion_overlap", token, leaf)
        if overlap.get("http_status") != 200:
            raise ValueError("Prior real workload assertion must remain valid during overlap")
    deadline, attempts = time.monotonic() + 90, []
    while time.monotonic() < deadline:
        assertion = sender.fetch("jwt")["token"]
        if jwt.get_unverified_header(assertion)["kid"] != new_id:
            time.sleep(2)
            continue
        response = execute(["sandbox", "exec", "--name", native.SANDBOX, "--no-login-shell",
            "--timeout", "90", "--no-tty", "--", "python", "-c", native.read_program(resource, tool)],
            json_output=True)
        attempts.append({"new_native_assertion": True, "read_passed": response.get("read_passed") is True})
        if attempts[-1]["read_passed"]:
            break
        time.sleep(3)
    else:
        raise TimeoutError("Native protected read did not recover after signing-key rotation")
    after = native.kube(args, "get", "pods", "-n", native.NAMESPACE,
        "-l", "app=fixture-keycloak-upstream", "-o", "json")
    if before_uids != sorted(p["metadata"]["uid"] for p in after["items"]):
        raise ValueError("Issuer restarted during signing-key acceptance")
    summary = {"passed": True, "published_before_activation": True,
        "old_key_retained_for_overlap": True, "new_actual_workload_assertion": True,
        "native_protected_read_after_rollover": True, "issuer_not_restarted": True,
        "prior_authority": old_id, "new_authority": new_id, "attempts": attempts,
        "prepared_source": prepared_source,
        "prior_native_assertion_accepted_after_activation": True}
    sender.save("summary.json", summary)
    return summary
