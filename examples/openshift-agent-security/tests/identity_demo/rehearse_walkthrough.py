#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Rehearse one UI-led scenario on a fresh owned execution identity.

Uses the accepted native exchange gate and restores temporary route/provider
configuration. Never reuse a retired context. This is a development rehearsal,
not full NeMo/model execution, disconnected acceptance or production approval.
"""

import argparse
import json
import os
from pathlib import Path
import re

from browser_permission_flow import BrowserPermissionFlow, BrowserBoundaryPermissionFlow
import probe_native_exchange as native


def main() -> None:
    """Require private inputs and publish only bounded acceptance classifications."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("kubeconfig", "expected-server", "credentials-file", "cli", "cli-config-dir",
                 "context-file", "catalog-credential-file", "driver-credentials-file", "output-dir"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--username", choices=("analyst", "viewer"), default="analyst")
    parser.add_argument("--label", required=True)
    parser.add_argument("--enable-create", action="store_true")
    parser.add_argument("--headed", action="store_true", help="Show the real operator browser for a live rehearsal")
    parser.add_argument("--record-video", action="store_true", help="Record authenticated UI only to private output; excludes login")
    parser.add_argument("--check-boundary", action="store_true")
    parser.add_argument("--workflow", choices=("cve", "service-request"), default="cve")
    parser.add_argument("--inference-config", help="Private Messages configuration; service workflow only")
    parser.add_argument("--spire-agent-cli")
    args = parser.parse_args()
    if not re.fullmatch(r"walkthrough-[a-z0-9-]{1,48}", args.label):
        raise ValueError("Neutral bounded rehearsal label required")
    os.umask(0o077)
    args.output_dir = Path(args.output_dir)
    args.output_dir.mkdir(mode=0o700)
    args.namespace = native.NAMESPACE
    args.protected_backend_catalog_credential_file = args.catalog_credential_file
    for name in ("investigate_substitution", "require_substitution_denial", "check_sender_rejection",
                 "retain_run_retirement", "check_key_rollover", "check_backend_rotation", "check_renewal"):
        setattr(args, name, False)
    for name in ("upstream_development_issuer", "check_run_binding", "bound_sender_listener",
                 "diagnose_native_grant"):
        setattr(args, name, True)
    if args.check_boundary and not args.spire_agent_cli:
        raise ValueError("Boundary rehearsal requires the trusted SPIRE diagnostic binary")
    if args.workflow == "service-request" and args.check_boundary:
        raise ValueError("Use the focused reuse gate; CVE boundary rehearsal is separate")
    flow_type = BrowserBoundaryPermissionFlow if args.check_boundary else BrowserPermissionFlow
    if args.workflow == "service-request":
        from service_request_flow import ServiceRequestFlow

        flow_type = ServiceRequestFlow
    if args.inference_config:
        if args.workflow != "service-request":
            raise ValueError("Bounded model inference requires the service-request workflow")
        from enmaas_flow import EnmaasFlow, private_inference

        private_inference(args.inference_config)
        flow_type = EnmaasFlow
    flow = flow_type(args, Path(args.driver_credentials_file), username=args.username)
    args.permission_flow = flow
    try:
        result = native.run(args)
        permission = result.get("permission_flow", {})
        summary = {
            "passed": result["passed"],
            "native_checks_passed": sum(c["passed"] for c in result["cases"]),
            "native_checks_total": len(result["cases"]),
            "permission_gate_passed": permission.get("passed", False),
            "username": args.username,
            "workflow": args.workflow,
            "project": flow.project,
            "writes_enabled": args.enable_create,
            "verified_issue_key": permission.get("verified_issue_key"),
            "backend_before": permission.get("backend_before"),
            "backend_after": permission.get("backend_after"),
            "real_browser_submission_and_approval": bool(permission.get("passed")),
            "boundary_acceptance": permission.get("boundary_acceptance"),
            "full_model_execution_proven": False,
            "workload_messages_inference_proven": bool(permission.get("passed") and
                permission.get("model_inference", {}).get("actual_native_workload")),
            "full_nemo_cve_execution_proven": False,
            "steps5_and6_complete": False,
            "errors": [{"kind": e.get("failure_kind")} for e in result["errors"]],
        }
        native.private_write(args.output_dir / (args.label + ".walkthrough.summary.json"), summary)
        print(json.dumps(summary))
        if not result["passed"]:
            raise SystemExit(1)
    except Exception as error:
        import traceback

        native.private_write(args.output_dir / (args.label + ".failure.private.json"), {
            "kind": type(error).__name__, "traceback": traceback.format_exc()
        })
        print(json.dumps({"passed": False, "kind": type(error).__name__, "details_withheld": True}))
        raise SystemExit(1) from None
    finally:
        flow.shutdown_browser()


if __name__ == "__main__":
    main()
