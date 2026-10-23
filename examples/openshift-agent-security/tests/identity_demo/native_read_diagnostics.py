# SPDX-License-Identifier: Apache-2.0
"""Retain bounded, fixed-category supervisor diagnostics before automatic retirement."""

from __future__ import annotations

import argparse
import subprocess
from typing import Callable

from execution_context import context_of, resolve_context

MARKERS = {
    "workload_api_unavailable": ("workload api unavailable", "workload attestor"),
    "svid_unavailable": (
        "failed to fetch gateway jwt-svid",
        "failed to fetch x509",
        "no identity issued",
    ),
    "exchange_failed": (
        "token exchange failed",
        "failed to exchange",
        "credential resolution failed",
        "final_exchange_failed",
    ),
    "upstream_unavailable": (
        "connection refused",
        "upstream connect error",
        "connection reset",
    ),
    "timeout": ("deadline exceeded", "timed out", "timeout=true"),
    "certificate_rejected": (
        "certificate verify",
        "unknown issuer",
        "invalid certificate",
        "category=invalid_certificate",
        "category=peer_alert",
        "category=no_peer_certificate",
    ),
    "sender_io_failure": ("pilot sender io failure",),
    "sender_request_failure": ("pilot sender http failure",),
    "gateway_502": ("502 bad gateway", "status=502", "status: 502"),
    "gateway_503": ("503 service unavailable", "status=503", "status: 503"),
}


def categories(text: str) -> dict:
    """Discard raw log text and return only fixed category counts."""
    lines = text.lower().splitlines()[:150]
    return {
        name: sum(any(marker in line for marker in markers) for line in lines)
        for name, markers in MARKERS.items()
    }


def capture(args: argparse.Namespace, kube: Callable) -> dict:
    """Revalidate exact owned context and read its supervisor logs without saving raw text.

    Diagnostic failure cannot authorize access, mask the read failure or stop cleanup.
    No credential, arbitrary message, request body or exception text is retained.
    """
    try:
        context = resolve_context(
            args.context_file,
            lambda kind, name, ns=None: kube(
                args, "get", kind, name, *(["-n", ns] if ns else []), "-o", "json"
            ),
        )
        if context != context_of(args):
            raise ValueError("Diagnostic context changed")
        name = "os-supervisor-" + context.sandbox_id
        result = subprocess.run(
            [
                "oc",
                "--kubeconfig=" + args.kubeconfig,
                "--request-timeout=10s",
                "logs",
                "-n",
                context.namespace,
                name,
                "-c",
                "supervisor",
                "--since=5m",
                "--tail=150",
                "--limit-bytes=32768",
                "--timestamps",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode:
            return {
                "captured": False,
                "failure_kind": "log_read_unavailable",
                "raw_logs_retained": False,
            }
        return {
            "captured": True,
            "component": "exact_owned_supervisor",
            "categories": categories(result.stdout[:32768]),
            "raw_logs_retained": False,
            "diagnostic_proves_root_cause": False,
        }
    except Exception as error:
        return {
            "captured": False,
            "failure_kind": type(error).__name__,
            "details_withheld": True,
            "raw_logs_retained": False,
        }
