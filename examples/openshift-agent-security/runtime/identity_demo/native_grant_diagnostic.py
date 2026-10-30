# SPDX-License-Identifier: Apache-2.0
"""Classify a failed native credential grant before guarded probe cleanup."""

from __future__ import annotations

import argparse
import base64
from urllib.parse import unquote

from execution_context import context_of
from native_sender_acceptance import SenderAcceptance
import native_subject_boundary as subject


PREREQUISITES = {
    "provider profile not found": "profile_missing",
    "credential not declared by provider profile": "credential_undeclared",
    "credential does not declare token_grant": "grant_missing",
    "credential token_grant is not token_exchange": "grant_type",
    "token_exchange subject_token is missing": "subject_configuration_missing",
    "unsupported subject_token source": "subject_source",
    "subject token credential not declared by provider profile": "subject_undeclared",
    "subject token credential is not configured": "subject_not_configured",
    "subject token credential has expired": "subject_expired",
    "gateway SVID audience does not match token grant audience": "gateway_audience",
    "gateway SVID subject is not a SPIFFE ID": "gateway_identity",
    "gateway SVID has expired": "gateway_expired",
}


def classify(status: int, message: str) -> str:
    """Return a fixed category, never issuer text or credential-bearing errors."""
    if status == 0:
        return "grant_succeeded"
    decoded = unquote(message)
    if status == 9:
        if decoded in PREREQUISITES:
            return PREREQUISITES[decoded]
        if decoded.startswith("SPIFFE Workload API unavailable:"):
            return "gateway_workload_api_unavailable"
        if decoded.startswith("failed to fetch gateway JWT-SVID:"):
            return "gateway_svid_unavailable"
    return "unclassified"


def diagnose(args: argparse.Namespace, human: dict) -> dict:
    """Request one intermediate grant with the exact supervisor's real SVID.

    This diagnostic does not retry a tool call, contact Jira or change a run.
    Raw responses stay private; a passing diagnostic cannot override a failed read.
    """
    diagnostic = SenderAcceptance(args, human)
    assertion = diagnostic.fetch("jwt")["token"]
    context = context_of(args)
    with diagnostic.tunnel("fixture-openshell", 19445, 8080):
        status, data, message = subject.exchange(
            diagnostic.native_ca, diagnostic.bootstrap, context.sandbox_id,
            context.provider_prefix, assertion, port=19445,
        )
    diagnostic.save("failed-read-grant.private.json", {
        "grpc_status": status, "grpc_message": message,
        "response_base64": base64.b64encode(data).decode(),
    })
    return {
        "grpc_status": status, "category": classify(status, message),
        "tool_call_retried": False, "raw_response_withheld": True,
    }
