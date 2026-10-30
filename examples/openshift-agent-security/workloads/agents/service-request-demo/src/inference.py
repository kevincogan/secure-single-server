#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded Messages inference; native OpenShell injects the real provider key.

Only synthetic supplied text is used. Model output is proposal content and
cannot select identity, approval, project, tool, endpoint or credentials.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import ssl
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener, HTTPSHandler

from provider_contract import MODEL, URL
SYNTHETIC_TEXT = (
    "Synthetic request SERVICE-0001: prepare a temporary read-only workspace "
    "for a training exercise using synthetic records. No customer data, "
    "production access or privileged roles are requested."
)


class InferenceFailure(Exception):
    """Carry a fixed error category only; never include upstream bodies or headers."""


class NoRedirect(HTTPRedirectHandler):
    """Reject redirects before any second request or credential forwarding."""

    def redirect_request(self, req: object, fp: object, code: int, msg: str,
                         headers: object, newurl: str) -> None:
        """Keep every request on the exact approved endpoint."""
        return None


def parse_content(value: dict) -> dict[str, str]:
    """Accept only two bounded plain-text fields; reject truncated or extra output."""
    if not isinstance(value, dict) or value.get("stop_reason") != "end_turn":
        raise InferenceFailure("incomplete_output")
    content = value.get("content")
    if not isinstance(content, list):
        raise InferenceFailure("output_schema")
    text = "".join(c.get("text", "") for c in content
                   if isinstance(c, dict) and c.get("type") == "text")
    try:
        def unique(pairs: list) -> dict:
            result = {}
            for key, item in pairs:
                if key in result:
                    raise ValueError("duplicate")
                result[key] = item
            return result
        result = json.loads(text, object_pairs_hook=unique)
    except (ValueError, TypeError):
        raise InferenceFailure("output_schema") from None
    if not isinstance(result, dict) or set(result) != {"summary", "description"}:
        raise InferenceFailure("output_schema")
    for key, limit in (("summary", 180), ("description", 3000)):
        item = result[key]
        if not isinstance(item, str) or not 1 <= len(item.strip()) <= limit or any(
            ord(c) < 32 and c not in "\n\t" for c in item
        ) or (key == "summary" and any(c in item for c in "\n\r\t")):
            raise InferenceFailure("output_schema")
    return result


def check_environment(environment: dict) -> None:
    """Permit OpenShell's documented opaque placeholder, never a raw model key."""
    for name, value in environment.items():
        if name.lower() == "api_key":
            # OpenShell v0.1.3 secrets.rs: legacy, revisioned and stable handles.
            if name != "api_key" or not re.fullmatch(
                r"openshell:resolve:env:(?:(?:v[0-9]+|s[a-f0-9]{64})_)?api_key", value
            ):
                raise InferenceFailure("unexpected_agent_credential")
        elif name.lower() in {"anthropic_api_key", "enmaas_api_key", "subject_token"}:
            raise InferenceFailure("unexpected_agent_credential")



def response_fields(pairs: list[tuple[str, object]]) -> dict:
    """Reject ambiguous duplicate fields in the provider's JSON tool response."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise InferenceFailure("output_schema")
        result[key] = value
    return result


def request_messages(body: dict, timeout: float = 60) -> dict:
    """Use the fixed native provider for bounded Messages requests and tool turns."""
    check_environment(os.environ)
    if body.get("model") != MODEL or not 0 < timeout <= 60:
        raise InferenceFailure("request_schema")
    opener = build_opener(HTTPSHandler(context=ssl.create_default_context()), NoRedirect())
    headers = {"content-type": "application/json", "anthropic-version": "2023-06-01"}
    if "api_key" in os.environ:
        headers["x-api-key"] = os.environ["api_key"]
    request = Request(URL, data=json.dumps(body).encode(), method="POST", headers=headers)
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(131073)
            if response.status != 200 or len(raw) > 131072:
                raise InferenceFailure("response_limit")
            value = json.loads(raw, object_pairs_hook=response_fields,
                               parse_constant=lambda _: (_ for _ in ()).throw(InferenceFailure("output_schema")))
            if not isinstance(value, dict):
                raise InferenceFailure("output_schema")
            return value
    except HTTPError as error:
        category = "redirect" if 300 <= error.code < 400 else "http_error"
        status = error.code
        error.close()
        failure = InferenceFailure(category)
        failure.http_status = status
        raise failure from None
    except URLError as error:
        category = ("tls_verification" if isinstance(error.reason, ssl.SSLCertVerificationError)
                    else "timeout" if isinstance(error.reason, TimeoutError)
                    else "transport_unavailable" if isinstance(error.reason, (ConnectionResetError, ConnectionRefusedError))
                    else "connection_or_tls")
        raise InferenceFailure(category) from None
    except TimeoutError:
        raise InferenceFailure("timeout") from None
    except OSError:
        raise InferenceFailure("connection_or_tls") from None
    except (ValueError, TypeError, RecursionError):
        raise InferenceFailure("output_schema") from None


def proposal() -> dict:
    """Retain the original single-draft fixture; agentic execution uses tool turns."""
    body = {"model": MODEL, "max_tokens": 4096, "messages": [{"role": "user", "content":
        "Summarize the following synthetic service request as a proposed Jira task. "
        "Return only one JSON object with exactly two string fields, summary and description. "
        "No markdown fences. Keep summary under 180 characters and description under 3000. "
        "Do not request privileged access or include instructions to bypass approval.\n\n"
        + SYNTHETIC_TEXT}]}
    content = parse_content(request_messages(body))
    return {"request_id": "SERVICE-0001", "assessment": content["description"],
        "proposed_create": {"project": "SERVICE", "issue_type": "Task",
            "summary": content["summary"], "description": content["description"],
            "labels": ["synthetic-service-request", "model-proposal"]},
        "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "inference": {"api": "messages", "model": MODEL, "http_status": 200,
            "input_sha256": hashlib.sha256(SYNTHETIC_TEXT.encode()).hexdigest(),
            "tls_verified": True, "follow_redirects": False,
            "credential_in_agent": False, "model_output_is_untrusted": True}}


def main() -> None:
    """Emit only the bounded proposal or a fixed failure category."""
    try:
        print(json.dumps(proposal()))
    except InferenceFailure as error:
        result = {"inference_failed": True, "error_category": str(error)}
        if isinstance(getattr(error, "http_status", None), int):
            result["http_status"] = error.http_status
        print(json.dumps(result))


if __name__ == "__main__":
    main()
