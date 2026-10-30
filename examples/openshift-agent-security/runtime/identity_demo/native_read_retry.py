# SPDX-License-Identifier: Apache-2.0
"""Bounded transport recovery for the initial read-only native identity check."""

from __future__ import annotations

from collections.abc import Callable
import time

MAX_ATTEMPTS = 3


def transient_read_failure(value: dict) -> bool:
    """Never retry a policy/TLS rejection or a tool error as a transport outage."""
    if value.get("read_passed") is not False:
        return False
    markers = set(value.get('reason_markers', []))
    if markers & {'denied', 'forbidden', 'certificate', 'verify', 'issuer', 'policy'} or value.get('mcp_failure_category'):
        return False
    events = value.get('events', [])
    if not isinstance(events, list) or any(not isinstance(e, dict) for e in events):
        return False
    # Only a failed MCP initialize is safe to repeat on a gateway availability
    # response. Once a tool was invoked, an HTTP error is not a retry signal.
    if len(events) == 1 and events[0].get('method') == 'initialize':
        if events[0].get('http_status') in (502, 503, 504):
            return value.get('failure_kind') == 'ValueError'
    if any(e.get('http_status') not in (200, 202, 204) for e in events):
        return False
    kind = value.get("failure_kind")
    if kind in ("RemoteDisconnected", "ConnectionResetError", "TimeoutError"):
        return True
    markers = set(value.get("reason_markers", []))
    return (
        kind == "URLError"
        and bool(markers & {"timeout", "timed", "refused", "reset", "unreachable"})
        and not markers
        & {"denied", "forbidden", "certificate", "verify", "issuer", "policy"}
    )


def initial_protected_read(
    read: Callable[[], dict],
    retry: Callable[[int], None],
    sleep: Callable[[float], None] = time.sleep,
    *, observe: Callable[[dict, int], None] | None = None,
) -> tuple[dict, dict]:
    """Retry only this pre-approval read, at most twice; never accept a write callable here.

    An unavailable SPIRE workload-attestor can close initialize before a response.
    Backoff permits its selector cache to settle. Initial gateway availability
    errors can recover within the same bound. Policy denials and model/tool
    errors fail immediately. This helper is deliberately absent from write paths.
    """
    attempts = []
    for index in range(MAX_ATTEMPTS):
        value = read()
        if observe is not None:
            observe(value, index + 1)
        attempts.append(
            {
                "attempt": index + 1,
                "passed": value.get("read_passed") is True,
                "transport_unavailable": transient_read_failure(value),
            }
        )
        if not attempts[-1]["transport_unavailable"] or index == MAX_ATTEMPTS - 1:
            return value, {"attempts": attempts, "write_retried": False}
        retry(index + 1)
        sleep(2**index)
    raise AssertionError("bounded read loop exhausted")
