# SPDX-License-Identifier: Apache-2.0
"""Transport recovery is bounded and cannot mask a real authorization denial."""

import pytest

from native_read_retry import initial_protected_read, transient_read_failure


@pytest.mark.parametrize(
    "failure", ["RemoteDisconnected", "ConnectionResetError", "TimeoutError"]
)
def test_idempotent_read_recovers_after_temporary_transport_loss(failure: str) -> None:
    responses = iter(
        [
            {"read_passed": False, "failure_kind": failure, "events": []},
            {
                "read_passed": True,
                "events": [{"method": "tools/call", "http_status": 200}],
            },
        ]
    )
    retried, waits = [], []
    result, evidence = initial_protected_read(
        lambda: next(responses), retried.append, waits.append
    )
    assert result["read_passed"] and len(evidence["attempts"]) == 2
    assert retried == [1] and waits == [1] and evidence["write_retried"] is False


def test_persistent_transport_loss_exhausts_two_retries_and_remains_failed() -> None:
    attempts, retried, waits = [], [], []

    def read() -> dict:
        attempts.append(True)
        return {
            "read_passed": False,
            "failure_kind": "RemoteDisconnected",
            "events": [],
        }

    result, evidence = initial_protected_read(read, retried.append, waits.append)
    assert result["read_passed"] is False and len(attempts) == 3
    assert retried == [1, 2] and waits == [1, 2] and len(evidence["attempts"]) == 3


@pytest.mark.parametrize(
    "value",
    [
        {
            "read_passed": False,
            "failure_kind": "RemoteDisconnected",
            "events": [{"http_status": 403}],
        },
        {
            "read_passed": False,
            "failure_kind": "URLError",
            "events": [],
            "reason_markers": ["certificate", "verify", "timed"],
        },
        {
            "read_passed": False,
            "failure_kind": "ValueError",
            "events": [{"http_status": 200}],
        },
        {"read_passed": False, "mcp_failure_category": "tool_error", "events": []},
        {"read_passed": True, "events": []},
    ],
)
def test_denial_tls_failure_and_tool_errors_are_never_retried(value: dict) -> None:
    calls, retries = [], []

    def read() -> dict:
        calls.append(True)
        return value

    result, _ = initial_protected_read(read, retries.append, lambda _: None)
    assert result is value and calls == [True] and retries == []
    assert not transient_read_failure(value)


@pytest.mark.parametrize('status', [502, 503, 504])
def test_only_initial_gateway_unavailability_can_recover(status: int) -> None:
    responses = iter([
        {'read_passed':False, 'failure_kind':'ValueError', 'events':[{'method':'initialize','http_status':status}]},
        {'read_passed':True, 'events':[{'method':'initialize','http_status':200}]},
    ])
    observations, retries = [], []
    result, evidence = initial_protected_read(lambda: next(responses), retries.append, lambda _:None,
        observe=lambda value, attempt: observations.append((attempt, value['read_passed'])))
    assert result['read_passed'] and retries == [1]
    assert observations == [(1, False), (2, True)] and evidence['write_retried'] is False


@pytest.mark.parametrize('event', [
    {'method':'initialize','http_status':401}, {'method':'initialize','http_status':403},
    {'method':'initialize','http_status':500}, {'method':'tools/call','http_status':502},
    {'method':'tools/list','http_status':503}, {'http_status':502},
])
def test_http_denial_and_post_initialize_errors_are_not_retried(event: dict) -> None:
    value = {'read_passed':False, 'failure_kind':'ValueError', 'events':[event]}
    attempts, retries = [], []
    result, _ = initial_protected_read(lambda: attempts.append(True) or value, retries.append, lambda _:None)
    assert result is value and attempts == [True] and not retries


def test_persistent_initialize_502_remains_failed_after_three_attempts() -> None:
    value = {'read_passed':False, 'failure_kind':'ValueError', 'events':[{'method':'initialize','http_status':502}]}
    attempts, retries = [], []
    result, evidence = initial_protected_read(lambda: attempts.append(True) or value, retries.append, lambda _:None)
    assert result is value and len(attempts) == len(evidence['attempts']) == 3 and retries == [1,2]
