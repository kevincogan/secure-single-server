# SPDX-License-Identifier: Apache-2.0
"""Shared admission/display timing; durable allocation remains authoritative."""
import time

MIN_RUN_SECONDS = 480

ROUTINE_CHECK_FRESH_SECONDS = 90

ROUTINE_CHECK_WAIT_SECONDS = 30

def checking_readiness(coordinator: dict) -> bool:
    """Recognize routine preflight while preserving every admission and recovery gate."""
    return bool(coordinator.get('online') and coordinator.get('phase') == 'preparing'
                and not any(coordinator.get(key) for key in
                            ('ready', 'busy', 'reason', 'uncertain', 'recovery_required', 'preparing_context')))

def can_start_during_check(coordinator: dict, *, now: float | None = None) -> bool:
    """Allow a request during routine preflight only after a recent successful check."""
    checked_at = coordinator.get('checked_at')
    current = time.time() if now is None else now
    return (checking_readiness(coordinator) and type(checked_at) is int and checked_at > 0
            and 0 <= current - checked_at <= ROUTINE_CHECK_FRESH_SECONDS)
