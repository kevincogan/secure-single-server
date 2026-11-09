# SPDX-License-Identifier: Apache-2.0
"""Shared bounded HTTP authentication and request parsing."""
from __future__ import annotations
import secrets
from starlette.requests import Request
from starlette.responses import JSONResponse
from identity_demo_run_store import Denied, strict_json

def secret_matches(actual: str, expected: str) -> bool:
    """Compare credential bytes safely, including malformed non-ASCII input."""
    return secrets.compare_digest(actual.encode(), expected.encode())

async def json_fields(self, request, expected, *, limit, reason):
    """Validate one bounded JSON shape after the caller's role check."""
    data = strict_json(await self.body(request, limit))
    if data.keys() != expected:
        raise Denied(reason)
    return data


def internal(request: Request, secret: str) -> None:
    """Authenticate scoped internal callers using constant-time comparison."""
    received = request.headers.get("authorization", "")
    if not secret_matches(received, "Bearer " + secret):
        raise Denied("internal_authentication")


def console_operator(self, request: Request, role: str = 'coordinator') -> None:
    """Keep coordination behind the existing operator credential boundary."""
    if self.config.private_operator_api:
        if role == 'observer':
            actual = request.headers.get('Authorization', '')
            if not any(secret_matches(actual, 'Bearer ' + key) for key in
                       (self.config.coordinator_secret, self.config.preparer_secret, self.config.operator_secret)):
                raise Denied('internal_auth')
        else:
            key = {'coordinator': self.config.coordinator_secret,
                   'preparer': self.config.preparer_secret, 'operator': self.config.operator_secret}[role]
            internal(request, key)
    else:
        internal(request, self.config.operator_secret)
    if not self.config.coordinator_enabled:
        raise Denied("console_disabled")


def execution_operator(self, request: Request) -> None:
    """Select explicit execution mode; never fall back after failed runtime auth.

    Direct CLI maintenance uses the installer-held operator credential on
    the private listener. Cluster mode requires the separate coordinator
    credential; neither runtime role can enable direct mode.
    """
    if self.config.private_operator_api and self.config.coordinator_enabled:
        console_operator(self, request)
    else:
        internal(request, self.config.operator_secret)


async def denied(request, error):
    return JSONResponse({"allowed": False, "reason": str(error)}, status_code=403)
