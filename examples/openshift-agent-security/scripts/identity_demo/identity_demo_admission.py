# SPDX-License-Identifier: Apache-2.0
"""Bound public request admission without retaining anonymous client identities."""
import time

from starlette.responses import JSONResponse


class PublicAdmission:
    """One process-wide budget; forwarding headers cannot create extra buckets.

    Authentication/authorization remain inside the application. Operator and
    backend traffic use their separate listener/routes and are not login traffic.
    These limits complement platform ingress limits; they do not stop upstream
    network saturation or provide per-user fairness under deliberate flooding.
    """
    def __init__(self, app, *, clock=time.monotonic, maximum=64, login_burst=30, login_rate=2):
        self.app, self.clock, self.maximum = app, clock, maximum
        self.burst, self.rate = login_burst, login_rate
        self.tokens, self.at, self.active = float(login_burst), clock(), 0

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or scope['path'] == '/healthz':
            await self.app(scope, receive, send)
            return
        limited = self.active >= self.maximum
        if scope['path'] in ('/login', '/callback'):
            now = self.clock()
            self.tokens = min(self.burst, self.tokens+max(0, now-self.at)*self.rate)
            self.at = now
            limited = limited or self.tokens < 1
            if not limited:
                self.tokens -= 1
        if limited:
            response = JSONResponse({'allowed': False, 'reason': 'request_capacity'}, status_code=429,
                                    headers={'Retry-After': '2', 'Cache-Control': 'no-store'})
            await response(scope, receive, send)
            return
        self.active += 1
        try:
            await self.app(scope, receive, send)
        finally:
            self.active -= 1
