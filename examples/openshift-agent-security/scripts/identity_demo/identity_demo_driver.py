# SPDX-License-Identifier: Apache-2.0
"""One HTTPS pilot driver: real PKCE login, approval UI and live authorization.

Only trusted operators register execution contexts and supply actual workload
reports. Browser requests cannot select a subject, SPIFFE ID or provider token.
Operator coordination retains native management credentials outside the UI.
No backend mutation is implemented here; an adapter must separately claim it.
"""

from __future__ import annotations

import base64
import asyncio
from dataclasses import dataclass
import hashlib
from html import escape
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import sqlite3
import stat
import time
from uuid import UUID
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request as URLRequest,
    build_opener,
)

import jwt
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

import identity_demo_console as console
from identity_demo_console_store import ConsoleStore

from identity_demo_run_store import (
    Denied,
    RunStore,
    create_call,
    read_call,
    strict_json,
)

COOKIE = "__Host-identity-demo"
STATE_COOKIE = "__Host-identity-login"
SESSION_MAX_SECONDS = 36000
SESSION_IDLE_SECONDS = 1800
REFRESH_MARGIN_SECONDS = 60


@dataclass(frozen=True)
class Config:
    """Operator-supplied fixed endpoints, contexts and separately scoped credentials."""

    issuer: str
    client: str
    origin: str
    audience: str
    database: Path
    contexts: tuple[dict, ...]
    gateway_secret: str
    operator_secret: str
    adapter_secret: str
    project: str = "TEST"
    issuer_service: str | None = None
    issuer_ca: str | None = None
    normalized_tool_host: str | None = None
    coordinator_enabled: bool = False
    presenter_subjects: tuple[str, ...] = ()
    stateless_login: bool = False
    private_operator_api: bool = False
    coordinator_secret: str | None = None
    preparer_secret: str | None = None
    jira_view_url: str | None = None
    jira_view_ca: str | None = None


class Verifier:
    """Use the maintained JWT library and only the configured issuer's keys."""

    def __init__(
        self, issuer: str, service: str | None = None, ca: str | None = None
    ) -> None:
        self.issuer = issuer
        self.keys = FixedIssuerKeys(
            (service or issuer) + "/protocol/openid-connect/certs",
            ssl_context=ssl.create_default_context(cafile=ca),
            timeout=5,
        )

    def __call__(self, token: str, audience: str) -> dict:
        """Validate signature, issuer, recipient, expiry and required claims."""
        if not isinstance(token, str) or not 1 <= len(token) <= 16_384:
            raise Denied("invalid_token")
        try:
            key = self.keys.get_signing_key_from_jwt(token).key
            return jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                issuer=self.issuer,
                audience=audience,
                options={"require": ["exp", "iat", "iss", "sub", "aud"]},
            )
        except jwt.PyJWTError as error:
            raise Denied("invalid_token") from error


class NoIssuerRedirect(HTTPRedirectHandler):
    """Never follow redirects while sending a login code or retrieving keys."""

    def redirect_request(
        self,
        req: URLRequest,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        """Deny a redirect without exposing its location or request credentials."""
        raise Denied("issuer_redirect")


class FixedIssuerKeys(jwt.PyJWKClient):
    """Keep PyJWT key refresh/cache behavior with bounded, redirect-free HTTPS."""

    def fetch_data(self) -> dict:
        """Read only the configured issuer; clear failed cache refreshes safely."""
        value = None
        try:
            client = build_opener(
                ProxyHandler({}),
                HTTPSHandler(context=self.ssl_context),
                NoIssuerRedirect(),
            )
            with client.open(URLRequest(self.uri), timeout=self.timeout) as response:
                body = response.read(65_537)
            if len(body) > 65_536:
                raise Denied("issuer_response_size")
            candidate = strict_json(body)
            if not isinstance(candidate, dict) or not isinstance(candidate.get("keys"), list):
                raise Denied("invalid_issuer_keys")
            value = candidate
            return value
        except (HTTPError, URLError, TimeoutError, OSError, ValueError) as error:
            raise Denied("issuer_unavailable") from error
        finally:
            if self.jwk_set_cache is not None:
                self.jwk_set_cache.put(value)


def exchange_code(endpoint: str, fields: bytes, ca: str | None) -> dict:
    """Bound a fixed HTTPS token request with normal CA/name verification."""
    client = build_opener(
        ProxyHandler({}),
        HTTPSHandler(context=ssl.create_default_context(cafile=ca)),
        NoIssuerRedirect(),
    )
    try:
        with client.open(
            URLRequest(endpoint + "/protocol/openid-connect/token", data=fields),
            timeout=8,
        ) as response:
            body = response.read(65_537)
            if len(body) > 65_536:
                raise Denied("issuer_response_size")
            return strict_json(body)
    except HTTPError as error:
        raise Denied("login_exchange") from error
    except (URLError, TimeoutError, OSError) as error:
        raise Denied("issuer_unavailable") from error



def end_issuer_session(endpoint: str, client_id: str, refresh_token: str, ca: str | None) -> bool:
    """End this IdP session once; local sign-out never depends on the network."""
    client = build_opener(ProxyHandler({}),
        HTTPSHandler(context=ssl.create_default_context(cafile=ca)), NoIssuerRedirect())
    try:
        fields = urlencode({"client_id": client_id, "refresh_token": refresh_token}).encode()
        with client.open(URLRequest(endpoint + "/protocol/openid-connect/logout", data=fields),
                         timeout=8) as response:
            response.read(1)
            return response.status in (200, 204)
    except (Denied, HTTPError, URLError, TimeoutError, OSError):
        return False


def safe_https(value: str) -> bool:
    """Require a fixed clean HTTPS endpoint; never accept user-selected URLs."""
    parsed = urlparse(value)
    return (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and not (parsed.username or parsed.password or parsed.query or parsed.fragment)
    )


def secret_matches(actual: str, expected: str) -> bool:
    """Compare credential bytes safely, including malformed non-ASCII input."""
    return secrets.compare_digest(actual.encode(), expected.encode())


def prepare_storage(database: Path) -> None:
    """Restore private modes after a PVC mount without replacing durable state."""
    os.umask(0o077)
    parent = database.parent
    parent.mkdir(mode=0o700, exist_ok=True)
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise ValueError("Owned private state directory required")
    parent.chmod(0o700)
    # SQLite uses these fixed sibling files, never user-selected paths.
    for path in (
        database,
        Path(str(database) + "-journal"),
        Path(str(database) + "-wal"),
        Path(str(database) + "-shm"),
    ):
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError("Owned regular state file required")
        path.chmod(0o600)


def peer_matches(claims: dict, headers: dict) -> bool:
    """Check the sanitized TLS peer forwarded by the trusted bound gateway."""
    peer = headers.get("x-forwarded-client-cert", "")
    if not isinstance(peer, str) or len(peer) > 4096 or "\n" in peer or "\r" in peer:
        return False
    fields = {}
    for part in peer.split(";"):
        name, separator, value = part.partition("=")
        if (
            not separator
            or name in fields
            or name not in ("By", "Hash", "URI", "Subject", "Cert")
        ):
            return False
        if name not in ("Subject", "Cert") and ("," in value or '"' in value):
            return False
        fields[name] = value
    try:
        thumb = claims["cnf"]["x5t#S256"]
        if not isinstance(thumb, str) or len(thumb) != 43:
            return False
        digest = base64.b64decode(thumb + "=", altchars=b"-_", validate=True).hex()
        return fields.get("Hash") == digest and fields.get("URI") == claims["azp"]
    except (KeyError, ValueError, TypeError):
        return False


class Driver:
    """Trusted state owner with a small browser surface and protected internal APIs."""

    def __init__(
        self, config: Config, verifier: Callable[[str, str], dict] | None = None
    ) -> None:
        if not all(
            safe_https(v) for v in (config.issuer, config.origin, config.audience)
        ):
            raise ValueError("Fixed HTTPS endpoints required")
        if config.issuer_service is not None and (
            not safe_https(config.issuer_service)
            or urlparse(config.issuer_service).path != urlparse(config.issuer).path
            or not config.issuer_ca
        ):
            raise ValueError("Fixed issuer service, matching realm and CA required")
        if config.normalized_tool_host not in (
            None,
            "fixture-step4-read-route.fixture-mcp.local",
        ):
            raise ValueError("Exact owned receiving adapter route required")
        if (
            urlparse(config.origin).path not in ("", "/")
            or any(
                len(v) < 32
                for v in (
                    config.gateway_secret,
                    config.operator_secret,
                    config.adapter_secret,
                )
            )
            or len(
                {config.gateway_secret, config.operator_secret, config.adapter_secret}
            )
            != 3
        ):
            raise ValueError(
                "Exact origin and separately scoped private credentials required"
            )
        if type(config.stateless_login) is not bool:
            raise ValueError("Explicit stateless login flag required")
        self.config, self.verify = (
            config,
            verifier
            or Verifier(config.issuer, config.issuer_service, config.issuer_ca),
        )
        if type(config.private_operator_api) is not bool:
            raise ValueError('Boolean private API configuration required')
        if config.private_operator_api:
            credentials = [config.gateway_secret, config.operator_secret, config.adapter_secret,
                           config.coordinator_secret, config.preparer_secret]
            if any(not isinstance(v, str) or len(v) < 32 for v in credentials) or len(set(credentials)) != 5:
                raise ValueError('Distinct role-specific private API credentials required')
        if config.jira_view_url:
            from deployment_profile import active_profile
            expected = 'https://' + active_profile().service_host('fixture-protected-adapter') + ':8443'
            if config.jira_view_url != expected or not config.jira_view_ca:
                raise ValueError('Fixed protected adapter service and CA required')
        if type(config.coordinator_enabled) is not bool:
            raise ValueError("Boolean coordinator configuration required")
        if (not isinstance(config.presenter_subjects, (tuple, list)) or len(config.presenter_subjects) > 8
                or any(not isinstance(v, str) or not 1 <= len(v) <= 255 or any(ord(c) < 32 for c in v)
                       for v in config.presenter_subjects) or len(set(config.presenter_subjects)) != len(config.presenter_subjects)):
            raise ValueError('Explicit bounded presenter subject allowlist required')
        self.store = RunStore(config.database)
        self.console = ConsoleStore(self.store)
        self.store.recover_dispatched()
        self.sessions: dict[str, dict] = {}
        self.pending: dict[str, dict] = {}
        from identity_demo_login_state import LoginState
        self.login_state = LoginState()
        self.tickets: dict[str, dict] = {}
        if len({c["workload"] for c in config.contexts}) != len(
            config.contexts
        ):
            raise ValueError("Distinct trusted execution contexts required")
        from deployment_profile import active_profile

        profile = active_profile()
        for context in config.contexts:
            if (
                context["role"] not in ("triage", "reader")
                or context["namespace"] != profile.namespace_for(context["role"])
                or context["service_account"] != "fixture-openshell-sandbox"
                or context["workload"]
                != "spiffe://" + profile.trust_domain + "/openshell/sandbox/"
                + context["sandbox_id"]
                or context.get("workflow", "cve") not in ("cve", "service-request", "incident-triage")
                or not isinstance(context.get("project", config.project), str)
                or not re.fullmatch(r"[A-Z][A-Z0-9]{1,15}", context.get("project", config.project))
                or (context.get("workflow") == "incident-triage" and context.get("project") != "OPS")
                or (context.get("workflow") in ("service-request", "incident-triage")
                    and context.get("project", config.project) == config.project)
            ):
                raise ValueError("Controlled namespace/role mapping required")
        self.app = Starlette(
            routes=[
                Route("/", self.home),
                Route("/login", self.login),
                Route("/callback", self.callback),
                Route("/logout", self.logout, methods=["POST"]),
                Route("/submit", self.submit, methods=["POST"]),
                Route("/runs/{run}", self.status),
                Route("/runs/{run}/live", self.live_run),
                Route("/runs/{run}/jira", self.jira_issue),
                Route("/console/live", self.live_home),
                Route("/assets/console.js", self.console_script),
                Route("/runs/{run}/approve", self.approve, methods=["POST"]),
                Route("/runs/{run}/cancel", self.cancel, methods=["POST"]),
                Route("/internal/authorize", self.authorize, methods=["POST"]),
                Route("/internal/identity", self.identity, methods=["POST"]),
                Route("/internal/adapter/claim", self.claim, methods=["POST"]),
                Route("/internal/adapter/preview", self.preview, methods=["POST"]),
                Route("/internal/adapter/read", self.adapter_read, methods=["POST"]),
                Route("/internal/adapter/history", self.history_ticket, methods=["POST"]),
                Route("/internal/adapter/observation", self.observation_ticket, methods=["POST"]),
                Route("/internal/adapter/finish", self.finish, methods=["POST"]),
                Route(
                    "/internal/adapter/reconciliation",
                    self.reconciliation,
                    methods=["POST"],
                ),
                Route("/internal/adapter/reconcile", self.reconcile, methods=["POST"]),
                Route("/internal/operator/run", self.operator_run, methods=["POST"]),
                Route("/internal/operator/report", self.report, methods=["POST"]),
                Route("/internal/operator/revoke", self.revoke, methods=["POST"]),
                Route("/internal/operator/credentials/{run}", self.credentials),
                Route("/runs", self.history),
                Route("/evidence", self.evidence),
                Route("/settings", self.settings),
                Route("/settings/live", self.live_settings),
                Route("/settings/prepare", self.prepare_presentation, methods=["POST"]),
                Route("/internal/operator/console/heartbeat", self.console_heartbeat, methods=["POST"]),
                Route("/internal/operator/console/next", self.console_next, methods=["POST"]),
                Route("/internal/operator/console/update", self.console_update, methods=["POST"]),
                Route("/internal/operator/console/runs/{run}", self.console_inspect),
                Route("/internal/operator/console/backend-state/{run}", self.backend_state),
                Route("/internal/operator/console/state", self.console_state),
                Route("/internal/operator/console/pool", self.console_pool, methods=["GET", "POST"]),
                Route("/internal/operator/console/prepare/next", self.prepare_next, methods=["POST"]),
                Route("/internal/operator/console/prepare/finish", self.prepare_finish, methods=["POST"]),
                Route("/internal/operator/console/prepare/retirement-check", self.retirement_check, methods=["POST"]),
                Route("/internal/operator/console/review-recovery", self.console_review_recovery, methods=["POST"]),
                Route("/healthz", self.health),
            ],
            exception_handlers={Denied: self.denied},
        )
        private_routes = [r for r in self.app.routes if r.path.startswith('/internal/operator/') or r.path == '/healthz']
        self.private_app = Starlette(routes=private_routes, exception_handlers={Denied: self.denied})
        async def private_headers(request, next_handler):
            response = await next_handler(request)
            response.headers.update({'Cache-Control':'no-store', 'X-Content-Type-Options':'nosniff'})
            return response
        self.private_app.add_middleware(BaseHTTPMiddleware, dispatch=private_headers)
        if config.private_operator_api:
            self.app.router.routes[:] = [r for r in self.app.routes if not r.path.startswith('/internal/operator/')]
        self.app.add_middleware(BaseHTTPMiddleware, dispatch=self.browser_session_cookie)
        if config.stateless_login:
            from identity_demo_admission import PublicAdmission
            self.app.add_middleware(PublicAdmission)

    def execution_contexts(self, *, active_only: bool = False) -> tuple[dict, ...]:
        """Combine source configuration with append-only trusted runtime registrations."""
        return (*self.config.contexts, *self.console.contexts(active_only=active_only))

    def context_for_workload(self, workload: str) -> dict | None:
        configured=next((c for c in self.config.contexts if c['workload']==workload),None)
        return configured or self.console.context_for_workload(workload)

    async def prepare_next(self, request: Request) -> Response:
        """Reserve fresh preparation without stopping or replacing the coordinator."""
        self.console_operator(request, 'preparer')
        data = strict_json(await self.body(request, 1024))
        if set(data) != {'owner'}:
            raise Denied('console_fields')
        return JSONResponse({'preparation': self.console.prepare_next(data['owner'], self.config.contexts, self.config.project)},
                            headers={'Cache-Control': 'no-store'})

    async def prepare_finish(self, request: Request) -> Response:
        """Accept only a trusted provisioner's exact fresh native identity receipt."""
        self.console_operator(request, 'preparer')
        data = strict_json(await self.body(request, 8192))
        if set(data) != {'owner', 'id', 'context', 'receipt_sha256'}:
            raise Denied('console_fields')
        context = data['context']
        with self.store.transaction() as db:
            reservation = db.execute('SELECT target FROM console_preparations WHERE id=? AND owner=?',
                                     (data['id'], data['owner'])).fetchone()
        retiring = reservation and json.loads(reservation['target']).get('operation') == 'retire'
        if context is not None and not retiring:
            from deployment_profile import active_profile
            profile = active_profile()
            required = {'sandbox_name', 'sandbox_id', 'role', 'service_account', 'registration_name',
                        'provider_prefix', 'namespace', 'workspace', 'workload', 'workflow', 'project', 'console_prepared'}
            target = json.loads(reservation['target']) if reservation else {}
            if target.get('profile_id'):
                required = required - {'workflow','project'} | {'profile_id','profile_fingerprint','native_policy_hash'}
            if not isinstance(context, dict) or set(context) != required:
                raise Denied('preparation_context')
            try:
                canonical = str(UUID(context['sandbox_id'])) == context['sandbox_id']
                prefix = 'identity-demo-step56-' + ('' if profile.installation_id == 'identity-demo' else profile.installation_id + '-')
                suffix = context['sandbox_name'].rsplit('-', 1)[-1]
                valid = (canonical and context['role'] in ('triage', 'reader')
                    and re.fullmatch('[a-z0-9]{1,3}', suffix)
                    and context['sandbox_name'] == 'demo-s56-' + context['role'] + '-' + suffix
                    and len(context['sandbox_name']) <= 19
                    and context['registration_name'] == prefix + context['role'] + '-' + suffix
                    and context['provider_prefix'] == context['sandbox_name'] + '-exchange'
                    and context['namespace'] == profile.namespace_for(context['role'])
                    and context['workspace'] == context['namespace']
                    and context['service_account'] == 'fixture-openshell-sandbox'
                    and context['workload'] == 'spiffe://' + profile.trust_domain + '/openshell/sandbox/' + context['sandbox_id']
                    and context['console_prepared'] is True
                    and not any(c['workload'] == context['workload'] or
                        (c.get('namespace'), c.get('sandbox_name')) == (context['namespace'], context['sandbox_name'])
                        for c in self.config.contexts))
            except (KeyError, TypeError, ValueError, AttributeError):
                valid = False
            if not valid:
                raise Denied('preparation_context')
        self.console.finish_preparation(data['owner'], data['id'], context, data['receipt_sha256'])
        return JSONResponse({'recorded': True}, headers={'Cache-Control': 'no-store'})

    async def denied(self, request: Request, error: Denied) -> Response:
        """Return deliberate safe denials with no credential or exception body."""
        if "text/html" in request.headers.get("accept", ""):
            response = self.page('<div class="heading"><h1>Request could not proceed</h1></div>'
                '<section class="card"><p>' + escape(console.public_error(str(error)))
                + '</p><p><a href="/">Return to workflows</a> · <a href="/login">Sign in again</a></p></section>')
            response.status_code = 403
            return response
        return JSONResponse({"allowed": False, "reason": str(error)}, status_code=403)

    async def health(self, request: Request) -> Response:
        """Expose readiness without run, session or credential information."""
        return JSONResponse({"ready": True, "execution_contexts_configured": bool(self.execution_contexts(active_only=True))})

    def end_browser_session(self, identifier: str, session: dict) -> None:
        """Remove local authority and revoke its runs without replaying dispatched writes."""
        if self.sessions.get(identifier) is session:
            self.sessions.pop(identifier)
        for run in session.get("runs", ()):
            self.store.revoke("run_id", run)

    @staticmethod
    def session_deadline(session: dict) -> int:
        """Keep the bounded sliding browser lifetime distinct from run authority."""
        return int(session.get("session_expires", session["claims"]["exp"]))

    def display_claims(self, session: dict) -> dict:
        """Use local lifetime only for presentation, never token verification or delegation."""
        return {**session["claims"], "exp": self.session_deadline(session),
                "session_refresh": "session_expires" in session,
                "display_role": self.role(session["claims"])}

    async def session(self, request: Request, *, minimum: int = 0, renew: bool = True, touch: bool = True, force: bool = False) -> dict:
        """Renew only trusted backend credentials; never extend a registered run."""
        identifier = request.cookies.get(COOKIE, "")
        session = self.sessions.get(identifier)
        now = time.time()
        if session is None:
            raise Denied("login_required")
        if (self.session_deadline(session) <= now
                or session.get("last_activity", now) + SESSION_IDLE_SECONDS <= now):
            self.end_browser_session(identifier, session)
            raise Denied("login_required")
        if "session_expires" not in session:
            return session  # Existing non-refreshable headless/fixture session.
        lock = session.setdefault("refresh_lock", asyncio.Lock())
        async with lock:
            now = time.time()
            if self.sessions.get(identifier) is not session:
                raise Denied("login_required")
            if (self.session_deadline(session) <= now
                    or session.get("last_activity", now) + SESSION_IDLE_SECONDS <= now):
                self.end_browser_session(identifier, session)
                raise Denied("login_required")
            if renew and (force or session["claims"]["exp"] <= now + max(minimum, REFRESH_MARGIN_SECONDS)
                          or session.get("refresh_expires", 0) <= now + REFRESH_MARGIN_SECONDS):
                try:
                    if session.get("refresh_expires", 0) <= now:
                        raise Denied("login_required")
                    fields = urlencode({"grant_type": "refresh_token", "client_id": self.config.client,
                                        "refresh_token": session["refresh_token"]}).encode()
                    tokens = await run_in_threadpool(exchange_code,
                        self.config.issuer_service or self.config.issuer, fields, self.config.issuer_ca)
                    claims = await run_in_threadpool(self.verify, tokens["access_token"], self.config.client)
                    old = session["claims"]
                    if (claims["iss"] != old["iss"] or claims["sub"] != old["sub"]
                            or claims.get("azp") != self.config.client
                            or self.role(claims) != self.role(old)
                            or (old.get("sid") and claims.get("sid") != old["sid"])
                            or claims["exp"] <= time.time() + REFRESH_MARGIN_SECONDS):
                        raise Denied("login_binding")
                    if "id_token" in tokens:
                        identity = await run_in_threadpool(self.verify, tokens["id_token"], self.config.client)
                        if identity["sub"] != claims["sub"] or (old.get("sid") and identity.get("sid") != old["sid"]):
                            raise Denied("login_binding")
                    refresh = tokens.get("refresh_token", session["refresh_token"])
                    lifetime = tokens.get("refresh_expires_in")
                    if (not isinstance(refresh, str) or not 1 <= len(refresh) <= 16384
                            or type(lifetime) is not int or lifetime <= 0):
                        raise Denied("login_binding")
                    if (self.sessions.get(identifier) is not session
                            or self.session_deadline(session) <= time.time()
                            or session.get("last_activity", time.time()) + SESSION_IDLE_SECONDS <= time.time()):
                        raise Denied("login_required")
                    # A response lost after rotation must never be blindly replayed.
                    session.update(claims=claims, token=tokens["access_token"],
                        refresh_token=refresh, refresh_expires=min(session["absolute_expires"], int(time.time()) + lifetime))
                except asyncio.CancelledError:
                    self.end_browser_session(identifier, session)
                    raise
                except Exception:
                    self.end_browser_session(identifier, session)
                    raise Denied("session_renewal_required") from None
            # Passive polling may renew tokens but cannot keep an idle browser alive forever.
            if touch and not request.url.path.endswith("/live"):
                session["last_activity"] = time.time()
            session["session_expires"] = min(session["absolute_expires"], session["refresh_expires"],
                int(session["last_activity"] + SESSION_IDLE_SECONDS))
            request.state.browser_session = (identifier, session)
        return session

    async def browser_session_cookie(self, request: Request, call_next: Callable) -> Response:
        """Renew only an authenticated opaque cookie, bounded by server-side expiry."""
        response = await call_next(request)
        binding = getattr(request.state, "browser_session", None)
        if binding is not None:
            identifier, session = binding
            remaining = int(self.session_deadline(session) - time.time())
            if self.sessions.get(identifier) is session and remaining > 0:
                response.set_cookie(COOKIE, identifier, path="/", secure=True,
                    httponly=True, samesite="lax", max_age=remaining)
        return response

    @staticmethod
    def internal(request: Request, secret: str) -> None:
        """Authenticate scoped internal callers using constant-time comparison."""
        received = request.headers.get("authorization", "")
        if not secret_matches(received, "Bearer " + secret):
            raise Denied("internal_authentication")

    async def body(self, request: Request, limit: int = 131_072) -> bytes:
        """Bound the actual incoming stream even without Content-Length."""
        result = bytearray()
        async for chunk in request.stream():
            result.extend(chunk)
            if len(result) > limit:
                raise Denied("request_size")
        return bytes(result)

    async def form(self, request: Request, *, renew: bool = True) -> tuple[dict, dict]:
        """Check exact Origin, session CSRF and duplicate-free bounded form fields."""
        session = await self.session(request, renew=False, touch=False)
        if request.headers.get("origin") != self.config.origin:
            raise Denied("csrf_origin")
        try:
            fields = parse_qs(
                (await self.body(request, 8192)).decode(),
                strict_parsing=True,
                max_num_fields=12,
            )
        except (ValueError, UnicodeError) as error:
            raise Denied("invalid_form") from error
        if any(len(v) != 1 for v in fields.values()):
            raise Denied("duplicate_field")
        values = {k: v[0] for k, v in fields.items()}
        if not secret_matches(values.pop("csrf", ""), session["csrf"]):
            raise Denied("csrf_token")
        session = await self.session(request, renew=renew)
        return session, values

    def page(self, content: str, *, user: str = "", active: str = "Workflows",
             presentation: bool = False, refresh: bool = False, csrf: str = "", status_code: int = 200, live_url: str = "", live_kind: str = "run", session_deadline: int = 0) -> HTMLResponse:
        """Render one local-asset console while preserving existing browser protections."""
        headers = {
            "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
            "Referrer-Policy": "same-origin",
        }
        response = HTMLResponse(console.shell(content, user=user, active=active,
            presentation=presentation, csrf=csrf, live_url=live_url, live_kind=live_kind,
            session_deadline=session_deadline), headers=headers, status_code=status_code)
        return response

    @staticmethod
    def presentation(request: Request) -> bool:
        """Ignore legacy visual preferences; navigation remains available on every page."""
        return False

    def used_contexts(self, contexts: list[dict]) -> set[str]:
        """Probe only current candidates using the unique workload index."""
        workloads = [c['workload'] for c in contexts]
        used = set()
        with self.store.read_transaction() as db:
            for start in range(0, len(workloads), 64):
                selected = workloads[start:start+64]
                used.update(r[0] for r in db.execute('SELECT workload FROM runs WHERE workload IN ('
                    + ','.join('?' for _ in selected) + ')', selected))
        return used

    async def home(self, request: Request) -> Response:
        """Show fixed approved workflows and observed coordinator availability."""
        try:
            session = await self.session(request)
        except Denied:
            return self.page('<div class="heading"><div><h1>Secure agent workflows</h1>'
                '<p class="muted">One place to review proposals, approve exact actions and follow protected outcomes.</p></div></div>'
                '<section class="card"><h2>Sign in to your workspace</h2><p>Use your real identity. User and workload permissions are enforced independently.</p>'
                '<a class="button primary" href="/login">Sign in</a></section>')
        claims = self.display_claims(session)
        configured = [c for c in self.execution_contexts(active_only=True) if not self.config.coordinator_enabled or c.get("console_prepared") is True]
        if self.config.coordinator_enabled:
            used = self.used_contexts(configured)
            visible = [c for c in configured if c["workload"] not in used and self.console.context_ready(c["workload"])]
        else:
            visible = configured
        if request.query_params.get("view") == "overview":
            return self.page(console.overview(self.console.history(claims["sub"]),
                self.console.available(self.config.coordinator_enabled), claims),
                user=claims.get("preferred_username", claims["display_role"]), active="Overview",
                presentation=self.presentation(request), csrf=session["csrf"], live_url="/console/live", live_kind="home",
                session_deadline=self.session_deadline(session))
        return self.page(console.home(claims, session["csrf"],
            available=bool(configured),
            service=any(c.get("workflow") == "service-request" for c in configured),
            coordinator=self.console.available(self.config.coordinator_enabled),
            roles=tuple(r for r in ('triage', 'reader') if any(c['role'] == r and c.get('workflow', 'cve') == 'cve' for c in configured)),
            available_roles=tuple(r for r in ('triage', 'reader') if any(c['role'] == r and c.get('workflow', 'cve') == 'cve' for c in visible)),
            service_available=any(c.get("workflow") == "service-request" for c in visible),
            incident=any(c.get("workflow") == "incident-triage" for c in configured),
            incident_available=any(c.get("workflow") == "incident-triage" for c in visible)),
            user=claims.get("preferred_username", claims["display_role"]),
            active="Overview" if request.query_params.get("view") == "overview" else "Workflows",
            presentation=self.presentation(request), csrf=session["csrf"], live_url="/console/live", live_kind="home",
            session_deadline=self.session_deadline(session))

    async def history(self, request: Request) -> Response:
        """Expose only the signed-in owner's retained runs."""
        session = await self.session(request)
        return self.page(console.run_list(self.console.history(session["claims"]["sub"])),
            user=session["claims"].get("preferred_username", self.role(session["claims"])), active="Runs", presentation=self.presentation(request), csrf=session["csrf"], session_deadline=self.session_deadline(session))

    async def evidence(self, request: Request) -> Response:
        """Keep evidence traceable to actual owner-scoped runs, not illustrative badges."""
        session = await self.session(request)
        records = self.console.history(session["claims"]["sub"])
        proofs = [(r, self.console.describe(r['id'])) for r in records]
        return self.page(console.evidence_view(proofs),
            user=session["claims"].get("preferred_username", self.role(session["claims"])),
            active="Evidence", csrf=session["csrf"], session_deadline=self.session_deadline(session))

    def presenter(self, session: dict) -> bool:
        """Limit bounded provisioning requests to explicitly configured current analyst subjects."""
        claims = session['claims']
        return bool(self.config.coordinator_enabled and claims.get('iss') == self.config.issuer
                    and claims.get('sub') in self.config.presenter_subjects and self.role(claims) == 'analyst')

    def presentation_plan(self) -> dict:
        """Fix scope and caps on the server; the browser supplies no resource parameters."""
        slots = {(c.get('workflow', 'cve'), c['role']) for c in self.execution_contexts(active_only=True)}
        sequence = [v for v in (
            {'workflow': 'cve', 'role': 'triage'}, {'workflow': 'cve', 'role': 'triage'},
            {'workflow': 'cve', 'role': 'reader'}, {'workflow': 'service-request', 'role': 'triage'},
            {'workflow': 'incident-triage', 'role': 'triage'}) if (v['workflow'], v['role']) in slots]
        return {'sequence': sequence, 'buffer': 0, 'global_limit': 6,
                'workflow_limits': {w: 4 if w == 'cve' else 1 for w in {v[0] for v in slots}}}

    def settings_content(self, session: dict) -> str:
        """Render aggregate pool progress without execution identities or operator credentials."""
        pool = self.console.pool_status(self.config.contexts, self.config.project, synchronize=False)
        state = self.console.available(self.config.coordinator_enabled)
        plan = self.presentation_plan()
        counts = {}
        for v in plan['sequence']:
            key = (v['workflow'], v['role'])
            counts[key] = counts.get(key, 0) + 1
        if pool.get('automatic'):
            state['automatic_pool'] = pool['automatic']
            return console.settings(session['csrf'], pool['automatic']['slots'], pool['batch'], state, self.presenter(session), cluster_jira=bool(self.config.jira_view_url))
        rows = [{'workflow': w, 'role': r, 'target': n,
                 'available': sum(c.get('workflow', 'cve') == w and c['role'] == r for c in pool['contexts'])}
                for (w, r), n in counts.items()]
        return console.settings(session['csrf'], rows, pool['batch'], state, self.presenter(session), cluster_jira=bool(self.config.jira_view_url))

    async def settings(self, request: Request) -> Response:
        """Show boundaries and the explicitly authorized bounded batch action."""
        session = await self.session(request)
        return self.page(self.settings_content(session),
            user=session['claims'].get('preferred_username', self.role(session['claims'])), active='Settings',
            presentation=self.presentation(request), csrf=session['csrf'], live_url='/settings/live', live_kind='settings',
            session_deadline=self.session_deadline(session))

    async def live_settings(self, request: Request) -> Response:
        """Publish authenticated aggregate progress; no raw pool mappings reach the browser."""
        session = await self.session(request)
        html = self.settings_content(session)
        return JSONResponse({'html': html, 'revision': hashlib.sha256(html.encode()).hexdigest(),
                             'poll': True, 'server_time': int(time.time()),
                             'session_deadline': self.session_deadline(session)}, headers={'Cache-Control': 'no-store'})

    async def prepare_presentation(self, request: Request) -> Response:
        """Request only the fixed batch using fresh authentication and existing CSRF protection."""
        _, fields = await self.form(request, renew=False)
        session = await self.session(request, force=True)
        if fields:
            raise Denied('presentation_fields')
        if not self.presenter(session):
            raise Denied('presentation_presenter')
        state = self.console.available(True)
        if (not state['online'] or not state['auto_prepare'] or state['recovery_required']
                or state['busy'] or state['uncertain'] or state['phase'] == 'blocked'):
            raise Denied('presentation_not_idle')
        pool = self.console.pool_status(self.config.contexts, self.config.project)
        if pool.get('automatic'):
            return RedirectResponse('/settings', status_code=303)
        plan = self.presentation_plan()
        full = all(sum(c.get('workflow', 'cve') == item['workflow'] and c['role'] == item['role']
                       for c in pool['contexts']) >= plan['sequence'].count(item)
                   for item in plan['sequence'])
        if pool['batch'] and pool['batch']['phase'] == 'holding' and full:
            return RedirectResponse('/settings', status_code=303)
        self.console.configure_pool(plan, self.config.contexts, self.config.project,
                                    requested_by=session['claims']['sub'])
        return RedirectResponse('/settings', status_code=303)

    async def logout(self, request: Request) -> Response:
        """Revoke local run authority and end this IdP session without exposing credentials."""
        session, fields = await self.form(request, renew=False)
        if fields:
            raise Denied("logout_fields")
        identifier = request.cookies.get(COOKIE, "")
        async with session.setdefault("refresh_lock", asyncio.Lock()):
            self.end_browser_session(identifier, session)
            if session.get("refresh_token"):
                await run_in_threadpool(end_issuer_session,
                    self.config.issuer_service or self.config.issuer, self.config.client,
                    session["refresh_token"], self.config.issuer_ca)
        response = RedirectResponse("/", status_code=303)
        response.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="lax")
        response.headers["Cache-Control"] = "no-store"
        return response

    async def login(self, request: Request) -> Response:
        """Start real Authorization Code + PKCE with single-use state and nonce."""
        now = time.time()
        self.pending = {k: v for k, v in self.pending.items() if v["expires"] > now}
        self.sessions = {
            k: v for k, v in self.sessions.items()
            if self.session_deadline(v) > now and v.get("last_activity", now) + SESSION_IDLE_SECONDS > now
        }
        if (not self.config.stateless_login and len(self.pending) >= 32) or len(self.sessions) >= 32:
            return JSONResponse({"reason": "login_capacity"}, status_code=503)
        state, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(3))
        pending = {"nonce": nonce, "verifier": verifier, "expires": now + 300}
        if not self.config.stateless_login:
            self.pending[state] = pending
        state_cookie = self.login_state.issue(state, nonce, verifier) if self.config.stateless_login else state
        query = urlencode(
            {
                "client_id": self.config.client,
                "response_type": "code",
                "scope": "openid",
                "redirect_uri": self.config.origin + "/callback",
                "state": state,
                "nonce": nonce,
                "code_challenge": base64.urlsafe_b64encode(
                    hashlib.sha256(verifier.encode()).digest()
                )
                .decode()
                .rstrip("="),
                "code_challenge_method": "S256",
                "prompt": "login",
            }
        )
        response = RedirectResponse(
            self.config.issuer + "/protocol/openid-connect/auth?" + query,
            status_code=302,
        )
        response.set_cookie(
            STATE_COOKIE,
            state_cookie,
            secure=True,
            httponly=True,
            samesite="lax",
            max_age=300,
            path="/",
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    async def callback(self, request: Request) -> Response:
        """Exchange one code and verify ID nonce plus both signed token recipients."""
        params = parse_qs(request.url.query, max_num_fields=10)
        if (
            any(len(v) != 1 for v in params.values())
            or "code" not in params
            or "state" not in params
        ):
            raise Denied("login_state")
        state = params["state"][0]
        pending = (self.login_state.consume(request.cookies.get(STATE_COOKIE, ''), state)
                   if self.config.stateless_login else self.pending.pop(state, None))
        if (
            pending is None
            or pending["expires"] <= time.time()
            or (not self.config.stateless_login and not secret_matches(request.cookies.get(STATE_COOKIE, ""), state))
        ):
            raise Denied("login_state")
        fields = urlencode(
            {
                "grant_type": "authorization_code",
                "client_id": self.config.client,
                "redirect_uri": self.config.origin + "/callback",
                "code": params["code"][0],
                "code_verifier": pending["verifier"],
            }
        ).encode()
        tokens = await run_in_threadpool(
            exchange_code,
            self.config.issuer_service or self.config.issuer,
            fields,
            self.config.issuer_ca,
        )
        if (not isinstance(tokens, dict) or not isinstance(tokens.get("access_token"), str)
                or not isinstance(tokens.get("id_token"), str)):
            raise Denied("login_exchange")
        claims = await run_in_threadpool(
            self.verify, tokens["access_token"], self.config.client
        )
        identity = await run_in_threadpool(
            self.verify, tokens["id_token"], self.config.client
        )
        if (
            identity.get("nonce") != pending["nonce"]
            or claims["sub"] != identity["sub"]
            or claims.get("azp") != self.config.client
        ):
            raise Denied("login_binding")
        self.role(claims)
        if len(self.sessions) >= 32:
            raise Denied('session_capacity')
        identifier = secrets.token_urlsafe(32)
        self.sessions[identifier] = {
            "claims": claims,
            "token": tokens["access_token"],
            "csrf": secrets.token_urlsafe(32),
        }
        session = self.sessions[identifier]
        refresh = tokens.get("refresh_token")
        lifetime = tokens.get("refresh_expires_in")
        if refresh is not None:
            if not isinstance(refresh, str) or not 1 <= len(refresh) <= 16384 or type(lifetime) is not int or lifetime <= 0:
                self.sessions.pop(identifier)
                raise Denied("login_binding")
            now = time.time()
            absolute = int(now) + SESSION_MAX_SECONDS
            refresh_expires = min(absolute, int(now) + lifetime)
            session.update(refresh_token=refresh, refresh_expires=refresh_expires,
                absolute_expires=absolute, session_expires=min(refresh_expires, int(now) + SESSION_IDLE_SECONDS),
                last_activity=now)
        # Replace this browser's old cookie. Preserve only the same owner's original grants.
        previous_id = request.cookies.get(COOKIE, "")
        previous = self.sessions.get(previous_id)
        if previous:
            async with previous.setdefault("refresh_lock", asyncio.Lock()):
                if self.sessions.get(previous_id) is previous:
                    if (previous["claims"]["iss"] == claims["iss"] and previous["claims"]["sub"] == claims["sub"]
                            and self.role(previous["claims"]) == self.role(claims)):
                        session["runs"] = previous.get("runs", set()).copy()
                        session["run_credentials"] = previous.get("run_credentials", {}).copy()
                        for run in session["runs"]:
                            session["run_credentials"].setdefault(run, {
                                "claims": json.loads(json.dumps(previous["claims"])), "token": previous["token"],
                                "expires_at": self.store.describe(run, previous["claims"]["sub"])["run"]["expires"]})
                        self.sessions.pop(previous_id, None)
                    else:
                        self.end_browser_session(previous_id, previous)
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(
            COOKIE,
            identifier,
            secure=True,
            httponly=True,
            samesite="lax",
            path="/",
            max_age=max(1, int(self.session_deadline(session) - time.time())),
        )
        response.delete_cookie(
            STATE_COOKIE, secure=True, httponly=True, samesite="lax", path="/"
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @staticmethod
    def role(claims: dict) -> str:
        """Accept only one approved human role from the verified token."""
        roles = set(claims.get("realm_access", {}).get("roles", [])) & {
            "analyst",
            "viewer",
        }
        if len(roles) != 1:
            raise Denied("user_role")
        return roles.pop()

    def register_run(self, claims: dict, context: dict, *, queue_workflow: str | None = None, expires_at: int | None = None) -> str:
        """Bind validated human claims to an operator-controlled execution context."""
        return self.store.create_run(
            issuer=claims["iss"],
            user=claims["sub"],
            user_role=self.role(claims),
            workload=context["workload"],
            workload_role=context["role"],
            project=context.get("project", self.config.project),
            expires=min(int(claims["exp"]), expires_at if expires_at is not None else int(claims["exp"])),
            assessment="Assessment pending workload execution.",
            require_console_idle=self.config.coordinator_enabled,
            console_workflow=queue_workflow if self.config.coordinator_enabled else None,
        )

    async def submit(self, request: Request) -> Response:
        """Select an unused context by role; no browser-supplied workload or subject."""
        session, fields = await self.form(request, renew=False)
        session = await self.session(request, minimum=console.MIN_RUN_SECONDS, force=True)
        if fields.keys() == {"role", "cve"} and fields["cve"] == "CVE-2099-0001":
            workflow = "cve"
        elif fields.keys() == {"role", "request"} and fields["request"] == "SERVICE-0001":
            workflow = "service-request"
        elif fields.keys() == {"role", "request"} and fields["request"] == "OPS-0001":
            workflow = "incident-triage"
        else:
            raise Denied("unapproved_source")
        if self.config.coordinator_enabled:
            readiness = self.console.available(True)
            # A recent successful check may let the user request a run during
            # routine preflight. Wait boundedly; allocate nothing until ready.
            for _ in range(console.ROUTINE_CHECK_WAIT_SECONDS * 4):
                if (readiness['ready'] or not readiness['online'] or readiness['busy']
                        or readiness.get('preparing_context') or readiness.get('recovery_required')
                        or readiness.get('phase') != 'preparing' or readiness.get('reason')
                        or min(session['claims']['exp'], self.session_deadline(session)) - time.time() < console.MIN_RUN_SECONDS):
                    break
                await asyncio.sleep(.25)
                readiness = self.console.available(True)
            session = await self.session(request, minimum=console.MIN_RUN_SECONDS)  # Recheck after any wait.
            if not readiness["ready"] or readiness["busy"] or min(session["claims"]["exp"], self.session_deadline(session)) - time.time() < console.MIN_RUN_SECONDS:
                reason = ("console_busy" if readiness["busy"] else "coordinator_offline" if not readiness["online"]
                          else "coordinator_not_ready" if not readiness["ready"] else "fresh_login_required")
                if "text/html" in request.headers.get("accept", ""):
                    return self.page('<div class="heading"><h1>Workflow not started</h1></div>'
                        '<section class="card"><p>' + escape(reason.replace("_", " "))
                        + '</p><p><a href="/login">Sign in again</a> · <a href="/">Return to workflows</a></p></section>',
                        user=session["claims"].get("preferred_username", self.role(session["claims"])),
                        csrf=session["csrf"], session_deadline=self.session_deadline(session), status_code=409)
                return JSONResponse({"reason": reason}, status_code=409)
        for context in self.execution_contexts(active_only=True):
            if self.config.coordinator_enabled and context.get("console_prepared") is not True:
                continue
            if not self.console.context_ready(context["workload"]):
                continue
            if context["role"] != fields["role"] or context.get("workflow", "cve") != workflow:
                continue
            try:
                run = self.register_run(session["claims"], context, queue_workflow=workflow, expires_at=self.session_deadline(session))
            except sqlite3.IntegrityError:
                continue
            session.setdefault("runs", set()).add(run)
            session.setdefault("run_credentials", {})[run] = {
                "claims": json.loads(json.dumps(session["claims"])), "token": session["token"],
                "expires_at": self.store.describe(run, session["claims"]["sub"])["run"]["expires"]}
            return RedirectResponse("/runs/" + run, status_code=303)
        if "text/html" in request.headers.get("accept", ""):
            return self.page('<div class="heading"><h1>Fresh context required</h1></div>'
                '<section class="card"><p>All prepared identities for this workflow have been used. '
                'Ask the operator to prepare a new context.</p><a href="/">Return to workflows</a></section>',
                user=session["claims"].get("preferred_username", self.role(session["claims"])),
                csrf=session["csrf"], session_deadline=self.session_deadline(session), status_code=409)
        return JSONResponse({"reason": "fresh_context_required"}, status_code=409)

    def run_content(self, session: dict, run_id: str) -> tuple[str, bool]:
        """Render only this session owner's persisted run and public observations."""
        record = self.store.describe(run_id, session["claims"]["sub"])
        context = self.context_for_workload(record["run"]["workload"]) or {}
        return console.run_page(record, session["csrf"], context, self.console.describe(run_id),
                                self.console.available(self.config.coordinator_enabled),
                                cluster_jira=bool(self.config.jira_view_url))

    async def jira_issue(self, request: Request) -> Response:
        """Historical viewing never reopens execution or accepts a caller's issue key."""
        session = await self.session(request)
        record = self.store.describe(request.path_params['run'], session['claims']['sub'])
        job = self.console.describe(record['run']['id'])
        evidence = job['evidence'] if job else {}
        matches = [a for a in record['actions'] if a['state'] == 'succeeded' and a['issue_key']
                   and (not job or (evidence.get('backend_fields_match_approval') is True
                                    and evidence.get('verified_issue_key') == a['issue_key']))]
        if len(matches) != 1 or not self.config.jira_view_url:
            raise Denied('verified_issue_unavailable')
        from identity_demo_issue_view import fetch_issue, issue_html
        self.tickets = {k: v for k, v in self.tickets.items() if v['expires'] > time.time()}
        if len(self.tickets) >= 512:
            raise Denied('issue_view_capacity')
        ticket = secrets.token_urlsafe(32)
        self.tickets[ticket] = {'purpose': 'history', 'expires': time.time() + 15,
                               'issue_key': matches[0]['issue_key'], 'run': record['run']['id']}
        try:
            issue = await run_in_threadpool(fetch_issue, self.config.jira_view_url,
                self.config.jira_view_ca, ticket, matches[0]['issue_key'])
        except Exception:
            return self.page('<section class="card"><h1>Jira view temporarily unavailable</h1>'
                             '<p>The retained run and verified outcome remain available. No action was retried.</p></section>',
                             user=self.display_claims(session).get('preferred_username', ''), status_code=502)
        finally:
            self.tickets.pop(ticket, None)
        return self.page(issue_html(issue, record['run']['id']),
                         user=self.display_claims(session).get('preferred_username', ''), csrf=session['csrf'])

    async def history_ticket(self, request: Request) -> Response:
        """A one-use historical read capability grants no execution or mutation."""
        self.internal(request, self.config.adapter_secret)
        data = strict_json(await self.body(request, 1024))
        if set(data) != {'decision_ticket'} or not isinstance(data['decision_ticket'], str):
            raise Denied('history_ticket')
        ticket = self.tickets.get(data['decision_ticket'])
        if not ticket or ticket.get('purpose') != 'history' or ticket['expires'] <= time.time():
            raise Denied('history_ticket')
        del self.tickets[data['decision_ticket']]
        return JSONResponse({'allowed': True, 'issue_key': ticket['issue_key']},
                            headers={'Cache-Control': 'no-store'})

    async def backend_state(self, request: Request) -> Response:
        from identity_demo_backend_observation import observe
        return await observe(self, request)

    async def observation_ticket(self, request: Request) -> Response:
        from identity_demo_backend_observation import redeem
        return await redeem(self, request)

    async def status(self, request: Request) -> Response:
        """Show stable controls; refresh recorded progress without reloading the document."""
        session = await self.session(request)
        content, _ = self.run_content(session, request.path_params["run"])
        return self.page(content, user=session["claims"].get("preferred_username", self.role(session["claims"])),
            presentation=self.presentation(request), csrf=session["csrf"],
            live_url="/runs/" + request.path_params["run"] + "/live",
            session_deadline=self.session_deadline(session))

    async def live_run(self, request: Request) -> Response:
        """Return an authenticated owner-scoped fragment; never credentials or raw logs."""
        session = await self.session(request)
        content, poll = self.run_content(session, request.path_params["run"])
        revision = hashlib.sha256(content.encode()).hexdigest()
        headers = {"Cache-Control": "no-store", "ETag": '"' + revision + '"',
                   "X-Session-Deadline": str(self.session_deadline(session))}
        if request.headers.get('if-none-match') == headers['ETag']:
            return Response(status_code=304, headers=headers)
        return JSONResponse({"html": content, "revision": revision,
            "poll": poll, "server_time": int(time.time()),
            "session_deadline": self.session_deadline(session)}, headers=headers)

    async def live_home(self, request: Request) -> Response:
        """Update readiness without replacing workflow forms or dropdown selection."""
        session = await self.session(request)
        claims = self.display_claims(session)
        configured = [c for c in self.execution_contexts(active_only=True) if not self.config.coordinator_enabled or
                      c.get("console_prepared") is True]
        used = self.used_contexts(configured)
        contexts = [c for c in configured if not self.config.coordinator_enabled or (c["workload"] not in used and self.console.context_ready(c["workload"]))]
        readiness = self.console.available(self.config.coordinator_enabled)
        records = self.console.history(claims['sub'])
        label = console.coordinator_label(readiness)
        return JSONResponse({"readiness_html": console.readiness_panel(claims, readiness),
            "coordinator_label": label, "active_runs": sum(bool(r['active']) and r['expires'] > time.time() for r in records),
            "retained_runs": len(records),
            "cve_roles": [r for r in ('triage', 'reader') if any(c['role'] == r and c.get('workflow', 'cve') == 'cve' for c in contexts)],
            "service_available": any(c.get('workflow') == 'service-request' for c in contexts),
            "incident_available": any(c.get('workflow') == 'incident-triage' for c in contexts),
            "can_start": not self.config.coordinator_enabled or ((readiness['ready']
                or console.can_start_during_check(readiness)) and not readiness['busy']
                and claims['exp'] - time.time() >= console.MIN_RUN_SECONDS),
            "missing_context_hint": console.missing_context_hint(readiness),
            "auto_prepare": readiness.get("auto_prepare", False), "server_time": int(time.time()),
            "session_deadline": self.session_deadline(session)}, headers={"Cache-Control": "no-store"})

    async def console_script(self, request: Request) -> Response:
        """Serve fixed local code under a same-origin-only browser policy."""
        return Response(console.LIVE_SCRIPT, media_type="application/javascript", headers={
            "Cache-Control": "no-cache", "X-Content-Type-Options": "nosniff"})

    async def approve(self, request: Request) -> Response:
        """Record consent from the authenticated owner and displayed proposal digest."""
        session, fields = await self.form(request, renew=False)
        session = await self.session(request, force=True)
        if fields.keys() != {"action", "digest"}:
            raise Denied("approval_fields")
        run = request.path_params["run"]
        owner = session["claims"]["sub"]
        original_deadline = self.store.describe(run, owner)["run"]["expires"]
        self.store.approve(
            run,
            fields["action"],
            owner,
            fields["digest"],
            min(int(session["claims"]["exp"]), self.session_deadline(session), original_deadline),
        )
        return RedirectResponse("/runs/" + run, status_code=303)

    async def cancel(self, request: Request) -> Response:
        """Cancel live authorization while keeping the owner's assessment inspectable."""
        session, fields = await self.form(request)
        if fields:
            raise Denied("cancel_fields")
        run = request.path_params["run"]
        self.store.cancel(run, session["claims"]["sub"])
        return RedirectResponse("/runs/" + run, status_code=303)

    def console_operator(self, request: Request, role: str = 'coordinator') -> None:
        """Keep coordination behind the existing operator credential boundary."""
        if self.config.private_operator_api:
            if role in ('observer', 'preparation-verifier'):
                actual = request.headers.get('Authorization', '')
                if not any(secret_matches(actual, 'Bearer ' + key) for key in
                           ((self.config.coordinator_secret, self.config.preparer_secret, self.config.operator_secret)
                            if role == 'observer' else (self.config.preparer_secret, self.config.operator_secret))):
                    raise Denied('internal_auth')
            else:
                key = {'coordinator': self.config.coordinator_secret,
                       'preparer': self.config.preparer_secret, 'operator': self.config.operator_secret}[role]
                self.internal(request, key)
        else:
            self.internal(request, self.config.operator_secret)
        if not self.config.coordinator_enabled:
            raise Denied("console_disabled")

    async def console_heartbeat(self, request: Request) -> Response:
        """Observe one authorized coordinator process without issuing browser credentials."""
        self.console_operator(request)
        data = strict_json(await self.body(request, 1024))
        if set(data) not in ({"worker"}, {"worker", "phase", "reason", "catalog_expires", "checked_at"}):
            raise Denied("console_fields")
        self.console.heartbeat(data["worker"], **{k: v for k, v in data.items() if k != "worker"})
        return JSONResponse({"recorded": True})

    async def retirement_check(self, request: Request) -> Response:
        """Prove durable cleanup without giving the preparer database/Pod access."""
        self.console_operator(request, 'preparer')
        data = strict_json(await self.body(request, 1024))
        if set(data) != {'workload'} or not isinstance(data['workload'], str):
            raise Denied('console_fields')
        with self.store.read_transaction() as db:
            runs = db.execute('SELECT id,active FROM runs WHERE workload=?',
                              (data['workload'],)).fetchall()
            eligible = len(runs) == 1 and runs[0]['active'] == 0
            if eligible:
                run = runs[0]['id']
                uncertain = db.execute("SELECT count(*) FROM actions WHERE run_id=? AND state IN ('executing','unknown')", (run,)).fetchone()[0]
                jobs = db.execute('SELECT state,evidence FROM console_jobs WHERE run_id=?', (run,)).fetchall()
                eligible = not uncertain and bool(jobs) and all(
                    job['state'] in ('completed', 'failed')
                    and strict_json(job['evidence']).get('cleanup_verified') is True for job in jobs)
        if not eligible:
            raise Denied('retirement_not_verified')
        return JSONResponse({'eligible': True}, headers={'Cache-Control': 'no-store'})

    async def console_state(self, request: Request) -> Response:
        """Allow the existing operator to inspect coordination safety without changing jobs."""
        self.console_operator(request, 'observer')
        return JSONResponse({**self.console.available(True), "verified_issue_keys": self.console.verified_issue_keys()}, headers={"Cache-Control": "no-store"})

    async def console_pool(self, request: Request) -> Response:
        """Configure bounded idle preparation through the existing operator boundary."""
        if request.method == 'GET':
            self.console_operator(request, 'observer')
            result = self.console.pool_status(self.config.contexts, self.config.project)
        else:
            data = strict_json(await self.body(request, 8192))
            verification = (set(data) == {'action', 'id', 'status'} and data.get('action') == 'verification-status'
                or set(data) == {'action', 'id', 'receipt_sha256'} and data.get('action') == 'seal')
            self.console_operator(request, 'preparation-verifier' if verification else 'operator')
            preparer = self.config.private_operator_api and secret_matches(
                request.headers.get('Authorization', ''), 'Bearer '+self.config.preparer_secret)
            if set(data) == {'action','configuration','receipt_sha256'} and data['action']=='profiles':
                result = self.console.configure_profile_pool(data['configuration'],data['receipt_sha256'],self.config.contexts,self.config.project)
            elif set(data) in ({'action', 'enabled', 'receipt_sha256', 'retired_workloads'},
                              {'action', 'enabled', 'receipt_sha256', 'retired_workloads', 'initial_empty'}) and data['action'] == 'automatic':
                result = self.console.configure_automatic(data['enabled'], data['receipt_sha256'], data['retired_workloads'],
                                                          self.config.contexts, self.config.project, initial_empty=data.get('initial_empty', False))
            elif set(data) == {'action', 'plan'} and data['action'] == 'configure':
                result = self.console.configure_pool(data['plan'], self.config.contexts, self.config.project)
            elif set(data) == {'action', 'id', 'status'} and data['action'] == 'verification-status':
                self.console.verification_state(data['id'], data['status'])
                result = self.console.pool_status(self.config.contexts, self.config.project)
            elif (set(data) == {'action', 'id', 'receipt_sha256'}
                  and data['action'] in ('seal', 'release')):
                result = self.console.finish_pool(data['id'], data['receipt_sha256'],
                    self.config.contexts, self.config.project, release=data['action'] == 'release',
                    browser_only=preparer)
            else:
                raise Denied('console_fields')
        return JSONResponse(result, headers={'Cache-Control': 'no-store'})

    async def console_review_recovery(self, request: Request) -> Response:
        """Require existing operator authentication and a retained reconciliation receipt."""
        self.console_operator(request, 'operator')
        data = strict_json(await self.body(request, 2048))
        if set(data) != {'run_id', 'receipt_sha256'}:
            raise Denied('console_fields')
        self.console.review_recovery(data['run_id'], data['receipt_sha256'])
        return JSONResponse({'recorded':True}, headers={'Cache-Control':'no-store'})

    async def console_next(self, request: Request) -> Response:
        """Claim one browser-created run; no browser controls execution identifiers."""
        self.console_operator(request)
        data = strict_json(await self.body(request, 1024))
        if data.keys() != {"worker"}:
            raise Denied("console_fields")
        job = self.console.claim(data["worker"])
        if job:
            context = self.context_for_workload(job["workload"])
            if context is None:
                raise Denied("unknown_workload")
            job["context"] = context
        return JSONResponse({"job": job})

    async def console_update(self, request: Request) -> Response:
        """Persist allowlisted observations for an exactly claimed execution."""
        self.console_operator(request)
        data = strict_json(await self.body(request, 8192))
        if data.keys() != {"run_id", "worker", "stage", "evidence"}:
            raise Denied("console_fields")
        self.console.update(data["run_id"], data["worker"], data["stage"], data["evidence"])
        return JSONResponse({"recorded": True})

    async def console_inspect(self, request: Request) -> Response:
        """Read coordination state without sharing sessions, tokens or operator keys."""
        self.console_operator(request)
        run_id = request.path_params["run"]
        with self.store.transaction() as db:
            row = db.execute("SELECT user FROM runs WHERE id=?", (run_id,)).fetchone()
        if not row:
            raise Denied("run_binding")
        return JSONResponse({**self.store.describe(run_id, row["user"]), "console": self.console.describe(run_id)},
            headers={"Cache-Control": "no-store"})

    def execution_operator(self, request: Request) -> None:
        """Select explicit execution mode; never fall back after failed runtime auth.

        Direct CLI maintenance uses the installer-held operator credential on
        the private listener. Cluster mode requires the separate coordinator
        credential; neither runtime role can enable direct mode.
        """
        if self.config.private_operator_api and self.config.coordinator_enabled:
            self.console_operator(request)
        else:
            self.internal(request, self.config.operator_secret)

    async def operator_run(self, request: Request) -> Response:
        """Bind a real login to a preverified context for headless acceptance only."""
        self.internal(request, self.config.operator_secret)
        data = strict_json(await self.body(request, 65_536))
        if data.keys() != {"access_token", "workload"}:
            raise Denied("operator_fields")
        claims = await run_in_threadpool(
            self.verify, data["access_token"], self.config.client
        )
        if claims.get("azp") != self.config.client:
            raise Denied("login_binding")
        context = self.context_for_workload(data["workload"])
        if context is None:
            raise Denied("unknown_workload")
        run = self.register_run(claims, context)
        self.sessions["operator-" + run] = {
            "claims": claims,
            "token": data["access_token"],
            "csrf": secrets.token_urlsafe(32),
            "runs": {run},
        }
        return JSONResponse({"run_id": run, "workload": context["workload"]})

    async def revoke(self, request: Request) -> Response:
        """Only trusted operators may revoke a user, workload or run association."""
        self.execution_operator(request)
        data = strict_json(await self.body(request, 8192))
        if len(data) != 1:
            raise Denied("revocation_selector")
        selector, value = next(iter(data.items()))
        if self.config.private_operator_api and selector != 'run_id':
            raise Denied('revocation_selector')
        affected = self.store.revoke(selector, value)
        return JSONResponse({"revoked_runs": affected})

    async def report(self, request: Request) -> Response:
        """Accept the actual workload report/proposal only from trusted coordination."""
        self.execution_operator(request)
        data = strict_json(await self.body(request, 65_536))
        if data.keys() != {"run_id", "user", "workload", "assessment", "arguments"}:
            raise Denied("operator_fields")
        run = self.store.identity_run(data["user"], data["workload"])
        if run["id"] != data["run_id"]:
            raise Denied("run_binding")
        self.store.save_assessment(run["id"], run["user"], data["assessment"])
        proposal = self.store.propose(run["id"], run["user"], data["arguments"])
        return JSONResponse(proposal)

    async def credentials(self, request: Request) -> Response:
        """Release a still-valid human token solely to authenticated coordination."""
        self.execution_operator(request)
        run_id = request.path_params["run"]
        for session in self.sessions.values():
            if (self.session_deadline(session) <= time.time()
                    or session.get("last_activity", time.time()) + SESSION_IDLE_SECONDS <= time.time()
                    or run_id not in session.get("runs", ())):
                continue
            captured = session.get("run_credentials", {}).get(run_id, session)
            claims = captured["claims"]
            if claims["exp"] <= time.time():
                continue
            with self.store.transaction() as db:
                row = db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
                if (row is None or row["user"] != claims["sub"]
                        or row["issuer"] != claims["iss"]
                        or row["user_role"] != self.role(claims)
                        or row["expires"] != captured.get("expires_at", claims["exp"])):
                    continue
                self.store.active_run(db, run_id, claims["sub"], row["workload"])
                return JSONResponse(
                    {
                        "access_token": captured["token"],
                        "expires_at": row["expires"],
                        "workload": row["workload"],
                        "user": claims["sub"],
                    },
                    headers={"Cache-Control": "no-store"},
                )
        raise Denied("reauthentication_required")

    async def authorize(self, request: Request) -> Response:
        """Authorize the actual body from the gateway; do not consume approval."""
        self.internal(request, self.config.gateway_secret)
        context = strict_json(await self.body(request))
        return JSONResponse(await self.context_decision(context))

    async def identity(self, request: Request) -> Response:
        """Check live identity before MCP routing; writes still require full body authorization."""
        self.internal(request, self.config.gateway_secret)
        context = strict_json(await self.body(request))
        return JSONResponse(await self.context_decision(context, identity_only=True))

    async def adapter_ticket(self, request: Request) -> tuple[dict, str]:
        """Resolve an expiring decision and match the actual upstream body."""
        self.internal(request, self.config.adapter_secret)
        data = strict_json(await self.body(request))
        if data.keys() != {"decision_ticket", "actual_body"}:
            raise Denied("adapter_fields")
        if not isinstance(data["decision_ticket"], str):
            raise Denied("decision_expired")
        ticket = self.tickets.get(data["decision_ticket"])
        if ticket is None or ticket.get('purpose') is not None or ticket["expires"] <= time.time():
            raise Denied("decision_expired")
        body = data["actual_body"]
        if not isinstance(body, str):
            raise Denied("complete_body_required")
        if hashlib.sha256(body.encode()).hexdigest() != ticket["body_hash"]:
            raise Denied("action_binding")
        return ticket, body

    async def claim(self, request: Request) -> Response:
        """Claim a verified create without passing human tokens to the adapter."""
        ticket, body = await self.adapter_ticket(request)
        run, action, arguments = create_call(body.encode(), tool_name="createJiraIssue")
        if run != ticket["run"] or action != ticket["action"]:
            raise Denied("action_binding")
        return JSONResponse(
            self.store.decision(
                run, action, ticket["user"], ticket["workload"], arguments, claim=True
            )
        )

    async def preview(self, request: Request) -> Response:
        """Recheck an approved create at the adapter without claiming or writing."""
        ticket, body = await self.adapter_ticket(request)
        run, action, arguments = create_call(body.encode(), tool_name="createJiraIssue")
        if run != ticket["run"] or action != ticket["action"]:
            raise Denied("action_binding")
        return JSONResponse(
            self.store.decision(
                run, action, ticket["user"], ticket["workload"], arguments
            )
        )

    async def adapter_read(self, request: Request) -> Response:
        """Recheck project permission and cancellation before returning backend data."""
        ticket, body = await self.adapter_ticket(request)
        run, project, _ = read_call(body.encode(), tool_name="readJiraProject")
        if run != ticket["run"] or ticket["action"] is not None:
            raise Denied("action_binding")
        return JSONResponse(
            self.store.read_decision(
                run, ticket["user"], ticket["workload"], project, ticket["body_hash"]
            )
        )

    def issue_ticket(
        self, claims: dict, run: str, action: str | None, body: str
    ) -> str:
        """Keep a bounded short-lived decision in RAM; restart denies old references."""
        now = time.time()
        self.tickets = {k: v for k, v in self.tickets.items() if v["expires"] > now}
        if len(self.tickets) >= 128:
            raise Denied("decision_capacity")
        identifier = secrets.token_urlsafe(32)
        self.tickets[identifier] = {
            "expires": claims["exp"],
            "run": run,
            "action": action,
            "user": claims["sub"],
            "workload": claims["azp"],
            "body_hash": hashlib.sha256(body.encode()).hexdigest(),
        }
        return identifier

    async def finish(self, request: Request) -> Response:
        """Only the scoped adapter may record a claimed backend result."""
        self.internal(request, self.config.adapter_secret)
        data = strict_json(await self.body(request, 8192))
        if data.keys() != {"run_id", "action_id", "execution_id", "state", "issue_key"}:
            raise Denied("adapter_fields")
        self.store.finish(
            data["run_id"],
            data["action_id"],
            data["execution_id"],
            state=data["state"],
            issue_key=data["issue_key"],
        )
        return JSONResponse({"recorded": True})

    async def reconciliation(self, request: Request) -> Response:
        """Allow only the scoped trusted adapter to inspect uncertain dispatch state."""
        self.internal(request, self.config.adapter_secret)
        data = strict_json(await self.body(request, 8192))
        if data.keys() != {"run_id", "action_id"}:
            raise Denied("adapter_fields")
        return JSONResponse(
            self.store.reconciliation(data["run_id"], data["action_id"])
        )

    async def reconcile(self, request: Request) -> Response:
        """Record a positive backend read; cancellation never authorizes another write."""
        self.internal(request, self.config.adapter_secret)
        data = strict_json(await self.body(request, 16384))
        if data.keys() != {
            "run_id",
            "action_id",
            "execution_id",
            "issue_key",
            "arguments",
        }:
            raise Denied("adapter_fields")
        self.store.reconcile(
            data["run_id"],
            data["action_id"],
            data["execution_id"],
            data["issue_key"],
            data["arguments"],
        )
        return JSONResponse({"recorded": True})

    async def context_decision(
        self, context: dict, *, identity_only: bool = False
    ) -> dict:
        """Check immutable identity plus live state, then the actual registered tool body."""
        try:
            http = context["context"]["request"]["http"]
            header = http["headers"].get("authorization", "")
            if not header.startswith("Bearer "):
                raise Denied("missing_token")
            claims = await run_in_threadpool(
                self.verify, header[7:], self.config.audience
            )
            now = time.time()
            if (
                not claims["iat"] <= now < claims["exp"]
                or claims["exp"] - claims["iat"] > 30
                or not peer_matches(claims, http["headers"])
            ):
                raise Denied("sender_binding")
            run = self.store.identity_run(claims["sub"], claims["azp"])
            if self.role(claims) != run["user_role"]:
                raise Denied("user_permission")
            if claims["iat"] < run["not_before"] or claims["exp"] > run["expires"]:
                raise Denied("credential_lifetime")
            if http["path"] != "/mcp" or http["method"] not in (
                "GET",
                "POST",
                "DELETE",
            ):
                raise Denied("request_boundary")
            if identity_only or http["method"] != "POST":
                return {
                    "allowed": True,
                    "reason": "authenticated_protocol",
                    "run_id": run["id"],
                }
            body = http.get("body")
            if not isinstance(body, str):
                raise Denied("complete_body_required")
            rpc = strict_json(body.encode())
            if rpc.get("method") in (
                "initialize",
                "notifications/initialized",
                "tools/list",
            ):
                return {
                    "allowed": True,
                    "reason": "authenticated_protocol",
                    "run_id": run["id"],
                }
            prefix = "step56_jira_"
            if (
                self.config.normalized_tool_host is not None
                and http.get("host") == self.config.normalized_tool_host
            ):
                prefix = ""
            params = rpc.get("params", {})
            if not isinstance(params, dict):
                raise Denied("unsupported_rpc")
            if params.get("name") == prefix + "readJiraProject":
                parsed_run, project, _ = read_call(
                    body.encode(), tool_name=prefix + "readJiraProject"
                )
                if parsed_run != run["id"]:
                    raise Denied("run_binding")
                decision = self.store.read_decision(
                    parsed_run,
                    claims["sub"],
                    claims["azp"],
                    project,
                    hashlib.sha256(body.encode()).hexdigest(),
                )
                if decision["allowed"] and prefix == "":
                    decision["decision_ticket"] = self.issue_ticket(
                        claims, parsed_run, None, body
                    )
                return decision
            parsed_run, action, arguments = create_call(
                body.encode(), tool_name=prefix + "createJiraIssue"
            )
            if parsed_run != run["id"]:
                raise Denied("run_binding")
            # The verified token role already matches the immutable run role.
            # Let the store enforce the permission intersection and retain the
            # viewer denial with its run/action/digest audit association.
            decision = self.store.decision(
                parsed_run, action, claims["sub"], claims["azp"], arguments
            )
            if decision["allowed"] and prefix == "":
                decision["decision_ticket"] = self.issue_ticket(
                    claims, parsed_run, action, body
                )
            return {
                **decision,
                "run_id": parsed_run,
                "action_id": action,
                "actual_body_sha256": hashlib.sha256(body.encode()).hexdigest(),
            }
        except (KeyError, TypeError, Denied) as error:
            return {
                "allowed": False,
                "reason": str(error)
                if isinstance(error, Denied)
                else "authorization_context",
            }


def main() -> None:
    """Run the sole driver over its service-issued certificate; never log requests."""
    import uvicorn

    value = json.loads(Path(os.environ["DRIVER_CONFIG"]).read_text())
    if value.get('private_operator_api') is True:
        value.update({role + '_secret': Path(os.environ[role.upper() + '_SECRET_FILE']).read_text().strip()
                      for role in ('coordinator', 'preparer')})
    config = Config(
        **{
            **value,
            "database": Path(os.environ["DRIVER_DATABASE"]),
            "contexts": tuple(value["contexts"]),
            **{
                key: Path(os.environ[key.upper() + "_FILE"]).read_text().strip()
                for key in ("gateway_secret", "operator_secret", "adapter_secret")
            },
        }
    )
    prepare_storage(config.database)
    driver = Driver(config)
    if config.private_operator_api:
        from contextlib import contextmanager
        import signal
        class PrivateServer(uvicorn.Server):
            @contextmanager
            def capture_signals(self):
                yield
        async def serve() -> None:
            options = {'host': '0.0.0.0', 'log_level': 'warning', 'access_log': False}
            public = PrivateServer(uvicorn.Config(driver.app, port=8443,
                ssl_certfile=os.environ['DRIVER_TLS_CERT'], ssl_keyfile=os.environ['DRIVER_TLS_KEY'], **options))
            private = PrivateServer(uvicorn.Config(driver.private_app, port=8444,
                ssl_certfile=os.environ['DRIVER_PRIVATE_TLS_CERT'], ssl_keyfile=os.environ['DRIVER_PRIVATE_TLS_KEY'], **options))
            servers = (public, private)
            def stop() -> None:
                for server in servers: server.should_exit = True
            loop = asyncio.get_running_loop()
            for signum in (signal.SIGINT, signal.SIGTERM): loop.add_signal_handler(signum, stop)
            tasks = [asyncio.create_task(server.serve()) for server in servers]
            try:
                await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            finally:
                stop()
                await asyncio.gather(*tasks)
        asyncio.run(serve())
        return
    uvicorn.run(
        driver.app,
        host="0.0.0.0",
        port=8443,
        ssl_certfile=os.environ["DRIVER_TLS_CERT"],
        ssl_keyfile=os.environ["DRIVER_TLS_KEY"],
        log_level="warning",
        access_log=False,
    )


if __name__ == "__main__":
    main()
