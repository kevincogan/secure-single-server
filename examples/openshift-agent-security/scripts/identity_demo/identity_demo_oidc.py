# SPDX-License-Identifier: Apache-2.0
"""Fixed-issuer OIDC transport and delegated-token validation for trusted hosts."""
from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import time
import base64
import ssl
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request as URLRequest, build_opener

import jwt
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from typing import Callable
from agent_security_contracts import Denied, strict_json


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



def valid_delegation(claims: dict, now: float | None = None) -> bool:
    """Check a verified bearer grant; callers must also enforce live run authority.

    JWT signature, issuer and audience validation belongs to ``Verifier``.
    Never silently reinterpret an old sender-constrained token as a bearer grant.
    Caller-supplied identity headers confer no authority.
    """
    issued, expiry = claims.get("iat"), claims.get("exp")
    return (type(issued) is int and type(expiry) is int
            and issued <= (time.time() if now is None else now) < expiry
            and 0 < expiry - issued <= 30 and "cnf" not in claims
            and all(isinstance(claims.get(k), str) and 0 < len(claims[k]) <= 256
                    for k in ("sub", "azp")))



COOKIE = "__Host-identity-demo"
STATE_COOKIE = "__Host-identity-login"
SESSION_MAX_SECONDS = 36000
SESSION_IDLE_SECONDS = 1800
REFRESH_MARGIN_SECONDS = 60


def secret_matches(actual: str, expected: str) -> bool:
    return secrets.compare_digest(actual.encode(), expected.encode())


class OIDCSession:
    """Concrete PKCE/session mechanism; no UI, Jira or agent execution imports."""

    def __init__(self, config, store, verifier=None):
        self.config, self.store = config, store
        self.verify = verifier or Verifier(config.issuer, config.issuer_service, config.issuer_ca)
        self.sessions, self.pending = {}, {}
        from identity_demo_login_state import LoginState
        self.login_state = LoginState()

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
