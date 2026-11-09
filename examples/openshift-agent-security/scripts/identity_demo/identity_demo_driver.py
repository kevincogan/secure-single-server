# SPDX-License-Identifier: Apache-2.0
"""Compose trusted demo operations with optional browser and private HTTP adapters."""
from __future__ import annotations
import sqlite3
import asyncio
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import time
from typing import Callable
from urllib.parse import urlparse
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from agent_security_service import RunService
from agent_security import prepare_storage
from openshift_security.oidc import OIDCSession, Verifier, FixedIssuerKeys, NoIssuerRedirect, safe_https, valid_delegation
from identity_demo_console_store import ConsoleStore
from identity_demo_run_store import Denied, RunStore, create_call, read_call, strict_json
from functools import partial
import identity_demo_http as http
import identity_demo_operator_routes as operator
import identity_demo_protected_routes as protected
from identity_demo_http import secret_matches

if __import__("sys").flags.optimize:
    raise RuntimeError("Optimized interpreter is unsupported for security execution")

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
    presenter_subjects: tuple[str, ...] = ()  # Read old rendered configs.
    stateless_login: bool = False
    private_operator_api: bool = False
    coordinator_secret: str | None = None
    preparer_secret: str | None = None
    jira_view_url: str | None = None
    jira_view_ca: str | None = None

class Driver:
    """Application state and composition root for independently scoped HTTP adapters."""

    def __init__(
        self, config: Config, verifier: Callable[[str, str], dict] | None = None, *, with_ui: bool = True
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
        self.config = config
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
        self.store = RunStore(config.database)
        self.actions = RunService(self.store)
        self.console = ConsoleStore(self.store)
        self.store.recover_dispatched()
        self.authentication = OIDCSession(config, self.store, verifier,
                                          role_map={"analyst": "analyst", "viewer": "viewer"})
        # Concrete session mechanism, shared with the unrelated document host.
        self.session = self.authentication.session
        self.form = self.authentication.form
        self.body = self.authentication.body
        self.role = self.authentication.role
        self.session_deadline = self.authentication.session_deadline
        self.end_browser_session = self.authentication.end_browser_session
        self.login = self.authentication.login
        self.callback = self.authentication.callback
        self.logout = self.authentication.logout
        self.browser_session_cookie = self.authentication.browser_session_cookie
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
        auth_routes = [
            Route("/login", self.login),
            Route("/callback", self.callback),
            Route("/logout", self.logout, methods=["POST"]),
        ]
        protected_routes = [
            Route("/internal/authorize", partial(protected.authorize, self), methods=["POST"]),
            Route("/internal/identity", partial(protected.identity, self), methods=["POST"]),
            Route("/internal/adapter/claim", partial(protected.claim, self), methods=["POST"]),
            Route("/internal/adapter/preview", partial(protected.preview, self), methods=["POST"]),
            Route("/internal/adapter/read", partial(protected.adapter_read, self), methods=["POST"]),
            Route("/internal/adapter/history", partial(protected.history_ticket, self), methods=["POST"]),
            Route("/internal/adapter/observation", partial(protected.observation_ticket, self), methods=["POST"]),
            Route("/internal/adapter/finish", partial(protected.finish, self), methods=["POST"]),
            Route(
                                "/internal/adapter/reconciliation",
                                partial(protected.reconciliation, self),
                                methods=["POST"],
                            ),
            Route("/internal/adapter/reconcile", partial(protected.reconcile, self), methods=["POST"]),
        ]
        operator_routes = [
            Route("/internal/operator/run", partial(operator.operator_run, self), methods=["POST"]),
            Route("/internal/operator/report", partial(operator.report, self), methods=["POST"]),
            Route("/internal/operator/revoke", partial(operator.revoke, self), methods=["POST"]),
            Route("/internal/operator/credentials/{run}", partial(operator.credentials, self)),
            Route("/internal/operator/console/heartbeat", partial(operator.console_heartbeat, self), methods=["POST"]),
            Route("/internal/operator/console/next", partial(operator.console_next, self), methods=["POST"]),
            Route("/internal/operator/console/update", partial(operator.console_update, self), methods=["POST"]),
            Route("/internal/operator/console/runs/{run}", partial(operator.console_inspect, self)),
            Route("/internal/operator/console/backend-state/{run}", partial(operator.backend_state, self)),
            Route("/internal/operator/console/state", partial(operator.console_state, self)),
            Route("/internal/operator/console/pool", partial(operator.console_pool, self), methods=["GET", "POST"]),
            Route("/internal/operator/console/prepare/next", partial(operator.prepare_next, self), methods=["POST"]),
            Route("/internal/operator/console/prepare/finish", partial(operator.prepare_finish, self), methods=["POST"]),
            Route("/internal/operator/console/prepare/retirement-check", partial(operator.retirement_check, self), methods=["POST"]),
            Route("/internal/operator/console/review-recovery", partial(operator.console_review_recovery, self), methods=["POST"]),
        ]
        health_routes = [
            Route("/healthz", self.health),
        ]
        routes = auth_routes + protected_routes + health_routes
        if with_ui:
            import identity_demo_browser_routes as browser
            routes += [
                Route("/", partial(browser.home, self)),
                Route("/submit", partial(browser.submit, self), methods=["POST"]),
                Route("/runs/{run}", partial(browser.status, self)),
                Route("/runs/{run}/live", partial(browser.live_run, self)),
                Route("/runs/{run}/jira", partial(browser.jira_issue, self)),
                Route("/console/live", partial(browser.live_home, self)),
                Route("/assets/console.js", partial(browser.console_script, self)),
                Route("/runs/{run}/approve", partial(browser.approve, self), methods=["POST"]),
                Route("/runs/{run}/cancel", partial(browser.cancel, self), methods=["POST"]),
                Route("/runs", partial(browser.history, self)),
                Route("/evidence", partial(browser.evidence, self)),
                Route("/settings", partial(browser.settings, self)),
                Route("/settings/live", partial(browser.live_settings, self)),
            ]
            denial = partial(browser.denied, self)
        else:
            denial = http.denied
        if not config.private_operator_api:
            routes += operator_routes
        self.app = Starlette(routes=routes, exception_handlers={Denied: denial})
        self.private_app = Starlette(routes=operator_routes + health_routes, exception_handlers={Denied: http.denied})
        async def private_headers(request, next_handler):
            response = await next_handler(request)
            response.headers.update({'Cache-Control':'no-store', 'X-Content-Type-Options':'nosniff'})
            return response
        self.private_app.add_middleware(BaseHTTPMiddleware, dispatch=private_headers)
        self.app.add_middleware(BaseHTTPMiddleware, dispatch=self.browser_session_cookie)
        if config.stateless_login:
            from identity_demo_admission import PublicAdmission
            self.app.add_middleware(PublicAdmission)


    internal = staticmethod(http.internal)
    json_fields = http.json_fields
    console_operator = http.console_operator
    execution_operator = http.execution_operator

    def execution_contexts(self, *, active_only: bool = False) -> tuple[dict, ...]:
        """Combine source configuration with append-only trusted runtime registrations."""
        return (*self.config.contexts, *self.console.contexts(active_only=active_only))


    def context_for_workload(self, workload: str) -> dict | None:
        configured=next((c for c in self.config.contexts if c['workload']==workload),None)
        return configured or self.console.context_for_workload(workload)


    @property
    def sessions(self):
        return self.authentication.sessions


    @sessions.setter
    def sessions(self, value):
        self.authentication.sessions = value


    @property
    def pending(self):
        return self.authentication.pending


    @property
    def verify(self):
        return self.authentication.verify


    @verify.setter
    def verify(self, value):
        self.authentication.verify = value


    async def health(self, request: Request) -> Response:
        """Expose readiness without run, session or credential information."""
        return JSONResponse({"ready": True, "execution_contexts_configured": bool(self.execution_contexts(active_only=True))})


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


    async def context_decision(
        self, context: dict, *, identity_only: bool = False
    ) -> dict:
        """Check immutable identity plus live state, then the actual registered tool body."""
        try:
            http = context["context"]["request"]["http"]
            header = http["headers"].get("authorization", "")
            if not header.startswith("Bearer "):
                raise Denied("missing_token")
            claims, run = await self.authentication.delegated_run(header[7:])
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

    async def wait_for_readiness(self, session: dict) -> None:
        """Wait without allocating; the caller revalidates authentication afterwards."""
        from identity_demo_admission_policy import MIN_RUN_SECONDS, ROUTINE_CHECK_WAIT_SECONDS
        for _ in range(ROUTINE_CHECK_WAIT_SECONDS * 4):
            state = self.console.available(True)
            if (state['ready'] or not state['online'] or state['busy']
                    or state.get('preparing_context') or state.get('recovery_required')
                    or state.get('phase') != 'preparing' or state.get('reason')
                    or min(session['claims']['exp'], self.session_deadline(session)) - time.time() < MIN_RUN_SECONDS):
                return
            await asyncio.sleep(.25)

    def start_workflow(self, session: dict, workflow: str, role: str) -> str:
        """Allocate and queue once through the existing shared store transaction.

        Only trusted authentication adapters supply the server-held session.
        Agent or browser fields cannot supply its identity, token or consent.
        """
        from identity_demo_admission_policy import MIN_RUN_SECONDS
        if workflow not in ('cve', 'service-request', 'incident-triage') or role not in ('triage', 'reader'):
            raise Denied('unapproved_source')
        if self.config.coordinator_enabled:
            state = self.console.available(True)
            if not state['ready'] or state['busy'] or min(session['claims']['exp'], self.session_deadline(session)) - time.time() < MIN_RUN_SECONDS:
                raise Denied('console_busy' if state['busy'] else 'coordinator_offline' if not state['online']
                             else 'coordinator_not_ready' if not state['ready'] else 'fresh_login_required')
        for context in self.execution_contexts(active_only=True):
            if ((self.config.coordinator_enabled and context.get('console_prepared') is not True)
                    or not self.console.context_ready(context['workload'])
                    or context['role'] != role or context.get('workflow', 'cve') != workflow):
                continue
            try:
                run = self.register_run(session['claims'], context, queue_workflow=workflow,
                                        expires_at=self.session_deadline(session))
            except sqlite3.IntegrityError:
                continue
            session.setdefault('runs', set()).add(run)
            session.setdefault('run_credentials', {})[run] = {
                'claims': json.loads(json.dumps(session['claims'])), 'token': session['token'],
                'expires_at': self.store.describe(run, session['claims']['sub'])['run']['expires']}
            return run
        raise Denied('fresh_context_required')


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
