# SPDX-License-Identifier: Apache-2.0
"""Headless trusted host. Control and native MCP use separate TLS listeners."""
import asyncio
from dataclasses import dataclass
import json
import hashlib
import os
from pathlib import Path
import time
from urllib.parse import urlparse

import httpx
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.routing import Route

from agent_security_runtime import RunStore, prepare_storage
from agent_security_runtime import Denied, strict_json, tool_arguments
from agent_security_runtime import BackendPort, SecurityService, VerifiedActor
from identity_demo_oidc import OIDCSession, valid_delegation, safe_https, secret_matches
from contract import DOCUMENTS


@dataclass(frozen=True)
class HostConfig:
    issuer: str
    client: str
    origin: str
    audience: str
    trust_domain: str
    database: Path
    contexts: tuple
    operator_secret: str
    issuer_service: str | None = None
    issuer_ca: str | None = None
    stateless_login: bool = True


class HTTPDocuments:
    """A fixed HTTPS destination. Neither dispatch nor observation retries writes."""

    def __init__(self, origin, ca_file, write_key, observe_key):
        if (not safe_https(origin) or urlparse(origin).path not in ("", "/")
                or not ca_file or not all(len(k) >= 32 for k in (write_key, observe_key))
                or secret_matches(write_key, observe_key)):
            raise ValueError("Fixed verified backend and distinct credentials required")
        import ssl
        self.client = httpx.Client(base_url=origin, verify=ssl.create_default_context(cafile=ca_file),
            timeout=8, follow_redirects=False, trust_env=False)
        self.write_key, self.observe_key = write_key, observe_key

    def request(self, method, path, value=None):
        key = self.write_key if method == "POST" else self.observe_key
        with self.client.stream(method, path, json=value,
                headers={"Authorization": "Bearer " + key}) as response:
            response.raise_for_status()
            if response.is_redirect:
                raise Denied("backend_redirect")
            body = bytearray()
            for chunk in response.iter_bytes():
                body.extend(chunk)
                if len(body) > 16384:
                    raise Denied("backend_response_size")
            return strict_json(bytes(body))

    def dispatch(self, effects):
        return self.request("POST", "/revisions", effects)["reference"]

    def observe(self, reference):
        DOCUMENTS.check_reference(reference.split("/", 1)[0], reference)
        return self.request("GET", "/revisions/" + reference)

    def read(self, resource):
        if not DOCUMENTS.valid_scope(resource):
            raise Denied("backend_resource")
        return self.request("GET", "/context/" + resource)


class DocumentHost:
    def __init__(self, config, backend, verifier=None):
        if (not all(safe_https(v) for v in (config.issuer, config.origin, config.audience))
                or urlparse(config.origin).path not in ("", "/")
                or not isinstance(config.operator_secret, str) or len(config.operator_secret) < 32):
            raise ValueError("Fixed authenticated host configuration required")
        self.config = config
        self.store = RunStore(config.database, connector=DOCUMENTS, trust_domain=config.trust_domain)
        self.store.recover_dispatched()
        self.security = SecurityService(self.store, BackendPort(DOCUMENTS.fingerprint,
            backend.dispatch, backend.observe, backend.read))
        self.authentication = OIDCSession(config, self.store, verifier)
        self.contexts = {}
        for context in config.contexts:
            if (set(context) != {"name", "workload", "role", "collection"}
                    or not isinstance(context["name"], str) or not context["name"]
                    or context["name"] in self.contexts
                    or context["role"] not in DOCUMENTS.workload_roles
                    or not DOCUMENTS.valid_scope(context["collection"])):
                raise ValueError("Unique operator-verified document execution contexts required")
            self.contexts[context["name"]] = dict(context)
        if len({c["workload"] for c in config.contexts}) != len(config.contexts):
            raise ValueError("Single-use execution identities required")
        auth = self.authentication
        self.control = Starlette(routes=[Route("/", self.home), Route("/login", auth.login),
            Route("/callback", auth.callback), Route("/logout", auth.logout, methods=["POST"]),
            Route("/runs", self.start, methods=["POST"]), Route("/runs/{run}", self.describe),
            Route("/runs/{run}/approve", self.approve, methods=["POST"]),
            Route("/runs/{run}/cancel", self.cancel, methods=["POST"]),
            Route("/runs/{run}/reconcile", self.reconcile, methods=["POST"]),
            Route("/internal/credentials/{run}", self.credentials)], exception_handlers={Denied: self.denied})
        self.control.add_middleware(BaseHTTPMiddleware, dispatch=auth.browser_session_cookie)
        self.tools = Starlette(routes=[Route("/mcp", self.mcp, methods=["POST"])],
            exception_handlers={Denied: self.denied})

    async def denied(self, request, error):
        return self.response({"allowed": False, "reason": str(error)}, 403)

    @staticmethod
    def response(value, status=200):
        return JSONResponse(value, status_code=status, headers={"Cache-Control": "no-store"})

    def owner(self, session, run):
        record = self.store.describe(run, session["claims"]["sub"])["run"]
        return VerifiedActor(record["user"], record["workload"])

    async def home(self, request):
        session = await self.authentication.session(request)
        return self.response({"user": session["claims"]["sub"], "csrf": session["csrf"],
            "contexts": sorted(self.contexts), "runs": sorted(session.get("runs", ())),
            "credential_expires": session["claims"]["exp"]})

    async def start(self, request):
        session, fields = await self.authentication.form(request)
        if set(fields) != {"context"} or fields["context"] not in self.contexts:
            raise Denied("execution_context")
        context = self.contexts[fields["context"]]
        claims = session["claims"]
        run = self.store.create_run(issuer=claims["iss"], user=claims["sub"],
            user_role={"analyst": "reviewer", "viewer": "viewer"}[self.authentication.role(claims)],
            workload=context["workload"], workload_role=context["role"], project=context["collection"],
            expires=int(claims["exp"]), assessment="Synthetic document publication")
        session.setdefault("runs", set()).add(run)
        session.setdefault("run_credentials", {})[run] = {"claims": json.loads(json.dumps(claims)),
            "token": session["token"], "expires_at": int(claims["exp"])}
        return self.response({"run_id": run, "workload": context["workload"], "expires": int(claims["exp"])}, 201)

    async def describe(self, request):
        session = await self.authentication.session(request)
        return self.response(self.store.describe(request.path_params["run"], session["claims"]["sub"]))

    async def approve(self, request):
        session, fields = await self.authentication.form(request)
        if set(fields) != {"action", "digest"}:
            raise Denied("approval_fields")
        run = request.path_params["run"]
        self.security.approve(self.owner(session, run), run, fields["action"], fields["digest"], int(time.time()) + 120)
        return self.response({"approved": True})

    async def cancel(self, request):
        session, fields = await self.authentication.form(request, renew=False)
        if fields:
            raise Denied("cancel_fields")
        run = request.path_params["run"]
        self.owner(session, run)
        self.store.revoke("run_id", run)
        return self.response({"cancelled": True})

    async def reconcile(self, request):
        session, fields = await self.authentication.form(request)
        if set(fields) != {"action", "reference"}:
            raise Denied("reconciliation_fields")
        run = request.path_params["run"]
        self.owner(session, run)
        pending = self.store.reconciliation(run, fields["action"])
        observed = await run_in_threadpool(self.security.backend.observe, fields["reference"])
        self.store.reconcile_result(run, fields["action"], pending["execution_id"], fields["reference"], observed)
        return self.response({"reconciled": True, "reference": fields["reference"]})

    async def credentials(self, request):
        values = request.headers.getlist("authorization")
        if len(values) != 1 or not secret_matches(values[0], "Bearer " + self.config.operator_secret):
            raise Denied("internal_authentication")
        run = request.path_params["run"]
        current = dict(request.query_params)
        if current not in ({}, {"current": "true"}):
            raise Denied("credential_mode")
        for session in self.authentication.sessions.values():
            retained = session.get("run_credentials", {}).get(run)
            if retained and self.authentication.session_deadline(session) > time.time():
                if current:
                    # Operator-only expiry acceptance: new human credentials cannot
                    # extend the original run. Never sent to an agent process.
                    record = self.store.describe(run, session["claims"]["sub"])["run"]
                    return self.response({"access_token": session["token"], "user": record["user"],
                        "workload": record["workload"], "expires_at": session["claims"]["exp"]})
                claims = retained["claims"]
                record = self.store.identity_run(claims["sub"], self.owner(session, run).workload)
                if record["id"] == run and retained["expires_at"] > time.time():
                    return self.response({"access_token": retained["token"], "user": record["user"],
                        "workload": record["workload"], "expires_at": record["expires"]})
        raise Denied("reauthentication_required")

    async def actor(self, request):
        values = request.headers.getlist("authorization")
        if len(values) != 1 or not values[0].startswith("Bearer "):
            raise Denied("missing_token")
        claims = await run_in_threadpool(self.authentication.verify, values[0][7:], self.config.audience)
        if not valid_delegation(claims):
            raise Denied("delegation_contract")
        run = self.store.identity_run(claims["sub"], claims["azp"])
        role = {"analyst": "reviewer", "viewer": "viewer"}[self.authentication.role(claims)]
        if (role != run["user_role"] or claims["iat"] < run["not_before"]
                or claims["exp"] > run["expires"]):
            raise Denied("credential_binding")
        return VerifiedActor(claims["sub"], claims["azp"]), run["id"]

    async def mcp(self, request):
        actor, run = await self.actor(request)
        body = await self.authentication.body(request, 16384)
        with self.store.transaction() as db:
            self.store.event(db, run, None, 'authenticated_request', {
                'user': actor.user, 'workload': actor.workload,
                'delegation': 'short-lived-bearer', 'audience': self.config.audience,
                'actual_body_sha256': hashlib.sha256(body).hexdigest()})
        rpc = strict_json(body)
        if not isinstance(rpc, dict) or rpc.get("jsonrpc") != "2.0":
            raise Denied("invalid_rpc")
        if rpc.get("method") == "initialize":
            value = {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}},
                "serverInfo": {"name": "document-security", "version": "1"}}
        elif rpc.get("method") == "notifications/initialized":
            return self.response({}, 202)
        elif rpc.get("method") == "tools/list":
            value = {"tools": [{"name": name, "description": description, "inputSchema": {"type": "object"}}
                for name, description in [("documents.read", "Read the bound collection"),
                    ("documents.propose", "Propose exact document effects"), (DOCUMENTS.tool, "Publish an exactly approved revision")]]}
        elif rpc.get("method") == "tools/call":
            params = rpc.get("params")
            if not isinstance(params, dict) or not isinstance(params.get("name"), str):
                raise Denied("unsupported_tool")
            args = tool_arguments(body, params["name"])
            if not isinstance(args, dict) or args.get("run_id") != run:
                raise Denied("run_binding")
            if params["name"] == "documents.read" and set(args) == {"run_id", "collection"}:
                result = await run_in_threadpool(self.security.read, actor, run, args["collection"])
            elif params["name"] == "documents.propose" and set(args) == {"run_id", "effects"}:
                result = self.security.propose(actor, run, args["effects"])
            elif params["name"] == DOCUMENTS.tool:
                result = await run_in_threadpool(self.security.execute, actor, body)
            else:
                raise Denied("unsupported_tool")
            value = {"content": [{"type": "text", "text": json.dumps(result)}]}
        else:
            raise Denied("unsupported_rpc")
        return self.response({"jsonrpc": "2.0", "id": rpc.get("id"), "result": value})


async def serve(config):
    import uvicorn
    os.umask(0o077)
    database = Path(config["database"])
    prepare_storage(database)
    host_config = HostConfig(**{**config["host"], "database": database,
        "contexts": tuple(config["host"]["contexts"]),
        "operator_secret": Path(config["operator_key_file"]).read_text().strip()})
    backend = HTTPDocuments(config["backend_origin"], config["backend_ca"],
        Path(config["backend_write_key_file"]).read_text().strip(),
        Path(config["backend_observe_key_file"]).read_text().strip())
    host = DocumentHost(host_config, backend)
    servers = [uvicorn.Server(uvicorn.Config(app, host="0.0.0.0", port=port,
        ssl_certfile=config["certificate"], ssl_keyfile=config["private_key"],
        limit_concurrency=32, timeout_keep_alive=2, access_log=False, proxy_headers=False))
        for app, port in [(host.tools, 8443), (host.control, 8444)]]
    try:
        await asyncio.gather(*(server.serve() for server in servers))
    finally:
        backend.client.close()


if __name__ == "__main__":
    asyncio.run(serve(strict_json(Path(os.environ["DOCUMENT_HOST_CONFIG"]).read_bytes())))
