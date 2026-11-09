# SPDX-License-Identifier: Apache-2.0
"""Private coordinator, preparer and maintenance HTTP operations."""
from __future__ import annotations
from openshift_security.oidc import SESSION_IDLE_SECONDS
import json
import re
import secrets
import time
from uuid import UUID
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from agent_security_service import VerifiedActor
from identity_demo_run_store import Denied, strict_json
import identity_demo_http as http
from identity_demo_http import secret_matches

async def prepare_next(self, request: Request) -> Response:
    """Reserve fresh preparation without stopping or replacing the coordinator."""
    http.console_operator(self, request, 'preparer')
    data = await http.json_fields(self, request, {'owner'},
        limit=1024, reason='console_fields')
    return JSONResponse({'preparation': self.console.prepare_next(data['owner'], self.config.contexts, self.config.project)},
                        headers={'Cache-Control': 'no-store'})


async def prepare_finish(self, request: Request) -> Response:
    """Accept only a trusted provisioner's exact fresh native identity receipt."""
    http.console_operator(self, request, 'preparer')
    data = await http.json_fields(self, request, {'owner', 'id', 'context', 'receipt_sha256'},
        limit=8192, reason='console_fields')
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


async def backend_state(self, request: Request) -> Response:
    from identity_demo_backend_observation import observe
    return await observe(self, request)


async def console_heartbeat(self, request: Request) -> Response:
    """Observe one authorized coordinator process without issuing browser credentials."""
    http.console_operator(self, request)
    data = strict_json(await self.body(request, 1024))
    if set(data) not in ({"worker"}, {"worker", "phase", "reason", "catalog_expires", "checked_at"}):
        raise Denied("console_fields")
    self.console.heartbeat(data["worker"], **{k: v for k, v in data.items() if k != "worker"})
    return JSONResponse({"recorded": True})


async def retirement_check(self, request: Request) -> Response:
    """Prove durable cleanup without giving the preparer database/Pod access."""
    http.console_operator(self, request, 'preparer')
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
    http.console_operator(self, request, 'observer')
    return JSONResponse({**self.console.available(True), "verified_issue_keys": self.console.verified_issue_keys()}, headers={"Cache-Control": "no-store"})


async def console_pool(self, request: Request) -> Response:
    """Configure bounded idle preparation through the existing operator boundary."""
    if request.method == 'GET':
        http.console_operator(self, request, 'observer')
        result = self.console.pool_status(self.config.contexts, self.config.project)
    else:
        data = strict_json(await self.body(request, 8192))
        http.console_operator(self, request, 'operator')
        if set(data) == {'action', 'id', 'receipt_sha256'} and data['action'] == 'recheck-quarantine':
            if not self.config.private_operator_api:
                raise Denied('private_operator_required')
            result = {'id': self.console.queue_quarantine_recheck(data['id'], data['receipt_sha256'], self.config.contexts)}
        elif set(data) == {'action','configuration','receipt_sha256'} and data['action']=='profiles':
            result = self.console.configure_profile_pool(data['configuration'],data['receipt_sha256'],self.config.contexts,self.config.project)
        elif (set(data) in ({'action', 'enabled', 'receipt_sha256', 'retired_workloads'},
                           {'action', 'enabled', 'receipt_sha256', 'retired_workloads', 'initial_empty'})
              and data['action'] == 'automatic' and data['enabled'] is False
              and data.get('initial_empty', False) is False):
            retired = data['retired_workloads']
            result = self.console.pause_pool(data['receipt_sha256'], {} if retired == [] else retired,
                                             self.config.contexts, self.config.project)
        else:
            raise Denied('console_fields')
    return JSONResponse(result, headers={'Cache-Control': 'no-store'})


async def console_review_recovery(self, request: Request) -> Response:
    """Require existing operator authentication and a retained reconciliation receipt."""
    http.console_operator(self, request, 'operator')
    data = await http.json_fields(self, request, {'run_id', 'receipt_sha256'},
        limit=2048, reason='console_fields')
    self.console.review_recovery(data['run_id'], data['receipt_sha256'])
    return JSONResponse({'recorded':True}, headers={'Cache-Control':'no-store'})


async def console_next(self, request: Request) -> Response:
    """Claim one browser-created run; no browser controls execution identifiers."""
    http.console_operator(self, request)
    data = await http.json_fields(self, request, {'worker'},
        limit=1024, reason='console_fields')
    job = self.console.claim(data["worker"])
    if job:
        context = self.context_for_workload(job["workload"])
        if context is None:
            raise Denied("unknown_workload")
        job["context"] = context
    return JSONResponse({"job": job})


async def console_update(self, request: Request) -> Response:
    """Persist allowlisted observations for an exactly claimed execution."""
    http.console_operator(self, request)
    data = await http.json_fields(self, request, {'run_id', 'worker', 'stage', 'evidence'},
        limit=8192, reason='console_fields')
    self.console.update(data["run_id"], data["worker"], data["stage"], data["evidence"])
    return JSONResponse({"recorded": True})


async def console_inspect(self, request: Request) -> Response:
    """Read coordination state without sharing sessions, tokens or operator keys."""
    http.console_operator(self, request)
    run_id = request.path_params["run"]
    with self.store.transaction() as db:
        row = db.execute("SELECT user FROM runs WHERE id=?", (run_id,)).fetchone()
    if not row:
        raise Denied("run_binding")
    return JSONResponse({**self.store.describe(run_id, row["user"]), "console": self.console.describe(run_id)},
        headers={"Cache-Control": "no-store"})


async def operator_run(self, request: Request) -> Response:
    """Bind a real login to a preverified context for headless acceptance only."""
    http.internal(request, self.config.operator_secret)
    data = await http.json_fields(self, request, {'access_token', 'workload'},
        limit=65536, reason='operator_fields')
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
    http.execution_operator(self, request)
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
    http.execution_operator(self, request)
    data = await http.json_fields(self, request, {'run_id', 'user', 'workload', 'assessment', 'arguments'},
        limit=65536, reason='operator_fields')
    run = self.store.identity_run(data["user"], data["workload"])
    if run["id"] != data["run_id"]:
        raise Denied("run_binding")
    self.store.save_assessment(run["id"], run["user"], data["assessment"])
    proposal = self.actions.propose(VerifiedActor(run["user"], run["workload"]), run["id"], data["arguments"])
    return JSONResponse(proposal)


async def credentials(self, request: Request) -> Response:
    """Release a still-valid human token solely to authenticated coordination."""
    http.execution_operator(self, request)
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
