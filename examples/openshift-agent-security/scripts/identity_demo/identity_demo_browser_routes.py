# SPDX-License-Identifier: Apache-2.0
"""Browser HTTP adapters; rendering receives only projected display state."""
from __future__ import annotations
import hashlib
from html import escape
import secrets
import time
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from agent_security_service import VerifiedActor
import identity_demo_console as console
from identity_demo_run_store import Denied
import identity_demo_admission_policy as policy

async def denied(self, request: Request, error: Denied) -> Response:
    """Return deliberate safe denials with no credential or exception body."""
    if "text/html" in request.headers.get("accept", ""):
        response = page(self, '<div class="heading"><h1>Request could not proceed</h1></div>'
            '<section class="card"><p>' + escape(console.public_error(str(error)))
            + '</p><p><a href="/">Return to workflows</a> · <a href="/login">Sign in again</a></p></section>')
        response.status_code = 403
        return response
    return JSONResponse({"allowed": False, "reason": str(error)}, status_code=403)


def display_claims(self, session: dict) -> dict:
    """Use local lifetime only for presentation, never token verification or delegation."""
    return {**{key: session["claims"][key] for key in ("sub", "preferred_username") if key in session["claims"]}, "exp": self.session_deadline(session),
            "session_refresh": "session_expires" in session,
            "display_role": self.role(session["claims"])}


def page(self, content: str, *, user: str = "", active: str = "Workflows",
         csrf: str = "", status_code: int = 200, live_url: str = "", live_kind: str = "run", session_deadline: int = 0) -> HTMLResponse:
    """Render one local-asset console while preserving existing browser protections."""
    headers = {
        "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        "Referrer-Policy": "same-origin",
    }
    response = HTMLResponse(console.shell(content, user=user, active=active,
        csrf=csrf, live_url=live_url, live_kind=live_kind,
        session_deadline=session_deadline), headers=headers, status_code=status_code)
    return response


async def home(self, request: Request) -> Response:
    """Show fixed approved workflows and observed coordinator availability."""
    try:
        session = await self.session(request)
    except Denied:
        return page(self, '<div class="heading"><div><h1>Secure agent workflows</h1>'
            '<p class="muted">One place to review proposals, approve exact actions and follow protected outcomes.</p></div></div>'
            '<section class="card"><h2>Sign in to your workspace</h2><p>Use your real identity. User and workload permissions are enforced independently.</p>'
            '<a class="button primary" href="/login">Sign in</a></section>')
    claims = display_claims(self, session)
    configured = [c for c in self.execution_contexts(active_only=True) if not self.config.coordinator_enabled or c.get("console_prepared") is True]
    if self.config.coordinator_enabled:
        used = self.used_contexts(configured)
        visible = [c for c in configured if c["workload"] not in used and self.console.context_ready(c["workload"])]
    else:
        visible = configured
    if request.query_params.get("view") == "overview":
        return page(self, console.overview(self.console.history(claims["sub"]),
            self.console.available(self.config.coordinator_enabled), claims),
            user=claims.get("preferred_username", claims["display_role"]), active="Overview",
            csrf=session["csrf"], live_url="/console/live", live_kind="home",
            session_deadline=self.session_deadline(session))
    return page(self, console.home(claims, session["csrf"],
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
        csrf=session["csrf"], live_url="/console/live", live_kind="home",
        session_deadline=self.session_deadline(session))


async def history(self, request: Request) -> Response:
    """Expose only the signed-in owner's retained runs."""
    session = await self.session(request)
    return page(self, console.run_list(self.console.history(session["claims"]["sub"])),
        user=session["claims"].get("preferred_username", self.role(session["claims"])), active="Runs", csrf=session["csrf"], session_deadline=self.session_deadline(session))


async def evidence(self, request: Request) -> Response:
    """Keep evidence traceable to actual owner-scoped runs, not illustrative badges."""
    session = await self.session(request)
    records = self.console.history(session["claims"]["sub"])
    proofs = [(r, self.console.describe(r['id'])) for r in records]
    return page(self, console.evidence_view(proofs),
        user=session["claims"].get("preferred_username", self.role(session["claims"])),
        active="Evidence", csrf=session["csrf"], session_deadline=self.session_deadline(session))


def settings_content(self) -> str:
    """Project bounded worker and profile capacity state for the signed-in user."""
    return console.settings(self.console.available(self.config.coordinator_enabled),
                            cluster_jira=bool(self.config.jira_view_url))


async def settings(self, request: Request) -> Response:
    """Show preparation capacity and recovery status."""
    session = await self.session(request)
    return page(self, settings_content(self),
        user=session['claims'].get('preferred_username', self.role(session['claims'])), active='Settings',
        csrf=session['csrf'], live_url='/settings/live', live_kind='settings',
        session_deadline=self.session_deadline(session))


async def live_settings(self, request: Request) -> Response:
    """Publish authenticated aggregate progress; no raw pool mappings reach the """
    session = await self.session(request)
    html = settings_content(self)
    return JSONResponse({'html': html, 'revision': hashlib.sha256(html.encode()).hexdigest(),
                         'poll': True, 'server_time': int(time.time()),
                         'session_deadline': self.session_deadline(session)}, headers={'Cache-Control': 'no-store'})


async def submit(self, request: Request) -> Response:
    """Select an unused context by role; no browser-supplied workload or subject."""
    session, fields = await self.form(request, renew=False)
    session = await self.session(request, minimum=policy.MIN_RUN_SECONDS, force=True)
    if fields.keys() == {"role", "cve"} and fields["cve"] == "CVE-2099-0001":
        workflow = "cve"
    elif fields.keys() == {"role", "request"} and fields["request"] == "SERVICE-0001":
        workflow = "service-request"
    elif fields.keys() == {"role", "request"} and fields["request"] == "OPS-0001":
        workflow = "incident-triage"
    else:
        raise Denied("unapproved_source")
    if self.config.coordinator_enabled:
        await self.wait_for_readiness(session)
        session = await self.session(request, minimum=policy.MIN_RUN_SECONDS)
    try:
        run = self.start_workflow(session, workflow, fields['role'])
        return RedirectResponse('/runs/' + run, status_code=303)
    except Denied as error:
        reason = str(error)
        if reason != 'fresh_context_required':
            if "text/html" in request.headers.get("accept", ""):
                return page(self, '<div class="heading"><h1>Workflow not started</h1></div>'
                    '<section class="card"><p>' + escape(reason.replace("_", " "))
                    + '</p><p><a href="/login">Sign in again</a> · <a href="/">Return to workflows</a></p></section>',
                    user=session["claims"].get("preferred_username", self.role(session["claims"])),
                    csrf=session["csrf"], session_deadline=self.session_deadline(session), status_code=409)
            return JSONResponse({"reason": reason}, status_code=409)

    if "text/html" in request.headers.get("accept", ""):
        return page(self, '<div class="heading"><h1>Fresh context required</h1></div>'
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
        return page(self, '<section class="card"><h1>Jira view temporarily unavailable</h1>'
                         '<p>The retained run and verified outcome remain available. No action was retried.</p></section>',
                         user=display_claims(self, session).get('preferred_username', ''), status_code=502)
    finally:
        self.tickets.pop(ticket, None)
    return page(self, issue_html(issue, record['run']['id']),
                     user=display_claims(self, session).get('preferred_username', ''), csrf=session['csrf'])


async def status(self, request: Request) -> Response:
    """Show stable controls; refresh recorded progress without reloading the document."""
    session = await self.session(request)
    content, _ = run_content(self, session, request.path_params["run"])
    return page(self, content, user=session["claims"].get("preferred_username", self.role(session["claims"])),
        csrf=session["csrf"],
        live_url="/runs/" + request.path_params["run"] + "/live",
        session_deadline=self.session_deadline(session))


async def live_run(self, request: Request) -> Response:
    """Return an authenticated owner-scoped fragment; never credentials or raw logs."""
    session = await self.session(request)
    content, poll = run_content(self, session, request.path_params["run"])
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
    claims = display_claims(self, session)
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
            or policy.can_start_during_check(readiness)) and not readiness['busy']
            and claims['exp'] - time.time() >= policy.MIN_RUN_SECONDS),
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
    record = self.store.describe(run, owner)["run"]
    original_deadline = record["expires"]
    self.actions.approve(
        VerifiedActor(owner, record["workload"]),
        run,
        fields["action"],
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
