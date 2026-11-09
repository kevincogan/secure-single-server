# SPDX-License-Identifier: Apache-2.0
"""Server-rendered, credential-free presentation of trusted driver state."""

from __future__ import annotations
from pathlib import Path

from datetime import datetime, timezone
import json
import re
import time

import identity_demo_console_visuals as visuals
from identity_demo_admission_policy import (MIN_RUN_SECONDS, ROUTINE_CHECK_FRESH_SECONDS,
    ROUTINE_CHECK_WAIT_SECONDS, checking_readiness, can_start_during_check)


STYLE = visuals.STYLE
text = visuals.text


def jira_preview_href(issue_key: object) -> str | None:
    """Link synthetic Jira keys only to the fixed read-only local preview."""
    if not isinstance(issue_key, str) or not re.fullmatch(r"(?:TEST|SERVICE|OPS)-[1-9][0-9]*", issue_key):
        return None
    return "http://127.0.0.1:18088/issue/" + issue_key


def badge(label: str, kind: str = "") -> str:
    """Render a fixed status class with escaped text."""
    return '<span class="tag ' + kind + '">' + text(label) + '</span>'


def shell(content: str, *, user: str = "", active: str = "Workflows", csrf: str = "", live_url: str = "", live_kind: str = "run", session_deadline: int = 0) -> str:
    """Provide one self-contained console without third-party assets or scripts."""
    nav = "".join('<a class="' + ('active' if name == active else '') + '" href="' + href + '">' + name + '</a>'
                  for name, href in (("Overview", "/?view=overview"), ("Workflows", "/"),
                                     ("Runs", "/runs"), ("Evidence", "/evidence"), ("Settings", "/settings")))
    account = ''
    if user and csrf:
        if session_deadline > 0:
            deadline = datetime.fromtimestamp(session_deadline, timezone.utc)
            remaining = max(0, session_deadline - int(time.time()))
            remaining_label = (str(remaining // 60) + 'm ' + str(remaining % 60) + 's remaining'
                               if remaining else 'Sign in again')
            session_status = ('<section class="account-session" aria-label="Browser session">'
                '<div class="account-session-heading"><span class="account-session-label">Browser session</span>'
                '<span class="account-session-state" data-session-state><span class="account-session-dot" aria-hidden="true"></span>'
                '<span data-session-state-label>Active</span></span></div>'
                '<time class="account-session-time" data-session-deadline="' + text(session_deadline) + '" datetime="'
                + text(deadline.isoformat(timespec="seconds")) + '">'
                + text(remaining_label) + '</time>'
                '<span class="account-session-note">Activity can extend this session within its configured limits.</span></section>')
        else:
            session_status = ('<section class="account-session" aria-label="Browser session">'
                '<div class="account-session-heading"><span class="account-session-label">Browser session</span>'
                '<span class="account-session-state" data-session-state><span class="account-session-dot" aria-hidden="true"></span>'
                '<span data-session-state-label>Active</span></span></div>'
                '<span class="account-session-time">Current session</span></section>')
        account = ('<details class="account-menu"><summary aria-label="Account options for ' + text(user) + '">'
            '<span class="avatar" aria-hidden="true">' + text(user[:1].upper()) + '</span>'
            '<span class="account-name">' + text(user) + '</span><span class="account-chevron" aria-hidden="true"></span>'
            '</summary><div class="account-panel"><div class="account-panel-heading">'
            '<span class="avatar account-panel-avatar" aria-hidden="true">' + text(user[:1].upper()) + '</span>'
            '<div class="account-panel-identity"><span class="account-panel-label">Signed in</span><strong>' + text(user) + '</strong></div></div>'
            + session_status + '<div class="account-actions"><a class="account-action" href="/login">Sign in again</a>'
            '<form method="post" action="/logout">' + csrf_field(csrf)
            + '<button class="account-action account-signout" type="submit">Sign out</button></form></div></div></details>')
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            '<title>Agent Security Console</title><style>' + STYLE + '</style>' + ('<script src="/assets/console.js" defer></script>' if live_url or session_deadline else '') + '</head><body'
            + '><div class="layout">'
            '<aside class="sidebar"><a class="brand" href="/"><span class="shield" aria-hidden="true"></span>Agent Security</a>'
            '<nav class="nav" aria-label="Main navigation">' + nav + '</nav>'
            '<div class="sidebar-foot">Development demo<br>Synthetic inputs · Neutral branding</div></aside>'
            '<div class="main"><header class="topbar"><strong>Agent Security Console</strong><div class="account">'
            + account + '</div></header>'
            '<main class="content"' + (' data-live-url="' + text(live_url) + '" data-live-kind="' + text(live_kind) + '"' if live_url else '') + '><div class="banner">Development demonstration · Synthetic data · Decisions come from the protected execution path</div>'
            + '<div id="connection-status" class="notice connection" role="status" hidden></div><div id="live-content">' + content + '</div></main></div></div></body></html>')


def public_error(reason: str) -> str:
    """Explain recovery without exposing internal authentication or binding details."""
    return {
        'session_renewal_required':'Your sign-in could not be renewed safely. Sign in again; recorded results are retained and existing run deadlines are unchanged.',
        'login_required':'Your sign-in is unavailable or has expired. Sign in again to continue; recorded results are retained.',
        'run_binding':'This run is not available to the current account. Return to workflows or open one of your own runs.',
        'approval_binding':'This proposal has changed or has already been handled. Reopen the run to review its recorded state before taking another action.',
        'csrf_origin':'The request could not be verified. Return to the console and submit the action from its own page.',
        'csrf_token':'This page is no longer valid for submission. Reopen the run or sign in again before continuing.',
        'presentation_not_idle':'Pool settings cannot change until the current run, cleanup and preparation are complete.',
        'run_expired':'The original run deadline has passed. Sign in again and start a new workflow.'
    }.get(reason, 'Authorization or request validation prevented this operation. Return to workflows to check the current state; do not repeat a write with an uncertain outcome.')


def csrf_field(csrf: str) -> str:
    """Keep CSRF values confined to their existing protected browser forms."""
    return '<input type="hidden" name="csrf" value="' + text(csrf) + '">'








def coordinator_label(coordinator: dict) -> str:
    """Use one consistent meaning for coordinator state across every page."""
    if not coordinator.get('online'):
        return 'Coordinator offline'
    if coordinator.get('reason') == 'context_preparing':
        return 'Preparing fresh demo sandbox'
    if coordinator.get('reason') == 'presentation_preparing':
        return 'Pool migration required'
    if coordinator.get('phase') == 'stopping':
        return 'Coordinator stopped'
    if coordinator.get('reason') == 'recovery_required' or coordinator.get('phase') == 'blocked':
        return 'Operator review required'
    if coordinator.get('busy'):
        return 'Run in progress'
    if checking_readiness(coordinator):
        return 'Ready to start' if coordinator.get('automatic_pool') and can_start_during_check(coordinator) else 'Checking readiness'
    return 'Ready to start' if coordinator.get('ready', True) else 'Preparing demo'


def readiness_panel(claims: dict, coordinator: dict) -> str:
    """Explain observed readiness and the original sign-in deadline in plain language."""
    fresh = claims.get('exp', 0) - time.time() >= MIN_RUN_SECONDS
    ready = coordinator.get('ready', coordinator.get('online', False))
    phase, reason = coordinator.get('phase', ''), coordinator.get('reason', '')
    if not coordinator.get('enabled'):
        label, detail, tone = 'Operator rehearsal mode', 'Browser submission is prepared for the operator rehearsal.', 'wait'
    elif phase == 'stopping':
        label, detail, tone = 'Coordinator stopped', 'The operator has stopped coordination for preparation. No new run will start.', 'wait'
    elif not coordinator.get('online'):
        label, detail, tone = 'Coordinator offline', 'The operator must start the demo coordinator. No new run will be allocated.', 'bad'
    elif coordinator.get('busy') and ready:
        label, detail, tone = 'Run in progress', 'One protected run is executing or restoring its environment. Wait before starting the next.', 'wait'
    elif checking_readiness(coordinator) and coordinator.get('automatic_pool') and can_start_during_check(coordinator):
        label, detail, tone = 'Ready to start', 'Available workflows can be requested while routine checks finish. All security checks must pass before allocation.', 'good'
    elif checking_readiness(coordinator):
        detail = ('Background checks are running. You can request a workflow now; it will start only after they pass.'
                  if can_start_during_check(coordinator) else
                  'Routine background checks are running. Start becomes available after a successful check.')
        label, tone = 'Checking readiness', 'active'
    elif not ready:
        label, tone = ('Operator review required' if phase == 'blocked' or reason == 'recovery_required' else 'Preparing demo'), 'wait'
        if reason == 'context_preparing':
            label = 'Preparing fresh demo sandbox'
        elif reason == 'presentation_preparing':
            label = 'Pool migration required'
        detail = {'context_preparing':'The previous run is safely closed. A new owned sandbox and identity are being prepared automatically. Start will become available when preparation finishes.',
                  'presentation_preparing':'The operator must retire the legacy inventory before activating profile scheduling.',
                  'context_preparation_failed':'Fresh preparation stopped safely. The operator must review its private receipt; no mutation will be replayed automatically.',
                  'identity_network':'A current worker node is missing from the owned SPIRE kubelet-egress rule. The operator must review the guarded network reconciliation command before a new run.',
                  'sender_trust':'Historical certificate-bound delegation warning; consult the original installation records.',
                  'operator_login':'Operator cluster authentication needs renewal before another run. The app will not start with insufficient credential lifetime.',
                  'cluster_unavailable':'Cluster access is unavailable. The coordinator is checking again.',
                  'catalog_expiring':'The discovery credential needs renewal before another run.',
                  'catalog_refresh_failed':'Credential refresh needs operator review.',
                  'recovery_required':'An uncertain outcome or incomplete cleanup needs operator review. Writes will not be replayed.',
                  'control_unavailable':'The coordinator is reconnecting to its control channel.'}.get(reason, 'Preflight checks are running. Start becomes available when they pass.')
    elif not fresh:
        label, detail, tone = 'Fresh sign-in required', 'Sign in again before starting. Your current login has too little time left for preparation and approval.', 'wait'
    else:
        label, detail, tone = 'Ready to start', 'The coordinator is online. Choose a workflow; it will pause for your approval before a create attempt.', 'good'
    return ('<section class="readiness" aria-label="Demo readiness">' + badge(label, tone)
            + '<p>' + text(detail) + '</p></section>')


def missing_context_hint(coordinator: dict) -> str:
    """Describe replacement accurately when readiness blocks its preparation."""
    if coordinator.get('recovery_required'):
        return 'Sandbox replacement is paused until operator recovery completes.'
    if not coordinator.get('online') or coordinator.get('phase') == 'blocked':
        return 'Sandbox preparation is paused until the coordinator is ready.'
    if coordinator.get('automatic_pool') and (coordinator.get('ready') or checking_readiness(coordinator)):
        return 'Preparing your next run. A verified context will become available automatically.'
    if coordinator.get('reason') == 'presentation_preparing':
        return 'The operator must complete the profile-pool migration before starting a run.'
    if coordinator.get('auto_prepare'):
        return 'A fresh sandbox will be prepared automatically after cleanup. Please wait.'
    return 'A fresh context is needed. Ask the demo operator.'



def automatic_settings(slots: list[dict], state: dict, *, cluster_jira: bool = False) -> str:
    """Report the verified ready pool without making refill a presentation task."""
    pool = state['automatic_pool']
    available = sum(min(s['target'], s['available']) for s in slots)
    missing = max(0, pool['target'] - available)
    quarantined = pool['states']['quarantined']
    blocked = state.get('recovery_required') or state.get('uncertain') or state.get('phase') == 'blocked'
    busy = bool(state.get('busy') or state.get('running'))
    label = coordinator_label(state)
    startable = label == 'Ready to start' and not busy
    if startable and not available:
        label = 'Preparing your next run'
    detail = 'Available workflows can start while replacement contexts are prepared in the background. One demo executes at a time.'
    if not state.get('online'):
        detail = 'The coordinator is offline. Prepared contexts are retained; the operator must restore coordination before a run can start.'
    elif blocked:
        detail = 'A security or recovery check needs operator review before another run.'
    elif busy:
        detail = 'The current demo is executing or closing its authorization and credentials. Preparation may continue; wait before starting another demo.'
    elif not startable:
        detail = 'Coordinator checks must pass before a run starts. Prepared contexts remain available after successful verification.'
    elif not state.get('auto_prepare'):
        detail = 'Automatic preparation is offline. Existing ready workflows remain available; ask the operator to check the preparer service.'
    elif pool['managed'] >= pool['limit'] and not pool['states']['preparing'] and missing:
        detail = ('Making room for replacements. Used contexts retire automatically; ready workflows remain available.'
                  if pool['states']['consumed'] or pool['states']['retiring'] else
                  'Preparation is paused at capacity. Ready workflows remain available; the operator should review quarantined contexts.')
    names = {'cve': 'CVE triage', 'service-request': 'Remediation change request', 'incident-triage': 'Incident triage'}
    rows = ''.join('<tr><td>' + text(names.get(s['workflow'], s['workflow'])) + '</td><td>' + text('Reader' if s['role'] == 'reader' else 'Triage')
        + '</td><td>' + text(s['available']) + ' / ' + text(s['target']) + '</td><td>'
        + badge(('Ready to start' if startable else 'Prepared') if s['available'] else 'Preparing your next run', 'good' if s['available'] else 'wait') + '</td></tr>' for s in slots)
    notice = ('<p class="notice">' + text(quarantined) + ' context(s) quarantined. The operator must review their private receipts; uncertain mutations are never replayed.</p>') if quarantined else ''
    jira_detail = ('Verified Jira issues open in the authenticated, read-only run view. Access follows your run permissions.'
                   if cluster_jira else 'Access Jira uses the read-only preview on the operator machine. That service and the Jira fixture must remain available.')
    return ('<div class="heading"><div><h1>Settings</h1><p class="muted">Automatic demo preparation and recovery.</p></div></div>'
        '<section class="card"><div class="card-head"><h2>Demo availability</h2>' + badge(label, 'bad' if blocked or not state.get('online') else 'good' if startable and available else 'wait') + '</div>'
        '<p role="status">' + text(detail) + '</p><div class="preparation-metrics">'
        '<div class="compare"><strong>' + text(available) + ' ready</strong><span>Target: ' + text(pool['target']) + '</span></div>'
        '<div class="compare"><strong>' + text(missing) + ' remaining</strong><span>Verified individually before use</span></div>'
        '<div class="compare"><strong>' + text(pool['managed']) + ' / ' + text(pool['limit']) + '</strong><span>Managed capacity, including quarantines</span></div></div>'
        '<div class="table-wrap"><table><thead><tr><th>Workflow</th><th>Workload</th><th>Ready / target</th><th>Availability</th></tr></thead><tbody>' + rows + '</tbody></table></div>'
        + notice + '<p class="small muted">Contexts are prepared and retired automatically. Workflows with a ready compatible context stay available.</p>'
        '<div class="actions"><a class="button primary" href="/">Open workflows</a></div></section>'
        '<section class="card"><h2>Completed runs</h2><p>Sandbox scratch is disposable. Your authorized run history, approvals, audit and verified Jira outcomes remain available after cleanup.</p>'
        '<div class="actions"><a class="button" href="/runs">Review runs</a><a class="button" href="/evidence">View evidence</a></div>'
        '<p class="small muted">' + text(jira_detail) + '</p></section>')


def settings(state: dict, *, cluster_jira: bool = False) -> str:
    """Show profile scheduling or the current pause and recovery status."""
    if pool := state.get('automatic_pool'):
        return automatic_settings(pool['slots'], state, cluster_jira=cluster_jira)
    return ('<div class="heading"><h1>Settings</h1></div>'
        '<section class="card"><h2>Demo preparation</h2><p role="status">'
        + text(coordinator_label(state)) + '</p>'
        '<p>Profile scheduling is paused or awaiting operator configuration.</p>'
        '<div class="actions"><a class="button" href="/">Open workflows</a>'
        '<a class="button" href="/runs">Review runs</a></div></section>')


def home(claims: dict, csrf: str, *, available: bool, service: bool, coordinator: dict,
         roles: tuple[str, ...] | None = None,
         available_roles: tuple[str, ...] | None = None,
         service_available: bool = True, incident: bool = False, incident_available: bool = False) -> str:
    """Show available workflows while preserving selections during readiness updates."""
    role = claims.get("display_role", "")
    roles = ('triage', 'reader') if roles is None and available else roles or ()
    ready = coordinator.get('ready', coordinator.get('online', False))
    startable = ready or can_start_during_check(coordinator)
    enabled = not coordinator.get('enabled') or (startable and not coordinator.get('busy')
        and claims.get('exp', 0) - time.time() >= MIN_RUN_SECONDS)
    disabled = '' if enabled else ' disabled'
    lead = ('<div class="heading"><div><h1>Secure agent workflows</h1><p class="muted">Choose a workflow. Review the proposal. Approve an exact action.</p></div></div>'
            '<div id="readiness-panel">' + readiness_panel(claims, coordinator) + '</div>')
    if not available:
        return lead + '<div class="notice">No workloads are available. Contact the demo operator for fresh contexts.</div>'
    available_roles = set(roles if available_roles is None else available_roles)
    selected_role = next((r for r in roles if r in available_roles), roles[0] if roles else None)
    choices = ''.join('<option value="' + r + '" data-label="' +
        ('Triage — assessment and controlled create' if r == 'triage' else 'Reader — assessment, create denied') + '"' +
        ('' if r in available_roles else ' disabled') +
        (' selected' if r == selected_role else '') + '>' +
        ('Triage — assessment and controlled create' if r == 'triage' else 'Reader — assessment, create denied') +
        ('' if r in available_roles else ' · fresh context needed') + '</option>' for r in roles)
    cve_disabled = disabled if available_roles else ' disabled'
    missing_hint = missing_context_hint(coordinator)
    cve_hint = 'Prepared context available.' if available_roles else missing_hint
    cve = ('<section class="card"><h2>CVE triage</h2>' + badge("Frozen synthetic assessment")
           + '<p>Assess the supplied CVE finding and propose a Jira task. No live vulnerability scan is performed.</p>'
           '<form method="post" action="/submit">' + csrf_field(csrf)
           + '<input type="hidden" name="cve" value="CVE-2099-0001">'
           '<label for="role">Approved workload</label><p><select id="role" name="role">' + choices + '</select></p>'
           + ''.join('<div data-cve-preview="' + workload + '"' + ('' if workload == selected_role else ' hidden') + '>'
               + workflow_preview([
                   'Verify sandbox identity and read TEST', 'Show the frozen CVE assessment',
                   'Review and approve the exact proposal',
                   ('Gateway denies the viewer; Jira unchanged' if role == 'viewer' else
                    'Gateway denies the reader; Jira unchanged' if workload == 'reader' else
                    'Gateway checks permission; verify the Jira task')],
                   'Reader: assessment is allowed; create is denied.' if workload == 'reader' else
                   'Triage: an analyst may create after approval; a viewer is denied.') + '</div>'
               for workload in roles)
           + '<p id="cve-availability" class="small muted">' + text(cve_hint) + '</p>'
           '<button class="primary"' + cve_disabled + '>Start assessment</button></form></section>') if roles else ''
    def model_card(workflow: str, title: str, request_id: str, project: str, description: str, available: bool, steps: list[str]) -> str:
        return ('<section class="card"><h2>' + title + '</h2>' + badge('Approved chat model')
            + '<p>' + description + '</p>' + workflow_preview(steps[:-1] + ['Gateway denies the viewer; Jira unchanged'] if role == 'viewer' else steps,
                'Viewer: the draft can be reviewed, but create is denied.' if role == 'viewer' else
                'Analyst: may create the exact task after approval.')
            + '<form method="post" action="/submit" data-workflow="' + workflow + '">'
            + csrf_field(csrf) + '<input type="hidden" name="role" value="triage">'
            + '<input type="hidden" name="request" value="' + request_id + '">'
            + '<p class="small muted">Workload: triage · Authorized project: ' + project + '</p>'
            + '<p id="' + ('service' if workflow == 'service-request' else 'incident') + '-availability" class="small muted">'
            + ('Prepared context available.' if available else missing_hint)
            + '</p><button class="primary"' + (disabled if available else ' disabled') + '>Start '
            + ('remediation request' if workflow == 'service-request' else title.lower()) + '</button></form></section>')
    reuse = model_card('service-request', 'Remediation change request', 'SERVICE-0001', 'SERVICE',
        'Turn a supplied synthetic CVE finding into a proposed change with tests, a maintenance window and rollback. Approval creates a review ticket; no patch is applied.', service_available,
        ['Verify sandbox identity', 'Read related SERVICE change records', 'Model drafts the change, tests and rollback',
         'Review and approve the exact plan', 'Gateway checks permission; verify the Jira task']) if service else ''
    ops = model_card('incident-triage', 'Incident triage', 'OPS-0001', 'OPS',
        'Investigate a synthetic checkout timeout. Read related incidents, correlate observed facts and propose the next investigation task.', incident_available,
        ['Verify sandbox identity', 'Read OPS; controlled TEST access is denied', 'Model drafts an investigation task',
         'Review and approve the exact proposal', 'Gateway checks permission; verify the Jira task']) if incident else ''
    return lead + '<div class="workflow-grid workflow-cards">' + ops + reuse + cve + '</div>' + comparisons()



def workflow_preview(steps: list[str], note: str) -> str:
    """Describe expected behavior separately from live evidence and authorization."""
    return ('<div class="workflow-preview"><span class="eyebrow">Expected flow</span><ol>'
            + ''.join('<li>' + text(step) + '</li>' for step in steps)
            + '</ol><p class="small muted">' + text(note)
            + ' Each run finishes with verified cleanup. These are expected steps, not recorded results.</p></div>')


def comparisons() -> str:
    """Explain expected comparisons without presenting illustrative outcomes as live decisions."""
    return ('<section class="card"><h2>Permission comparisons</h2>'
            '<p class="muted small">Expected scenarios, not results of this run. Each uses a fresh identity and real user authentication.</p>'
            '<div class="comparison"><div class="compare"><strong>Analyst + triage</strong><span>May create after exact approval</span></div>'
            '<div class="compare"><strong>Viewer + triage</strong><span>Create denied by user permission</span></div>'
            '<div class="compare"><strong>Analyst + reader</strong><span>Create denied by workload permission</span></div></div></section>')


def jira_context(evidence: dict) -> str:
    """Present only actual completed read observations, separately from pending requests."""
    if 'jira_project' not in evidence:
        return ''
    items = evidence.get('jira_issues', [])
    result = '<section class="finding"><h3>Jira context the agent inspected</h3><p>Project ' + text(evidence['jira_project'])
    result += ' · ' + text(evidence.get('jira_issue_count', 0)) + ' issues retrieved · ' + text(len(items)) + ' shown</p>'
    if items:
        result += '<div class="table-wrap"><table><thead><tr><th>Issue</th><th>Existing work</th><th>Status</th></tr></thead><tbody>'
        for item in items:
            result += '<tr><td>' + text(item['key']) + '</td><td>' + text(item['summary']) + '</td><td>' + text(item['status']) + '</td></tr>'
        result += '</tbody></table></div>'
    else:
        result += '<p>No issues were returned by this completed read.</p>'
    result += '<details><summary>Read scope and limits</summary><p>' + text(evidence.get('jira_query', '')) + '</p>'
    result += '<p>Protected delegated MCP read · bounded results · issue text is untrusted data · no mutation tool offered to the model.</p></details></section>'
    return result


def run_page(record: dict, csrf: str, context: dict, job: dict | None, coordinator: dict | None = None, *, cluster_jira: bool = False) -> tuple[str, bool]:
    """Derive visible progress from persisted run/action state and observed coordinator evidence."""
    run, actions, events = record['run'], record['actions'], record['audit']
    evidence = (job or {}).get('evidence', {})
    service = context.get('workflow') in ('service-request', 'incident-triage')
    incident = context.get('workflow') == 'incident-triage'
    remediation = service and evidence.get('scenario_version') == 'remediation-v1'
    title = 'Incident triage' if incident else 'Remediation change request' if remediation else 'Service request' if service else 'CVE triage'
    label = ('Actual model inference observed' if evidence.get('model_inference') else 'Inference not yet observed') if service else 'Frozen synthetic assessment'
    now = int(time.time())
    expired = run['expires'] <= now
    active = bool(run['active']) and not expired
    action = actions[-1] if actions else None
    state = action['state'] if action else 'pending'
    denied = visuals.projection(record, job)['denied']
    terminal = (job or {}).get('state') in ('completed', 'failed', 'interrupted')
    safe_cancelled = ((job or {}).get('stage') == 'cancelled' and evidence.get('cleanup_verified') is True
                      and state not in ('executing', 'unknown'))
    if state == 'succeeded':
        outcome, tone = ('Protected action succeeded', 'good') if not job or evidence.get('backend_fields_match_approval') else ('Verifying the created Jira issue', 'active')
    elif denied:
        outcome, tone = 'Protected action denied: ' + denied.replace('_', ' '), 'bad'
    elif state == 'unknown':
        outcome, tone = 'Outcome uncertain — operator reconciliation required', 'bad'
    elif (job or {}).get('stage') == 'agent_stopping':
        outcome, tone = 'Agent stopped — closing safely', 'bad'
    elif safe_cancelled:
        outcome, tone = ('Proposal rejected — no issue created', 'bad') if state == 'proposed' else ('Run cancelled — review recorded outcome', 'wait')
    elif (job or {}).get('state') in ('failed', 'interrupted'):
        outcome, tone = 'Execution stopped — ' + (job or {}).get('stage', 'failed').replace('_', ' '), 'bad'
    elif expired:
        outcome, tone = 'Run expired — start with a fresh context', 'wait'
    elif not run['active']:
        outcome, tone = 'Run closed — assessment and audit retained', 'wait'
    elif state == 'proposed':
        outcome, tone = 'Awaiting your approval · No issue created', 'wait'
    elif state == 'approved':
        outcome, tone = 'Approval recorded · Waiting for protected execution', 'wait'
    elif state == 'executing':
        outcome, tone = 'Protected action executing', 'active'
    else:
        outcome, tone = ((job or {}).get('stage', 'Waiting for trusted coordinator').replace('_', ' '), 'active')
    content = ('<div class="heading"><div><h1>' + title + '</h1><p class="muted">Follow the observed steps. Review the exact proposal before approval.</p></div>' + badge(label) + '</div>'
               '<div class="contextbar"><span>User role: ' + text(run['user_role']) + '</span><span>Workload: ' + text(run['workload_role'])
               + '</span><span>Project: ' + text(run['project']) + '</span><span class="small">Run ' + text(run['id'][:10])
               + ' · Original deadline ' + text(datetime.fromtimestamp(run['expires'], timezone.utc).strftime('%H:%M:%S UTC')) + '</span></div>')
    content += progress_view(record, job, coordinator or {}, denied)
    content += visuals.architecture(record, job, coordinator or {}, context.get('workflow', 'cve'))
    content += visuals.input_context(context.get('workflow', 'cve'), scenario_version=evidence.get('scenario_version'))
    proposal = '<div class="card-head"><h2>' + ('Jira outcome' if state == 'succeeded' or denied else 'Review proposed Jira action' if action else 'Workload assessment') + '</h2>' + badge(outcome, tone) + '</div>'
    proposal += '<div class="finding"><strong>' + ('OPS-0001' if incident else 'SERVICE-0001' if service else 'CVE-2099-0001') + '</strong><p>' + ('Synthetic supplied text · Model output requires review' if service else 'Synthetic finding · Repeatable fixture, no live vulnerability scan') + '</p></div>'
    if run['assessment'] != 'Assessment pending workload execution.':
        proposal += '<details><summary>Read assessment report</summary><pre>' + text(run['assessment']) + '</pre></details>'
    if run['assessment'] == 'Assessment pending workload execution.' and active and not terminal:
        proposal += '<div class="assessment-placeholder" role="status"><p>Waiting for the workload’s recorded assessment.</p><span></span><span></span><span></span></div>'
    if service:
        observed = jira_context(evidence)
        proposal += ('<details><summary>Jira findings used by the agent · ' + text(evidence.get('jira_issue_count', 0)) + ' issue observations</summary>' + observed + '</details>') if action and observed else observed
    if evidence.get('scope_probe_denied'):
        proposal += ('<section class="outcome scope-check" aria-label="Project isolation check">'
                     '<div class="outcome-heading"><div><span class="eyebrow">Security check</span>'
                     '<strong class="outcome-title">Project isolation check passed</strong></div>'
                     '<span class="tag good">TEST blocked · HTTP 403</span></div>'
                     '<p>The same OPS run requested TEST through the native MCP path. The gateway returned HTTP 403: project permission. No TEST data was returned. This controlled probe is supplied to the agent as tool feedback.</p></section>')
    for a in actions:
        args = json.loads(a['payload'])
        fields = '<dl class="fields">'
        for key, name in (('project', 'Project'), ('issue_type', 'Issue type'), ('summary', 'Summary'), ('description', 'Description')):
            fields += '<dt>' + name + '</dt><dd>' + text(args.get(key, '')) + '</dd>'
        fields += '</dl><details><summary>Exact tool arguments</summary><pre>' + text(json.dumps(args, indent=2)) + '</pre></details>'
        fields += '<p class="muted small">State: ' + text(a['state']) + '</p>'
        if a['issue_key']:
            verified = a['state'] == 'succeeded' and (not job or evidence.get('backend_fields_match_approval') and evidence.get('verified_issue_key') == a['issue_key'])
            preview_href = '/runs/' + run['id'] + '/jira' if cluster_jira and verified else jira_preview_href(a['issue_key']) if verified and (not job or evidence.get('jira_preview_ready')) else None
            proposal += '<section class="outcome jira-result" aria-label="Jira issue outcome"><div class="jira-result-copy"><span class="eyebrow">Jira outcome</span><strong class="result-key">' + ('Verified issue: ' if evidence.get('backend_fields_match_approval') else 'Created issue: ') + text(a['issue_key']) + '</strong><p>The protected adapter recorded the issue. Its fields are checked against the exact approval; user and workload attribution remain in the audit.</p></div>'
            if preview_href:
                proposal += ('<div class="jira-result-action"><a class="button primary" href="' + preview_href
                             + '" target="_blank" rel="noopener noreferrer" aria-label="Access Jira (opens in a new tab)">Access Jira <span aria-hidden="true">↗</span></a>'
                             '<span class="muted small">Read-only Jira view · new tab</span></div>')
            proposal += '</section>'
        proposal += ('<details><summary>Approved Jira fields</summary>' + fields + '</details>') if a['state'] == 'succeeded' else '<h3>Proposed Jira create</h3>' + fields
        if a['state'] == 'proposed' and active:
            proposal += ('<form method="post" action="/runs/' + run['id'] + '/approve">' + csrf_field(csrf)
                         + '<input type="hidden" name="action" value="' + text(a['id']) + '">'
                         + '<input type="hidden" name="digest" value="' + text(a['digest']) + '">'
                         '<div class="actions"><button class="primary">Approve this exact proposal</button></div></form>'
                         '<p class="muted small">Approval applies only to these exact fields. It cannot override user or workload permissions.</p>')
    if state == 'succeeded':
        proposal += '<p class="muted small">' + ('Independent backend field verification passed.' if evidence.get('backend_fields_match_approval') else 'Independent backend field verification has not yet been reported.') + '</p>'
    if denied:
        explanation = {'user_permission':'This account can read the assessment but is not permitted to create an issue.',
                       'workload_permission':'The reader workload cannot create issues, even when the user may create them.'}.get(denied, 'The protected path rejected this action. Review the recorded reason below.')
        proposal += '<div class="outcome bad"><strong>' + text(outcome) + '</strong><p>' + text(explanation) + ' The assessment and audit remain available.</p></div>'
    if 'backend_before' in evidence and 'backend_after' in evidence:
        proposal += '<p><strong>Independently checked project count:</strong> ' + text(evidence['backend_before']) + ' → ' + text(evidence['backend_after']) + '</p>'
    if active and not terminal and (job or {}).get('stage') != 'agent_stopping':
        proposal += '<div class="actions"><form method="post" action="/runs/' + run['id'] + '/cancel">' + csrf_field(csrf) + '<button class="danger">' + ('Reject proposal and close run' if state == 'proposed' else 'Cancel run') + '</button></form></div>'
    elif expired and not safe_cancelled and state not in ('succeeded', 'unknown'):
        proposal += '<div class="notice">This run has expired. Reauthentication cannot extend its original approval deadline.</div>'
    if terminal and (job or {}).get('state') != 'completed' and not safe_cancelled:
        proposal += '<div class="notice">An execution problem was recorded. No automatic write retry will be attempted. Review the audit before starting another run.</div>'
    identity = '<span class="dot ' + ('good' if evidence.get('native_bound_read') else 'wait') + '"></span>'
    observed_at = datetime.fromtimestamp(job['updated'], timezone.utc).strftime('%H:%M:%S UTC') if job else 'Not reported'
    routing = {key: evidence[key] for key in ('gateway_backend_services', 'tool_schemas', 'live_run_identity_check',
        'actual_arguments_and_approval_check', 'scoped_adapter_service_token_delivery') if key in evidence}
    security = ('<h2>Security context</h2><p class="muted small">Coordinator evidence: ' + text(observed_at) + '</p><section class="security-item"><h3><span class="dot good"></span>User identity</h3><p>' + text(run['user_role']) + ' · Authenticated at run creation</p></section>'
                '<section class="security-item"><h3>' + identity + 'Workload identity</h3><p>' + ('Verified native protected delegated read' if evidence.get('native_bound_read') else 'Registered workload · Runtime verification pending')
                + '</p><p class="identity">' + text(run['workload']) + '</p></section>'
                '<section class="security-item"><h3>OpenShell</h3><p>Approved ' + text(run['workload_role']) + ' workload</p><details><summary>View policy & settings evidence</summary><p>'
                + ('Agent socket-denial checks observed for this run.' if evidence.get('egress_denied') else 'Live socket-denial evidence has not been reported for this run.')
                + '</p><p class="small muted">Trusted supervisor, DNS, image pulls and operator traffic are explicit exceptions.</p></details></section>'
                '<section class="security-item"><h3>MCP Gateway</h3><p>' + ('Registration Ready observed' if evidence.get('gateway_ready') else 'Discovery observation pending')
                + '</p><details><summary>View tools &amp; routing</summary><p>' + text(', '.join(evidence.get('tool_names', [])) or 'Tools not yet observed')
                + '</p><p>User + workload + project + exact approval are checked by the existing protected path.</p>'
                + ('<p class="small muted">Observed tool schemas and routing configuration:</p><pre>' + text(json.dumps(routing, indent=2)) + '</pre>' if routing else '') + '</details></section>'
                '<section class="security-item"><h3>Credential custody</h3><p>Backend credentials stay outside the agent.</p>'
                '<details><summary>Certificate and renewal evidence</summary><p>' + ('A read after final-token expiry was observed.' if evidence.get('final_token_renewal') else 'Renewal has not been observed in this run.')
                + '</p><p class="small muted">Public certificate details and broader acceptance receipts remain operator evidence; no keys or bearer tokens are shown.</p></details></section>')
    activity = activity_view(events, job)
    proposal_card = '<section class="card">' + proposal + '</section>'
    work = proposal_card + activity if action else activity + proposal_card
    content += '<div class="columns"><div class="work-area">' + work + '</div><aside class="card" id="security-context">' + security + '</aside></div>'
    content += '<section class="card" id="decision-audit"><span class="eyebrow">Correlated security trace</span><h2>Decision and outcome audit</h2><p class="muted small">Each event identifies the responsible component and its meaning. Expand an event for the recorded context.</p>' + visuals.timeline(events) + '</section>'
    content += '<p class="footer-note"><span data-connection-label>Live persisted run state</span> · Last observed ' + text(datetime.fromtimestamp(job['updated'], timezone.utc).strftime('%H:%M:%S UTC') if job else 'Recorded state') + ' · <a href="">Refresh</a></p>'
    refresh = job.get('state') in ('queued', 'running') if job else active and state not in ('succeeded', 'unknown') and not denied
    return content, refresh


def evidence_view(proofs: list[tuple[dict, dict | None]]) -> str:
    """Curate control evidence separately from the owner-scoped run history."""
    controls = (
        ('Protected delegated access', 'native_bound_read', 'A successful native protected read verifies the delegated user, workload and run.', 'security-context'),
        ('Sandbox isolation', 'egress_denied', 'Agent socket-denial checks were observed. Trusted runtime traffic has explicit exceptions.', 'security-context'),
        ('Model inference', 'model_inference', 'The actual workload received an accepted model response. This does not establish factual correctness.', 'architecture'),
        ('Exact backend outcome', 'backend_fields_match_approval', 'Independent issue fields matched the approved payload.', 'decision-audit'),
        ('Secure cleanup', 'cleanup_verified', 'Temporary access cleanup was positively verified.', 'decision-audit'),
        ('Token renewal', 'final_token_renewal', 'A protected read after final-token expiry was observed. This is separate from certificate rotation.', 'security-context'))
    result = '<div class="heading"><div><span class="eyebrow">Trust, with receipts</span><h1>Security evidence</h1><p class="muted">Runs shows investigation history. Evidence groups the controls actually observed in your latest 50 runs.</p></div></div><div class="workflow-grid">'
    for title, field, explanation, anchor in controls:
        matches = [(r,j) for r,j in proofs if (j or {}).get('evidence',{}).get(field) is True]
        result += '<section class="card"><h2>' + title + '</h2>' + badge(str(len(matches)) + ' observed runs' if matches else 'Not observed', 'good' if matches else '') + '<p>' + explanation + '</p>'
        if matches:
            r,_ = matches[0]
            result += '<a class="button small" href="/runs/' + text(r['id']) + '#' + anchor + '">Inspect latest evidence</a>'
        else:
            result += '<p class="muted small">No positive receipt in the displayed owner-scoped history. Configuration alone is not proof.</p>'
        result += '</section>'
    result += '</div><section class="card"><h2>Evidence boundaries</h2><p>These cards describe recorded observations, not continuous health or full RFC acceptance. Open a run for exact approval, policy decisions, actor attribution and outcomes.</p><p>Public identity details are available in the run. Private certificate material, credentials and broader installation/rotation acceptance receipts remain in protected operator storage.</p><a href="/runs">Browse your run history →</a></section>'
    return result


def overview(records: list[dict], coordinator: dict, claims: dict | None = None) -> str:
    """Summarize only this owner's retained runs and observed worker availability."""
    active = sum(bool(r['active']) and r['expires'] > time.time() for r in records)
    status = coordinator_label(coordinator)
    return ('<div class="heading"><div><h1>Workspace overview</h1><p class="muted">Your workflows, recent activity and execution readiness.</p></div>'
            '<a class="button primary" href="/">Choose a workflow</a></div>'
            + ('<div id="readiness-panel">' + readiness_panel(claims, coordinator) + '</div>' if claims else '')
            + '<div class="comparison"><section class="compare"><strong>Execution coordinator</strong><span data-readiness-status>' + text(status)
            + '</span></section><section class="compare"><strong>Your active runs</strong><span data-active-count>' + text(active)
            + '</span></section><section class="compare"><strong>Your retained runs</strong><span data-retained-count>' + text(len(records))
            + ' (latest 50)</span></section></div>' + run_list(records[:5], embedded=True))


def run_list(records: list[dict], *, embedded: bool = False) -> str:
    """List only the authenticated owner's durable history."""
    heading = '<h2>Recent runs</h2>' if embedded else '<h1>Your runs</h1>'
    body = '<div class="heading"><div>' + heading + '<p class="muted">Retained assessments, decisions and outcomes for your authenticated identity.</p></div></div><section class="card">'
    if not records:
        return body + '<p class="empty">No runs yet. <a href="/">Start a workflow</a>.</p></section>'
    body += '<div class="table-wrap"><table><thead><tr><th>Run</th><th>Workload</th><th>Project</th><th>Outcome</th><th>Access</th></tr></thead><tbody>'
    for r in records:
        access = 'Expired' if r['expires'] <= time.time() else 'Active' if r['active'] else 'Closed'
        state = ('Succeeded' if r.get('action_state') == 'succeeded' else 'Outcome uncertain' if r.get('action_state') == 'unknown'
                 else 'Cancelled' if r.get('console_stage') == 'cancelled' else 'Execution stopped' if r.get('console_state') == 'failed'
                 else 'Denied' if r.get('denial_detail') and not r['active'] else 'In progress' if r['active'] and access != 'Expired' else access)
        workflow = 'Incident triage' if r.get('workflow') == 'incident-triage' else ('Remediation change request' if r.get('scenario_version') == 'remediation-v1' else 'Service request') if r.get('workflow') == 'service-request' else 'CVE triage' if r.get('workflow') == 'cve' else 'Retained run'
        body += '<tr><td><a href="/runs/' + text(r['id']) + '">' + workflow + '</a><br><span class="muted small">' + text(r['id'][:12]) + '</span></td><td>' + text(r['workload_role']) + '</td><td>' + text(r['project']) + '</td><td>' + text(state) + '</td><td>' + access + '</td></tr>'
    return body + '</tbody></table></div></section>'



STAGE_COPY = {
    'queued': ('Queued for coordinator', 'Your request is recorded. Native execution has not started yet.', 'Wait for the coordinator to claim this run. No Jira action has been requested.'),
    'preparing_identity': ('Checking the run', 'Resolve the approved sandbox and check the original user/workload association.', 'Wait for preparation. No Jira action has been requested.'),
    'configuring_gateway': ('Preparing protected access', 'Create the run-scoped issuer and gateway configuration using existing owned components.', 'Preparation is active; no user action is needed.'),
    'waiting_gateway': ('Waiting for gateway readiness', 'Wait for the cluster to discover tools and verify the protected TLS route.', 'Cluster reconciliation can take time. The current observation remains visible below.'),
    'attaching_credentials': ('Attaching scoped credentials', 'Attach the run-bound exchange provider to this exact sandbox.', 'The agent receives scoped access through the trusted runtime.'),
    'verifying_native_read': ('Verifying identity and transport', 'Perform a real protected MCP read before running the assessment.', 'Wait for the protected read result.'),
    'retrying_identity': ('Retrying the identity check', 'The read-only connection ended before verification. A bounded transport retry is in progress.', 'No approval or Jira write is being retried.'),
    'identity_verified': ('Identity verified', 'The native protected read passed for this user and workload.', 'The coordinator is preparing the assessment.'),
    'discovering_tools': ('Inspecting available tools', 'Observe the actual gateway registration, schemas and protected adapter routing.', 'No Jira create has been attempted.'),
    'tools_discovered': ('Tools observed', 'The gateway registration, argument schemas and protected adapter routing were observed.', 'The workload can now produce its proposal.'),
    'egress_verified': ('Agent egress checked', 'The actual agent socket-denial checks passed for this run.', 'The model request will use the approved native provider.'),
    'assessment_running': ('Producing the assessment', 'Run the selected workload against the supplied synthetic input.', 'Wait for a proposal, then review its exact fields.'),
    'model_inference': ('Generating the proposal with the model', 'The actual OpenShift workload is requesting Approved chat model inference over synthetic text.', 'Model output must be reviewed before approval.'),
    'agent_reasoning': ('Agent choosing its next step', 'The model is reviewing the task and the approved read capability.', 'Only a permitted Jira read or an unapproved draft can be returned.'),
    'checking_project_boundary': ('Checking the project boundary', 'The dedicated synthetic probe requests TEST using this OPS run. The gateway must decide independently.', 'No other-project data may be returned. Normal model queries remain restricted to OPS.'),
    'project_boundary_verified': ('Outside-project request blocked', 'The actual protected gateway returned HTTP 403 project permission. No TEST data was returned.', 'The agent receives this denial as tool feedback and continues with authorized OPS observations.'),
    'agent_read_requested': ('Agent requesting Jira context', 'The agent selected a bounded project query. The protected gateway must independently authorize it.', 'Wait for the actual read result; a request alone is not an allow decision.'),
    'agent_query_rejected': ('Query rejected before execution', 'Local validation rejected unsupported query syntax. No backend request was sent.', 'The agent receives validation feedback within its original turn limit and deadline. Permissions remain unchanged.'),
    'agent_read_complete': ('Jira context retrieved', 'A real governed read returned the bounded project context shown below.', 'The agent will use these observations to prepare its draft.'),
    'agent_read_denied': ('Jira read blocked', 'The governed path denied the requested read. No out-of-scope data was returned.', 'The agent receives only the denial reason and remains subject to the same limits.'),
    'draft_validated': ('Draft validated', 'The generated fields passed validation. The original driver will record an exact proposal for your review.', 'Wait for the approval controls; validation is not consent.'),
    'agent_draft_ready': ('Read-informed draft ready', 'The agent completed its bounded investigation and returned proposed fields.', 'Review the exact fields before approving; a draft is not execution authority.'),
    'agent_retry': ('Retrying a safe agent request', 'A model or read transport failed temporarily. The shared retry budget is bounded.', 'No approval or Jira write is retried.'),
    'agent_stopping': ('Agent stopped — closing safely', 'An agent step could not complete. No unvalidated draft can become an approvable action.', 'Wait for provider detachment and verified cleanup. No Jira write will be attempted.'),
    'agent_failed': ('Agent could not finish', 'The agent ended without an acceptable read-informed proposal.', 'Review the fixed failure category and retained evidence. No fallback draft is invented.'),
    'awaiting_approval': ('Your approval is needed', 'The assessment is ready. Approval applies only to the exact fields shown below.', 'Review the proposed Jira fields, then approve or cancel. Approval cannot override permissions.'),
    'approval_recorded': ('Approval recorded', 'Your consent for these exact fields has been recorded. The coordinator has not yet reported protected execution.', 'Wait for the gateway decision. Do not approve the same proposal again.'),
    'cancellation_recorded': ('Cancellation recorded', 'This run has been closed to further authorization. The coordinator is restoring its environment.', 'Wait for cleanup. Cancellation does not undo a completed write.'),
    'protected_execution': ('Checking permissions and executing', 'The protected path checks user, workload, project and exact approval before backend access.', 'Wait for the authoritative decision. Do not submit the action again.'),
    'outcome_verified': ('Outcome checked', 'The coordinator independently checked the backend result and project count.', 'The environment is being restored before the next run.'),
    'restoring_environment': ('Restoring the environment', 'Close this run and remove its temporary credentials and routing configuration.', 'The recorded business outcome remains visible. Wait for cleanup to finish.'),
    'completed': ('Run complete', 'Execution and cleanup finished. Review the verified outcome and audit below.', 'Return to workflows to start another run with a fresh context.'),
    'expired': ('Run expired', 'The original sign-in/run deadline has passed. It cannot be extended by another login.', 'Sign in again and start a new workflow; this run stays closed.'),
    'cancelled': ('Run cancelled', 'The run was closed without granting further execution authority.', 'Review the recorded outcome below. Cancellation does not undo a completed write.'),
    'execution_failed': ('Execution stopped', 'A protected execution step failed. No automatic tool-call retry will be made.', 'Read the recovery message below before starting another run.'),
    'inference_failed': ('Model request failed', 'The configured model could not produce an accepted proposal.', 'No fallback proposal is invented. The operator must check model access.'),
}


def progress_view(record: dict, job: dict | None, coordinator: dict, denied: str | None) -> str:
    """Explain six actual milestones, the active operation and the next user action."""
    run, actions, events = record['run'], record['actions'], record['audit']
    action = actions[-1] if actions else None
    evidence = (job or {}).get('evidence', {})
    stage = 'queued' if (job or {}).get('state') == 'queued' else (job or {}).get('stage', 'preparing_identity')
    terminal = (job or {}).get('state') in ('completed', 'failed')
    if run['expires'] <= time.time() and not terminal:
        stage = 'expired'
    elif stage == 'awaiting_approval' and action and action['state'] == 'approved':
        stage = 'approval_recorded'
    elif not terminal and not run['active'] and any(e['event'] == 'cancelled' for e in events) and stage != 'restoring_environment':
        stage = 'cancellation_recorded'
    steps = visuals.progress(record, job, denied)
    title, purpose, next_action = STAGE_COPY.get(stage, STAGE_COPY['preparing_identity'])
    code = evidence.get('failure_code')
    if code == 'native_read_failed':
        purpose = 'The workload identity/transport check failed before assessment. No model draft or Jira write was attempted.'
    if code == 'agent_failed':
        purpose = 'Agent stopped: ' + str(evidence.get('agent_error_category', 'agent validation failed')).replace('_', ' ') + '. No draft was substituted.'
        if evidence.get('agent_error_category') == 'model_output_limit':
            purpose = 'The model reached its output limit before returning a complete response. No draft was substituted; no approval or Jira write was attempted.'
    if code == 'session_expired':
        title, purpose, next_action = STAGE_COPY['expired']
    elif code == 'recovery_required' and not evidence.get('cleanup_verified'):
        next_action = 'Operator review is required. Cleanup or a write outcome is uncertain; do not repeat the action.'
    elif terminal and evidence.get('cleanup_verified') and stage != 'completed':
        next_action += ' This run is safely closed; the coordinator can accept another fresh run.'
    connection = ''
    if coordinator.get('enabled') and not coordinator.get('online') and not terminal:
        connection = '<div class="notice">Coordinator connection lost. The last recorded step is shown; no completion is assumed. The operator must restore coordination.</div>'
    elif coordinator.get('phase') == 'blocked':
        connection = '<div class="notice">Coordinator needs operator review before further execution. No action will be replayed automatically.</div>'
    view = visuals.projection(record, job, denied)
    if denied:
        title, purpose, next_action = ('Action blocked at MCP Gateway', visuals.REASONS.get(denied, 'The protected request was denied.'),
            'Jira was not modified (verified count unchanged).' if view['unchanged'] else 'Backend outcome verification is pending. Do not repeat this action.')
    elif view['rejected']:
        title, purpose, next_action = ('Proposal rejected by the user', 'No approval was granted for this proposal.',
            'Wait for verified cleanup before starting another run.' if not view['cleanup'] else 'This run is safely closed. Start another run with a fresh context.')
    waiting = stage in ('queued', 'awaiting_approval', 'approval_recorded', 'cancellation_recorded')
    status_tone = 'good' if stage == 'completed' and not denied else 'bad' if stage == 'agent_stopping' or denied or terminal and stage != 'completed' else 'wait' if waiting else 'active'
    status_css = 'done' if status_tone == 'good' else 'failed' if status_tone == 'bad' else 'waiting' if waiting else ''
    if view['rejected'] or view['cancelled']:
        status_css = 'rejected' if view['rejected'] else 'cancelled'
        status_tone = 'rejected' if view['rejected'] else 'cancelled'
    return steps + connection + '<section class="card execution-status ' + status_css + '" aria-live="polite"><div class="card-head"><h2>' + text(title) + '</h2>' + badge('Rejected' if view['rejected'] else 'Cancelled' if view['cancelled'] else 'Closing safely' if stage == 'agent_stopping' else 'Waiting for coordinator' if stage == 'queued' else 'Waiting on cluster' if stage == 'waiting_gateway' else 'Waiting for your review' if stage == 'awaiting_approval' else 'Waiting for coordinator' if stage in ('approval_recorded', 'cancellation_recorded') else 'Finished' if terminal else 'In progress', status_tone) + '</div><p>' + text(purpose) + '</p><p class="next-action"><strong>Next:</strong> ' + text(next_action) + '</p><p class="small muted">Original authorization window: <span data-deadline="' + text(run['expires']) + '">' + text(datetime.fromtimestamp(run['expires'], timezone.utc).strftime('%H:%M:%S UTC')) + '</span></p></section>'


def activity_view(events: list[dict], job: dict | None) -> str:
    """Present only fixed, persisted milestones rather than raw operator logs."""
    observed = []
    for event in events:
        if event['event'].removeprefix('console_') not in ('assessment_running', 'model_inference', 'agent_reasoning', 'agent_read_requested', 'agent_query_rejected', 'agent_read_complete', 'agent_read_denied', 'agent_retry', 'agent_draft_ready', 'draft_validated', 'agent_failed', 'inference_failed', 'checking_project_boundary', 'project_boundary_verified'):
            continue
        if not observed or observed[-1]['event'] != event['event']:
            observed.append(event)
    rows = ''
    for index, e in enumerate(observed):
        stage = e['event'].removeprefix('console_')
        label = STAGE_COPY[stage][0] if stage in STAGE_COPY else {'run_created':'Authenticated run registered', 'console_queued':'Waiting for the coordinator', 'console_claimed':'Coordinator started this run'}[e['event']]
        at = datetime.fromtimestamp(e['at'], timezone.utc).strftime('%H:%M:%S')
        position = next(i for i, candidate in enumerate(events) if candidate is e)
        end = events[position+1]['at'] if position+1 < len(events) else None
        timing = text(max(0, end-e['at'])) + 's' if end is not None else ('<span data-elapsed-since="' + text(e['at']) + '">0s</span>' if (job or {}).get('state') in ('queued','running') and (job or {}).get('stage') == stage else 'Recorded')
        detail = json.loads(e['detail'])
        facts = []
        if 'agent_turn' in detail:
            facts.append('Turn ' + str(detail['agent_turn']) + ' of 4')
        if 'agent_query' in detail or 'jira_query' in detail:
            facts.append(detail.get('agent_query', detail.get('jira_query')))
        if 'jira_issue_count' in detail:
            facts.append(str(detail['jira_issue_count']) + ' bounded issue observations')
        if detail.get('scope_probe_denied'):
            facts.append('TEST blocked by the actual gateway · HTTP 403 · no issue data returned')
        if 'agent_denial_reason' in detail:
            facts.append('Blocked: ' + detail['agent_denial_reason'].replace('_', ' '))
        if 'agent_retry_count' in detail:
            facts.append('Retry ' + str(detail['agent_retry_count']) + ' of 3 · ' + detail['agent_retry_boundary'].replace('_', ' '))
        rows += '<li><time>' + text(at) + ' UTC</time><span class="activity-label">' + text(label)
        rows += ('<span class="event-detail">' + text(' · '.join(facts)) + '</span>') if facts else ''
        rows += '</span><span class="activity-time">' + timing + '</span></li>'
    return '<section class="card"><div class="card-head"><h2>Agent activity</h2><span class="small muted">Observed milestones · no secrets</span></div><p class="small muted">Times and durations come from recorded events. Waiting does not imply completion.</p><ol class="activity-log" aria-label="Observed agent activity">' + (rows or '<li>No agent activity has been recorded yet. Setup and identity checks appear in the security trace below.</li>') + '</ol></section>'


LIVE_SCRIPT = (Path(__file__).parent / "console.js").read_text()
