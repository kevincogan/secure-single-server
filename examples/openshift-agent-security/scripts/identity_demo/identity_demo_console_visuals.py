# SPDX-License-Identifier: Apache-2.0
"""Evidence-derived console visualizations. This module grants no execution authority."""

from __future__ import annotations
from pathlib import Path

from datetime import datetime, timezone
from html import escape
import json
import time


def text(value: object) -> str:
    """Escape all external content before inserting it in local markup."""
    return escape(str(value), quote=True)


COMPONENTS = {
    "user": (
        "01",
        "User",
        "Authenticated request",
        "Keycloak authenticates the person. The trusted entrypoint retains their role and binds the request to one run.",
    ),
    "keycloak": (
        "ID",
        "Keycloak",
        "User & delegated access",
        "The identity provider authenticates users and issues scoped access tokens. Tokens and refresh credentials are never displayed.",
    ),
    "spire": (
        "CA",
        "SPIFFE / SPIRE",
        "Attested workload identity",
        "SPIRE attests the workload and supplies credentials through the trusted runtime. A protected read verifies delegated identity; issuance and renewal timestamps require separate evidence.",
    ),
    "model": (
        "AI",
        "Inference",
        "Approved model provider",
        "For model workflows, the sandbox requests inference through the approved provider. The CVE workflow uses a frozen synthetic assessment, not live model inference.",
    ),
    "coordinator": (
        "02",
        "Coordinator",
        "Trusted run orchestration",
        "Resolves the immutable user, workload and run association, sequences execution, and verifies cleanup before accepting another run.",
    ),
    "sandbox": (
        "03",
        "OpenShell",
        "Isolated execution",
        "The approved workload runs inside its own sandbox. Network policy and the trusted runtime govern access; backend credentials remain outside the agent.",
    ),
    "agent": (
        "04",
        "Agent",
        "Read → assess → propose",
        "The model may request bounded authorized Jira reads and return an unapproved draft. It cannot approve, broaden permissions, or directly create an issue.",
    ),
    "gateway": (
        "05",
        "MCP Gateway",
        "Identity & policy enforcement",
        "The protected path checks user, workload, active run, project, exact arguments and approval before releasing scoped backend access.",
    ),
    "jira": (
        "06",
        "Jira",
        "Verified protected outcome",
        "The trusted adapter performs an authorized operation. The coordinator separately checks the actual issue fields and project count.",
    ),
    "approval": (
        "H",
        "Human approval",
        "Consent for exact fields",
        "Consent binds to the exact proposal digest. Approval does not override user, workload or project permissions.",
    ),
}
STEPS = (
    "Sign in",
    "Sandbox & identity",
    "Assessment",
    "Review & approve",
    "Gateway decision",
    "Jira outcome",
    "Secure cleanup",
)
# index, component, readable title, explanation. Labels describe evidence, not hidden reasoning.
EVENTS = {
    "unknown": (5, "jira", "Write outcome uncertain",
        "Dispatch finished without a verified outcome. Do not repeat the write; trusted reconciliation is required."),
    "dispatch_rejection_reviewed": (5, "jira", "Backend rejection verified",
        "The installer reviewed terminal rejection and no-commit evidence. The original action is failed and cannot be redispatched."),
    "console_recovery_reviewed": (6, "coordinator", "Cleanup reviewed",
        "The trusted operator verified cleanup separately. Original authorization, failure history and single-use identity remain closed."),
    "run_created": (
        0,
        "user",
        "Authenticated run registered",
        "The trusted entrypoint associated this user with the approved workload and project.",
    ),
    "console_queued": (
        1,
        "coordinator",
        "Run queued",
        "The request is recorded; execution waits for the shared lane and readiness checks.",
    ),
    "console_claimed": (
        1,
        "coordinator",
        "Coordinator accepted the run",
        "This coordinator owns execution for this run.",
    ),
    "console_preparing_identity": (
        1,
        "coordinator",
        "Checking run identity",
        "Checking the original approved user and sandbox association.",
    ),
    "console_configuring_gateway": (
        1,
        "gateway",
        "Preparing protected access",
        "Applying the run-scoped routing and identity configuration.",
    ),
    "console_waiting_gateway": (
        1,
        "gateway",
        "Waiting for gateway readiness",
        "Waiting for cluster reconciliation and protected route checks; waiting is not success.",
    ),
    "console_attaching_credentials": (
        1,
        "sandbox",
        "Attaching scoped access",
        "The trusted runtime attaches the run-bound exchange provider to this sandbox.",
    ),
    "console_verifying_native_read": (
        1,
        "gateway",
        "Checking protected delegated access",
        "A protected read is requested before assessment can proceed.",
    ),
    "console_retrying_identity": (
        1,
        "gateway",
        "Retrying a safe identity read",
        "A bounded read-only transport retry; no write is replayed.",
    ),
    "console_identity_verified": (
        1,
        "sandbox",
        "Workload access verified",
        "The native protected delegated read passed for this user and workload.",
    ),
    "console_egress_verified": (
        2,
        "sandbox",
        "Sandbox egress check passed",
        "The recorded agent socket-denial checks passed; trusted runtime traffic has explicit exceptions.",
    ),
    "console_discovering_tools": (
        2,
        "gateway",
        "Discovering governed tools",
        "Reading actual tool registration, schemas and protected routing.",
    ),
    "console_tools_discovered": (
        2,
        "gateway",
        "Governed tools observed",
        "The coordinator observed the available schemas and routing.",
    ),
    "console_assessment_running": (
        2,
        "agent",
        "Assessment started",
        "The selected workload is processing its supplied synthetic input.",
    ),
    "console_model_inference": (
        2,
        "model",
        "Model request in progress",
        "The workload is requesting the approved model. An accepted response is not yet recorded.",
    ),
    "console_agent_reasoning": (
        2,
        "model",
        "Model turn started",
        "Observable model request stage; private chain of thought is neither shown nor recorded here.",
    ),
    "console_agent_read_requested": (
        2,
        "agent",
        "Agent requested Jira context",
        "The model selected a restricted query; the gateway must authorize the read.",
    ),
    "console_agent_query_rejected": (
        2,
        "agent",
        "Query rejected before execution",
        "Local validation rejected unsupported query syntax. No backend request was sent; feedback consumes the existing model turn budget.",
    ),
    "console_checking_project_boundary": (
        2,
        "gateway",
        "Project isolation check requested",
        "A controlled TEST probe uses the OPS run identity; this is a security test, not an autonomous model choice.",
    ),
    "console_project_boundary_verified": (
        2,
        "gateway",
        "Project isolation check passed",
        "The gateway blocked TEST with HTTP 403 and returned no TEST issue data. Authorized OPS work may continue.",
    ),
    "read_allowed": (
        1,
        "gateway",
        "Protected read authorized",
        "The recorded access check allowed this protected read. This grants no write permission.",
    ),
    "console_agent_read_complete": (
        2,
        "agent",
        "Jira context received",
        "A completed governed read returned bounded records for the model to inspect.",
    ),
    "console_agent_read_denied": (
        2,
        "gateway",
        "Agent read denied",
        "The agent received a denial reason instead of protected issue content.",
    ),
    "console_agent_retry": (
        2,
        "model",
        "Safe request retry",
        "A transient model or governed-read transport failure consumed the bounded shared retry budget. No write is retried.",
    ),
    "console_agent_draft_ready": (
        2,
        "agent",
        "Read-informed draft returned",
        "The model returned proposed fields after a permitted read. This is not approval.",
    ),
    "console_draft_validated": (
        2,
        "agent",
        "Draft structure validated",
        "The fields passed structural validation; this does not establish the factual correctness of the recommendation.",
    ),
    "assessment_recorded": (
        2,
        "agent",
        "Assessment recorded",
        "The workload report is retained for this run.",
    ),
    "proposed": (
        2,
        "agent",
        "Exact action proposed",
        "The proposed fields and digest were recorded for review.",
    ),
    "console_awaiting_approval": (
        3,
        "approval",
        "Waiting for your decision",
        "Review the exact fields. Nothing here grants permission to create an issue yet.",
    ),
    "approved": (
        3,
        "approval",
        "Exact proposal approved",
        "The requesting account consented to this proposal digest. Gateway policy still applies.",
    ),
    "console_protected_execution": (
        4,
        "gateway",
        "Protected action requested",
        "Checking user, workload, project, run and exact approval before protected execution.",
    ),
    "authorized": (
        4,
        "gateway",
        "Action authorized",
        "The protected action passed the recorded policy check.",
    ),
    "claimed": (
        4,
        "gateway",
        "Dispatch claimed once",
        "The adapter claimed this action. A claim alone does not prove that Jira committed it.",
    ),
    "succeeded": (
        5,
        "jira",
        "Jira operation succeeded",
        "The adapter recorded the created issue; independent field verification is reported separately.",
    ),
    "denied": (
        4,
        "gateway",
        "Protected request denied",
        "The gateway refused this request. No permission is granted by the refusal.",
    ),
    "revoked": (
        6,
        "coordinator",
        "Run authorization closed",
        "Further access under this run was revoked. A completed write is not undone.",
    ),
    "console_outcome_verified": (
        5,
        "jira",
        "Backend outcome checked",
        "The actual backend result and project count were checked.",
    ),
    "console_restoring_environment": (
        6,
        "coordinator",
        "Secure cleanup in progress",
        "Detaching temporary access and restoring shared routing before another run.",
    ),
    "cancelled": (
        1,
        "coordinator",
        "Cancellation recorded",
        "Further authorization was closed. Any in-flight or completed action still requires outcome reconciliation.",
    ),
    "console_cancelled": (
        1,
        "coordinator",
        "Cancellation processed",
        "The coordinator recorded the stop. Cleanup evidence determines whether the lane is safe.",
    ),
    "console_completed": (
        6,
        "coordinator",
        "Run and cleanup finished",
        "The coordinator recorded completion; inspect outcome and cleanup evidence separately.",
    ),
    "console_execution_failed": (
        1,
        "coordinator",
        "Execution stopped",
        "A protected step could not finish. Check the failure boundary and cleanup status; do not replay a write.",
    ),
    "console_agent_failed": (
        2,
        "agent",
        "Agent could not finish",
        "No valid draft was substituted for the failed agent response.",
    ),
    "console_agent_stopping": (
        2,
        "agent",
        "Agent stopping safely",
        "The agent failed before a valid approvable draft; access is being closed.",
    ),
    "console_inference_failed": (
        2,
        "model",
        "Model request failed",
        "No fallback draft is manufactured when inference is unavailable.",
    ),
}
REASONS = {
    "policy_denied": "The protected request was denied; no further reason was reported.",
    "user_permission": "This user may read, but cannot create Jira issues.",
    "workload_permission": "The reader workload cannot create Jira issues, even for an authorized analyst.",
    "project_permission": "This run does not have access to the requested project.",
    "run_inactive": "The run is closed, cancelled or outside its original authorization window.",
    "approval_required": "Consent for these exact fields has not been recorded.",
    "recovery_required": "Cleanup or a write outcome is uncertain. Operator reconciliation is required.",
    "native_read_failed": "Protected delegated access failed before assessment.",
    "agent_failed": "The agent did not return an accepted draft.",
    "session_expired": "The original authorization deadline passed.",
}


def detail(event: dict) -> dict:
    """Read persisted detail defensively without exposing raw content by default."""
    try:
        value = json.loads(event.get("detail") or "{}")
        return value if isinstance(value, dict) else {}
    except (ValueError, TypeError):
        return {}


def projection(record: dict, job: dict | None, denied: str | None = None) -> dict:
    """Derive business, failure and cleanup states using positive evidence only."""
    run, actions, events = record["run"], record["actions"], record["audit"]
    job = job or {}
    evidence = job.get("evidence", {})
    action = actions[-1] if actions else {}
    state = action.get("state", "pending")
    names = {e["event"] for e in events}
    approved = bool(action) and any(
        e["event"] == "approved" and e.get("action_id") == action.get("id")
        for e in events
    )
    # Compatibility argument is never authority: use only this action’s persisted denial.
    denied = None
    if state not in ("succeeded", "unknown"):
        denied = next(
            (
                (detail(e).get("reason") or "policy_denied")
                for e in reversed(events)
                if e["event"] == "denied"
                and action
                and e.get("action_id") == action.get("id")
            ),
            None,
        )
    terminal = job.get("state") in ("completed", "failed", "interrupted")
    cancelled = "cancelled" in names or job.get("stage") == "cancelled"
    rejected = cancelled and bool(action) and state == "proposed" and not approved
    expired = run["expires"] <= time.time() and not terminal and not cancelled
    cleanup = evidence.get("cleanup_verified") is True and not run["active"]
    verified = (
        state == "succeeded" and evidence.get("backend_fields_match_approval") is True
    )
    done = [
        True,
        bool(evidence.get("native_bound_read")),
        bool(action) or "assessment_recorded" in names,
        approved,
        any(
            e["event"] == "authorized" and e.get("action_id") == action.get("id")
            for e in events
        ),
        verified,
        cleanup,
    ]
    business = [
        e
        for e in events
        if e["event"] in EVENTS
        and EVENTS[e["event"]][0] not in (0, 6)
        and e["event"]
        not in ("console_execution_failed", "console_cancelled", "cancelled")
        and not (
            e["event"] == "denied"
            and (not e.get("action_id") or e.get("action_id") != action.get("id"))
        )
    ]
    current = EVENTS[business[-1]["event"]][0] if business else 1
    stage = job.get("stage", "")
    stage_index = EVENTS.get("console_" + stage, (current,))[0]
    if not terminal and stage_index != 6:
        current = stage_index
    stopped = None
    stop_label = ""
    stop_component = None
    if denied:
        stopped, stop_label, stop_component = 4, "Denied", "gateway"
    elif state == "unknown":
        stopped, stop_label, stop_component = 5, "Uncertain", "jira"
    elif rejected:
        stopped, stop_label, stop_component = 3, "Rejected", "approval"
    elif cancelled and state != "succeeded":
        stopped, stop_label = current, "Cancelled"
        stop_component = (
            EVENTS.get(business[-1]["event"], (1, "coordinator"))[1]
            if business
            else "coordinator"
        )
    elif expired:
        stopped, stop_label, stop_component = current, "Expired", "coordinator"
    elif job.get("state") in ("failed", "interrupted") or stage in (
        "agent_stopping",
        "agent_failed",
        "inference_failed",
    ):
        code = evidence.get("failure_code")
        stopped = (
            1
            if code == "native_read_failed"
            else 2
            if code in ("agent_failed", "inference_failed")
            else 6
            if stage == "restoring_environment" or verified
            else current
        )
        stop_label = "Failed"
        stop_component = (
            "model"
            if code == "inference_failed"
            else "gateway"
            if code == "native_read_failed"
            else "agent"
            if code == "agent_failed"
            else "coordinator"
            if stopped == 6
            else EVENTS[business[-1]["event"]][1]
            if business
            else "coordinator"
        )
    live = (
        not terminal
        and not expired
        and (not cancelled or stage == "restoring_environment")
    )
    statuses = []
    for i in range(7):
        if i == stopped:
            status = stop_label.lower()
        elif stopped is not None and i > stopped and i != 6:
            status = "not-run"
        elif done[i]:
            status = "done"
        elif i == 6 and stage == "restoring_environment" and not terminal:
            status = "active"
        elif terminal or cancelled or expired:
            status = "not-run"
        elif i == current:
            status = (
                "waiting"
                if stage in ("awaiting_approval", "queued", "waiting_gateway")
                else "active"
            )
        else:
            status = "pending"
        statuses.append(status)
    return {
        "statuses": statuses,
        "current": stopped if stopped is not None else current,
        "stop": stopped,
        "stop_label": stop_label,
        "stop_component": stop_component,
        "denied": denied,
        "rejected": rejected,
        "cancelled": cancelled,
        "terminal": terminal,
        "live": live,
        "verified": verified,
        "cleanup": cleanup,
        "evidence": evidence,
        "action": action,
        "unchanged": evidence.get("backend_before") is not None
        and evidence.get("backend_before") == evidence.get("backend_after"),
    }


def progress(record: dict, job: dict | None, denied: str | None) -> str:
    """Render the same semantic states used by the interactive architecture."""
    p = projection(record, job, denied)
    labels = {
        "done": "Completed",
        "active": "Running",
        "waiting": "Waiting",
        "pending": "Pending",
        "not-run": "Not executed",
        "denied": "Denied",
        "failed": "Failed",
        "rejected": "Rejected",
        "cancelled": "Cancelled",
        "expired": "Expired",
        "uncertain": "Uncertain",
    }
    result = '<ol class="steps progress-rail" aria-label="Execution progress">'
    for i, (name, status) in enumerate(zip(STEPS, p["statuses"])):
        mark = (
            "✓"
            if status == "done"
            else "×"
            if status in ("failed", "denied", "uncertain")
            else "−"
            if status in ("cancelled", "rejected", "expired", "not-run")
            else str(i + 1)
        )
        result += (
            '<li class="'
            + status
            + '" data-step="'
            + str(i)
            + '" data-state="'
            + status
            + '"'
            + (' aria-current="step"' if i == p["current"] else "")
            + '><span class="step-dot" aria-hidden="true">'
            + mark
            + "</span><strong>"
            + text(name)
            + '</strong><span class="step-state">'
            + labels[status]
            + "</span></li>"
        )
    return (
        '<div class="progress-sticky" tabindex="0" aria-label="Workflow progress">'
        + result
        + "</ol></div>"
    )


def timeline(events: list[dict], *, raw: bool = True) -> str:
    """Readable component-owned events, with explicit meaning and no empty reasons."""
    rows = ""
    reported_phase = 1
    controlled_probe = False
    for e in events:
        d = detail(e)
        if e["event"] == "console_checking_project_boundary":
            controlled_probe = True
        if (
            e["event"].startswith("console_")
            and e["event"] in EVENTS
            and e["event"] not in ("console_cancelled", "console_execution_failed")
        ):
            reported_phase = EVENTS[e["event"]][0]
        idx, node, title, why = EVENTS.get(
            e["event"],
            (
                1,
                "coordinator",
                "Recorded platform event",
                "Additional event retained in the correlated audit.",
            ),
        )
        if (
            e["event"]
            in (
                "read_allowed",
                "cancelled",
                "console_cancelled",
                "console_execution_failed",
            )
            or e["event"] == "denied"
            and not e.get("action_id")
        ):
            idx = reported_phase
        tone = (
            "denied"
            if e["event"] == "denied" or e["event"] == "console_agent_read_denied"
            else "failed"
            if "failed" in e["event"] or e["event"] in ("unknown", "dispatch_rejection_reviewed")
            else "cancelled"
            if "cancelled" in e["event"]
            else "waiting"
            if "retry" in e["event"] or e["event"] == "console_awaiting_approval"
            else "done"
        )
        reason = REASONS.get(d.get("reason") or d.get("failure_code"))
        if (
            e["event"] == "denied"
            and d.get("reason") == "project_permission"
            and not e.get("action_id")
        ):
            title = "Outside-project request blocked"
            why = (
                "A controlled isolation test was denied. This does not imply the permitted workflow stopped."
                if controlled_probe
                else "The recorded project-access request was denied. Consult adjacent events for its execution context."
            )
        if e["event"] == "console_project_boundary_verified":
            controlled_probe = False
        extras = []
        for key, label in (
            ("agent_turn", "Model turn"),
            ("agent_query", "Requested query"),
            ("jira_query", "Completed query"),
            ("jira_issue_count", "Returned issue count"),
            ("agent_retry_count", "Retry number"),
            ("issue_key", "Issue"),
        ):
            if key in d:
                extras.append(label + ": " + str(d[key]))
        if d.get("cleanup_verified") is True:
            extras.append("Cleanup verified")
        at = datetime.fromtimestamp(e["at"], timezone.utc).strftime("%H:%M:%S UTC")
        rows += (
            '<li class="trace-event '
            + tone
            + '" data-component="'
            + node
            + '"><span class="trace-mark" aria-hidden="true"></span><details data-event="'
            + text(e.get("sequence", str(e["at"]) + e["event"]))
            + '"><summary><span class="trace-time">'
            + text(at)
            + '</span><span class="trace-heading"><b>'
            + title
            + "</b><span>"
            + COMPONENTS[node][1]
            + " · "
            + STEPS[idx]
            + '</span></span><span class="tag '
            + tone
            + '">'
            + (
                "Blocked"
                if tone == "denied"
                else "Stopped"
                if tone == "failed"
                else "Recorded"
            )
            + "</span></summary><p>"
            + text(why + (" " + reason if reason else ""))
            + "</p>"
            + (
                '<p class="small">' + text(" · ".join(extras)) + "</p>"
                if extras
                else ""
            )
            + "</details></li>"
        )
    result = (
        '<ol class="trace-timeline" aria-label="Decision and outcome timeline">'
        + rows
        + "</ol>"
    )
    if raw:
        result += (
            '<details class="raw-audit"><summary>Correlation and technical details</summary><p class="muted small">Original persisted events, in sequence. UTC timestamps; no inferred network packets or hidden model reasoning.</p><pre>'
            + text(json.dumps(events, indent=2))
            + "</pre></details>"
        )
    return result


def response_signals(record: dict, job: dict | None, online: bool) -> str:
    """Render logical response receipts; never infer certificate issuance or rotation.

    Only actual recorded read results, accepted model responses, policy denials,
    write receipts and verified cleanup qualify. JavaScript plays each recent
    receipt once; unchanged polling and old history cannot replay it.
    """
    action = record["actions"][-1] if record["actions"] else {}
    evidence = (job or {}).get("evidence", {})
    latest = {}
    for event in record["audit"]:
        name, values = event["event"], detail(event)
        signal = None
        if name == "console_agent_read_complete":
            signal = (
                "gateway",
                "agent",
                "M665 210 H475",
                "Governed Jira response received",
                "allowed",
            )
        elif (
            name in ("console_agent_read_requested", "console_agent_query_rejected", "console_agent_draft_ready")
            and values.get("model_inference") is True
        ):
            signal = (
                "model",
                "agent",
                "M677 58 V142 H487 V198",
                "Accepted model response received",
                "allowed",
            )
        elif (
            name == "console_project_boundary_verified"
            and values.get("scope_probe_denied") is True
        ):
            signal = (
                "gateway",
                "agent",
                "M665 210 H475",
                "Controlled project denial recorded",
                "blocked",
            )
        elif (
            name == "console_agent_read_denied"
            or name == "denied"
            and action
            and event.get("action_id") == action.get("id")
        ):
            signal = (
                "gateway",
                "agent",
                "M665 210 H475",
                "Policy denial recorded",
                "blocked",
            )
        elif (
            name == "console_identity_verified"
            and evidence.get("native_bound_read") is True
        ):
            signal = (
                "gateway",
                "sandbox",
                "M665 198 V264 H285 V198",
                "Protected delegated read verified",
                "allowed",
            )
        elif (
            name == "succeeded"
            and action.get("state") == "succeeded"
            and event.get("action_id") == action.get("id")
            and values.get("issue_key") == action.get("issue_key")
        ):
            signal = (
                "jira",
                "gateway",
                "M855 210 H665",
                "Jira creation receipt recorded",
                "allowed",
            )
        elif (
            name == "console_completed"
            and values.get("cleanup_verified") is True
            and evidence.get("cleanup_verified") is True
            and not record["run"]["active"]
        ):
            signal = (
                "sandbox",
                "coordinator",
                "M285 210 H95",
                "Temporary access cleanup verified",
                "allowed",
            )
        if signal:
            latest[signal[:2]] = (event, signal)
    result = ""
    now = time.time()
    for event, (src, dst, path, label, outcome) in latest.values():
        sequence = event.get("sequence", str(event["at"]) + event["event"])
        key = f"{record['run']['id']}:{sequence}:{src}-{dst}"
        recent = online and 0 <= now - event["at"] <= 10
        result += (
            f'<path class="response-edge {outcome}" data-response-event="{text(key)}" '
            f'data-response-recent="{str(recent).lower()}" data-from="{src}" '
            f'data-to="{dst}" pathLength="1000" d="{path}">'
            f'<title>{label}</title></path>'
        )
    return result


def architecture(
    record: dict, job: dict | None, coordinator: dict, workflow: str
) -> str:
    """Show logical communication paths; only supported observations become green."""
    p = projection(record, job)
    e = p["evidence"]
    action = p["action"]
    events = record["audit"]
    names = {v["event"] for v in events}
    stage = (job or {}).get("stage", "")
    states = {k: "pending" for k in COMPONENTS}
    states["user"] = states["keycloak"] = "done"
    states["coordinator"] = (
        "done"
        if p["cleanup"]
        else "active"
        if "console_claimed" in names
        else "waiting"
    )
    states["sandbox"] = (
        "done"
        if e.get("native_bound_read")
        else "active"
        if "console_preparing_identity" in names
        else "pending"
    )
    states["spire"] = "done" if e.get("native_bound_read") else "pending"
    states["agent"] = p["statuses"][2]
    states["approval"] = p["statuses"][3]
    states["gateway"] = (
        p["statuses"][4]
        if p["statuses"][4] != "pending"
        else "done"
        if e.get("native_bound_read")
        else "active"
        if "console_configuring_gateway" in names
        else "pending"
    )
    states["jira"] = p["statuses"][5]
    states["model"] = (
        "done"
        if e.get("model_inference")
        else "active"
        if stage in ("agent_reasoning", "model_inference", "agent_retry")
        else "pending"
    )
    current_component = EVENTS.get("console_" + stage, (1, "coordinator"))[1]
    if (
        p["live"]
        and stage not in ("completed", "outcome_verified")
        and not (stage == "awaiting_approval" and p["statuses"][3] == "done")
    ):
        states[current_component] = (
            "waiting" if stage in ("awaiting_approval", "waiting_gateway") else "active"
        )
    if stage == "agent_read_denied":
        states["gateway"] = "denied"
    if workflow == "cve":
        states["model"] = "not-run"
    if p["stop_component"]:
        states[p["stop_component"]] = p["stop_label"].lower()
    online = not coordinator.get("enabled") or coordinator.get("online", False)
    live = p["live"] and online
    if not live:
        states = {
            k: (
                "waiting"
                if v == "active" and not p["terminal"]
                else "not-run"
                if v == "active"
                else v
            )
            for k, v in states.items()
        }
    status_labels = {
        "done": "Observed",
        "active": "Processing",
        "waiting": "Waiting",
        "pending": "Not observed",
        "not-run": "Not executed",
        "denied": "Denied",
        "failed": "Failed",
        "cancelled": "Cancelled",
        "rejected": "Rejected",
        "expired": "Expired",
        "uncertain": "Uncertain",
    }
    notes = {
        "user": "Authenticated role: " + str(record["run"]["user_role"]),
        "keycloak": "Authenticated session recorded. Token exchange is corroborated by the protected delegated read."
        if e.get("native_bound_read")
        else "User authentication recorded. Token exchange not yet verified.",
        "spire": "Attested workload verified in a protected read."
        if e.get("native_bound_read")
        else "Workload registered. Protected access not yet observed.",
        "sandbox": "Socket-denial checks passed."
        if e.get("egress_denied")
        else "Live socket-denial evidence not reported.",
        "model": "Actual model response observed."
        if e.get("model_inference")
        else "Frozen CVE assessment; no model request."
        if workflow == "cve"
        else "No accepted model response reported yet.",
        "agent": str(e.get("agent_read_count", 0))
        + " completed model-directed reads; turn "
        + str(e.get("agent_turn", 0))
        + " of 4."
        if workflow != "cve"
        else "Frozen synthetic CVE report, not a live vulnerability scan.",
        "gateway": REASONS.get(
            p["denied"],
            "User ∩ workload ∩ project ∩ exact approval. Only recorded decisions are shown.",
        ),
        "approval": "Consent recorded for the exact digest."
        if p["statuses"][3] == "done"
        else "No permission is granted by a draft.",
        "jira": "Write outcome uncertain; operator reconciliation is required."
        if action.get("state") == "unknown"
        else "Issue fields independently verified."
        if p["verified"]
        else "No backend change verified (count unchanged)."
        if p["unchanged"]
        else "No independently verified backend outcome yet.",
        "coordinator": "Cleanup verified; temporary access detached."
        if p["cleanup"]
        else "Temporary access is still active or cleanup is not yet verified.",
    }
    edges = [
        ("user", "keycloak", "M95 58 H285"),
        ("user", "coordinator", "M95 58 V198"),
        ("coordinator", "sandbox", "M95 198 H285"),
        ("sandbox", "spire", "M285 198 V122 H475 V58"),
        ("sandbox", "agent", "M285 198 H475"),
        ("sandbox", "keycloak", "M285 198 V58"),
        ("agent", "model", "M475 198 V134 H665 V58"),
        ("agent", "gateway", "M475 198 H665"),
        ("user", "approval", "M95 58 H5 V338 H665"),
        ("approval", "gateway", "M665 338 V198"),
        ("gateway", "jira", "M665 198 H855"),
    ]
    observed_edges = {("user", "keycloak")}
    if "console_queued" in names:
        observed_edges.add(("user", "coordinator"))
    if e.get("native_bound_read"):
        observed_edges.update({("coordinator", "sandbox"), ("sandbox", "spire"),
                               ("sandbox", "keycloak"), ("sandbox", "agent"),
                               ("agent", "gateway")})
    if e.get("model_inference"):
        observed_edges.add(("agent", "model"))
    if p["statuses"][3] == "done":
        observed_edges.update({("user", "approval"), ("approval", "gateway")})
    if action.get("state") == "succeeded":
        observed_edges.add(("gateway", "jira"))
    active_stages = {
        ("agent", "gateway"): ("verifying_native_read", "agent_read_requested", "protected_execution"),
        ("agent", "model"): ("agent_reasoning", "model_inference"),
        ("coordinator", "sandbox"): ("preparing_identity",),
    }
    if p["statuses"][3] == "done":
        active_stages[("approval", "gateway")] = ("protected_execution",)
    paths = ""
    for src, dst, path in edges:
        observed = (src, dst) in observed_edges
        active = live and stage in active_stages.get((src, dst), ())
        css = "edge observed" if observed else "edge"
        if active:
            css += " transmitting"
        if dst == p["stop_component"]:
            css += " blocked"
        direction = "v" if path.rfind("V") > path.rfind("H") else "h"
        paths += (f'<path data-from="{src}" data-to="{dst}" '
                  f'marker-end="url(#flow-arrow-{direction})" class="{css}" d="{path}" />')
    nodes = ""
    for key, (icon, title, subtitle, _) in COMPONENTS.items():
        state = states[key]
        nodes += (
            f'<button type="button" class="flow-node {state}" data-node="{key}" '
            f'aria-controls="inspector-{key}" aria-pressed="false">'
            f'<span class="node-icon" aria-hidden="true">{icon}</span>'
            f'<span class="node-name">{title}</span><span class="node-subtitle">{subtitle}</span>'
            f'<span class="node-status"><i aria-hidden="true"></i>{status_labels[state]}</span></button>'
        )
    panels = ""
    for key, (_, title, _, why) in COMPONENTS.items():
        panels += (
            f'<section class="node-inspector" id="inspector-{key}" data-inspector="{key}" hidden>'
            f'<span class="eyebrow">Component evidence</span><h3>{title}</h3><p>{why}</p>'
            f'<div class="inspector-fact">{text(notes[key])}</div>'
        )
        if key == "spire":
            panels += (
                '<p class="identity">'
                + text(record["run"]["workload"])
                + '</p><p class="small muted">Certificate/key bytes are never displayed. Issuance, expiry and rotation events are not available in this run stream.</p>'
            )
        if key == "gateway":
            panels += '<p class="small">Observed tools: ' + text(", ".join(e.get("tool_names", [])) or "Not yet reported") + "</p>"
        panels += "</section>"
    label = (
        "Recorded trace"
        if p["terminal"]
        else "Live trace"
        if online
        else "Connection unavailable"
    )
    return (
        '<section class="architecture card" id="architecture" data-trace-live="'
        + ("true" if live else "false")
        + '"><div class="card-head"><div><span class="eyebrow">Identity → investigation → controlled action</span><h2>Security in motion</h2><p class="muted small">Follow the protected path. Select a component to inspect its role and evidence.</p></div><div class="links"><span class="tag active">'
        + label
        + '</span><button type="button" class="small" data-motion-toggle aria-pressed="false">Pause motion</button></div></div><div class="flow-scroll"><div class="flow-map"><svg class="flow-links" viewBox="0 0 950 396" aria-hidden="true"><defs><marker id="flow-arrow-h" viewBox="0 0 10 10" refX="105" refY="5" markerWidth="5" markerHeight="5" orient="auto"><path d="M0 0 L10 5 L0 10" fill="#8fa5c3"/></marker><marker id="flow-arrow-v" viewBox="0 0 10 10" refX="72" refY="5" markerWidth="5" markerHeight="5" orient="auto"><path d="M0 0 L10 5 L0 10" fill="#8fa5c3"/></marker></defs>'
        + paths
        + response_signals(record, job, online)
        + "</svg>"
        + nodes
        + '</div></div><div class="flow-legend"><span><i class="legend-dot done"></i>Observed</span><span><i class="legend-dot active"></i>In progress</span><span><i class="legend-dot denied"></i>Blocked / failed</span><span><i class="legend-dot pending"></i>Not observed</span></div><p class="small muted">Logical architecture—not a packet capture. Dashed blue paths indicate recorded request stages; green or red arrivals indicate observed responses. Unobserved certificate issuance and rotation are never animated.</p><div class="inspector-placeholder">Select any component above to explore its security boundary.</div>'
        + panels
        + "</section>"
    )


def input_context(workflow: str, *, scenario_version: str | None = None) -> str:
    """Explain the selected actual fixture without inventing vulnerability facts."""
    if workflow == "cve":
        return '<details class="card input-context"><summary><span class="eyebrow">Investigation input</span><strong>CVE-2099-0001 · Synthetic vulnerability</strong><span>View the supplied context</span></summary><p>A frozen, repeatable CVE fixture in the reviewed workload image. Supplied package: <strong>example-lib 1.2.3</strong>. Frozen assessment: package present and reachable; actionable finding. This is synthetic input, not a published vulnerability. No live vulnerability scan, CVSS verification, exploit lookup or remediation is performed.</p><p>The workload produces an assessment and proposed Jira fields. Review the actual assessment below; its content does not grant execution permission.</p></details>'
    incident = workflow == "incident-triage"
    return (
        '<details class="card input-context"><summary><span class="eyebrow">Investigation input</span><strong>'
        + (
            "OPS-0001 · Checkout timeouts"
            if incident
            else "SERVICE-0001 · Remediation change request" if scenario_version == "remediation-v1" else "SERVICE-0001 · Training workspace"
        )
        + "</strong><span>View the supplied context</span></summary><p>"
        + (
            "Synthetic checkout timeouts after a deployment. The agent reads authorized OPS records, distinguishes observations from hypotheses and drafts an investigation task. No application logs or live service metrics are inspected."
            if incident
            else "Supplied frozen CVE-2099-0001 affects example-lib 1.2.3 in a synthetic training checkout service. Candidate 1.2.4 is supplied for review, not a verified fix. The agent reads SERVICE change records and drafts a plan covering scope, proposed change, tests, a proposed window, rollback and acceptance criteria. No patch, scan or test is executed; this is an independent supplied fixture, not an automatic handoff from a CVE run." if scenario_version == "remediation-v1" else "A temporary read-only training workspace using synthetic records. The agent inspects SERVICE tasks before drafting a proposed task. This is the retained earlier scenario."
        )
        + "</p><p>The model can perform bounded reads and draft text. The workflow supports a proposed create, not autonomous remediation, issue updates or a no-action decision.</p></details>"
    )


STYLE = (Path(__file__).parent / "console.css").read_text()

STYLE += "\nmain[data-connection=unavailable] .edge, main[data-connection=unavailable] .active .node-status i{animation:none!important}\n"

STYLE += """
.assessment-placeholder{margin:16px 0;color:var(--muted);font-size:12px}.assessment-placeholder span{display:block;height:10px;border-radius:6px;margin:10px 0;background:linear-gradient(90deg,#edf1f7,#f8faff,#edf1f7);background-size:200% 100%;animation:skeleton 2s linear infinite}.assessment-placeholder span:nth-of-type(2){width:85%}.assessment-placeholder span:nth-of-type(3){width:65%}@keyframes skeleton{to{background-position:-200% 0}}
"""

STYLE += """
.node-subtitle{font-size:10px;color:#596b83}.node-status{font-size:10px}.execution-status{padding:13px 18px}.execution-status .card-head{margin-bottom:5px}.execution-status h2{font-size:17px}.execution-status p{margin:5px 0;font-size:12px}.execution-status p.small{font-size:10px}
"""

STYLE += "\n.architecture,#security-context,#decision-audit{scroll-margin-top:110px}\n"

STYLE += """
.topbar{position:relative;z-index:30}
.account{gap:8px}
.account-menu{position:relative}
.account-menu>summary{display:flex;align-items:center;gap:9px;list-style:none;cursor:pointer;padding:5px 9px 5px 5px;border:1px solid transparent;border-radius:999px;color:#263954;transition:background .15s,border-color .15s,box-shadow .15s}
.account-menu>summary::-webkit-details-marker{display:none}
.account-menu>summary:hover,.account-menu[open]>summary{background:#f4f6fb;border-color:#e0e5ef}
.account-menu>summary:focus-visible{outline:3px solid #6588ff;outline-offset:3px}
.account-menu .avatar{flex:none;width:34px;height:34px;background:linear-gradient(145deg,#e7edff,#d7e0ff);color:#3658bc;box-shadow:inset 0 0 0 1px #d3dcfb}
.account-name{font-size:13px;font-weight:650;max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.account-chevron{width:8px;height:8px;border-right:1.7px solid #66758b;border-bottom:1.7px solid #66758b;transform:rotate(45deg);margin:0 2px 4px 3px;transition:transform .15s}
.account-menu[open] .account-chevron{transform:rotate(225deg);margin-bottom:-3px}
.account-panel{position:absolute;top:calc(100% + 11px);right:0;z-index:80;width:min(340px,calc(100vw - 24px));padding:10px;background:#fff;border:1px solid #dfe5ef;border-radius:16px;box-shadow:0 16px 42px #10203c24;animation:account-enter .14s ease-out}
.account-panel-heading{display:flex;align-items:center;gap:12px;padding:8px 9px 14px;border-bottom:1px solid #edf0f5}
.account-panel-avatar{flex:none;width:40px;height:40px;font-size:15px;background:linear-gradient(145deg,#e7edff,#d7e0ff);color:#3658bc;box-shadow:inset 0 0 0 1px #d3dcfb}
.account-panel-identity{display:grid;gap:3px;min-width:0}
.account-panel-label{color:#73819a;text-transform:uppercase;letter-spacing:1.1px;font-size:9px;font-weight:750}
.account-panel-heading strong{font-size:15px;color:#243752;overflow-wrap:anywhere}
.account-session{display:grid;gap:9px;margin:12px 2px;padding:14px;border:1px solid #e4eaf5;border-radius:12px;background:linear-gradient(145deg,#f8faff,#f3f6fc)}
.account-session-heading{display:flex;align-items:center;justify-content:space-between;gap:10px}
.account-session-label{font-size:11px;font-weight:700;color:#4a5d79}
.account-session-state{display:inline-flex;align-items:center;gap:6px;padding:4px 8px;border:1px solid #cce7d8;border-radius:999px;background:#eff9f3;color:#24734d;font-size:10px;font-weight:700;white-space:nowrap}
.account-session-dot{width:6px;height:6px;border-radius:50%;background:#2c9a62;box-shadow:0 0 0 3px #2c9a621a}
.account-session-state.expired{border-color:#f0cbd2;background:#fff3f5;color:#a52e47}
.account-session-state.expired .account-session-dot{background:#c1435b;box-shadow:0 0 0 3px #c1435b1a}
.account-session-time{display:block;color:#223752;font-size:22px;font-weight:750;line-height:1.2;letter-spacing:-.5px;font-variant-numeric:tabular-nums}
.account-session-note{color:#687991;font-size:11px;line-height:1.45}
.account-actions{display:grid;grid-template-columns:1fr 1fr;gap:8px;padding:8px;border-top:1px solid #edf0f5}
.account-actions form{margin:0}
.account-action{display:flex;align-items:center;justify-content:center;min-height:40px;width:100%;padding:9px 11px;border:1px solid #dce3ed;border-radius:9px;background:#fff;color:#2e4f98;font-size:12px;font-weight:650;text-align:center;white-space:nowrap}
.account-action:hover{background:#f4f6fb;border-color:#b8c7e2;text-decoration:none}
.account-actions .account-signout{color:#a52e47;cursor:pointer}
.account-session,.account-panel-heading{overflow-wrap:anywhere}
.readiness{display:flex;align-items:center;gap:12px;padding:13px 15px;border:1px solid var(--line);border-radius:11px;background:#fff}
.readiness p{margin:4px 0 0;color:var(--muted);font-size:12px}
@keyframes account-enter{from{opacity:.6;transform:translateY(-3px)}to{opacity:1;transform:none}}
@media(max-width:480px){.account-name{max-width:95px}.account-menu>summary{gap:6px;padding-right:6px}.account-panel{right:-2px}}
@media(prefers-reduced-motion:reduce){.account-panel{animation:none}}
"""

STYLE += "\n.connection:not([hidden])~#live-content *{animation-play-state:paused!important}.execution-status.rejected,.execution-status.cancelled{border-left-color:#8760b4}\n"

STYLE += """
.response-edge{fill:none;stroke:#25856b;stroke-width:1.5;stroke-dasharray:2 8;opacity:.35}.response-edge.blocked{stroke:#bb3c55}.response-edge.arriving{opacity:1;stroke-width:3;stroke-dasharray:15 985;animation:response-arrival 1.5s linear 1 both}@keyframes response-arrival{from{stroke-dashoffset:0;opacity:1}90%{opacity:1}to{stroke-dashoffset:-1000;opacity:0}}
"""

STYLE += """
.node-status,.node-subtitle,.trace-time,.trace-heading>span,.flow-legend{color:#586b83}.eyebrow{color:#536c92}.flow-node.not-run{color:#586b83}.steps .not-run{opacity:1}.steps .step-state{color:#586b83}.steps .not-run .step-dot{background:#f4f6fa;color:#586b83}
"""


# Keep the observed security check visually separate from the business outcome.
STYLE += """
.scope-check,.jira-result{margin:18px 0;padding:20px;border:1px solid;border-radius:12px;min-width:0}
.scope-check{background:#f7f9fd;border-color:#dfe6f1}
.outcome-heading{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap}
.outcome-heading .tag{flex-shrink:0}.outcome-title{display:block;font-size:15px;line-height:1.45}
.scope-check p,.jira-result p{margin:10px 0 0;color:#52647c;line-height:1.65;max-width:72ch}
.jira-result{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:center;gap:22px;background:#f2faf6;border-color:#c9e3d5}
.jira-result .eyebrow{color:#23694f}.jira-result .result-key{font-size:23px;line-height:1.35;overflow-wrap:anywhere}
.jira-result-action{display:flex;flex-direction:column;align-items:stretch;gap:8px;text-align:center;max-width:180px}
.jira-result-action .button{white-space:nowrap}.jira-result-action .small{font-size:10px;line-height:1.5}
@media(max-width:800px){.scope-check,.jira-result{padding:16px}.jira-result{grid-template-columns:minmax(0,1fr);gap:16px}.jira-result-action{align-items:flex-start;max-width:none;text-align:left}.jira-result .result-key{font-size:21px}}
"""


STYLE += """
.workflow-preview{margin:16px 0;padding:15px 16px;background:#f6f8fc;border:1px solid #e1e7f1;border-radius:10px}.workflow-preview ol{margin:9px 0 12px;padding-left:21px;display:grid;gap:8px;color:#304761;font-size:12px}.workflow-preview li::marker{color:#5774bf;font-weight:700}.workflow-preview p:last-child{margin-bottom:0}.workflow-grid>.card{display:flex;flex-direction:column}.workflow-grid>.card>form{margin-top:auto}.workflow-grid>.card>form>.primary{width:100%}
"""

STYLE += """
.workflow-cards{grid-template-columns:repeat(3,minmax(0,1fr))}
@media(max-width:1280px){.workflow-cards{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:900px){.workflow-cards{grid-template-columns:1fr}}
"""
