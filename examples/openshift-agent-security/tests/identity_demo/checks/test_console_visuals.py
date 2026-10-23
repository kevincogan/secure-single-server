# SPDX-License-Identifier: Apache-2.0
"""Behavioral rendering checks: evidence is not authorization or inferred success."""

from __future__ import annotations

import json
import time
from copy import deepcopy

import pytest

import identity_demo_console as console
import identity_demo_console_visuals as visual


def scenario() -> tuple[dict, dict]:
    """Construct synthetic persisted state, never a live acceptance receipt."""
    now = int(time.time())
    record = {
        "run": {
            "id": "visual-fixture",
            "user_role": "analyst",
            "workload_role": "triage",
            "project": "TEST",
            "workload": "spiffe://example.test/sandbox/fixture",
            "active": 1,
            "expires": now + 600,
            "assessment": "Assessment pending workload execution.",
        },
        "actions": [],
        "audit": [],
    }
    job = {
        "state": "running",
        "stage": "preparing_identity",
        "updated": now,
        "evidence": {},
    }
    add(record, "run_created")
    add(record, "console_claimed")
    return record, job


def add(
    record: dict, name: str, values: dict | None = None, action: str | None = None
) -> None:
    """Append one synthetic authoritative event in sequence."""
    record["audit"].append(
        {
            "sequence": len(record["audit"]) + 1,
            "at": int(time.time()),
            "event": name,
            "action_id": action,
            "detail": json.dumps(values or {}),
        }
    )


def proposed(record: dict, job: dict) -> None:
    """Advance only the evidence that the producer would actually report."""
    record["actions"] = [
        {
            "id": "action-fixture",
            "state": "proposed",
            "payload": json.dumps(
                {
                    "project": "TEST",
                    "summary": "Review synthetic evidence",
                    "description": "No production data.",
                }
            ),
            "digest": "fixture-digest",
            "issue_key": None,
        }
    ]
    job["evidence"]["native_bound_read"] = True
    job["stage"] = "awaiting_approval"
    add(record, "console_awaiting_approval")


@pytest.mark.parametrize(
    "reason", ["user_permission", "workload_permission", "project_permission"]
)
def test_denial_is_red_at_gateway_and_jira_is_not_a_success(reason: str) -> None:
    r, j = scenario()
    proposed(r, j)
    add(r, "approved", action="action-fixture")
    add(r, "denied", {"reason": reason}, "action-fixture")
    r["run"]["active"] = 0
    j.update(state="completed", stage="completed")
    j["evidence"].update(cleanup_verified=True, backend_before=4, backend_after=4)
    p = visual.projection(r, j)
    assert p["statuses"] == [
        "done",
        "done",
        "done",
        "done",
        "denied",
        "not-run",
        "done",
    ]
    html = visual.architecture(r, j, {"enabled": True, "online": True}, "cve")
    assert 'flow-node denied" data-node="gateway"' in html
    assert 'flow-node not-run" data-node="jira"' in html
    assert "transmitting" not in html
    page, _ = console.run_page(r, "csrf-fixture", {"workflow": "cve"}, j)
    assert (
        "Action blocked at MCP Gateway" in page and "verified count unchanged" in page
    )


def test_controlled_probe_does_not_stop_the_authorized_workflow() -> None:
    r, j = scenario()
    j["stage"] = "agent_read_complete"
    j["evidence"].update(native_bound_read=True, scope_probe_denied=True)
    add(r, "console_agent_read_requested")
    add(r, "console_checking_project_boundary")
    add(r, "denied", {"reason": "project_permission"})
    add(r, "console_project_boundary_verified")
    add(r, "console_agent_read_complete")
    p = visual.projection(r, j)
    assert p["denied"] is None and p["stop"] is None and p["current"] == 2
    assert "controlled isolation test" in visual.timeline(r["audit"])


def test_local_query_rejection_is_agent_feedback_not_a_gateway_denial() -> None:
    r, j = scenario()
    j["stage"] = "agent_query_rejected"
    j["evidence"].update(native_bound_read=True)
    add(r, "console_agent_query_rejected", {"agent_turn": 2, "agent_error_category": "invalid_jql"})
    view = visual.projection(r, j)
    assert view["denied"] is None and view["stop"] is None and view["current"] == 2
    html = visual.timeline(r["audit"])
    assert "Query rejected before execution" in html and "No backend request was sent" in html
    activity = console.activity_view(r["audit"], j)
    assert "Query rejected before execution" in activity and "Turn 2 of 4" in activity
    assert "project_permission" not in activity


def test_human_rejection_stops_at_approval_without_green_gateway_or_jira() -> None:
    r, j = scenario()
    proposed(r, j)
    add(r, "cancelled")
    add(r, "console_cancelled")
    r["run"]["active"] = 0
    j.update(state="completed", stage="cancelled")
    j["evidence"]["cleanup_verified"] = True
    assert visual.projection(r, j)["statuses"] == [
        "done",
        "done",
        "done",
        "rejected",
        "not-run",
        "not-run",
        "done",
    ]
    page, _ = console.run_page(r, "csrf-fixture", {"workflow": "cve"}, j)
    assert "Proposal rejected by the user" in page


def test_queued_cancellation_has_no_unobserved_identity_or_assessment_success() -> None:
    r, j = scenario()
    r["audit"] = r["audit"][:1]
    add(r, "console_queued")
    add(r, "cancelled")
    r["run"]["active"] = 0
    j.update(state="completed", stage="cancelled")
    j["evidence"]["cleanup_verified"] = True
    assert visual.projection(r, j)["statuses"] == [
        "done",
        "cancelled",
        "not-run",
        "not-run",
        "not-run",
        "not-run",
        "done",
    ]


@pytest.mark.parametrize(
    "code,index",
    [("native_read_failed", 1), ("agent_failed", 2), ("inference_failed", 2)],
)
def test_failure_uses_original_boundary_not_final_cleanup_stage(
    code: str, index: int
) -> None:
    r, j = scenario()
    add(
        r,
        "console_assessment_running" if index == 2 else "console_verifying_native_read",
    )
    add(r, "console_execution_failed")
    r["run"]["active"] = 0
    j.update(state="failed", stage="execution_failed")
    j["evidence"].update(failure_code=code, cleanup_verified=True)
    p = visual.projection(r, j)
    assert (
        p["stop"] == index
        and p["statuses"][index] == "failed"
        and p["statuses"][6] == "done"
    )
    assert all(s == "not-run" for s in p["statuses"][index + 1 : 6])


def test_success_requires_independent_verification_and_cleanup_is_separate() -> None:
    r, j = scenario()
    proposed(r, j)
    r["actions"][0].update(state="succeeded", issue_key="TEST-1")
    add(r, "approved", action="action-fixture")
    add(r, "authorized", action="action-fixture")
    add(r, "succeeded", {"issue_key": "TEST-1"}, "action-fixture")
    j["stage"] = "restoring_environment"
    r["run"]["active"] = 0
    assert visual.projection(r, j)["statuses"][5] != "done"
    j["evidence"]["backend_fields_match_approval"] = True
    assert visual.projection(r, j)["statuses"][5] == "done"
    assert visual.projection(r, j)["statuses"][6] == "active"
    j["evidence"]["cleanup_verified"] = True
    j.update(state="completed", stage="completed")
    assert visual.projection(r, j)["statuses"] == ["done"] * 7


def test_unknown_write_never_claims_unchanged_backend_or_retries() -> None:
    r, j = scenario()
    proposed(r, j)
    r["actions"][0]["state"] = "unknown"
    j.update(state="failed", stage="execution_failed")
    assert visual.projection(r, j)["statuses"][5] == "uncertain"
    page, _ = console.run_page(r, "csrf-fixture", {"workflow": "cve"}, j)
    assert "Outcome uncertain" in page and "unchanged (verified)" not in page


def test_disconnect_freezes_motion_and_recovery_preserves_original_deadline() -> None:
    r, j = scenario()
    j["stage"] = "agent_reasoning"
    add(r, "console_agent_reasoning")
    original = deepcopy(r)
    disconnected = visual.architecture(
        r, j, {"enabled": True, "online": False}, "incident-triage"
    )
    assert (
        'data-trace-live="false"' in disconnected and "transmitting" not in disconnected
    )
    recovered = visual.architecture(
        r, j, {"enabled": True, "online": True}, "incident-triage"
    )
    assert 'data-trace-live="true"' in recovered and "transmitting" in recovered
    assert r == original


def test_no_certificate_or_model_success_is_inferred_from_configuration() -> None:
    r, j = scenario()
    html = visual.architecture(
        r, j, {"enabled": True, "online": True}, "incident-triage"
    )
    assert 'flow-node pending" data-node="spire"' in html
    assert 'flow-node pending" data-node="model"' in html
    assert "issuance" in html.lower() and "rotation" in html.lower()
    assert "Certificate/key bytes are never displayed" in html


def test_audit_explains_components_without_empty_reason_columns_or_duplicate_json() -> (
    None
):
    r, j = scenario()
    add(r, "cancelled")
    add(r, "denied", {"reason": "user_permission"}, "a")
    html = visual.timeline(r["audit"])
    assert "Coordinator" in html and "MCP Gateway" in html
    assert "This user may read, but cannot create Jira issues." in html
    assert "<table" not in html and html.count("<pre>") == 1
    assert "Cancellation recorded" in html


def test_untrusted_input_and_unknown_event_details_cannot_inject_markup() -> None:
    r, j = scenario()
    r["run"]["workload"] = "<script>secret()</script>"
    j["evidence"]["tool_names"] = ["<img src=x onerror=steal()>"]
    add(r, "unknown_event", {"reason": "<script>boom()</script>"})
    html = visual.architecture(r, j, {}, "cve") + visual.timeline(r["audit"])
    assert "<script>" not in html and "<img" not in html
    assert "&lt;script&gt;" in html


def test_accessibility_and_motion_controls_preserve_navigation() -> None:
    r, j = scenario()
    html = console.shell(
        console.run_page(r, "csrf", {}, j)[0],
        live_url="/runs/fixture/live",
        presentation=True,
    )
    assert "prefers-reduced-motion:reduce" in html and "data-motion-toggle" in html
    assert 'aria-controls="inspector-spire"' in html and 'aria-current="step"' in html
    assert "Presentation mode" not in html and 'class="presentation"' not in html
    assert "Main navigation" in html and "Pause motion" in html
    assert "selectedNode" in console.LIVE_SCRIPT and "setNotice" in console.LIVE_SCRIPT


@pytest.mark.parametrize(
    "stage,expected",
    [
        ("verifying_native_read", {("agent", "gateway")}),
        ("agent_read_requested", {("agent", "gateway")}),
        ("agent_reasoning", {("agent", "model")}),
        ("preparing_identity", {("coordinator", "sandbox")}),
    ],
)
def test_motion_only_marks_the_current_requested_path(
    stage: str, expected: set
) -> None:
    """A pending identity read must never animate a nonexistent approval request."""
    from html.parser import HTMLParser

    class Paths(HTMLParser):
        def __init__(self) -> None:
            super().__init__()
            self.active = set()

        def handle_starttag(self, tag: str, attrs: list) -> None:
            values = dict(attrs)
            if tag == "path" and "transmitting" in values.get("class", ""):
                self.active.add((values["data-from"], values["data-to"]))

    r, j = scenario()
    j["stage"] = stage
    parser = Paths()
    parser.feed(
        visual.architecture(r, j, {"enabled": True, "online": True}, "incident-triage")
    )
    assert parser.active == expected


def test_cleanup_failure_does_not_erase_a_verified_jira_outcome() -> None:
    r, j = scenario()
    proposed(r, j)
    r["actions"][0].update(state="succeeded", issue_key="TEST-1")
    for name in ("approved", "authorized", "succeeded"):
        add(r, name, action="action-fixture")
    r["run"]["active"] = 0
    j.update(state="failed", stage="execution_failed")
    j["evidence"].update(
        backend_fields_match_approval=True, failure_code="recovery_required"
    )
    p = visual.projection(r, j)
    assert p["statuses"] == ["done", "done", "done", "done", "done", "done", "failed"]
    assert p["stop_component"] == "coordinator"


def test_evidence_page_groups_actual_controls_without_duplicating_run_table() -> None:
    row = {"id": "owned-run"}
    html = console.evidence_view(
        [(row, {"evidence": {"native_bound_read": True, "cleanup_verified": True}})]
    )
    assert "Certificate-bound access" in html and "1 observed runs" in html
    assert "No positive receipt" in html and "#security-context" in html
    assert "<table" not in html and "Browse your run history" in html


def test_uncertain_setup_failure_does_not_blame_an_unobserved_gateway() -> None:
    r, j = scenario()
    add(r, "console_execution_failed", {"failure_code": "recovery_required"})
    r["run"]["active"] = 0
    j.update(state="failed", stage="execution_failed")
    j["evidence"]["failure_code"] = "recovery_required"
    p = visual.projection(r, j)
    assert p["stop"] == 1 and p["stop_component"] == "coordinator"
    html = visual.architecture(r, j, {"enabled": True, "online": True}, "cve")
    assert 'flow-node failed" data-node="coordinator"' in html
    assert 'flow-node failed" data-node="gateway"' not in html


def test_audit_places_governed_reads_in_their_observed_stage() -> None:
    r, j = scenario()
    add(r, "console_agent_read_requested")
    add(r, "read_allowed", {"reason": "project_read"})
    html = visual.timeline(r["audit"], raw=False)
    assert "Protected read authorized</b><span>MCP Gateway · Assessment" in html


def test_unrelated_project_denial_is_not_invented_as_a_controlled_probe() -> None:
    r, j = scenario()
    add(r, "denied", {"reason": "project_permission"})
    html = visual.timeline(r["audit"], raw=False)
    assert "controlled isolation test" not in html and "request was denied" in html


def test_response_signals_require_accepted_model_or_completed_read_events() -> None:
    r, j = scenario()
    j["evidence"]["model_inference"] = True
    add(r, "console_agent_read_requested", {"agent_turn": 1})
    assert visual.response_signals(r, j, True) == ""
    add(r, "console_agent_read_requested", {"model_inference": True, "agent_turn": 1})
    html = visual.response_signals(r, j, True)
    assert 'data-from="model" data-to="agent"' in html
    assert 'data-from="gateway"' not in html
    add(r, "console_agent_read_complete", {"jira_issue_count": 2})
    html = visual.response_signals(r, j, True)
    assert 'data-from="gateway" data-to="agent"' in html
    assert 'data-response-recent="true"' in html


def test_unverified_certificate_or_cleanup_configuration_creates_no_response() -> None:
    r, j = scenario()
    add(r, "console_identity_verified")
    add(r, "console_completed", {"cleanup_verified": True})
    assert visual.response_signals(r, j, True) == ""
    j["evidence"].update(native_bound_read=True, cleanup_verified=True)
    html = visual.response_signals(r, j, True)
    assert "Certificate-bound read verified" in html
    assert "Temporary access cleanup verified" not in html
    r["run"]["active"] = 0
    assert "Temporary access cleanup verified" in visual.response_signals(r, j, True)


def test_recorded_responses_do_not_reanimate_old_history_or_disconnected_state() -> (
    None
):
    r, j = scenario()
    add(r, "console_agent_read_complete")
    r["audit"][-1]["at"] -= 30
    assert 'data-response-recent="false"' in visual.response_signals(r, j, True)
    r["audit"][-1]["at"] = int(time.time())
    assert 'data-response-recent="false"' in visual.response_signals(r, j, False)
    r["audit"][-1]["at"] += 30
    assert 'data-response-recent="false"' in visual.response_signals(r, j, True)


def test_latest_reply_on_a_path_replaces_old_denial_without_replaying_it() -> None:
    r, j = scenario()
    add(r, "console_project_boundary_verified", {"scope_probe_denied": True})
    assert "Controlled project denial" in visual.response_signals(r, j, True)
    add(r, "console_agent_read_complete", {"jira_issue_count": 2})
    html = visual.response_signals(r, j, True)
    assert (
        "Controlled project denial" not in html
        and html.count("data-response-event=") == 1
    )


def test_jira_response_requires_the_matching_successful_action_receipt() -> None:
    r, j = scenario()
    proposed(r, j)
    add(r, "succeeded", {"issue_key": "TEST-1"}, "action-fixture")
    assert visual.response_signals(r, j, True) == ""
    r["actions"][0].update(state="succeeded", issue_key="TEST-2")
    assert visual.response_signals(r, j, True) == ""
    r["actions"][0]["issue_key"] = "TEST-1"
    assert "Jira creation receipt recorded" in visual.response_signals(r, j, True)


def test_provider_attachment_is_runtime_preparation_not_an_issuer_request() -> None:
    r, j = scenario()
    j["stage"] = "attaching_credentials"
    add(r, "console_attaching_credentials")
    html = visual.architecture(r, j, {"enabled": True, "online": True}, "cve")
    assert 'flow-node active" data-node="sandbox"' in html
    assert 'flow-node active" data-node="keycloak"' not in html


def test_probe_before_draft_never_turns_the_run_header_or_progress_into_a_denied_create() -> (
    None
):
    r, j = scenario()
    j["stage"] = "agent_read_complete"
    j["evidence"].update(native_bound_read=True, scope_probe_denied=True)
    add(r, "console_checking_project_boundary")
    add(r, "denied", {"reason": "project_permission"})
    add(r, "console_project_boundary_verified")
    add(r, "console_agent_read_complete")
    page, _ = console.run_page(
        r,
        "csrf-fixture",
        {"workflow": "incident-triage"},
        j,
        {"enabled": True, "online": True},
    )
    assert "Project isolation check passed" in page
    assert "Action blocked at MCP Gateway" not in page
    assert 'data-step="4" data-state="denied"' not in page
    assert 'flow-node denied" data-node="gateway"' not in page


def test_unrecorded_denial_argument_cannot_fabricate_a_blocked_run() -> None:
    r, j = scenario()
    assert visual.projection(r, j, "user_permission")["denied"] is None
    assert visual.projection(r, j, "user_permission")["stop"] is None


def test_recorded_action_denial_without_a_reason_is_still_blocked_explicitly() -> None:
    r, j = scenario()
    proposed(r, j)
    add(r, "denied", {}, "action-fixture")
    p = visual.projection(r, j)
    assert p["denied"] == "policy_denied" and p["statuses"][4] == "denied"
    page, _ = console.run_page(r, "csrf-fixture", {"workflow": "cve"}, j)
    assert "no further reason was reported" in page


def test_recorded_consent_does_not_look_pending_while_worker_observes_approval() -> None:
    r, j = scenario()
    proposed(r, j)
    r["actions"][-1]["state"] = "approved"
    add(r, "approved", action="action-fixture")
    html = visual.architecture(r, j, {"enabled": True, "online": True}, "cve")
    assert 'flow-node done" data-node="approval"' in html
    assert 'flow-node waiting" data-node="approval"' not in html
    assert visual.projection(r, j)["statuses"][4:] == ["pending", "pending", "pending"]


def test_agent_activity_duration_stops_when_approval_wait_starts() -> None:
    r, j = scenario()
    add(r, "console_draft_validated")
    r["audit"][-1]["at"] = 100
    add(r, "console_awaiting_approval")
    r["audit"][-1]["at"] = 101
    j["stage"] = "awaiting_approval"
    html = console.activity_view(r["audit"], j)
    assert '1s' in html
    assert 'data-elapsed-since' not in html


def test_reviewed_backend_rejection_does_not_erase_gateway_authorization_or_history():
    record,job=scenario()
    record['run']['active']=0
    record['actions']=[{'id':'rejected-action','state':'failed'}]
    for event in ('approved','authorized','claimed','unknown','dispatch_rejection_reviewed'):
        add(record,event,action='rejected-action')
    add(record,'console_recovery_reviewed')
    job.update(state='failed',stage='execution_failed',evidence={'native_bound_read':True,
        'cleanup_verified':True,'failure_code':'recovery_required'})
    result=visual.projection(record,job)
    assert result['statuses'][4:] == ['done','failed','done']
    assert result['stop_component']=='jira' and result['verified'] is False
    timeline=visual.timeline(record['audit'])
    assert 'Write outcome uncertain' in timeline and 'Backend rejection verified' in timeline
    assert 'Cleanup reviewed' in timeline and 'Recorded platform event' not in timeline
