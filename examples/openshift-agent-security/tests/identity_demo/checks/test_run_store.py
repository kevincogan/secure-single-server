# SPDX-License-Identifier: Apache-2.0
"""Approval must match actual arguments and duplicate dispatch must remain closed."""

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sqlite3
import time
from uuid import uuid4

import pytest
from identity_demo_run_store import Denied, RunStore, canonical, strict_json


def prepare(
    tmp_path: Path, user_role: str = "analyst", workload_role: str = "triage"
) -> tuple:
    """Use private synthetic storage; no issuer or backend calls are mocked as proof."""
    tmp_path.chmod(0o700)
    store = RunStore(tmp_path / "runs.db")
    workload = "spiffe://agents.example.test/openshell/sandbox/" + str(uuid4())
    run = store.create_run(
        issuer="https://issuer.example.test/realms/pilot",
        user="user-a",
        user_role=user_role,
        workload=workload,
        workload_role=workload_role,
        project="TEST",
        expires=int(time.time()) + 300,
        assessment="synthetic assessment",
    )
    proposal = store.propose(
        run,
        "user-a",
        {
            "project": "TEST",
            "summary": "Synthetic CVE",
            "description": "Frozen assessment",
        },
    )
    store.approve(
        run, proposal["action_id"], "user-a", proposal["digest"], int(time.time()) + 100
    )
    return store, run, workload, proposal


def decision(
    store: RunStore, run: str, workload: str, proposal: dict, **kwargs: object
) -> dict:
    """Supply the actor and payload that the gateway/adapter must independently verify."""
    return store.decision(
        run, proposal["action_id"], "user-a", workload, proposal["arguments"], **kwargs
    )


def test_authorization_does_not_consume_approval(tmp_path: Path) -> None:
    store, run, workload, p = prepare(tmp_path)
    assert all(decision(store, run, workload, p)["allowed"] for _ in range(3))
    claim = decision(store, run, workload, p, claim=True)
    assert claim["dispatch"] is True
    assert decision(store, run, workload, p, claim=True)["reason"] == "action_executing"
    store.finish(
        run,
        p["action_id"],
        claim["execution_id"],
        state="succeeded",
        issue_key="TEST-1",
    )
    # Reopening persistent state does not replay the backend mutation.
    reopened = RunStore(tmp_path / "runs.db")
    result = decision(reopened, run, workload, p, claim=True)
    assert (
        result["allowed"] and not result["dispatch"] and result["issue_key"] == "TEST-1"
    )


def test_concurrent_claims_have_one_dispatch(tmp_path: Path) -> None:
    store, run, workload, p = prepare(tmp_path)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(
            pool.map(lambda _: decision(store, run, workload, p, claim=True), range(8))
        )
    assert sum(r["dispatch"] for r in results) == 1


@pytest.mark.parametrize(
    "user_role,workload_role,reason",
    [
        ("viewer", "triage", "user_permission"),
        ("analyst", "reader", "workload_permission"),
    ],
)
def test_permissions_deny_even_with_valid_approval(
    tmp_path: Path, user_role: str, workload_role: str, reason: str
) -> None:
    store, run, workload, p = prepare(tmp_path, user_role, workload_role)
    assert decision(store, run, workload, p, claim=True)["reason"] == reason
    assert store.assessment(run, "user-a") == "synthetic assessment"


@pytest.mark.parametrize(
    "field,value",
    [
        ("project", "OTHER"),
        ("summary", "Changed"),
        ("description", "Changed"),
        ("labels", ["changed"]),
    ],
)
def test_effectful_argument_changes_denied(
    tmp_path: Path, field: str, value: object
) -> None:
    store, run, workload, p = prepare(tmp_path)
    p["arguments"][field] = value
    assert not decision(store, run, workload, p, claim=True)["allowed"]


def test_cancelled_context_cannot_reactivate_or_lose_assessment(tmp_path: Path) -> None:
    store, run, workload, p = prepare(tmp_path)
    store.cancel(run, "user-a")
    with pytest.raises(Denied, match="run_inactive"):
        decision(store, run, workload, p, claim=True)
    assert store.assessment(run, "user-a") == "synthetic assessment"
    with pytest.raises(sqlite3.IntegrityError):
        store.create_run(
            issuer="https://issuer.example.test",
            user="user-a",
            user_role="analyst",
            workload=workload,
            workload_role="triage",
            project="TEST",
            expires=int(time.time()) + 100,
            assessment="new",
        )
    with pytest.raises(Denied):
        store.assessment(run, "user-b")


def test_restart_during_dispatch_never_becomes_new_approval(tmp_path: Path) -> None:
    store, run, workload, p = prepare(tmp_path)
    decision(store, run, workload, p, claim=True)
    store = RunStore(tmp_path / "runs.db")
    assert store.recover_dispatched() == 1
    assert decision(store, run, workload, p, claim=True)["reason"] == "action_unknown"


def test_unknown_response_blocks_retry(tmp_path: Path) -> None:
    store, run, workload, p = prepare(tmp_path)
    result = decision(store, run, workload, p, claim=True)
    store.finish(run, p["action_id"], result["execution_id"], state="unknown")
    assert decision(store, run, workload, p, claim=True)["reason"] == "action_unknown"


def test_wrong_actor_and_wrong_execution_denied(tmp_path: Path) -> None:
    store, run, workload, p = prepare(tmp_path)
    with pytest.raises(Denied):
        decision(store, run, "spiffe://wrong/workload", p, claim=True)
    result = decision(store, run, workload, p, claim=True)
    with pytest.raises(Denied):
        store.finish(
            run, p["action_id"], "another", state="succeeded", issue_key="TEST-1"
        )
    store.finish(run, p["action_id"], result["execution_id"], state="failed")
    assert not decision(store, run, workload, p, claim=True)["allowed"]


def test_displayed_digest_and_missing_approval(tmp_path: Path) -> None:
    store, run, workload, _ = prepare(tmp_path)
    p = store.propose(
        run,
        "user-a",
        {"project": "TEST", "summary": "Second", "description": "Assessment"},
    )
    with pytest.raises(Denied):
        store.approve(run, p["action_id"], "user-a", "wrong", int(time.time()) + 100)
    assert decision(store, run, workload, p, claim=True)["reason"] == "action_proposed"


@pytest.mark.parametrize(
    "data",
    [
        b"[]",
        b'{"x":1,"x":2}',
        b'{"arguments":{"x":1,"x":2}}',
        b'{"x":NaN}',
        b'{"x":Infinity}',
        b"\xff",
        b"{",
        b" " * 65537,
    ],
)
def test_ambiguous_or_partial_json_denied(data: bytes) -> None:
    with pytest.raises(Denied):
        strict_json(data)


def test_schema_and_defaults_bound() -> None:
    base = {"project": "TEST", "summary": "Summary", "description": "Description"}
    assert canonical(base) == canonical({**base, "issue_type": "Task", "labels": []})
    with pytest.raises(Denied):
        canonical({**base, "assignee": "admin"})
    with pytest.raises(Denied):
        canonical({**base, "issue_type": "Bug"})


def test_expiry_and_audit_are_durable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, run, workload, p = prepare(tmp_path)
    real = time.time()
    monkeypatch.setattr("identity_demo_run_store.time.time", lambda: real + 150)
    assert decision(store, run, workload, p, claim=True)["reason"] == "approval_expired"
    with store.transaction() as db:
        events = [dict(r) for r in db.execute("SELECT * FROM audit")]
    assert events[-1]["event"] == "denied"
    assert json.loads(events[-1]["detail"])["reason"] == "approval_expired"
    assert "synthetic assessment" not in json.dumps(events)
    assert not (tmp_path / "runs.db").stat().st_mode & 0o077


def test_retired_step4_workload_is_never_reassigned(tmp_path: Path) -> None:
    """Even a fresh database cannot resurrect the globally retired demo identity."""
    from identity_demo_run_store import RETIRED_WORKLOAD

    tmp_path.chmod(0o700)
    store = RunStore(tmp_path / "runs.db")
    with pytest.raises(ValueError):
        store.create_run(
            issuer="https://issuer.example.test",
            user="user-a",
            user_role="analyst",
            workload=RETIRED_WORKLOAD,
            workload_role="triage",
            project="TEST",
            expires=int(time.time()) + 300,
            assessment="synthetic",
        )


def test_wrong_backend_project_is_not_recorded_as_success(tmp_path: Path) -> None:
    """A successful-looking response must still belong to the approved project."""
    store, run, workload, p = prepare(tmp_path)
    claim = decision(store, run, workload, p, claim=True)
    with pytest.raises(Denied, match="backend_project"):
        store.finish(
            run,
            p["action_id"],
            claim["execution_id"],
            state="succeeded",
            issue_key="OTHER-1",
        )
    store.finish(run, p["action_id"], claim["execution_id"], state="unknown")
    assert not decision(store, run, workload, p, claim=True)["dispatch"]


def test_client_cannot_supply_trusted_correlation_marker(tmp_path: Path) -> None:
    """The original create must carry a server-generated action marker."""
    store, run, _, _ = prepare(tmp_path)
    with pytest.raises(Denied, match="reserved_marker"):
        store.propose(
            run,
            "user-a",
            {
                "project": "TEST",
                "summary": "Summary",
                "description": "Description",
                "labels": ["demo-action-forged"],
            },
        )


def test_actual_rpc_arguments_feed_approval_comparison(tmp_path: Path) -> None:
    """A forged route/hash cannot substitute a different actual tool body."""
    from identity_demo_run_store import create_call

    store, run, workload, p = prepare(tmp_path)
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "step56_jira_createJiraIssue",
            "arguments": {"run_id": run, "action_id": p["action_id"], **p["arguments"]},
        },
    }
    r, a, effects = create_call(json.dumps(body).encode())
    assert store.decision(r, a, "user-a", workload, effects)["allowed"]
    body["params"]["arguments"]["description"] = "Unapproved replacement"
    r, a, effects = create_call(json.dumps(body).encode())
    assert not store.decision(r, a, "user-a", workload, effects)["allowed"]
    body["params"]["arguments"]["user"] = "admin"
    with pytest.raises(Denied):
        create_call(json.dumps(body).encode())


@pytest.mark.parametrize(
    "change",
    ["tool", "method", "missing_ref", "fake_ref", "extra", "batch", "boolean_id"],
)
def test_mutation_rpc_rejects_ambiguity(change: str) -> None:
    """Batching, unsupported tools and caller-added authority do not authorize a mutation."""
    from identity_demo_run_store import create_call

    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "step56_jira_createJiraIssue",
            "arguments": {
                "run_id": "a" * 32,
                "action_id": "b" * 32,
                "project": "TEST",
                "summary": "Summary",
                "description": "Description",
            },
        },
    }
    if change == "tool":
        body["params"]["name"] = "updateJiraIssue"
    if change == "method":
        body["method"] = "initialize"
    if change == "missing_ref":
        del body["params"]["arguments"]["run_id"]
    if change == "fake_ref":
        body["params"]["arguments"]["action_id"] = "selected"
    if change == "extra":
        body["params"]["trusted_user"] = "admin"
    if change == "boolean_id":
        body["id"] = True
    data = json.dumps([body] if change == "batch" else body).encode()
    with pytest.raises(Denied):
        create_call(data)


def test_positive_reconciliation_preserves_single_dispatch_after_cancellation(
    tmp_path: Path,
) -> None:
    """An uncertain create may become verified success without restoring permission."""
    store, run, workload, proposal = prepare(tmp_path)
    claim = decision(store, run, workload, proposal, claim=True)
    store.finish(run, proposal["action_id"], claim["execution_id"], state="unknown")
    record = store.reconciliation(run, proposal["action_id"])
    assert record["arguments"] == proposal["arguments"]
    assert (
        decision(store, run, workload, proposal, claim=True)["reason"]
        == "action_unknown"
    )
    store.cancel(run, "user-a")
    store.reconcile(
        run,
        proposal["action_id"],
        claim["execution_id"],
        "TEST-123",
        record["arguments"],
    )
    assert store.describe(run, "user-a")["actions"][0]["state"] == "succeeded"
    assert store.describe(run, "user-a")["audit"][-1]["event"] == "reconciled"
    with pytest.raises(Denied, match="run_inactive"):
        decision(store, run, workload, proposal, claim=True)


def test_reconciliation_does_not_accept_an_unclaimed_or_changed_action(
    tmp_path: Path,
) -> None:
    """Only the original uncertain dispatch and exact project/payload can resolve."""
    store, run, workload, proposal = prepare(tmp_path)
    with pytest.raises(Denied, match="reconciliation_state"):
        store.reconciliation(run, proposal["action_id"])
    claim = decision(store, run, workload, proposal, claim=True)
    store.finish(run, proposal["action_id"], claim["execution_id"], state="unknown")
    for key, args, execution in [
        ("OTHER-1", proposal["arguments"], claim["execution_id"]),
        (
            "TEST-1",
            {**proposal["arguments"], "description": "changed"},
            claim["execution_id"],
        ),
        ("TEST-1", proposal["arguments"], "f" * 32),
    ]:
        with pytest.raises(Denied, match="reconciliation_binding"):
            store.reconcile(run, proposal["action_id"], execution, key, args)
    assert store.reconciliation(run, proposal["action_id"])["allowed"]


def rejected_dispatch(tmp_path):
    store, run, workload, proposal = prepare(tmp_path)
    claim = decision(store, run, workload, proposal, claim=True)
    store.finish(run, proposal['action_id'], claim['execution_id'], state='unknown')
    store.revoke('run_id', run)
    return store, run, workload, proposal, claim


def test_installer_rejection_review_preserves_history_and_never_reopens_execution(tmp_path):
    store, run, workload, p, claim = rejected_dispatch(tmp_path)
    before = store.describe(run, 'user-a')
    result = store.review_dispatch_rejection(run, p['action_id'], claim['execution_id'], p['digest'], 'f'*64)
    assert result['state'] == 'failed' and result['redispatch'] is False
    assert result['console_recovery_cleared'] is False
    after = store.describe(run, 'user-a')
    assert after['run'] == before['run']
    assert len(after['audit']) == len(before['audit']) + 1
    assert after['audit'][:-1] == before['audit']
    assert after['actions'][0]['payload'] == before['actions'][0]['payload']
    assert after['actions'][0]['execution_id'] == claim['execution_id']
    with pytest.raises(Denied):
        decision(store, run, workload, p, claim=True)
    with pytest.raises(Denied):
        store.review_dispatch_rejection(run, p['action_id'], claim['execution_id'], p['digest'], 'f'*64)


@pytest.mark.parametrize('alter', ['run', 'action', 'execution', 'digest', 'receipt', 'active', 'executing', 'succeeded', 'missing_unknown', 'payload', 'duplicate_claim'])
def test_rejection_review_rejects_stale_or_unfinished_evidence_atomically(tmp_path, alter):
    store, run, workload, p, claim = rejected_dispatch(tmp_path)
    values = [run, p['action_id'], claim['execution_id'], p['digest'], 'f'*64]
    if alter in ('run', 'action', 'execution', 'digest', 'receipt'):
        i = ('run', 'action', 'execution', 'digest', 'receipt').index(alter)
        values[i] = ('0' * len(values[i])) if alter != 'receipt' else 'not-a-hash'
    else:
        with store.transaction() as db:
            if alter == 'active': db.execute('UPDATE runs SET active=1 WHERE id=?', (run,))
            elif alter == 'missing_unknown': db.execute("DELETE FROM audit WHERE action_id=? AND event='unknown'", (p['action_id'],))
            elif alter == 'payload':
                payload = dict(p['arguments'], summary='Changed')
                db.execute('UPDATE actions SET payload=? WHERE id=?', (json.dumps(payload), p['action_id']))
            elif alter == 'duplicate_claim': store.event(db, run, p['action_id'], 'claimed', {})
            else: db.execute('UPDATE actions SET state=? WHERE id=?', (alter, p['action_id']))
    before = store.describe(run, 'user-a')
    with pytest.raises(Denied): store.review_dispatch_rejection(*values)
    assert store.describe(run, 'user-a') == before
