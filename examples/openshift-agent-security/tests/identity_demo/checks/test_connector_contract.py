# SPDX-License-Identifier: Apache-2.0
"""Non-Jira proof using real approval/dispatch storage and an independent document fixture."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import json
import time
from uuid import uuid4

import pytest

from identity_demo_connector import ConnectorContract, Denied, tool_arguments
from identity_demo_jira_contract import JIRA, canonical
from identity_demo_run_store import RunStore


def normalize(value):
    if (
        not isinstance(value, dict)
        or not {"collection", "document", "revision", "content"} <= value.keys()
        or value.keys() - {"collection", "document", "revision", "content", "operation_id"}
        or value["collection"] not in ("handbook", "restricted")
        or value["document"] != "runbook"
        or type(value["revision"]) is not int
        or not 0 < value["revision"] < 1000
        or not isinstance(value["content"], str)
        or not 0 < len(value["content"]) <= 8000
    ):
        raise Denied("document_schema")
    if "operation_id" in value and (
        not isinstance(value["operation_id"], str)
        or len(value["operation_id"]) != 32
        or any(c not in "0123456789abcdef" for c in value["operation_id"])
    ):
        raise Denied("document_schema")
    return dict(value)


def proposal(value, action):
    value = normalize(value)
    if "operation_id" in value:
        raise Denied("reserved_marker")
    return dict(value, operation_id=action)


def check_reference(scope, reference):
    if reference != scope + "/runbook@1":
        raise Denied("backend_resource")


DOCUMENTS = ConnectorContract(
    "documents.publish.v1",
    "fixture-documents",
    "document-v1",
    "document.publish",
    normalize,
    lambda v: v["collection"],
    lambda v: v in ("handbook", "restricted"),
    proposal,
    check_reference,
    lambda v, a: v.get("operation_id") == a,
)


class Documents:
    """A separate backend outcome store, with fixed operations and no network destination."""

    def __init__(self):
        self.entries = {}

    def publish(self, payload):
        key = payload["collection"] + "/" + payload["document"] + "@" + str(payload["revision"])
        if key in self.entries:
            raise AssertionError("duplicate backend dispatch")
        self.entries[key] = dict(payload)
        return key

    def verify(self, key, approved):
        return self.entries.get(key) == approved


def prepared(tmp_path, user_role="analyst", workload_role="triage"):
    tmp_path.chmod(0o700)
    store = RunStore(tmp_path / "runs.db", connector=DOCUMENTS)
    workload = "spiffe://agents.example.test/openshell/sandbox/" + str(uuid4())
    run = store.create_run(
        issuer="https://issuer.example.test",
        user="user-a",
        user_role=user_role,
        workload=workload,
        workload_role=workload_role,
        project="handbook",
        expires=int(time.time()) + 300,
        assessment="synthetic document review",
    )
    drafted = store.propose(
        run,
        "user-a",
        {
            "collection": "handbook",
            "document": "runbook",
            "revision": 1,
            "content": "Reviewed steps",
        },
    )
    store.approve(run, drafted["action_id"], "user-a", drafted["digest"], int(time.time()) + 100)
    return store, run, workload, drafted


def test_non_jira_read_approval_dispatch_verification_and_retained_audit(tmp_path):
    store, run, workload, p = prepared(tmp_path)
    assert store.read_decision(run, "user-a", workload, "handbook", "a" * 64)["allowed"]
    assert not store.read_decision(run, "user-a", workload, "restricted", "b" * 64)["allowed"]
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "document.publish", "arguments": p["arguments"]},
        }
    ).encode()
    actual = tool_arguments(body, DOCUMENTS.tool)
    decision = store.decision(run, p["action_id"], "user-a", workload, actual, claim=True)
    assert decision["dispatch"]
    backend = Documents()
    reference = backend.publish(actual)
    assert backend.verify(reference, p["arguments"])
    store.finish(
        run, p["action_id"], decision["execution_id"], state="succeeded", result_ref=reference
    )
    assert not store.decision(run, p["action_id"], "user-a", workload, actual, claim=True)[
        "dispatch"
    ]
    store.cancel(run, "user-a")
    restored = RunStore(store.path, connector=DOCUMENTS)
    history = restored.describe(run, "user-a")
    assert history["actions"][0]["result_ref"] == reference
    assert history["actions"][0]["issue_key"] is None
    assert {v["event"] for v in history["audit"]} >= {
        "run_created",
        "read_allowed",
        "denied",
        "approved",
        "claimed",
        "succeeded",
        "cancelled",
    }


@pytest.mark.parametrize(
    "user,workload,reason",
    [("viewer", "triage", "user_permission"), ("analyst", "reader", "workload_permission")],
)
def test_approval_cannot_override_user_or_workload_permission(tmp_path, user, workload, reason):
    store, run, identity, p = prepared(tmp_path, user, workload)
    decision = store.decision(run, p["action_id"], "user-a", identity, p["arguments"], claim=True)
    assert decision == {"allowed": False, "dispatch": False, "reason": reason}


@pytest.mark.parametrize(
    "change", [{"collection": "restricted"}, {"revision": 2}, {"content": "Changed after approval"}]
)
def test_actual_scope_or_payload_substitution_is_denied(tmp_path, change):
    store, run, workload, p = prepared(tmp_path)
    assert not store.decision(
        run, p["action_id"], "user-a", workload, dict(p["arguments"], **change), claim=True
    )["dispatch"]


def test_unknown_tool_wrong_schema_and_connector_cannot_reuse_approval(tmp_path):
    store, run, workload, p = prepared(tmp_path)
    for value in (
        JIRA,
        replace(DOCUMENTS, identifier="other.publish.v1"),
        replace(DOCUMENTS, schema="document-v2"),
        replace(DOCUMENTS, write_workload_roles=frozenset({"triage", "reader"})),
    ):
        other = RunStore(store.path, connector=value)
        with pytest.raises(Denied, match="connector_binding"):
            other.approve(run, p["action_id"], "user-a", p["digest"], int(time.time()) + 30)
        with pytest.raises(Denied, match="connector_binding"):
            other.cancel(run, "user-a")
    with pytest.raises(Denied, match="unsupported_tool"):
        tool_arguments(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "unknown", "arguments": p["arguments"]},
                }
            ).encode(),
            DOCUMENTS.tool,
        )
    with pytest.raises(Denied, match="document_schema"):
        store.decision(
            run,
            p["action_id"],
            "user-a",
            workload,
            dict(p["arguments"], project="TEST"),
            claim=True,
        )


def test_atomic_claim_uncertain_dispatch_and_verified_reconciliation(tmp_path):
    store, run, workload, p = prepared(tmp_path)

    def claim(_):
        return store.decision(run, p["action_id"], "user-a", workload, p["arguments"], claim=True)

    with ThreadPoolExecutor(max_workers=6) as pool:
        decisions = list(pool.map(claim, range(6)))
    dispatched = [d for d in decisions if d.get("dispatch")]
    assert len(dispatched) == 1
    backend = Documents()
    reference = backend.publish(p["arguments"])
    assert store.recover_dispatched() == 1
    assert not claim(None)["dispatch"]
    restored = RunStore(store.path, connector=DOCUMENTS)
    with pytest.raises(Denied):
        restored.reconcile_result(run, p["action_id"], "wrong", reference, p["arguments"])
    assert backend.verify(reference, p["arguments"])
    restored.reconcile_result(
        run, p["action_id"], dispatched[0]["execution_id"], reference, p["arguments"]
    )
    assert not claim(None)["dispatch"]


def test_expiry_cancellation_and_invalid_backend_outcomes(tmp_path):
    store, run, workload, p = prepared(tmp_path)
    decision = store.decision(run, p["action_id"], "user-a", workload, p["arguments"], claim=True)
    with pytest.raises(Denied):
        store.finish(
            run,
            p["action_id"],
            decision["execution_id"],
            state="succeeded",
            result_ref="restricted/runbook@1",
        )
    store.finish(run, p["action_id"], decision["execution_id"], state="unknown")
    store.cancel(run, "user-a")
    with pytest.raises(Denied, match="run_inactive"):
        store.read_decision(run, "user-a", workload, "handbook", "a" * 64)
    with store.transaction() as db:
        db.execute("UPDATE runs SET expires=?,active=1 WHERE id=?", (int(time.time()) - 1, run))
    with pytest.raises(Denied, match="run_inactive"):
        store.read_decision(run, "user-a", workload, "handbook", "a" * 64)


def test_jira_approval_digest_and_legacy_records_stay_compatible(tmp_path):
    value = {"project": "TEST", "summary": "Summary", "description": "Description"}
    payload = json.dumps(
        dict(value, issue_type="Task", labels=[]),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    digest = hashlib.sha256(
        json.dumps(
            ["pilot-jira", "jira-create-v1", "createJiraIssue", payload],
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
    ).hexdigest()
    assert canonical(value) == JIRA.canonical(value) == (payload, digest)
    tmp_path.chmod(0o700)
    store = RunStore(tmp_path / "old.db")
    run = store.create_run(
        issuer="https://issuer.example.test",
        user="user-a",
        user_role="analyst",
        workload="spiffe://agents.example.test/openshell/sandbox/" + str(uuid4()),
        workload_role="triage",
        project="TEST",
        expires=int(time.time()) + 300,
        assessment="legacy",
    )
    with store.transaction() as db:
        db.execute("DELETE FROM run_contracts WHERE run_id=?", (run,))
    assert RunStore(store.path).describe(run, "user-a")["run"]["assessment"] == "legacy"
    with pytest.raises(Denied, match="connector_binding"):
        RunStore(store.path, connector=DOCUMENTS).describe(run, "user-a")
    with store.transaction() as db:
        db.execute("UPDATE security_contract_schema SET version=999")
    with pytest.raises(ValueError, match="Unsupported"):
        RunStore(store.path)


def test_explicit_registry_rejects_unknown_or_duplicate_integrations():
    from identity_demo_connector import ConnectorRegistry, supported_connectors
    from identity_demo_jira_contract import JIRA

    assert supported_connectors().resolve(JIRA.identifier) is JIRA
    with pytest.raises(Denied, match="unsupported_connector"):
        supported_connectors().resolve("unknown.backend")
    with pytest.raises(ValueError):
        ConnectorRegistry((JIRA, JIRA))


def test_new_connectors_cannot_select_legacy_approval_digests():
    with pytest.raises(ValueError,match='Legacy digest'):
        replace(DOCUMENTS,legacy_digest=True)
    read_only=replace(DOCUMENTS,write_user_roles=frozenset(),write_workload_roles=frozenset())
    assert not read_only.write_user_roles and not read_only.write_workload_roles


@pytest.mark.parametrize("fields", [
    {"profile_tools": ["record.read"]},
    {"profile_tools": ({},)},
    {"profile_tools": ("record.read", "record.read")},
    {"profile_tools": ("record.read",), "profile_write_actions": ("record.create",)},
    {"profile_tools": ("record.read",), "profile_write_actions": ()},
])
def test_profile_action_descriptors_are_bounded_immutable_and_consistent(fields):
    with pytest.raises(ValueError):
        replace(DOCUMENTS, **fields)
