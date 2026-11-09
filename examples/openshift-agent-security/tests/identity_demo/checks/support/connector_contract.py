# SPDX-License-Identifier: Apache-2.0
"""Shared connector contract test setup; contains no collected tests."""
import time
from uuid import uuid4
from identity_demo_connector import ConnectorContract, Denied
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
