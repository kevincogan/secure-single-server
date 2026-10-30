# SPDX-License-Identifier: Apache-2.0
"""Offline integration proof; identities below are synthetic, not authenticated.

A real host obtains both identities from verified authentication/attestation.
The agent supplies content only. This fixture is not a public security endpoint.
"""
from pathlib import Path
import argparse
import json
import os
import re
import sys
import tempfile
import time
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "runtime"))
from agent_security import RunStore
from agent_security_contracts import ConnectorContract, Denied
from agent_security_service import BackendPort, SecurityService, VerifiedActor
from agent import draft


def normalize(value):
    required = {"collection", "document", "revision", "content"}
    if (not isinstance(value, dict) or not required <= value.keys()
            or value.keys() - required - {"operation_id"}
            or not isinstance(value["collection"], str)
            or value["collection"] not in {"engineering", "research"}
            or value["document"] != "runbook" or type(value["revision"]) is not int
            or not 1 <= value["revision"] <= 1000
            or not isinstance(value["content"], str) or not 1 <= len(value["content"]) <= 2000
            or "\x00" in value["content"]
            or "operation_id" in value and (not isinstance(value["operation_id"], str)
                or not re.fullmatch(r"[a-f0-9]{32}", value["operation_id"]))):
        raise Denied("document_schema")
    return dict(value)


def proposal(value, action):
    if "operation_id" in value:
        raise Denied("reserved_marker")
    return {**normalize(value), "operation_id": action}


def check_reference(resource, reference):
    if (not isinstance(reference, str)
            or not re.fullmatch(re.escape(resource) + r"/runbook@[1-9][0-9]{0,3}", reference)):
        raise Denied("backend_resource")


DOCUMENTS = ConnectorContract(
    "documents.publish.v1", "local-document-fixture", "document-v1", "document.publish",
    normalize, lambda v: v["collection"], lambda v: isinstance(v, str) and v in {"engineering", "research"},
    proposal, check_reference, lambda v, action: v.get("operation_id") == action,
    user_roles=frozenset({"reviewer", "viewer"}),
    workload_roles=frozenset({"publisher", "reader"}),
    write_user_roles=frozenset({"reviewer"}), write_workload_roles=frozenset({"publisher"}))


class Documents:
    """A private file-backed service, independent of the security database."""

    def __init__(self, directory):
        self.directory = directory
        directory.mkdir(mode=0o700)
        self.dispatches = 0

    def read(self, resource):
        if resource not in {"engineering", "research"}:
            raise Denied("document_scope")
        return {"instruction": "Record observations separately from hypotheses."}

    def path(self, reference):
        if not re.fullmatch(r"(?:engineering|research)/runbook@[1-9][0-9]{0,3}", reference):
            raise Denied("backend_reference")
        return self.directory / (reference.replace("/", "-") + ".json")

    def publish(self, effects):
        reference = effects["collection"] + "/runbook@" + str(effects["revision"])
        fd = os.open(self.path(reference), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as output:
            json.dump(effects, output)
            output.flush()
            os.fsync(output.fileno())
        self.dispatches += 1
        return reference

    def observe(self, reference):
        return json.loads(self.path(reference).read_text())


def prepare(directory, *, user_role="reviewer", workload_role="publisher"):
    directory.chmod(0o700)
    store = RunStore(directory / "runs.db", connector=DOCUMENTS, trust_domain="lab.example.test")
    actor = VerifiedActor("synthetic-person", "spiffe://lab.example.test/openshell/sandbox/" + str(uuid4()))
    backend = Documents(directory / "documents")
    service = SecurityService(store, BackendPort(
        DOCUMENTS.fingerprint, backend.publish, backend.observe, backend.read))
    run = store.create_run(issuer="https://issuer.example.test/realms/evaluation", user=actor.user,
        user_role=user_role, workload=actor.workload, workload_role=workload_role,
        project="engineering", expires=int(time.time()) + 300, assessment="Synthetic document review")
    return service, actor, run, backend


def call(run, proposed):
    return json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": DOCUMENTS.tool, "arguments": {
            "run_id": run, "action_id": proposed["action_id"], **proposed["arguments"]}}}).encode()


def demonstrate(directory, *, approved=False, user_role="reviewer", workload_role="publisher"):
    service, actor, run, backend = prepare(directory, user_role=user_role, workload_role=workload_role)
    context = service.read(actor, run, "engineering")
    proposed = service.propose(actor, run, draft(context))
    result = {"synthetic_identity_fixture": True, "proposal": proposed["arguments"], "state": "awaiting_approval"}
    if approved:
        service.approve(actor, run, proposed["action_id"], proposed["digest"], int(time.time()) + 120)
        try:
            result.update(service.execute(actor, call(run, proposed)))
        except Denied as error:
            result.update(state="denied", reason=str(error))
    result["backend_dispatches"] = backend.dispatches
    result["audit_events"] = [v["event"] for v in service.store.describe(run, actor.user)["audit"]]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--approve", action="store_true", help="Record synthetic consent for the displayed fixture action")
    parser.add_argument("--user-role", choices=("reviewer", "viewer"), default="reviewer")
    parser.add_argument("--workload-role", choices=("publisher", "reader"), default="publisher")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="document-security-proof-") as directory:
        print(json.dumps(demonstrate(Path(directory), approved=args.approve,
            user_role=args.user_role, workload_role=args.workload_role), indent=2))


if __name__ == "__main__":
    main()
