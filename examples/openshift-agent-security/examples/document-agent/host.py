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
import tempfile
import time
from uuid import uuid4

from agent_security_runtime import RunStore, Denied
from contract import DOCUMENTS, normalize, proposal, check_reference
from agent_security_runtime import BackendPort, SecurityService, VerifiedActor
from agent import draft


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
