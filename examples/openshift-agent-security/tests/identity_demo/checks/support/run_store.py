# SPDX-License-Identifier: Apache-2.0
"""Shared run store test setup; contains no collected tests."""
from pathlib import Path
import time
from uuid import uuid4
from identity_demo_run_store import RunStore

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

def rejected_dispatch(tmp_path):
    store, run, workload, proposal = prepare(tmp_path)
    claim = decision(store, run, workload, proposal, claim=True)
    store.finish(run, proposal['action_id'], claim['execution_id'], state='unknown')
    store.revoke('run_id', run)
    return store, run, workload, proposal, claim
