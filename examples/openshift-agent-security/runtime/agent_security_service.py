# SPDX-License-Identifier: Apache-2.0
"""Headless action service for trusted authentication and backend adapters.

This is an in-process interface, not an authentication endpoint. Only the trusted
host creates VerifiedActor from validated user/workload credentials. Untrusted
agents supply tool-call bytes, never actors, connectors, credentials or callbacks.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Callable

from agent_security_contracts import Denied, tool_arguments


@dataclass(frozen=True)
class VerifiedActor:
    """Server-derived association; construction alone is not authentication."""

    user: str
    workload: str

    def __post_init__(self):
        if (not isinstance(self.user, str) or not 1 <= len(self.user) <= 160
                or not isinstance(self.workload, str) or not 1 <= len(self.workload) <= 512):
            raise ValueError("Verified bounded actor association required")


@dataclass(frozen=True)
class BackendPort:
    """Reviewed callbacks with a fixed destination and privately held credentials."""

    contract_fingerprint: str
    dispatch: Callable[[dict], str]
    observe: Callable[[str], dict]
    read: Callable[[str], object] | None = None


class RunService:
    """Shared proposal/consent interface for authenticated UI, CLI and hosts."""

    def __init__(self, store):
        self.store = store

    def _owner(self, actor: VerifiedActor, run: str):
        if not isinstance(actor, VerifiedActor):
            raise Denied("verified_actor_required")
        with self.store.read_transaction() as db:
            self.store.active_run(db, run, actor.user, actor.workload)

    def propose(self, actor: VerifiedActor, run: str, effects: dict) -> dict:
        self._owner(actor, run)
        return self.store.propose(run, actor.user, effects)

    def approve(self, actor: VerifiedActor, run: str, action: str, digest: str, expires: int):
        self._owner(actor, run)
        self.store.approve(run, action, actor.user, digest, expires)

class SecurityService(RunService):
    """Use the shared store at the actual read/write boundary; never return a grant."""

    def __init__(self, store, backend: BackendPort):
        if (not isinstance(backend, BackendPort)
                or backend.contract_fingerprint != store.connector.fingerprint
                or not callable(backend.dispatch) or not callable(backend.observe)
                or backend.read is not None and not callable(backend.read)):
            raise ValueError("Exact reviewed connector/backend binding required")
        self.store, self.backend = store, backend

    def read(self, actor: VerifiedActor, run: str, resource: str):
        self._owner(actor, run)
        if self.backend.read is None or not self.store.connector.valid_scope(resource):
            raise Denied("unsupported_read")
        body = json.dumps({"resource": resource}, sort_keys=True).encode()
        decision = self.store.read_decision(
            run, actor.user, actor.workload, resource, hashlib.sha256(body).hexdigest())
        if not decision["allowed"]:
            raise Denied(decision["reason"])
        return self.backend.read(resource)

    def execute(self, actor: VerifiedActor, body: bytes) -> dict:
        """Validate actual MCP effects, claim once, dispatch and verify independently.

        A timeout or invalid backend observation becomes unknown and cannot be
        retried. Cancellation closes future claims; it cannot undo a claimed
        operation already in flight. Backend callbacks must never follow an
        agent-selected URL or choose credentials from the request.
        """
        if not isinstance(actor, VerifiedActor):
            raise Denied("verified_actor_required")
        contract = self.store.connector
        actual = tool_arguments(body, contract.tool)
        if not isinstance(actual, dict) or not {"run_id", "action_id"} <= actual.keys():
            raise Denied("missing_action")
        run, action = actual["run_id"], actual["action_id"]
        if any(not isinstance(v, str) or not re.fullmatch(r"[a-f0-9]{32}", v)
               for v in (run, action)):
            raise Denied("invalid_action_reference")
        effects = {k: v for k, v in actual.items() if k not in {"run_id", "action_id"}}
        payload, digest = contract.canonical(effects)
        effects = json.loads(payload)
        claim = self.store.decision(run, action, actor.user, actor.workload, effects, claim=True)
        if not claim["allowed"]:
            raise Denied(claim["reason"])
        if not claim["dispatch"]:
            return {"state": claim["state"], "dispatched": False,
                    contract.result_field: claim.get(contract.result_field)}
        execution = claim["execution_id"]
        try:
            # Credentials are used only inside this trusted callback after claim.
            reference = self.backend.dispatch(json.loads(payload))
            contract.check_reference(contract.resource(effects), reference)
            observed = self.backend.observe(reference)
            if (contract.canonical(observed)[1] != digest
                    or not contract.has_marker(observed, action)):
                raise Denied("backend_effect_mismatch")
        except Exception:
            self.store.finish(run, action, execution, state="unknown")
            raise Denied("outcome_unknown") from None
        self.store.finish(run, action, execution, state="succeeded",
                          **{contract.result_field: reference})
        return {"state": "succeeded", "dispatched": True,
                contract.result_field: reference, "verified": True}
