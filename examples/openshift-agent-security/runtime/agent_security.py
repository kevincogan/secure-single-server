# SPDX-License-Identifier: Apache-2.0
"""Reusable durable authorization, approval and dispatch state.

This is an internal storage boundary, not an authentication endpoint. Callers
must derive the human and workload association from validated credentials and
controlled registrations. No agent request may create or change that association.
Authorization is read-only; only the trusted adapter may atomically claim writes.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time
from typing import Iterator
from uuid import UUID, uuid4

from agent_security_contracts import ConnectorContract, Denied, strict_json, tool_arguments


class RunStore:
    """Single-instance SQLite storage with short atomic claims and durable audit."""

    def __init__(self, path: Path, *, connector: ConnectorContract, trust_domain: str,
                 legacy_fingerprint: str | None = None,
                 retired_workloads: frozenset[str] = frozenset()) -> None:
        """Require private persistent storage; never store tokens or signing keys."""
        if (
            path.is_symlink()
            or not path.parent.is_dir()
            or path.parent.stat().st_mode & 0o077
        ):
            raise ValueError("Private storage directory required")
        if path.exists() and path.stat().st_mode & 0o077:
            raise ValueError("Private database file required")
        if not path.exists():
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
        if not isinstance(connector, ConnectorContract):
            raise ValueError('Trusted registered connector required')
        if (not isinstance(trust_domain, str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", trust_domain)):
            raise ValueError("Trusted SPIFFE domain required")
        if legacy_fingerprint is not None and (not connector.legacy_digest or legacy_fingerprint != connector.fingerprint):
            raise ValueError("Explicit matching historical contract required")
        if not isinstance(retired_workloads, frozenset) or any(not isinstance(v,str) for v in retired_workloads):
            raise ValueError("Immutable retired workload identities required")
        self.retired_workloads = retired_workloads
        self.trust_domain = trust_domain
        self.legacy_fingerprint = legacy_fingerprint
        self.connector = connector
        self.path = path
        with self.transaction() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY, issuer TEXT NOT NULL, user TEXT NOT NULL,
                user_role TEXT NOT NULL, workload TEXT NOT NULL UNIQUE,
                workload_role TEXT NOT NULL, project TEXT NOT NULL,
                expires INTEGER NOT NULL, active INTEGER NOT NULL,
                assessment TEXT NOT NULL, not_before INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS actions (
                id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id),
                payload TEXT NOT NULL, digest TEXT NOT NULL, state TEXT NOT NULL,
                approval_expires INTEGER, approver TEXT, execution_id TEXT,
                issue_key TEXT, outcome TEXT);
            CREATE TABLE IF NOT EXISTS audit (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL,
                run_id TEXT NOT NULL, action_id TEXT, event TEXT NOT NULL,
                detail TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS run_contracts (
                run_id TEXT PRIMARY KEY REFERENCES runs(id), connector TEXT NOT NULL,
                fingerprint TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS action_results (
                action_id TEXT PRIMARY KEY REFERENCES actions(id), reference TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS security_contract_schema (
                id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL);
            INSERT OR IGNORE INTO security_contract_schema VALUES(1,1);
            CREATE INDEX IF NOT EXISTS actions_run ON actions(run_id);
            CREATE INDEX IF NOT EXISTS runs_user ON runs(user);
            CREATE INDEX IF NOT EXISTS audit_run_sequence ON audit(run_id,sequence);
            CREATE INDEX IF NOT EXISTS audit_run_event ON audit(run_id,event,sequence);
            """)
            if db.execute('SELECT version FROM security_contract_schema WHERE id=1').fetchone()[0] != 1:
                raise ValueError('Unsupported security contract state version')

    def contract_binding(self, db, run):
        recorded = db.execute('SELECT connector,fingerprint FROM run_contracts WHERE run_id=?', (run,)).fetchone()
        if recorded is None:
            if self.legacy_fingerprint is None or self.connector.fingerprint != self.legacy_fingerprint:
                raise Denied('connector_binding')
        elif (recorded['connector'], recorded['fingerprint']) != (self.connector.identifier, self.connector.fingerprint):
            raise Denied('connector_binding')

    def result_reference(self, db, action):
        if self.connector.result_field == 'issue_key':
            row = db.execute('SELECT issue_key FROM actions WHERE id=?', (action,)).fetchone()
        else:
            row = db.execute('SELECT reference FROM action_results WHERE action_id=?', (action,)).fetchone()
        return row[0] if row else None

    @contextmanager
    def read_transaction(self) -> Iterator[sqlite3.Connection]:
        """Read one consistent snapshot without reserving the SQLite writer lock."""
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            yield db
        finally:
            db.rollback()
            db.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Serialize state transitions; no backend network calls inside a transaction."""
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def event(
        db: sqlite3.Connection, run: str, action: str | None, event: str, detail: dict
    ) -> None:
        """Retain a bounded decision/outcome record without credentials or report text."""
        db.execute(
            "INSERT INTO audit(at,run_id,action_id,event,detail) VALUES (?,?,?,?,?)",
            (int(time.time()), run, action, event, json.dumps(detail, sort_keys=True)),
        )

    def create_run(
        self,
        *,
        issuer: str,
        user: str,
        user_role: str,
        workload: str,
        workload_role: str,
        project: str,
        expires: int,
        assessment: str,
        require_context: bool = False,
        workflow: str | None = None,
    ) -> str:
        """Persist a server-derived association; never reassign a retired workload."""
        if (
            not issuer.startswith("https://")
            or not user
            or user_role not in self.connector.user_roles
            or workload_role not in self.connector.workload_roles
            or not re.fullmatch(
                r"spiffe://" + re.escape(self.trust_domain) + r"/openshell/sandbox/[a-f0-9-]{36}",
                workload,
            )
            or not self.connector.valid_scope(project)
            or type(expires) is not int
            or expires <= time.time()
            or not isinstance(assessment, str)
            or len(assessment) > 65_536
            or workload in self.retired_workloads
        ):
            raise ValueError("Validated trusted run association required")
        if str(UUID(workload.rsplit("/", 1)[1])) != workload.rsplit("/", 1)[1]:
            raise ValueError("Canonical native sandbox UUID required")
        if workflow is not None and (not require_context or not isinstance(workflow,str)
                or not re.fullmatch(r"[a-z][a-z0-9_.:-]{0,63}",workflow)):
            raise ValueError('Trusted execution workflow required')
        run = uuid4().hex
        with self.transaction() as db:
            self.reserve_context(db, workload, require_context, workflow)
            db.execute(
                "INSERT INTO runs VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    run,
                    issuer,
                    user,
                    user_role,
                    workload,
                    workload_role,
                    project,
                    expires,
                    1,
                    assessment,
                    int(time.time()),
                ),
            )
            self.bind_context(db, run, workload, project, workload_role, require_context, workflow)
            db.execute('INSERT INTO run_contracts VALUES(?,?,?)',
                       (run, self.connector.identifier, self.connector.fingerprint))
            self.event(
                db,
                run,
                None,
                "run_created",
                {"user": user, "workload": workload, "project": project},
            )
            self.queue_context(db, run, workflow)
        return run

    def reserve_context(self, db, workload, required, workflow):
        """A platform adapter must enforce allocation/fencing inside this transaction."""
        if required or workflow is not None:
            raise Denied("platform_admission_required")

    def bind_context(self, db, run, workload, resource, role, required, workflow):
        """Optional platform hook; never called outside the run transaction."""

    def queue_context(self, db, run, workflow):
        """Optional platform hook; queueing and the one-use claim remain atomic."""

    def active_run(
        self, db: sqlite3.Connection, run: str, user: str, workload: str | None = None
    ) -> sqlite3.Row:
        """Enforce owner and optional attested actor, plus current run lifetime."""
        row = db.execute("SELECT * FROM runs WHERE id=?", (run,)).fetchone()
        if (
            row is None
            or row["user"] != user
            or (workload is not None and row["workload"] != workload)
        ):
            raise Denied("run_binding")
        self.contract_binding(db, run)
        if not row["active"] or row["expires"] <= time.time():
            raise Denied("run_inactive")
        return row

    def propose(self, run: str, user: str, arguments: dict) -> dict:
        """Store a new immutable proposal; edits create a different action/approval."""
        action = uuid4().hex
        args = self.connector.proposal(arguments, action)
        payload, digest = self.connector.canonical(args)
        with self.transaction() as db:
            self.active_run(db, run, user)
            db.execute(
                "INSERT INTO actions(id,run_id,payload,digest,state) VALUES (?,?,?,?,?)",
                (action, run, payload, digest, "proposed"),
            )
            self.event(db, run, action, "proposed", {"digest": digest})
        return {"action_id": action, "digest": digest, "arguments": json.loads(payload)}

    def approve(
        self, run: str, action: str, user: str, displayed_digest: str, expires: int
    ) -> None:
        """Record explicit consent for the displayed exact proposal, even for denial comparisons."""
        with self.transaction() as db:
            row = self.active_run(db, run, user)
            proposal = db.execute(
                "SELECT * FROM actions WHERE id=? AND run_id=?", (action, run)
            ).fetchone()
            if (
                proposal is None
                or proposal["state"] != "proposed"
                or proposal["digest"] != displayed_digest
                or type(expires) is not int
                or not time.time() < expires <= row["expires"]
            ):
                raise Denied("approval_binding")
            db.execute(
                "UPDATE actions SET state='approved',approver=?,approval_expires=? WHERE id=?",
                (user, expires, action),
            )
            self.event(
                db,
                run,
                action,
                "approved",
                {"approver": user, "digest": displayed_digest},
            )

    def decision(
        self,
        run: str,
        action: str,
        user: str,
        workload: str,
        arguments: dict,
        *,
        claim: bool = False,
    ) -> dict:
        """Check actual arguments; claim only at the trusted adapter before dispatch."""
        payload, digest = self.connector.canonical(arguments)
        with self.transaction() as db:
            row = self.active_run(db, run, user, workload)
            proposed = db.execute(
                "SELECT * FROM actions WHERE id=? AND run_id=?", (action, run)
            ).fetchone()
            reason = None
            if row["user_role"] not in self.connector.write_user_roles:
                reason = "user_permission"
            elif row["workload_role"] not in self.connector.write_workload_roles:
                reason = "workload_permission"
            elif self.connector.resource(json.loads(payload)) != row["project"]:
                reason = self.connector.scope_denial
            elif proposed is None or proposed["digest"] != digest:
                reason = "action_binding"
            elif proposed["state"] == "succeeded":
                return {
                    "allowed": True,
                    "dispatch": False,
                    "state": "succeeded",
                    self.connector.result_field: self.result_reference(db, action),
                }
            elif proposed["state"] != "approved":
                reason = "action_" + proposed["state"]
            elif (
                proposed["approver"] != user
                or proposed["approval_expires"] <= time.time()
            ):
                reason = "approval_expired"
            if reason:
                self.event(
                    db, run, action, "denied", {"reason": reason, "digest": digest}
                )
                return {"allowed": False, "dispatch": False, "reason": reason}
            execution = uuid4().hex if claim else None
            if claim:
                db.execute(
                    "UPDATE actions SET state='executing',execution_id=? WHERE id=? AND state='approved'",
                    (execution, action),
                )
            self.event(
                db,
                run,
                action,
                "claimed" if claim else "authorized",
                {"digest": digest},
            )
            return {
                "allowed": True,
                "dispatch": claim,
                "execution_id": execution,
                "state": "executing" if claim else "approved",
            }

    def finish(self, run: str, action: str, execution: str, *, state: str,
               issue_key: str | None = None, result_ref: str | None = None) -> None:
        """Record a verified result; an unknown dispatch can never be retried."""
        if state not in ('succeeded', 'failed', 'unknown') or (issue_key is not None and result_ref is not None):
            raise ValueError('Verified bounded backend outcome required')
        reference = issue_key if issue_key is not None else result_ref
        if ((issue_key is not None and self.connector.result_field != 'issue_key')
                or (result_ref is not None and self.connector.result_field != 'result_ref')):
            raise Denied('connector_binding')
        with self.transaction() as db:
            self.contract_binding(db, run)
            if state == 'succeeded':
                owner = db.execute('SELECT project FROM runs WHERE id=?', (run,)).fetchone()
                if owner is None:
                    raise Denied('run_binding')
                self.connector.check_reference(owner['project'], reference)
            updated = db.execute(
                "UPDATE actions SET state=?,issue_key=? WHERE id=? AND run_id=? AND state='executing' AND execution_id=?",
                (state, reference if self.connector.result_field == 'issue_key' else None, action, run, execution))
            if updated.rowcount != 1:
                raise Denied('execution_binding')
            if reference is not None and self.connector.result_field == 'result_ref':
                db.execute('INSERT INTO action_results VALUES(?,?)', (action, reference))
            self.event(db, run, action, state, {self.connector.result_field: reference})

    def reconciliation(self, run: str, action: str) -> dict:
        """Return an uncertain dispatched action only to trusted adapter coordination."""
        with self.transaction() as db:
            self.contract_binding(db, run)
            row = db.execute(
                "SELECT * FROM actions WHERE id=? AND run_id=?", (action, run)
            ).fetchone()
            if row is None or row["state"] != "unknown" or not row["execution_id"]:
                raise Denied("reconciliation_state")
            return {
                "allowed": True,
                "execution_id": row["execution_id"],
                "arguments": json.loads(row["payload"]),
            }

    def reconcile(self, run: str, action: str, execution: str, issue_key: str, arguments: dict) -> None:
        """Keep the historical Jira adapter API while sharing result reconciliation."""
        if self.connector.result_field != 'issue_key':
            raise Denied('connector_binding')
        self.reconcile_result(run, action, execution, issue_key, arguments)

    def reconcile_result(self, run: str, action: str, execution: str, reference: str, arguments: dict) -> None:
        """Record an independently verified uncertain outcome; never reopen dispatch."""
        _, digest = self.connector.canonical(arguments)
        with self.transaction() as db:
            self.contract_binding(db, run)
            row = db.execute('SELECT a.*,r.project FROM actions a JOIN runs r ON r.id=a.run_id '
                             'WHERE a.id=? AND a.run_id=?', (action, run)).fetchone()
            if (row is None or row['state'] != 'unknown' or row['execution_id'] != execution
                    or row['digest'] != digest or not self.connector.has_marker(arguments, action)):
                raise Denied('reconciliation_binding')
            try:
                self.connector.check_reference(row['project'], reference)
            except ValueError:
                raise Denied('reconciliation_binding') from None
            db.execute("UPDATE actions SET state='succeeded',issue_key=? WHERE id=? AND run_id=? "
                       "AND state='unknown' AND execution_id=?",
                       (reference if self.connector.result_field == 'issue_key' else None, action, run, execution))
            if self.connector.result_field == 'result_ref':
                db.execute('INSERT INTO action_results VALUES(?,?)', (action, reference))
            self.event(db, run, action, 'reconciled', {self.connector.result_field: reference, 'digest': digest})

    def review_dispatch_rejection(
        self, run: str, action: str, execution: str, digest: str, receipt_sha256: str
    ) -> dict:
        """Installer-only adjudication of a proved rejection, never an HTTP API.

        The operator must retain the terminal rejection and no-commit evidence.
        An empty backend search is insufficient. This closes an unknown action;
        it cannot grant approval, reopen a run, or clear console recovery.
        """
        if (any(not isinstance(v, str) or not re.fullmatch(r"[a-f0-9]{32}", v)
                for v in (run, action, execution))
                or any(not isinstance(v, str) or not re.fullmatch(r"[a-f0-9]{64}", v)
                       for v in (digest, receipt_sha256))):
            raise Denied("rejection_review_binding")
        with self.transaction() as db:
            self.contract_binding(db, run)
            row = db.execute(
                "SELECT a.*,r.active FROM actions a JOIN runs r ON r.id=a.run_id "
                "WHERE a.id=? AND a.run_id=?", (action, run)
            ).fetchone()
            events = [v[0] for v in db.execute(
                "SELECT event FROM audit WHERE run_id=? AND action_id=? ORDER BY sequence",
                (run, action))]
            if (row is None or row["active"] or row["state"] != "unknown"
                    or row["execution_id"] != execution or row["digest"] != digest
                    or row["issue_key"] is not None
                    or self.connector.canonical(json.loads(row["payload"]))[1] != digest
                    or not self.connector.has_marker(json.loads(row["payload"]), action)
                    or events.count("claimed") != 1 or events.count("unknown") != 1
                    or any(e in events for e in ("succeeded", "reconciled", "dispatch_rejection_reviewed"))
                    or db.execute("SELECT 1 FROM runs WHERE active<>0").fetchone()
                    or db.execute("SELECT 1 FROM actions WHERE state='executing'").fetchone()):
                raise Denied("rejection_review_state")
            changed = db.execute(
                "UPDATE actions SET state='failed' WHERE id=? AND run_id=? "
                "AND state='unknown' AND execution_id=? AND digest=?",
                (action, run, execution, digest))
            if changed.rowcount != 1:
                raise Denied("rejection_review_state")
            self.event(db, run, action, "dispatch_rejection_reviewed",
                       {"receipt_sha256": receipt_sha256, "digest": digest,
                        "outcome": "rejected_without_commit", "redispatch": False})
            return {"run_id": run, "action_id": action, "state": "failed",
                    "receipt_sha256": receipt_sha256, "redispatch": False,
                    "console_recovery_cleared": False}

    def revoke(self, selector: str, value: str) -> int:
        """Disable trusted run associations without reviving or undoing dispatched work."""
        if (
            selector not in ("run_id", "user", "workload")
            or not isinstance(value, str)
            or not 1 <= len(value) <= 160
        ):
            raise Denied("revocation_selector")
        column = {"run_id": "id", "user": "user", "workload": "workload"}[selector]
        with self.transaction() as db:
            # Column is fixed above; the operator's selector value is always bound.
            rows = db.execute(
                "SELECT id FROM runs WHERE " + column + "=? AND active=1", (value,)
            ).fetchall()
            for row in rows:
                db.execute("UPDATE runs SET active=0 WHERE id=?", (row["id"],))
                self.event(
                    db,
                    row["id"],
                    None,
                    "revoked",
                    {"selector": selector, "actor": "trusted-operator"},
                )
            return len(rows)

    def cancel(self, run: str, user: str) -> None:
        """Invalidate future claims without pretending to cancel a dispatched backend request."""
        with self.transaction() as db:
            row = db.execute("SELECT user FROM runs WHERE id=?", (run,)).fetchone()
            if row is None or row["user"] != user:
                raise Denied("run_binding")
            self.contract_binding(db, run)
            db.execute("UPDATE runs SET active=0 WHERE id=?", (run,))
            self.event(db, run, None, "cancelled", {})

    def assessment(self, run: str, user: str) -> str:
        """Keep owner-scoped assessment available after authorization denial/cancellation."""
        with self.read_transaction() as db:
            row = db.execute(
                "SELECT user,assessment FROM runs WHERE id=?", (run,)
            ).fetchone()
            if row is None or row["user"] != user:
                raise Denied("run_binding")
            self.contract_binding(db, run)
            return row["assessment"]

    def identity_run(self, user: str, workload: str) -> dict:
        """Resolve the one immutable execution context without an agent-selected run."""
        with self.transaction() as db:
            row = db.execute(
                "SELECT * FROM runs WHERE user=? AND workload=?", (user, workload)
            ).fetchone()
            if row is None:
                raise Denied("run_binding")
            self.active_run(db, row["id"], user, workload)
            return dict(row)

    def read_decision(
        self, run: str, user: str, workload: str, project: str, body_hash: str
    ) -> dict:
        """Authorize a live owner's project read without approval or a write claim."""
        with self.transaction() as db:
            row = self.active_run(db, run, user, workload)
            allowed = row["project"] == project
            reason = self.connector.read_reason if allowed else self.connector.scope_denial
            self.event(
                db,
                run,
                None,
                "read_allowed" if allowed else "denied",
                {"reason": reason, "actual_body_sha256": body_hash},
            )
            return {
                "allowed": allowed,
                "reason": reason,
                "run_id": run,
                "actual_body_sha256": body_hash,
            }

    def describe(self, run: str, user: str) -> dict:
        """Return only the owner's retained assessment, proposals and safe audit."""
        with self.read_transaction() as db:
            row = db.execute(
                "SELECT * FROM runs WHERE id=? AND user=?", (run, user)
            ).fetchone()
            if row is None:
                raise Denied("run_binding")
            self.contract_binding(db, run)
            actions = [
                dict(a)
                for a in db.execute(
                    "SELECT * FROM actions WHERE run_id=? ORDER BY rowid", (run,)
                )
            ]
            if self.connector.result_field == 'result_ref':
                for action in actions:
                    action['result_ref'] = self.result_reference(db, action['id'])
            events = [
                dict(a)
                for a in db.execute(
                    "SELECT * FROM audit WHERE run_id=? ORDER BY sequence", (run,)
                )
            ]
            return {"run": dict(row), "actions": actions, "audit": events}

    def save_assessment(self, run: str, user: str, assessment: str) -> None:
        """Accept a bounded report from the trusted execution coordinator."""
        if (
            not isinstance(assessment, str)
            or not assessment
            or len(assessment) > 65_536
        ):
            raise Denied("invalid_assessment")
        with self.transaction() as db:
            self.active_run(db, run, user)
            db.execute("UPDATE runs SET assessment=? WHERE id=?", (assessment, run))
            self.event(db, run, None, "assessment_recorded", {})

    def recover_dispatched(self) -> int:
        """On coordinated single-instance startup, mark interrupted dispatches unknown."""
        with self.transaction() as db:
            rows = db.execute(
                "SELECT id,run_id FROM actions WHERE state='executing'"
            ).fetchall()
            for row in rows:
                db.execute(
                    "UPDATE actions SET state='unknown' WHERE id=?", (row["id"],)
                )
                self.event(
                    db,
                    row["run_id"],
                    row["id"],
                    "unknown",
                    {"reason": "restart_during_dispatch"},
                )
            return len(rows)
