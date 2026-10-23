# SPDX-License-Identifier: Apache-2.0
"""Durable pilot run/approval/action state for one trusted authenticated driver.

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

from deployment_profile import active_profile

SCHEMA = "jira-create-v1"
BACKEND = "pilot-jira"
TOOL = "createJiraIssue"
RETIRED_WORKLOAD = "spiffe://agents.example.test/openshell/sandbox/00000000-0000-4000-8000-000000000001"


class Denied(ValueError):
    """A deliberate, safe authorization or lifecycle denial."""


def strict_json(data: bytes) -> dict:
    """Refuse incomplete, duplicate-key, oversized and non-object requests."""
    if not data or len(data) > 65_536:
        raise Denied("request_size")

    def pairs(values: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in values:
            if key in result:
                raise Denied("duplicate_field")
            result[key] = value
        return result

    try:
        value = json.loads(
            data,
            object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(Denied("invalid_number")),
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise Denied("malformed_json") from error
    if not isinstance(value, dict):
        raise Denied("object_required")
    return value


def normalize_create(arguments: dict) -> dict:
    """Resolve and bind all permitted effectful fields; deny arbitrary Jira fields."""
    required = {"project", "summary", "description"}
    if (
        not isinstance(arguments, dict)
        or not required <= arguments.keys()
        or arguments.keys() - required - {"issue_type", "labels"}
    ):
        raise Denied("unsupported_arguments")
    project = arguments["project"]
    if not isinstance(project, str) or not re.fullmatch(
        r"[A-Z][A-Z0-9]{1,15}", project
    ):
        raise Denied("invalid_project")
    issue_type = arguments.get("issue_type", "Task")
    if issue_type != "Task":
        raise Denied("unsupported_issue_type")
    for field, limit in (("summary", 200), ("description", 8_000)):
        value = arguments[field]
        if (
            not isinstance(value, str)
            or not value.strip()
            or len(value) > limit
            or "\x00" in value
        ):
            raise Denied("invalid_" + field)
    labels = arguments.get("labels", [])
    if (
        not isinstance(labels, list)
        or len(labels) > 8
        or any(
            not isinstance(v, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", v)
            for v in labels
        )
        or len(set(labels)) != len(labels)
    ):
        raise Denied("invalid_labels")
    return {
        "project": project,
        "issue_type": issue_type,
        "summary": arguments["summary"],
        "description": arguments["description"],
        "labels": sorted(labels),
    }


def canonical(arguments: dict) -> tuple[str, str]:
    """Bind the normalized payload to the fixed tool/backend/schema contract."""
    payload = json.dumps(
        normalize_create(arguments),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    material = json.dumps(
        [BACKEND, SCHEMA, TOOL, payload], separators=(",", ":"), ensure_ascii=False
    )
    return payload, hashlib.sha256(material.encode()).hexdigest()


def tool_arguments(data: bytes, tool_name: str) -> object:
    """Validate the complete MCP envelope before either read or create parsing."""
    value = strict_json(data)
    if (
        value.keys() != {"jsonrpc", "id", "method", "params"}
        or value["jsonrpc"] != "2.0"
        or value["method"] != "tools/call"
        or type(value["id"]) not in (str, int)
        or len(str(value["id"])) > 128
    ):
        raise Denied("unsupported_rpc")
    params = value["params"]
    if (
        not isinstance(params, dict)
        or params.keys() != {"name", "arguments"}
        or params["name"] != tool_name
    ):
        raise Denied("unsupported_tool")
    return params["arguments"]


def create_call(
    data: bytes, *, tool_name: str = "step56_jira_createJiraIssue"
) -> tuple[str, str, dict]:
    """Parse the complete actual mutation body, never routing headers or hashes.

    The caller supplies a trusted registered tool name. Protocol initialization
    and reads require their own authenticated handling; they are not mutations.
    Run/action references are selectors, not proof of user, workload or approval.
    """
    args = tool_arguments(data, tool_name)
    if not isinstance(args, dict) or not {"run_id", "action_id"} <= args.keys():
        raise Denied("missing_action")
    for field in ("run_id", "action_id"):
        if not isinstance(args[field], str) or not re.fullmatch(
            r"[a-f0-9]{32}", args[field]
        ):
            raise Denied("invalid_action_reference")
    effects = {k: v for k, v in args.items() if k not in ("run_id", "action_id")}
    return args["run_id"], args["action_id"], normalize_create(effects)



def scoped_read_jql(value: object, project: str) -> str | None:
    """Independently constrain model JQL to this actual run's project and issue."""
    if not isinstance(value, str) or len(value) > 160:
        raise Denied("invalid_jql")
    match = re.fullmatch(r'project\s*=\s*(?:"([A-Z][A-Z0-9]{1,15})"|([A-Z][A-Z0-9]{1,15}))'
                         r'(?:\s+AND\s+key\s*=\s*(?:"([A-Z][A-Z0-9]{1,15}-[1-9][0-9]*)"|([A-Z][A-Z0-9]{1,15}-[1-9][0-9]*)))?', value)
    if not match:
        raise Denied("invalid_jql")
    selected, issue = match[1] or match[2], match[3] or match[4]
    if selected != project or (issue and issue.split('-', 1)[0] != project):
        raise Denied("project_permission")
    return issue


def read_call(
    data: bytes, *, tool_name: str = "step56_jira_readJiraProject"
) -> tuple[str, str, str | None]:
    """Accept one project-scoped read; never expose arbitrary JQL or remote URLs."""
    args = tool_arguments(data, tool_name)
    if (
        not isinstance(args, dict)
        or not {"run_id", "project"} <= args.keys()
        or args.keys() - {"run_id", "project", "issue_key", "jql"}
    ):
        raise Denied("unsupported_arguments")
    run, project, issue = args["run_id"], args["project"], args.get("issue_key")
    if not isinstance(run, str) or not re.fullmatch(r"[a-f0-9]{32}", run):
        raise Denied("invalid_action_reference")
    if not isinstance(project, str) or not re.fullmatch(
        r"[A-Z][A-Z0-9]{1,15}", project
    ):
        raise Denied("invalid_project")
    if "issue_key" in args and (
        not isinstance(issue, str)
        or not re.fullmatch(re.escape(project) + r"-[1-9][0-9]*", issue)
    ):
        raise Denied("project_permission")
    if "jql" in args:
        if "issue_key" in args:
            raise Denied("unsupported_arguments")
        issue = scoped_read_jql(args["jql"], project)
    return run, project, issue


class RunStore:
    """Single-instance SQLite storage with short atomic claims and durable audit."""

    def __init__(self, path: Path) -> None:
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
            CREATE INDEX IF NOT EXISTS actions_run ON actions(run_id);
            CREATE INDEX IF NOT EXISTS runs_user ON runs(user);
            CREATE INDEX IF NOT EXISTS audit_run_sequence ON audit(run_id,sequence);
            CREATE INDEX IF NOT EXISTS audit_run_event ON audit(run_id,event,sequence);
            """)

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
        require_console_idle: bool = False,
        console_workflow: str | None = None,
    ) -> str:
        """Persist a server-derived association; never reassign a retired workload."""
        if (
            not issuer.startswith("https://")
            or not user
            or user_role not in ("analyst", "viewer")
            or workload_role not in ("triage", "reader")
            or not re.fullmatch(
                r"spiffe://" + re.escape(active_profile().trust_domain) + r"/openshell/sandbox/[a-f0-9-]{36}",
                workload,
            )
            or not re.fullmatch(r"[A-Z][A-Z0-9]{1,15}", project)
            or type(expires) is not int
            or expires <= time.time()
            or not isinstance(assessment, str)
            or len(assessment) > 65_536
            or workload == RETIRED_WORKLOAD
        ):
            raise ValueError("Validated trusted run association required")
        if str(UUID(workload.rsplit("/", 1)[1])) != workload.rsplit("/", 1)[1]:
            raise ValueError("Canonical native sandbox UUID required")
        if console_workflow is not None and (not require_console_idle
                or console_workflow not in ('cve', 'service-request', 'incident-triage')):
            raise ValueError('Trusted console workflow required')
        run = uuid4().hex
        with self.transaction() as db:
            from identity_demo_warm_pool import blocked_identity, blocks_execution
            if blocked_identity(db, workload):
                raise Denied('retired_workload')
            if blocks_execution(db):
                raise Denied('context_preparing')
            if console_workflow is not None:
                if db.execute("SELECT 1 FROM console_batches WHERE state='preparing'").fetchone():
                    raise Denied('presentation_preparing')
                worker = db.execute('SELECT phase,updated FROM console_worker WHERE id=1').fetchone()
                if not worker or worker['phase'] != 'ready' or worker['updated'] <= time.time()-20:
                    raise Denied('coordinator_not_ready')
                if db.execute("SELECT 1 FROM console_jobs WHERE state IN ('queued','running')").fetchone():
                    raise Denied('console_busy')
                if (db.execute("SELECT 1 FROM actions WHERE state IN ('executing','unknown')").fetchone()
                        or any(json.loads(v[0]).get('failure_code') == 'recovery_required'
                               and json.loads(v[0]).get('cleanup_verified') is not True
                               for v in db.execute("SELECT evidence FROM console_jobs WHERE state='failed'"))):
                    raise Denied('recovery_required')
            if require_console_idle:
                from identity_demo_warm_pool import allocate, blocks_execution, enabled as automatic_pool_enabled
                if blocks_execution(db):
                    raise Denied('context_preparing')
                if automatic_pool_enabled(db) and db.execute('SELECT 1 FROM runs WHERE active<>0').fetchone():
                    raise Denied('console_busy')
                allocate(db, workload)
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
            self.event(
                db,
                run,
                None,
                "run_created",
                {"user": user, "workload": workload, "project": project},
            )
            if console_workflow is not None:
                # Reserve the lane and identity in the SAME transaction. A racing
                # submission cannot consume a second identity without a job.
                evidence = {"scenario_version": "remediation-v1"} if console_workflow == "service-request" else {}
                db.execute("INSERT INTO console_jobs VALUES (?,?, 'queued','preparing_identity',NULL,?,?)",
                           (run, console_workflow, int(time.time()), json.dumps(evidence)))
                self.event(db, run, None, 'console_queued', {'workflow':console_workflow})
        return run

    @staticmethod
    def active_run(
        db: sqlite3.Connection, run: str, user: str, workload: str | None = None
    ) -> sqlite3.Row:
        """Enforce owner and optional attested actor, plus current run lifetime."""
        row = db.execute("SELECT * FROM runs WHERE id=?", (run,)).fetchone()
        if (
            row is None
            or row["user"] != user
            or (workload is not None and row["workload"] != workload)
        ):
            raise Denied("run_binding")
        if not row["active"] or row["expires"] <= time.time():
            raise Denied("run_inactive")
        return row

    def propose(self, run: str, user: str, arguments: dict) -> dict:
        """Store a new immutable proposal; edits create a different action/approval."""
        action = uuid4().hex
        args = normalize_create(arguments)
        if len(args["labels"]) > 7:
            raise Denied("marker_capacity")
        if any(label.startswith("demo-action-") for label in args["labels"]):
            raise Denied("reserved_marker")
        args["labels"].append("demo-action-" + action)
        payload, digest = canonical(args)
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
        _, digest = canonical(arguments)
        with self.transaction() as db:
            row = self.active_run(db, run, user, workload)
            proposed = db.execute(
                "SELECT * FROM actions WHERE id=? AND run_id=?", (action, run)
            ).fetchone()
            reason = None
            if row["user_role"] != "analyst":
                reason = "user_permission"
            elif row["workload_role"] != "triage":
                reason = "workload_permission"
            elif arguments["project"] != row["project"]:
                reason = "project_permission"
            elif proposed is None or proposed["digest"] != digest:
                reason = "action_binding"
            elif proposed["state"] == "succeeded":
                return {
                    "allowed": True,
                    "dispatch": False,
                    "state": "succeeded",
                    "issue_key": proposed["issue_key"],
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

    def finish(
        self,
        run: str,
        action: str,
        execution: str,
        *,
        state: str,
        issue_key: str | None = None,
    ) -> None:
        """Record a verified backend outcome; uncertainty is never retryable approval."""
        if state not in ("succeeded", "failed", "unknown") or (
            state == "succeeded"
            and (
                not issue_key
                or not re.fullmatch(r"[A-Z][A-Z0-9]{1,15}-[1-9][0-9]*", issue_key)
            )
        ):
            raise ValueError("Verified bounded backend outcome required")
        with self.transaction() as db:
            if state == "succeeded":
                owner = db.execute(
                    "SELECT project FROM runs WHERE id=?", (run,)
                ).fetchone()
                if owner is None or issue_key.split("-", 1)[0] != owner["project"]:
                    raise Denied("backend_project")
            updated = db.execute(
                "UPDATE actions SET state=?,issue_key=? WHERE id=? AND run_id=? AND state='executing' AND execution_id=?",
                (state, issue_key, action, run, execution),
            )
            if updated.rowcount != 1:
                raise Denied("execution_binding")
            self.event(db, run, action, state, {"issue_key": issue_key})

    def reconciliation(self, run: str, action: str) -> dict:
        """Return an uncertain dispatched action only to trusted adapter coordination."""
        with self.transaction() as db:
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

    def reconcile(
        self, run: str, action: str, execution: str, issue_key: str, arguments: dict
    ) -> None:
        """Record a positively verified uncertain create; never reopen dispatch."""
        _, digest = canonical(arguments)
        with self.transaction() as db:
            row = db.execute(
                "SELECT a.*,r.project FROM actions a JOIN runs r ON r.id=a.run_id "
                "WHERE a.id=? AND a.run_id=?",
                (action, run),
            ).fetchone()
            if (
                row is None
                or row["state"] != "unknown"
                or row["execution_id"] != execution
                or row["digest"] != digest
                or not isinstance(issue_key, str)
                or not re.fullmatch(
                    re.escape(row["project"]) + r"-[1-9][0-9]*", issue_key
                )
                or "demo-action-" + action not in arguments["labels"]
            ):
                raise Denied("reconciliation_binding")
            db.execute(
                "UPDATE actions SET state='succeeded',issue_key=? "
                "WHERE id=? AND run_id=? AND state='unknown' AND execution_id=?",
                (issue_key, action, run, execution),
            )
            self.event(
                db,
                run,
                action,
                "reconciled",
                {"issue_key": issue_key, "digest": digest},
            )

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
                    or canonical(json.loads(row["payload"]))[1] != digest
                    or "demo-action-" + action not in json.loads(row["payload"])["labels"]
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
            reason = "project_read" if allowed else "project_permission"
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
            actions = [
                dict(a)
                for a in db.execute(
                    "SELECT * FROM actions WHERE run_id=? ORDER BY rowid", (run,)
                )
            ]
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
