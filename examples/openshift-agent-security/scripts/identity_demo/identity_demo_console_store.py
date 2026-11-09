# SPDX-License-Identifier: Apache-2.0
"""Durable single-flight coordination metadata; never an authorization substitute."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
import time
from uuid import uuid4

from identity_demo_run_store import Denied, RunStore, scoped_read_jql
import identity_demo_warm_pool as warm
import identity_demo_pool_profiles as profiles
from provider_contract import MODEL

STAGES = {"preparing_identity", "identity_verified", "assessment_running", "awaiting_approval",
          "protected_execution", "outcome_verified", "completed", "execution_failed", "inference_failed", "cancelled",
          "configuring_gateway", "waiting_gateway", "attaching_credentials", "verifying_native_read",
          "discovering_tools", "tools_discovered", "egress_verified", "model_inference", "restoring_environment", "expired", "retrying_identity", "agent_reasoning", "agent_read_requested", "agent_read_complete",
          "agent_read_denied", "agent_query_rejected", "checking_project_boundary", "project_boundary_verified", "agent_draft_ready", "draft_validated", "agent_retry", "agent_failed", "agent_stopping"}
BOOL_EVIDENCE = {"native_bound_read", "model_inference", "gateway_ready", "egress_denied",
                 "final_token_renewal", "backend_fields_match_approval", "live_run_identity_check",
                 "actual_arguments_and_approval_check", "scoped_adapter_service_token_delivery", "cleanup_verified", "jira_preview_ready", "scope_probe_denied"}


def safe_evidence(value: object) -> dict:
    """Reject arbitrary coordinator text, URLs, private certificate material and secrets."""
    if not isinstance(value, dict):
        raise Denied("console_evidence")
    for key, item in value.items():
        if key == "scenario_version" and item == "remediation-v1":
            continue
        if key == "failure_code" and item in ("session_expired", "model_unavailable", "native_read_failed",
                "preparation_failed", "recovery_required", "cancelled", "control_unavailable", "agent_failed"):
            continue
        if key in ("agent_turn", "agent_read_count") and type(item) is int and 1 <= item <= 4:
            continue
        if key == "scope_probe_project" and item == 'TEST':
            continue
        if key == "scope_probe_status" and type(item) is int and item == 403:
            continue
        if key == "agent_retry_count" and type(item) is int and 1 <= item <= 3:
            continue
        if key == "agent_retry_boundary" and item in ("model", "governed_read"):
            continue
        if key == "jira_issue_count" and type(item) is int and 0 <= item <= 10:
            continue
        if key == "jira_project" and isinstance(item, str) and re.fullmatch(r"[A-Z][A-Z0-9]{1,15}", item):
            continue
        if key in ("agent_query", "jira_query") and isinstance(item, str) and len(item) <= 160 and re.fullmatch(
                r"project = [A-Z][A-Z0-9]{1,15}(?: AND key = [A-Z][A-Z0-9]{1,15}-[1-9][0-9]*)?", item):
            continue
        if key == "agent_denial_reason" and item in ("project_permission", "run_inactive", "user_permission", "workload_permission"):
            continue
        if key == "agent_error_category" and item in ("model_unavailable", "model_output_invalid", "governed_read_failed",
                "agent_timeout", "retry_limit", "turn_limit", "project_permission", "invalid_jql", "backend_project",
                "read_schema", "result_limit", "read_required", "unauthorised_tool", "action_schema", "invalid_text",
                "denial_schema", "inference_receipt", "model_schema", "invalid_project", "duplicate_field", "draft_schema",
                "invalid_json", "one_read_per_turn", "incomplete_output", "model_output_limit", "invalid_deadline", "agent_validation_failed", "agent_transport_failed", "scope_probe_failed", "agent_context_limit", "diagnostic_not_observed"):
            continue
        if key == "jira_issues" and isinstance(item, list) and len(item) <= 10 and len(json.dumps(item).encode()) <= 5000:
            for issue in item:
                if (not isinstance(issue, dict) or set(issue) != {"key", "summary", "status"}
                        or not isinstance(issue["key"], str) or not re.fullmatch(r"[A-Z][A-Z0-9]{1,15}-[1-9][0-9]*", issue["key"])
                        or any(not isinstance(issue[field], str) or not 1 <= len(issue[field]) <= limit
                               or any(ord(c) < 32 for c in issue[field]) for field, limit in (("summary", 160), ("status", 50)))):
                    raise Denied("console_evidence")
            continue
        if key == "native_read_retries" and type(item) is int and 1 <= item <= 2:
            continue
        if key in BOOL_EVIDENCE and type(item) is bool:
            continue
        if key in ("backend_before", "backend_after") and type(item) is int and 0 <= item < 1_000_000:
            continue
        if key == "model" and item == MODEL:
            continue
        if key == "verified_issue_key" and isinstance(item, str) and re.fullmatch(r"[A-Z][A-Z0-9]{1,15}-[1-9][0-9]*", item):
            continue
        if key == "gateway_backend_services" and isinstance(item, list) and len(item) <= 20 and all(
                isinstance(v, str) and re.fullmatch(r"[a-z0-9-]{1,63}", v) for v in item):
            continue
        if key == "tool_schemas" and isinstance(item, list) and len(item) <= 20:
            for tool in item:
                if (not isinstance(tool, dict) or set(tool) != {"name", "arguments"}
                        or not isinstance(tool["name"], str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,100}", tool["name"])
                        or not isinstance(tool["arguments"], list) or len(tool["arguments"]) > 20):
                    raise Denied("console_evidence")
                for arg in tool["arguments"]:
                    if (not isinstance(arg, dict) or set(arg) != {"name", "type", "required"}
                            or not isinstance(arg["name"], str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,100}", arg["name"])
                            or arg["type"] not in ("string", "integer", "number", "boolean", "object", "array", "schema-defined")
                            or type(arg["required"]) is not bool):
                        raise Denied("console_evidence")
            continue
        if key == "tool_names" and isinstance(item, list) and len(item) <= 20 and all(
                isinstance(v, str) and re.fullmatch(r"[a-zA-Z0-9_-]{1,100}", v) for v in item):
            continue
        raise Denied("console_evidence")
    return value


class ConsoleStore:
    """Keep console jobs alongside existing durable runs with one active execution."""

    def __init__(self, store: RunStore) -> None:
        """Add independent metadata tables without rewriting accepted run/action history."""
        self.store = store
        with store.transaction() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS console_jobs (
              run_id TEXT PRIMARY KEY REFERENCES runs(id), workflow TEXT NOT NULL,
              state TEXT NOT NULL, stage TEXT NOT NULL, worker TEXT,
              updated INTEGER NOT NULL, evidence TEXT NOT NULL);
            CREATE UNIQUE INDEX IF NOT EXISTS console_one_active ON console_jobs((1))
              WHERE state IN ('queued','running');
            CREATE TABLE IF NOT EXISTS console_contexts (
              workload TEXT PRIMARY KEY, context TEXT NOT NULL,
              namespace TEXT NOT NULL, name TEXT NOT NULL, UNIQUE(namespace,name));
            CREATE TABLE IF NOT EXISTS console_preparer (
              id INTEGER PRIMARY KEY CHECK(id=1), updated INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS console_preparations (
              id TEXT PRIMARY KEY, owner TEXT NOT NULL, state TEXT NOT NULL,
              target TEXT NOT NULL, updated INTEGER NOT NULL, receipt TEXT NOT NULL DEFAULT '');
            CREATE UNIQUE INDEX IF NOT EXISTS console_one_preparation ON console_preparations((1))
              WHERE state IN ('preparing','blocked');
            CREATE UNIQUE INDEX IF NOT EXISTS console_one_queued_recheck ON console_preparations((1))
              WHERE state='queued';
            CREATE TABLE IF NOT EXISTS console_batches (
              id TEXT PRIMARY KEY, plan TEXT NOT NULL, state TEXT NOT NULL,
              run_rowid INTEGER NOT NULL, updated INTEGER NOT NULL,
              receipt TEXT NOT NULL DEFAULT '', release_receipt TEXT NOT NULL DEFAULT '');
            CREATE UNIQUE INDEX IF NOT EXISTS console_one_batch ON console_batches((1))
              WHERE state IN ('preparing','holding');
            CREATE TABLE IF NOT EXISTS console_worker (
              id INTEGER PRIMARY KEY CHECK(id=1), worker TEXT NOT NULL, updated INTEGER NOT NULL);
            """)
            batch_columns = {r[1] for r in db.execute("PRAGMA table_info(console_batches)")}
            for name in ('requested_by', 'verification_state'):
                if name not in batch_columns:
                    db.execute('ALTER TABLE console_batches ADD COLUMN ' + name + " TEXT NOT NULL DEFAULT ''")
            columns = {r[1] for r in db.execute("PRAGMA table_info(console_worker)")}
            for name, definition in (("phase", "TEXT NOT NULL DEFAULT 'ready'"),
                                     ("reason", "TEXT NOT NULL DEFAULT ''"),
                                     ("catalog_expires", "INTEGER NOT NULL DEFAULT 0"),
                                     ("checked_at", "INTEGER NOT NULL DEFAULT 0")):
                if name not in columns:
                    db.execute("ALTER TABLE console_worker ADD COLUMN " + name + " " + definition)

        with self.store.transaction() as db:
            warm.initialize(db)

    @staticmethod
    def recovery_required(db: sqlite3.Connection) -> bool:
        """Keep incomplete cleanup blocked across process replacement and lease renewal."""
        return any(json.loads(row[0]).get('failure_code') == 'recovery_required'
                   and json.loads(row[0]).get('cleanup_verified') is not True
                   for row in db.execute("SELECT evidence FROM console_jobs WHERE state='failed'"))

    def available(self, enabled: bool) -> dict:
        """Distinguish liveness, checked readiness and recovery without exposing secrets."""
        with self.store.read_transaction() as db:
            worker = db.execute("SELECT * FROM console_worker WHERE id=1").fetchone()
            busy = db.execute("SELECT count(*) FROM console_jobs WHERE state IN ('queued','running')").fetchone()[0]
            uncertain = db.execute("SELECT count(*) FROM actions WHERE state IN ('executing','unknown')").fetchone()[0]
            running = db.execute("SELECT count(*) FROM console_jobs WHERE state='running'").fetchone()[0]
            recovery = self.recovery_required(db)
            preparation = db.execute("SELECT state FROM console_preparations WHERE state IN ('preparing','blocked')").fetchone()
            automatic = warm.status(db, synchronize=False)
            if automatic and not warm.blocks_execution(db):
                preparation = None
            batch = db.execute("SELECT state FROM console_batches WHERE state IN ('preparing','holding')").fetchone()
            preparer = db.execute("SELECT updated FROM console_preparer WHERE id=1").fetchone()
        online = bool(enabled and worker and worker['updated'] > time.time() - 20)
        phase = worker['phase'] if online else 'offline'
        reason = worker['reason'] if worker else ''
        catalog = worker['catalog_expires'] if worker else 0
        ready = online and phase == 'ready' and not uncertain and not recovery
        if ready and catalog and catalog <= time.time() + 600:
            ready, reason = False, 'catalog_expiring'
        if preparation:
            ready = False
            phase = 'blocked' if preparation['state'] == 'blocked' else 'preparing'
            reason = 'context_preparation_failed' if phase == 'blocked' else 'context_preparing'
            if phase == 'preparing' and batch and batch['state'] == 'preparing':
                reason = 'presentation_preparing'
        elif batch and batch['state'] == 'preparing':
            ready = False
            if online and (phase == 'ready' or (phase == 'preparing' and not reason)):
                phase, reason = 'preparing', 'presentation_preparing'
        return {"automatic_pool": automatic, "auto_prepare": bool(preparer and (preparer['updated'] > time.time() - 45 or preparation)),
                "preparing_context": bool(preparation or (batch and batch['state'] == 'preparing')),
                "enabled": enabled, "online": online, "ready": bool(ready), "busy": bool(busy or uncertain),
                "running": running, "uncertain": uncertain, "recovery_required": recovery,
                "phase": phase, "reason": 'recovery_required' if uncertain or recovery else reason,
                "last_seen": worker['updated'] if worker else None,
                "checked_at": worker['checked_at'] if worker else 0, "catalog_expires": catalog}

    def contexts(self, *, active_only: bool = False) -> tuple[dict, ...]:
        """Read immutable operator mappings; historical identities remain tombstoned."""
        with self.store.read_transaction() as db:
            if active_only and warm.enabled(db):
                return tuple(profiles.expand(db,[json.loads(r[0]) for r in db.execute("""SELECT c.context
                  FROM console_pool_items p JOIN console_contexts c ON c.workload=p.workload
                  WHERE p.state IN ('preparing','ready','allocated','consumed','retiring','quarantined')
                  ORDER BY c.rowid""")]))
            return tuple(profiles.expand(db,[json.loads(r[0]) for r in db.execute('SELECT context FROM console_contexts ORDER BY rowid')]))

    def context_for_workload(self, workload: str) -> dict | None:
        """Resolve a retained historical mapping by its immutable primary key."""
        with self.store.read_transaction() as db:
            row=db.execute('SELECT context FROM console_contexts WHERE workload=?',(workload,)).fetchone()
            values=profiles.expand(db,[json.loads(row[0])]) if row else []
            return values[0] if values else None

    @staticmethod
    def pool_contexts(db: sqlite3.Connection, configured: tuple[dict, ...]) -> list[dict]:
        """Count immutable mappings once; consumed identities never become spares again."""
        query = ("""SELECT c.context FROM console_pool_items p JOIN console_contexts c ON c.workload=p.workload
            WHERE p.state IN ('preparing','ready','allocated','consumed','retiring','quarantined')"""
            if warm.enabled(db) and profiles.configuration(db) else 'SELECT context FROM console_contexts')
        values = (*configured, *(json.loads(r[0]) for r in db.execute(query)))
        return list({c['workload']: c for c in values if c.get('console_prepared') is True}.values())

    @staticmethod
    def pool_counts(db: sqlite3.Connection, contexts: list[dict]) -> dict:
        """Report unused contexts without authorizing them."""
        workloads = [c['workload'] for c in contexts]
        used = set()
        blocked = set()
        for start in range(0,len(workloads),64):
            selected=workloads[start:start+64]
            used.update(r[0] for r in db.execute('SELECT workload FROM runs WHERE workload IN ('
                + ','.join('?' for _ in selected) + ')',selected))
            blocked.update(r[0] for r in db.execute("SELECT workload FROM console_pool_items "
                "WHERE state IN ('retiring','quarantined','retired') AND workload IN ("
                + ','.join('?' for _ in selected) + ')', selected))
        unused = [c for c in contexts if c['workload'] not in used and c['workload'] not in blocked]
        result = {'mapped': len(contexts), 'consumed': len(used & {c['workload'] for c in contexts}),
                  'unused': len(unused), 'contexts': [{**c, 'consumed': False} for c in unused]}
        return result

    def pool_status(self, configured: tuple[dict, ...], project: str, *, synchronize: bool = True) -> dict:
        """Expose accounting; display-only callers do not transition lifecycle state."""
        with (self.store.transaction() if synchronize else self.store.read_transaction()) as db:
            result = self.pool_counts(db, self.pool_contexts(db, configured))
            result['all_contexts'] = self.pool_contexts(db, configured)
            result['automatic'] = warm.status(db, synchronize=synchronize)
            if result['automatic']:
                managed = {r[0] for r in db.execute("SELECT workload FROM console_pool_items WHERE state<>'retired' AND workload IS NOT NULL")}
                result['all_contexts'] = [c for c in result['all_contexts'] if c['workload'] in managed]
                result['contexts'] = [c for c in result['contexts'] if warm.ready(db, c['workload'])]
                result['unused'] = len(result['contexts'])
            result['contexts'] = profiles.expand(db, result['contexts'])
            result['preparation_pending'] = bool(db.execute(
                "SELECT 1 FROM console_preparations WHERE state IN ('preparing','blocked')").fetchone())
            worker = db.execute('SELECT * FROM console_worker WHERE id=1').fetchone()
            result['worker'] = {k: worker[k] for k in ('phase', 'updated', 'checked_at', 'catalog_expires')} if worker else None
            return result

    @staticmethod
    def pool_idle(db: sqlite3.Connection) -> None:
        """Require the durable idle and recovery boundary for pool changes."""
        if (db.execute("SELECT 1 FROM console_preparations WHERE state IN ('queued','preparing','blocked')").fetchone()
                or db.execute("SELECT 1 FROM console_jobs WHERE state IN ('queued','running')").fetchone()
                or db.execute('SELECT 1 FROM runs WHERE active<>0').fetchone()
                or db.execute("SELECT 1 FROM actions WHERE state IN ('executing','unknown')").fetchone()
                or ConsoleStore.recovery_required(db)):
            raise Denied('presentation_not_idle')

    def pause_pool(self, receipt: str, retired: dict[str, str],
                   configured: tuple[dict, ...], project: str) -> dict:
        """Pause scheduling and record verified legacy retirement without deleting history."""
        with self.store.transaction() as db:
            self.pool_idle(db)
            warm.pause(db, self.pool_contexts(db, configured), receipt, retired)
        return self.pool_status(configured, project)

    def configure_profile_pool(self, configuration: dict, receipt: str,
                               configured: tuple[dict, ...], project: str) -> dict:
        with self.store.transaction() as db:
            self.pool_idle(db)
            if not profiles.configuration(db):
                if (warm.enabled(db)
                        or db.execute("SELECT 1 FROM console_batches WHERE state IN ('preparing','holding')").fetchone()
                        or db.execute("SELECT 1 FROM console_pool_items WHERE state<>'retired'").fetchone()):
                    raise Denied('legacy_contexts_not_retired')
                retired = {row[0] for row in db.execute("SELECT workload FROM console_pool_items WHERE state='retired'")}
                if any(context['workload'] not in retired for context in self.pool_contexts(db, configured)):
                    raise Denied('legacy_contexts_not_retired')
            profiles.configure(db, configuration, receipt)
        return self.pool_status(configured, project)

    def context_ready(self, workload: str) -> bool:
        with self.store.read_transaction() as db:
            return warm.ready(db, workload)

    @staticmethod
    def reserve_preparation(db: sqlite3.Connection, contexts: list[dict], owner: str,
                            target: dict, *, queued: bool = False) -> dict:
        """Reserve an unoccupied native name and the sole shared preparation lane atomically."""
        names = {c.get('sandbox_name') for c in contexts}
        for row in db.execute('SELECT target FROM console_preparations'):
            previous = json.loads(row[0])
            if previous.get('operation') == 'retire-unused':
                item = db.execute('SELECT context FROM console_pool_items WHERE id=? AND workload=?',
                                  (previous['item_id'], previous['workload'])).fetchone()
                if not item or hashlib.sha256(item[0].encode()).hexdigest() != previous['context_sha256']:
                    raise Denied('unused_retirement_binding')
                names.add(json.loads(item[0])['sandbox_name'])
            else:
                names.add('demo-s56-' + previous['role'] + '-' + previous['suffix'])
        for _ in range(32):
            suffix = ''.join(secrets.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(3))
            if 'demo-s56-' + target['role'] + '-' + suffix not in names:
                break
        else:
            raise Denied('preparation_names')
        target = {**target, 'suffix': suffix}
        reservation = uuid4().hex
        db.execute("INSERT INTO console_preparations(id,owner,state,target,updated) VALUES(?,?,?,?,?)",
                   (reservation, owner, 'queued' if queued else 'preparing', json.dumps(target, sort_keys=True), int(time.time())))
        return {'id': reservation, 'target': target}

    def queue_quarantine_recheck(self, failure: str, receipt: str, configured: tuple[dict, ...]) -> str:
        """Accept one reviewed retry, leaving the context quarantined until verification succeeds."""
        self.worker_id(failure)
        if not isinstance(receipt, str) or not re.fullmatch('[a-f0-9]{64}', receipt):
            raise Denied('preparation_receipt')
        with self.store.transaction() as db:
            if not warm.enabled(db):
                raise Denied('automatic_pool_disabled')
            target = warm.reverification_target(db, failure, receipt)
            for row in db.execute("SELECT id,state,target FROM console_preparations WHERE state IN ('queued','preparing')"):
                existing = json.loads(row['target']).get('recheck_of')
                if existing == failure:
                    return row['id']
                if row['state'] == 'queued' or existing is not None:
                    raise Denied('quarantine_recheck_pending')
            reserved = self.reserve_preparation(db, self.pool_contexts(db, configured), '', target, queued=True)
            self.store.event(db, 'maintenance:'+reserved['id'], None, 'quarantine_recheck_requested',
                             {'original_reservation': failure, 'receipt_sha256': receipt})
            return reserved['id']

    def prepare_next(self, owner: str, configured: tuple[dict, ...], project: str) -> dict | None:
        """Reserve one isolated profile operation after readiness and recovery gates."""
        self.worker_id(owner)
        with self.store.transaction() as db:
            db.execute("INSERT INTO console_preparer VALUES(1,?) ON CONFLICT(id) DO UPDATE SET updated=excluded.updated", (int(time.time()),))
            if not warm.enabled(db) or not profiles.configuration(db):
                return None
            pending = db.execute("SELECT * FROM console_preparations WHERE state IN ('preparing','blocked')").fetchone()
            if pending:
                if pending['owner'] != owner or pending['state'] == 'blocked':
                    return None
                return {'id': pending['id'], 'target': json.loads(pending['target'])}
            worker = db.execute('SELECT * FROM console_worker WHERE id=1').fetchone()
            if (not worker or worker['updated'] <= time.time() - 20 or worker['phase'] != 'ready'
                    or worker['checked_at'] < time.time() - 90
                    or (worker['catalog_expires'] and worker['catalog_expires'] <= time.time() + 600)
                    or self.recovery_required(db)
                    or db.execute("SELECT 1 FROM actions WHERE state IN ('executing','unknown')").fetchone()):
                return None
            recheck = db.execute("SELECT id,target FROM console_preparations WHERE state='queued'").fetchone()
            if recheck:
                target = json.loads(recheck['target'])
                try:
                    checked = warm.reverification_target(db, target['recheck_of'], target['failure_sha256'])
                    if checked != {k: v for k, v in target.items() if k != 'suffix'}:
                        raise Denied('quarantine_binding')
                except Denied as error:
                    db.execute("UPDATE console_preparations SET state='cancelled',updated=? WHERE id=?",
                               (int(time.time()), recheck['id']))
                    self.store.event(db, 'maintenance:'+recheck['id'], None, 'quarantine_recheck_cancelled',
                                     {'reason': str(error)})
                else:
                    db.execute("UPDATE console_preparations SET state='preparing',owner=?,updated=? WHERE id=?",
                               (owner, int(time.time()), recheck['id']))
                    return {'id': recheck['id'], 'target': target}
            target = warm.next_target(db)
            if target is None:
                return None
            reservation = self.reserve_preparation(db, self.pool_contexts(db, configured), owner, target)
            warm.reserved(db, reservation)
            return reservation

    def finish_preparation(self, owner: str, reservation: str, context: dict | None, receipt: str) -> None:
        """Commit one attested context or retain an explicit recovery block; never reassign."""
        self.worker_id(owner)
        self.worker_id(reservation)
        if not isinstance(receipt, str) or not re.fullmatch('[a-f0-9]{64}', receipt):
            raise Denied('preparation_receipt')
        with self.store.transaction() as db:
            row = db.execute('SELECT * FROM console_preparations WHERE id=? AND owner=?', (reservation, owner)).fetchone()
            if not row:
                raise Denied('preparation_owner')
            target = json.loads(row['target'])
            if (row['state'] == 'quarantined' and 'recheck_of' in target
                    and context is None and row['receipt'] == receipt):
                return
            if row['state'] == 'completed' and json.loads(row['target']).get('operation') == 'retire':
                if row['receipt'] != receipt or context != json.loads(row['target'])['previous']:
                    raise Denied('preparation_replay')
                return
            if row['state'] == 'completed':
                if row['receipt'] != receipt or context is None or not db.execute(
                        'SELECT 1 FROM console_contexts WHERE workload=? AND context=?',
                        (context['workload'], json.dumps(context, sort_keys=True))).fetchone():
                    raise Denied('preparation_replay')
                return
            if row['state'] != 'preparing':
                raise Denied('preparation_blocked')
            if target.get('automatic') and target.get('operation') == 'retire':
                if context is not None and context != target['previous']:
                    raise Denied('retirement_binding')
                if context is not None and not warm.closed(db, context['workload']):
                    raise Denied('retirement_binding')
                warm.finish(db, row, context, receipt)
                db.execute('UPDATE console_preparations SET state=?,receipt=?,updated=? WHERE id=?',
                           ('completed' if context is not None else 'quarantined', receipt, int(time.time()), reservation))
                return
            if target.get('automatic') is not True or not target.get('profile_id'):
                raise Denied('legacy_preparation_requires_recovery')
            if target['operation'] == 'verify':
                if context is not None and context != target['previous']:
                    raise Denied('preparation_binding')
            elif context is not None:
                if (context['sandbox_name'] != 'demo-s56-' + target['role'] + '-' + target['suffix']
                        or db.execute('SELECT 1 FROM runs WHERE workload=?',(context['workload'],)).fetchone()):
                    raise Denied('preparation_binding')
                db.execute('INSERT INTO console_contexts VALUES(?,?,?,?)',
                           (context['workload'],json.dumps(context,sort_keys=True),context['namespace'],context['sandbox_name']))
            warm.finish(db,row,context,receipt)
            db.execute('UPDATE console_preparations SET state=?,receipt=?,updated=? WHERE id=?',
                       ('completed' if context is not None else 'quarantined', receipt, int(time.time()), reservation))

    def enqueue(self, run: str, workflow: str) -> None:
        """Accept only a server-created run and keep shared native configuration single-flight."""
        with self.store.transaction() as db:
            if db.execute("SELECT 1 FROM console_batches WHERE state='preparing'").fetchone():
                raise Denied('presentation_preparing')
            if warm.blocks_execution(db):
                raise Denied('context_preparing')
            try:
                evidence = {"scenario_version": "remediation-v1"} if workflow == "service-request" else {}
                db.execute("INSERT INTO console_jobs VALUES (?,?, 'queued','preparing_identity',NULL,?,?)",
                           (run, workflow, int(time.time()), json.dumps(evidence)))
            except sqlite3.IntegrityError as error:
                raise Denied("console_busy") from error
            self.store.event(db, run, None, "console_queued", {"workflow": workflow})

    @staticmethod
    def worker_id(value: object) -> str:
        """Use a bounded process identifier in addition to existing operator authentication."""
        if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{32}", value):
            raise Denied("console_worker")
        return value

    def heartbeat(self, worker: str, *, phase: str = 'ready', reason: str = '',
                  catalog_expires: int = 0, checked_at: int = 0) -> None:
        """Keep one live owner and publish only bounded operator readiness observations."""
        self.worker_id(worker)
        if (phase not in ('ready', 'preparing', 'reconnecting', 'blocked', 'stopping')
                or reason not in ('', 'cluster_unavailable', 'catalog_expiring', 'catalog_refresh_failed',
                                  'recovery_required', 'control_unavailable', 'invalid_configuration', 'identity_network', 'sender_trust', 'operator_login')
                or type(catalog_expires) is not int or type(checked_at) is not int
                or not 0 <= catalog_expires <= time.time() + 7200 or not 0 <= checked_at <= time.time() + 5):
            raise Denied('console_readiness')
        with self.store.transaction() as db:
            current = db.execute("SELECT * FROM console_worker WHERE id=1").fetchone()
            if current and current['worker'] != worker and current['updated'] > time.time() - 20:
                raise Denied("console_worker_busy")
            db.execute("""INSERT INTO console_worker (id,worker,updated,phase,reason,catalog_expires,checked_at)
              VALUES (1,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET worker=excluded.worker,
              updated=excluded.updated,phase=excluded.phase,reason=excluded.reason,
              catalog_expires=excluded.catalog_expires,checked_at=excluded.checked_at""",
              (worker, int(time.time()), phase, reason, catalog_expires, checked_at))

    def claim(self, worker: str) -> dict | None:
        """Claim a queued run once; abandoned running jobs are never automatically redispatched."""
        self.worker_id(worker)
        with self.store.transaction() as db:
            owner = db.execute("SELECT * FROM console_worker WHERE id=1").fetchone()
            if not owner or owner['worker'] != worker or owner['updated'] <= time.time() - 20:
                raise Denied("console_worker")
            if db.execute("SELECT 1 FROM console_batches WHERE state='preparing'").fetchone():
                return None
            if warm.blocks_execution(db):
                return None
            if self.recovery_required(db) or db.execute("SELECT count(*) FROM actions WHERE state IN ('executing','unknown')").fetchone()[0]:
                return None
            if (owner['phase'] != 'ready' or
                    (owner['catalog_expires'] and owner['catalog_expires'] <= time.time() + 600)):
                return None
            if db.execute("SELECT count(*) FROM console_jobs WHERE state='running'").fetchone()[0]:
                return None
            row = db.execute("SELECT j.*,r.user,r.workload,r.user_role,r.active,r.expires FROM console_jobs j JOIN runs r ON r.id=j.run_id WHERE j.state='queued' ORDER BY j.rowid LIMIT 1").fetchone()
            if not row:
                return None
            if not row['active'] or row['expires'] <= time.time():
                stage = 'expired' if row['expires'] <= time.time() else 'cancelled'
                db.execute("UPDATE console_jobs SET state='failed',stage=?,updated=?,evidence=? WHERE run_id=?", (stage, int(time.time()), json.dumps({**json.loads(row['evidence']), "cleanup_verified": True}), row['run_id']))
                db.execute("UPDATE runs SET active=0 WHERE id=?", (row['run_id'],))
                self.store.event(db, row['run_id'], None, 'console_' + stage, {})
                return None
            db.execute("UPDATE console_jobs SET state='running',worker=?,updated=? WHERE run_id=?", (worker, int(time.time()), row['run_id']))
            self.store.event(db, row['run_id'], None, "console_claimed", {})
            return {key: row[key] for key in ('run_id', 'workflow', 'user', 'workload', 'user_role')}

    def update(self, run: str, worker: str, stage: str, evidence: dict) -> None:
        """Record only bounded observed evidence for the exact claimed job."""
        self.worker_id(worker)
        if (not isinstance(run, str) or not re.fullmatch(r"[a-f0-9]{32}", run)
                or not isinstance(stage, str) or stage not in STAGES):
            raise Denied("console_stage")
        safe_evidence(evidence)
        with self.store.transaction() as db:
            row = db.execute("SELECT * FROM console_jobs WHERE run_id=?", (run,)).fetchone()
            if not row or row['worker'] != worker or row['state'] != 'running':
                raise Denied("console_claim")
            project = db.execute("SELECT project FROM runs WHERE id=?", (run,)).fetchone()[0]
            if any(key.startswith('scope_probe_') for key in evidence) and project != 'OPS':
                raise Denied('project_permission')
            if 'jira_project' in evidence and evidence['jira_project'] != project:
                raise Denied('project_permission')
            for field in ('agent_query', 'jira_query'):
                if field in evidence:
                    scoped_read_jql(evidence[field], project)
            if any(issue['key'].split('-', 1)[0] != project for issue in evidence.get('jira_issues', [])):
                raise Denied('project_permission')
            merged = {**json.loads(row['evidence']), **evidence}
            if row['stage'] == stage and merged == json.loads(row['evidence']):
                return
            state = 'completed' if stage == 'completed' else 'failed' if stage in ('execution_failed','inference_failed','cancelled','expired','agent_failed') else 'running'
            db.execute("UPDATE console_jobs SET state=?,stage=?,updated=?,evidence=? WHERE run_id=?",
                       (state, stage, int(time.time()), json.dumps(merged), run))
            self.store.event(db, run, None, 'console_' + stage, evidence)

    def review_recovery(self, run: str, receipt_sha256: str) -> None:
        """Record an explicit trusted operator review after reconciliation, never replay work."""
        if not isinstance(receipt_sha256, str) or not re.fullmatch(r'[a-f0-9]{64}', receipt_sha256):
            raise Denied('recovery_receipt')
        with self.store.transaction() as db:
            job = db.execute('SELECT j.*,r.active FROM console_jobs j JOIN runs r ON r.id=j.run_id WHERE j.run_id=?', (run,)).fetchone()
            if (not job or job['state'] != 'failed' or job['active']
                    or db.execute("SELECT count(*) FROM actions WHERE run_id=? AND state IN ('executing','unknown')", (run,)).fetchone()[0]):
                raise Denied('recovery_state')
            evidence = json.loads(job['evidence'])
            if evidence.get('failure_code') != 'recovery_required' or evidence.get('cleanup_verified') is True:
                raise Denied('recovery_state')
            evidence.update(cleanup_verified=True)
            db.execute('UPDATE console_jobs SET evidence=?,updated=? WHERE run_id=?', (json.dumps(evidence), int(time.time()), run))
            self.store.event(db, run, None, 'console_recovery_reviewed', {'receipt_sha256':receipt_sha256})

    def verified_issue_keys(self) -> list[str]:
        """Expose only synthetic issue references backed by independent outcome evidence."""
        with self.store.transaction() as db:
            rows = db.execute("""SELECT a.issue_key,r.project,j.evidence FROM actions a
                JOIN runs r ON r.id=a.run_id JOIN console_jobs j ON j.run_id=r.id
                WHERE a.state='succeeded' ORDER BY a.rowid DESC LIMIT 100""").fetchall()
        keys = []
        for row in rows:
            evidence = json.loads(row['evidence'])
            key = row['issue_key']
            if (row['project'] in ('TEST', 'SERVICE', 'OPS') and isinstance(key, str)
                    and re.fullmatch(re.escape(row['project']) + r'-[1-9][0-9]*', key)
                    and evidence.get('backend_fields_match_approval') is True
                    and evidence.get('verified_issue_key') == key):
                keys.append(key)
        return sorted(set(keys))

    def describe(self, run: str) -> dict | None:
        """Return display metadata without operator credentials or worker identifiers."""
        with self.store.read_transaction() as db:
            row = db.execute("SELECT state,stage,updated,evidence FROM console_jobs WHERE run_id=?", (run,)).fetchone()
        return {**dict(row), 'evidence': json.loads(row['evidence'])} if row else None

    def history(self, user: str) -> list[dict]:
        """Bound history to the authenticated owner and latest fifty runs."""
        with self.store.read_transaction() as db:
            rows = [dict(r) for r in db.execute("""SELECT r.id,r.user_role,r.workload_role,r.project,r.expires,r.active,
              (SELECT state FROM actions a WHERE a.run_id=r.id ORDER BY a.rowid DESC LIMIT 1) AS action_state,
              (SELECT workflow FROM console_jobs j WHERE j.run_id=r.id) AS workflow,
              (SELECT evidence FROM console_jobs j WHERE j.run_id=r.id) AS console_evidence,
              (SELECT state FROM console_jobs j WHERE j.run_id=r.id) AS console_state,
              (SELECT stage FROM console_jobs j WHERE j.run_id=r.id) AS console_stage,
              (SELECT detail FROM audit e WHERE e.run_id=r.id AND e.event='denied' ORDER BY e.rowid DESC LIMIT 1) AS denial_detail
              FROM runs r WHERE r.user=? ORDER BY r.rowid DESC LIMIT 50""", (user,))]
            for row in rows:
                row['scenario_version'] = json.loads(row.pop('console_evidence') or '{}').get('scenario_version')
            return rows
