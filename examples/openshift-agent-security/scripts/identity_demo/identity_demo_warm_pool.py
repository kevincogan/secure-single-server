# SPDX-License-Identifier: Apache-2.0
"""Durable bounded inventory for unused single-use contexts, never authorization.

Only the existing authenticated operator can enable or acknowledge retirement.
Run allocation shares the authorization database transaction. Unknown native
mutations become counted quarantines; they are never retried as fresh creates.
"""
from __future__ import annotations

import json
import hashlib
import re
import sqlite3
import time
from uuid import uuid4

from identity_demo_run_store import Denied, RunStore
import identity_demo_pool_profiles as profiles

LIMIT = 12


def initialize(db: sqlite3.Connection) -> None:
    db.executescript('''
      BEGIN IMMEDIATE;
      CREATE TABLE IF NOT EXISTS console_pool_settings (
        id INTEGER PRIMARY KEY CHECK(id=1), enabled INTEGER NOT NULL,
        receipt TEXT NOT NULL, updated INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS console_pool_items (
        id TEXT PRIMARY KEY, workload TEXT UNIQUE, context TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN
          ('preparing','ready','allocated','consumed','retiring','quarantined','retired')),
        disposable INTEGER NOT NULL, receipt TEXT NOT NULL, updated INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS pool_state_updated ON console_pool_items(state,updated,id);
      CREATE TABLE IF NOT EXISTS console_pool_state_counts (
        state TEXT PRIMARY KEY, n INTEGER NOT NULL CHECK(n>=0));
      WITH states(state) AS (VALUES ('preparing'),('ready'),('allocated'),
          ('consumed'),('retiring'),('quarantined'),('retired'))
      INSERT OR IGNORE INTO console_pool_state_counts
        SELECT state,(SELECT count(*) FROM console_pool_items p WHERE p.state=states.state)
        FROM states WHERE NOT EXISTS
          (SELECT 1 FROM console_pool_state_counts c WHERE c.state=states.state);
      CREATE TRIGGER IF NOT EXISTS console_pool_count_insert
        AFTER INSERT ON console_pool_items BEGIN
          UPDATE console_pool_state_counts SET n=n+1 WHERE state=NEW.state;
        END;
      CREATE TRIGGER IF NOT EXISTS console_pool_count_delete
        AFTER DELETE ON console_pool_items BEGIN
          UPDATE console_pool_state_counts SET n=n-1 WHERE state=OLD.state;
        END;
      CREATE TRIGGER IF NOT EXISTS console_pool_count_update
        AFTER UPDATE OF state ON console_pool_items WHEN OLD.state<>NEW.state BEGIN
          UPDATE console_pool_state_counts SET n=n-1 WHERE state=OLD.state;
          UPDATE console_pool_state_counts SET n=n+1 WHERE state=NEW.state;
        END;
      COMMIT;
    ''')
    profiles.initialize(db)


def enabled(db: sqlite3.Connection) -> bool:
    # RunStore can be used independently before console migrations have run.
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='console_pool_settings'").fetchone():
        return False
    row = db.execute('SELECT enabled FROM console_pool_settings WHERE id=1').fetchone()
    return bool(row and row[0])


def blocks_execution(db: sqlite3.Connection) -> bool:
    """Legacy/shared preparation still excludes execution; isolated auto work does not."""
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='console_preparations'").fetchone():
        return False
    automatic = enabled(db)
    return any(not automatic or not json.loads(r['target']).get('automatic')
               for r in db.execute("SELECT target FROM console_preparations WHERE state IN ('preparing','blocked')"))


def blocked_identity(db: sqlite3.Connection, workload: str) -> bool:
    """Retirement/quarantine is durable even when automatic scheduling is disabled."""
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='console_pool_items'").fetchone():
        return False
    return bool(db.execute("SELECT 1 FROM console_pool_items WHERE workload=? "
                           "AND state IN ('retiring','quarantined','retired')", (workload,)).fetchone())


def ready(db: sqlite3.Connection, workload: str) -> bool:
    if blocked_identity(db, workload):
        return False
    configuration = profiles.configuration(db)
    if (configuration and not profiles.ready(db, workload)) or (not configuration and db.execute(
            'SELECT 1 FROM console_pool_settings WHERE id=1').fetchone()):
        return False
    return not enabled(db) or bool(db.execute(
        "SELECT 1 FROM console_pool_items WHERE workload=? AND state='ready'", (workload,)).fetchone())


def allocate(db: sqlite3.Connection, workload: str) -> None:
    if not ready(db, workload):
        raise Denied('context_unavailable')
    if enabled(db) and db.execute("UPDATE console_pool_items SET state='allocated',updated=? "
            "WHERE workload=? AND state='ready'", (int(time.time()), workload)).rowcount != 1:
        raise Denied('context_unavailable')


def closed(db: sqlite3.Connection, workload: str) -> bool:
    run = db.execute('SELECT id,active FROM runs WHERE workload=?', (workload,)).fetchone()
    if not run or run['active'] or db.execute(
            "SELECT 1 FROM actions WHERE run_id=? AND state IN ('executing','unknown')", (run['id'],)).fetchone():
        return False
    jobs = db.execute('SELECT state,evidence FROM console_jobs WHERE run_id=?', (run['id'],)).fetchall()
    return all(j['state'] in ('completed', 'failed') and json.loads(j['evidence']).get('cleanup_verified') is True for j in jobs)


def retirement_identity(context: dict) -> str:
    from execution_context import ExecutionContext
    return profiles.digest({field: context.get(field) for field in ExecutionContext.__dataclass_fields__})


def pause(db: sqlite3.Connection, contexts: list[dict], receipt: str, retired: dict[str, str]) -> None:
    """Pause profiles or stage exact legacy inventory for guarded migration."""
    if (not isinstance(receipt, str) or not re.fullmatch('[a-f0-9]{64}', receipt)
            or not isinstance(retired, dict) or len(retired) > 32
            or any(not isinstance(value, str) or not re.fullmatch('[a-f0-9]{64}', value)
                   for value in retired.values())):
        raise Denied('pool_configuration')
    now = int(time.time())
    if profiles.configuration(db):
        if retired:
            raise Denied('pool_retirement_receipt')
    else:
        sync_closed(db)
        known = {context['workload']: context for context in contexts}
        if retired and (enabled(db) or any(workload not in known
                or retirement_identity(known[workload]) != digest or not closed(db, workload)
                for workload, digest in retired.items())):
            raise Denied('pool_retirement_receipt')
        for workload, context in known.items():
            existing = db.execute('SELECT context,state FROM console_pool_items WHERE workload=?',
                                  (workload,)).fetchone()
            encoded = json.dumps(context, sort_keys=True)
            if existing and existing['context'] != encoded:
                raise Denied('pool_context_changed')
            if workload in retired:
                # Old paused pools left used rows ready. The exact identity and
                # closed run above still need to match the retirement proof.
                if existing and existing['state'] not in ('ready', 'consumed', 'retired'):
                    raise Denied('pool_retirement_receipt')
                state = 'retired'
            elif existing:
                continue
            else:
                used = db.execute('SELECT 1 FROM runs WHERE workload=?', (workload,)).fetchone()
                state = 'consumed' if used else 'ready'
            if existing:
                db.execute("UPDATE console_pool_items SET state='retired',receipt=?,updated=? WHERE workload=?",
                           (receipt, now, workload))
            else:
                db.execute('INSERT INTO console_pool_items VALUES(?,?,?,?,?,?,?)',
                           (uuid4().hex, workload, encoded, state, 0, receipt, now))
        db.execute("UPDATE console_batches SET state='superseded',updated=? WHERE state IN ('holding','preparing')", (now,))
    db.execute('INSERT INTO console_pool_settings VALUES(1,0,?,?) ON CONFLICT(id) DO UPDATE SET '
               'enabled=0,receipt=excluded.receipt,updated=excluded.updated', (receipt, now))


def sync_closed(db: sqlite3.Connection) -> None:
    for row in db.execute("SELECT workload FROM console_pool_items WHERE state='allocated'").fetchall():
        if closed(db, row['workload']):
            db.execute("UPDATE console_pool_items SET state='consumed',updated=? WHERE workload=?",
                       (int(time.time()), row['workload']))


def status(db: sqlite3.Connection, *, synchronize: bool = True) -> dict | None:
    if not enabled(db) or not profiles.configuration(db):
        return None
    if synchronize:
        sync_closed(db)
    return profiles.snapshot(db)


def next_target(db: sqlite3.Connection) -> dict | None:
    if enabled(db) and profiles.configuration(db):
        sync_closed(db)
        return profiles.next_target(db, closed)
    return None


def reserved(db: sqlite3.Connection, reservation: dict) -> None:
    target = reservation['target']
    if target['operation'] == 'verify':
        db.execute("UPDATE console_pool_items SET state='preparing',updated=? WHERE id=? AND state='ready'", (int(time.time()),target['item_id']))
    if target['operation'] == 'prepare':
        db.execute('INSERT INTO console_pool_items VALUES(?,NULL,?,\'preparing\',1,\'\',?)',
                   (reservation['id'], json.dumps(target, sort_keys=True), int(time.time())))


def reverification_target(db: sqlite3.Connection, failure: str, receipt: str) -> dict:
    """Bind a fresh read-only check to the current quarantine of an unused identity."""
    row = db.execute("SELECT target FROM console_preparations WHERE id=? AND state='quarantined' AND receipt=?",
                     (failure, receipt)).fetchone()
    old = json.loads(row['target']) if row else {}
    if old.get('operation') != 'verify' or old.get('automatic') is not True:
        raise Denied('quarantine_binding')
    item = db.execute("SELECT workload,context FROM console_pool_items WHERE id=? AND state='quarantined' AND receipt=?",
                      (old.get('item_id'), receipt)).fetchone()
    previous = old.get('previous')
    if (not item or not isinstance(previous, dict) or not item['workload']
            or previous.get('workload') != item['workload'] or json.loads(item['context']) != previous
            or not db.execute('SELECT 1 FROM console_contexts WHERE workload=? AND context=?',
                              (item['workload'], item['context'])).fetchone()
            or db.execute('SELECT 1 FROM runs WHERE workload=?', (item['workload'],)).fetchone()):
        raise Denied('quarantine_binding')
    profile = profiles.profile_for(db, previous.get('profile_id'))
    if previous.get('profile_fingerprint') != profiles.fingerprint(profile):
        raise Denied('quarantine_binding')
    return {'operation': 'verify', 'automatic': True, 'item_id': old['item_id'], 'previous': previous,
            'role': previous['role'], 'profile_id': profile['id'], 'profile': profile,
            'recheck_of': failure, 'failure_sha256': receipt}


def finish(db: sqlite3.Connection, row: sqlite3.Row, context: dict | None, receipt: str) -> None:
    target = json.loads(row['target'])
    identifier = target.get('item_id', row['id'])
    if 'recheck_of' in target:
        checked = reverification_target(db, target['recheck_of'], target['failure_sha256'])
        if checked != {k: v for k, v in target.items() if k != 'suffix'}:
            raise Denied('quarantine_binding')
        RunStore.event(db, 'maintenance:'+row['id'], None,
                       'quarantine_reverified' if context is not None else 'quarantine_recheck_failed',
                       {'original_reservation': target['recheck_of'], 'receipt_sha256': receipt})
    if target.get('profile_id') and target['operation'] in ('prepare','verify'):
        profiles.finish(db,target,context)
    state = 'retired' if target['operation'] == 'retire' and context is not None else 'ready' if context is not None else 'quarantined'
    if context is not None and target['operation'] == 'prepare':
        db.execute('UPDATE console_pool_items SET workload=?,context=?,state=?,receipt=?,updated=? WHERE id=?',
                   (context['workload'], json.dumps(context, sort_keys=True), state, receipt, int(time.time()), identifier))
    else:
        db.execute('UPDATE console_pool_items SET state=?,receipt=?,updated=? WHERE id=?',
                   (state, receipt, int(time.time()), identifier))


def unused_retirement_gate(db: sqlite3.Connection, reservation: str | None = None) -> None:
    """Installer-only maintenance requires stopped scheduling and a certain idle lane."""
    if (enabled(db) or db.execute('SELECT 1 FROM runs WHERE active<>0').fetchone()
            or db.execute("SELECT 1 FROM actions WHERE state IN ('executing','unknown')").fetchone()
            or db.execute("SELECT 1 FROM console_jobs WHERE state IN ('queued','running')").fetchone()
            or any(json.loads(v[0]).get('failure_code') == 'recovery_required'
                   and json.loads(v[0]).get('cleanup_verified') is not True
                   for v in db.execute("SELECT evidence FROM console_jobs WHERE state='failed'"))):
        raise Denied('unused_retirement_not_idle')
    for table in ('console_worker', 'console_preparer'):
        if db.execute('SELECT 1 FROM '+table+' WHERE updated>?', (int(time.time())-45,)).fetchone():
            raise Denied('unused_retirement_workers_online')
    pending = db.execute("SELECT id FROM console_preparations WHERE state IN ('preparing','blocked')").fetchall()
    if any(v['id'] != reservation for v in pending):
        raise Denied('unused_retirement_preparation_active')


def quarantine_unused(db: sqlite3.Connection, workload: str, context_sha256: str,
                      reservation: str, review_sha256: str) -> dict:
    """Reserve an unused identity for human-installer retirement, never a fake run.

    Not exposed through any runtime/browser API. The caller fences the actual
    processes and verifies exact resource UIDs before this atomic transaction.
    A crash leaves a counted quarantine and blocked maintenance reservation.
    """
    if (not isinstance(reservation, str) or not re.fullmatch('[a-f0-9]{32}', reservation)
            or any(not isinstance(v, str) or not re.fullmatch('[a-f0-9]{64}', v)
                   for v in (context_sha256, review_sha256))):
        raise Denied('unused_retirement_receipt')
    unused_retirement_gate(db)
    row = unused_context(db, workload, context_sha256)
    target = {'operation': 'retire-unused', 'automatic': False, 'item_id': row['id'],
              'workload': workload, 'context_sha256': context_sha256, 'review_sha256': review_sha256}
    now = int(time.time())
    db.execute("INSERT INTO console_preparations(id,owner,state,target,updated,receipt) "
               "VALUES(?,?,'blocked',?,?,?)", (reservation, 'installer-'+reservation,
               json.dumps(target, sort_keys=True), now, review_sha256))
    db.execute("UPDATE console_pool_items SET state='quarantined',receipt=?,updated=? WHERE id=?",
               (review_sha256, now, row['id']))
    RunStore.event(db, 'maintenance:'+reservation, None, 'unused_retirement_quarantined',
                   {'workload': workload, 'receipt_sha256': review_sha256})
    return {'id': reservation, 'target': target, 'state': 'blocked'}


def unused_context(db: sqlite3.Connection, workload: str, context_sha256: str) -> sqlite3.Row:
    """Read-only binding check shared by planning and the atomic quarantine."""
    row = db.execute('SELECT * FROM console_pool_items WHERE workload=?', (workload,)).fetchone()
    if (not row or row['state'] != 'ready'
            or hashlib.sha256(row['context'].encode()).hexdigest() != context_sha256
            or db.execute('SELECT 1 FROM runs WHERE workload=?', (workload,)).fetchone()):
        raise Denied('unused_retirement_identity')
    return row


def unused_retirement(db: sqlite3.Connection, reservation: str, review_sha256: str) -> dict:
    """Read the exact durable quarantine; never infer cleanup or retry a mutation."""
    unused_retirement_gate(db, reservation)
    row = db.execute('SELECT * FROM console_preparations WHERE id=?', (reservation,)).fetchone()
    if (not row or row['state'] != 'blocked' or row['owner'] != 'installer-'+reservation
            or row['receipt'] != review_sha256):
        raise Denied('unused_retirement_binding')
    target = json.loads(row['target'])
    if (target.get('operation') != 'retire-unused' or target.get('automatic') is not False
            or target.get('review_sha256') != review_sha256):
        raise Denied('unused_retirement_binding')
    item = db.execute('SELECT * FROM console_pool_items WHERE id=? AND workload=?',
                      (target['item_id'], target['workload'])).fetchone()
    if (not item or item['state'] != 'quarantined' or item['receipt'] != review_sha256
            or hashlib.sha256(item['context'].encode()).hexdigest() != target['context_sha256']
            or db.execute('SELECT 1 FROM runs WHERE workload=?', (target['workload'],)).fetchone()):
        raise Denied('unused_retirement_identity')
    return target


def complete_unused_retirement(db: sqlite3.Connection, reservation: str,
                               review_sha256: str, absence_sha256: str) -> None:
    """Installer confirms exact native absence; preserve immutable context/history."""
    if not isinstance(absence_sha256, str) or not re.fullmatch('[a-f0-9]{64}', absence_sha256):
        raise Denied('unused_retirement_receipt')
    target = unused_retirement(db, reservation, review_sha256)
    now = int(time.time())
    db.execute("UPDATE console_pool_items SET state='retired',receipt=?,updated=? WHERE id=?",
               (absence_sha256, now, target['item_id']))
    db.execute("UPDATE console_preparations SET state='completed',updated=?,receipt=? WHERE id=?",
               (now, absence_sha256, reservation))
    RunStore.event(db, 'maintenance:'+reservation, None, 'unused_retirement_completed',
                   {'workload': target['workload'], 'absence_sha256': absence_sha256})


def confirm_failed_creation_absent(db: sqlite3.Connection, reservation: str,
                                  failure_sha256: str, target_sha256: str,
                                  absence_sha256: str) -> None:
    """Installer confirms absence after fencing and exact native/resource review.

    No runtime endpoint exposes this operation. Keep the original quarantined
    preparation, failed target and receipt; retire only its counted capacity.
    The trusted caller verifies backup, resource UIDs and native absence first.
    """
    unused_retirement_gate(db)
    if (not isinstance(reservation, str) or not re.fullmatch('[a-f0-9]{32}', reservation)
            or any(not isinstance(v, str) or not re.fullmatch('[a-f0-9]{64}', v)
                   for v in (failure_sha256, target_sha256, absence_sha256))):
        raise Denied('failed_creation_receipt')
    preparation = db.execute('SELECT * FROM console_preparations WHERE id=?', (reservation,)).fetchone()
    item = db.execute('SELECT * FROM console_pool_items WHERE id=?', (reservation,)).fetchone()
    if (not preparation or preparation['state'] != 'quarantined'
            or preparation['receipt'] != failure_sha256 or not item or item['workload'] is not None
            or item['context'] != preparation['target']
            or hashlib.sha256(item['context'].encode()).hexdigest() != target_sha256):
        raise Denied('failed_creation_binding')
    target = json.loads(preparation['target'])
    if (target.get('operation') != 'prepare' or target.get('automatic') is not True
            or target.get('previous') is not None):
        raise Denied('failed_creation_binding')
    detail = {'failure_sha256': failure_sha256, 'target_sha256': target_sha256,
              'absence_sha256': absence_sha256}
    previous = db.execute("SELECT detail FROM audit WHERE run_id=? AND event='failed_creation_absence_confirmed'",
                          ('maintenance:'+reservation,)).fetchall()
    if (item['state'] == 'retired' and item['receipt'] == absence_sha256
            and len(previous) == 1 and json.loads(previous[0]['detail']) == detail):
        return  # Confirm a known completed outcome; never repeat native cleanup.
    if item['state'] != 'quarantined' or item['receipt'] != failure_sha256 or previous:
        raise Denied('failed_creation_binding')
    db.execute("UPDATE console_pool_items SET state='retired',receipt=?,updated=? WHERE id=?",
               (absence_sha256, int(time.time()), reservation))
    RunStore.event(db, 'maintenance:'+reservation, None, 'failed_creation_absence_confirmed', detail)
