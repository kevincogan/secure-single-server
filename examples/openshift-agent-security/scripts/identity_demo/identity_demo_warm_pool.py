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

LIMIT = 12
SLOTS = (('cve', 'triage', 'TEST'), ('cve', 'reader', 'TEST'),
         ('incident-triage', 'triage', 'OPS'), ('service-request', 'triage', 'SERVICE'))


def initialize(db: sqlite3.Connection) -> None:
    db.executescript('''
      CREATE TABLE IF NOT EXISTS console_pool_settings (
        id INTEGER PRIMARY KEY CHECK(id=1), enabled INTEGER NOT NULL,
        receipt TEXT NOT NULL, updated INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS console_pool_items (
        id TEXT PRIMARY KEY, workload TEXT UNIQUE, context TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN
          ('preparing','ready','allocated','consumed','retiring','quarantined','retired')),
        disposable INTEGER NOT NULL, receipt TEXT NOT NULL, updated INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS pool_state_updated ON console_pool_items(state,updated,id);
      CREATE INDEX IF NOT EXISTS pool_slot ON console_pool_items(
        coalesce(json_extract(context,'$.workflow'),'cve'),
        json_extract(context,'$.role'),
        coalesce(json_extract(context,'$.project'),'TEST'));
    ''')


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
    return not enabled(db) or bool(db.execute(
        "SELECT 1 FROM console_pool_items WHERE workload=? AND state='ready'", (workload,)).fetchone())


def allocate(db: sqlite3.Connection, workload: str) -> None:
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


def configure(db: sqlite3.Connection, contexts: list[dict], enable: bool,
              receipt: str, retired: list[str], *, initial_empty: bool = False) -> None:
    """Explicit idle migration; retirement receipts never erase immutable mappings."""
    if (type(enable) is not bool or type(initial_empty) is not bool or initial_empty and not enable
            or not isinstance(receipt, str) or not re.fullmatch('[a-f0-9]{64}', receipt)
            or not isinstance(retired, list) or len(retired) > 64
            or any(not isinstance(w, str) for w in retired) or len(set(retired)) != len(retired)):
        raise Denied('pool_configuration')
    slots = {(c.get('workflow', 'cve'), c['role'], c.get('project', 'TEST')) for c in contexts}
    if initial_empty:
        # Never reinterpret missing contexts or previous history as a clean install.
        tables = ('runs','actions','audit','console_preparations','console_batches',
                  'console_pool_items','console_pool_settings')
        if contexts or any(db.execute('SELECT 1 FROM '+table+' LIMIT 1').fetchone() for table in tables):
            raise Denied('pool_initial_state')
    elif enable and not set(SLOTS).issubset(slots):
        raise Denied('pool_slots_missing')
    known = {c['workload']: c for c in contexts}
    if any(w not in known or not closed(db, w) for w in retired):
        raise Denied('pool_retirement_receipt')
    now = int(time.time())
    for workload, c in known.items():
        used = db.execute('SELECT 1 FROM runs WHERE workload=?', (workload,)).fetchone()
        state = 'retired' if workload in retired else 'consumed' if used else 'ready'
        existing = db.execute('SELECT context,state FROM console_pool_items WHERE workload=?', (workload,)).fetchone()
        text = json.dumps(c, sort_keys=True)
        if existing:
            if existing['context'] != text:
                raise Denied('pool_context_changed')
            if workload in retired:
                db.execute("UPDATE console_pool_items SET state='retired',receipt=?,updated=? WHERE workload=?",
                           (receipt, now, workload))
            elif used and existing['state'] == 'ready':
                db.execute("UPDATE console_pool_items SET state='consumed',updated=? WHERE workload=?", (now, workload))
        else:
            db.execute('INSERT INTO console_pool_items VALUES(?,?,?,?,?,?,?)',
                       (uuid4().hex, workload, text, state, 0, receipt, now))
    if enable and db.execute("SELECT count(*) FROM console_pool_items WHERE state<>'retired'").fetchone()[0] > LIMIT:
        raise Denied('pool_capacity')
    db.execute("UPDATE console_batches SET state='superseded',updated=? WHERE state IN ('holding','preparing')", (now,))
    db.execute('INSERT INTO console_pool_settings VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET '
               'enabled=excluded.enabled,receipt=excluded.receipt,updated=excluded.updated', (int(enable), receipt, now))


def sync_closed(db: sqlite3.Connection) -> None:
    for row in db.execute("SELECT workload FROM console_pool_items WHERE state='allocated'").fetchall():
        if closed(db, row['workload']):
            db.execute("UPDATE console_pool_items SET state='consumed',updated=? WHERE workload=?",
                       (int(time.time()), row['workload']))


def status(db: sqlite3.Connection, *, synchronize: bool = True) -> dict | None:
    if not enabled(db):
        return None
    if synchronize:
        sync_closed(db)
    rows = db.execute("SELECT * FROM console_pool_items WHERE state<>'retired'").fetchall()
    slots = []
    for workflow, role, project in SLOTS:
        group = [r for r in rows if (lambda c: (c.get('workflow', 'cve'), c.get('role'), c.get('project', 'TEST')))(json.loads(r['context'])) == (workflow, role, project)]
        slots.append({'workflow': workflow, 'role': role, 'project': project, 'target': 2,
                      'available': sum(r['state'] == 'ready' for r in group),
                      'preparing': sum(r['state'] == 'preparing' for r in group)})
    counts = {state: 0 for state in
              ('preparing', 'ready', 'allocated', 'consumed', 'retiring', 'quarantined', 'retired')}
    counts.update({r['state']: r['n'] for r in db.execute(
        'SELECT state,count(*) AS n FROM console_pool_items GROUP BY state')})
    return {'mode': 'automatic', 'target': 8, 'limit': LIMIT, 'managed': len(rows),
            'states': counts, 'slots': slots}


def next_target(db: sqlite3.Connection) -> dict | None:
    snapshot = status(db)
    if snapshot is None:
        return None
    attempted = {slot: db.execute("SELECT max(rowid) FROM console_pool_items WHERE "
        "coalesce(json_extract(context,'$.workflow'),'cve')=? AND "
        "json_extract(context,'$.role')=? AND "
        "coalesce(json_extract(context,'$.project'),'TEST')=?", slot).fetchone()[0] or 0
        for slot in SLOTS}
    depleted = sorted((s for s in snapshot['slots'] if s['available'] < s['target']),
                      key=lambda s: (s['available'], attempted.get((s['workflow'], s['role'], s['project']), 0)))
    # Retire first at capacity, otherwise refill first. Consumed items eventually
    # retire even with a full ready pool, so native resources cannot accumulate.
    if snapshot['managed'] >= LIMIT or not depleted:
        item = db.execute("SELECT * FROM console_pool_items WHERE state='consumed' ORDER BY updated,id LIMIT 1").fetchone()
        if item and closed(db, item['workload']):
            c = json.loads(item['context'])
            db.execute("UPDATE console_pool_items SET state='retiring',updated=? WHERE id=?", (int(time.time()), item['id']))
            return {'operation': 'retire', 'automatic': True, 'item_id': item['id'], 'previous': c,
                    'workflow': c.get('workflow', 'cve'), 'role': c['role'], 'project': c.get('project', 'TEST'),
                    'disposable': bool(item['disposable'])}
    if snapshot['managed'] >= LIMIT or not depleted:
        return None
    s = depleted[0]
    return {k: s[k] for k in ('workflow', 'role', 'project')} | {
        'operation': 'prepare', 'automatic': True, 'previous': None, 'disposable': True}


def reserved(db: sqlite3.Connection, reservation: dict) -> None:
    target = reservation['target']
    if target['operation'] == 'prepare':
        db.execute('INSERT INTO console_pool_items VALUES(?,NULL,?,\'preparing\',1,\'\',?)',
                   (reservation['id'], json.dumps(target, sort_keys=True), int(time.time())))


def finish(db: sqlite3.Connection, row: sqlite3.Row, context: dict | None, receipt: str) -> None:
    target = json.loads(row['target'])
    identifier = target.get('item_id', row['id'])
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
