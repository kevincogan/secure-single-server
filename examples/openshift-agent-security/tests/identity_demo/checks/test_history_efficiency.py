# SPDX-License-Identifier: Apache-2.0
"""Retained history must not lock writers or deserialize retired contexts."""
import json
import sqlite3
from uuid import uuid4
import identity_demo_warm_pool as warm
from checks.test_driver import setup


def test_owner_history_remains_readable_while_another_writer_has_transaction(tmp_path):
    driver,_,run,_=setup(tmp_path)
    writer=sqlite3.connect(driver.config.database,isolation_level=None)
    try:
        writer.execute('BEGIN IMMEDIATE')
        writer.execute('UPDATE runs SET assessment=? WHERE id=?',('uncommitted',run))
        record=driver.store.describe(run,'user-a')
        assert record['run']['id']==run and record['run']['assessment']!='uncommitted'
    finally:
        writer.rollback();writer.close()


def test_retained_pool_tombstones_are_counted_without_deserializing_contexts(tmp_path,monkeypatch):
    driver,_,_,_=setup(tmp_path)
    with driver.store.transaction() as db:
        db.execute("INSERT INTO console_pool_settings VALUES (1,1,?,1)", ("a"*64,))
        for _ in range(1000):
            ident=uuid4().hex
            db.execute('INSERT INTO console_pool_items VALUES (?,?,?,?,?,?,?)',
                (ident,'spiffe://example/'+ident,json.dumps({'role':'triage'}),'retired',0,'a'*64,1))
        # Every retained tombstone remains durable, but the status hot path
        # should not even attempt to parse its context.
        old=warm.json.loads
        def no_retired(value):
            result=old(value)
            assert result!={'role':'triage'}
            return result
        monkeypatch.setattr(warm.json,'loads',no_retired)
        result=warm.status(db)
        assert result['states']['retired']==1000 and result['managed']==0
        assert db.execute("SELECT count(*) FROM console_pool_items WHERE state='retired'").fetchone()[0]==1000


def test_active_inventory_omits_retired_mappings_without_erasing_them(tmp_path):
    driver,_,_,_=setup(tmp_path)
    with driver.store.transaction() as db:
        db.execute('INSERT INTO console_pool_settings VALUES (1,1,?,1)',('a'*64,))
        for state in ('ready','retired'):
            ident=uuid4().hex;context={'workload':ident,'role':'triage','namespace':'synthetic','sandbox_name':ident}
            db.execute('INSERT INTO console_contexts VALUES (?,?,?,?)',(ident,json.dumps(context),'synthetic',ident))
            db.execute('INSERT INTO console_pool_items VALUES (?,?,?,?,?,?,?)',(ident,ident,json.dumps(context),state,0,'a'*64,1))
    assert len(driver.console.contexts(active_only=True))==1
    assert len(driver.console.contexts())==2
