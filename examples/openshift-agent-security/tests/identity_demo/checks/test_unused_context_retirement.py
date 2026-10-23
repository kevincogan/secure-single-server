# SPDX-License-Identifier: Apache-2.0
"""Installer quarantine is durable, single-use and distinct from business runs."""
import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest

from checks.test_automatic_warm_pool import automatic
from checks.test_console import operator
from identity_demo_driver import Driver
from identity_demo_run_store import Denied
import identity_demo_warm_pool as warm


def idle_installation(tmp_path):
    driver, client, contexts, _ = automatic(tmp_path)
    response = client.post('/internal/operator/console/pool', headers=operator(driver), json={
        'action': 'automatic', 'enabled': False, 'receipt_sha256': 'c'*64, 'retired_workloads': []})
    assert response.status_code == 200
    with driver.store.transaction() as db:
        db.execute('UPDATE console_worker SET updated=0')
        db.execute('UPDATE console_preparer SET updated=0')
        row = db.execute('SELECT context FROM console_pool_items WHERE workload=?',
                         (contexts[0]['workload'],)).fetchone()
    return driver, client, contexts, hashlib.sha256(row['context'].encode()).hexdigest()


def test_quarantine_and_completed_retirement_never_create_a_business_run(tmp_path):
    driver, client, contexts, digest = idle_installation(tmp_path)
    workload = contexts[0]['workload']
    reservation = uuid4().hex
    with driver.store.read_transaction() as db:
        before = list(db.execute('SELECT * FROM runs'))
    with driver.store.transaction() as db:
        warm.quarantine_unused(db, workload, digest, reservation, 'd'*64)
    assert not driver.console.context_ready(workload)
    assert driver.console.pool_status(driver.config.contexts, 'TEST')['unused'] == 3
    with pytest.raises(Denied, match='retired_workload'):
        driver.register_run(driver.sessions['opaque']['claims'], contexts[0])
    restored = Driver(driver.config, driver.verify)
    assert not restored.console.available(True)['ready']
    with restored.store.read_transaction() as db:
        assert warm.unused_retirement(db, reservation, 'd'*64)['workload'] == workload
        assert db.execute('SELECT state FROM console_pool_items WHERE workload=?', (workload,)).fetchone()[0] == 'quarantined'
    with restored.store.transaction() as db:
        warm.complete_unused_retirement(db, reservation, 'd'*64, 'e'*64)
    with restored.store.read_transaction() as db:
        assert list(db.execute('SELECT * FROM runs')) == before
        assert db.execute('SELECT state FROM console_pool_items WHERE workload=?', (workload,)).fetchone()[0] == 'retired'
        assert db.execute('SELECT state FROM console_preparations WHERE id=?', (reservation,)).fetchone()[0] == 'completed'
        assert [v[0] for v in db.execute('SELECT event FROM audit WHERE run_id=? ORDER BY sequence',
                                       ('maintenance:'+reservation,))] == [
            'unused_retirement_quarantined', 'unused_retirement_completed']
    assert restored.console.context_for_workload(workload) is None  # Configured mapping is still retained by config.
    assert restored.config.contexts == driver.config.contexts
    assert not restored.console.context_ready(workload)
    with pytest.raises(Denied, match='retired_workload'):
        restored.register_run(restored.sessions.get('opaque', driver.sessions['opaque'])['claims'], contexts[0])


def test_maintenance_blocks_other_direct_runs_and_is_not_a_runtime_api(tmp_path):
    driver, client, contexts, digest = idle_installation(tmp_path)
    with driver.store.transaction() as db:
        warm.quarantine_unused(db, contexts[0]['workload'], digest, uuid4().hex, 'd'*64)
    with pytest.raises(Denied, match='context_preparing'):
        driver.register_run(driver.sessions['opaque']['claims'], contexts[1])
    for headers in ({}, operator(driver)):
        response = client.post('/internal/operator/console/pool', headers=headers,
                               json={'action': 'retire-unused', 'workload': contexts[0]['workload']})
        assert response.status_code == 403


def test_reenabling_automatic_pool_does_not_revive_unused_retirement_tombstones(tmp_path):
    driver, client, contexts, _ = idle_installation(tmp_path)
    with driver.store.read_transaction() as db:
        original_runs = [tuple(r) for r in db.execute('SELECT * FROM runs')]
    for context in contexts:
        reservation = uuid4().hex
        with driver.store.transaction() as db:
            raw = db.execute('SELECT context FROM console_pool_items WHERE workload=?',
                             (context['workload'],)).fetchone()[0]
            warm.quarantine_unused(db, context['workload'], hashlib.sha256(raw.encode()).hexdigest(),
                                   reservation, 'd'*64)
        with driver.store.transaction() as db:
            warm.complete_unused_retirement(db, reservation, 'd'*64, 'e'*64)
    response = client.post('/internal/operator/console/pool', headers=operator(driver), json={
        'action': 'automatic', 'enabled': True, 'receipt_sha256': 'f'*64, 'retired_workloads': []})
    assert response.status_code == 200
    assert response.json()['automatic']['managed'] == 0
    assert response.json()['automatic']['states']['retired'] == 4
    assert response.json()['unused'] == 0
    with driver.store.read_transaction() as db:
        assert [tuple(r) for r in db.execute('SELECT * FROM runs')] == original_runs
    assert all(not driver.console.context_ready(c['workload']) for c in contexts)


def test_allocation_and_installer_quarantine_have_only_one_winner(tmp_path):
    driver, _, contexts, digest = idle_installation(tmp_path)
    workload = contexts[0]['workload']
    def operation(action):
        try:
            if action == 'run':
                driver.register_run(driver.sessions['opaque']['claims'], contexts[0])
            else:
                with driver.store.transaction() as db:
                    warm.quarantine_unused(db, workload, digest, uuid4().hex, 'd'*64)
            return action
        except Denied:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        winners = [value for value in pool.map(operation, ('run', 'quarantine')) if value]
    assert len(winners) == 1
    with driver.store.read_transaction() as db:
        run = db.execute('SELECT 1 FROM runs WHERE workload=?', (workload,)).fetchone()
        state = db.execute('SELECT state FROM console_pool_items WHERE workload=?', (workload,)).fetchone()[0]
    assert (bool(run), state) == ((True, 'ready') if winners == ['run'] else (False, 'quarantined'))


@pytest.mark.parametrize('change', ['scheduling', 'worker', 'preparer', 'active-run', 'used', 'context', 'busy-preparation'])
def test_unfenced_or_uncertain_retirement_is_refused_atomically(tmp_path, change):
    driver, _, contexts, digest = idle_installation(tmp_path)
    workload = contexts[0]['workload']
    with driver.store.transaction() as db:
        if change == 'scheduling': db.execute('UPDATE console_pool_settings SET enabled=1')
        elif change == 'worker': db.execute('UPDATE console_worker SET updated=?', (int(time.time()),))
        elif change == 'preparer': db.execute('INSERT INTO console_preparer VALUES(1,?)', (int(time.time()),))
        elif change == 'active-run': db.execute('UPDATE runs SET active=1')
        elif change == 'used': db.execute('UPDATE runs SET workload=?', (workload,))
        elif change == 'context': digest = '0'*64
        else:
            db.execute("INSERT INTO console_preparations(id,owner,state,target,updated) VALUES(?,?,'preparing','{}',0)",
                       (uuid4().hex, 'another-worker'))
    with pytest.raises(Denied):
        with driver.store.transaction() as db:
            warm.quarantine_unused(db, workload, digest, uuid4().hex, 'd'*64)
    with driver.store.read_transaction() as db:
        assert db.execute('SELECT state FROM console_pool_items WHERE workload=?', (workload,)).fetchone()[0] == 'ready'
        assert not db.execute("SELECT 1 FROM audit WHERE event='unused_retirement_quarantined'").fetchone()


@pytest.mark.parametrize('change', ['review', 'identity', 'state', 'reservation', 'absence'])
def test_failed_or_changed_reservation_cannot_be_completed(tmp_path, change):
    driver, _, contexts, digest = idle_installation(tmp_path)
    reservation = uuid4().hex
    with driver.store.transaction() as db:
        warm.quarantine_unused(db, contexts[0]['workload'], digest, reservation, 'd'*64)
        if change == 'identity':
            db.execute("UPDATE console_pool_items SET context='{}' WHERE workload=?", (contexts[0]['workload'],))
        elif change == 'state':
            db.execute("UPDATE console_pool_items SET state='ready' WHERE workload=?", (contexts[0]['workload'],))
    with pytest.raises(Denied):
        with driver.store.transaction() as db:
            warm.complete_unused_retirement(db, uuid4().hex if change == 'reservation' else reservation,
                'f'*64 if change == 'review' else 'd'*64, 'invalid' if change == 'absence' else 'e'*64)
    with driver.store.read_transaction() as db:
        assert db.execute('SELECT state FROM console_preparations WHERE id=?', (reservation,)).fetchone()[0] == 'blocked'


def test_completed_unused_retirement_allows_verified_replacement_after_restart(tmp_path):
    driver, client, contexts, digest = idle_installation(tmp_path)
    reservation = uuid4().hex
    with driver.store.transaction() as db:
        warm.quarantine_unused(db, contexts[0]['workload'], digest, reservation, 'd'*64)
    with driver.store.transaction() as db:
        warm.complete_unused_retirement(db, reservation, 'd'*64, 'e'*64)
    response = client.post('/internal/operator/console/pool', headers=operator(driver), json={
        'action': 'automatic', 'enabled': True, 'receipt_sha256': 'f'*64, 'retired_workloads': []})
    assert response.status_code == 200
    restored = Driver(driver.config, driver.verify)
    restored.console.heartbeat(uuid4().hex, checked_at=int(time.time()))
    replacement = restored.console.prepare_next(uuid4().hex, restored.config.contexts, 'TEST')
    assert replacement and replacement['target']['operation'] == 'prepare'
    assert replacement['target']['role'] == contexts[0]['role']
    assert 'demo-s56-' + replacement['target']['role'] + '-' + replacement['target']['suffix'] != contexts[0]['sandbox_name']
    assert not restored.console.context_ready(contexts[0]['workload'])
