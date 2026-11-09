# SPDX-License-Identifier: Apache-2.0
"""Legacy state must survive a guarded transition to profile scheduling."""
from dataclasses import replace
import hashlib
import json
import time
from uuid import uuid4

import pytest

from checks.support.console import configured, operator
from checks.support.pool_profiles import apply_profiles, configuration, prepare
from identity_demo_driver import Driver
from identity_demo_run_store import Denied
import identity_demo_warm_pool as warm


@pytest.mark.parametrize('legacy_state', ['allocated', 'ready'])
def test_legacy_migration_retires_exact_contexts_and_preserves_history(tmp_path, legacy_state):
    driver, client, consumed = configured(tmp_path)
    identifier = str(uuid4())
    unused = {**consumed, 'sandbox_id': identifier, 'sandbox_name': 'demo-s56-triage-new',
              'workload': consumed['workload'].rsplit('/', 1)[0] + '/' + identifier}
    driver.config = replace(driver.config, contexts=(consumed, unused))
    with driver.store.transaction() as db:
        db.execute('UPDATE runs SET active=0')
    worker = uuid4().hex
    driver.console.heartbeat(worker)
    claims = driver.sessions['opaque']['claims']
    run = driver.register_run(claims, consumed, queue_workflow='cve')
    assert driver.console.claim(worker)['run_id'] == run
    with driver.store.transaction() as db:
        db.execute("INSERT INTO console_batches(id,plan,state,run_rowid,updated,receipt) "
                   "VALUES('legacy','{}','holding',1,0,?)", ('a'*64,))
        # The old scheduler left a used row ready if it was paused at allocation.
        db.execute("INSERT INTO console_pool_settings VALUES(1,?,?,0)",
                   (int(legacy_state == 'allocated'), 'b'*64))
        db.execute("INSERT INTO console_pool_items VALUES('previous',?,?,?,0,?,0)",
                   (consumed['workload'], json.dumps(consumed, sort_keys=True), legacy_state, 'b'*64))

    def pause(retired):
        return client.post('/internal/operator/console/pool', headers=operator(driver), json={
            'action': 'automatic', 'enabled': False, 'receipt_sha256': 'c'*64,
            'retired_workloads': retired})

    assert apply_profiles(driver, client, configuration()).status_code == 403
    proof = {consumed['workload']: warm.retirement_identity(consumed)}
    assert pause(proof).status_code == 403
    assert driver.console.prepare_next(uuid4().hex, driver.config.contexts, 'TEST') is None
    driver.store.cancel(run, 'user-a')
    driver.console.update(run, worker, 'completed', {'cleanup_verified': True})
    before = driver.store.describe(run, 'user-a')
    if legacy_state == 'allocated':
        assert pause(proof).status_code == 403  # Retirement requires an existing pause.
    assert pause([]).status_code == 200
    assert pause({unused['workload']: warm.retirement_identity(unused)}).status_code == 403
    assert pause({consumed['workload']: 'f'*64}).status_code == 403
    assert pause(proof).status_code == 200
    assert not driver.console.context_ready(unused['workload'])
    with pytest.raises(Denied, match='context_unavailable'):
        driver.register_run(claims, unused)
    assert apply_profiles(driver, client, configuration()).status_code == 403

    reservation = uuid4().hex
    digest = hashlib.sha256(json.dumps(unused, sort_keys=True).encode()).hexdigest()
    with driver.store.transaction() as db:
        db.execute('UPDATE console_worker SET updated=0')
        db.execute('UPDATE console_preparer SET updated=0')
        warm.quarantine_unused(db, unused['workload'], digest, reservation, 'd'*64)
    assert apply_profiles(driver, client, configuration()).status_code == 403
    with driver.store.transaction() as db:
        warm.complete_unused_retirement(db, reservation, 'd'*64, 'e'*64)
    assert apply_profiles(driver, client, configuration()).status_code == 200

    restored = Driver(driver.config, driver.verify)
    restored.console.heartbeat(worker, checked_at=int(time.time()))
    assert prepare(restored, client)['workload'] not in (consumed['workload'], unused['workload'])
    assert restored.store.describe(run, 'user-a') == before
    with restored.store.read_transaction() as db:
        assert tuple(db.execute('SELECT id,plan,state,receipt FROM console_batches').fetchone()) == (
            'legacy', '{}', 'superseded', 'a'*64)
        assert db.execute("SELECT count(*) FROM console_pool_items WHERE state='retired'").fetchone()[0] == 2
