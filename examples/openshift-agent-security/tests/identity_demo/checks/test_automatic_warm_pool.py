# SPDX-License-Identifier: Apache-2.0
"""Real driver/database gates for concurrent refill, immutable allocation and caps."""
from concurrent.futures import ThreadPoolExecutor
import time
from uuid import uuid4

import pytest

from identity_demo_driver import Driver
from identity_demo_run_store import Denied

from checks.support.console import operator, submit
from checks.support.console_preparer import reserve, finish
from checks.support.pool_profiles import mapping

from checks.support.automatic_warm_pool import automatic





def test_ready_run_can_start_and_be_claimed_while_another_context_is_preparing(tmp_path):
    driver, client, contexts, worker = automatic(tmp_path)
    owner = uuid4().hex
    preparation = reserve(driver, client, owner)
    assert preparation['target']['automatic'] and preparation['target']['previous'] is None
    assert driver.console.available(True)['ready']
    assert submit(driver, client).status_code == 303
    job = driver.console.claim(worker)
    assert job and job['workload'] == contexts[0]['workload']
    assert reserve(driver, client, uuid4().hex) is None
    assert reserve(driver, client, owner) == preparation
    assert finish(driver, client, owner, preparation, mapping(preparation['target'])).status_code == 200
    assert submit(driver, client).status_code == 409  # Only one execution lane.


def test_allocation_is_atomic_and_consumed_workload_is_not_reassigned(tmp_path):
    driver, client, contexts, worker = automatic(tmp_path)
    def allocate(_):
        try:return driver.register_run(driver.sessions['opaque']['claims'], contexts[0], queue_workflow='cve')
        except (Denied, __import__('sqlite3').IntegrityError):return None
    with ThreadPoolExecutor(max_workers=8) as pool:
        runs = [r for r in pool.map(allocate, range(8)) if r]
    assert len(runs) == 1
    driver.console.claim(worker)
    driver.store.cancel(runs[0], 'user-a')
    driver.console.update(runs[0], worker, 'completed', {'cleanup_verified': True})
    status = driver.console.pool_status(driver.config.contexts, driver.config.project)['automatic']
    assert status['states']['consumed'] == 1
    with pytest.raises(Denied, match='context_unavailable'):
        driver.register_run(driver.sessions['opaque']['claims'], contexts[0], queue_workflow='cve')


def test_ambiguous_new_create_is_quarantined_counted_and_not_replayed(tmp_path):
    driver, client, _, worker = automatic(tmp_path)
    owner = uuid4().hex
    reservation = reserve(driver, client, owner)
    assert finish(driver, client, owner, reservation, None).status_code == 200
    snapshot = driver.console.pool_status(driver.config.contexts, driver.config.project)
    assert snapshot['automatic']['states']['quarantined'] == 1
    assert snapshot['automatic']['managed'] == 5
    assert driver.console.available(True)['ready']
    restored = Driver(driver.config, driver.verify)
    restored.console.heartbeat(worker, checked_at=int(time.time()))
    assert restored.console.pool_status(driver.config.contexts, driver.config.project)['automatic']['states']['quarantined'] == 1
    following = restored.console.prepare_next(owner, restored.config.contexts, restored.config.project)
    assert following['id'] != reservation['id'] and following['target']['suffix'] != reservation['target']['suffix']
    assert finish(driver, client, owner, reservation, mapping(reservation['target'])).status_code == 403


def test_cap_counts_quarantines_and_reserved_native_creates(tmp_path):
    driver, client, _, _ = automatic(tmp_path)
    owner = uuid4().hex
    for _ in range(8):
        reservation = reserve(driver, client, owner)
        assert reservation is not None
        assert finish(driver, client, owner, reservation, None).status_code == 200
    assert driver.console.pool_status(driver.config.contexts, driver.config.project)['automatic']['managed'] == 12
    assert reserve(driver, client, owner) is None
    assert driver.console.available(True)['ready']  # Capacity blocks refill, not verified spares.


def test_full_pool_retires_only_verified_closed_identity_without_changing_history(tmp_path):
    driver, client, contexts, worker = automatic(tmp_path)
    assert submit(driver, client).status_code == 303
    job = driver.console.claim(worker)
    driver.store.cancel(job['run_id'], 'user-a')
    driver.console.update(job['run_id'], worker, 'completed', {'cleanup_verified': True})
    owner = uuid4().hex
    # Refill both profiles; the consumed context remains counted meanwhile.
    while True:
        reservation = reserve(driver, client, owner)
        if reservation['target']['operation'] == 'retire':break
        assert finish(driver, client, owner, reservation, mapping(reservation['target'])).status_code == 200
    assert reservation['target']['previous']['workload'] == contexts[0]['workload']
    before = driver.store.describe(job['run_id'], 'user-a')
    assert finish(driver, client, owner, reservation, reservation['target']['previous']).status_code == 200
    assert finish(driver, client, owner, reservation, reservation['target']['previous']).status_code == 200
    assert driver.store.describe(job['run_id'], 'user-a') == before
    status = driver.console.pool_status(driver.config.contexts, driver.config.project)['automatic']
    assert status['states']['ready'] == 8 and status['states']['retired'] == 1 and status['managed'] == 8


def test_uncertain_write_and_incomplete_cleanup_still_stop_execution_and_refill(tmp_path):
    driver, client, contexts, worker = automatic(tmp_path)
    assert submit(driver, client).status_code == 303
    job = driver.console.claim(worker)
    driver.store.cancel(job['run_id'], 'user-a')
    driver.console.update(job['run_id'], worker, 'execution_failed', {'cleanup_verified': False, 'failure_code': 'recovery_required'})
    assert not driver.console.available(True)['ready']
    assert reserve(driver, client, uuid4().hex) is None
    assert submit(driver, client).status_code == 409
    assert driver.console.pool_status(driver.config.contexts, driver.config.project)['automatic']['states']['allocated'] == 1


def test_settings_show_automatic_progress_and_browser_cannot_enable_mode(tmp_path):
    driver, client, _, _ = automatic(tmp_path)
    page = client.get('/settings')
    assert 'Contexts are prepared and retired automatically' in page.text
    assert '4 ready' in page.text and '4 / 12' in page.text
    assert '/settings/prepare' not in page.text
    assert 'Preparation needed' not in page.text
    assert client.post('/internal/operator/console/pool', json={
        'action':'automatic','enabled':False,'receipt_sha256':'b'*64,'retired_workloads':[]}).status_code == 403
    assert driver.config.operator_secret not in page.text


def test_unknown_retirement_and_pause_during_job_are_refused(tmp_path):
    driver, client, _, worker = automatic(tmp_path)
    def request(retired):
        return client.post('/internal/operator/console/pool',headers=operator(driver),json={
            'action':'automatic','enabled':False,'receipt_sha256':'c'*64,'retired_workloads':retired})
    assert request(['spiffe://other/workload']).status_code == 403
    assert submit(driver,client).status_code == 303
    assert request([]).status_code == 403
