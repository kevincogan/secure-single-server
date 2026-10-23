# SPDX-License-Identifier: Apache-2.0
"""Presentation batches bound capacity without recycling identities or the shared lane."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import time
from uuid import uuid4

import pytest

from checks.test_console import configured, operator, submit
from checks.test_console_preparer import finish, mapping, reserve
from identity_demo_console_preparer import prepare_one
from identity_demo_driver import Driver
from identity_demo_run_store import Denied


def setup_pool(tmp_path: Path) -> tuple:
    """Keep the real driver/store boundary; only native provisioning is outside unit scope."""
    driver, client, context = configured(tmp_path)
    with driver.store.transaction() as db:
        db.execute('UPDATE runs SET active=0')
    worker = uuid4().hex
    driver.console.heartbeat(worker, checked_at=int(time.time()))
    return driver, client, context, worker


def plan(count: int = 3, *, buffer: int = 0, limit: int = 4) -> dict:
    """Specify the actual scenario sequence and optional bounded per-slot buffer."""
    return {'sequence': [{'workflow': 'cve', 'role': 'triage'} for _ in range(count)],
            'buffer': buffer, 'workflow_limits': {'cve': limit}, 'global_limit': limit}


def configure(driver: Driver, client: object, value: dict) -> object:
    """Use the authenticated operator route rather than bypassing its validation."""
    return client.post('/internal/operator/console/pool', headers=operator(driver),
                       json={'action': 'configure', 'plan': value})


def seal(driver: Driver, client: object, identifier: str, *, action: str = 'seal') -> object:
    """Keep an immutable private readiness/rollback receipt reference on each transition."""
    return client.post('/internal/operator/console/pool', headers=operator(driver),
                       json={'action': action, 'id': identifier, 'receipt_sha256': 'b' * 64})


def test_three_repeated_demos_use_distinct_spares_without_refilling(tmp_path: Path) -> None:
    driver, client, original, worker = setup_pool(tmp_path)
    response = configure(driver, client, plan())
    assert response.status_code == 200
    identifier = response.json()['batch']['id']
    assert not driver.console.available(True)['ready']
    assert 'Preparing presentation batch' in client.get('/').text
    with pytest.raises(Denied, match='presentation_preparing'):
        driver.register_run(driver.sessions['opaque']['claims'], original, queue_workflow='cve')
    assert submit(driver, client).status_code == 409
    assert seal(driver, client, identifier).status_code == 403

    owner = uuid4().hex
    for _ in range(2):
        reservation = reserve(driver, client, owner)
        assert reservation['target']['previous'] is None
        assert reservation['target']['batch_id'] == identifier
        assert driver.console.claim(worker) is None
        assert finish(driver, client, owner, reservation, mapping(reservation['target'])).status_code == 200
    assert reserve(driver, client, owner) is None
    assert not driver.console.available(True)['ready']  # Filling alone is not live acceptance.
    assert seal(driver, client, identifier).status_code == 200
    assert driver.console.available(True)['ready']
    home = client.get('/').text
    assert 'Ready to start' in home
    assert 'Automatic refill is paused' not in home

    identities = []
    for index in range(3):
        assert submit(driver, client).status_code == 303
        job = driver.console.claim(worker)
        identities.append(job['workload'])
        assert reserve(driver, client, owner) is None
        driver.store.cancel(job['run_id'], 'user-a')
        driver.console.update(job['run_id'], worker, 'completed', {'cleanup_verified': True})
        assert reserve(driver, client, owner) is None  # No 20-second refill deadline.
        status = driver.console.pool_status(driver.config.contexts, driver.config.project)
        assert status['batch']['sequence_covered']
        assert status['batch']['slots'][0]['remaining'] == 2 - index
    assert len(set(identities)) == 3
    assert submit(driver, client).status_code == 409
    assert driver.console.pool_status(driver.config.contexts, driver.config.project)['unused'] == 0
    assert 'Ask the operator to prepare the next batch.' in client.get('/').text
    restored = Driver(driver.config, driver.verify)
    assert restored.console.pool_status(restored.config.contexts, restored.config.project)['batch']['phase'] == 'holding'


@pytest.mark.parametrize('change, reason', [
    ({'global_limit': 2, 'workflow_limits': {'cve': 2}}, 'presentation_capacity'),
    ({'workflow_limits': {'cve': 2}}, 'presentation_capacity'),
    ({'global_limit': 13}, 'presentation_plan'),
    ({'buffer': True}, 'presentation_plan'),
    ({'buffer': 3}, 'presentation_plan'),
    ({'sequence': []}, 'presentation_plan'),
    ({'sequence': [{'workflow': [], 'role': 'triage'}]}, 'presentation_plan'),
    ({'sequence': [{'workflow': 'service-request', 'role': 'reader'}]}, 'presentation_slot'),
    ({'workflow_limits': {'foreign': 4}}, 'presentation_limits'),
])
def test_invalid_or_over_capacity_batch_allocates_nothing(tmp_path: Path, change: dict, reason: str) -> None:
    driver, client, _, _ = setup_pool(tmp_path)
    response = configure(driver, client, {**plan(), **change})
    assert response.status_code == 403 and response.json()['reason'] == reason
    assert driver.console.pool_status(driver.config.contexts, driver.config.project)['batch'] is None
    with driver.store.transaction() as db:
        assert not db.execute('SELECT 1 FROM console_preparations').fetchone()


def test_cap_includes_existing_unplanned_unused_contexts(tmp_path: Path) -> None:
    driver, client, old, _ = setup_pool(tmp_path)
    other = mapping({'workflow': 'cve', 'role': 'reader', 'project': 'TEST', 'suffix': 'xyz'})
    driver.config = replace(driver.config, contexts=(old, other))
    assert configure(driver, client, plan(limit=3)).json()['reason'] == 'presentation_capacity'
    response = configure(driver, client, plan(limit=4))
    assert response.status_code == 200 and response.json()['unused'] == 2


def test_optional_buffer_and_competing_preparers_are_bounded(tmp_path: Path) -> None:
    driver, client, _, _ = setup_pool(tmp_path)
    assert configure(driver, client, plan(2, buffer=1, limit=3)).status_code == 200
    def attempt(_: int) -> dict | None:
        return driver.console.prepare_next(uuid4().hex, driver.config.contexts, driver.config.project)
    with ThreadPoolExecutor(max_workers=8) as pool:
        reservations = list(pool.map(attempt, range(8)))
    assert sum(r is not None for r in reservations) == 1
    with driver.store.transaction() as db:
        assert db.execute('SELECT count(*) FROM console_preparations').fetchone()[0] == 1


def test_sealing_requires_fresh_success_and_keeps_security_blocks_visible(tmp_path: Path) -> None:
    driver, client, _, worker = setup_pool(tmp_path)
    identifier = configure(driver, client, plan(1)).json()['batch']['id']
    driver.console.heartbeat(worker, phase='blocked', reason='sender_trust', checked_at=int(time.time()))
    assert driver.console.available(True)['reason'] == 'sender_trust'
    assert seal(driver, client, identifier).json()['reason'] == 'coordinator_not_ready'
    driver.console.heartbeat(worker, checked_at=int(time.time()) - 91)
    assert seal(driver, client, identifier).status_code == 403
    driver.console.heartbeat(worker, checked_at=int(time.time()))
    assert seal(driver, client, identifier).status_code == 200


def test_release_retains_unused_contexts_and_batch_history(tmp_path: Path) -> None:
    driver, client, _, _ = setup_pool(tmp_path)
    identifier = configure(driver, client, plan(1)).json()['batch']['id']
    assert seal(driver, client, identifier).status_code == 200
    assert seal(driver, client, identifier, action='release').status_code == 200
    snapshot = driver.console.pool_status(driver.config.contexts, driver.config.project)
    assert snapshot['batch'] is None and snapshot['unused'] == 1
    with driver.store.transaction() as db:
        assert db.execute('SELECT state FROM console_batches WHERE id=?', (identifier,)).fetchone()[0] == 'released'


def test_failed_batch_preparation_keeps_recovery_lock_across_restart(tmp_path: Path) -> None:
    driver, client, _, worker = setup_pool(tmp_path)
    identifier = configure(driver, client, plan(2)).json()['batch']['id']
    owner = uuid4().hex
    reservation = reserve(driver, client, owner)
    assert finish(driver, client, owner, reservation, None).status_code == 200
    replacement = Driver(driver.config, driver.verify)
    replacement.console.heartbeat(worker, checked_at=int(time.time()))
    assert replacement.console.available(True)['reason'] == 'context_preparation_failed'
    assert seal(driver, client, identifier, action='release').status_code == 403
    assert reserve(driver, client, owner) is None


def test_browser_cannot_configure_pools_and_incomplete_cleanup_prevents_batch(tmp_path: Path) -> None:
    driver, client, _, worker = setup_pool(tmp_path)
    assert client.get('/internal/operator/console/pool').status_code == 403
    assert client.post('/internal/operator/console/pool', json={'action': 'configure', 'plan': plan()}).status_code == 403
    assert submit(driver, client).status_code == 303
    job = driver.console.claim(worker)
    driver.store.cancel(job['run_id'], 'user-a')
    assert configure(driver, client, plan()).json()['reason'] == 'presentation_not_idle'


def test_additive_provisioning_never_calls_retirement(tmp_path: Path, monkeypatch) -> None:
    import identity_demo_console_preparer as helper
    import identity_demo_presentation as presentation
    from dataclasses import asdict
    from identity_demo_execution_setup import context_template
    target = {'role': 'triage', 'workflow': 'cve', 'project': 'TEST', 'suffix': 'xyz',
              'previous': None, 'batch_id': uuid4().hex}
    reservation = {'id': uuid4().hex, 'target': target}
    context = replace(context_template('triage', 'xyz'), sandbox_id=str(uuid4()))
    monkeypatch.setattr(helper, 'retire_previous', lambda *a: pytest.fail('Additive preparation must not retire anything'))
    monkeypatch.setattr(presentation, 'check_capacity', lambda *a: {'additional_contexts': 1})
    def provision(args: object) -> dict:
        helper.native.private_write(args.output_dir / 'context.private.json', asdict(context))
        return {'native_ready': True}
    monkeypatch.setattr(helper, 'provision', provision)
    monkeypatch.setattr(helper, 'resolve_context', lambda *a: context)
    result = prepare_one(SimpleNamespace(output_dir=tmp_path), SimpleNamespace(request=lambda *a: {}), uuid4().hex, reservation)
    assert result['prepared']
    import json
    receipt = json.loads((tmp_path / reservation['id'] / 'preparation.receipt.private.json').read_text())
    assert receipt['retirement']['retirement_requested'] is False
    assert receipt['timings_seconds']['total'] >= 0


def test_next_batch_atomically_replaces_hold_without_enabling_legacy_retirement(tmp_path: Path) -> None:
    driver, client, _, _ = setup_pool(tmp_path)
    first = configure(driver, client, plan(1)).json()['batch']['id']
    assert seal(driver, client, first).status_code == 200
    second = configure(driver, client, plan(2)).json()['batch']['id']
    assert second != first and driver.console.available(True)['reason'] == 'presentation_preparing'
    reservation = reserve(driver, client, uuid4().hex)
    assert reservation['target']['batch_id'] == second and reservation['target']['previous'] is None
    with driver.store.transaction() as db:
        old = db.execute('SELECT state,receipt FROM console_batches WHERE id=?', (first,)).fetchone()
        assert old['state'] == 'superseded' and old['receipt'] == 'b' * 64


def test_capacity_observation_can_retry_before_any_provisioning_checkpoint(tmp_path: Path, monkeypatch) -> None:
    import identity_demo_console_preparer as helper
    import identity_demo_presentation as presentation
    reservation = {'id': uuid4().hex, 'target': {'role': 'triage', 'previous': None, 'batch_id': uuid4().hex}}
    def unavailable(*args: object) -> dict:
        raise ValueError('Capacity unavailable')
    monkeypatch.setattr(presentation, 'check_capacity', unavailable)
    monkeypatch.setattr(helper, 'provision', lambda *a: pytest.fail('Capacity failure must precede native mutation'))
    with pytest.raises(helper.PreparationCapacityUnavailable):
        prepare_one(SimpleNamespace(output_dir=tmp_path), SimpleNamespace(), uuid4().hex, reservation)
    assert not (tmp_path / reservation['id'] / 'checkpoint.private.json').exists()
