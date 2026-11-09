# SPDX-License-Identifier: Apache-2.0
"""Shared console preparer test setup; contains no collected tests."""
from dataclasses import replace
from pathlib import Path
from uuid import uuid4
from checks.support.console import configured, operator, submit
from identity_demo_driver import Driver

def exhausted(tmp_path: Path) -> tuple:
    driver, client, context = configured(tmp_path)
    with driver.store.transaction() as db:
        db.execute("UPDATE runs SET active=0")
    worker = uuid4().hex
    driver.console.heartbeat(worker)
    response = submit(driver, client)
    run = response.headers['location'].split('/')[-1]
    driver.console.claim(worker)
    driver.store.cancel(run, 'user-a')
    driver.console.update(run, worker, 'completed', {'cleanup_verified': True})
    return driver, client, context, worker

def reserve(driver: Driver, client: object, owner: str) -> dict | None:
    return client.post('/internal/operator/console/prepare/next', headers=operator(driver), json={'owner': owner}).json()['preparation']

def mapping(target: dict) -> dict:
    from identity_demo_execution_setup import context_template
    from dataclasses import asdict
    template = replace(context_template(target['role'], target['suffix']), sandbox_id=str(uuid4()))
    return {**asdict(template), 'workload': template.workload, 'workflow': target['workflow'],
            'project': target['project'], 'console_prepared': True}

def finish(driver: Driver, client: object, owner: str, reservation: dict, context: dict | None) -> object:
    return client.post('/internal/operator/console/prepare/finish', headers=operator(driver), json={
        'owner': owner, 'id': reservation['id'], 'context': context, 'receipt_sha256': 'a' * 64})
