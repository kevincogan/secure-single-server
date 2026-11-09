# SPDX-License-Identifier: Apache-2.0
"""Shared console test setup; contains no collected tests."""
from dataclasses import replace
from pathlib import Path
import time
from uuid import uuid4
from starlette.testclient import TestClient
from checks.support.driver import setup
from identity_demo_driver import COOKIE, Driver

def configured(tmp_path: Path) -> tuple:
    previous, _, _, _ = setup(tmp_path)
    context = dict(previous.config.contexts[0])
    context['sandbox_id'] = str(uuid4())
    context['console_prepared'] = True
    context['workload'] = 'spiffe://agents.example.test/openshell/sandbox/' + context['sandbox_id']
    driver = Driver(replace(previous.config, contexts=(context,), coordinator_enabled=True), previous.verify)
    driver.sessions = previous.sessions
    driver.sessions['opaque']['claims']['exp'] = int(time.time()) + 600
    client = TestClient(driver.app, base_url=driver.config.origin)
    client.cookies.set(COOKIE, 'opaque')
    return driver, client, context

def operator(driver: Driver) -> dict:
    return {'Authorization': 'Bearer ' + driver.config.operator_secret}

def submit(driver: Driver, client: TestClient) -> object:
    return client.post('/submit', headers={'Origin': driver.config.origin},
        data={'csrf': 'csrf-fixture', 'role': 'triage', 'cve': 'CVE-2099-0001'}, follow_redirects=False)

def claim(driver: Driver, client: TestClient) -> tuple:
    worker = uuid4().hex
    assert client.post('/internal/operator/console/heartbeat', headers=operator(driver), json={'worker': worker}).status_code == 200
    response = submit(driver, client)
    assert response.status_code == 303
    job = client.post('/internal/operator/console/next', headers=operator(driver), json={'worker': worker}).json()['job']
    return worker, job
