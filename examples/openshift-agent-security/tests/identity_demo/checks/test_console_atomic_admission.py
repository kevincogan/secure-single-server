# SPDX-License-Identifier: Apache-2.0
"""Competing starts allocate one run/job atomically and consume no spare identities."""

from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4
import sqlite3

import pytest

from checks.test_console import configured
from identity_demo_run_store import Denied


def test_competing_starts_reserve_exactly_one_identity_and_job(tmp_path):
    driver, _, context = configured(tmp_path)
    worker = uuid4().hex
    driver.console.heartbeat(worker)
    claims = driver.sessions["opaque"]["claims"]
    with driver.store.transaction() as db:
        before = db.execute("SELECT count(*) FROM runs").fetchone()[0]

    def start(_):
        c = {
            **context,
            "workload": "spiffe://agents.example.test/openshell/sandbox/"
            + str(uuid4()),
        }
        try:
            return driver.register_run(claims, c, queue_workflow="cve")
        except Denied as error:
            assert str(error) == "console_busy"
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(start, range(8)))
    assert sum(r is not None for r in results) == 1
    with driver.store.transaction() as db:
        assert db.execute("SELECT count(*) FROM runs").fetchone()[0] == before + 1
        assert db.execute("SELECT count(*) FROM console_jobs").fetchone()[0] == 1
        assert (
            db.execute(
                "SELECT count(*) FROM audit WHERE event='console_queued'"
            ).fetchone()[0]
            == 1
        )


def test_queue_failure_rolls_back_identity_and_run_together(tmp_path):
    driver, _, context = configured(tmp_path)
    driver.console.heartbeat(uuid4().hex)
    claims = driver.sessions["opaque"]["claims"]
    with driver.store.transaction() as db:
        before = db.execute("SELECT count(*) FROM runs").fetchone()[0]
        db.execute(
            "CREATE TRIGGER reject_queue BEFORE INSERT ON console_jobs BEGIN SELECT RAISE(ABORT,'synthetic queue failure'); END"
        )
    with pytest.raises(sqlite3.IntegrityError):
        driver.register_run(claims, context, queue_workflow="cve")
    with driver.store.transaction() as db:
        assert db.execute("SELECT count(*) FROM runs").fetchone()[0] == before
        assert not db.execute("SELECT 1 FROM console_jobs").fetchone()
        db.execute("DROP TRIGGER reject_queue")
    assert driver.register_run(claims, context, queue_workflow="cve")


def test_stale_readiness_cannot_allocate_identity_after_preflight_starts(tmp_path):
    driver, _, context = configured(tmp_path)
    driver.console.heartbeat(uuid4().hex, phase="preparing")
    with pytest.raises(Denied, match="coordinator_not_ready"):
        driver.register_run(
            driver.sessions["opaque"]["claims"], context, queue_workflow="cve"
        )
    with driver.store.transaction() as db:
        assert not db.execute("SELECT 1 FROM console_jobs").fetchone()
