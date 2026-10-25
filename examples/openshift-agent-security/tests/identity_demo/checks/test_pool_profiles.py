# SPDX-License-Identifier: Apache-2.0
"""Profile capacity is shared; immutable run scope and permissions are not."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
import json
import time
from uuid import uuid4

import pytest

from checks.test_console import configured, operator
from checks.test_console_preparer import reserve, finish
from identity_demo_driver import Driver
from identity_demo_execution_setup import context_template
from identity_demo_run_store import Denied
from deployment_profile import active_profile
import identity_demo_pool_profiles as profiles


def configuration():
    p = active_profile()
    base = {
        "service_account": "fixture-openshell-sandbox",
        "workload_image": "registry.example.test/workload@sha256:" + "a" * 64,
        "supervisor_image": "ghcr.io/nvidia/openshell/supervisor@sha256:4ab2b970cdb02c7518ba4ccbbadb4861ae9a8d0b8770e5b160697f0453b0a8e4",
        "policy": {
            "version": 1,
            "filesystem_policy": {"read_only": ["/workspace"], "read_write": ["/tmp"]},
            "network_policies": {},
        },
        "trust_domain": p.trust_domain,
        "issuer": p.native_build_contract["OPENSHELL_DEMO_JWT_AUDIENCE"],
        "tools": ["jira.issue.read", "jira.issue.create"],
    }
    return {
        "schema_version": 2,
        "profiles": [
            dict(
                base,
                id="shared-triage-v1",
                role="triage",
                namespace=p.triage_namespace,
                write_actions=["jira.issue.create"],
                target=6,
            ),
            dict(
                base,
                id="read-only-v1",
                role="reader",
                namespace=p.reader_namespace,
                tools=["jira.issue.read"],
                write_actions=[],
                target=2,
            ),
        ],
        "workflows": [
            {
                "workflow": w,
                "profile": profile,
                "project": project,
                "connector": "jira.create.v1",
            }
            for w, profile, project in (
                ("cve", "shared-triage-v1", "TEST"),
                ("cve", "read-only-v1", "TEST"),
                ("incident-triage", "shared-triage-v1", "OPS"),
                ("service-request", "shared-triage-v1", "SERVICE"),
            )
        ],
    }


def setup(tmp_path):
    driver, client, _ = configured(tmp_path)
    with driver.store.transaction() as db:
        db.execute("UPDATE runs SET active=0")
    worker = uuid4().hex
    driver.console.heartbeat(worker, checked_at=int(time.time()))
    response = client.post(
        "/internal/operator/console/pool",
        headers=operator(driver),
        json={
            "action": "profiles",
            "configuration": configuration(),
            "receipt_sha256": "b" * 64,
        },
    )
    assert response.status_code == 200, response.text
    return driver, client, worker


def mapping(target):
    c = replace(
        context_template(target["role"], target["suffix"]), sandbox_id=str(uuid4())
    )
    return dict(
        asdict(c),
        workload=c.workload,
        console_prepared=True,
        profile_id=target["profile_id"],
        profile_fingerprint=target["profile_fingerprint"],
        native_policy_hash="c" * 64,
    )


def prepare(driver, client):
    owner = uuid4().hex
    r = reserve(driver, client, owner)
    assert r and r["target"]["operation"] == "prepare"
    context = mapping(r["target"])
    assert finish(driver, client, owner, r, context).status_code == 200
    return context


def test_shared_capacity_supports_all_triage_workflows_and_freezes_each_run_scope(
    tmp_path,
):
    driver, client, worker = setup(tmp_path)
    c = prepare(driver, client)
    offered = [
        v
        for v in driver.execution_contexts(active_only=True)
        if v["workload"] == c["workload"]
    ]
    assert {(v["workflow"], v["project"]) for v in offered} == {
        ("cve", "TEST"),
        ("incident-triage", "OPS"),
        ("service-request", "SERVICE"),
    }
    incident = next(v for v in offered if v.get("workflow") == "incident-triage")
    run = driver.register_run(
        driver.sessions["opaque"]["claims"], incident, queue_workflow="incident-triage"
    )
    assert driver.console.claim(worker)["run_id"] == run
    assert driver.context_for_workload(c["workload"])["project"] == "OPS"
    with driver.store.read_transaction() as db:
        stored = json.loads(
            db.execute(
                "SELECT context FROM console_contexts WHERE workload=?",
                (c["workload"],),
            ).fetchone()[0]
        )
        assert "project" not in stored and "workflow" not in stored
    assert driver.store.read_decision(run, "user-a", c["workload"], "OPS", "d" * 64)[
        "allowed"
    ]
    assert not driver.store.read_decision(
        run, "user-a", c["workload"], "TEST", "e" * 64
    )["allowed"]
    driver.store.cancel(run, "user-a")
    driver.console.update(run, worker, "completed", {"cleanup_verified": True})
    with pytest.raises(Denied, match="context_unavailable"):
        driver.register_run(
            driver.sessions["opaque"]["claims"], offered[0], queue_workflow="cve"
        )


def test_racing_allocations_bind_one_context_once(tmp_path):
    driver, client, worker = setup(tmp_path)
    c = prepare(driver, client)
    v = next(
        v
        for v in driver.execution_contexts()
        if v["workload"] == c["workload"] and v["workflow"] == "cve"
    )

    def claim(_):
        try:
            return driver.register_run(
                driver.sessions["opaque"]["claims"], v, queue_workflow="cve"
            )
        except (Denied, __import__("sqlite3").IntegrityError):
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        runs = list(pool.map(claim, range(8)))
    assert len([r for r in runs if r]) == 1


def test_unapproved_project_connector_or_role_rolls_back_allocation(tmp_path):
    driver, client, worker = setup(tmp_path)
    c = prepare(driver, client)
    v = next(
        v
        for v in driver.execution_contexts()
        if v["workload"] == c["workload"] and v["workflow"] == "cve"
    )
    for changed in (dict(v, project="OTHER"), dict(v, role="reader")):
        with pytest.raises(Denied):
            driver.register_run(
                driver.sessions["opaque"]["claims"], changed, queue_workflow="cve"
            )
        assert driver.console.context_ready(c["workload"])
    with driver.store.transaction() as db:
        value = configuration()
        value["workflows"][0]["connector"] = "unregistered.create.v1"
        db.execute(
            "UPDATE console_pool_contract SET configuration=?", (json.dumps(value),)
        )
    with pytest.raises(Denied):
        driver.register_run(
            driver.sessions["opaque"]["claims"], v, queue_workflow="cve"
        )


def test_stale_context_is_revalidated_without_new_identity_and_policy_substitution_is_denied(
    tmp_path,
):
    driver, client, worker = setup(tmp_path)
    c = prepare(driver, client)
    with driver.store.transaction() as db:
        db.execute("UPDATE console_profile_contexts SET verified_until=0")
    assert not driver.console.context_ready(c["workload"])
    owner = uuid4().hex
    r = reserve(driver, client, owner)
    assert r["target"]["operation"] == "verify" and r["target"]["previous"] == c
    assert (
        finish(
            driver, client, owner, r, dict(c, native_policy_hash="d" * 64)
        ).status_code
        == 403
    )
    assert finish(driver, client, owner, r, c).status_code == 200
    assert driver.console.context_ready(c["workload"])
    assert (
        driver.console.pool_status(driver.config.contexts, driver.config.project)[
            "automatic"
        ]["managed"]
        == 1
    )


def test_profile_fairness_cap_quarantine_and_restart(tmp_path):
    driver, client, worker = setup(tmp_path)
    first = prepare(driver, client)
    second = prepare(driver, client)
    assert first["role"] != second["role"]
    for _ in range(10):
        owner = uuid4().hex
        r = reserve(driver, client, owner)
        assert r and finish(driver, client, owner, r, None).status_code == 200
    assert reserve(driver, client, uuid4().hex) is None
    view = driver.console.pool_status(driver.config.contexts, driver.config.project)[
        "automatic"
    ]
    assert view["managed"] == 12 and view["states"]["quarantined"] == 10
    restored = Driver(driver.config, driver.verify)
    assert (
        restored.console.pool_status(driver.config.contexts, driver.config.project)[
            "automatic"
        ]["states"]["quarantined"]
        == 10
    )


def test_contract_is_explicit_idle_versioned_and_does_not_reinterpret_legacy(tmp_path):
    driver, client, worker = setup(tmp_path)
    prepare(driver, client)
    changed = configuration()
    changed["profiles"][0]["policy"]["filesystem_policy"]["read_write"].append("/different-isolation")
    assert (
        client.post(
            "/internal/operator/console/pool",
            headers=operator(driver),
            json={
                "action": "profiles",
                "configuration": changed,
                "receipt_sha256": "b" * 64,
            },
        ).status_code
        == 403
    )
    bad = configuration()
    bad["profiles"][1]["write_actions"] = ["jira.issue.create"]
    with pytest.raises(Denied, match="workload_permission"):
        profiles.validate(bad)
    with driver.store.transaction() as db:
        db.execute("UPDATE console_pool_contract SET version=999")
    with pytest.raises(Denied, match="pool_schema"):
        driver.console.pool_status(driver.config.contexts, driver.config.project)


def test_settings_and_live_views_report_shared_availability_without_double_counting(
    tmp_path,
):
    driver, client, worker = setup(tmp_path)
    prepare(driver, client)
    view = driver.console.pool_status(driver.config.contexts, driver.config.project)
    assert view["unused"] == 1 and view["automatic"]["managed"] == 1
    assert len(view["contexts"]) == 3
    assert client.get("/").status_code == 200
    assert client.get("/settings").status_code == 200
    assert client.get("/console/live").status_code == 200


def test_issuer_and_native_supervisor_are_bound_to_the_installation():
    for key, value in [
        ("issuer", "https://other.example.test/realms/demo"),
        ("supervisor_image", "registry.example.test/substitute@sha256:" + "d" * 64),
    ]:
        bad = configuration()
        bad["profiles"][0][key] = value
        with pytest.raises(Denied, match="pool_profile"):
            profiles.validate(bad)


def test_unknown_connector_is_rejected_before_profile_activation():
    bad = configuration()
    bad["workflows"][0]["connector"] = "unregistered.create.v1"
    with pytest.raises(Denied, match="unsupported_connector"):
        profiles.validate(bad)


def test_disabling_profile_scheduling_cannot_fall_back_to_legacy_preparation(tmp_path):
    driver, client, worker = setup(tmp_path)
    prepare(driver, client)
    with driver.store.transaction() as db:
        db.execute("UPDATE console_pool_settings SET enabled=0")
    owner = uuid4().hex
    assert reserve(driver, client, owner) is None
    with driver.store.read_transaction() as db:
        import identity_demo_warm_pool as warm

        assert warm.next_target(db) is None
        assert (
            db.execute(
                "SELECT count(*) FROM console_preparations WHERE state='preparing'"
            ).fetchone()[0]
            == 0
        )


@pytest.mark.parametrize(
    "fault",
    ["schema-float", "policy-bool", "policy-float", "profile-object", "tool-object"],
)
def test_malformed_profile_inputs_are_denied_without_type_confusion(fault):
    value = configuration()
    if fault == "schema-float":
        value["schema_version"] = 2.0
    elif fault == "policy-bool":
        value["profiles"][0]["policy"]["version"] = True
    elif fault == "policy-float":
        value["profiles"][0]["policy"]["version"] = 1.0
    elif fault == "profile-object":
        value["workflows"][0]["profile"] = {}
    else:
        value["profiles"][0]["tools"] = [{}]
    with pytest.raises(Denied):
        profiles.validate(value)


def apply_profiles(driver, client, value):
    return client.post(
        "/internal/operator/console/pool",
        headers=operator(driver),
        json={"action": "profiles", "configuration": value, "receipt_sha256": "b" * 64},
    )


def test_idle_target_and_workflow_revision_preserves_existing_run_bindings(tmp_path):
    driver, client, worker = setup(tmp_path)
    context = prepare(driver, client)
    incident = next(
        v
        for v in driver.execution_contexts(active_only=True)
        if v.get("workflow") == "incident-triage"
    )
    run = driver.register_run(
        driver.sessions["opaque"]["claims"], incident, queue_workflow="incident-triage"
    )
    assert driver.console.claim(worker)["run_id"] == run
    changed = configuration()
    changed["profiles"][0]["target"] = 3
    next(w for w in changed["workflows"] if w["workflow"] == "incident-triage")[
        "project"
    ] = "SERVICE"
    assert apply_profiles(driver, client, changed).status_code == 403
    driver.store.cancel(run, "user-a")
    driver.console.update(run, worker, "completed", {"cleanup_verified": True})
    assert apply_profiles(driver, client, changed).status_code == 200
    assert driver.context_for_workload(context["workload"])["project"] == "OPS"
    with driver.store.read_transaction() as db:
        assert profiles.configuration(db) == changed
        history = [
            json.loads(v[0])
            for v in db.execute(
                "SELECT configuration FROM console_pool_contract_history"
            )
        ]
        assert configuration() in history and changed in history
    fresh = prepare(driver, client)
    if fresh["role"] != "triage":
        fresh = prepare(driver, client)
    assert fresh["role"] == "triage"
    choice = next(
        v
        for v in driver.execution_contexts(active_only=True)
        if v["workload"] == fresh["workload"] and v.get("workflow") == "incident-triage"
    )
    assert choice["project"] == "SERVICE"
    restored = Driver(driver.config, driver.verify)
    assert restored.context_for_workload(context["workload"])["project"] == "OPS"


def test_security_profile_change_requires_retirement_without_erasing_old_contract(
    tmp_path,
):
    driver, client, worker = setup(tmp_path)
    context = prepare(driver, client)
    changed = configuration()
    changed["profiles"][0]["policy"]["filesystem_policy"]["read_only"].append(
        "/approved"
    )
    assert apply_profiles(driver, client, changed).status_code == 403
    # Represent completion of the separately guarded retirement path. The
    # configuration operation itself never changes or deletes native resources.
    with driver.store.transaction() as db:
        db.execute(
            "UPDATE console_pool_items SET state='retired' WHERE workload=?",
            (context["workload"],),
        )
    assert apply_profiles(driver, client, changed).status_code == 200
    with driver.store.read_transaction() as db:
        prior = json.loads(
            db.execute(
                "SELECT configuration FROM console_pool_contract_history WHERE digest=?",
                (profiles.digest(configuration()),),
            ).fetchone()[0]
        )
        assert prior == configuration()
        assert not profiles.ready(db, context["workload"])
        assert (
            db.execute(
                "SELECT fingerprint FROM console_profile_contexts WHERE workload=?",
                (context["workload"],),
            ).fetchone()[0]
            == context["profile_fingerprint"]
        )


def test_ambiguous_preparation_pins_its_contract_without_a_verified_context_row(
    tmp_path,
):
    driver, client, _ = setup(tmp_path)
    owner = uuid4().hex
    reservation = reserve(driver, client, owner)
    assert finish(driver, client, owner, reservation, None).status_code == 200
    changed = configuration()
    changed["profiles"][0]["policy"]["filesystem_policy"]["read_only"].append(
        "/changed"
    )
    assert apply_profiles(driver, client, changed).status_code == 403
    changed = configuration()
    changed["profiles"][0]["target"] = 3
    assert apply_profiles(driver, client, changed).status_code == 200
    assert (
        driver.console.pool_status(driver.config.contexts, driver.config.project)[
            "automatic"
        ]["states"]["quarantined"]
        == 1
    )


def test_replenishment_fairness_does_not_scan_retained_history(tmp_path):
    driver, _, _ = setup(tmp_path)
    with driver.store.transaction() as db:
        reader = json.dumps({"profile_id": "read-only-v1"})
        triage = json.dumps({"profile_id": "shared-triage-v1"})
        rows = [("old-reader", None, reader, "retired", 1, "a" * 64, 1)]
        rows += [("old-triage-" + str(i), None, triage, "retired", 1, "a" * 64, i + 2)
                 for i in range(10_000)]
        db.executemany("INSERT INTO console_pool_items VALUES(?,?,?,?,?,?,?)", rows)
        ticks = [0]

        def budget():
            ticks[0] += 1
            return int(ticks[0] > 50)

        # Bound actual SQLite work, rather than assert a particular index name.
        db.set_progress_handler(budget, 100)
        try:
            target = profiles.next_target(db, lambda *_: False)
        finally:
            db.set_progress_handler(None, 0)
        assert target["profile_id"] == "read-only-v1"
        assert target["operation"] == "prepare"
        assert ticks[0] < 50
        assert db.execute("SELECT count(*) FROM console_pool_items").fetchone()[0] == 10_001


def test_pool_totals_backfill_once_and_follow_legacy_writes_and_rollback(tmp_path):
    from identity_demo_warm_pool import initialize
    driver, _, _ = setup(tmp_path)
    with driver.store.transaction() as db:
        for name in ("insert", "update", "delete"):
            db.execute("DROP TRIGGER console_pool_count_" + name)
        db.execute("DROP TABLE console_pool_state_counts")
        db.execute("INSERT INTO console_pool_items VALUES(?,?,?,?,?,?,?)",
                   ("historical", None, "{}", "retired", 0, "a" * 64, 1))
    with driver.store.transaction() as db:
        initialize(db)
        initialize(db)
        assert profiles.state_counts(db)["retired"] == 1
        db.execute("INSERT INTO console_pool_items VALUES(?,?,?,?,?,?,?)",
                   ("new", None, "{}", "preparing", 1, "a" * 64, 2))
        db.execute("UPDATE console_pool_items SET state='ready' WHERE id='new'")
    with pytest.raises(RuntimeError, match="interrupted"):
        with driver.store.transaction() as db:
            db.execute("UPDATE console_pool_items SET state='quarantined' WHERE id='new'")
            raise RuntimeError("interrupted")
    with driver.store.read_transaction() as db:
        totals = profiles.state_counts(db)
        assert totals["ready"] == 1 and totals["quarantined"] == 0 and totals["retired"] == 1
        assert db.execute("SELECT count(*) FROM console_pool_items").fetchone()[0] == 2
    with driver.store.transaction() as db:
        db.execute("UPDATE console_pool_items SET state='retired' WHERE id='new'")
        assert profiles.state_counts(db)["retired"] == 2
        # Older code can change the same journal without knowing the new table.
        assert profiles.state_counts(db)["ready"] == 0


def test_reviewed_failed_creation_releases_capacity_and_preserves_quarantine(tmp_path):
    import hashlib
    import identity_demo_warm_pool as warm

    driver, client, _ = setup(tmp_path)
    owner = uuid4().hex
    reservation = reserve(driver, client, owner)
    assert finish(driver, client, owner, reservation, None).status_code == 200
    identifier = reservation['id']
    with driver.store.transaction() as db:
        failure = db.execute('SELECT * FROM console_preparations WHERE id=?', (identifier,)).fetchone()
        target = hashlib.sha256(failure['target'].encode()).hexdigest()
        receipt = failure['receipt']
        with pytest.raises(Denied, match='unused_retirement_not_idle'):
            warm.confirm_failed_creation_absent(db, identifier, receipt, target, 'e'*64)
        db.execute('UPDATE console_pool_settings SET enabled=0')
        db.execute('UPDATE console_worker SET updated=0')
        db.execute('UPDATE console_preparer SET updated=0')
        for wrong_receipt, wrong_target in [('f'*64, target), (receipt, 'f'*64)]:
            with pytest.raises(Denied, match='failed_creation_binding'):
                warm.confirm_failed_creation_absent(db, identifier, wrong_receipt, wrong_target, 'e'*64)
        warm.confirm_failed_creation_absent(db, identifier, receipt, target, 'e'*64)
        warm.confirm_failed_creation_absent(db, identifier, receipt, target, 'e'*64)
        retained = db.execute('SELECT * FROM console_preparations WHERE id=?', (identifier,)).fetchone()
        assert dict(retained) == dict(failure)
        item = db.execute('SELECT * FROM console_pool_items WHERE id=?', (identifier,)).fetchone()
        assert item['state'] == 'retired' and item['workload'] is None
        assert item['context'] == failure['target']
        assert db.execute("SELECT count(*) FROM audit WHERE event='failed_creation_absence_confirmed'").fetchone()[0] == 1
        with pytest.raises(Denied, match='failed_creation_binding'):
            warm.confirm_failed_creation_absent(db, identifier, receipt, target, 'a'*64)
    restarted = Driver(driver.config)
    with restarted.store.read_transaction() as db:
        assert db.execute('SELECT state FROM console_preparations WHERE id=?', (identifier,)).fetchone()[0] == 'quarantined'
        assert db.execute('SELECT state FROM console_pool_items WHERE id=?', (identifier,)).fetchone()[0] == 'retired'


@pytest.mark.parametrize('change', ['worker', 'active', 'unknown', 'preparing', 'workload', 'operation', 'target'])
def test_failed_creation_reconciliation_stops_on_live_or_changed_state(tmp_path, change):
    import hashlib
    import identity_demo_warm_pool as warm

    driver, client, _ = setup(tmp_path)
    owner = uuid4().hex
    reservation = reserve(driver, client, owner)
    assert finish(driver, client, owner, reservation, None).status_code == 200
    identifier = reservation['id']
    with driver.store.transaction() as db:
        row = db.execute('SELECT * FROM console_preparations WHERE id=?', (identifier,)).fetchone()
        target = hashlib.sha256(row['target'].encode()).hexdigest()
        db.execute('UPDATE console_pool_settings SET enabled=0')
        db.execute('UPDATE console_worker SET updated=0')
        db.execute('UPDATE console_preparer SET updated=0')
        if change == 'worker':
            db.execute('UPDATE console_worker SET updated=?', (int(time.time()),))
        elif change == 'active':
            db.execute('UPDATE runs SET active=1')
        elif change == 'unknown':
            run_id = db.execute('SELECT id FROM runs LIMIT 1').fetchone()[0]
            db.execute("INSERT INTO actions(id,run_id,payload,digest,state) VALUES(?,?,?,?,'unknown')",
                       ('uncertain-write', run_id, '{}', 'a'*64))
            assert db.execute("SELECT count(*) FROM actions WHERE state='unknown'").fetchone()[0] == 1
        elif change == 'preparing':
            db.execute("UPDATE console_preparations SET state='preparing'")
        elif change == 'workload':
            db.execute("UPDATE console_pool_items SET workload='spiffe://not-a-failed-create'")
        elif change == 'operation':
            value = json.loads(row['target'])
            value['operation'] = 'retire'
            encoded = json.dumps(value, sort_keys=True)
            db.execute('UPDATE console_preparations SET target=?', (encoded,))
            db.execute('UPDATE console_pool_items SET context=?', (encoded,))
            target = hashlib.sha256(encoded.encode()).hexdigest()
        else:
            db.execute("UPDATE console_pool_items SET context='{}'")
        with pytest.raises(Denied):
            warm.confirm_failed_creation_absent(db, identifier, row['receipt'], target, 'e'*64)
        assert db.execute('SELECT state FROM console_pool_items WHERE id=?', (identifier,)).fetchone()[0] == 'quarantined'


@pytest.mark.parametrize("fault", ["missing-write", "extra-write", "wrong-tools", "unknown-resource"])
def test_profile_cannot_misdescribe_registered_connector_authority(fault):
    value = configuration()
    if fault == "missing-write":
        value["profiles"][0]["write_actions"] = []
    elif fault == "extra-write":
        value["profiles"][0]["write_actions"].append("jira.issue.delete")
    elif fault == "wrong-tools":
        value["profiles"][0]["tools"] = ["unregistered.tool"]
    else:
        value["workflows"][0]["project"] = "not/a/jira/project"
    with pytest.raises(Denied, match="pool_connector_permissions"):
        profiles.validate(value)


def test_non_jira_profile_uses_reviewed_document_actions_and_scope(monkeypatch):
    from checks.test_connector_contract import DOCUMENTS
    from identity_demo_connector import ConnectorRegistry
    contract = replace(DOCUMENTS,
        profile_tools=("document.read", "document.publish"),
        profile_write_actions=("document.publish",))
    monkeypatch.setattr(profiles, "supported_connectors", lambda: ConnectorRegistry((contract,)))
    value = configuration()
    for p in value["profiles"]:
        p["tools"] = list(contract.profile_tools) if p["role"] == "triage" else ["document.read"]
        p["write_actions"] = list(contract.profile_write_actions) if p["role"] == "triage" else []
    for workflow in value["workflows"]:
        workflow.update(connector=contract.identifier, project="handbook")
    assert profiles.validate(value) == value
    value["workflows"][0]["project"] = "foreign-collection"
    with pytest.raises(Denied, match="pool_connector_permissions"):
        profiles.validate(value)


def test_profile_rejects_connector_without_reviewed_pool_actions(monkeypatch):
    from checks.test_connector_contract import DOCUMENTS
    from identity_demo_connector import ConnectorRegistry
    monkeypatch.setattr(profiles, "supported_connectors", lambda: ConnectorRegistry((DOCUMENTS,)))
    value = configuration()
    for workflow in value["workflows"]:
        workflow.update(connector=DOCUMENTS.identifier, project="handbook")
    with pytest.raises(Denied, match="pool_connector_permissions"):
        profiles.validate(value)


def test_profile_action_consistency_preserves_existing_grant_fingerprints():
    from identity_demo_jira_contract import JIRA
    previous = replace(JIRA, profile_tools=(), profile_write_actions=())
    assert previous.fingerprint == JIRA.fingerprint
    assert previous.canonical({"project": "TEST", "issue_type": "Task", "summary": "Reviewed task",
        "description": "Synthetic context", "labels": []}) == JIRA.canonical({
        "project": "TEST", "issue_type": "Task", "summary": "Reviewed task",
        "description": "Synthetic context", "labels": []})


def test_invalid_profile_actions_cannot_change_active_inventory(tmp_path):
    driver, client, worker = setup(tmp_path)
    prepare(driver, client)
    with driver.store.read_transaction() as db:
        before = [tuple(row) for row in db.execute("SELECT * FROM console_pool_items ORDER BY id")]
        contract = tuple(db.execute("SELECT * FROM console_pool_contract").fetchone())
    bad = configuration()
    bad["profiles"][0]["write_actions"] = []
    response = client.post("/internal/operator/console/pool", headers=operator(driver),
        json={"action": "profiles", "configuration": bad, "receipt_sha256": "d" * 64})
    assert response.status_code == 403
    with driver.store.read_transaction() as db:
        assert [tuple(row) for row in db.execute("SELECT * FROM console_pool_items ORDER BY id")] == before
        assert tuple(db.execute("SELECT * FROM console_pool_contract").fetchone()) == contract
