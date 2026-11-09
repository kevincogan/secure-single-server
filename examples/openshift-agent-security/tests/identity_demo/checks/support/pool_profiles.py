# SPDX-License-Identifier: Apache-2.0
"""Shared pool profiles test setup; contains no collected tests."""
from dataclasses import asdict, replace
import time
from uuid import uuid4
from checks.support.console import configured, operator
from checks.support.console_preparer import reserve, finish
from identity_demo_execution_setup import context_template
from deployment_profile import active_profile

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
        "issuer": p.delegation_issuer,
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
    driver.config = replace(driver.config, contexts=())
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

def apply_profiles(driver, client, value):
    return client.post(
        "/internal/operator/console/pool",
        headers=operator(driver),
        json={"action": "profiles", "configuration": value, "receipt_sha256": "b" * 64},
    )
