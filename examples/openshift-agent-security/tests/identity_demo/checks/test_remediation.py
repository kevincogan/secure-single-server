# SPDX-License-Identifier: Apache-2.0
"""Remediation input, versioned history and repeatable fixture preparation contracts."""

from argparse import Namespace
from copy import deepcopy
from dataclasses import replace
from io import StringIO
from contextlib import redirect_stdout
import json
from types import SimpleNamespace
import sys
import time
from uuid import uuid4

import pytest

import identity_demo_console as console
import identity_demo_console_visuals as visuals
import identity_demo_execution_setup as setup
from identity_demo_console_store import safe_evidence
from identity_demo_run_store import Denied
from checks.test_console import configured


@pytest.mark.parametrize("role", ["analyst", "viewer"])
@pytest.mark.parametrize("selected", ["triage", "reader"])
def test_cards_describe_expected_role_specific_flow(role, selected):
    page = console.home(
        {"display_role": role, "exp": time.time() + 1200},
        "fixture-csrf",
        available=True,
        service=True,
        incident=True,
        incident_available=True,
        roles=(selected, "reader" if selected == "triage" else "triage"),
        coordinator={"enabled": True, "online": True, "ready": True},
    )
    assert "Remediation change request" in page and "Start remediation request" in page
    assert "Model drafts the change, tests and rollback" in page
    assert "controlled TEST access is denied" in page
    assert f'<div data-cve-preview="{selected}">' in page
    other = "reader" if selected == "triage" else "triage"
    assert f'<div data-cve-preview="{other}" hidden>' in page
    assert (
        "Gateway denies the viewer" in page
        if role == "viewer"
        else "Gateway denies the reader" in page
    )
    assert "expected steps, not recorded results" in page
    assert "cvePreview(); if (latestHome) home(latestHome)" in console.LIVE_SCRIPT


def test_new_service_jobs_are_versioned_without_rewriting_old_history(tmp_path):
    driver, client, context = configured(tmp_path)
    context = {**context, "workflow": "service-request", "project": "SERVICE"}
    driver.config = replace(driver.config, contexts=(context,))
    driver.console.heartbeat(uuid4().hex)
    response = client.post(
        "/submit",
        headers={"Origin": driver.config.origin},
        data={"csrf": "csrf-fixture", "role": "triage", "request": "SERVICE-0001"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    run = response.headers["location"].rsplit("/", 1)[-1]
    assert (
        driver.console.describe(run)["evidence"]["scenario_version"] == "remediation-v1"
    )
    assert "Remediation change request" in client.get("/runs/" + run).text
    assert "Supplied frozen CVE-2099-0001" in client.get("/runs/" + run).text
    assert "Remediation change request" in client.get("/runs").text
    # Legacy jobs have no version: never relabel or invent a historical input.
    with driver.store.transaction() as db:
        db.execute("UPDATE console_jobs SET evidence='{}' WHERE run_id=?", (run,))
    old = client.get("/runs/" + run).text
    assert "<h1>Service request</h1>" in old and "Training workspace" in old
    assert "Supplied frozen CVE-2099-0001" not in old
    assert "Remediation change request" not in client.get("/runs").text
    assert "Training workspace" in visuals.input_context("service-request")


def test_scenario_metadata_never_accepts_arbitrary_text():
    assert safe_evidence({"scenario_version": "remediation-v1"})
    with pytest.raises(Denied):
        safe_evidence({"scenario_version": "unreviewed-or-secret"})


def capture_seed_program(monkeypatch, tmp_path):
    """Capture the actual sandboxed setup program; no cluster mutation occurs."""
    captured = {}
    monkeypatch.setattr(setup, "guard", lambda _: None)
    monkeypatch.setattr(setup, "inspect_state", lambda _: {"rollback_quiescent": True})
    monkeypatch.setattr(
        setup, "read", lambda *a: {"metadata": {"labels": setup.LABELS}}
    )

    def run(words, **kw):
        captured.update(source=words[-1], settings=json.loads(kw["input"]))
        return SimpleNamespace(returncode=0, stdout="{}", stderr="")

    monkeypatch.setattr(setup.subprocess, "run", run)
    setup.provision_project(
        Namespace(
            project="SERVICE", apply=True, kubeconfig="fixture", output_dir=tmp_path
        )
    )
    compile(captured["source"], "<fixture-preparation>", "exec")
    return captured


@pytest.mark.parametrize("conflict", [False, True])
def test_seed_preparation_is_additive_idempotent_and_collision_refusing(
    monkeypatch, tmp_path, conflict
):
    captured = capture_seed_program(monkeypatch, tmp_path)
    original = {
        "key": "SERVICE-1",
        "fields": {"summary": "Retained workspace task", "description": "Preserve me"},
    }
    issues = {"SERVICE": [deepcopy(original)], "TEST": [], "OPS": []}
    posts = []
    if conflict:
        issues["SERVICE"].append(
            {
                "key": "SERVICE-2",
                "fields": {
                    **captured["settings"]["reuse_seeds"][0],
                    "labels": ["foreign-owner"],
                },
            }
        )

    class Response:
        def __init__(self, data, status=200):
            self.data, self.status_code = data, status

        def json(self):
            return deepcopy(self.data)

    class Client:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

        async def get(self, url, params=None):
            if url.endswith("/project/SERVICE"):
                return Response({"name": "Synthetic service requests"})
            project = params["jql"].split()[-1]
            return Response({"total": len(issues[project]), "issues": issues[project]})

        async def post(self, url, json):
            assert url.endswith("/rest/api/2/issue")
            fields = json["fields"]
            assert fields["project"]["key"] == "SERVICE"
            issue = {
                "key": "SERVICE-" + str(len(issues["SERVICE"]) + 1),
                "fields": deepcopy(fields),
            }
            issues["SERVICE"].append(issue)
            posts.append(issue)
            return Response({"key": issue["key"]}, 201)

    monkeypatch.setitem(
        sys.modules,
        "httpx",
        SimpleNamespace(AsyncClient=Client, BasicAuth=lambda *a: None),
    )
    import ssl

    monkeypatch.setattr(ssl, "create_default_context", lambda **kwargs: None)
    monkeypatch.setenv("JIRA_USER", "synthetic")
    monkeypatch.setenv("JIRA_TOKEN", "synthetic")

    def execute():
        monkeypatch.setattr(sys, "stdin", StringIO(json.dumps(captured["settings"])))
        with redirect_stdout(StringIO()):
            exec(captured["source"], {})

    if conflict:
        with pytest.raises(AssertionError, match="ownership/content differs"):
            execute()
        assert not posts
    else:
        execute()
        execute()
        assert len(posts) == 3 and len(issues["SERVICE"]) == 4
        assert issues["SERVICE"][0] == original
        assert issues["TEST"] == [] and issues["OPS"] == []
