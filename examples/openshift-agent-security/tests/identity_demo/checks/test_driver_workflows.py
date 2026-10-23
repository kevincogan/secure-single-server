# SPDX-License-Identifier: Apache-2.0
"""Reuse changes only trusted workflow/project configuration, not authorization."""

from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest
from starlette.testclient import TestClient

from identity_demo_driver import COOKIE, Driver
from checks.test_driver import setup


def configured(tmp_path: Path) -> tuple:
    """Add a separately identified service context to the existing driver fixture."""
    previous, _, _, _ = setup(tmp_path)
    context = dict(previous.config.contexts[0])
    context.update(sandbox_id=str(uuid4()), workflow="service-request", project="SERVICE")
    context["workload"] = "spiffe://agents.example.test/openshell/sandbox/" + context["sandbox_id"]
    driver = Driver(replace(previous.config, contexts=(*previous.config.contexts, context)), previous.verify)
    driver.sessions = previous.sessions
    client = TestClient(driver.app, base_url=driver.config.origin)
    client.cookies.set(COOKIE, "opaque")
    return driver, client, context


def test_service_submission_uses_trusted_separate_project_and_identity(tmp_path: Path) -> None:
    """A service request cannot borrow a CVE identity or browser-selected project."""
    driver, client, context = configured(tmp_path)
    assert "Start remediation request" in client.get("/").text
    response = client.post("/submit", headers={"Origin": driver.config.origin},
        data={"csrf": "csrf-fixture", "role": "triage", "request": "SERVICE-0001"},
        follow_redirects=False)
    assert response.status_code == 303
    record = driver.store.describe(response.headers["location"].split("/")[-1], "user-a")
    assert record["run"]["workload"] == context["workload"]
    assert record["run"]["project"] == "SERVICE"


@pytest.mark.parametrize("extra", [
    {"project": "TEST"}, {"request": "unknown"}, {"cve": "CVE-2099-0001"},
    {"workload": "forged"},
])
def test_service_submission_rejects_unapproved_inputs(tmp_path: Path, extra: dict) -> None:
    """Additional fields cannot alter identity, workflow or project mapping."""
    driver, client, _ = configured(tmp_path)
    response = client.post("/submit", headers={"Origin": driver.config.origin},
        data={"csrf": "csrf-fixture", "role": "triage", "request": "SERVICE-0001", **extra})
    assert response.status_code == 403


def test_cve_submission_cannot_consume_service_context(tmp_path: Path) -> None:
    """The already consumed CVE context stays retired; service context is separate."""
    driver, client, _ = configured(tmp_path)
    response = client.post("/submit", headers={"Origin": driver.config.origin},
        data={"csrf": "csrf-fixture", "role": "triage", "cve": "CVE-2099-0001"})
    assert response.status_code == 409


@pytest.mark.parametrize("project", ["TEST", "bad project", None])
def test_service_mapping_requires_valid_dedicated_project(tmp_path: Path, project: object) -> None:
    """Reject invalid or non-dedicated service workflow configuration at startup."""
    driver, _, context = configured(tmp_path)
    with pytest.raises(ValueError, match="Controlled namespace/role"):
        Driver(replace(driver.config, contexts=({**context, "project": project},)), driver.verify)
