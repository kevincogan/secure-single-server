# SPDX-License-Identifier: Apache-2.0
"""Shared driver test setup; contains no collected tests."""
import json
from pathlib import Path
import time
from uuid import uuid4
from starlette.testclient import TestClient
from identity_demo_driver import Config, COOKIE, Driver

def setup(
    tmp_path: Path, role: str = "analyst", workload_role: str = "triage"
) -> tuple:
    """Create synthetic trusted inputs without claiming these authenticate a live user."""
    tmp_path.chmod(0o700)
    wid = str(uuid4())
    workload = "spiffe://agents.example.test/openshell/sandbox/" + wid
    config = Config(
        "https://issuer.example.test/realms/pilot",
        "identity-demo-driver",
        "https://driver.example.test",
        "https://mcp.example.test/mcp",
        tmp_path / "runs.db",
        (
            {
                "role": workload_role,
                "namespace": "demo-" + workload_role,
                "service_account": "fixture-openshell-sandbox",
                "workload": workload,
                "sandbox_id": wid,
            },
        ),
        "g" * 40,
        "o" * 40,
        "a" * 40,
    )
    now = int(time.time())
    user = {
        "iss": config.issuer,
        "sub": "user-a",
        "aud": config.client,
        "azp": config.client,
        "iat": now,
        "exp": now + 300,
        "realm_access": {"roles": [role]},
    }
    final = {
        **user,
        "aud": config.audience,
        "azp": workload,
        "exp": now + 30,
    }

    def verify(token: str, audience: str) -> dict:
        assert token in ("human", "final")
        value = user if token == "human" else final
        assert value["aud"] == audience
        return value

    driver = Driver(config, verify)
    run = driver.register_run(user, config.contexts[0])
    # A final exchange happens after run registration. Avoid minting the test
    # token in the preceding wall-clock second and tripping the real iat gate.
    final["iat"] = driver.store.describe(run, user["sub"])["run"]["not_before"]
    final["exp"] = final["iat"] + 30
    driver.sessions["opaque"] = {
        "claims": user,
        "token": "human",
        "csrf": "csrf-fixture",
        "runs": {run},
    }
    client = TestClient(driver.app, base_url=config.origin)
    client.cookies.set(COOKIE, "opaque")
    return driver, client, run, final

def approved(driver: Driver, run: str) -> dict:
    """Persist consent to the exact fixture action."""
    p = driver.store.propose(
        run,
        "user-a",
        {"project": "TEST", "summary": "Summary", "description": "Description"},
    )
    driver.store.approve(
        run, p["action_id"], "user-a", p["digest"], int(time.time()) + 100
    )
    return p

def auth_context(driver: Driver, run: str, claims: dict, p: dict) -> dict:
    """Shape the authenticated gateway context without unsigned identity authority."""
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "step56_jira_createJiraIssue",
            "arguments": {"run_id": run, "action_id": p["action_id"], **p["arguments"]},
        },
    }
    return {
        "context": {
            "request": {
                "http": {
                    "path": "/mcp",
                    "method": "POST",
                    "headers": {
                        "authorization": "Bearer final",
                    },
                    "body": json.dumps(body),
                }
            }
        }
    }
