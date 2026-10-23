# SPDX-License-Identifier: Apache-2.0
"""Driver boundary tests; real issuer and gateway proof is separate live evidence."""

import base64
import hashlib
import json
from pathlib import Path
import time
from types import SimpleNamespace
from uuid import uuid4
from dataclasses import replace
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.testclient import TestClient
from identity_demo_console import LIVE_SCRIPT
from identity_demo_driver import (
    Config,
    COOKIE,
    Driver,
    Verifier,
    peer_matches,
    NoIssuerRedirect,
    prepare_storage,
)
from identity_demo_run_store import Denied


def test_empty_installation_starts_without_authorizing_a_workload(tmp_path: Path) -> None:
    """Fresh installation can become healthy before trusted workload provisioning."""
    previous, _, _, _ = setup(tmp_path)
    driver = Driver(replace(previous.config, database=tmp_path / "fresh.db", contexts=()), previous.verify)
    driver.sessions = previous.sessions
    client = TestClient(driver.app, base_url=driver.config.origin)
    client.cookies.set(COOKIE, "opaque")
    assert client.get("/healthz").json() == {"ready": True, "execution_contexts_configured": False}
    assert "No workloads are available" in client.get("/").text
    response = client.post("/submit", headers={"Origin": driver.config.origin},
        data={"csrf": "csrf-fixture", "role": "triage", "cve": "CVE-2099-0001"})
    assert response.status_code in (403, 409)
    assert not driver.config.contexts


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
    thumb = (
        base64.urlsafe_b64encode(hashlib.sha256(b"public-cert-fixture").digest())
        .decode()
        .rstrip("=")
    )
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
        "cnf": {"x5t#S256": thumb},
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


def test_ui_displays_profile_menu_session_and_verified_run_role(tmp_path: Path) -> None:
    """Keep account actions and bounded browser-session status in the navigation."""
    driver, client, run, _ = setup(tmp_path)
    home = client.get("/")
    assert home.status_code == 200
    assert "Browser session" in home.text and "data-session-deadline=" in home.text
    assert 'class="account-panel-label">Signed in</span><strong>analyst</strong>' in home.text
    assert 'class="account-session-heading">' in home.text
    assert 'class="account-session-state" data-session-state>' in home.text
    assert 'class="account-session-time" data-session-deadline=' in home.text
    assert "Activity can extend this session within its configured limits." in home.text
    assert "Sign-in needed" in LIVE_SCRIPT
    assert "Sign in again" in home.text and "Sign out" in home.text
    assert 'action="/logout"' in home.text and 'name="csrf"' in home.text
    assert "Signed in as " not in home.text and "Authenticated role:" not in home.text
    assert "Automatic refill is paused" not in home.text
    assert home.headers["referrer-policy"] == "same-origin"
    status = client.get("/runs/" + run)
    assert status.status_code == 200
    assert "User role: analyst" in status.text and "Workload: triage" in status.text
    assert "Project: TEST" in status.text
    assert "csrf-fixture" not in status.text.split("<h2>Decision and outcome audit</h2>")[-1]
    live = client.get("/runs/" + run + "/live")
    assert live.status_code == 200
    assert live.json()["session_deadline"] == driver.sessions["opaque"]["claims"]["exp"]
    assert live.headers["x-session-deadline"] == str(driver.sessions["opaque"]["claims"]["exp"])


@pytest.mark.parametrize("origin", ["null", "https://untrusted.example"])
def test_browser_compatibility_never_accepts_wrong_origin(tmp_path: Path, origin: str) -> None:
    """Keep exact Origin and CSRF enforcement after changing Referrer-Policy."""
    _, client, _, _ = setup(tmp_path)
    response = client.post("/submit", headers={"Origin": origin}, data={
        "csrf": "csrf-fixture", "role": "triage", "cve": "CVE-2099-0001"})
    assert response.status_code == 403 and response.json()["reason"] == "csrf_origin"


def test_reauthenticated_owner_approves_without_extending_run(tmp_path: Path) -> None:
    """A renewed session may consent, but never pushes the original deadline forward."""
    driver, client, run, _ = setup(tmp_path)
    original = driver.store.describe(run, "user-a")["run"]["expires"]
    proposal = driver.store.propose(run, "user-a", {"project": "TEST", "summary": "Renewed session", "description": "Synthetic"})
    driver.sessions["opaque"]["claims"]["exp"] = original + 600
    response = client.post("/runs/" + run + "/approve", follow_redirects=False,
        headers={"Origin": driver.config.origin}, data={"csrf": "csrf-fixture",
        "action": proposal["action_id"], "digest": proposal["digest"]})
    assert response.status_code == 303
    record = driver.store.describe(run, "user-a")
    assert record["run"]["expires"] == original
    assert record["actions"][0]["approval_expires"] == original


def test_reauthentication_cannot_approve_expired_run(tmp_path: Path, monkeypatch: object) -> None:
    """A fresh human session cannot revive the expired execution context."""
    driver, client, run, _ = setup(tmp_path)
    original = driver.store.describe(run, "user-a")["run"]["expires"]
    proposal = driver.store.propose(run, "user-a", {"project": "TEST", "summary": "Expired run", "description": "Synthetic"})
    driver.sessions["opaque"]["claims"]["exp"] = original + 600
    monkeypatch.setattr("identity_demo_run_store.time.time", lambda: original + 1)
    response = client.post("/runs/" + run + "/approve", follow_redirects=False,
        headers={"Origin": driver.config.origin}, data={"csrf": "csrf-fixture",
        "action": proposal["action_id"], "digest": proposal["digest"]})
    assert response.status_code == 403
    assert driver.store.describe(run, "user-a")["actions"][0]["state"] == "proposed"


def auth_context(driver: Driver, run: str, claims: dict, p: dict) -> dict:
    """Shape the tested Authorino context, with a simulated trusted TLS peer."""
    fingerprint = base64.urlsafe_b64decode(claims["cnf"]["x5t#S256"] + "=").hex()
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
                        "x-forwarded-client-cert": "Hash="
                        + fingerprint
                        + ";URI="
                        + claims["azp"],
                    },
                    "body": json.dumps(body),
                }
            }
        }
    }


def test_actual_body_matches_approval_and_authorization_does_not_claim(
    tmp_path: Path,
) -> None:
    """Credential metadata lookup must not consume the action."""
    d, c, r, claims = setup(tmp_path)
    p = approved(d, r)
    ctx = auth_context(d, r, claims, p)
    response = c.post(
        "/internal/authorize",
        json=ctx,
        headers={"Authorization": "Bearer " + d.config.gateway_secret},
    )
    assert response.status_code == 200 and response.json()["allowed"]
    assert d.store.describe(r, "user-a")["actions"][0]["state"] == "approved"
    rpc = json.loads(ctx["context"]["request"]["http"]["body"])
    rpc["params"]["arguments"]["description"] = "Changed"
    ctx["context"]["request"]["http"]["body"] = json.dumps(rpc)
    response = c.post(
        "/internal/authorize",
        json=ctx,
        headers={"Authorization": "Bearer " + d.config.gateway_secret},
    )
    assert response.json()["reason"] == "action_binding"


@pytest.mark.parametrize(
    "change", ["missing_body", "peer", "run", "expired_run", "missing_token"]
)
def test_auth_context_fails_closed(tmp_path: Path, change: str) -> None:
    """Identity, body and current state must all remain valid."""
    d, c, r, claims = setup(tmp_path)
    p = approved(d, r)
    ctx = auth_context(d, r, claims, p)
    http = ctx["context"]["request"]["http"]
    if change == "missing_body":
        del http["body"]
    if change == "peer":
        http["headers"]["x-forwarded-client-cert"] = (
            "Hash=" + "0" * 64 + ";URI=" + claims["azp"]
        )
    if change == "run":
        rpc = json.loads(http["body"])
        rpc["params"]["arguments"]["run_id"] = "f" * 32
        http["body"] = json.dumps(rpc)
    if change == "expired_run":
        d.store.cancel(r, "user-a")
    if change == "missing_token":
        del http["headers"]["authorization"]
    assert not c.post(
        "/internal/authorize",
        json=ctx,
        headers={"Authorization": "Bearer " + d.config.gateway_secret},
    ).json()["allowed"]


@pytest.mark.parametrize(
    "user_role,workload_role,reason",
    [
        ("viewer", "triage", "user_permission"),
        ("analyst", "reader", "workload_permission"),
    ],
)
def test_permission_intersection_with_real_stored_approval(
    tmp_path: Path, user_role: str, workload_role: str, reason: str
) -> None:
    """Approval cannot elevate the user's or controlled workload's authority."""
    d, c, r, claims = setup(tmp_path, user_role, workload_role)
    p = approved(d, r)
    response = c.post(
        "/internal/authorize",
        json=auth_context(d, r, claims, p),
        headers={"Authorization": "Bearer " + d.config.gateway_secret},
    )
    assert response.json()["reason"] == reason
    audit = d.store.describe(r, "user-a")["audit"]
    assert audit[-1]["event"] == "denied"
    assert audit[-1]["action_id"] == p["action_id"]
    assert json.loads(audit[-1]["detail"])["reason"] == reason


def test_internal_secrets_have_separate_scope(tmp_path: Path) -> None:
    """A gateway credential cannot register a user context or release credentials."""
    d, c, r, _ = setup(tmp_path)
    assert (
        c.post(
            "/internal/operator/run",
            json={},
            headers={"Authorization": "Bearer " + d.config.gateway_secret},
        ).status_code
        == 403
    )
    assert c.get("/internal/operator/credentials/" + r).status_code == 403
    response = c.get(
        "/internal/operator/credentials/" + r,
        headers={"Authorization": "Bearer " + d.config.operator_secret},
    )
    assert response.status_code == 200 and response.json()["access_token"] == "human"
    d.store.cancel(r, "user-a")
    assert (
        c.get(
            "/internal/operator/credentials/" + r,
            headers={"Authorization": "Bearer " + d.config.operator_secret},
        ).status_code
        == 403
    )


def test_ui_owner_scope_escape_and_no_tokens(tmp_path: Path) -> None:
    """Untrusted report text remains text, with no browser credential disclosure."""
    d, c, r, _ = setup(tmp_path)
    d.store.save_assessment(r, "user-a", "<script>window.pwned=true</script>")
    response = c.get("/runs/" + r)
    assert "&lt;script&gt;" in response.text and "<script>" not in response.text
    assert "Bearer" not in response.text and "access_token" not in response.text
    d.sessions["opaque"]["claims"]["sub"] = "user-b"
    assert c.get("/runs/" + r).status_code == 403


@pytest.mark.parametrize(
    "origin,csrf",
    [
        ("https://evil.example", "csrf-fixture"),
        ("https://driver.example.test", "wrong"),
    ],
)
def test_approval_csrf_denied(tmp_path: Path, origin: str, csrf: str) -> None:
    """A cross-site or unbound consent request cannot change approval state."""
    d, c, r, _ = setup(tmp_path)
    p = d.store.propose(
        r,
        "user-a",
        {"project": "TEST", "summary": "Summary", "description": "Description"},
    )
    response = c.post(
        "/runs/" + r + "/approve",
        data={"csrf": csrf, "action": p["action_id"], "digest": p["digest"]},
        headers={"Origin": origin},
        follow_redirects=False,
    )
    assert response.status_code == 403
    assert d.store.describe(r, "user-a")["actions"][0]["state"] == "proposed"


def test_approval_exact_fields_and_cancel_preserve_assessment(tmp_path: Path) -> None:
    """The real form path binds the displayed digest and supports explicit cancellation."""
    d, c, r, _ = setup(tmp_path)
    p = d.store.propose(
        r,
        "user-a",
        {"project": "TEST", "summary": "Summary", "description": "Description"},
    )
    headers = {"Origin": d.config.origin}
    response = c.post(
        "/runs/" + r + "/approve",
        data={"csrf": "csrf-fixture", "action": p["action_id"], "digest": p["digest"]},
        headers=headers,
        follow_redirects=False,
    )
    assert (
        response.status_code == 303
        and d.store.describe(r, "user-a")["actions"][0]["state"] == "approved"
    )
    assert (
        c.post(
            "/runs/" + r + "/cancel",
            data={"csrf": "csrf-fixture"},
            headers=headers,
            follow_redirects=False,
        ).status_code
        == 303
    )
    assert c.get("/runs/" + r).status_code == 200


def test_login_state_cookie_and_pkce(tmp_path: Path) -> None:
    """Authorization redirects carry state/nonce/S256; state cookie stays Secure/HttpOnly."""
    d, c, _, _ = setup(tmp_path)
    response = c.get("/login", follow_redirects=False)
    assert response.status_code == 302
    assert "code_challenge_method=S256" in response.headers["location"]
    assert (
        "nonce=" in response.headers["location"]
        and "state=" in response.headers["location"]
    )
    assert (
        "Secure" in response.headers["set-cookie"]
        and "HttpOnly" in response.headers["set-cookie"]
    )
    assert c.get("/callback?state=forged&code=fake").status_code == 403


@pytest.mark.parametrize(
    "change", ["issuer", "audience", "expiry", "signature", "algorithm", "subject"]
)
def test_standard_library_rejects_invalid_jwt(change: str) -> None:
    """No unverified human or gateway claims enter the trusted driver state."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier = Verifier("https://issuer.example.test")
    verifier.keys = SimpleNamespace(
        get_signing_key_from_jwt=lambda _: SimpleNamespace(key=key.public_key())
    )
    now = int(time.time())
    claims = {
        "iss": verifier.issuer,
        "sub": "user-a",
        "aud": "driver",
        "iat": now,
        "exp": now + 60,
    }
    signing = key
    algorithm = "RS256"
    if change == "issuer":
        claims["iss"] = "https://evil.example"
    if change == "audience":
        claims["aud"] = "other"
    if change == "expiry":
        claims["exp"] = now - 1
    if change == "signature":
        signing = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if change == "algorithm":
        algorithm = "HS256"
        signing = "different-secret"
    if change == "subject":
        del claims["sub"]
    token = jwt.encode(claims, signing, algorithm=algorithm, headers={"kid": "test"})
    with pytest.raises(Denied):
        verifier(token, "driver")


def test_peer_duplicates_or_wrong_certificate_rejected() -> None:
    """A caller cannot smuggle another TLS peer or reuse only its SPIFFE string."""
    digest = hashlib.sha256(b"cert").digest()
    claims = {
        "azp": "spiffe://example.test/workload",
        "cnf": {"x5t#S256": base64.urlsafe_b64encode(digest).decode().rstrip("=")},
    }
    good = "Hash=" + digest.hex() + ";URI=" + claims["azp"]
    assert peer_matches(claims, {"x-forwarded-client-cert": good})
    assert not peer_matches(
        claims, {"x-forwarded-client-cert": good + ";Hash=" + digest.hex()}
    )
    assert not peer_matches(
        claims, {"x-forwarded-client-cert": good + ",Hash=" + digest.hex()}
    )


def test_internal_issuer_transport_retains_public_issuer() -> None:
    """Internal routing must not change the accepted signed issuer identity."""
    v = Verifier(
        "https://issuer.example/realms/pilot", "https://service.example/realms/pilot"
    )
    assert v.issuer == "https://issuer.example/realms/pilot"
    assert (
        v.keys.uri
        == "https://service.example/realms/pilot/protocol/openid-connect/certs"
    )


@pytest.mark.parametrize(
    "service,ca",
    [
        ("http://internal.example/realms/pilot", "ca.pem"),
        ("https://internal.example/realms/other", "ca.pem"),
        ("https://internal.example/realms/pilot", None),
    ],
)
def test_internal_issuer_requires_tls_matching_realm_and_ca(
    tmp_path: Path,
    service: str,
    ca: str | None,
) -> None:
    """Operator configuration cannot silently disable issuer transport verification."""
    d, _, _, _ = setup(tmp_path)
    with pytest.raises(ValueError):
        Driver(replace(d.config, issuer_service=service, issuer_ca=ca), d.verify)


def test_issuer_redirect_is_rejected() -> None:
    """Login credentials must never follow an HTTP redirect."""
    with pytest.raises(Denied, match="issuer_redirect"):
        NoIssuerRedirect().redirect_request(
            None, None, 302, "", {}, "https://other.example"
        )


def test_real_callback_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Callback validates nonce and subject, issues an opaque cookie, and rejects replay."""
    d, c, _, _ = setup(tmp_path)
    response = c.get("/login", follow_redirects=False)
    state = parse_qs(urlparse(response.headers["location"]).query)["state"][0]
    nonce = d.pending[state]["nonce"]
    human = d.sessions["opaque"]["claims"]
    d.verify = lambda token, audience: (
        human if token == "human" else {**human, "nonce": nonce}
    )
    monkeypatch.setattr(
        "identity_demo_driver.exchange_code",
        lambda *args: {"access_token": "human", "id_token": "identity"},
    )
    callback = "/callback?state=" + state + "&code=one-use"
    response = c.get(callback, follow_redirects=False)
    assert response.status_code == 303
    assert "HttpOnly" in response.headers["set-cookie"]
    assert "Secure" in response.headers["set-cookie"]
    assert c.get("/").status_code == 200
    assert c.get(callback, follow_redirects=False).status_code == 403


def test_volume_remount_preserves_state_with_private_modes(tmp_path: Path) -> None:
    """fsGroup widening on restart must not reset stored run/action state."""
    directory = tmp_path / "private"
    directory.mkdir(mode=0o770)
    db = directory / "runs.db"
    db.write_bytes(b"existing-state")
    db.chmod(0o660)
    prepare_storage(db)
    assert directory.stat().st_mode & 0o777 == 0o700
    assert db.stat().st_mode & 0o777 == 0o600
    assert db.read_bytes() == b"existing-state"


def test_storage_refuses_symlink(tmp_path: Path) -> None:
    """Permission restoration must not touch another path."""
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "private"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError):
        prepare_storage(link / "runs.db")


@pytest.mark.parametrize("role", ["analyst", "viewer"])
@pytest.mark.parametrize("workload_role", ["triage", "reader"])
def test_project_read_needs_identity_but_no_mutation_approval(
    tmp_path: Path,
    role: str,
    workload_role: str,
) -> None:
    """Both users and workloads retain their own project reads without write consent."""
    d, c, r, claims = setup(tmp_path, role, workload_role)
    ctx = auth_context(d, r, claims, {"action_id": "a" * 32, "arguments": {}})
    http = ctx["context"]["request"]["http"]
    rpc = json.loads(http["body"])
    rpc["params"] = {
        "name": "step56_jira_readJiraProject",
        "arguments": {"run_id": r, "project": "TEST"},
    }
    http["body"] = json.dumps(rpc)
    headers = {"Authorization": "Bearer " + d.config.gateway_secret}
    assert c.post("/internal/authorize", json=ctx, headers=headers).json()["allowed"]
    rpc["params"]["arguments"]["project"] = "OTHER"
    http["body"] = json.dumps(rpc)
    assert (
        c.post("/internal/authorize", json=ctx, headers=headers).json()["reason"]
        == "project_permission"
    )
    rpc["params"]["arguments"] = {
        "run_id": r,
        "project": "TEST",
        "issue_key": "OTHER-1",
    }
    http["body"] = json.dumps(rpc)
    assert (
        c.post("/internal/authorize", json=ctx, headers=headers).json()["reason"]
        == "project_permission"
    )
    assert d.store.describe(r, "user-a")["actions"] == []


def test_adapter_claim_is_separate_scoped_and_durable(tmp_path: Path) -> None:
    """Authorization retries do not claim; only the adapter can reserve and finish."""
    d, c, r, claims = setup(tmp_path)
    p = approved(d, r)
    ctx = auth_context(d, r, claims, p)
    d.config = replace(
        d.config, normalized_tool_host="fixture-step4-read-route.fixture-mcp.local"
    )
    http = ctx["context"]["request"]["http"]
    http["host"] = d.config.normalized_tool_host
    rpc = json.loads(http["body"])
    rpc["params"]["name"] = "createJiraIssue"
    http["body"] = json.dumps(rpc)
    gateway = {"Authorization": "Bearer " + d.config.gateway_secret}
    adapter = {"Authorization": "Bearer " + d.config.adapter_secret}
    assert (
        c.post("/internal/adapter/claim", json=ctx, headers=gateway).status_code == 403
    )
    decision = c.post("/internal/authorize", json=ctx, headers=gateway).json()
    assert decision["allowed"]
    claim_body = {
        "decision_ticket": decision["decision_ticket"],
        "actual_body": http["body"],
    }
    assert c.post("/internal/adapter/preview", json=claim_body, headers=adapter).json()[
        "allowed"
    ]
    assert d.store.describe(r, "user-a")["actions"][0]["state"] == "approved"
    result = c.post("/internal/adapter/claim", json=claim_body, headers=adapter).json()
    assert result["allowed"] and result["dispatch"]
    assert not c.post(
        "/internal/adapter/claim", json=claim_body, headers=adapter
    ).json()["allowed"]
    fields = {
        "run_id": r,
        "action_id": p["action_id"],
        "execution_id": result["execution_id"],
        "state": "succeeded",
        "issue_key": "TEST-123",
    }
    assert (
        c.post("/internal/adapter/finish", json=fields, headers=gateway).status_code
        == 403
    )
    assert c.post("/internal/adapter/finish", json=fields, headers=adapter).json()[
        "recorded"
    ]
    cached = c.post("/internal/adapter/claim", json=claim_body, headers=adapter).json()
    assert (
        cached["allowed"]
        and not cached["dispatch"]
        and cached["issue_key"] == "TEST-123"
    )


@pytest.mark.parametrize("change", ["body", "expired", "cancel", "restart"])
def test_adapter_decision_reference_fails_closed(tmp_path: Path, change: str) -> None:
    """A ticket cannot authorize changed arguments or survive expiry/cancellation/restart."""
    d, c, r, claims = setup(tmp_path)
    d.config = replace(
        d.config, normalized_tool_host="fixture-step4-read-route.fixture-mcp.local"
    )
    p = approved(d, r)
    ctx = auth_context(d, r, claims, p)
    http = ctx["context"]["request"]["http"]
    http["host"] = d.config.normalized_tool_host
    rpc = json.loads(http["body"])
    rpc["params"]["name"] = "createJiraIssue"
    http["body"] = json.dumps(rpc)
    decision = c.post(
        "/internal/authorize",
        json=ctx,
        headers={"Authorization": "Bearer " + d.config.gateway_secret},
    ).json()
    data = {"decision_ticket": decision["decision_ticket"], "actual_body": http["body"]}
    if change == "body":
        rpc["params"]["arguments"]["description"] = "Changed after gateway"
        data["actual_body"] = json.dumps(rpc)
    elif change == "expired":
        d.tickets[data["decision_ticket"]]["expires"] = 0
    elif change == "cancel":
        d.store.cancel(r, "user-a")
    else:
        d.tickets.clear()
    response = c.post(
        "/internal/adapter/claim",
        json=data,
        headers={"Authorization": "Bearer " + d.config.adapter_secret},
    )
    assert response.status_code == 403
    assert d.store.describe(r, "user-a")["actions"][0]["state"] == "approved"


def test_frontend_identity_gate_does_not_authorize_missing_write_body(
    tmp_path: Path,
) -> None:
    """The body-less frontend check must be followed by complete tool authorization."""
    d, c, r, claims = setup(tmp_path)
    ctx = auth_context(d, r, claims, approved(d, r))
    del ctx["context"]["request"]["http"]["body"]
    headers = {"Authorization": "Bearer " + d.config.gateway_secret}
    assert c.post("/internal/identity", json=ctx, headers=headers).json()["allowed"]
    assert not c.post("/internal/authorize", json=ctx, headers=headers).json()[
        "allowed"
    ]
    d.store.cancel(r, "user-a")
    assert not c.post("/internal/identity", json=ctx, headers=headers).json()["allowed"]


def test_normalized_tool_requires_exact_trusted_receiver(tmp_path: Path) -> None:
    """A stripped tool name is accepted only on the configured receiving adapter route."""
    d, c, r, claims = setup(tmp_path)
    d.config = replace(
        d.config, normalized_tool_host="fixture-step4-read-route.fixture-mcp.local"
    )
    ctx = auth_context(d, r, claims, approved(d, r))
    http = ctx["context"]["request"]["http"]
    rpc = json.loads(http["body"])
    rpc["params"]["name"] = "createJiraIssue"
    http["body"] = json.dumps(rpc)
    headers = {"Authorization": "Bearer " + d.config.gateway_secret}
    assert not c.post("/internal/authorize", json=ctx, headers=headers).json()[
        "allowed"
    ]
    http["host"] = d.config.normalized_tool_host
    assert c.post("/internal/authorize", json=ctx, headers=headers).json()["allowed"]


def test_malformed_params_are_deliberately_denied(tmp_path: Path) -> None:
    """Untrusted params types must not produce an accidental application exception."""
    d, c, r, claims = setup(tmp_path)
    ctx = auth_context(d, r, claims, approved(d, r))
    rpc = json.loads(ctx["context"]["request"]["http"]["body"])
    rpc["params"] = ["not-an-object"]
    ctx["context"]["request"]["http"]["body"] = json.dumps(rpc)
    response = c.post(
        "/internal/authorize",
        json=ctx,
        headers={"Authorization": "Bearer " + d.config.gateway_secret},
    )
    assert response.status_code == 200 and not response.json()["allowed"]


def test_adapter_rechecks_read_without_human_token(tmp_path: Path) -> None:
    """A read uses an exact gateway decision reference and live cancellation."""
    d, c, r, claims = setup(tmp_path, "viewer", "reader")
    d.config = replace(
        d.config, normalized_tool_host="fixture-step4-read-route.fixture-mcp.local"
    )
    ctx = auth_context(d, r, claims, {"action_id": "a" * 32, "arguments": {}})
    http = ctx["context"]["request"]["http"]
    http["host"] = d.config.normalized_tool_host
    rpc = json.loads(http["body"])
    rpc["params"] = {
        "name": "readJiraProject",
        "arguments": {"run_id": r, "project": "TEST"},
    }
    http["body"] = json.dumps(rpc)
    result = c.post(
        "/internal/authorize",
        json=ctx,
        headers={"Authorization": "Bearer " + d.config.gateway_secret},
    ).json()
    data = {"decision_ticket": result["decision_ticket"], "actual_body": http["body"]}
    adapter = {"Authorization": "Bearer " + d.config.adapter_secret}
    assert c.post("/internal/adapter/read", json=data, headers=adapter).json()[
        "allowed"
    ]
    assert (
        c.post("/internal/adapter/claim", json=data, headers=adapter).status_code == 403
    )
    d.store.cancel(r, "user-a")
    assert (
        c.post("/internal/adapter/read", json=data, headers=adapter).status_code == 403
    )


def test_reconciliation_endpoints_require_adapter_scope(tmp_path: Path) -> None:
    """Recovery uses trusted adapter reads; human/operator/gateway tokens cannot record success."""
    driver, client, run, final = setup(tmp_path)
    proposal = approved(driver, run)
    claim = driver.store.decision(
        run,
        proposal["action_id"],
        "user-a",
        final["azp"],
        proposal["arguments"],
        claim=True,
    )
    driver.store.finish(
        run, proposal["action_id"], claim["execution_id"], state="unknown"
    )
    ids = {"run_id": run, "action_id": proposal["action_id"]}
    for secret in ("", driver.config.gateway_secret, driver.config.operator_secret):
        assert (
            client.post(
                "/internal/adapter/reconciliation",
                json=ids,
                headers={"Authorization": "Bearer " + secret},
            ).status_code
            == 403
        )
    response = client.post(
        "/internal/adapter/reconciliation",
        json=ids,
        headers={"Authorization": "Bearer " + driver.config.adapter_secret},
    )
    assert (
        response.status_code == 200
        and response.json()["arguments"] == proposal["arguments"]
    )
    outcome = {
        **ids,
        "execution_id": claim["execution_id"],
        "issue_key": "TEST-123",
        "arguments": proposal["arguments"],
    }
    assert (
        client.post(
            "/internal/adapter/reconcile",
            json=outcome,
            headers={"Authorization": "Bearer " + driver.config.gateway_secret},
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/internal/adapter/reconcile",
            json=outcome,
            headers={"Authorization": "Bearer " + driver.config.adapter_secret},
        ).status_code
        == 200
    )
    assert driver.store.describe(run, "user-a")["actions"][0]["state"] == "succeeded"


@pytest.mark.parametrize("selector", ["run_id", "user", "workload"])
def test_operator_revocation_blocks_gateway_and_token_release(
    tmp_path: Path, selector: str
) -> None:
    """Old valid credentials cannot bypass live operator revocation."""
    driver, client, run, final = setup(tmp_path)
    values = {"run_id": run, "user": "user-a", "workload": final["azp"]}
    value = {selector: values[selector]}
    assert (
        client.post(
            "/internal/operator/revoke",
            json=value,
            headers={"Authorization": "Bearer " + driver.config.gateway_secret},
        ).status_code
        == 403
    )
    response = client.post(
        "/internal/operator/revoke",
        json=value,
        headers={"Authorization": "Bearer " + driver.config.operator_secret},
    )
    assert response.status_code == 200 and response.json()["revoked_runs"] == 1
    assert (
        client.get(
            "/internal/operator/credentials/" + run,
            headers={"Authorization": "Bearer " + driver.config.operator_secret},
        ).status_code
        == 403
    )
    with pytest.raises(Denied, match="run_inactive"):
        driver.store.identity_run(final["sub"], final["azp"])
    assert driver.store.describe(run, "user-a")["audit"][-1]["event"] == "revoked"
    assert driver.store.assessment(run, "user-a")
