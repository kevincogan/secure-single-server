# SPDX-License-Identifier: Apache-2.0
"""Browser renewal preserves fixed run authority for both human permission roles."""

import asyncio
from pathlib import Path
from copy import deepcopy
import time
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import httpx
import pytest

import identity_demo_driver as module
from checks.test_console import configured, operator, submit
from identity_demo_driver import COOKIE, Driver
from identity_demo_run_store import Denied


def renewable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str) -> tuple:
    driver, client, context = configured(tmp_path)
    clock = [int(time.time())]
    monkeypatch.setattr(module.time, "time", lambda: clock[0])
    session = driver.sessions["opaque"]
    claims = deepcopy(session["claims"])
    claims.update(exp=clock[0] + 600, iat=clock[0], sid="original-idp-session",
                  realm_access={"roles": [role]})
    session.update(claims=claims, runs=set(), token="human-initial",
                   refresh_token="refresh-initial", refresh_expires=clock[0] + 1800,
                   session_expires=clock[0] + 1800, absolute_expires=clock[0] + 36000, last_activity=clock[0])
    issued = {"human-initial": claims}
    requests = []

    def exchange(endpoint: str, fields: bytes, ca: str | None) -> dict:
        parsed = parse_qs(fields.decode())
        assert endpoint == (driver.config.issuer_service or driver.config.issuer)
        assert parsed["grant_type"] == ["refresh_token"]
        assert parsed["client_id"] == [driver.config.client]
        assert set(parsed) == {"grant_type", "client_id", "refresh_token"}
        requests.append(parsed["refresh_token"][0])
        name = "human-renewed-" + str(len(requests))
        issued[name] = {**deepcopy(claims), "iat": clock[0], "exp": clock[0] + 600}
        return {"access_token": name, "refresh_token": "refresh-" + str(len(requests)),
                "refresh_expires_in": 1800}

    def verify(token: str, audience: str) -> dict:
        value = deepcopy(issued[token])
        if value["aud"] != audience or value["iss"] != driver.config.issuer or value["exp"] <= clock[0]:
            raise Denied("invalid_token")
        return value

    driver.verify = verify
    monkeypatch.setattr(module, "exchange_code", exchange)
    return driver, client, context, clock, session, requests, issued


@pytest.mark.parametrize("role", ["analyst", "viewer"])
def test_active_browser_slides_beyond_one_hour_but_retains_absolute_maximum(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str) -> None:
    d, c, _, clock, session, requests, _ = renewable(tmp_path, monkeypatch, role)
    original = clock[0]
    for elapsed in range(240, 36000, 240):
        clock[0] = original + elapsed
        response = c.get("/")
        assert response.status_code == 200 and "Browser session" in response.text
        assert "Sign in again" in response.text and "Sign out" in response.text
        assert "Authenticated role:" not in response.text
        assert "Sign in to your workspace" not in response.text
        assert session["session_expires"] > clock[0]
        assert session["absolute_expires"] == original + 36000
        assert session["session_expires"] <= min(session["refresh_expires"], original + 36000)
        assert "HttpOnly" in response.headers["set-cookie"]
        assert "Max-Age=" in response.headers["set-cookie"]
        assert session["refresh_token"] not in response.text
        assert session["token"] not in response.text
    assert len(requests) >= 5
    clock[0] = original + 36001
    assert c.get("/runs").status_code == 403
    assert "opaque" not in d.sessions


@pytest.mark.parametrize("role", ["analyst", "viewer"])
def test_start_renews_on_demand_and_keeps_run_and_approval_deadlines(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str) -> None:
    d, c, _, clock, session, requests, _ = renewable(tmp_path, monkeypatch, role)
    initial_exp = session["claims"]["exp"]
    clock[0] += 181
    d.console.heartbeat(uuid4().hex)
    response = submit(d, c)
    assert response.status_code == 303
    run = response.headers["location"].split("/")[-1]
    record = d.store.describe(run, session["claims"]["sub"])
    deadline = record["run"]["expires"]
    assert requests == ["refresh-initial"]
    assert deadline == clock[0] + 600 and deadline > initial_exp
    captured_token = session["token"]
    captured = deepcopy(session["run_credentials"][run])
    proposal = d.store.propose(run, session["claims"]["sub"],
        {"project": "TEST", "summary": "Exact synthetic task", "description": "Fixture"})
    clock[0] += 541
    assert c.get("/").status_code == 200  # Ordinary browser renewal.
    assert len(requests) == 2 and session["token"] != captured_token
    credentials = c.get("/internal/operator/credentials/" + run, headers=operator(d))
    assert credentials.status_code == 200
    assert credentials.json()["access_token"] == captured_token
    assert credentials.json()["expires_at"] == deadline
    assert captured == session["run_credentials"][run]
    approved = c.post("/runs/" + run + "/approve", headers={"Origin": d.config.origin},
        data={"csrf": session["csrf"], "action": proposal["action_id"], "digest": proposal["digest"]},
        follow_redirects=False)
    assert approved.status_code == 303
    record = d.store.describe(run, session["claims"]["sub"])
    assert record["run"]["expires"] == deadline
    assert record["actions"][0]["approval_expires"] == deadline
    clock[0] = deadline + 1
    assert c.get("/runs/" + run).status_code == 200  # Retained result remains visible.
    assert c.get("/internal/operator/credentials/" + run, headers=operator(d)).status_code == 403
    assert d.store.describe(run, session["claims"]["sub"])["run"]["expires"] == deadline


@pytest.mark.parametrize("role", ["analyst", "viewer"])
def test_run_cannot_outlive_the_browser_absolute_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str) -> None:
    d, c, _, clock, session, _, _ = renewable(tmp_path, monkeypatch, role)
    session["session_expires"] = clock[0] + 510
    session["absolute_expires"] = clock[0] + 510
    session["claims"]["exp"] = clock[0] + 590
    d.console.heartbeat(uuid4().hex)
    response = submit(d, c)
    assert response.status_code == 303
    run = response.headers["location"].split("/")[-1]
    assert d.store.describe(run, session["claims"]["sub"])["run"]["expires"] == session["session_expires"]
    released = c.get("/internal/operator/credentials/" + run, headers=operator(d)).json()
    assert released["expires_at"] == session["session_expires"]


@pytest.mark.parametrize("role", ["analyst", "viewer"])
def test_passive_polling_does_not_extend_idle_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str) -> None:
    d, c, _, clock, session, _, _ = renewable(tmp_path, monkeypatch, role)
    original = clock[0]
    for elapsed in range(120, 1800, 120):
        clock[0] = original + elapsed
        assert c.get("/console/live").status_code == 200
        assert session["last_activity"] == original
    clock[0] = original + 1801
    assert c.get("/console/live").status_code == 403
    assert "opaque" not in d.sessions


@pytest.mark.parametrize("role", ["analyst", "viewer"])
@pytest.mark.parametrize("change", ["subject", "role", "issuer", "client", "sid", "audience"])
def test_renewal_cannot_change_identity_or_permission_profile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str, change: str) -> None:
    d, c, _, clock, session, requests, issued = renewable(tmp_path, monkeypatch, role)
    original = module.exchange_code
    clock[0] += 541

    def tamper(*args: object) -> dict:
        value = original(*args)
        claims = issued[value["access_token"]]
        key, replacement = {
            "subject": ("sub", "another-user"), "role": ("realm_access", {"roles": ["viewer" if role == "analyst" else "analyst"]}),
            "issuer": ("iss", "https://foreign.example/realm"), "client": ("azp", "another-client"),
            "sid": ("sid", "another-session"), "audience": ("aud", "another-client"),
        }[change]
        claims[key] = replacement
        return value

    monkeypatch.setattr(module, "exchange_code", tamper)
    assert c.get("/runs").status_code == 403
    assert "opaque" not in d.sessions and len(requests) == 1
    assert c.get("/runs").status_code == 403 and len(requests) == 1


@pytest.mark.parametrize("role", ["analyst", "viewer"])
@pytest.mark.parametrize("failure", [Denied("login_exchange"), TimeoutError("secret-withheld")])
def test_revocation_or_ambiguous_refresh_ends_authority_without_retry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str, failure: Exception) -> None:
    d, c, _, clock, session, _, _ = renewable(tmp_path, monkeypatch, role)
    d.console.heartbeat(uuid4().hex)
    response = submit(d, c)
    run = response.headers["location"].split("/")[-1]
    calls = []

    def fail(*args: object) -> None:
        calls.append(True)
        raise failure

    monkeypatch.setattr(module, "exchange_code", fail)
    clock[0] += 541
    response = c.get("/runs")
    assert response.status_code == 403 and response.json()["reason"] == "session_renewal_required"
    assert "secret-withheld" not in response.text
    assert not d.store.describe(run, session["claims"]["sub"])["run"]["active"]
    assert c.get("/internal/operator/credentials/" + run, headers=operator(d)).status_code == 403
    assert c.get("/runs").status_code == 403 and len(calls) == 1


@pytest.mark.parametrize("role", ["analyst", "viewer"])
def test_logout_revokes_runs_even_when_idp_unavailable_and_does_not_refresh(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str) -> None:
    d, c, _, clock, session, requests, _ = renewable(tmp_path, monkeypatch, role)
    d.console.heartbeat(uuid4().hex)
    run = submit(d, c).headers["location"].split("/")[-1]
    proposal = d.store.propose(run, session["claims"]["sub"],
        {"project": "TEST", "summary": "Dispatched synthetic action", "description": "Fixture"})
    with d.store.transaction() as db:
        db.execute("UPDATE actions SET state='executing' WHERE id=?", (proposal["action_id"],))
    remote = []
    monkeypatch.setattr(module, "end_issuer_session", lambda *args: remote.append(args[2]) or False)
    clock[0] += 601  # Old access token expired; opaque session still valid for logout.
    response = c.post("/logout", headers={"Origin": d.config.origin},
        data={"csrf": session["csrf"]}, follow_redirects=False)
    assert response.status_code == 303 and "Max-Age=0" in response.headers["set-cookie"]
    assert requests == ["refresh-initial"] and remote == ["refresh-1"]
    assert "opaque" not in d.sessions
    record = d.store.describe(run, session["claims"]["sub"])
    assert not record["run"]["active"] and record["actions"][0]["state"] == "executing"
    assert c.get("/internal/operator/credentials/" + run, headers=operator(d)).status_code == 403


def test_concurrent_requests_use_a_single_refresh_and_preserve_opaque_cookie(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    d, _, _, clock, session, requests, _ = renewable(tmp_path, monkeypatch, "analyst")
    clock[0] += 541
    original = module.exchange_code

    def slow(*args: object) -> dict:
        time.sleep(.03)
        return original(*args)

    monkeypatch.setattr(module, "exchange_code", slow)

    async def exercise() -> None:
        transport = httpx.ASGITransport(app=d.app)
        async with httpx.AsyncClient(transport=transport, base_url=d.config.origin,
                                    cookies={COOKIE: "opaque"}) as client:
            responses = await asyncio.gather(*(client.get("/console/live") for _ in range(8)))
            assert all(r.status_code == 200 for r in responses)
            assert all("refresh-initial" not in r.text and session["refresh_token"] not in r.text for r in responses)

    asyncio.run(exercise())
    assert requests == ["refresh-initial"]


@pytest.mark.parametrize("role", ["analyst", "viewer"])
def test_invalid_forms_never_refresh_or_extend_idle_deadline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str) -> None:
    _, c, _, clock, session, requests, _ = renewable(tmp_path, monkeypatch, role)
    original = session["last_activity"]
    clock[0] += 541
    for origin, csrf in (("https://foreign.example", session["csrf"]),
                         ("https://driver.example.test", "forged")):
        response = c.post("/logout", headers={"Origin": origin}, data={"csrf": csrf})
        assert response.status_code == 403
    assert requests == [] and session["last_activity"] == original


@pytest.mark.parametrize("role", ["analyst", "viewer"])
def test_callback_keeps_refresh_server_side_and_bounds_cookie(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str) -> None:
    d, c, _, _, session, _, _ = renewable(tmp_path, monkeypatch, role)
    response = c.get("/login", follow_redirects=False)
    state = parse_qs(urlparse(response.headers["location"]).query)["state"][0]
    nonce = d.pending[state]["nonce"]
    claims = deepcopy(session["claims"])
    d.verify = lambda token, audience: claims if token == "fresh-human" else {**claims, "nonce": nonce}
    monkeypatch.setattr(module, "exchange_code", lambda *a: {
        "access_token": "fresh-human", "id_token": "identity", "refresh_token": "refresh-private",
        "refresh_expires_in": 1800})
    response = c.get("/callback?state=" + state + "&code=one-use", follow_redirects=False)
    assert response.status_code == 303
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=lax" in cookie
    assert "Max-Age=1800" in cookie  # Cookie cannot outlive idle or the IdP refresh grant.
    assert "refresh-private" not in cookie and "fresh-human" not in cookie
    assert c.get("/").status_code == 200
    assert "refresh-private" not in c.get("/").text
    new = next(v for v in d.sessions.values() if v.get("refresh_token") == "refresh-private")
    assert new["refresh_token"] == "refresh-private"
    restarted = Driver(d.config, d.verify)
    assert not restarted.sessions  # A driver restart requires real login, never token recovery from logs.



@pytest.mark.parametrize("role", ["analyst", "viewer"])
def test_logout_serializes_with_inflight_refresh_and_cannot_resurrect_session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str) -> None:
    import threading
    d, _, _, clock, session, requests, _ = renewable(tmp_path, monkeypatch, role)
    clock[0] += 541
    started, release = threading.Event(), threading.Event()
    original = module.exchange_code
    ended = []

    def slow(*args: object) -> dict:
        started.set()
        assert release.wait(2)
        return original(*args)

    monkeypatch.setattr(module, "exchange_code", slow)
    monkeypatch.setattr(module, "end_issuer_session", lambda *args: ended.append(args[2]) or True)

    async def exercise() -> None:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=d.app),
                base_url=d.config.origin, cookies={COOKIE: "opaque"}) as client:
            pending = asyncio.create_task(client.get("/console/live"))
            assert await asyncio.to_thread(started.wait, 2)
            logout = asyncio.create_task(client.post("/logout",
                headers={"Origin": d.config.origin}, data={"csrf": session["csrf"]}))
            await asyncio.sleep(.02)
            release.set()
            observed, signed_out = await asyncio.gather(pending, logout)
            assert observed.status_code == 200 and signed_out.status_code == 303

    asyncio.run(exercise())
    assert requests == ["refresh-initial"] and ended == ["refresh-1"]
    assert "opaque" not in d.sessions


@pytest.mark.parametrize("role", ["analyst", "viewer"])
def test_cancelled_refresh_discards_ambiguous_grant(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str) -> None:
    from starlette.requests import Request
    d, c, _, clock, session, _, _ = renewable(tmp_path, monkeypatch, role)
    d.console.heartbeat(uuid4().hex)
    run = submit(d, c).headers["location"].split("/")[-1]
    clock[0] += 541

    async def cancelled(*args: object) -> None:
        raise asyncio.CancelledError()

    monkeypatch.setattr(module, "run_in_threadpool", cancelled)
    request = Request({"type": "http", "method": "GET", "path": "/console/live", "scheme": "https",
        "server": ("driver.example.test", 443), "headers": [(b"cookie", b"__Host-identity-demo=opaque")]})
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(d.session(request))
    assert "opaque" not in d.sessions
    assert not d.store.describe(run, session["claims"]["sub"])["run"]["active"]



@pytest.mark.parametrize("role", ["analyst", "viewer"])
@pytest.mark.parametrize("action", ["start", "approve"])
def test_revoked_idp_session_cannot_use_a_still_valid_access_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str, action: str) -> None:
    d, c, _, clock, session, _, _ = renewable(tmp_path, monkeypatch, role)
    d.console.heartbeat(uuid4().hex)
    run = None
    if action == "approve":
        run = submit(d, c).headers["location"].split("/")[-1]
        proposal = d.store.propose(run, session["claims"]["sub"],
            {"project": "TEST", "summary": "Consent after revocation", "description": "Fixture"})
    before = len(d.console.history(session["claims"]["sub"]))
    clock[0] += 61
    assert session["claims"]["exp"] > clock[0] + 480
    calls = []

    def revoked(*args: object) -> dict:
        calls.append(True)
        raise Denied("login_exchange")

    monkeypatch.setattr(module, "exchange_code", revoked)
    if action == "start":
        response = submit(d, c)
    else:
        response = c.post("/runs/" + run + "/approve", headers={"Origin": d.config.origin},
            data={"csrf": session["csrf"], "action": proposal["action_id"], "digest": proposal["digest"]},
            follow_redirects=False)
        record = d.store.describe(run, session["claims"]["sub"])
        assert record["actions"][0]["state"] == "proposed" and not record["run"]["active"]
    assert response.status_code == 403 and response.json()["reason"] == "session_renewal_required"
    assert len(d.console.history(session["claims"]["sub"])) == before
    assert calls == [True] and "opaque" not in d.sessions



@pytest.mark.parametrize("role", ["analyst", "viewer"])
def test_idp_shorter_session_expiry_bounds_sliding_cookie_and_new_runs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str) -> None:
    d, c, _, clock, session, _, _ = renewable(tmp_path, monkeypatch, role)
    original = module.exchange_code
    clock[0] += 541

    def near_idp_max(*args: object) -> dict:
        value = original(*args)
        value["refresh_expires_in"] = 120
        return value

    monkeypatch.setattr(module, "exchange_code", near_idp_max)
    response = c.get("/")
    assert response.status_code == 200
    assert session["session_expires"] == session["refresh_expires"] == clock[0] + 120
    assert "Max-Age=120" in response.headers["set-cookie"]
    d.console.heartbeat(uuid4().hex)
    assert submit(d, c).status_code == 409  # A short remaining IdP grant cannot start an eight-minute run.
    clock[0] += 121
    assert c.get("/runs").status_code == 403
    assert "opaque" not in d.sessions
