# SPDX-License-Identifier: Apache-2.0
"""HTTP adapter boundaries; synthetic signed-edge claims do not count as live proof."""
from dataclasses import replace
import hashlib
import importlib.util
import json
from pathlib import Path
import time
from uuid import uuid4

import pytest
from starlette.testclient import TestClient


@pytest.fixture
def document_host(tmp_path, monkeypatch):
    directory = Path(__file__).resolve().parents[3] / "examples/document-agent"
    monkeypatch.syspath_prepend(str(directory))
    modules = {}
    for name in ("backend", "service"):
        spec = importlib.util.spec_from_file_location("document_test_" + name, directory / (name + ".py"))
        module = importlib.util.module_from_spec(spec)
        # Dataclass annotation resolution uses the registered defining module.
        monkeypatch.setitem(__import__("sys").modules, spec.name, module)
        spec.loader.exec_module(module)
        modules[name] = module
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    workload = "spiffe://lab.example.test/openshell/sandbox/" + str(uuid4())
    config = modules["service"].HostConfig(issuer="https://issuer.example.test/realms/evaluation",
        client="document-proof-ui", origin="https://control.example.test", audience="https://mcp.example.test/mcp",
        trust_domain="lab.example.test", database=private / "runs.db", operator_secret="operator-key-" * 4,
        contexts=({"name": "publisher", "workload": workload, "role": "publisher", "collection": "engineering"},))
    claims = {"iss": config.issuer, "sub": "synthetic-person", "azp": workload,
        "aud": config.audience, "iat": int(time.time()), "exp": int(time.time()) + 25,
        "realm_access": {"roles": ["analyst"]}}
    backend = modules["backend"].RevisionStore(private / "documents.db")
    backend.dispatch = backend.publish
    backend.read = lambda collection: {"instruction": "Synthetic observations only"}
    host = modules["service"].DocumentHost(config, backend, lambda token, audience: claims)
    run = host.store.create_run(issuer=config.issuer, user=claims["sub"], user_role="reviewer", workload=workload,
        workload_role="publisher", project="engineering", expires=int(time.time()) + 120, assessment="Synthetic")
    # Mint the delegated test token after admission, as real exchange does.
    # Crossing a wall-clock second during setup must not predate not_before.
    claims.update(iat=int(time.time()), exp=int(time.time()) + 25)
    headers = {"Authorization": "Bearer synthetic-verified-edge-token"}
    return host, backend, claims, run, headers


def rpc(tool, arguments):
    return {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": arguments}}


def propose(host, run, headers):
    effects = {"collection": "engineering", "document": "runbook", "revision": 1, "content": "Synthetic findings"}
    result = TestClient(host.tools).post("/mcp", json=rpc("documents.propose", {"run_id": run, "effects": effects}), headers=headers)
    assert result.status_code == 200
    return json.loads(result.json()["result"]["content"][0]["text"])


def approve(host, run, action):
    from agent_security_service import VerifiedActor
    record = host.store.describe(run, "synthetic-person")["run"]
    host.security.approve(VerifiedActor(record["user"], record["workload"]), run,
        action["action_id"], action["digest"], int(time.time()) + 60)


def test_control_listener_has_no_mcp_or_native_header_bypass(document_host):
    host, backend, _, run, headers = document_host
    assert TestClient(host.control).post("/mcp", json=rpc("documents.read", {"run_id": run, "collection": "engineering"}),
        headers=headers).status_code == 404
    assert TestClient(host.tools).get("/internal/credentials/" + run, headers=headers).status_code == 404
    assert backend.inventory() == []


@pytest.mark.parametrize("changed", ["missing_token", "old_constrained_token", "wrong_workload", "wrong_role", "expired", "long_lifetime"])
def test_delegation_checks_precede_tool_execution(document_host, changed):
    host, backend, claims, run, headers = document_host
    if changed == "missing_token": headers.pop("Authorization")
    elif changed == "old_constrained_token": claims["cnf"] = {"x5t#S256": "old-token"}
    elif changed == "wrong_workload": claims["azp"] = "spiffe://lab.example.test/openshell/sandbox/" + str(uuid4())
    elif changed == "wrong_role": claims["realm_access"] = {"roles": ["viewer"]}
    elif changed == "expired": claims["exp"] = int(time.time()) - 1
    else: claims["exp"] = int(time.time()) + 60
    result = TestClient(host.tools).post("/mcp", json=rpc("documents.read", {"run_id": run, "collection": "engineering"}), headers=headers)
    assert result.status_code == 403 and backend.inventory() == []


def test_actual_tool_effects_require_exact_approval_and_single_dispatch(document_host):
    host, backend, _, run, headers = document_host
    action = propose(host, run, headers)
    arguments = {"run_id": run, "action_id": action["action_id"], **action["arguments"]}
    client = TestClient(host.tools)
    assert client.post("/mcp", json=rpc("document.publish", arguments), headers=headers).status_code == 403
    approve(host, run, action)
    assert client.post("/mcp", json=rpc("document.publish", {**arguments, "content": "changed"}), headers=headers).status_code == 403
    for _ in range(2):
        result = client.post("/mcp", json=rpc("document.publish", arguments), headers=headers)
        assert result.status_code == 200
    assert len(backend.inventory()) == 1 and backend.observe(backend.inventory()[0]["reference"]) == action["arguments"]


def test_cancelled_run_rejects_even_previously_valid_delegation(document_host):
    host, backend, _, run, headers = document_host
    action = propose(host, run, headers)
    approve(host, run, action)
    host.store.revoke("run_id", run)
    response = TestClient(host.tools).post("/mcp", json=rpc("document.publish",
        {"run_id": run, "action_id": action["action_id"], **action["arguments"]}), headers=headers)
    assert response.status_code == 403 and backend.inventory() == []


def test_duplicate_authorization_is_rejected(document_host):
    host,backend,_,run,headers=document_host
    values=[*headers.items(),('Authorization',headers['Authorization'])]
    response=TestClient(host.tools).post('/mcp',json=rpc('documents.read',{'run_id':run,'collection':'engineering'}),headers=values)
    assert response.status_code==403 and backend.inventory()==[]


def test_unsigned_identity_headers_cannot_repair_wrong_workload(document_host):
    host, backend, claims, run, headers = document_host
    expected = claims['azp']
    claims['azp'] = 'spiffe://lab.example.test/openshell/sandbox/' + str(uuid4())
    forged = {**headers, 'x-forwarded-client-cert': 'URI=' + expected,
        'x-workload': expected, 'x-user': claims['sub'], 'x-run-id': run}
    response = TestClient(host.tools).post('/mcp', json=rpc('documents.read', {
        'run_id': run, 'collection': 'engineering'}), headers=forged)
    assert response.status_code == 403 and backend.inventory() == []


def test_unknown_document_outcome_can_only_be_reconciled_from_matching_observation(document_host):
    host,backend,_,run,headers=document_host
    action=propose(host,run,headers);approve(host,run,action)
    def lose(effects):
        backend.publish(effects)
        raise OSError('synthetic response loss')
    from agent_security_service import BackendPort,SecurityService
    host.security=SecurityService(host.store,BackendPort(host.store.connector.fingerprint,lose,backend.observe,backend.read))
    arguments={'run_id':run,'action_id':action['action_id'],**action['arguments']}
    response=TestClient(host.tools).post('/mcp',json=rpc('document.publish',arguments),headers=headers)
    assert response.status_code==403 and response.json()['reason']=='outcome_unknown'
    assert TestClient(host.tools).post('/mcp',json=rpc('document.publish',arguments),headers=headers).status_code==403
    pending=host.store.reconciliation(run,action['action_id'])
    from agent_security_contracts import Denied
    with pytest.raises(Denied):
        host.store.reconcile_result(run,action['action_id'],pending['execution_id'],'engineering/runbook@1',{**action['arguments'],'content':'altered'})
    host.store.reconcile_result(run,action['action_id'],pending['execution_id'],'engineering/runbook@1',backend.observe('engineering/runbook@1'))
    result=TestClient(host.tools).post('/mcp',json=rpc('document.publish',arguments),headers=headers)
    assert result.status_code==200 and len(backend.inventory())==1
    assert 'reconciled' in [event['event'] for event in host.store.describe(run,'synthetic-person')['audit']]


def test_authenticated_audit_correlates_real_request_and_verified_delegation(document_host):
    host, _, claims, run, headers = document_host
    body = json.dumps(rpc('documents.read', {'run_id': run, 'collection': 'engineering'})).encode()
    result = TestClient(host.tools).post('/mcp', content=body, headers={**headers, 'Content-Type': 'application/json'})
    assert result.status_code == 200
    records = host.store.describe(run, 'synthetic-person')['audit']
    event, = [v for v in records if v['event'] == 'authenticated_request']
    detail = json.loads(event['detail'])
    assert detail['actual_body_sha256'] == hashlib.sha256(body).hexdigest()
    assert detail['delegation'] == 'short-lived-bearer'
    assert detail['workload'] == claims['azp']
    assert detail['user'] == 'synthetic-person'


def test_renewed_operator_credential_never_extends_expired_run(document_host):
    host, backend, claims, run, headers = document_host
    future = int(time.time()) + 300
    host.authentication.sessions['synthetic-session'] = {
        'claims': {**claims, 'exp': future}, 'token': 'renewed-synthetic-human-token',
        'run_credentials': {run: {'claims': dict(claims), 'token': 'original', 'expires_at': future}},
        'session_expires': future}
    with host.store.transaction() as db:
        db.execute('UPDATE runs SET expires=? WHERE id=?', (int(time.time()) - 1, run))
    client = TestClient(host.control)
    url = '/internal/credentials/' + run + '?current=true'
    assert client.get(url).status_code == 403
    response = client.get(url, headers={'Authorization': 'Bearer ' + host.config.operator_secret})
    assert response.status_code == 200 and response.json()['access_token'] == 'renewed-synthetic-human-token'
    assert TestClient(host.tools).post('/mcp', json=rpc('documents.read', {
        'run_id': run, 'collection': 'engineering'}), headers=headers).status_code == 403
    assert host.store.describe(run, 'synthetic-person')['run']['expires'] < time.time()
    assert backend.inventory() == []
