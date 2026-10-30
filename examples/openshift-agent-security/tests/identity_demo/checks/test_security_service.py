# SPDX-License-Identifier: Apache-2.0
"""Unrelated agent, real shared enforcement and independent file-backed outcomes."""
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest
from agent_security import RunStore
from agent_security_contracts import Denied
from agent_security_service import BackendPort, SecurityService, VerifiedActor

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def documents(monkeypatch):
    path = ROOT / "examples/document-agent"
    monkeypatch.syspath_prepend(str(path))
    spec = importlib.util.spec_from_file_location("document_reference_host", path / "host.py")
    host = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(host)
    return host


def proposed(host, directory, **roles):
    service, actor, run, backend = host.prepare(directory, **roles)
    context = service.read(actor, run, "engineering")
    proposal = service.propose(actor, run, host.draft(context))
    service.approve(actor, run, proposal["action_id"], proposal["digest"], int(time.time()) + 100)
    return service, actor, run, backend, proposal


def test_independent_agent_uses_only_runtime_without_browser_jira_or_demo_imports():
    code = '''import importlib.abc,runpy,sys
class RefuseDemo(importlib.abc.MetaPathFinder):
 def find_spec(self, fullname, path=None, target=None):
  if fullname.startswith(('identity_demo','checks','pytest','playwright','jira','probe_')):
   raise ImportError('demo dependency: '+fullname)
sys.meta_path.insert(0,RefuseDemo())
sys.argv=['host.py','--approve']
runpy.run_path('examples/document-agent/host.py',run_name='__main__')
'''
    env = {"PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
           "PYTHONPATH": str(ROOT / "runtime") + os.pathsep + str(ROOT / "examples/document-agent")}
    result = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env,
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout)
    assert value["verified"] and value["backend_dispatches"] == 1
    assert value["audit_events"] == ["run_created", "read_allowed", "proposed", "approved", "claimed", "succeeded"]


def test_actual_publication_matches_approval_and_remains_auditable_after_restart(documents, tmp_path):
    service, actor, run, backend, p = proposed(documents, tmp_path)
    result = service.execute(actor, documents.call(run, p))
    assert result["verified"] and result["dispatched"]
    assert backend.observe(result["result_ref"]) == p["arguments"]
    reopened = RunStore(service.store.path, connector=documents.DOCUMENTS, trust_domain="lab.example.test")
    retained = reopened.describe(run, actor.user)
    assert retained["actions"][0]["state"] == "succeeded"
    assert retained["actions"][0]["result_ref"] == result["result_ref"]
    assert not service.execute(actor, documents.call(run, p))["dispatched"]
    assert backend.dispatches == 1


@pytest.mark.parametrize("roles,reason", [({"user_role": "viewer"}, "user_permission"),
    ({"workload_role": "reader"}, "workload_permission")])
def test_recorded_consent_cannot_grant_missing_authority(documents, tmp_path, roles, reason):
    service, actor, run, backend, p = proposed(documents, tmp_path, **roles)
    with pytest.raises(Denied, match=reason):
        service.execute(actor, documents.call(run, p))
    assert backend.dispatches == 0 and not list(backend.directory.iterdir())


@pytest.mark.parametrize("change,reason", [({"content": "substituted"}, "action_binding"),
    ({"collection": "research"}, "resource_permission"), ({"user": "forged"}, "document_schema")])
def test_actual_request_effects_are_checked_before_backend_access(documents, tmp_path, change, reason):
    service, actor, run, backend, p = proposed(documents, tmp_path)
    p["arguments"].update(change)
    with pytest.raises(Denied, match=reason):
        service.execute(actor, documents.call(run, p))
    assert backend.dispatches == 0


def test_scope_guard_is_independent_of_approval_digest(documents, tmp_path):
    service, actor, run, backend = documents.prepare(tmp_path)
    p = service.propose(actor, run, {**documents.draft(backend.read("engineering")), "collection": "research"})
    service.approve(actor, run, p["action_id"], p["digest"], int(time.time()) + 100)
    with pytest.raises(Denied, match="resource_permission"):
        service.execute(actor, documents.call(run, p))
    assert backend.dispatches == 0


def test_unapproved_action_and_different_actor_cannot_dispatch(documents, tmp_path):
    service, actor, run, backend = documents.prepare(tmp_path)
    p = service.propose(actor, run, documents.draft(backend.read("engineering")))
    with pytest.raises(Denied, match="action_proposed"):
        service.execute(actor, documents.call(run, p))
    with pytest.raises(Denied, match="run_binding"):
        service.execute(VerifiedActor("another-person", actor.workload), documents.call(run, p))
    with pytest.raises(Denied, match="verified_actor_required"):
        service.execute({"user": actor.user, "workload": actor.workload}, documents.call(run, p))
    assert backend.dispatches == 0


def test_parallel_requests_dispatch_at_most_once(documents, tmp_path):
    service, actor, run, backend, p = proposed(documents, tmp_path)
    def execute(_):
        try:
            return service.execute(actor, documents.call(run, p))
        except Denied as error:
            assert str(error) == "action_executing"
            return {"dispatched": False}
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(execute, range(8)))
    assert sum(v["dispatched"] for v in results) == 1 and backend.dispatches == 1


def test_lost_response_never_replays_a_committed_publication(documents, tmp_path):
    service, actor, run, backend, p = proposed(documents, tmp_path)
    attempts = []
    def dispatch(effects):
        attempts.append(effects)
        return backend.publish(effects)
    def unavailable(_):
        raise TimeoutError("synthetic observation failure")
    service = SecurityService(service.store, BackendPort(documents.DOCUMENTS.fingerprint,
        dispatch, unavailable, backend.read))
    with pytest.raises(Denied, match="outcome_unknown"):
        service.execute(actor, documents.call(run, p))
    assert backend.dispatches == 1 and len(list(backend.directory.iterdir())) == 1
    with pytest.raises(Denied, match="action_unknown"):
        service.execute(actor, documents.call(run, p))
    assert backend.dispatches == 1 and len(attempts) == 1


@pytest.mark.parametrize("mode", ["cancel", "expiry"])
def test_closed_or_expired_run_cannot_dispatch(documents, tmp_path, monkeypatch, mode):
    service, actor, run, backend, p = proposed(documents, tmp_path)
    if mode == "cancel":
        service.store.cancel(run, actor.user)
    else:
        now = time.time()
        monkeypatch.setattr("agent_security.time.time", lambda: now + 301)
    with pytest.raises(Denied, match="run_inactive"):
        service.execute(actor, documents.call(run, p))
    assert backend.dispatches == 0


def test_wrong_backend_and_outside_resource_read_are_refused(documents, tmp_path):
    service, actor, run, backend = documents.prepare(tmp_path)
    with pytest.raises(ValueError, match="connector/backend"):
        SecurityService(service.store, BackendPort("0" * 64, backend.publish, backend.observe))
    with pytest.raises(Denied, match="resource_permission"):
        service.read(actor, run, "research")
    assert backend.dispatches == 0


@pytest.mark.parametrize("change", [
    {"content": "backend substituted different content"},
    {"operation_id": "0" * 32},
    {"collection": "research"},
])
def test_backend_observation_must_match_exact_approved_effects(documents, tmp_path, change):
    service, actor, run, backend, p = proposed(documents, tmp_path)
    def altered(reference):
        return {**backend.observe(reference), **change}
    service = SecurityService(service.store, BackendPort(documents.DOCUMENTS.fingerprint,
        backend.publish, altered, backend.read))
    with pytest.raises(Denied, match="outcome_unknown"):
        service.execute(actor, documents.call(run, p))
    # The write occurred, but an unverified outcome never becomes success or retries.
    assert backend.dispatches == 1
    assert service.store.describe(run, actor.user)["actions"][0]["state"] == "unknown"
    with pytest.raises(Denied, match="action_unknown"):
        service.execute(actor, documents.call(run, p))
    assert backend.dispatches == 1


def test_verified_workload_cannot_substitute_another_workload(documents, tmp_path):
    service, actor, run, backend, p = proposed(documents, tmp_path)
    substituted = VerifiedActor(actor.user, actor.workload + "-other")
    with pytest.raises(Denied, match="run_binding"):
        service.execute(substituted, documents.call(run, p))
    with pytest.raises(Denied, match="run_binding"):
        service.approve(substituted, run, p["action_id"], p["digest"], int(time.time()) + 100)
    assert backend.dispatches == 0


@pytest.mark.parametrize("mutation", ["tool", "method", "extra_envelope", "extra_params"])
def test_envelope_cannot_change_the_reviewed_execution_contract(documents, tmp_path, mutation):
    service, actor, run, backend, p = proposed(documents, tmp_path)
    request = json.loads(documents.call(run, p))
    if mutation == "tool":
        request["params"]["name"] = "document.delete"
    elif mutation == "method":
        request["method"] = "tools/list"
    elif mutation == "extra_envelope":
        request["actor"] = actor.user
    else:
        request["params"]["destination"] = "https://elsewhere.example.test"
    with pytest.raises(Denied):
        service.execute(actor, json.dumps(request).encode())
    assert backend.dispatches == 0
