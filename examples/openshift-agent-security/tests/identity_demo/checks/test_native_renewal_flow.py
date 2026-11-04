# SPDX-License-Identifier: Apache-2.0
"""Synthetic renewal evidence must distinguish native reads from stale logs."""

import argparse
from copy import deepcopy
import hashlib
import json
import subprocess
import sys
from types import SimpleNamespace

import pytest

import native_renewal_flow as renewal


def record() -> dict:
    """Return a safely attributed read with signed bounded delegation times."""
    return {"event": "step4-private-read", "status": 200, "request": "new-request",
            "tls_version": "TLSv1.3", "verified": {"user": "user", "workload": "workload",
                "delegation": "short-lived-bearer", "issued": 100, "expiry": 130, "run": "run",
                "policy": "step56-live-action-v1", "actual_body_sha256": "body"}}


@pytest.mark.parametrize("fault", [None, "wrong-delegation", "missing-issued", "wrong-user", "wrong-workload",
                                   "wrong-policy", "extra-field", "extra-metadata", "long-ttl", "bad-request", "bool-time"])
def test_native_renewal_audit_checks_each_trust_input(fault: str | None) -> None:
    """A successful status alone cannot prove verified run attribution."""
    value = record()
    if fault == "wrong-delegation":
        value["verified"]["delegation"] = "different"
    elif fault == "missing-issued":
        value["verified"].pop("issued")
    elif fault in ("wrong-user", "wrong-workload", "wrong-policy"):
        value["verified"][fault.removeprefix("wrong-")] = "different"
    elif fault == "extra-field":
        value["raw_token"] = "must-not-be-accepted"
    elif fault == "extra-metadata":
        value["verified"]["credential"] = "must-not-be-accepted"
    elif fault == "long-ttl":
        value["verified"]["expiry"] = 131
    elif fault == "bool-time":
        value["verified"].update(issued=True, expiry=30)
    elif fault == "bad-request":
        value["request"] = "unsafe\nrequest"
    if fault:
        with pytest.raises(ValueError):
            renewal.delegated_reads(json.dumps(value), run="run", user="user", workload="workload", body_hash="body")
    else:
        assert renewal.delegated_reads(json.dumps(value), run="run", user="user", workload="workload", body_hash="body") == {
            "new-request": 100}


@pytest.mark.parametrize("change", ["other-run", "other-body", "denied", "non-object", "non-json"])
def test_unrelated_or_denied_logs_cannot_prove_renewal(change: str) -> None:
    """Old/different requests cannot satisfy the native read requirement."""
    value = record()
    if change == "other-run":
        value["verified"]["run"] = "other"
    elif change == "other-body":
        value["verified"]["actual_body_sha256"] = "different"
    elif change == "denied":
        value["status"] = 403
    text = "not-json" if change == "non-json" else json.dumps([] if change == "non-object" else value)
    assert renewal.delegated_reads(text, run="run", user="user", workload="workload", body_hash="body") == {}


def test_read_hash_matches_normalized_generated_native_request() -> None:
    """Check client bytes separately from the broker's policy-body normalization."""
    program = renewal.native.read_program("https://synthetic.invalid/mcp", "step56_jira_readJiraProject",
        {"run_id": "run", "project": "TEST"}, "project_scope")
    prefix = '''import urllib.request,json,hashlib
class Response:
    status=200
    headers={}
    def __enter__(self): return self
    def __exit__(self,*args): pass
    def read(self,*args):
        return json.dumps({'result': {'protocolVersion':'2025-11-25','tools':[],
            'content':[{'type':'text','text':'{"project_scope":"TEST"}'}]}}).encode()
class Client:
    def open(self,request,**kwargs):
        if json.loads(request.data)['method']=='tools/call':
            body=json.loads(request.data)
            assert body['params']['name']=='step56_jira_readJiraProject'
            body['params']['name']='readJiraProject'
            normalized=json.dumps(body,sort_keys=True,separators=(',',':')).encode()
            print(json.dumps({'body_sha256':hashlib.sha256(normalized).hexdigest(),
                'client_body_sha256':hashlib.sha256(request.data).hexdigest()}))
        return Response()
urllib.request.build_opener=lambda *args:Client()
'''
    result = subprocess.run([sys.executable, "-c", prefix + program], capture_output=True, text=True, check=True)
    lines = [json.loads(line) for line in result.stdout.splitlines()]
    assert lines[0]["body_sha256"] == renewal.read_body_hash("run", "TEST")
    original = {"jsonrpc": "2.0", "method": "tools/call", "id": 4,
                "params": {"name": "step56_jira_readJiraProject", "arguments": {"run_id": "run", "project": "TEST"}}}
    assert lines[0]["client_body_sha256"] == hashlib.sha256(json.dumps(original).encode()).hexdigest()
    assert lines[0]["client_body_sha256"] != lines[0]["body_sha256"]
    assert lines[-1]["read_passed"]


def test_conflicting_request_rejected() -> None:
    """The same request ID cannot be attributed to conflicting signed issuance times."""
    first = record()
    second = deepcopy(first)
    second["verified"].update(issued=101, expiry=131)
    with pytest.raises(ValueError, match="Conflicting"):
        renewal.delegated_reads(json.dumps(first) + "\n" + json.dumps(second),
            run="run", user="user", workload="workload", body_hash="body")


@pytest.mark.parametrize("recover", [True, False])
def test_only_log_capture_retries_with_all_attempts_retained(tmp_path, monkeypatch, recover) -> None:
    """API log-channel failure cannot silently replace native acceptance evidence."""
    flow = renewal.NativeRenewalFlow.__new__(renewal.NativeRenewalFlow)
    flow.args = argparse.Namespace(kubeconfig="private", output_dir=tmp_path, label="synthetic")
    flow.user, flow.run_id, flow.project = "user", "run", "TEST"
    flow.renewal_audit_sequence = 0
    profile = renewal.active_profile()
    monkeypatch.setattr(renewal.native, "kube", lambda *args: {"metadata": {"labels": profile.labels}})
    monkeypatch.setattr(renewal.time, "sleep", lambda seconds: None)
    calls = []
    value = record()
    value["verified"]["actual_body_sha256"] = renewal.read_body_hash("run", "TEST")

    def capture(words, **kwargs):
        calls.append(words)
        success = recover and len(calls) == 2
        return SimpleNamespace(returncode=0 if success else 1,
            stdout=json.dumps(value) if success else "", stderr="" if success else "private-diagnostic")

    monkeypatch.setattr(renewal.subprocess, "run", capture)
    if recover:
        assert flow.audit_reads(SimpleNamespace(workload="workload")) == {"new-request": value["verified"]["issued"]}
    else:
        with pytest.raises(RuntimeError, match="details withheld"):
            flow.audit_reads(SimpleNamespace(workload="workload"))
    assert len(calls) == (2 if recover else 3)
    assert all("logs" in words for words in calls)
    assert len(list(tmp_path.glob("*.private.json"))) == len(calls)


@pytest.mark.parametrize("fault", [None, "no-renewal", "read-failed", "backend-changed", "long-ttl", "stale-audit", "supervisor-restarted"])
def test_native_renewal_sequence_uses_expired_identity_and_new_request(tmp_path, monkeypatch, fault) -> None:
    """No restart, reissued credential or operator request stands in for native proof."""
    now = [100.0]
    monkeypatch.setattr(renewal.time, "time", lambda: now[0])
    monkeypatch.setattr(renewal.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(renewal.time, "sleep", lambda seconds: now.__setitem__(0, now[0] + seconds))
    flow = renewal.NativeRenewalFlow.__new__(renewal.NativeRenewalFlow)
    flow.args = argparse.Namespace(label="synthetic", output_dir=tmp_path)
    flow.user, flow.run_id = "user", "run"
    flow.project = "TEST"
    calls, closed = [], []
    flow.close = lambda: closed.append(True)
    flow.backend_count = lambda: 2 if fault == "backend-changed" and calls else 1
    flow.supervisor_state = lambda context: {"pod_uid": "owned", "restart_count": (
        1 if fault == "supervisor-restarted" and len(calls) > 1 else 0)}
    flow.read_program = lambda resource: "synthetic-read"

    class Sender:
        """Provide only SVID snapshots, without any exchange/replay method."""

        def __init__(self, *args):
            pass

        def identity_snapshot(self):
            return {"sha256": "old" if now[0] < 105 or fault == "no-renewal" else "new",
                    "expires_at": 1000 if fault == "long-ttl" else 105}

    monkeypatch.setattr(renewal, "DelegationAcceptance", Sender)
    flow.audit_reads = lambda context: {"old-request": 90, **(
        {"baseline": 100} if calls else {}), **(
        {"renewed": 137} if len(calls) > 1 and fault != "stale-audit" else {})}

    def execute(words, **kwargs):
        calls.append({"at": now[0], "words": words, "kwargs": kwargs})
        return {"read_passed": fault != "read-failed"}

    context = SimpleNamespace(sandbox_name="owned-sandbox", workload="workload")
    if fault:
        with pytest.raises((ValueError, TimeoutError)):
            flow.accept(execute, "synthetic", context)
        assert not closed
    else:
        result = flow.accept(execute, "synthetic", context)
        assert result["passed"] and result["old_jwt_expired_before_second_read"]
        assert len(calls) == 2 and calls[0]["at"] < 105 < calls[1]["at"]
        assert all(call["words"][:2] == ["sandbox", "exec"] for call in calls)
        assert result["renewed_requests"] == ["renewed"] and closed == [True]
