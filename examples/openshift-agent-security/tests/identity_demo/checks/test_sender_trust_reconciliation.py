# SPDX-License-Identifier: Apache-2.0
"""Owned trust refresh is idle-only, fail-closed and durable across process restarts."""

from argparse import Namespace
import base64
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import identity_demo_console_worker as worker
import identity_demo_sender_trust as trust
import identity_demo_execution_setup as setup
from deployment_profile import active_profile


def args_at(tmp_path: Path) -> Namespace:
    output = tmp_path / "worker-one"
    output.mkdir(mode=0o700)
    return Namespace(
        output_dir=output, kubeconfig="private", auto_refresh_sender_trust=True
    )


def test_current_trust_does_not_mutate_or_check_durable_run_rows(tmp_path, monkeypatch):
    monkeypatch.setattr(trust, "current", lambda _: True)
    monkeypatch.setattr(
        trust,
        "refresh",
        lambda _: (_ for _ in ()).throw(AssertionError("must not mutate")),
    )
    monkeypatch.setattr(
        setup,
        "inspect_state",
        lambda _: (_ for _ in ()).throw(AssertionError("no mutation check needed")),
    )
    assert worker.reconcile_sender_trust(args_at(tmp_path))
    assert not list(tmp_path.glob("*.pending.private.json"))


@pytest.mark.parametrize("enabled,idle", [(False, True), (True, False)])
def test_manual_mode_or_active_work_refuses_automatic_mutation(
    tmp_path, monkeypatch, enabled, idle
):
    monkeypatch.setattr(trust, "current", lambda _: False)
    monkeypatch.setattr(setup, "inspect_state", lambda _: {"rollback_quiescent": idle})
    monkeypatch.setattr(
        trust,
        "refresh",
        lambda _: (_ for _ in ()).throw(AssertionError("must not mutate")),
    )
    args = args_at(tmp_path)
    args.auto_refresh_sender_trust = enabled
    assert worker.reconcile_sender_trust(args) is False
    assert not list(tmp_path.glob("*.pending.private.json"))


def test_changed_owned_trust_waits_for_rollout_and_verifies_before_ready(
    tmp_path, monkeypatch
):
    states = iter([False, True])
    monkeypatch.setattr(trust, "current", lambda _: next(states))
    monkeypatch.setattr(setup, "inspect_state", lambda _: {"rollback_quiescent": True})
    observed = []

    def refresh(args):
        assert args.apply and len(list(tmp_path.glob("*.pending.private.json"))) == 1
        observed.append("refresh")
        return {"issuer_rollout_started": True}

    monkeypatch.setattr(trust, "refresh", refresh)
    monkeypatch.setattr(
        worker.subprocess,
        "run",
        lambda words, **kw: observed.append("rollout") or SimpleNamespace(returncode=0),
    )
    assert worker.reconcile_sender_trust(args_at(tmp_path))
    assert observed == ["refresh", "rollout"] and not list(
        tmp_path.glob("*.pending.private.json")
    )
    assert (
        len(
            list(
                tmp_path.glob(
                    "worker-one/sender-trust-*/automatic-reconciliation.private.json"
                )
            )
        )
        == 1
    )


@pytest.mark.parametrize("failure", ["mutation", "rollout", "drift"])
def test_unknown_or_incomplete_mutation_blocks_replay_even_after_restart(
    tmp_path, monkeypatch, failure
):
    states = iter([False, False])
    monkeypatch.setattr(trust, "current", lambda _: next(states))
    monkeypatch.setattr(setup, "inspect_state", lambda _: {"rollback_quiescent": True})
    mutations = []

    def refresh(args):
        mutations.append(True)
        if failure == "mutation":
            raise RuntimeError("private-fixture-value")
        return {"issuer_rollout_started": True}

    monkeypatch.setattr(trust, "refresh", refresh)
    monkeypatch.setattr(
        worker.subprocess,
        "run",
        lambda *a, **kw: SimpleNamespace(returncode=1 if failure == "rollout" else 0),
    )
    args = args_at(tmp_path)
    with pytest.raises(worker.SenderTrustMutationUncertain):
        worker.reconcile_sender_trust(args)
    assert len(list(tmp_path.glob("*.pending.private.json"))) == 1
    args.output_dir = tmp_path / "worker-two"
    args.output_dir.mkdir(mode=0o700)
    monkeypatch.setattr(trust, "current", lambda _: True)
    with pytest.raises(worker.SenderTrustMutationUncertain):
        worker.reconcile_sender_trust(args)
    assert mutations == [True]  # A healthy observation cannot erase a pending mutation.


def public_copies(
    monkeypatch, installed=("one", "two"), listener="one,two", foreign=False
):
    class Root:
        def __init__(self, name):
            self.name = name

        def fingerprint(self, _):
            return self.name

    monkeypatch.setattr(
        trust, "certificates", lambda pem: [Root(x) for x in pem.split(",")]
    )
    monkeypatch.setattr(
        trust.pkcs12,
        "load_pkcs12",
        lambda *a: SimpleNamespace(
            additional_certs=[SimpleNamespace(certificate=Root(x)) for x in installed]
        ),
    )
    namespace = {"metadata": {"labels": dict(trust.LABELS)}}
    bundle = {
        "metadata": {
            "namespace": trust.SPIRE_NAMESPACE,
            "labels": {
                "identity-demo-owner": active_profile().owner,
                "app.kubernetes.io/managed-by": "zero-trust-workload-identity-manager",
            },
            "ownerReferences": [
                {
                    "kind": "SpireServer",
                    "name": "cluster",
                    "uid": "exact-fixture-server",
                }
            ],
        },
        "data": {"bundle.crt": "one,two"},
    }
    secrets = {
        "kind": "List",
        "items": [
            {
                "metadata": {
                    "name": trust.ISSUER + "-client-trust",
                    "namespace": trust.NAMESPACE,
                    "labels": dict(trust.LABELS),
                },
                "data": {
                    "truststore.p12": base64.b64encode(b"fixture").decode(),
                    "password": base64.b64encode(b"fixture").decode(),
                },
            },
            {
                "metadata": {
                    "name": "fixture-mcp-bound-mutual",
                    "namespace": trust.NAMESPACE,
                    "labels": dict(trust.LABELS),
                },
                "data": {"ca.crt": base64.b64encode(listener.encode()).decode()},
            },
        ],
    }
    if foreign:
        bundle["metadata"]["labels"]["identity-demo-owner"] = "foreign"
    responses = iter([namespace, bundle, secrets])
    monkeypatch.setattr(trust, "command", lambda *a: json.dumps(next(responses)))


@pytest.mark.parametrize(
    "installed,listener,expected",
    [
        (("one", "two"), "one,two", True),
        (("one",), "one,two", False),
        (("one", "two"), "one", False),
        (("one", "two", "old"), "one,two", False),
    ],
)
def test_both_copies_must_match_the_authoritative_public_roots(
    monkeypatch, installed, listener, expected
):
    public_copies(monkeypatch, installed, listener)
    assert trust.current(Namespace()) is expected


def test_foreign_public_bundle_cannot_become_a_trust_source(monkeypatch):
    public_copies(monkeypatch, foreign=True)
    with pytest.raises(ValueError, match="operator-managed"):
        trust.current(Namespace())


@pytest.mark.parametrize('change', ['none','roots','reference','uid','issuer'])
def test_cluster_public_observation_never_reads_serving_key_secrets(tmp_path,monkeypatch,change):
    import hashlib
    volume={'name':'client-trust','secret':{'secretName':trust.ISSUER+'-client-trust'}}
    observation={'profile':active_profile().to_dict(),'spire_fingerprints':['01'],
        'issuer_fingerprints':['01'],'listener_fingerprints':['01'],
        'issuer_uid':'issuer-uid','issuer_annotation':'root-receipt','issuer_trust_volumes':[volume]}
    payload=json.dumps(observation)
    live={'metadata':{'namespace':trust.NAMESPACE,'uid':'public-uid','labels':dict(trust.LABELS)},
          'immutable':True,'data':{'observation.json':payload}}
    issuer={'metadata':{'uid':'issuer-uid','labels':dict(trust.LABELS)},'spec':{'template':{
        'metadata':{'annotations':{'demo-identity-trust-sha256':'root-receipt'}},'spec':{'volumes':[volume]}}}}
    receipt=tmp_path/'reference.json';receipt.write_text(json.dumps({'uid':'public-uid',
        'observation_sha256':hashlib.sha256(payload.encode()).hexdigest()}));receipt.chmod(0o600)
    monkeypatch.setenv('IDENTITY_DEMO_SENDER_TRUST_RECEIPT',str(receipt))
    calls=[]
    def command(args,*words):
        calls.append(words)
        assert words[1] in ('configmap','deployment')
        return json.dumps(live if words[1]=='configmap' else issuer)
    monkeypatch.setattr(trust,'command',command)
    if change=='roots': assert trust.public_observation(Namespace(),{b'\x02'}) is False
    elif change!='none':
        if change=='reference':issuer['spec']['template']['spec']['volumes']=[]
        if change=='uid':live['metadata']['uid']='replacement'
        if change=='issuer':issuer['metadata']['uid']='foreign'
        with pytest.raises(ValueError):trust.public_observation(Namespace(),{b'\x01'})
    else:assert trust.public_observation(Namespace(),{b'\x01'}) is True
    assert all('secret' not in words for words in calls)


def test_trust_observation_does_not_pause_admission_but_changed_trust_does(tmp_path, monkeypatch):
    states = iter([True, False])
    monkeypatch.setattr(trust, 'current', lambda _: next(states))
    monkeypatch.setattr(setup, 'inspect_state', lambda _: pytest.fail('Busy admission must stop before mutation'))
    monkeypatch.setattr(trust, 'refresh', lambda _: pytest.fail('Busy admission cannot change trust'))
    paused = []
    args = args_at(tmp_path)
    def close_admission():
        paused.append(True)
        return False
    assert worker.reconcile_sender_trust(args, close_admission)
    assert paused == []
    assert worker.reconcile_sender_trust(args, close_admission) is False
    assert paused == [True] and not list(tmp_path.glob('*.pending.private.json'))
