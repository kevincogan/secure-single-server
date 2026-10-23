# SPDX-License-Identifier: Apache-2.0
"""Retirement cannot delete live, foreign, replaced or uncertain SPIRE identities."""
from argparse import Namespace
from dataclasses import asdict, replace
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

import identity_demo_execution_setup as setup
from identity_demo_lab import LABELS


def registration(context: object) -> dict:
    return {'metadata': {'uid': 'exact', 'resourceVersion': '7', 'labels': dict(LABELS)},
            'spec': {'spiffeID': context.workload, 'className': 'zero-trust-workload-identity-manager-spire',
                     'selectors': ['k8s:ns:' + context.namespace, 'k8s:sa:' + context.service_account,
                                   'k8s:container-name:supervisor', 'k8s:pod-uid:old']}}


@pytest.mark.parametrize('failure', ['owner', 'identity', 'class', 'namespace', 'service-account', 'container'])
def test_foreign_or_mismatched_registration_cannot_be_deleted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    context = replace(setup.context_template('reader', 't01'), sandbox_id=str(uuid4()))
    entry = registration(context)
    if failure == 'owner':
        entry['metadata']['labels'] = {}
    elif failure == 'identity':
        entry['spec']['spiffeID'] += '-other'
    elif failure == 'class':
        entry['spec']['className'] = 'other'
    else:
        index = {'namespace': 0, 'service-account': 1, 'container': 2}[failure]
        entry['spec']['selectors'][index] += '-other'
    monkeypatch.setattr(setup, 'read', lambda _, kind, *a, **kw: entry if kind.startswith('clusterstatic') else None)
    monkeypatch.setattr(setup.native, 'kube', lambda *a, **kw: pytest.fail('Unsafe registration delete'))
    with pytest.raises(ValueError):
        setup.retire_registration(Namespace(output_dir=tmp_path), context)


def test_cleanup_is_idempotent_and_uses_current_uid_resourceversion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    context = replace(setup.context_template('reader', 't01'), sandbox_id=str(uuid4()))
    entry = registration(context)
    calls = []
    monkeypatch.setattr(setup, 'read', lambda _, kind, *a, **kw: entry if kind.startswith('clusterstatic') and not calls else None)
    monkeypatch.setattr(setup.native, 'kube', lambda _, *a, **kw: calls.append((a, kw)))
    args = Namespace(output_dir=tmp_path)
    assert setup.retire_registration(args, context)['registration_absent']
    assert setup.retire_registration(args, context)['registration_absent']
    assert len(calls) == 1
    assert calls[0][1]['payload']['preconditions'] == {'uid': 'exact', 'resourceVersion': '7'}
    assert calls[0][0][2].endswith('/' + context.registration_name)


@pytest.mark.parametrize('replacement', ['uid', 'spec', 'owner'])
def test_replaced_registration_stops_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, replacement: str) -> None:
    context = replace(setup.context_template('reader', 't01'), sandbox_id=str(uuid4()))
    entry = registration(context)
    changed = json.loads(json.dumps(entry))
    if replacement == 'uid':
        changed['metadata']['uid'] = 'replaced'
    elif replacement == 'spec':
        changed['spec']['spiffeID'] += '-replaced'
    else:
        changed['metadata']['labels'] = {}
    reads = iter([entry, changed])
    monkeypatch.setattr(setup, 'read', lambda _, kind, *a, **kw: next(reads) if kind.startswith('clusterstatic') else None)
    monkeypatch.setattr(setup.native, 'kube', lambda *a, **kw: pytest.fail('Replacement must survive'))
    with pytest.raises(ValueError):
        setup.retire_registration(Namespace(output_dir=tmp_path), context)


def test_live_native_execution_blocks_registration_removal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    context = replace(setup.context_template('reader', 't01'), sandbox_id=str(uuid4()))
    monkeypatch.setattr(setup, 'read', lambda *a, **kw: {'metadata': {'name': 'still-present'}})
    ticks = iter([0, 31])
    monkeypatch.setattr(setup.time, 'monotonic', lambda: next(ticks))
    monkeypatch.setattr(setup.native, 'kube', lambda *a, **kw: pytest.fail('Live execution must survive'))
    with pytest.raises(ValueError, match='native execution still present'):
        setup.retire_registration(Namespace(output_dir=tmp_path), context)


@pytest.mark.parametrize('delete_fails', [False, True])
def test_uncertain_delete_or_remaining_entry_is_not_reported_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, delete_fails: bool) -> None:
    context = replace(setup.context_template('reader', 't01'), sandbox_id=str(uuid4()))
    entry = registration(context)
    monkeypatch.setattr(setup, 'read', lambda _, kind, *a, **kw: entry if kind.startswith('clusterstatic') else None)
    def delete(*a: object, **kw: object) -> None:
        if delete_fails:
            raise RuntimeError('API timeout')
    monkeypatch.setattr(setup.native, 'kube', delete)
    with pytest.raises((RuntimeError, ValueError)):
        setup.retire_registration(Namespace(output_dir=tmp_path), context)
    assert (tmp_path / 'registration-before.private.json').exists()


@pytest.mark.parametrize('eligible', [False, True])
def test_manual_retirement_can_resume_after_native_deletion_only_for_closed_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, eligible: bool) -> None:
    context = replace(setup.context_template('reader', 't01'), sandbox_id=str(uuid4()))
    location = tmp_path / 'context.private.json'
    location.write_text(json.dumps(asdict(context)))
    location.chmod(0o600)
    monkeypatch.setattr(setup, 'guard', lambda _: (None, {}, None))
    monkeypatch.setattr(setup, 'read', lambda _, kind, *a, **kw: {'metadata': {'labels': dict(LABELS)}} if kind in ('namespace', 'deployment') else None)
    monkeypatch.setattr(setup.subprocess, 'run', lambda *a, **kw: SimpleNamespace(returncode=0 if eligible else 1,
                        stdout='{"eligible":true}' if eligible else '', stderr=''))
    calls = []
    monkeypatch.setattr(setup, 'retire_registration', lambda *a: (calls.append(a), {'registration_absent': True})[1])
    args = Namespace(context_file=[str(location)], output_dir=tmp_path, kubeconfig='private', apply=True)
    if eligible:
        assert setup.retire(args)['registration_absent'] and len(calls) == 1
    else:
        with pytest.raises(ValueError, match='closed'):
            setup.retire(args)
        assert not calls
