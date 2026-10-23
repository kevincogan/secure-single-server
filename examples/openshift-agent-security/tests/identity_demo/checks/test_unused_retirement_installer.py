# SPDX-License-Identifier: Apache-2.0
"""Installer reconciliation cannot replay native deletion or bypass fencing."""
from copy import deepcopy
from dataclasses import fields, replace
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from checks.test_unused_context_retirement import idle_installation
from deployment_profile import active_profile
from execution_context import ExecutionContext
import identity_demo_execution_setup as execution
import unused_context_retirement as unused


def arguments(tmp_path):
    context = replace(execution.context_template('reader', 'q1'), sandbox_id=str(uuid4()))
    path = tmp_path/'context.json'
    from dataclasses import asdict
    path.write_text(json.dumps(asdict(context)))
    path.chmod(0o600)
    return SimpleNamespace(context_file=[str(path)], output_dir=tmp_path,
        apply=True, resume_unused_retirement=True, review_sha256='d'*64), context


def test_resume_only_confirms_absence_and_never_calls_native_retire(tmp_path, monkeypatch):
    args, _ = arguments(tmp_path)
    phases = []
    monkeypatch.setattr(execution, 'guard', lambda a: None)
    monkeypatch.setattr(execution, 'read', lambda *a, **kw: None)
    monkeypatch.setattr(execution, 'retire', lambda *a: pytest.fail('Resume must not replay deletion'))
    monkeypatch.setattr(unused, 'review', lambda *a: {'reservation': 'a'*32, 'resources': {}})
    monkeypatch.setattr(unused, 'state', lambda a, c, v, phase, *extra: phases.append(phase))
    result = unused.run(args)
    assert result['unused_identity_retired'] and phases == ['eligible', 'finish']
    assert result['resume_native_mutations'] == 0 and not result['business_run_created']


@pytest.mark.parametrize('remaining', ['sandbox', 'worker', 'supervisor', 'registration'])
def test_resume_cannot_finish_while_any_reviewed_resource_remains(tmp_path, monkeypatch, remaining):
    args, context = arguments(tmp_path)
    phases = []
    monkeypatch.setattr(execution, 'guard', lambda a: None)
    monkeypatch.setattr(execution, 'retire', lambda *a: pytest.fail('No automatic mutation retry'))
    monkeypatch.setattr(unused, 'review', lambda *a: {'reservation': 'a'*32, 'resources': {}})
    monkeypatch.setattr(unused, 'state', lambda a, c, v, phase, *extra: phases.append(phase))
    def read(_args, kind, name, *rest, **kw):
        present = ((remaining == 'sandbox' and kind.startswith('sandboxes'))
            or remaining == 'worker' and kind == 'pod' and name == context.resource_name
            or remaining == 'supervisor' and kind == 'pod' and name.startswith('os-supervisor-')
            or remaining == 'registration' and kind.startswith('clusterstaticentries'))
        return {'metadata': {'uid': 'still-present'}} if present else None
    monkeypatch.setattr(execution, 'read', read)
    import identity_demo_controller_identity as identities
    monkeypatch.setattr(identities, 'enabled', lambda: False)
    with pytest.raises(ValueError): unused.run(args)
    assert phases == ['eligible']


def test_failed_initial_retirement_leaves_quarantine_for_explicit_review(tmp_path, monkeypatch):
    args, context = arguments(tmp_path)
    args.resume_unused_retirement = False
    phases = []
    monkeypatch.setattr(execution, 'guard', lambda a: None)
    monkeypatch.setattr(execution, 'resolve_context', lambda *a: context)
    monkeypatch.setattr(unused, 'review', lambda *a: {'reservation': 'a'*32, 'resources': {}})
    monkeypatch.setattr(unused, 'state', lambda a, c, v, phase, *extra: phases.append(phase))
    calls = []
    def fail(_args):
        calls.append(True)
        raise TimeoutError('Native reply unknown')
    monkeypatch.setattr(execution, 'retire', fail)
    with pytest.raises(TimeoutError): unused.run(args)
    assert calls == [True] and phases == ['plan', 'begin']
    assert not (tmp_path/'unused-absence.private.json').exists()


def test_runtime_pod_cannot_select_installer_retirement(monkeypatch):
    monkeypatch.setenv('IDENTITY_DEMO_RUNTIME', 'cluster')
    with pytest.raises(ValueError, match='human installer'):
        unused.review(SimpleNamespace(), None)


def test_serviceaccount_cannot_bypass_installer_boundary_by_unsetting_runtime_flag(tmp_path, monkeypatch):
    from dataclasses import asdict
    args, context = arguments(tmp_path)
    profile = active_profile()
    principal = 'system:serviceaccount:'+profile.core_namespace+':fixture-console-preparer'
    value = {'schema_version': 1, 'decision': 'retire_verified_unused', 'profile': profile.to_dict(),
             'reviewed_by': principal, 'reservation': uuid4().hex, 'context': asdict(context),
             'pool_context_sha256': 'a'*64, 'resources': {}, 'evidence': {}}
    path = tmp_path/'review.json'
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    args.review_receipt = str(path)
    args.review_sha256 = __import__('hashlib').sha256(path.read_bytes()).hexdigest()
    args.expected_server = profile.expected_server
    args.kubeconfig = 'offline-installer-fixture'
    monkeypatch.delenv('IDENTITY_DEMO_RUNTIME', raising=False)
    monkeypatch.setattr(unused.subprocess, 'run', lambda *a, **kw: SimpleNamespace(
        returncode=0, stdout=principal+'\n'))
    monkeypatch.setattr(execution, 'read', lambda *a, **kw: pytest.fail('No resource or backup access'))
    with pytest.raises(ValueError, match='human installer'):
        unused.review(args, context)


@pytest.mark.parametrize('condition', ['running-pod', 'live-lease', 'replacement', 'wrong-lease'])
def test_cluster_fencing_requires_exact_stopped_process_and_expired_lease(monkeypatch, condition):
    profile = active_profile()
    workers = [{'name': 'fixture-console-'+r, 'uid': r+'-uid', 'lease_uid': r+'-lease',
                'holder': r+'-holder'} for r in ('coordinator', 'preparer')]
    def read(_args, kind, name, *rest, **kw):
        role = name.removeprefix('fixture-console-')
        if kind == 'deployment':
            return {'metadata': {'labels': profile.labels, 'uid': role+'-uid' if condition != 'replacement' else 'foreign'},
                    'spec': {'replicas': 0}}
        return {'metadata': {'labels': profile.labels, 'uid': role+'-lease' if condition != 'wrong-lease' else 'foreign'},
                'spec': {'holderIdentity': role+'-holder', 'leaseDurationSeconds': 45,
                         'renewTime': datetime.fromtimestamp(time.time() if condition == 'live-lease' else 0,
                                                             timezone.utc).isoformat()}}
    monkeypatch.setattr(execution, 'read', read)
    monkeypatch.setattr(execution.native, 'kube', lambda *a, **kw: {'items': [{}] if condition == 'running-pod' else []})
    with pytest.raises(ValueError):
        unused.fencing(SimpleNamespace(), {'schema_version': 1, 'profile': profile.to_dict(),
                                          'runtime': 'cluster', 'workers': workers})


def test_installer_protocol_uses_real_transactions_and_verified_live_source(tmp_path, monkeypatch):
    driver, _, contexts, digest = idle_installation(tmp_path)
    identity = contexts[0]
    context = ExecutionContext(**{f.name: identity[f.name] for f in fields(ExecutionContext)})
    profile = active_profile()
    profile_path = tmp_path/'profile.json'
    profile_path.write_text(json.dumps(profile.to_dict()))
    args = SimpleNamespace(kubeconfig='unused-by-offline-test', output_dir=tmp_path, review_sha256='d'*64)
    value = {'reservation': uuid4().hex, 'pool_context_sha256': digest, 'profile': profile.to_dict()}
    real_run = subprocess.run
    def local_program(command, **kwargs):
        assert command[:1] == ['oc'] and command[-3:-1] == ['python', '-c']
        env = {**os.environ, 'IDENTITY_DEMO_CONFIG': str(profile_path),
               'DRIVER_DATABASE': str(driver.store.path),
               'PYTHONPATH': str(execution.ROOT/'scripts/identity_demo')+':'+str(execution.ROOT/'tests/identity_demo')}
        return real_run([sys.executable, '-c', command[-1]], env=env, **kwargs)
    monkeypatch.setattr(unused.subprocess, 'run', local_program)
    assert unused.state(args, context, value, 'plan')['eligible']
    assert unused.state(args, context, value, 'begin')['eligible']
    assert unused.state(args, context, value, 'eligible')['eligible']
    assert unused.state(args, context, value, 'finish', 'e'*64)['eligible']
    with driver.store.read_transaction() as db:
        assert not db.execute('SELECT 1 FROM runs WHERE workload=?', (context.workload,)).fetchone()
        assert db.execute('SELECT state FROM console_pool_items WHERE workload=?', (context.workload,)).fetchone()[0] == 'retired'
