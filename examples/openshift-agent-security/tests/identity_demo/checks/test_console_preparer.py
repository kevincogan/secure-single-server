# SPDX-License-Identifier: Apache-2.0
"""Automatic replenishment excludes execution and cannot reuse or replay authority."""
from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from identity_demo_driver import Driver
from identity_demo_run_store import Denied
from identity_demo_console_preparer import prepare_one, retire_previous

from checks.support.console import configured, operator, submit

from checks.support.console_preparer import reserve, finish
from checks.support.pool_profiles import mapping, prepare, setup











def test_idle_spares_do_not_provision_and_browser_cannot_reserve(tmp_path: Path) -> None:
    driver, client, _ = configured(tmp_path)
    driver.console.heartbeat(uuid4().hex)
    assert client.post('/internal/operator/console/prepare/next', json={'owner': uuid4().hex}).status_code == 403
    assert reserve(driver, client, uuid4().hex) is None
    assert driver.console.available(True)['auto_prepare'] is True


@pytest.mark.parametrize('change', [
    {'project': 'OTHER'}, {'role': 'reader'}, {'namespace': 'foreign'}, {'console_prepared': False},
    {'workflow': 'incident-triage'}, {'sandbox_name': 'demo-s56-triage-xx'}, {'service_account': 'admin'},
    {'workload': 'spiffe://other/openshell/sandbox/' + str(uuid4())}, {'extra': 'not allowed'},
])
def test_preparer_cannot_change_trusted_role_project_or_identity_contract(tmp_path: Path, change: dict) -> None:
    driver, client, _ = setup(tmp_path)
    owner = uuid4().hex
    reservation = reserve(driver, client, owner)
    context = {**mapping(reservation['target']), **change}
    assert finish(driver, client, owner, reservation, context).status_code == 403
    assert not driver.console.contexts()


def test_helper_restart_never_replays_unknown_native_mutation(tmp_path: Path, monkeypatch) -> None:
    import identity_demo_console_preparer as helper
    reservation = {'id': uuid4().hex, 'target': {'operation': 'prepare', 'automatic': True, 'profile_id': 'triage'}}
    directory = tmp_path / reservation['id']
    directory.mkdir(mode=0o700)
    checkpoint = directory / 'checkpoint.private.json'
    checkpoint.write_text(json.dumps({'phase': 'mutation_pending'}))
    checkpoint.chmod(0o600)
    calls = []
    monkeypatch.setattr(helper, 'provision', lambda a: pytest.fail('Unknown provisioning must never replay'))
    control = SimpleNamespace(request=lambda route, data: calls.append((route, data)))
    result = prepare_one(SimpleNamespace(output_dir=tmp_path), control, uuid4().hex, reservation)
    assert result['blocked'] and calls[0][1]['context'] is None


def test_helper_repeats_only_identical_completion_receipt(tmp_path: Path) -> None:
    reservation = {'id': uuid4().hex, 'target': {'operation': 'prepare', 'automatic': True, 'profile_id': 'triage'}}
    directory = tmp_path / reservation['id']
    directory.mkdir(mode=0o700)
    checkpoint = directory / 'checkpoint.private.json'
    checkpoint.write_text(json.dumps({'phase': 'ready_to_commit', 'context': {'unchanged': True}, 'receipt_sha256': 'a' * 64}))
    checkpoint.chmod(0o600)
    calls = []
    result = prepare_one(SimpleNamespace(output_dir=tmp_path), SimpleNamespace(request=lambda *v: calls.append(v)), uuid4().hex, reservation)
    assert result['resumed_commit'] and calls[0][1]['context'] == {'unchanged': True}


@pytest.mark.parametrize('eligible', [False, True])
def test_automatic_retirement_requires_closed_cleanup_before_registration_delete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, eligible: bool
) -> None:
    import identity_demo_console_preparer as helper
    import identity_demo_execution_setup as setup
    from identity_demo_lab import LABELS
    from dataclasses import asdict
    context = replace(setup.context_template('triage', 'abc'), sandbox_id=str(uuid4()))
    entry = {'metadata': {'uid': 'exact', 'resourceVersion': '7', 'labels': dict(LABELS)},
             'spec': {'spiffeID': context.workload, 'className': 'zero-trust-workload-identity-manager-spire',
                      'selectors': ['k8s:ns:' + context.namespace, 'k8s:sa:' + context.service_account,
                                    'k8s:container-name:supervisor']}}
    deletes = []
    def read(_args: object, kind: str, *names: str, **kwargs: object) -> dict | None:
        if kind in ('namespace', 'deployment'):
            return {'metadata': {'labels': dict(LABELS)}}
        return entry if kind.startswith('clusterstatic') and not deletes else None
    def delete(_args: object, *words: str, **kwargs: object) -> None:
        assert words[0] == 'delete'
        assert kwargs['payload']['preconditions'] == {'uid': 'exact', 'resourceVersion': '7'}
        deletes.append(words)
    monkeypatch.setattr(setup, 'guard', lambda _: (None, {}, None))
    monkeypatch.setattr(setup, 'read', read)
    monkeypatch.setattr(helper, 'read', read)
    monkeypatch.setattr(setup.native, 'kube', delete)
    monkeypatch.setattr(setup.subprocess, 'run', lambda *a, **kw: SimpleNamespace(
        returncode=0 if eligible else 1, stdout='{"eligible":true}' if eligible else '', stderr=''))
    args = SimpleNamespace(output_dir=tmp_path, kubeconfig='private', apply=True)
    if eligible:
        result = retire_previous(args, asdict(context))
        assert result['workspace_data_retained'] and result['registration_absent']
        assert len(deletes) == 1
    else:
        with pytest.raises(ValueError, match='closed'):
            retire_previous(args, asdict(context))
        assert not deletes


def test_cancelled_unclaimed_job_can_be_replenished_without_runtime_replay(tmp_path: Path) -> None:
    driver, client, worker = setup(tmp_path)
    prepare(driver, client)
    response = submit(driver, client)
    run = response.headers['location'].split('/')[-1]
    driver.store.cancel(run, 'user-a')
    assert driver.console.claim(worker) is None
    assert driver.console.describe(run)['evidence']['cleanup_verified'] is True
    assert reserve(driver, client, uuid4().hex) is not None




def test_atomic_checkpoint_is_private_and_survives_replacement(tmp_path: Path) -> None:
    from identity_demo_console_preparer import record
    path = tmp_path / 'checkpoint.private.json'
    record(path, {'phase': 'mutation_pending'})
    assert json.loads(path.read_text()) == {'phase': 'mutation_pending'}
    assert path.stat().st_mode & 0o077 == 0
    record(path, {'phase': 'ready_to_commit'})
    assert json.loads(path.read_text()) == {'phase': 'ready_to_commit'}
    assert not path.with_suffix('.tmp').exists()


@pytest.mark.parametrize('interruption', ['preparation', 'retirement'])
def test_process_replacement_quarantines_interrupted_mutation_without_replay(
    tmp_path: Path, interruption: str
) -> None:
    """An actual process exit leaves a durable checkpoint; a new process cannot replay it.

    Native effects are isolated fault fixtures. The real preparer, checkpoint and
    driver completion/SQLite recovery paths run unchanged; no cluster is contacted.
    """
    import os
    import subprocess
    import sys

    driver, client, worker = setup(tmp_path)
    if interruption == 'retirement':
        prepare(driver, client)
        response = submit(driver, client)
        assert response.status_code == 303
        job = driver.console.claim(worker)
        driver.store.cancel(job['run_id'], 'user-a')
        driver.console.update(job['run_id'], worker, 'completed', {'cleanup_verified': True})
        for _ in range(8):
            prepare(driver, client)
    owner = uuid4().hex
    reservation = reserve(driver, client, owner)
    assert reservation['target']['operation'] == ('retire' if interruption == 'retirement' else 'prepare')
    root = tmp_path / 'worker'
    root.mkdir(mode=0o700)
    inputs = root / 'reservation.json'
    inputs.write_text(json.dumps({'owner': owner, 'reservation': reservation}))
    child = r'''
import json, os, sys
from pathlib import Path
from types import SimpleNamespace
import identity_demo_console_preparer as helper
root, mode, stage = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
inputs = json.loads((root / 'reservation.json').read_text())
def effect(name):
    with (root / 'native-effects.jsonl').open('a') as stream:
        stream.write(json.dumps({'effect': name}) + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    os._exit(71)
def retire(*args):
    if mode == 'retirement':
        effect('retirement')
    return {'workspace_data_retained': True}
def provision(*args):
    effect('preparation')
def request(route, payload):
    assert route == 'prepare/finish'
    (root / ('completion-' + stage + '.json')).write_text(json.dumps(payload))
helper.retire_previous = retire
helper.provision = provision
import identity_demo_capacity as capacity
capacity.check_capacity = lambda *a: {}
result = helper.prepare_one(SimpleNamespace(output_dir=root),
    SimpleNamespace(request=request), inputs['owner'], inputs['reservation'])
assert result['blocked'] and result['ambiguous_mutation_not_replayed']
'''
    environment = {**os.environ, 'PYTHONPATH': os.pathsep.join(sys.path)}
    first = subprocess.run([sys.executable, '-c', child, str(root), interruption, 'first'],
                           env=environment, capture_output=True, text=True, timeout=20)
    assert first.returncode == 71, first.stderr
    checkpoint = root / reservation['id'] / 'checkpoint.private.json'
    assert json.loads(checkpoint.read_text())['phase'] == 'mutation_pending'
    assert checkpoint.stat().st_mode & 0o077 == 0
    second = subprocess.run([sys.executable, '-c', child, str(root), interruption, 'replacement'],
                            env=environment, capture_output=True, text=True, timeout=20)
    assert second.returncode == 0, second.stderr
    assert len((root / 'native-effects.jsonl').read_text().splitlines()) == 1
    payload = json.loads((root / 'completion-replacement.json').read_text())
    assert payload['context'] is None and payload['id'] == reservation['id']
    assert client.post('/internal/operator/console/prepare/finish',
                       headers=operator(driver), json=payload).status_code == 200
    replacement = Driver(driver.config, driver.verify)
    with replacement.store.read_transaction() as db:
        state, = db.execute("SELECT state FROM console_preparations WHERE id=?",
                            (reservation['id'],)).fetchone()
        assert state == 'quarantined'
    assert len((root / 'native-effects.jsonl').read_text().splitlines()) == 1


def test_profile_preparation_keeps_creation_and_loaded_policy_receipts_separate(tmp_path, monkeypatch):
    from contextlib import contextmanager
    from dataclasses import fields
    import identity_demo_console_preparer as helper
    import identity_demo_runtime as runtime
    import identity_demo_capacity as capacity
    import identity_demo_workspace_retention as retention
    from checks.support.pool_profiles import setup, mapping
    from execution_context import ExecutionContext

    driver, client, _ = setup(tmp_path)
    owner = uuid4().hex
    reservation = reserve(driver, client, owner)
    expected = mapping(reservation['target'])
    context = ExecutionContext(**{f.name:expected[f.name] for f in fields(ExecutionContext)})
    root = tmp_path/'preparer'
    root.mkdir(mode=0o700)
    creation_directory = root/reservation['id']/'provision'
    verification_directory = root/reservation['id']/'loaded-policy'

    def provision(args):
        assert args.pool_profile == reservation['target']['profile']
        # Native session receipts intentionally refuse overwrites.
        (args.output_dir/'console-preparation.portforward-log').write_text('original creation log')
        (args.output_dir/'context.private.json').write_text(json.dumps(expected))
        return {'native_created':True}

    @contextmanager
    def session(args, credentials):
        with (args.output_dir/'console-preparation.portforward-log').open('x') as stream:
            stream.write('independent loaded-policy observation')
        def query(words, **kwargs):
            base = ['policy','get',context.sandbox_name]
            assert words in (base+['--base','--output','json'],base+['--rev','1','--base','--output','json'])
            return {'scope':'sandbox','sandbox':context.sandbox_name,'policy_source':'sandbox',
                    'status':'loaded' if '--rev' in words else 'effective',
                    'version':1,'active_version':1,'hash':'c'*64}
        yield query

    def complete(route, value):
        assert route == 'prepare/finish'
        driver.console.finish_preparation(value['owner'],value['id'],value['context'],value['receipt_sha256'])

    monkeypatch.setattr(capacity,'check_capacity',lambda *a,**kw:{'available':True})
    monkeypatch.setattr(helper,'provision',provision)
    monkeypatch.setattr(helper,'resolve_context',lambda *a,**kw:context)
    monkeypatch.setattr(retention,'capture',lambda *a,**kw:None)
    monkeypatch.setattr(runtime,'guard',lambda *a:(None,{},None))
    monkeypatch.setattr(helper.native,'native_session',session)
    result=prepare_one(SimpleNamespace(output_dir=root),SimpleNamespace(request=complete),owner,reservation)
    assert result['prepared'] and driver.console.context_ready(context.workload)
    assert (creation_directory/'console-preparation.portforward-log').read_text() == 'original creation log'
    assert (verification_directory/'console-preparation.portforward-log').read_text() == 'independent loaded-policy observation'


@pytest.mark.parametrize(('fault', 'attempts', 'passes'), [('tunnel-once', 2, True), ('tunnel', 2, False),
                                                          ('policy', 1, False), ('identity', 0, False)])
def test_verify_retries_only_tunnel_startup(tmp_path, monkeypatch, fault, attempts, passes):
    from contextlib import contextmanager
    from checks.support.pool_profiles import setup, prepare
    import identity_demo_console_preparer as helper
    import identity_demo_runtime as runtime

    driver, client, _ = setup(tmp_path)
    previous = prepare(driver, client)
    with driver.store.transaction() as db:
        db.execute('UPDATE console_profile_contexts SET verified_until=0')
    owner = uuid4().hex
    reservation = reserve(driver, client, owner)
    sessions, completion = [], []

    def resolve(*args, **kwargs):
        if fault == 'identity':
            raise ValueError('Exact identity mismatch')
        return SimpleNamespace(workload=previous['workload'])

    @contextmanager
    def session(args, _credentials):
        sessions.append(args.output_dir)
        if fault == 'tunnel' or fault == 'tunnel-once' and len(sessions) == 1:
            raise helper.native.NativeTunnelStartupError('test startup failure')
        yield None

    monkeypatch.setattr(runtime, 'guard', lambda _: (None, {}, None))
    monkeypatch.setattr(helper, 'resolve_context', resolve)
    monkeypatch.setattr(helper.native, 'native_session', session)
    monkeypatch.setattr(helper, 'loaded_policy', lambda *_: {
        'hash': 'f' * 64 if fault == 'policy' else previous['native_policy_hash'],
        'status': 'loaded', 'version': 1, 'active_version': 1})
    control = SimpleNamespace(request=lambda _, value: completion.append(value))
    for _ in range(2):
        prepare_one(SimpleNamespace(output_dir=tmp_path), control, owner, reservation)
    assert len(set(sessions)) == len(sessions) == attempts
    assert completion[0] == completion[1]
    assert completion[0]['context'] == (previous if passes else None)


@pytest.mark.parametrize('fault', [None, 'global', 'wrong_sandbox', 'missing_version',
                                  'bad_hash', 'pending', 'changed_hash', 'changed_active'])
def test_policy_verifier_matches_effective_and_explicit_loaded_revision(fault):
    from identity_demo_console_preparer import loaded_policy

    context = SimpleNamespace(sandbox_name='demo-s56-triage-abc')
    # Pinned CLI: the current config reports effective; an explicit revision
    # reports loaded. They are different observations and must agree.
    effective = {'scope':'sandbox','sandbox':context.sandbox_name,'policy_source':'sandbox',
                 'status':'effective','version':1,'active_version':1,'hash':'c'*64}
    revision = dict(effective,status='loaded')
    if fault == 'global':
        effective['policy_source']='global'
    elif fault == 'wrong_sandbox':
        effective['sandbox']='another-sandbox'
    elif fault == 'missing_version':
        effective.pop('version')
    elif fault == 'bad_hash':
        effective['hash']='not-a-native-policy-hash'
    elif fault == 'pending':
        revision['status']='pending'
    elif fault == 'changed_hash':
        revision['hash']='d'*64
    elif fault == 'changed_active':
        revision['active_version']=2
    calls=[]
    def execute(words, **kwargs):
        calls.append(words)
        return revision if '--rev' in words else effective
    if fault:
        with pytest.raises(ValueError):
            loaded_policy(execute,context)
    else:
        assert loaded_policy(execute,context)==revision
        assert calls==[['policy','get',context.sandbox_name,'--base','--output','json'],
                       ['policy','get',context.sandbox_name,'--rev','1','--base','--output','json']]


def test_capacity_observation_can_retry_before_any_provisioning_checkpoint(tmp_path, monkeypatch):
    import identity_demo_capacity as capacity
    import identity_demo_console_preparer as helper

    driver, client, _ = setup(tmp_path)
    owner = uuid4().hex
    reservation = reserve(driver, client, owner)

    def unavailable(*args):
        raise ValueError('Capacity unavailable')

    monkeypatch.setattr(capacity, 'check_capacity', unavailable)
    monkeypatch.setattr(helper, 'provision', lambda *a: pytest.fail('Capacity failure must precede native mutation'))
    with pytest.raises(helper.PreparationCapacityUnavailable):
        prepare_one(SimpleNamespace(output_dir=tmp_path), SimpleNamespace(), owner, reservation)
    assert not (tmp_path / reservation['id'] / 'checkpoint.private.json').exists()
