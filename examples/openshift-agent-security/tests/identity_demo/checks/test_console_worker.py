# SPDX-License-Identifier: Apache-2.0
"""Coordinator recovery requires positive cleanup evidence and preserves write uncertainty."""

from argparse import Namespace
import json
from pathlib import Path
import time
from uuid import uuid4

import pytest

import identity_demo_console_worker as worker


@pytest.mark.parametrize('result,record,expected', [
    ({'cleanup_verified':True},{'run':{'active':0},'actions':[]},True),
    ({},{'run':{'active':0},'actions':[]},False),
    ({'cleanup_verified':True},{'run':{'active':1},'actions':[]},False),
    ({'cleanup_verified':True},{'run':{'active':0},'actions':[{'state':'unknown'}]},False),
    ({'cleanup_verified':True},{'run':{'active':0},'actions':[{'state':'executing'}]},False),
    ({'cleanup_verified':True},{},False),
])
def test_next_run_requires_positive_cleanup_and_closed_authority(result: dict, record: dict, expected: bool) -> None:
    """Absence of an error is insufficient to release the execution lane."""
    assert worker.safe_after_failure(result,record) is expected


@pytest.mark.parametrize('failure',[OSError('temporary disconnect'),worker.ControlRejected(503)])
def test_heartbeat_survives_one_transient_failure(monkeypatch: pytest.MonkeyPatch, failure: Exception) -> None:
    """A harmless control outage does not kill the coordinator or claim another job."""
    control=worker.Control('synthetic')
    waits=iter([False,False,True])
    calls=[]
    monkeypatch.setattr(control.stopping,'wait',lambda _:next(waits))
    def publish() -> None:
        calls.append(True)
        if len(calls)==1:
            raise failure
    monkeypatch.setattr(control,'publish',publish)
    control.heartbeat()
    assert len(calls)==2 and not control.lost.is_set() and not control.ownership_lost.is_set()


def test_rejected_lease_does_not_take_over_another_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    """An explicit authentication/lease rejection stops authority immediately."""
    control=worker.Control('synthetic')
    monkeypatch.setattr(control.stopping,'wait',lambda _:False)
    monkeypatch.setattr(control,'publish',lambda:(_ for _ in ()).throw(worker.ControlRejected(403)))
    control.heartbeat()
    assert control.lost.is_set() and control.ownership_lost.is_set()


@pytest.mark.parametrize('cleanup,action_state,expected',[(True,None,True),(False,None,False),(True,'unknown',False)])
def test_execution_failure_keeps_service_only_after_verified_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                                    cleanup: bool, action_state: str | None, expected: bool) -> None:
    """The actual job exception handler closes only its own terminal attempt."""
    run=uuid4().hex
    record={'run':{'active':0,'expires':int(time.time())+600},'actions':([] if action_state is None else [{'state':action_state}]),'audit':[]}
    updates=[]
    class Control:
        def request(self,*args: object) -> dict:
            return record
        def update(self,*args: object) -> None:
            updates.append(args)
    class Flow:
        def __init__(self,*args: object,**kwargs: object) -> None:
            pass
        def progress(self,*args: object) -> None:
            pass
    monkeypatch.setattr(worker,'ConsoleCveFlow',Flow)
    monkeypatch.setattr(worker.native,'run',lambda _:{'passed':False,'errors':[{'failure_kind':'ValueError'}],'cleanup_verified':cleanup})
    context={'sandbox_name':'demo-s56-triage-abc','sandbox_id':str(uuid4()),'role':'triage',
             'service_account':'fixture-openshell-sandbox','registration_name':'identity-demo-test-abc',
             'provider_prefix':'demo-s56-triage-abc-exchange','namespace':'demo-triage','workspace':'demo-triage'}
    args=Namespace(output_dir=tmp_path,catalog_credential_file='private',driver_credentials_file='private')
    assert worker.execute_job(args,Control(),{'run_id':run,'context':context,'workflow':'cve','user_role':'analyst'}) is expected
    assert updates[-1][1]=='execution_failed'
    assert updates[-1][2]['cleanup_verified'] is expected
    failure=json.loads((tmp_path/('run-'+run)/'failure.private.json').read_text())
    assert failure['kind']=='RuntimeError'


def test_catalog_renewal_never_runs_during_unresolved_execution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Renewal is restricted to an idle execution lane and never changes run authority."""
    credential=tmp_path/'catalog.json'
    credential.write_text(json.dumps({'token':'discovery_synthetic','expires_at':int(time.time())+700}))
    credential.chmod(0o600)
    class Control:
        def __init__(self) -> None:
            self.readiness={}
        def state(self,phase: str,reason: str='',**kw: int) -> None:
            self.readiness={'phase':phase,'reason':reason,**kw}
        def publish(self) -> None:
            pass
        def request(self,*args: object) -> dict:
            return {'running':1,'uncertain':0}
    control=Control()
    calls=[]
    monkeypatch.setattr(worker,'guard',lambda _:None)
    monkeypatch.setattr(worker,'private_inference',lambda _:None)
    monkeypatch.setattr(worker,'refresh_catalog',lambda _:calls.append(True))
    assert worker.readiness_check(Namespace(catalog_credential_file=str(credential),inference_config='private',auto_refresh_catalog=True),control) is False
    assert not calls and control.readiness['reason']=='recovery_required'


@pytest.mark.parametrize('running,uncertain,recovery,expected', [
    (0, 0, False, True), (1, 0, False, False), (0, 1, False, False), (0, 0, True, False),
])
def test_control_reconnect_requires_authoritative_no_claim_or_uncertain_write(
        monkeypatch: pytest.MonkeyPatch, running: int, uncertain: int, recovery: bool, expected: bool) -> None:
    control = worker.Control('synthetic')
    control.state('reconnecting', 'control_unavailable')
    calls = []
    def request(suffix: str, data: dict | None = None) -> dict:
        calls.append(suffix)
        assert suffix in ('state', 'heartbeat')  # Never claim or replay an action here.
        return {'enabled': True, 'running': running, 'uncertain': uncertain, 'recovery_required': recovery,
                'busy': True}  # A queued, unclaimed job is safe only with running=0.
    monkeypatch.setattr(control, 'request', request)
    assert worker.recover_idle_control(control) is expected
    assert calls == (['state', 'heartbeat'] if expected else ['state'])
    if expected:
        assert control.readiness['phase'] == 'preparing'


def test_control_reconnect_never_takes_over_a_rejected_lease(monkeypatch: pytest.MonkeyPatch) -> None:
    control = worker.Control('synthetic')
    monkeypatch.setattr(control, 'request', lambda _: (_ for _ in ()).throw(worker.ControlRejected(403)))
    assert worker.recover_idle_control(control) is False
    assert control.ownership_lost.is_set()

def test_restart_reuses_only_existing_private_catalog_key_confirmed_by_live_trust(
    monkeypatch: pytest.MonkeyPatch, tmp_path: object
) -> None:
    """An old environment reference must not trigger a third active discovery key."""
    import base64
    import hashlib
    import json
    import time
    from argparse import Namespace
    import identity_demo_adapter_catalog as catalog

    old = tmp_path / "original.private.json"
    old.write_text(json.dumps({"token": "discovery_expired", "expires_at": 1}))
    old.chmod(0o600)
    previous = tmp_path / "console-worker-launch-previous"
    previous.mkdir(mode=0o700)
    renewed = previous / "catalog-renewed.private.json"
    expiry = int(time.time()) + 2000
    renewed.write_text(
        json.dumps({"token": "discovery_synthetic-renewed", "expires_at": expiry})
    )
    renewed.chmod(0o600)
    forged = previous / "catalog-untrusted.private.json"
    forged.write_text(
        json.dumps({"token": "discovery_untrusted", "expires_at": expiry + 999})
    )
    forged.chmod(0o600)
    digest = hashlib.sha256(b"discovery_synthetic-renewed").hexdigest()
    trust = {
        "data": {
            "digests.json": base64.b64encode(
                json.dumps({digest: expiry}).encode()
            ).decode()
        }
    }
    monkeypatch.setattr(catalog, "owned", lambda *a: trust)
    args = Namespace(
        output_dir=tmp_path / "console-worker-launch-new",
        catalog_credential_file=str(old),
    )
    assert worker.recover_catalog_reference(args) is True
    assert args.catalog_credential_file == str(renewed)
    renewed.write_text(
        json.dumps({"token": "discovery_synthetic-renewed", "expires_at": expiry + 1})
    )
    args.catalog_credential_file = str(old)
    assert worker.recover_catalog_reference(args) is False
    assert args.catalog_credential_file == str(old)


def test_diagnostic_deadlines_cannot_be_left_in_a_normal_multi_job_worker() -> None:
    import subprocess
    import sys
    from pathlib import Path
    source = Path(__file__).resolve().parents[3] / 'scripts/identity_demo/identity_demo_console_worker.py'
    flags = ('kubeconfig', 'expected-server', 'credentials-file', 'cli', 'cli-config-dir',
             'catalog-credential-file', 'driver-credentials-file', 'inference-config', 'output-dir')
    command = [sys.executable, str(source)]
    for flag in flags:
        command += ['--' + flag, 'synthetic-private-reference']
    result = subprocess.run([*command, '--diagnostic-failure', 'model-timeout'], capture_output=True, text=True, timeout=10)
    assert result.returncode == 2
    assert 'requires exactly --stop-after 1' in result.stderr


@pytest.mark.parametrize('action_state,close_fails,expected', [(None, False, True), ('unknown', False, False), (None, True, False)])
def test_tunnel_startup_failure_closes_only_a_proven_unused_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                              action_state: str | None, close_fails: bool, expected: bool) -> None:
    """Only the typed pre-dispatch failure can release an unused, revoked context."""
    run = uuid4().hex
    record = {'run': {'active': 1, 'expires': int(time.time()) + 600},
              'actions': [] if action_state is None else [{'state': action_state}], 'audit': []}
    updates, closes = [], []

    class Control:
        def request(self, *args: object) -> dict:
            return record
        def update(self, *args: object) -> None:
            updates.append(args)

    class Flow:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass
        def progress(self, *args: object) -> None:
            pass
        def close(self) -> None:
            closes.append(True)
            if close_fails:
                raise RuntimeError('Unverified retirement')
            record['run']['active'] = 0

    def failed_start(_: object) -> dict:
        raise worker.native.NativeTunnelStartupError('No native command dispatched')

    monkeypatch.setattr(worker, 'ConsoleCveFlow', Flow)
    monkeypatch.setattr(worker.native, 'run', failed_start)
    context = {'sandbox_name': 'demo-s56-reader-abc', 'sandbox_id': str(uuid4()), 'role': 'reader',
               'service_account': 'fixture-openshell-sandbox', 'registration_name': 'identity-demo-reader-abc',
               'provider_prefix': 'demo-s56-reader-abc-exchange', 'namespace': 'demo-reader', 'workspace': 'demo-reader'}
    args = Namespace(output_dir=tmp_path, catalog_credential_file='private', driver_credentials_file='private')
    assert worker.execute_job(args, Control(), {'run_id': run, 'context': context, 'workflow': 'cve', 'user_role': 'analyst'}) is expected
    assert updates[-1][2]['cleanup_verified'] is expected
    assert updates[-1][2]['failure_code'] == ('preparation_failed' if expected else 'recovery_required')
    assert bool(closes) == (action_state is None)


@pytest.mark.parametrize('age,expiry,first_phase,network_failure', [(10, 3600, 'ready', False), (121, 3600, 'preparing', False), (10, 700, 'preparing', False), (10, 3600, 'ready', True)])
def test_readiness_observation_preserves_only_recent_verified_admission(
        tmp_path, monkeypatch, age, expiry, first_phase, network_failure):
    """Read-only checks do not flicker; stale/startup state and maintenance close admission."""
    import identity_demo_sender_trust as trust
    import identity_demo_spire_network as network
    credential = tmp_path / 'catalog.json'
    credential.write_text(json.dumps({'token': 'discovery_synthetic', 'expires_at': int(time.time()) + expiry}))
    credential.chmod(0o600)
    control = worker.Control('synthetic')
    control.state('ready', checked_at=int(time.time()) - age, catalog_expires=int(time.time()) + expiry)
    published, checks = [], []
    monkeypatch.setattr(control, 'publish', lambda: published.append(control.readiness.copy()))
    def observe():
        checks.append(control.readiness['phase'])
        return {'running': 0, 'busy': False, 'uncertain': 0, 'recovery_required': False}
    monkeypatch.setattr(control, 'request', lambda suffix: observe() if suffix == 'state' else pytest.fail('Must not claim during checks'))
    monkeypatch.setattr(worker, 'guard', lambda _: checks.append('guard'))
    monkeypatch.setattr(worker, 'private_inference', lambda _: checks.append('inference'))
    monkeypatch.setattr(worker, 'recover_catalog_reference', lambda _: True)
    monkeypatch.setattr(trust, 'current', lambda _: checks.append('trust') or True)
    monkeypatch.setattr(network, 'kubelet_coverage_current', lambda _: checks.append('network') or not network_failure)
    monkeypatch.delenv('IDENTITY_DEMO_RUNTIME', raising=False)
    def rotate(_):
        assert control.readiness['phase'] == 'preparing' and published[-1]['phase'] == 'preparing'
        checks.append('rotate')
        return int(time.time()) + 3600
    monkeypatch.setattr(worker, 'refresh_catalog', rotate)
    args = Namespace(output_dir=tmp_path, kubeconfig='private', inference_config='private',
                     catalog_credential_file=str(credential), auto_refresh_catalog=True)
    result = worker.readiness_check(args, control)
    if network_failure:
        assert result is False and control.readiness['phase'] == 'blocked' and control.readiness['reason'] == 'identity_network'
        return
    assert result
    assert checks[:3] == ['guard', 'inference', first_phase]
    assert {'guard', 'inference', 'trust', 'network'} <= set(checks)
    assert ('rotate' in checks) == (expiry < 900)
    assert control.readiness['phase'] == 'ready' and control.readiness['checked_at'] >= int(time.time()) - 1
    if first_phase == 'ready':
        assert all(v['phase'] == 'ready' for v in published)


def test_queued_run_defers_catalog_mutation_without_claim_or_recovery_reset(tmp_path, monkeypatch):
    """A browser request racing maintenance cannot trigger a credential mutation."""
    import identity_demo_sender_trust as trust
    credential = tmp_path / 'catalog.json'
    credential.write_text(json.dumps({'token': 'discovery_synthetic', 'expires_at': int(time.time()) + 700}))
    credential.chmod(0o600)
    control = worker.Control('synthetic')
    published = []
    monkeypatch.setattr(control, 'publish', lambda: published.append(control.readiness.copy()))
    monkeypatch.setattr(control, 'request', lambda suffix: {'running': 0, 'busy': True, 'uncertain': 0, 'recovery_required': False}
                        if suffix == 'state' else pytest.fail('No claim or mutation allowed'))
    monkeypatch.setattr(worker, 'guard', lambda _: None)
    monkeypatch.setattr(worker, 'private_inference', lambda _: None)
    monkeypatch.setattr(worker, 'recover_catalog_reference', lambda _: True)
    monkeypatch.setattr(trust, 'current', lambda _: True)
    monkeypatch.setattr(worker, 'refresh_catalog', lambda _: pytest.fail('Must not rotate while queued'))
    args = Namespace(output_dir=tmp_path, inference_config='private', catalog_credential_file=str(credential), auto_refresh_catalog=True)
    assert worker.readiness_check(args, control) is False
    assert control.readiness['phase'] == 'preparing' and control.readiness['reason'] == 'catalog_expiring'
    assert published[-1]['reason'] == 'catalog_expiring'


def test_stalled_readiness_cannot_keep_admission_ready_by_heartbeat(monkeypatch):
    """Heartbeat liveness never extends the time of the actual prerequisite check."""
    control = worker.Control('synthetic')
    checked = int(time.time()) - 121
    control.state('ready', checked_at=checked, catalog_expires=int(time.time()) + 3600)
    waits = iter([False, True])
    monkeypatch.setattr(control.stopping, 'wait', lambda _: next(waits))
    published = []
    monkeypatch.setattr(control, 'publish', lambda: published.append(control.readiness.copy()))
    control.heartbeat()
    assert published[0]['phase'] == 'preparing' and published[0]['checked_at'] == checked


@pytest.mark.parametrize('same,admitted', [(True, False), (False, False), (False, True)])
def test_catalog_secret_changes_only_after_explicit_admission_pause(tmp_path, monkeypatch, same, admitted):
    """Unchanged catalog observation stays read-only; busy admission prevents the patch."""
    import base64
    import identity_demo_gateway_persistence as gateway
    import probe_broker_discovery as shared
    live = {'kind': 'Secret', 'metadata': {'name': 'synthetic-catalog', 'uid': 'exact-owned', 'resourceVersion': '12'},
            'type': 'Opaque', 'data': {'token': base64.b64encode(b'Bearer discovery_old').decode()}}
    credential = tmp_path / 'catalog.json'
    credential.write_text(json.dumps({'token': 'discovery_old' if same else 'discovery_new'}))
    receipt = tmp_path / 'gateway.json'
    receipt.write_text(json.dumps({'created': [live]}))
    for p in (credential, receipt):p.chmod(0o600)
    monkeypatch.setattr(shared, 'owned', lambda *args: live)
    monkeypatch.setattr(gateway, 'catalog_valid', lambda *args, **kwargs: None)
    actions = []
    def pause():
        actions.append('pause')
        return admitted
    def patch(*args, **kw):
        assert actions == ['pause'] and admitted
        assert kw['payload'][:3] == [
            {'op': 'test', 'path': '/metadata/uid', 'value': 'exact-owned'},
            {'op': 'test', 'path': '/metadata/resourceVersion', 'value': '12'},
            {'op': 'test', 'path': '/data', 'value': live['data']}]
        actions.append('patch')
    monkeypatch.setattr(shared, 'kube', patch)
    args = Namespace(gateway_receipt=str(receipt), catalog_credential_file=str(credential), output_dir=tmp_path)
    result = gateway.rotate_catalog(args, before_mutation=pause)
    assert actions == ([] if same else ['pause', 'patch'] if admitted else ['pause'])
    if not same and not admitted:assert result is False


def test_delayed_ready_heartbeat_cannot_arrive_after_completed_maintenance_pause(monkeypatch):
    """Serialize the actual publishers so an old readiness reply cannot reopen admission."""
    import threading
    control = worker.Control('synthetic')
    control.state('ready', checked_at=int(time.time()), catalog_expires=int(time.time()) + 3600)
    first_entered, release_first, second_entered = (threading.Event() for _ in range(3))
    observed, errors = [], []
    def request(suffix, value):
        assert suffix == 'heartbeat'
        observed.append(value['phase'])
        if len(observed) == 1:
            first_entered.set()
            assert release_first.wait(3)
        else:
            second_entered.set()
    monkeypatch.setattr(control, 'request', request)
    def publish():
        try:control.publish()
        except BaseException as error:errors.append(error)
    first = threading.Thread(target=publish)
    second = threading.Thread(target=publish)
    first.start()
    try:
        assert first_entered.wait(3)
        control.state('preparing')
        second.start()
        assert not second_entered.wait(.05)
    finally:
        release_first.set()
        first.join(3)
        if second.ident is not None:second.join(3)
    assert not first.is_alive() and not second.is_alive() and not errors
    assert observed == ['ready', 'preparing'] and second_entered.is_set()
