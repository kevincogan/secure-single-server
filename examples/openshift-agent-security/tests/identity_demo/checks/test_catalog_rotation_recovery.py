# SPDX-License-Identifier: Apache-2.0
"""A full overlap is safe to observe again; an uncertain credential patch is not."""
from argparse import Namespace
import base64
import json
import time

import pytest

import identity_demo_adapter_catalog as catalog
import identity_demo_console_worker as worker


def test_catalog_update_packages_runtime_sources(tmp_path, monkeypatch):
    """Code maintenance must work after operational sources leave the test tree."""
    from pathlib import Path

    deployment = {'metadata': {'uid': 'owned-deployment', 'resourceVersion': '1'},
        'spec': {'template': {'metadata': {'annotations': {'identity-demo-catalog-code': 'old'}},
            'spec': {'containers': [{'name': 'adapter-https', 'env': [
                {'name': 'ADAPTER_DISCOVERY_DIGESTS_FILE', 'value': '/catalog-trust/digests.json'}]}],
                'volumes': [{'name': 'catalog-code', 'configMap': {'name': 'old-code'}}]}}}}
    old = {'data': {}}
    created = []
    def owned(args, kind, name):
        return deployment if kind == 'deployment' else old
    def fresh(args, value):
        created.append(value)
        return {**value, 'metadata': {**value['metadata'], 'uid': 'fresh-code'}}
    def kube(args, *words, **options):
        if words[0] == 'config':
            return {'clusters': [{'cluster': {'server': catalog.SERVER}}]}
        assert words[:2] == ('patch', 'deployment')
        return {'spec': {}}
    monkeypatch.setattr(catalog, 'owned', owned)
    monkeypatch.setattr(catalog, 'fresh', fresh)
    monkeypatch.setattr(catalog, 'kube', kube)
    access = tmp_path / 'kubeconfig'
    access.write_text('synthetic')
    access.chmod(0o600)
    args = Namespace(expected_server=catalog.SERVER, kubeconfig=str(access),
                     receipt_file=str(tmp_path / 'receipt.json'))
    assert catalog.update_code(args)['code_changed']
    assert len(created) == 1
    root = Path(__file__).resolve().parents[3] / 'runtime/identity_demo'
    assert set(created[0]['data']) == {
        'start_protected_adapter.py', 'adapter_auth.py', 'adapter_live_auth.py', 'adapter_discovery.py'}
    for name, code in created[0]['data'].items():
        assert code == (root / name).read_text()
        compile(code, name, 'exec')


def test_full_overlap_refuses_before_any_file_or_mutation(tmp_path, monkeypatch):
    now = 10000
    keys = {'first': now + 100, 'second': now + 700}
    trust = {'metadata': {'uid': 'owned', 'resourceVersion': '1'},
             'data': {'digests.json': base64.b64encode(json.dumps(keys).encode()).decode()}}
    calls = []
    def kube(args, *words, **kwargs):
        calls.append(words)
        assert words[:3] == ('config', 'view', '--minify')
        return {'clusters': [{'cluster': {'server': catalog.SERVER}}]}
    monkeypatch.setattr(catalog, 'kube', kube)
    monkeypatch.setattr(catalog, 'owned', lambda args, kind, name: trust)
    monkeypatch.setattr(catalog.time, 'time', lambda: now)
    args = Namespace(expected_server=catalog.SERVER, kubeconfig=str(tmp_path/'kube'),
                     action='rotate', catalog_credential_file=str(tmp_path/'new.json'),
                     receipt_file=str(tmp_path/'receipt.json'))
    (tmp_path/'kube').write_text('synthetic')
    (tmp_path/'kube').chmod(0o600)
    with pytest.raises(catalog.CatalogRotationDeferred) as stopped:
        catalog.rotate_or_revoke(args)
    assert stopped.value.retry_at == now + 100
    assert not (tmp_path/'new.json').exists() and not (tmp_path/'receipt.json').exists()
    assert len(calls) == 1


def test_overlap_expiry_allows_one_rotation_without_eviction(tmp_path, monkeypatch):
    now = 10000
    keys = {'expired': now - 1, 'valid': now + 700}
    trust = {'metadata': {'uid': 'owned', 'resourceVersion': '1'},
             'data': {'digests.json': base64.b64encode(json.dumps(keys).encode()).decode()}}
    patches = []
    def kube(args, *words, **kwargs):
        if words[0] == 'config':
            return {'clusters': [{'cluster': {'server': catalog.SERVER}}]}
        assert words[0] == 'patch'
        patch = json.loads(words[words.index('--patch')+1]);patches.append(patch)
        return {**trust, 'data': patch[-1]['value']}
    monkeypatch.setattr(catalog, 'kube', kube)
    monkeypatch.setattr(catalog, 'owned', lambda args, kind, name: trust)
    monkeypatch.setattr(catalog.time, 'time', lambda: now)
    args = Namespace(expected_server=catalog.SERVER, kubeconfig=str(tmp_path/'kube'),
                     action='rotate', catalog_credential_file=str(tmp_path/'new.json'),
                     receipt_file=str(tmp_path/'receipt.json'))
    (tmp_path/'kube').write_text('synthetic');(tmp_path/'kube').chmod(0o600)
    result = catalog.rotate_or_revoke(args)
    updated = json.loads(base64.b64decode(patches[0][-1]['value']['digests.json']))
    assert result['active_credentials'] == 2 and len(patches) == 1
    assert updated['valid'] == now + 700 and 'expired' not in updated


@pytest.mark.parametrize('remaining,expected,phase', [(700, True, 'ready'), (500, False, 'preparing')])
def test_deferred_capacity_keeps_lifetime_gates_and_recovers(tmp_path, monkeypatch, remaining, expected, phase):
    import identity_demo_sender_trust as trust
    import identity_demo_spire_network as network
    credential = tmp_path/'catalog.json'
    credential.write_text(json.dumps({'token': 'discovery_synthetic', 'expires_at': int(time.time()) + remaining}))
    credential.chmod(0o600)
    control = worker.Control('synthetic')
    control.state('preparing')
    monkeypatch.setattr(control, 'publish', lambda: None)
    monkeypatch.setattr(control, 'request', lambda _: {'running': 0, 'busy': False, 'uncertain': 0, 'recovery_required': False})
    monkeypatch.setattr(worker, 'guard', lambda _: None)
    monkeypatch.setattr(worker, 'private_inference', lambda _: None)
    monkeypatch.setattr(worker, 'recover_catalog_reference', lambda _: True)
    monkeypatch.setattr(trust, 'current', lambda _: True)
    monkeypatch.setattr(network, 'kubelet_coverage_current', lambda _: True)
    monkeypatch.delenv('IDENTITY_DEMO_RUNTIME', raising=False)
    def deferred(_):
        raise catalog.CatalogRotationDeferred(int(time.time()) + 120)
    monkeypatch.setattr(worker, 'refresh_catalog', deferred)
    args = Namespace(output_dir=tmp_path, kubeconfig='private', inference_config='private',
                     catalog_credential_file=str(credential), auto_refresh_catalog=True)
    assert worker.readiness_check(args, control) is expected
    assert control.readiness['phase'] == phase
    assert control.readiness['reason'] != 'catalog_refresh_failed'
    monkeypatch.setattr(worker, 'refresh_catalog', lambda _: int(time.time()) + 3600)
    assert worker.readiness_check(args, control) is True
    assert control.readiness['phase'] == 'ready'


def test_unknown_refresh_failure_keeps_operator_stop(tmp_path, monkeypatch):
    import identity_demo_sender_trust as trust
    credential = tmp_path/'catalog.json'
    credential.write_text(json.dumps({'token': 'discovery_synthetic', 'expires_at': int(time.time()) + 700}))
    credential.chmod(0o600)
    control = worker.Control('synthetic');control.state('preparing')
    monkeypatch.setattr(control, 'publish', lambda: None)
    monkeypatch.setattr(control, 'request', lambda _: {'running': 0, 'busy': False, 'uncertain': 0, 'recovery_required': False})
    monkeypatch.setattr(worker, 'guard', lambda _: None)
    monkeypatch.setattr(worker, 'private_inference', lambda _: None)
    monkeypatch.setattr(worker, 'recover_catalog_reference', lambda _: True)
    monkeypatch.setattr(trust, 'current', lambda _: True)
    def uncertain(_):
        raise RuntimeError('reply lost after patch')
    monkeypatch.setattr(worker, 'refresh_catalog', uncertain)
    args = Namespace(output_dir=tmp_path, kubeconfig='private', inference_config='private',
                     catalog_credential_file=str(credential), auto_refresh_catalog=True)
    with pytest.raises(RuntimeError, match='operator review'):
        worker.readiness_check(args, control)
    assert control.readiness == {'phase': 'blocked', 'reason': 'catalog_refresh_failed', 'catalog_expires': 0, 'checked_at': 0}
