# SPDX-License-Identifier: Apache-2.0
"""In-place migration accepts a later UI only by its exact creation identity."""
from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

import cluster_console_install as install


@pytest.fixture
def receipt(tmp_path, monkeypatch):
    profile = SimpleNamespace(core_namespace='demo-core', labels={
        'identity-demo-owner': 'operator', 'app.kubernetes.io/part-of': 'identity-demo-preflight'})
    code = {'apiVersion': 'v1', 'kind': 'ConfigMap', 'immutable': True,
            'metadata': {'name': 'fixture-identity-driver-code-0123456789',
                         'namespace': profile.core_namespace, 'uid': 'original-created-uid',
                         'labels': dict(profile.labels)},
            'data': {'config.json': '{"origin":"https://console.example.test"}',
                     'identity_demo_driver.py': '# reviewed source\n'}}
    path = tmp_path/'code-created.json'
    path.write_text(json.dumps(code))
    path.chmod(0o600)
    args = SimpleNamespace(console_web_code_receipt=str(path), console_web_code_sha256=install.setup.sha(path))
    live = deepcopy(code)
    calls = []

    def kube(_args, *words):
        calls.append(words)
        assert words == ('get', 'ConfigMap', code['metadata']['name'], '-n', 'demo-core', '-o', 'json')
        return live

    monkeypatch.setattr(install.setup, 'kube', kube)
    return args, profile, code, live, path, calls


def test_exact_later_immutable_ui_receipt_is_read_only(receipt):
    args, profile, code, live, _, calls = receipt
    before = deepcopy(live)
    assert install.updated_web_code(args, profile, code['metadata']['name']) == before
    assert live == before and len(calls) == 1


@pytest.mark.parametrize('change', ['uid', 'namespace', 'owner', 'mutable', 'data', 'binary', 'deleting', 'owner-reference'])
def test_replaced_or_changed_live_code_is_not_adopted(receipt, change):
    args, profile, code, live, _, _ = receipt
    if change == 'uid': live['metadata']['uid'] = 'replacement-uid'
    elif change == 'namespace': live['metadata']['namespace'] = 'foreign'
    elif change == 'owner': live['metadata']['labels']['identity-demo-owner'] = 'another-owner'
    elif change == 'mutable': live['immutable'] = False
    elif change == 'data': live['data']['config.json'] = '{"origin":"https://foreign.example.test"}'
    elif change == 'binary': live['binaryData'] = {'extra': 'YQ=='}
    elif change == 'deleting': live['metadata']['deletionTimestamp'] = '2026-01-01T00:00:00Z'
    else: live['metadata']['ownerReferences'] = [{'uid': 'foreign-controller'}]
    with pytest.raises(ValueError): install.updated_web_code(args, profile, code['metadata']['name'])


@pytest.mark.parametrize('change', ['kind', 'name', 'namespace', 'uid', 'mutable', 'data', 'binary', 'owner'])
def test_invalid_saved_identity_stops_before_cluster_access(receipt, change):
    args, profile, code, _, path, calls = receipt
    name = code['metadata']['name']
    if change == 'kind': code['kind'] = 'Secret'
    elif change == 'name': code['metadata']['name'] = 'unrelated-code'
    elif change == 'namespace': code['metadata']['namespace'] = 'foreign'
    elif change == 'uid': code['metadata'].pop('uid')
    elif change == 'mutable': code['immutable'] = False
    elif change == 'data': code['data'] = []
    elif change == 'binary': code['binaryData'] = {'extra': 'YQ=='}
    else: code['metadata']['labels']['identity-demo-owner'] = 'another-owner'
    path.write_text(json.dumps(code))
    args.console_web_code_sha256 = install.setup.sha(path)
    with pytest.raises(ValueError): install.updated_web_code(args, profile, name)
    assert not calls


@pytest.mark.parametrize('change', ['missing', 'hash', 'permissions', 'symlink'])
def test_unreviewed_or_nonprivate_receipt_is_refused(receipt, change):
    args, profile, code, _, path, calls = receipt
    if change == 'missing': args.console_web_code_receipt = None
    elif change == 'hash': args.console_web_code_sha256 = '0'*64
    elif change == 'permissions': path.chmod(0o644)
    else:
        alias = path.parent/'alias.json'
        alias.symlink_to(path)
        args.console_web_code_receipt = str(alias)
    with pytest.raises(ValueError): install.updated_web_code(args, profile, code['metadata']['name'])
    assert not calls
