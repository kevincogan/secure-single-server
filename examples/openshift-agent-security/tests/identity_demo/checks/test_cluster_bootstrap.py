# SPDX-License-Identifier: Apache-2.0
"""Projected mounts are materialized without importing privileged installer state."""
import json
from pathlib import Path

import pytest

from deployment_profile import LEGACY
from identity_demo_cluster_bootstrap import mounted, prepare
from deployment_artifacts import IMAGE_ROLES


def inputs(tmp_path):
    root = tmp_path/'mount';root.mkdir()
    version = root/'..version';version.mkdir()
    artifacts={'schema_version': 1, 'images': {k: 'registry.example.test/'+k.replace('_', '-')+'@sha256:'+'a'*64 for k in IMAGE_ROLES},
        'native_build_contract': LEGACY.native_build_contract, 'native_ca_bundle_sha256': 'b'*64}
    credentials={'namespace': LEGACY.core_namespace, 'keycloak_url': LEGACY.origin('fixture-keycloak'),
        'gateway_url': LEGACY.origin('fixture-mcp')+'/mcp',
        'runtime_management': {'client_id': 'fixture-runtime-operator', 'audience': 'identity-demo-runtime', 'client_secret': 's'*40}}
    values={'installation-profile.json': LEGACY.to_dict(), 'artifacts.json': artifacts,
        'runtime-credentials.json': credentials, 'driver-credentials.json': {'operator_secret': 'p'*40},
        'capacity-budget.json': {'schema_version': 1, 'includes_supervisor': True, 'per_context': {
            'pods': '2', 'persistentvolumeclaims': '1', 'requests.storage': '2Gi',
            'requests.cpu': '75m', 'requests.memory': '256Mi', 'limits.cpu': '1', 'limits.memory': '512Mi'}}}
    for name,value in values.items(): (version/name).write_text(json.dumps(value))
    for name in ('management-ca.crt','service-ca.crt','kubernetes-ca.crt'): (version/name).write_text('synthetic-public-ca')
    for path in version.iterdir(): (root/path.name).symlink_to(Path('..version')/path.name)
    return root, version


def test_preparer_uses_projected_token_and_private_state_without_passwords(tmp_path):
    root, version=inputs(tmp_path)
    state=tmp_path/'state'
    arguments,env=prepare('preparer',root,state,LEGACY.core_namespace,'pod-uid')
    config=Path(env['IDENTITY_DEMO_CONFIG']).parent
    assert not config.is_symlink() and config.stat().st_mode & 0o077 == 0
    assert env['IDENTITY_DEMO_RUNTIME']=='cluster'
    assert env['HOME']==str(state)
    assert env['IDENTITY_DEMO_REGISTRATION_MODE']=='controller'
    kubeconfig=json.loads((config/'kubeconfig.json').read_text())
    user=kubeconfig['users'][0]['user']
    assert set(user)=={'tokenFile'} and user['tokenFile'].endswith('/serviceaccount/token')
    assert '--operator-login-file' not in arguments and '--initialize-management-profile' in arguments
    assert all(not p.is_symlink() and p.stat().st_mode & 0o077 == 0 for p in config.iterdir())
    # Restart reuses identical inputs and retains prior execution/checkpoint data.
    (state/'receipts'/'retained.json').write_text('retained')
    assert prepare('preparer',root,state,LEGACY.core_namespace,'pod-uid')[0]==arguments
    assert (state/'receipts'/'retained.json').read_text()=='retained'


@pytest.mark.parametrize('field',['keycloak_admin','analyst','viewer','adapter_clients'])
def test_bootstrap_rejects_extra_human_or_installer_credentials(tmp_path,field):
    root,version=inputs(tmp_path)
    p=version/'runtime-credentials.json';value=json.loads(p.read_text());value[field]='forbidden';p.write_text(json.dumps(value))
    with pytest.raises(ValueError,match='Minimal role credentials'):
        prepare('preparer',root,tmp_path/'state',LEGACY.core_namespace,'pod-uid')


def test_mounted_input_cannot_escape_fixed_secret_root(tmp_path):
    root=tmp_path/'mount';root.mkdir()
    outside=tmp_path/'outside';outside.write_text('secret')
    (root/'runtime-credentials.json').symlink_to(outside)
    with pytest.raises(ValueError): mounted(root,'runtime-credentials.json')


def test_nested_management_credentials_cannot_smuggle_bootstrap_passwords(tmp_path):
    root,version=inputs(tmp_path)
    path=version/'runtime-credentials.json';value=json.loads(path.read_text())
    value['runtime_management']['keycloak_admin']='must-not-be-mounted'
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError,match='Exact native management'):
        prepare('preparer',root,tmp_path/'state',LEGACY.core_namespace,'pod-uid')


def test_coordinator_receives_only_two_owned_realm_clients_and_public_trust_reference(tmp_path):
    root,version=inputs(tmp_path)
    path=version/'runtime-credentials.json';value=json.loads(path.read_text())
    value['realm_management']={LEGACY.origin(name):{'client_id':'fixture-console-realm-coordinator','client_secret':'s'*40}
        for name in ('fixture-keycloak','fixture-keycloak-upstream')}
    path.write_text(json.dumps(value))
    extra={'sender-trust.receipt.json':{'uid':'public-uid','observation_sha256':'b'*64},
           'gateway.receipt.json':{'kind':'synthetic'},'catalog-credential.json':{'token':'synthetic'},
           'inference.json':{'chat':{'credential_file':'/runtime-inputs/inference.key'}}}
    for name,data in extra.items():
        (version/name).write_text(json.dumps(data));(root/name).symlink_to(Path('..version')/name)
    (version/'inference.key').write_text('synthetic-model-key');(root/'inference.key').symlink_to(Path('..version')/'inference.key')
    arguments,env=prepare('coordinator',root,tmp_path/'state',LEGACY.core_namespace,'pod-uid')
    reference=Path(env['IDENTITY_DEMO_SENDER_TRUST_RECEIPT'])
    assert reference.read_text()==json.dumps(extra['sender-trust.receipt.json'])
    assert '--auto-refresh-sender-trust' not in arguments and '--auto-refresh-catalog' in arguments
    runtime=json.loads((reference.parent/'inference.runtime.json').read_text())
    assert runtime['chat']['credential_file']==str(reference.parent/'inference.key')
    value['realm_management']['https://foreign.example']={'client_id':'fixture-console-realm-coordinator','client_secret':'s'*40}
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError,match='two owned realm'):
        prepare('coordinator',root,tmp_path/'other',LEGACY.core_namespace,'pod-uid')
