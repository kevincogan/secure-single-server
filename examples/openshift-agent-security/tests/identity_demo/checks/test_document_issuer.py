# SPDX-License-Identifier: Apache-2.0
"""Receipt-bound PKCE setup must not adopt, widen or overwrite realm clients."""
from copy import deepcopy
import importlib.util
from pathlib import Path
from urllib.parse import parse_qs
import pytest
from deployment_profile import LEGACY


@pytest.fixture
def fixture(monkeypatch,tmp_path):
    directory=Path(__file__).resolve().parents[3]/'examples/document-agent'
    monkeypatch.syspath_prepend(str(directory))
    spec=importlib.util.spec_from_file_location('document_issuer_test',directory/'issuer.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    config={'profile':LEGACY.to_dict(),'control_origin':LEGACY.origin('fixture-document-control')}
    original={'id':'original-driver','clientId':'identity-demo-driver','publicClient':True,
        'standardFlowEnabled':True,'fullScopeAllowed':False,'attributes':{
            'identity-demo-owner':LEGACY.owner,'pkce.code.challenge.method':'S256'},
        'protocolMappers':[{'id':'old-mapper','config':{'included.client.audience':'identity-demo-driver'}}]}
    clients={'original-driver':deepcopy(original)};scopes={};calls=[]
    def request(path,method='GET',value=None):
        calls.append((path,method,deepcopy(value)))
        if path.startswith('/roles/'):
            name=path.rsplit('/',1)[1];return {'id':'role-'+name,'name':name}
        if path.endswith('/scope-mappings/realm'):
            identifier=path.split('/')[2]
            if method=='POST':scopes[identifier]=deepcopy(value);return None
            return deepcopy(scopes.get(identifier,[]))
        if '?' in path:
            name=parse_qs(path.split('?',1)[1])['clientId'][0]
            return deepcopy([v for v in clients.values() if v['clientId']==name])
        if method=='POST':
            made=deepcopy(value);made['id']='proof-created';clients[made['id']]=made;return None
        identifier=path.rsplit('/',1)[1]
        if method=='DELETE':del clients[identifier];return None
        return deepcopy(clients[identifier])
    return module,module.ProofClient(request,config,tmp_path),clients,scopes,calls,original


def test_pkce_lifecycle_keeps_original_and_scopes_only_two_roles(fixture):
    module,client,clients,scopes,calls,original=fixture
    plan=client.plan();client.install(plan)
    made=clients['proof-created']
    assert made['redirectUris']==[client.config['control_origin']+'/callback']
    assert made['fullScopeAllowed'] is False and made['attributes']['pkce.code.challenge.method']=='S256'
    assert {r['name'] for r in scopes['proof-created']}=={'analyst','viewer'}
    assert made['protocolMappers'][0]['config']['included.client.audience']=='document-proof-ui'
    assert clients['original-driver']==original
    client.cleanup()
    assert clients=={'original-driver':original}


@pytest.mark.parametrize('drift',['client-id','redirect','scope'])
def test_issuer_cleanup_refuses_replaced_or_changed_client(fixture,drift):
    _,client,clients,scopes,_,_=fixture;client.install(client.plan())
    if drift=='client-id':clients['proof-created']['id']='replaced'
    elif drift=='redirect':clients['proof-created']['redirectUris']=['https://outside.example.test/']
    else:scopes['proof-created'].append({'id':'admin-role','name':'realm-admin'})
    with pytest.raises(ValueError,match='changed'):client.cleanup()
    assert 'proof-created' in clients


def test_issuer_role_plan_cannot_grant_another_role(fixture):
    _,client,clients,_,_,original=fixture;plan=client.plan()
    plan['roles']=[{'id':'admin-role','name':'realm-admin'}]
    with pytest.raises(ValueError,match='exact existing'):client.install(plan)
    assert clients=={'original-driver':original}


def test_issuer_creation_uncertainty_stops_replay_and_unreceipted_cleanup(fixture):
    module,client,clients,_,calls,_=fixture;plan=client.plan();original=client.request
    def lost(path,method='GET',value=None):
        result=original(path,method,value)
        if path=='/clients' and method=='POST':raise OSError('Synthetic lost creation response')
        return result
    client.request=lost
    with pytest.raises(OSError):client.install(plan)
    with pytest.raises(ValueError,match='checkpoint'):client.install(plan)
    with pytest.raises(ValueError,match='Uncertain'):client.cleanup()
    assert sum(path=='/clients' and method=='POST' for path,method,_ in calls)==1
    assert 'proof-created' in clients
