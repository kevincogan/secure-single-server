# SPDX-License-Identifier: Apache-2.0
"""Operator acceptance checkpoints must never repeat an uncertain operation."""
import importlib.util
from pathlib import Path

import pytest


@pytest.fixture
def module(monkeypatch):
    directory = Path(__file__).resolve().parents[3] / 'examples/document-agent'
    monkeypatch.syspath_prepend(str(directory))
    spec = importlib.util.spec_from_file_location('document_qualification_test', directory / 'qualification.py')
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def test_recorded_response_reused_without_second_mutation(module, tmp_path):
    journal = module.Journal(tmp_path / 'private')
    calls = []
    def dispatch():
        calls.append(1)
        return {'dispatched': True}
    assert journal.once('dispatch', dispatch) == journal.once('dispatch', dispatch)
    assert len(calls) == 1


def test_lost_response_requires_review_without_replay(module, tmp_path):
    journal = module.Journal(tmp_path / 'private')
    calls = []
    def dispatch():
        calls.append(1)
        raise OSError('synthetic committed response loss')
    with pytest.raises(OSError):
        journal.once('dispatch', dispatch)
    with pytest.raises(ValueError, match='Uncertain'):
        journal.once('dispatch', dispatch)
    assert len(calls) == 1


def test_success_status_cannot_replace_successful_tool_contract(module):
    with pytest.raises((ValueError, KeyError)):
        module.tool_value({'status': 200, 'body': {'error': 'denied'}})
    with pytest.raises(ValueError):
        module.tool_value({'status': 403, 'body': {'reason': 'denied'}})


def test_backend_observation_is_readonly_and_bound_to_original_controller(module, tmp_path):
    import json
    directory = tmp_path / 'created'; directory.mkdir(mode=0o700)
    original = {'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': {
        'name': 'fixture-document-backend', 'uid': 'deployment-original'}, 'spec': {'replicas': 1}}
    path = directory / '000.json';path.write_text(json.dumps(original));path.chmod(0o600)
    calls = []
    class Cluster:
        config = {'profile': {'core_namespace': 'candidate-only'}}
        def uri(self, value):
            return '/apis/apps/v1/namespaces/candidate-only/deployments/fixture-document-backend'
        def call(self, words):
            calls.append(words)
            if words[:2] == ['get', '--raw']:
                return original
            if words[:2] == ['get', 'pods']:
                return {'items': [{'metadata': {'name': 'backend-pod', 'uid': 'pod-original', 'ownerReferences': [
                    {'kind': 'ReplicaSet', 'name': 'backend-replica', 'uid': 'replica-original', 'controller': True}]},
                    'status': {'phase': 'Running'}}]}
            if words[:2] == ['get', 'replicaset']:
                return {'metadata': {'uid': 'replica-original', 'ownerReferences': [
                    {'kind': 'Deployment', 'uid': 'deployment-original', 'controller': True}]}}
            assert words[0] == 'exec'
            program = words[-1]
            assert '?mode=ro' in program and 'PRAGMA query_only=ON' in program
            return {'revisions': []}
    result = module.observe_backend(Cluster(), tmp_path)
    assert result['revisions'] == [] and result['query_only'] is True
    assert result['pod_uid'] == 'pod-original'
    assert len([v for v in calls if v[0] == 'exec']) == 1


def test_setup_recovery_accepts_only_exact_pre_provider_checkpoint(module,tmp_path):
    names={'started.json','backend-before.json','analyst.browser.private.json','viewer.browser.private.json',
        *{'start-'+n+s for n in ('publisher','viewer','reader') for s in ('.json','.pending.json')}}
    for name in names:(tmp_path/name).write_text('{}')
    module.validate_setup_recovery(tmp_path)
    (tmp_path/'dispatch-1.pending.json').write_text('{}')
    with pytest.raises(ValueError,match='refuses'):
        module.validate_setup_recovery(tmp_path)


def test_native_issuer_clients_are_created_and_removed_by_exact_identity(module, tmp_path):
    from types import SimpleNamespace
    import copy
    clients=[];providers=[];calls=[]
    def request(path, method='GET', value=None):
        calls.append((path,method,copy.deepcopy(value)))
        if path.startswith('/roles/'):
            return {'id':path.rsplit('/',1)[1], 'name':path.rsplit('/',1)[1]}
        if path.endswith('/scope-mappings/realm'):
            assert {v['name'] for v in value}=={'analyst','viewer'}
            return None
        collection=providers if path.startswith('/identity-provider/') else clients
        if method=='POST':
            record=copy.deepcopy(value)
            record['internalId' if collection is providers else 'id']=str(len(collection)+1)
            collection.append(record);return None
        if method=='DELETE':
            collection.remove(next(v for v in collection if v.get('id',v.get('alias'))==path.rsplit('/',1)[1]))
            return None
        if '?' in path:
            from urllib.parse import parse_qs
            name=parse_qs(path.split('?',1)[1])['clientId'][0]
            return copy.deepcopy([v for v in clients if v['clientId']==name])
        if path in ('/clients','/identity-provider/instances'):return copy.deepcopy(collection)
        return copy.deepcopy(next(v for v in collection if v.get('id',v.get('alias'))==path.rsplit('/',1)[1]))
    config={'audience':'https://fixture.example.test/mcp'}
    contexts={n:SimpleNamespace(workload='spiffe://test.example/openshell/sandbox/'+n) for n in ('publisher','reader')}
    with module.issuer_clients(request,config,contexts,tmp_path):
        assert len(clients)==4 and len(providers)==1
        for client in clients:
            if client['clientId'] in {c.workload for c in contexts.values()}:
                assert 'tls.client.certificate.bound.access.tokens' not in client['attributes']
                assert client['attributes']['access.token.lifespan']=='30'
            assert client['fullScopeAllowed'] is False
    assert not clients and not providers
    assert (tmp_path/'issuer-cleanup.json').is_file()
    clients.append({'clientId':config['audience'],'id':'other-owner'})
    with pytest.raises(ValueError,match='Existing native issuer'):
        with module.issuer_clients(request,config,contexts,tmp_path):pass
    assert clients==[{'clientId':config['audience'],'id':'other-owner'}]


@pytest.mark.parametrize('status,active,expires,issuer_error,passes', [
    (502,0,2000,True,True), (502,0,2000,False,False),
    (502,1,2000,True,False), (502,0,900,True,False),
    (403,0,2000,False,True), (200,0,2000,True,False),
])
def test_logout_needs_independent_revocation_not_just_transport_error(
        module,monkeypatch,tmp_path,status,active,expires,issuer_error,passes):
    from deployment_profile import LEGACY
    monkeypatch.setattr(module,'recorded_pod',lambda *a: ({},{'metadata':{'name':'owned-host','uid':'original-pod'}}))
    monkeypatch.setattr(module.time,'time',lambda:1000)
    gateway='spiffe://'+LEGACY.trust_domain+'/openshell/gateway/'+LEGACY.gateway_id
    class Cluster:
        config={'profile':LEGACY.to_dict()}
        def call(self,words,raw=False):
            if words[0]=='exec':
                assert 'mode=ro' in words[-2] and 'PRAGMA query_only=ON' in words[-2]
                return {'active':active,'expires':expires}
            assert words[0]=='logs' and raw and '--since-time' in words
            return (('type="TOKEN_EXCHANGE_ERROR" error="invalid_token" reason="subject_token validation failure" '
                'client_assertion_sub="'+gateway+'"') if issuer_error else 'unrelated network timeout').encode()
    operation=lambda:module.verify_logout(Cluster(),tmp_path,tmp_path,'original-run',{'status':status},990)
    if passes:
        operation()
        assert (tmp_path/'logout-revocation.json').exists()
    else:
        with pytest.raises(ValueError):operation()
        assert not (tmp_path/'logout-revocation.json').exists()


def test_isolation_targets_include_privileged_issuer_gateway_and_backend(module):
    class Cluster:
        config = {'profile': {'core_namespace': 'candidate-only', 'owner': 'test-owner'},
                  'control_origin': 'https://control.example.test',
                  'issuer': 'https://issuer.example.test/realms/test'}
        def uri(self, value):
            assert value['metadata']['name'].startswith('fixture-document-')
            return '/verified-owned-service'
        def call(self, words):
            if words[1] == 'service':
                return {'kind': 'Service', 'metadata': {'name': words[2], 'namespace': 'candidate-only',
                    'uid': 'original-' + words[2], 'labels': {'identity-demo-owner': 'test-owner'}},
                    'spec': {'clusterIP': '10.0.0.' + str(len(words[2]))}}
            assert words[1] == 'pods'
            return {'items': []}
    values = module.isolation_destinations(Cluster())
    assert {'host': 'fixture-openshell.candidate-only.svc.cluster.local', 'port': 8080} in values
    assert {'host': 'fixture-keycloak-upstream.candidate-only.svc.cluster.local', 'port': 8443} in values
    assert {'host': 'fixture-document-backend.candidate-only.svc.cluster.local', 'port': 8443} in values
    assert {'host': 'control.example.test', 'port': 443} in values
    assert {'host': 'issuer.example.test', 'port': 443} in values


@pytest.mark.parametrize('alteration', ['owner', 'namespace', 'name', 'uid', 'deleting'])
def test_isolation_observation_refuses_substituted_application_service(module, alteration):
    class Cluster:
        config = {'profile': {'core_namespace': 'candidate-only', 'owner': 'test-owner'}}
        def uri(self, value):
            assert value['metadata']['name'].startswith('fixture-document-')
        def call(self, words):
            if words[1] == 'pods': return {'items': []}
            meta = {'name': words[2], 'namespace': 'candidate-only', 'uid': 'original',
                    'labels': {'identity-demo-owner': 'test-owner'}}
            if words[2] == 'fixture-keycloak-upstream':
                if alteration == 'owner': meta['labels']['identity-demo-owner'] = 'another-owner'
                elif alteration == 'deleting': meta['deletionTimestamp'] = '2026-11-03T00:00:00Z'
                else: meta[alteration] = ''
            return {'kind': 'Service', 'metadata': meta, 'spec': {'clusterIP': '10.0.0.1'}}
    with pytest.raises(ValueError, match='Exact owned application service'):
        module.isolation_destinations(Cluster())
