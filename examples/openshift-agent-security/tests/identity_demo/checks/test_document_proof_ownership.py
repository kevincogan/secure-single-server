# SPDX-License-Identifier: Apache-2.0
"""The optional runner must refuse foreign, replaced or changed resources."""
import importlib.util
from pathlib import Path

import pytest


@pytest.fixture
def module(monkeypatch):
    directory=Path(__file__).resolve().parents[3]/'examples/document-agent'
    monkeypatch.syspath_prepend(str(directory))
    spec=importlib.util.spec_from_file_location('document_proof_ownership',directory/'proof.py')
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


def cluster(module):
    value=object.__new__(module.Cluster)
    value.config={'profile':{'core_namespace':'candidate-core','owner':'test-owner'}}
    return value


def record():
    return {'apiVersion':'v1','kind':'ConfigMap','metadata':{
        'name':'fixture-document-trust','namespace':'candidate-core','uid':'original','resourceVersion':'1',
        'labels':{'identity-demo-owner':'test-owner','identity-demo-document-proof':'true'}},'data':{'trust':'public'}}


@pytest.mark.parametrize('changed',['namespace','owner','unmarked','name','kind'])
def test_foreign_resources_are_never_addressed(module,changed):
    client=cluster(module);value=record()
    if changed=='namespace':value['metadata']['namespace']='live-core'
    elif changed=='owner':value['metadata']['labels']['identity-demo-owner']='someone-else'
    elif changed=='unmarked':value['metadata']['labels'].pop('identity-demo-document-proof')
    elif changed=='name':value['metadata']['name']='unrelated'
    else:value['kind']='Namespace'
    with pytest.raises(ValueError,match='owned optional proof'):client.uri(value)


@pytest.mark.parametrize('changed',['uid','configuration','owner'])
def test_cleanup_refuses_drift_before_delete(module,tmp_path,changed):
    client=cluster(module);original=record();current=record()
    if changed=='uid':current['metadata']['uid']='replaced'
    elif changed=='configuration':current['data']['trust']='different'
    else:current['metadata']['labels']['identity-demo-owner']='someone-else'
    calls=[]
    def call(words,value=None):
        calls.append(words)
        assert words[0]=='get'
        return current
    client.call=call
    with pytest.raises(ValueError):client.delete(original,tmp_path/'receipt.json')
    assert len(calls)==1 and not list(tmp_path.iterdir())


def test_cleanup_sends_original_uid_and_latest_version_as_atomic_preconditions(module,tmp_path):
    client=cluster(module);original=record();current=record();current['metadata']['resourceVersion']='2'
    sent=[]
    def call(words,value=None):
        if words[0]=='get':return current
        sent.append((words,value));return {'status':'Success'}
    client.call=call;client.delete(original,tmp_path/'receipt.json')
    assert len(sent)==1
    assert sent[0][1]['preconditions']=={'uid':'original','resourceVersion':'2'}
    assert sent[0][1]['propagationPolicy']=='Foreground'


def test_uncertain_cleanup_is_not_automatically_repeated(module,tmp_path):
    client=cluster(module);original=record();calls=[]
    def call(words,value=None):
        calls.append(words)
        if words[0]=='get':return original
        raise RuntimeError('synthetic lost response')
    client.call=call
    with pytest.raises(RuntimeError):client.delete(original,tmp_path/'receipt.json')
    with pytest.raises(ValueError,match='without replay'):client.delete(original,tmp_path/'receipt.json')
    assert len(calls)==2


def test_bounded_gateway_diagnostics_do_not_use_tool_request_size_limit(module):
    import json
    client=cluster(module)
    client.config['profile']['core_namespace']='candidate-core'
    host={'name':'fixture-mcp-bound.candidate-core.svc.cluster.local:8443','routes':[]}
    def call(words,value=None,raw=False):
        if words[:2]==['get','pods']:
            return {'items':[{'metadata':{'name':'gateway'},'status':{'phase':'Running'},
                'spec':{'containers':[{'name':'proxy'}]}}]}
        if words[:2]==['get','gateway']:
            return {'metadata':{'labels':{'identity-demo-owner':'test-owner'}}}
        return json.dumps({'virtual_hosts':[host],'padding':'x'*70000}).encode()
    client.call=call
    assert module.gateway_routes(client)==host


@pytest.mark.parametrize('kind,field', [('ServiceAccount','imagePullSecrets'), ('ServiceAccount','secrets'),
    ('PersistentVolumeClaim','volumeName')])
def test_only_platform_assigned_fields_are_ignored_during_creation_maturation(module,kind,field):
    from copy import deepcopy
    original={'kind':kind,'apiVersion':'v1','metadata':{'uid':'original'}}
    if kind=='ServiceAccount':
        original['automountServiceAccountToken']=False
    else:
        original['spec']={'storageClassName':'approved','resources':{'requests':{'storage':'1Gi'}}}
    assigned=deepcopy(original)
    if kind=='ServiceAccount':
        assigned[field]=[{'name':'controller-assigned-pull-secret'}]
    else:
        assigned['spec'][field]='controller-assigned-volume'
    assert module.fingerprint(assigned)==module.fingerprint(original)
    if kind=='ServiceAccount':
        assigned['automountServiceAccountToken']=True
    else:
        assigned['spec']['storageClassName']='foreign'
    assert module.fingerprint(assigned)!=module.fingerprint(original)
