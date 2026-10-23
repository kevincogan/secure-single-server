# SPDX-License-Identifier: Apache-2.0
"""Offline faults preserve history, foreign consumers and immutable gateway state."""
from argparse import Namespace
import base64
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import time
from uuid import uuid4

import pytest

from deployment_profile import active_profile
from identity_demo_execution_setup import context_template
import identity_demo_workspace_retention as retention
import identity_demo_gateway_persistence as gateway
from run_binding import live_sender_authorization


def scratch(tmp_path, monkeypatch):
    context = replace(context_template('triage','new'), sandbox_id=str(uuid4()))
    sandbox={'metadata':{'uid':'new-sandbox'}}
    claim={'metadata':{'name':'workspace-'+context.resource_name,'uid':'new-claim',
        'ownerReferences':[{'uid':'new-sandbox','kind':'Sandbox'}]},'spec':{'resources':{'requests':{'storage':'2Gi'}}}}
    pod={'metadata':{'ownerReferences':[{'uid':'new-sandbox','kind':'Sandbox'}]},'spec':{
        'volumes':[{'persistentVolumeClaim':{'claimName':claim['metadata']['name']}}]}}
    def read(args,kind,*a,**kw):
        return sandbox if kind.startswith('sandboxes.') else pod if kind=='pod' else claim
    args=Namespace(output_dir=tmp_path,disposable_workspace_reservation='a'*32)
    proof=retention.capture(args,context,'a'*32,read)
    args.disposable_workspace_receipt=str(tmp_path/'disposable-workspaces.private.json')
    import probe_native_exchange as native
    monkeypatch.setattr(native,'kube',lambda *a,**kw:{'items':[pod]})
    return args,context,sandbox,claim,pod,read


def test_only_recorded_new_scratch_is_disposable(tmp_path,monkeypatch):
    args,context,sandbox,claim,pod,read=scratch(tmp_path,monkeypatch)
    assert retention.verify(args,context,sandbox,read)==[{'name':claim['metadata']['name'],'uid':'new-claim',
        'spec_sha256':hashlib.sha256(json.dumps(claim['spec'],sort_keys=True).encode()).hexdigest()}]


@pytest.mark.parametrize('fault',['pvc_uid','sandbox_uid','spec','owner','reservation','persistent_core'])
def test_replaced_foreign_or_unproved_workspace_is_preserved(tmp_path,monkeypatch,fault):
    args,context,sandbox,claim,pod,read=scratch(tmp_path,monkeypatch)
    if fault=='pvc_uid':claim['metadata']['uid']='replacement'
    elif fault=='sandbox_uid':sandbox['metadata']['uid']='replacement'
    elif fault=='spec':claim['spec']['resources']['requests']['storage']='3Gi'
    elif fault=='owner':claim['metadata']['ownerReferences']=[]
    elif fault=='reservation':args.disposable_workspace_reservation='b'*32
    else:pod['spec']['volumes'][0]['persistentVolumeClaim']['claimName']='fixture-jira-data'
    with pytest.raises(ValueError):retention.verify(args,context,sandbox,read)


def test_unexpected_live_consumer_blocks_disposal(tmp_path,monkeypatch):
    args,context,sandbox,claim,pod,read=scratch(tmp_path,monkeypatch)
    foreign=deepcopy(pod);foreign['metadata']['ownerReferences']=[{'uid':'someone-else'}]
    import probe_native_exchange as native
    monkeypatch.setattr(native,'kube',lambda *a,**kw:{'items':[pod,foreign]})
    with pytest.raises(ValueError,match='consumer'):retention.verify(args,context,sandbox,read)


@pytest.mark.parametrize('kind', ['Deployment', 'CronJob', 'PersistentVolumeClaim', 'MultiOwnerDeployment'])
def test_inactive_controller_or_clone_reference_blocks_disposal(tmp_path,monkeypatch,kind):
    args,context,sandbox,claim,pod,read=scratch(tmp_path,monkeypatch)
    template={'spec':{'volumes':[{'persistentVolumeClaim':{'claimName':claim['metadata']['name']}}]}}
    spec=({'replicas':0,'template':template} if kind in ('Deployment','MultiOwnerDeployment') else
          {'suspend':True,'jobTemplate':{'spec':{'template':template}}} if kind=='CronJob' else
          {'dataSourceRef':{'kind':'PersistentVolumeClaim','name':claim['metadata']['name']}})
    foreign={'kind':kind,'metadata':{'uid':'foreign-declared-reference'},'spec':spec}
    if kind=='MultiOwnerDeployment':
        foreign['kind']='Deployment'
        foreign['metadata']['ownerReferences']=[{'uid':'new-sandbox','kind':'Sandbox'},{'uid':'foreign-owner','kind':'Deployment'}]
    import probe_native_exchange as native
    monkeypatch.setattr(native,'kube',lambda a,verb,resource,*rest,**kw:{'items':[pod] if resource=='pods' else [foreign]})
    with pytest.raises(ValueError,match='declared controller or clone'):
        retention.verify(args,context,sandbox,read)


def persistent(tmp_path,monkeypatch):
    import probe_broker_discovery as shared
    labels=dict(active_profile().labels)
    def obj(kind,name,spec):return {'kind':kind,'apiVersion':'test/v1','metadata':{
        'name':name,'namespace':active_profile().core_namespace,'uid':name,'labels':labels},'spec':spec}
    auth=obj('AuthConfig','live-auth',{'driver':'live','fail_closed':True})
    policy=obj('AuthPolicy','live-policy',{'binding':'exact'})
    listener=obj('Gateway','fixture-mcp',{'listeners':[{'name':'bound','port':8443}]})
    token='discovery_'+'a'*32
    catalog={'kind':'Secret','apiVersion':'v1','metadata':{'name':'fixture-step4-read-route-catalog','uid':'catalog','labels':labels},
             'type':'Opaque','data':{'token':base64.b64encode(('Bearer '+token).encode()).decode()}}
    from identity_demo_adapter_catalog import TRUST
    trust={'metadata':{'labels':labels},'data':{'digests.json':base64.b64encode(json.dumps({
        hashlib.sha256(token.encode()).hexdigest():int(time.time())+1000}).encode()).decode()}}
    objects={o['metadata']['name']:o for o in (auth,policy,listener,catalog)};objects[TRUST]=trust
    receipt={'kind':'persistent-live-gateway-v1','profile':active_profile().to_dict(),'created':[deepcopy(auth),deepcopy(catalog)],
        'policies_after':[deepcopy(policy)],'gateway_before':deepcopy(listener),'gateway_spec':deepcopy(listener['spec']),
        'service_ca_sha256':hashlib.sha256(b'public ca').hexdigest()}
    path=tmp_path/'gateway.private.json';path.write_text(json.dumps(receipt));path.chmod(0o600)
    args=Namespace(gateway_receipt=str(path))
    monkeypatch.setattr(shared,'owned',lambda _,kind,name:objects[name])
    monkeypatch.setattr(shared,'kube',lambda *a,**kw:pytest.fail('Runtime verify must never mutate resources'))
    return args,objects,receipt


def test_persistent_runtime_verification_is_read_only(tmp_path,monkeypatch):
    args,objects,receipt=persistent(tmp_path,monkeypatch)
    assert gateway.verify(args,'public ca')==receipt


@pytest.mark.parametrize('fault',['uid','spec','listener','trust','catalog'])
def test_gateway_drift_or_revoked_catalog_blocks_before_access(tmp_path,monkeypatch,fault):
    args,objects,_=persistent(tmp_path,monkeypatch)
    ca='public ca'
    if fault=='uid':objects['live-auth']['metadata']['uid']='replacement'
    elif fault=='spec':objects['live-policy']['spec']['binding']='weaker'
    elif fault=='listener':objects['fixture-mcp']['spec']['listeners'][0]['port']=8080
    elif fault=='trust':ca='different ca'
    else:objects['fixture-step4-read-route-catalog']['data']['token']=base64.b64encode(b'Bearer stolen').decode()
    with pytest.raises(ValueError):gateway.verify(args,ca)


def test_stable_sender_gate_has_no_static_user_run_or_grant():
    policy=live_sender_authorization('https://issuer.example.test/realms/demo','https://mcp.example.test/mcp','agents.example.test')
    rego=policy['opa']['rego']
    assert 'bindings :=' not in rego and 'run_id' not in rego
    for required in ('identity.cnf','count(hash_fields) == 1','count(bad) == 0',
                     'count(names) == count({name','identity.exp - identity.iat <= 30','/mcp','binding.workload'):
        assert required in rego
    assert 'default allow' not in rego and 'contains(' not in rego


def test_persistent_cleanup_before_prepare_requires_current_gateway_verification(tmp_path, monkeypatch):
    import argparse
    import native_backend as backend
    import identity_demo_gateway_persistence as persistence
    probe = backend.NativeBackend(argparse.Namespace(output_dir=tmp_path,label='early',gateway_mode='persistent'))
    observations = []
    def owned(args, kind, name):
        assert (kind,name) == ('configmap','fixture-service-ca')
        return {'data':{'service-ca.crt':'current-public-ca'}}
    monkeypatch.setattr(backend.shared,'owned',owned)
    monkeypatch.setattr(persistence,'verify',lambda args, ca, **flags: observations.append((ca,flags)))
    probe.cleanup()
    assert observations == [('current-public-ca',{'require_catalog_fresh':False})]
    assert json.loads((tmp_path/'early.backend-cleanup.summary.json').read_text())['persistent_gateway_preserved']
    def drift(*args, **kwargs): raise ValueError('Gateway configuration changed')
    monkeypatch.setattr(persistence,'verify',drift)
    with pytest.raises(ValueError,match='Gateway configuration changed'):
        probe.cleanup()
