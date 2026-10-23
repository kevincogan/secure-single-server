# SPDX-License-Identifier: Apache-2.0
"""Trust maintenance cannot adopt foreign observations or run through live work."""
from argparse import Namespace
from copy import deepcopy
import base64
import hashlib
import json

import pytest

from deployment_profile import LEGACY
import cluster_console_trust as maintenance
import cluster_console_operator as operator
import identity_demo_execution_setup as execution
import identity_demo_setup as setup


def observation():
    data=json.dumps({'profile':LEGACY.to_dict()})
    item={'kind':'ConfigMap','metadata':{'name':'fixture-console-sender-trust',
        'namespace':LEGACY.core_namespace,'uid':'observed-uid','labels':LEGACY.labels},
        'immutable':True,'data':{'observation.json':data}}
    reference={'uid':'observed-uid','observation_sha256':hashlib.sha256(data.encode()).hexdigest()}
    inputs={'data':{'sender-trust.receipt.json':base64.b64encode(json.dumps(reference).encode()).decode()}}
    return inputs,item


def test_matching_public_observation_is_bound_to_current_worker_reference():
    inputs,item=observation()
    maintenance.observation_reference(inputs,item,LEGACY)


@pytest.mark.parametrize('change',['uid','owner','namespace','name','mutable','deleted','data','profile'])
def test_unrecorded_or_changed_public_observation_is_never_replaced(change):
    inputs,item=observation()
    if change in ('uid','namespace','name'):item['metadata'][change]='foreign'
    elif change=='owner':item['metadata']['labels']={**LEGACY.labels,'identity-demo-owner':'foreign'}
    elif change=='mutable':item['immutable']=False
    elif change=='deleted':item['metadata']['deletionTimestamp']='now'
    elif change=='data':item['data']['extra']='another-value'
    else:item['data']['observation.json']=json.dumps({'profile':{}})
    with pytest.raises(ValueError):maintenance.observation_reference(inputs,item,LEGACY)


@pytest.mark.parametrize('online,idle',[(True,True),(False,False)])
def test_maintenance_refuses_online_workers_or_uncertain_history(monkeypatch,online,idle):
    monkeypatch.setattr(operator,'private_request',lambda *a:{'online':online})
    monkeypatch.setattr(execution,'inspect_state',lambda *a:{'rollback_quiescent':idle})
    def forbidden(*a,**k):raise AssertionError('No trust reads/mutations before fencing')
    monkeypatch.setattr(maintenance,'recorded',forbidden)
    with pytest.raises(ValueError,match='Offline fenced'):maintenance.refresh(Namespace(),LEGACY,{})


def test_resource_drift_after_drain_cannot_be_adopted(monkeypatch):
    monkeypatch.setattr(operator,'private_request',lambda *a:{'online':False})
    monkeypatch.setattr(execution,'inspect_state',lambda *a:{'rollback_quiescent':True})
    before={'kind':'Secret','metadata':{'name':'owned'},'data':{'trust':'before'}}
    after=deepcopy(before);after['data']['trust']='changed'
    monkeypatch.setattr(maintenance,'recorded',lambda *a:[after])
    with pytest.raises(ValueError,match='changed during maintenance'):
        maintenance.refresh(Namespace(),LEGACY,{'targets':[before]})


def test_issuer_and_secrets_require_original_creation_uids(tmp_path,monkeypatch):
    entries=[]
    for kind,name in (('Secret','fixture-keycloak-upstream-client-trust'),('Secret','fixture-mcp-bound-mutual'),
                      ('Deployment','fixture-keycloak-upstream')):
        entries.append({'kind':kind,'namespace':LEGACY.core_namespace,'metadata':{
            'name':name,'namespace':LEGACY.core_namespace,'uid':name+'-original','labels':LEGACY.labels}})
    path=tmp_path/'ledger.json';path.write_text(json.dumps({'installation_profile':LEGACY.to_dict(),'created':entries}));path.chmod(0o600)
    args=Namespace(ledger=str(path),console_ledger_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    def kube(args,*words,**kwargs):
        assert words[0]=='get'
        value=deepcopy(next(v for v in entries if v['metadata']['name']==words[2]))
        if value['kind']=='Secret':value['metadata']['uid']='replacement'
        return value
    monkeypatch.setattr(setup,'kube',kube)
    with pytest.raises(ValueError,match='original owned'):maintenance.recorded(args,LEGACY)
