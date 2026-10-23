# SPDX-License-Identifier: Apache-2.0
from argparse import Namespace
import json
import pytest
from deployment_profile import active_profile
import identity_demo_capacity as capacity
import identity_demo_presentation as presentation
import probe_native_exchange as native

BUDGET={'schema_version':1,'includes_supervisor':True,'per_context':{
    'pods':'2','persistentvolumeclaims':'1','requests.storage':'2Gi',
    'requests.cpu':'300m','limits.cpu':'1','requests.memory':'1Gi','limits.memory':'2Gi'}}


def test_runtime_capacity_never_reads_foreign_namespaces_or_nodes(tmp_path,monkeypatch):
    path=tmp_path/'budget.json';path.write_text(json.dumps(BUDGET));path.chmod(0o600)
    ns=active_profile().triage_namespace
    monkeypatch.setattr(presentation,'read',lambda *args:{'metadata':{'labels':active_profile().labels}})
    calls=[]
    def kube(args,*words):
        calls.append(words)
        assert words==('get','resourcequotas','-n',ns,'-o','json')
        hard={**BUDGET['per_context'],'pods':'10','persistentvolumeclaims':'5','requests.storage':'20Gi','requests.cpu':'4','limits.cpu':'8','requests.memory':'8Gi','limits.memory':'16Gi'}
        return {'items':[{'spec':{'hard':hard},'status':{'hard':hard,'used':{k:'0' for k in hard}}}]}
    monkeypatch.setattr(native,'kube',kube)
    result=capacity.namespace_capacity(Namespace(namespace_capacity_budget_file=str(path)),1,{'triage':1})
    assert result['cluster_wide_scan'] is False and result['supervisor_included'] is True and len(calls)==1


def test_incomplete_budget_is_rejected_instead_of_underestimating_supervisor():
    with pytest.raises(ValueError):capacity.validate_budget({**BUDGET,'includes_supervisor':False})
    with pytest.raises(ValueError):capacity.validate_budget({**BUDGET,'per_context':{'requests.cpu':'250m'}})


def test_quotas_are_required_for_runtime_preparation(tmp_path,monkeypatch):
    path=tmp_path/'budget.json';path.write_text(json.dumps(BUDGET));path.chmod(0o600)
    monkeypatch.setattr(presentation,'read',lambda *args:{'metadata':{'labels':active_profile().labels}})
    monkeypatch.setattr(native,'kube',lambda *args:{'items':[]})
    with pytest.raises(ValueError,match='quota coverage'):
        capacity.namespace_capacity(Namespace(namespace_capacity_budget_file=str(path)),1,{'triage':1})
