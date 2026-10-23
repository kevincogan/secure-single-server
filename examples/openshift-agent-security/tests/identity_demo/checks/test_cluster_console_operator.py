# SPDX-License-Identifier: Apache-2.0
"""Installer-only private controls cannot become an arbitrary URL or execution proxy."""
from argparse import Namespace
import json

import pytest

from deployment_profile import LEGACY
import identity_demo_setup as setup
from cluster_console_operator import private_request, recorded


def test_worker_rejects_a_pod_image_changed_outside_its_recorded_deployment(monkeypatch):
    from argparse import Namespace
    import cluster_console_operator as control
    from deployment_profile import LEGACY
    name='fixture-console-coordinator'
    deployment={'metadata':{'uid':'deployment','generation':1},'spec':{'replicas':1,
        'template':{'spec':{'containers':[{'image':'approved@sha256:'+ 'a'*64}]}}},
        'status':{'readyReplicas':1,'observedGeneration':1}}
    monkeypatch.setattr(control,'recorded',lambda *a:deployment)
    monkeypatch.setattr(control.setup,'fingerprint',lambda *a:'expected')
    pod={'metadata':{'uid':'pod'},'spec':{'serviceAccountName':name,'containers':[{'image':'substituted'}]},
         'status':{'phase':'Running','containerStatuses':[{'ready':True}]}}
    def kube(args,*words,**kwargs):
        assert words[:2]==('get','pods')
        return {'items':[pod]}
    monkeypatch.setattr(control.setup,'kube',kube)
    with pytest.raises(ValueError,match='scoped worker Pod'):
        control.worker(Namespace(),LEGACY,[{'kind':'Deployment','name':name,'fingerprint':'expected'}],'coordinator')


def test_private_control_accepts_only_fixed_pool_or_state_routes(monkeypatch):
    calls=[]
    def kube(args,*words,value=None):
        calls.append((words,value))
        assert words[:2]==('exec','-i')
        assert 'deployment/fixture-identity-driver' in words
        assert value['suffix'] in ('state','pool')
        assert 'verify=\'/issuer-ca/service-ca.crt\'' in words[-1]
        assert 'trust_env=False' in words[-1] and 'follow_redirects=False' in words[-1]
        return {'status':200,'body':{'unused':0}}
    monkeypatch.setattr(setup,'kube',kube)
    assert private_request(Namespace(),LEGACY,'pool')=={'unused':0}
    for suffix,body in [('https://foreign.example',None),('../run',None),('state',{'action':'arbitrary'})]:
        with pytest.raises(ValueError):private_request(Namespace(),LEGACY,suffix,body)
    assert len(calls)==1


def test_replaced_or_foreign_operator_targets_are_refused(monkeypatch):
    records=[{'kind':'Deployment','name':'fixture-identity-driver','uid':'original'}]
    live={'metadata':{'uid':'replacement','labels':dict(LEGACY.labels)}}
    monkeypatch.setattr(setup,'kube',lambda *args,**kw:live)
    with pytest.raises(ValueError,match='recorded'):recorded(Namespace(),LEGACY,records,'Deployment','fixture-identity-driver')
    live['metadata']['uid']='original';live['metadata']['labels']['identity-demo-owner']='foreign'
    with pytest.raises(ValueError,match='Owned'):recorded(Namespace(),LEGACY,records,'Deployment','fixture-identity-driver')


def test_initial_activation_waits_through_observation_but_stops_on_security_failure(tmp_path,monkeypatch):
    import cluster_console_operator as control
    values=iter([{'online':True,'phase':'preparing'}, {'online':True,'phase':'ready'}])
    calls=[]
    def read(args,profile,suffix,data=None):
        assert suffix=='state' and data is None
        calls.append(suffix);return next(values)
    monkeypatch.setattr(control,'private_request',read)
    monkeypatch.setattr(control.time,'sleep',lambda _:None)
    control.wait_ready(Namespace(output_dir=tmp_path),LEGACY)
    assert len(calls)==2
    monkeypatch.setattr(control,'private_request',lambda *a,**kw:{'online':True,'phase':'blocked','reason':'sender_trust'})
    with pytest.raises(ValueError,match='security/recovery'):
        control.wait_ready(Namespace(output_dir=tmp_path),LEGACY)


@pytest.mark.parametrize('resume,items,remaining,native,accepted', [
    (True, 8, 0, False, True), (True, 0, 0, False, False),
    (True, 8, 1, False, False), (True, 8, 0, True, False),
    (False, 0, 0, False, True)])
def test_explicit_resume_preserves_history_only_after_exact_retirement(
        tmp_path, monkeypatch, resume, items, remaining, native, accepted):
    import cluster_console_operator as control
    import identity_demo_execution_setup as execution
    import identity_demo_capacity as capacity
    args = Namespace(output_dir=tmp_path, apply=True, resume_retired_pool=resume,
        console_runtime_stage='automatic-enable', console_configuration_receipt='configuration',
        console_configuration_sha256='a'*64, console_worker_receipt='workers', console_worker_sha256='b'*64)
    def receipt(path, expected):
        return {'applied': True, 'stage': 'configure', 'updated': []} if path == 'configuration' else {
            'applied': True, 'runtime': 'cluster', 'created': []}
    monkeypatch.setattr(control, 'receipt', receipt)
    monkeypatch.setattr(control, 'recorded', lambda *a: {})
    monkeypatch.setattr(execution, 'inspect_state', lambda *a: {
        'rollback_quiescent': True, 'pool_items': items, 'non_retired_pool_items': remaining})
    monkeypatch.setattr(control, 'worker', lambda a, p, r, role: {
        'pod_uid': role, 'port': 18443 if role == 'coordinator' else 18444})
    monkeypatch.setattr(control.setup, 'kube', lambda *a, **kw: {'items': [{}] if native else []})
    monkeypatch.setattr(capacity, 'namespace_capacity', lambda *a: None)
    monkeypatch.setattr(control, 'wait_ready', lambda *a: None)
    sent = []
    def request(a, p, suffix, data=None):
        assert suffix == 'pool'
        if data is not None:
            sent.append(data)
            return {'automatic': {'managed': 0}}
        return {'contexts': [], 'unused': 0, 'automatic': None}
    monkeypatch.setattr(control, 'private_request', request)
    if accepted:
        result = control.run(args, LEGACY)
        assert result['automatic_pool_enabled'] and result['retired_history_preserved'] == resume
        assert len(sent) == 1 and sent[0]['initial_empty'] is not resume
        assert sent[0]['retired_workloads'] == []
    else:
        with pytest.raises(ValueError): control.run(args, LEGACY)
        assert not sent
