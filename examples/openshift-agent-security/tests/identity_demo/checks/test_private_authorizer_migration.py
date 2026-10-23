# SPDX-License-Identifier: Apache-2.0
"""The idle repair changes policy selection, never identity or approval rules."""
from argparse import Namespace
from copy import deepcopy

import pytest

from deployment_profile import DeploymentProfile, LEGACY
import cluster_console_gateway as migration
import cluster_console_operator as operator
import identity_demo_execution_setup as execution
import identity_demo_setup as setup
from gateway_credential_route import READ_NAME, READ_HOST, FILTER


def fixture():
    profile=DeploymentProfile.from_dict({**LEGACY.to_dict(),'installation_id':'parallel','core_namespace':'customer-a'})
    def obj(kind,spec):return {'kind':kind,'metadata':{'name':READ_NAME,'namespace':profile.core_namespace,
        'uid':kind+'-original','labels':profile.labels},'spec':spec}
    auth=obj('AuthConfig',{'hosts':[READ_HOST],'authentication':{'signed-token':{'jwt':{'issuerUrl':'https://issuer.example'}}},
        'authorization':{'exact-live-approval':{'patternMatching':{'patterns':[{'predicate':'allowed'}]}}}})
    patches=[{'applyTo':'VIRTUAL_HOST','match':{'routeConfiguration':{'portNumber':port,'vhost':{'name':READ_HOST+':'+str(port)}}},
        'patch':{'operation':'MERGE','value':{'typed_per_filter_config':{FILTER+'-step4':{
            '@type':'type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute','disabled':False}}}}}
        for port in (8080,8443)]
    envoy=obj('EnvoyFilter',{'workloadSelector':{'labels':{'owned':'gateway'}},'configPatches':patches})
    return profile,{'profile':profile.to_dict(),'created':[auth,envoy]}


def test_repair_keeps_all_authentication_approval_and_gateway_selection_fields():
    profile,receipt=fixture();saved=deepcopy(receipt)
    before,after=migration.changes(profile,receipt)
    assert receipt==saved and before==receipt['created']
    restored=deepcopy(after)
    restored[0]['spec']['hosts']=[READ_HOST]
    for patch in restored[1]['spec']['configPatches']:
        value=patch['patch']['value']['typed_per_filter_config'][FILTER+'-step4']
        assert value.pop('check_settings')=={'context_extensions':{'host':profile.private_mcp_authorization_host}}
        value['disabled']=False
    assert restored==before


@pytest.mark.parametrize('change',['profile','namespace','host','disabled','missing-listener','other-settings'])
def test_repair_refuses_unreviewed_or_incomplete_routing(change):
    profile,receipt=fixture()
    if change=='profile':receipt['profile']['owner']='foreign'
    elif change=='namespace':receipt['created'][0]['metadata']['namespace']='foreign'
    elif change=='host':receipt['created'][0]['spec']['hosts']=['foreign']
    elif change=='missing-listener':receipt['created'][1]['spec']['configPatches'].pop()
    else:
        value=receipt['created'][1]['spec']['configPatches'][0]['patch']['value']['typed_per_filter_config'][FILTER+'-step4']
        if change=='disabled':value['disabled']=True
        else:value['unexpected']='setting'
    with pytest.raises(ValueError):migration.changes(profile,receipt)


def test_migration_refuses_a_replaced_owned_resource_before_dry_run(tmp_path,monkeypatch):
    profile,receipt=fixture()
    def kube(args,*words,**kwargs):
        assert words[0]=='get'
        value=deepcopy(receipt['created'][0]);value['metadata']['uid']='replacement';return value
    monkeypatch.setattr(setup,'kube',kube)
    with pytest.raises(ValueError,match='authorizer changed'):
        migration.prepare(Namespace(output_dir=tmp_path),profile,receipt)


def test_migration_requires_offline_workers_and_certain_history(monkeypatch):
    profile,receipt=fixture()
    monkeypatch.setattr(operator,'private_request',lambda *a:{'online':True})
    def forbidden(*a,**k):raise AssertionError('No change while workers are online')
    monkeypatch.setattr(setup,'kube',forbidden)
    monkeypatch.setattr(execution,'inspect_state',forbidden)
    with pytest.raises(ValueError,match='Offline fenced'):
        migration.repair(Namespace(),profile,receipt,{})


def status_wait(tmp_path,monkeypatch):
    profile,receipt=fixture();_,after=migration.changes(profile,receipt)
    value=deepcopy(after[0]);value['metadata']['resourceVersion']='7'
    value['status']={'summary':{'ready':False,'hostsReady':[]},'conditions':[{'type':'Ready','status':'False'}]}
    monkeypatch.setattr(operator,'private_request',lambda *a:{'online':False})
    monkeypatch.setattr(execution,'inspect_state',lambda *a:{'rollback_quiescent':True})
    monkeypatch.setattr(migration.time,'sleep',lambda _:None)
    return profile,value,Namespace(output_dir=tmp_path)


def test_stale_status_gets_one_spec_preserving_metadata_hint_and_requires_real_ready(tmp_path,monkeypatch):
    profile,value,args=status_wait(tmp_path,monkeypatch);calls=[];hinted=[False]
    def kube(args,*words,value=None):
        calls.append((words,value))
        if words[0]=='get':
            actual=deepcopy(expected)
            if hinted[0]:actual['status']={'summary':{'ready':True,'hostsReady':expected['spec']['hosts']},
                'conditions':[{'type':'Ready','status':'True'}]}
            return actual
        assert words[:3]==('patch','authconfig','fixture-step4-read-route')
        assert value[:3]==[{'op':'test','path':'/metadata/uid','value':expected['metadata']['uid']},
            {'op':'test','path':'/metadata/resourceVersion','value':'7'},
            {'op':'test','path':'/spec','value':expected['spec']}]
        assert all(v['op']=='test' or v['path'].startswith('/metadata/annotations') for v in value)
        if '--dry-run=server' not in words:hinted[0]=True
        return deepcopy(expected)
    expected=value
    monkeypatch.setattr(setup,'kube',kube)
    result=migration.wait_linked(args,profile,expected)
    assert result['status']['summary']['ready'] is True
    assert sum(w[0]=='patch' and '--dry-run=server' not in w for w,_ in calls)==1


def test_uncertain_status_hint_is_not_replayed(tmp_path,monkeypatch):
    profile,value,args=status_wait(tmp_path,monkeypatch)
    (tmp_path/'host-status-hint.pending.json').write_text('{}')
    def kube(args,*words,**kwargs):
        assert words[0]=='get'
        return deepcopy(value)
    monkeypatch.setattr(setup,'kube',kube)
    with pytest.raises(ValueError,match='Uncertain reconciliation hint'):
        migration.wait_linked(args,profile,value)


def test_status_wait_cannot_adopt_a_changed_policy(tmp_path,monkeypatch):
    profile,value,args=status_wait(tmp_path,monkeypatch);changed=deepcopy(value)
    changed['spec']['authorization']={}
    def kube(args,*words,**kwargs):
        assert words[0]=='get'
        return changed
    monkeypatch.setattr(setup,'kube',kube)
    with pytest.raises(ValueError,match='policy changed'):
        migration.wait_linked(args,profile,value)


@pytest.mark.parametrize('change',['uid','rules','live-rules'])
def test_recovery_never_replays_or_adopts_a_changed_completed_patch(tmp_path,monkeypatch,change):
    profile,original=fixture();_,completed=migration.changes(profile,original)
    live=deepcopy(completed[0])
    if change=='uid':completed[0]['metadata']['uid']='replacement'
    elif change=='rules':completed[0]['spec']['authorization']={}
    else:live['spec']['authorization']={}
    def kube(args,*words,**kwargs):
        assert words[0]=='get','Recovery must not replay gateway patches'
        return live
    monkeypatch.setattr(setup,'kube',kube)
    with pytest.raises(ValueError,match='differs|changed'):
        migration.recovered(Namespace(output_dir=tmp_path),profile,original,completed)
