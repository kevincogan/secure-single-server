# SPDX-License-Identifier: Apache-2.0
"""Worker maintenance changes neither authority nor persistent application state."""
from argparse import Namespace
from copy import deepcopy
from datetime import datetime, timezone
import base64
import json

import pytest

import cluster_console_update as update
from deployment_profile import LEGACY


def inputs():
    deployments = [{'metadata':{'namespace':LEGACY.core_namespace,'name':'fixture-console-'+role},
        'spec':{'replicas':1,'strategy':{'type':'Recreate'},'template':{'spec':{
            'serviceAccountName':'fixture-console-'+role,'containers':[{'name':role,'image':'previous',
                'volumeMounts':[{'name':'state','mountPath':'/state'}]}],
            'volumes':[{'name':'state','persistentVolumeClaim':{'claimName':role+'-state'}}]}}}}
        for role in ('coordinator','preparer')]
    gateway = {'profile':LEGACY.to_dict(),'created':[{'uid':'stable-route'}],'service_ca_sha256':'same-trust'}
    secret = {'metadata':{'namespace':LEGACY.core_namespace,'name':'fixture-console-coordinator-inputs'},
        'type':'Opaque','data':{'gateway.receipt.json':base64.b64encode(json.dumps(gateway).encode()).decode(),
                              'runtime-credentials.json':'unchanged-private-credentials'}}
    return deployments, secret, {**gateway,'runtime_observation':{'same_gateway':True}}


def image():
    return 'image-registry.openshift-image-registry.svc:5000/'+LEGACY.core_namespace+'/runtime@sha256:'+'a'*64


def test_update_preserves_credentials_authority_and_all_state_mounts():
    deployments,secret,gateway=inputs();before=deepcopy((deployments,secret,gateway))
    changed,new_secret=update.desired(LEGACY,image(),deployments,secret,gateway)
    assert before==(deployments,secret,gateway)
    restored=deepcopy(changed)
    for obj in restored:obj['spec']['template']['spec']['containers'][0]['image']='previous'
    assert restored==deployments
    assert new_secret['data']['runtime-credentials.json']==secret['data']['runtime-credentials.json']
    assert json.loads(base64.b64decode(new_secret['data']['gateway.receipt.json']))==gateway


@pytest.mark.parametrize('change',['namespace','account','rolling','replicas','trust','routing','missing-observation','foreign-image'])
def test_update_refuses_adoption_or_security_changes(change):
    deployments,secret,gateway=inputs();target=image()
    if change=='namespace':deployments[0]['metadata']['namespace']='foreign'
    if change=='account':deployments[0]['spec']['template']['spec']['serviceAccountName']='admin'
    if change=='rolling':deployments[0]['spec']['strategy']['type']='RollingUpdate'
    if change=='replicas':deployments[0]['spec']['replicas']=2
    if change=='trust':gateway['service_ca_sha256']='new-trust'
    if change=='routing':gateway['created'][0]['uid']='replacement-route'
    if change=='missing-observation':gateway.pop('runtime_observation')
    if change=='foreign-image':target=target.replace('/'+LEGACY.core_namespace+'/', '/foreign/')
    with pytest.raises(ValueError):update.desired(LEGACY,target,deployments,secret,gateway)


def test_drain_waits_for_lease_expiry_without_clearing_it(monkeypatch):
    now=[100.0];observed=[]
    monkeypatch.setattr(update.time,'time',lambda:now[0])
    monkeypatch.setattr(update.time,'monotonic',lambda:now[0])
    monkeypatch.setattr(update.time,'sleep',lambda seconds:now.__setitem__(0,now[0]+seconds))
    stamp=datetime.fromtimestamp(100,timezone.utc).isoformat().replace('+00:00','Z')
    proofs=[{'lease_uid':role,'holder':role+'/process'} for role in ('coordinator','preparer')]
    def kube(args,*words,**kwargs):
        assert words[0]=='get';observed.append(words)
        if words[1]=='pods':return {'items':[]}
        role=words[2].removeprefix('fixture-console-')
        return {'metadata':{'uid':role,'labels':LEGACY.labels},
                'spec':{'holderIdentity':role+'/process','renewTime':stamp,'leaseDurationSeconds':45}}
    monkeypatch.setattr(update.setup,'kube',kube)
    monkeypatch.setattr(update,'private_request',lambda *args:{'online':False})
    update.wait_stopped(Namespace(),LEGACY,proofs)
    assert now[0]>145 and observed


def test_drain_stops_when_another_owner_takes_the_lease(monkeypatch):
    def kube(args,*words,**kwargs):
        if words[1]=='pods':return {'items':[]}
        return {'metadata':{'uid':'replacement','labels':LEGACY.labels},'spec':{'holderIdentity':'foreign/process'}}
    monkeypatch.setattr(update.setup,'kube',kube)
    with pytest.raises(ValueError,match='ownership changed'):
        update.wait_stopped(Namespace(),LEGACY,[{'lease_uid':'previous','holder':'old/process'}]*2)


def recovery_inputs(tmp_path):
    deployments,secret,gateway=inputs()
    for obj in [*deployments,secret]:
        obj['kind']='Secret' if obj is secret else 'Deployment'
        obj['metadata'].update(uid=obj['metadata']['name']+'-uid',labels=LEGACY.labels)
    previous={'created':[{'kind':o['kind'],'name':o['metadata']['name'],'uid':o['metadata']['uid'],
        'fingerprint':update.setup.fingerprint(o)} for o in [*deployments,secret]]}
    publication={'images':{'console_runtime':image()}}
    after,new_secret=update.desired(LEGACY,image(),deployments,secret,gateway)
    stopped=deepcopy(deployments)
    for obj in stopped:obj['spec']['replicas']=0
    values={'before':('workers-before.private.json',[*deployments,secret]),
        'plan':('workers-plan.private.json',[*after,new_secret]),
        'idle':('idle-before.private.json',{'rollback_quiescent':True,'tables':{'audit':'hash'}}),
        'stop0':('stop-0.receipt.private.json',stopped[0]),'stop1':('stop-1.receipt.private.json',stopped[1]),
        'proofs':('worker-proofs-before.private.json',[{'management_profile_verified':True,
            'projected_api_identity_verified':True,'lease_uid':r,'pod_uid':r,'holder':r+'/process'}
            for r in ('coordinator','preparer')]),
        'AuthConfig':('host-AuthConfig.receipt.private.json',{}),
        'EnvoyFilter':('host-EnvoyFilter.receipt.private.json',{})}
    files={}
    for key,(name,value) in values.items():
        path=tmp_path/name;update.setup.write(path,value)
        files[key]={'path':str(path),'sha256':update.setup.sha(path)}
    manifest={'kind':'private-host-update-recovery-v1','profile':LEGACY.to_dict(),'files':files}
    path=tmp_path/'recovery.private.json';update.setup.write(path,manifest)
    args=Namespace(resume_worker_update=str(path),resume_worker_update_sha256=update.setup.sha(path),
        isolate_private_authorizer=True,refresh_sender_trust=False)
    return args,previous,publication,gateway,manifest


def test_recovery_accepts_only_the_original_stopped_plan_and_keeps_history(tmp_path):
    args,previous,publication,gateway,_=recovery_inputs(tmp_path)
    saved,before,after,secret,new_secret=update.recovery_plan(args,LEGACY,previous,publication,gateway)
    assert saved['idle']['tables']=={'audit':'hash'}
    assert secret['data']['runtime-credentials.json']==new_secret['data']['runtime-credentials.json']
    assert all(o['spec']['replicas']==1 for o in before+after)


@pytest.mark.parametrize('change',['hash','uid','plan','inputs','stop','proof','uncertain-input','uncertain-start'])
def test_recovery_refuses_changed_evidence_and_uncertain_activation(tmp_path,change):
    args,previous,publication,gateway,manifest=recovery_inputs(tmp_path)
    if change=='hash':args.resume_worker_update_sha256='0'*64
    elif change in ('uid','inputs'):previous['created'][0 if change=='uid' else 2]['fingerprint']='changed'
    elif change in ('plan','stop','proof'):
        key={'plan':'plan','stop':'stop0','proof':'proofs'}[change]
        path=tmp_path/manifest['files'][key]['path'];value=json.loads(path.read_text())
        if change=='plan':value[0]['spec']['template']['spec']['serviceAccountName']='admin'
        elif change=='stop':value['spec']['replicas']=1
        else:value[0]['holder']='foreign/process'
        path.write_text(json.dumps(value));manifest['files'][key]['sha256']=update.setup.sha(path)
        (tmp_path/'recovery.private.json').write_text(json.dumps(manifest))
        args.resume_worker_update_sha256=update.setup.sha(tmp_path/'recovery.private.json')
    else:(tmp_path/('inputs-update.pending.json' if change=='uncertain-input' else 'start-0.pending.json')).write_text('{}')
    with pytest.raises(ValueError):update.recovery_plan(args,LEGACY,previous,publication,gateway)


def test_adapter_update_cannot_change_code_while_coordinator_is_online(monkeypatch):
    import cluster_console_install as install
    monkeypatch.setattr(install,'namespaces',lambda *a:None)
    monkeypatch.setattr(update,'private_request',lambda *a:{'online':True})
    def forbidden(*a,**k):raise AssertionError('No create or patch before fencing')
    monkeypatch.setattr(update.setup,'kube',forbidden)
    with pytest.raises(ValueError,match='Fenced idle'):
        update.apply_adapter(Namespace(),LEGACY,({}, {}, {}))
