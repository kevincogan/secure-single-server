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
    (False, 0, 0, False, True), (False, 8, 0, False, False)])
def test_explicit_resume_preserves_history_only_after_exact_retirement(
        tmp_path, monkeypatch, resume, items, remaining, native, accepted):
    import cluster_console_operator as control
    import identity_demo_execution_setup as execution
    import identity_demo_capacity as capacity
    from checks.support.pool_profiles import configuration
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
    monkeypatch.setattr(control, 'demo_configuration', lambda _: configuration())
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
        assert len(sent) == 1 and sent[0]['action'] == 'profiles'
        assert sent[0]['configuration'] == configuration()
    else:
        with pytest.raises(ValueError): control.run(args, LEGACY)
        assert not sent


def test_default_profiles_require_configured_images_and_share_only_compatible_capacity(tmp_path,monkeypatch):
    from pathlib import Path
    from deployment_profile import LEGACY
    import cluster_console_operator as control
    from deployment_artifacts import IMAGE_ROLES
    path=tmp_path/'artifacts.json'
    path.write_text(json.dumps({'schema_version':1,'images':{k:'registry.example.test/'+k+'@sha256:'+'a'*64 for k in IMAGE_ROLES},
        'native_build_contract':LEGACY.native_build_contract,'native_ca_bundle_sha256':'b'*64}))
    path.chmod(0o600);monkeypatch.setenv('IDENTITY_DEMO_ARTIFACTS',str(path))
    image='registry.example.test/workload@sha256:'+'c'*64
    value=control.demo_configuration(image)
    assert [(p['role'],p['target']) for p in value['profiles']]==[('triage',6),('reader',2)]
    assert len({w['profile'] for w in value['workflows'] if w['workflow'] in ('incident-triage','service-request')})==1
    assert not value['profiles'][1]['write_actions']
    assert all(p['workload_image']==image for p in value['profiles'])


@pytest.mark.parametrize("image", ["registry.example.test/workload:latest", "registry.example.test/workload@sha256:" + "0" * 64])
def test_default_profiles_reject_unpinned_or_placeholder_workload(image, monkeypatch):
    import cluster_console_operator as control
    import deployment_artifacts
    from identity_demo_connector import Denied
    monkeypatch.setattr(deployment_artifacts, "configured_native_image", lambda role:
                        "registry.example.test/supervisor@sha256:" + "a" * 64)
    with pytest.raises(Denied, match="pool_profile"):
        control.demo_configuration(image)


@pytest.mark.parametrize('remaining', [None, 'sandboxes.agents.x-k8s.io', 'pod', 'clusterstaticentries.spire.spiffe.io'])
def test_legacy_retirement_acknowledges_only_independently_absent_resources(tmp_path, monkeypatch, remaining):
    from dataclasses import asdict, replace
    from uuid import uuid4

    import identity_demo_controller_identity as identities
    import identity_demo_execution_setup as execution
    from cluster_console_operator import confirmed_legacy_retirements
    from identity_demo_warm_pool import retirement_identity

    context = replace(execution.context_template('triage', 'ret'), sandbox_id=str(uuid4()))
    tmp_path.chmod(0o700)
    filename = tmp_path / 'retired.private.json'
    filename.write_text(json.dumps(asdict(context)))
    filename.chmod(0o600)
    checks = []

    def read(args, kind, name, namespace=None, optional=False):
        assert optional
        checks.append((kind, name, namespace))
        return {'present': True} if kind == remaining else None

    monkeypatch.setattr(execution, 'read', read)
    monkeypatch.setattr(identities, 'enabled', lambda: False)
    args = Namespace(retired_context_file=[str(filename)])
    if remaining:
        with pytest.raises(ValueError, match='absence'):
            confirmed_legacy_retirements(args, LEGACY)
    else:
        assert confirmed_legacy_retirements(args, LEGACY) == {context.workload: retirement_identity(asdict(context))}
        assert checks == [
            ('sandboxes.agents.x-k8s.io', context.resource_name, context.namespace),
            ('pod', context.resource_name, context.namespace),
            ('pod', 'os-supervisor-' + context.sandbox_id, context.namespace),
            ('clusterstaticentries.spire.spiffe.io', context.registration_name, None),
        ]
