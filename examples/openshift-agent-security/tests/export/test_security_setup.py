# SPDX-License-Identifier: Apache-2.0
from copy import deepcopy
import json
from pathlib import Path
import pytest
from deployment_profile import DeploymentProfile
from security_setup import render, validate_network, ready, tls_review
ROOT=Path(__file__).resolve().parents[2]
@pytest.fixture
def profile(): return DeploymentProfile.from_dict(json.loads((ROOT/'docs/examples/identity-demo-installation.example.json').read_text()))
@pytest.mark.parametrize('bad',[{}, {'api_cidrs':['0.0.0.0/0'],'worker_cidrs':['192.0.2.1/32']}, {'api_cidrs':['192.0.2.1/32']*2,'worker_cidrs':['192.0.2.2/32']}, {'api_cidrs':['224.0.0.1/32'],'worker_cidrs':['192.0.2.2/32']}, {'api_cidrs':['192.0.2.1/32'],'worker_cidrs':[]}])
def test_broad_or_ambiguous_egress_refused(bad):
    with pytest.raises(ValueError): validate_network(bad)
def test_guided_manifests_are_target_bound_and_manual(profile):
    manifests=render(profile,{'api_cidrs':['192.0.2.1/32'],'worker_cidrs':['192.0.2.2/32']})
    assert all(o['spec']['installPlanApproval']=='Manual' for o in manifests['operators'] if o['kind']=='Subscription')
    assert all(o['metadata']['labels']['identity-demo-owner']==profile.owner for group in manifests.values() for o in group)
    server=next(o for o in manifests['identity'] if o['kind']=='SpireServer')
    assert profile.identity_namespace in server['spec']['jwtIssuer']
    assert server['spec']['persistence']['storageClass']==profile.storage_class
    assert not any(o['kind'] in ('ClusterRoleBinding','Secret') for group in manifests.values() for o in group)
def test_stale_and_scaled_down_controller_is_not_ready():
    value={'metadata':{'generation':2},'spec':{'replicas':1},'status':{'observedGeneration':1,'readyReplicas':1,'updatedReplicas':1}}
    assert not ready(value)
    value['status']['observedGeneration']=2;assert ready(value)
    value['spec']['replicas']=0;assert not ready(value)
def test_daemon_requires_all_updated_nodes():
    value={'metadata':{'generation':1},'status':{'observedGeneration':1,'desiredNumberScheduled':2,'numberReady':2,'updatedNumberScheduled':1}}
    assert not ready(value,daemon=True)
    value['status']['updatedNumberScheduled']=2;assert ready(value,daemon=True)
def chain(profile):
    k={'metadata':{'name':'kuadrant','namespace':'kuadrant-system','uid':'k','resourceVersion':'1','labels':dict(profile.labels)}}
    a={'metadata':{'namespace':'kuadrant-system','uid':'a','resourceVersion':'2','ownerReferences':[{'kind':'Kuadrant','uid':'k','controller':True}]},'spec':{'listener':{'port':50051}}}
    s={'metadata':{'namespace':'kuadrant-system','uid':'s','resourceVersion':'3','ownerReferences':[{'kind':'Authorino','uid':'a','controller':True}]}}
    return k,a,s
def test_tls_plan_preserves_listener_and_tests_current_identity(profile):
    k,a,s=chain(profile);before=deepcopy(a);patch=tls_review(profile,k,a,s)['authorino'];assert a==before
    assert patch[0]=={'op':'test','path':'/metadata/uid','value':'a'}
    assert patch[1]['path']=='/metadata/resourceVersion' and patch[2]['value']['port']==50051
    assert patch[2]['value']['tls']['enabled'] is True
@pytest.mark.parametrize('mode',['foreign','replaced','certificate'])
def test_tls_plan_refuses_foreign_or_ambiguous_ownership(profile,mode):
    k,a,s=chain(profile)
    if mode=='foreign':k['metadata']['labels']['identity-demo-owner']='other-team'
    if mode=='replaced':a['metadata']['ownerReferences'][0]['uid']='other'
    if mode=='certificate':s['metadata']['annotations']={'service.beta.openshift.io/serving-cert-secret-name':'other'}
    with pytest.raises(ValueError):tls_review(profile,k,a,s)

def test_overlap_bundle_keeps_retiring_ca_but_requires_active_anchor():
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes,serialization
    from datetime import datetime,timedelta,timezone
    from security_setup import validate_ca_bundle
    now=datetime.now(timezone.utc);key=ec.generate_private_key(ec.SECP256R1());name=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,'synthetic-ca')])
    def cert(end,ca=True):
        return x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=3)).not_valid_after(end).add_extension(x509.BasicConstraints(ca=ca,path_length=None),critical=True).sign(key,hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()
    expired=cert(now-timedelta(days=1));active=cert(now+timedelta(days=1))
    assert len(validate_ca_bundle(expired+active))==2
    with pytest.raises(ValueError):validate_ca_bundle(expired)
    with pytest.raises(ValueError):validate_ca_bundle(active+cert(now+timedelta(days=1),False))

def test_identity_namespace_cannot_collide_with_other_operators(profile):
    from dataclasses import replace
    for ns in ['agent-sandbox-system','kuadrant-system']:
        with pytest.raises(ValueError):render(replace(profile,identity_namespace=ns),{'api_cidrs':['192.0.2.1/32'],'worker_cidrs':['192.0.2.2/32']})
def test_security_helpers_never_accept_apply():
    from argparse import Namespace
    from security_setup import run
    with pytest.raises(ValueError,match='read-only'):run(Namespace(apply=True))
