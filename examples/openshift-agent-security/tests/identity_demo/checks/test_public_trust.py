# SPDX-License-Identifier: Apache-2.0
"""Scoped public-CA rotation rejects substitutions and cannot read serving keys."""
from argparse import Namespace
import base64
from copy import deepcopy
from datetime import datetime,timedelta,timezone
import json
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
import pytest

import identity_demo_public_trust as public
import identity_demo_sender_trust as trust
import identity_demo_console_worker as worker
from cluster_console_public_trust import resources
from deployment_profile import active_profile


def ca():
    key=ec.generate_private_key(ec.SECP256R1());name=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,'synthetic')])
    now=datetime.now(timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1))
        .not_valid_after(now+timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True,path_length=None),True)
        .sign(key,hashes.SHA256()))
    return cert,cert.public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture
def fixture(tmp_path,monkeypatch):
    old,old_pem=ca();new,new_pem=ca()
    observed={'issuer_trust_uid':'issuer-trust-uid','listener_ca_uid':'listener-ca-uid',
              'bundle_uid':'bundle-uid','bundle_owners':[{'kind':'SpireServer','uid':'authority-uid','name':'cluster'}]}
    encode=lambda v:base64.b64encode(v).decode()
    store=pkcs12.serialize_java_truststore([pkcs12.PKCS12Certificate(old,b'old')],serialization.BestAvailableEncryption(b'synthetic-password'))
    def secret(name,uid,data):
        return {'kind':'Secret','metadata':{'name':name,'namespace':trust.NAMESPACE,'uid':uid,'resourceVersion':'4','labels':dict(trust.LABELS)},'type':'Opaque','data':data}
    copies={public.ISSUER_TRUST:secret(public.ISSUER_TRUST,'issuer-trust-uid',{'password':encode(b'synthetic-password'),'truststore.p12':encode(store)}),
            public.CA_SECRET:secret(public.CA_SECRET,'listener-ca-uid',{'ca.crt':encode(old_pem.encode())})}
    bundle={'metadata':{'uid':'bundle-uid','ownerReferences':observed['bundle_owners']},'data':{'bundle.crt':new_pem}}
    calls=[]
    def command(args,*words,**kw):
        calls.append((words,kw))
        if words[:2]==('get','configmap'):return json.dumps(bundle)
        if words[:2]==('get','secret'):
            assert words[2] in copies, 'Serving keys must never be requested'
            return json.dumps(copies[words[2]])
        assert words[:2]==('patch','secret') and words[2] in copies
        assert '--patch-file=/dev/stdin' in words
        changes=kw['value'];before=copies[words[2]]
        assert changes[:3]==trust.patch(before,'data',{})[:3]
        if '--dry-run=server' not in words:before['data']=changes[-1]['value']
        return '{}'
    monkeypatch.setattr(trust,'command',command)
    monkeypatch.setattr(trust,'public_reference',lambda args:({'automatic_public_refresh':True},observed))
    delays=[];monkeypatch.setattr(public.time,'sleep',delays.append)
    return SimpleNamespace(args=Namespace(output_dir=str(tmp_path)),observed=observed,copies=copies,
        bundle=bundle,calls=calls,delays=delays,expected={new.fingerprint(hashes.SHA256())})


def test_rotation_reviews_all_writes_then_changes_only_public_copies(fixture):
    f=fixture
    assert not public.current(f.args,f.observed,f.expected,f.bundle)
    result=public.refresh(f.args)
    assert result['changed_copies']==2 and not result['issuer_rollout_started']
    patches=[c for c in f.calls if c[0][0]=='patch']
    assert ['--dry-run=server' in c[0] for c in patches]==[True,True,False,False]
    assert f.delays==[public.RELOAD_SECONDS]
    assert public.current(f.args,f.observed,f.expected,f.bundle)
    public.refresh(f.args)
    assert f.delays==[public.RELOAD_SECONDS]  # A read-only repeat does not restart/wait/mutate.


@pytest.mark.parametrize('change',['issuer_uid','listener_uid','issuer_key','listener_key','password','source_uid','source_owner'])
def test_substitutions_stop_before_any_write(fixture,change):
    f=fixture
    if change=='issuer_uid':f.copies[public.ISSUER_TRUST]['metadata']['uid']='replacement'
    elif change=='listener_uid':f.copies[public.CA_SECRET]['metadata']['uid']='replacement'
    elif change=='issuer_key':f.copies[public.ISSUER_TRUST]['data']['tls.key']='private'
    elif change=='listener_key':f.copies[public.CA_SECRET]['data']['tls.key']='private'
    elif change=='password':f.copies[public.ISSUER_TRUST]['data']['password']=base64.b64encode(b'wrong').decode()
    elif change=='source_uid':f.bundle['metadata']['uid']='replacement'
    else:f.bundle['metadata']['ownerReferences']=[{'uid':'foreign'}]
    with pytest.raises(ValueError):public.refresh(f.args)
    assert not any(c[0][0]=='patch' for c in f.calls)


def test_scoped_role_excludes_serving_secret_and_shared_mutations():
    p=active_profile();objects=resources(p,'synthetic-public-ca')
    role,=[o for o in objects if o['kind']=='Role']
    assert role['rules']==[{'apiGroups':[''],'resources':['secrets'],
        'resourceNames':[public.ISSUER_TRUST,public.CA_SECRET],'verbs':['get','patch']}]
    assert all(o.get('metadata',{}).get('namespace') in (None,p.core_namespace) for o in objects)
    policy,=[o for o in objects if o['kind']=='ValidatingAdmissionPolicy']
    assert policy['spec']['failurePolicy']=='Fail'
    assert len(policy['spec']['validations'])==2


def test_cluster_refresh_requires_closed_control_lane(tmp_path,monkeypatch):
    monkeypatch.setenv('IDENTITY_DEMO_RUNTIME','cluster')
    monkeypatch.setattr(trust,'current',lambda _:False)
    monkeypatch.setattr(public,'refresh',lambda _:pytest.fail('No mutation without admission fencing'))
    out=tmp_path/'worker';out.mkdir(mode=0o700)
    args=Namespace(output_dir=out,auto_refresh_sender_trust=True)
    assert worker.reconcile_sender_trust(args) is False
    assert worker.reconcile_sender_trust(args,lambda:False) is False


def test_cluster_ambiguous_update_stays_blocked_after_process_replacement(tmp_path,monkeypatch):
    monkeypatch.setenv('IDENTITY_DEMO_RUNTIME','cluster')
    monkeypatch.setattr(trust,'current',lambda _:False)
    count=[]
    def fail(args):count.append(True);raise RuntimeError('withheld')
    monkeypatch.setattr(public,'refresh',fail)
    out=tmp_path/'worker';out.mkdir(mode=0o700)
    args=Namespace(output_dir=out,auto_refresh_sender_trust=True)
    with pytest.raises(worker.SenderTrustMutationUncertain):worker.reconcile_sender_trust(args,lambda:True)
    monkeypatch.setattr(trust,'current',lambda _:True)
    with pytest.raises(worker.SenderTrustMutationUncertain):worker.reconcile_sender_trust(args,lambda:True)
    assert count==[True]


def test_installer_does_not_patch_issuer_again_during_status_churn(tmp_path,monkeypatch):
    import hashlib
    import cluster_console_public_trust as install
    import cluster_console_install as cluster
    import identity_demo_setup as setup
    p=active_profile();bundle={'metadata':{'uid':'source'},'data':{'bundle.crt':'synthetic-public-ca'}}
    spec={'template':{'spec':{'containers':[{'env':[]}]}}}
    install.issuer_reload(spec)
    spec['template']['metadata']={'annotations':{'demo-identity-trust-sha256':hashlib.sha256(b'synthetic-public-ca').hexdigest()}}
    issuer={'metadata':{'uid':'issuer','labels':dict(p.labels)},'spec':spec}
    proposed=install.resources(p,'synthetic-ca');calls=[]
    def kube(args,*words,value=None):
        calls.append(words)
        if words[:2]==('get','deployment'):return deepcopy(issuer)
        if words[:2]==('get','configmap'):return deepcopy(bundle)
        if words[0]=='get':return {}
        assert words[0]=='create'
        result=deepcopy(value);result['metadata']['uid']='new-'+result['kind'];return result
    monkeypatch.setattr(setup,'kube',kube)
    monkeypatch.setattr(cluster,'namespaces',lambda *a:None)
    monkeypatch.setattr(cluster,'patch',lambda *a,**k:pytest.fail('Issuer must not be patched twice'))
    args=Namespace(output_dir=tmp_path)
    made=install.apply(args,p,{'objects':proposed,'issuer':issuer,'bundle':bundle})
    assert len(made)==5 and args.public_trust_ca_uid=='new-Secret'
    assert all(c[0]!='patch' for c in calls)
