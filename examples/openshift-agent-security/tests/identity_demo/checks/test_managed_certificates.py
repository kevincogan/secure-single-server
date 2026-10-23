# SPDX-License-Identifier: Apache-2.0
"""Managed PKI contracts reject substitution and never generate runtime issuer keys."""
from argparse import Namespace
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import base64
import json
from pathlib import Path
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
import pytest

from deployment_profile import LEGACY
import managed_certificates as managed
import source_render as renderer
import certificate_operations as operations


def pki():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Synthetic application authority')])
    now = datetime.now(timezone.utc)
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .sign(key, hashes.SHA256()))
    return key, ca


def leaf(key, ca, expected, *, days=30, age=0, usages=None):
    private = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    names = [x509.DNSName(n) for n in expected.get('dnsNames', [])]
    names += [x509.IPAddress(managed.ip_address(n)) for n in expected.get('ipAddresses', [])]
    eku = ExtendedKeyUsageOID.CLIENT_AUTH if 'client auth' in expected['usages'] else ExtendedKeyUsageOID.SERVER_AUTH
    builder = (x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, expected['commonName'])]))
        .issuer_name(ca.subject).public_key(private.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=age, minutes=5))
        .not_valid_after(now + timedelta(days=days-age))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, None, None), True)
        .add_extension(x509.ExtendedKeyUsage(usages or [eku]), True)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key()), False))
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), False)
    certificate = builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
    return certificate, private.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


@pytest.fixture
def inputs(tmp_path):
    key, ca = pki()
    pem = ca.public_bytes(serialization.Encoding.PEM).decode()
    path = tmp_path/'ca.pem'
    path.write_text(pem)
    config = {'certificate_management': {'mode': 'managed', 'ca_file': str(path),
        'issuer_ref': {'name': 'application-pki', 'kind': 'Issuer', 'group': 'cert-manager.io'},
        'issuer_uid': str(uuid4())}}
    return config, key, ca, pem


def test_controller_resources_preserve_identity_and_explicit_key_rotation(inputs):
    config, _, _, _ = inputs
    contract, _ = managed.configuration(config)
    values = managed.resources(LEGACY, contract)
    assert len(values) == 3
    assert {v['spec']['secretName'] for v in values} == set(managed.SECRETS)
    for obj in values:
        assert obj['kind'] == 'Certificate' and obj['metadata']['namespace'] == LEGACY.core_namespace
        assert obj['spec']['duration'] == '720h' and obj['spec']['renewBefore'] == '168h'
        assert obj['spec']['privateKey']['rotationPolicy'] == 'Always'
        assert obj['spec']['secretTemplate']['labels'] == LEGACY.labels
    assert '127.0.0.1' in values[0]['spec']['ipAddresses']
    assert 'client auth' in values[1]['spec']['usages']


@pytest.mark.parametrize('change', ['issuer_uid', 'group', 'kind', 'extra', 'private_ca'])
def test_invalid_or_unbound_issuer_configuration_is_rejected(inputs, change):
    config, key, _, _ = inputs
    c = deepcopy(config)
    if change == 'issuer_uid': c['certificate_management']['issuer_uid'] = None
    if change == 'group': c['certificate_management']['issuer_ref']['group'] = 'unreviewed.example'
    if change == 'kind': c['certificate_management']['issuer_ref']['kind'] = 'Secret'
    if change == 'extra': c['certificate_management']['disable_verification'] = True
    if change == 'private_ca':
        Path(c['certificate_management']['ca_file']).write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with pytest.raises((ValueError, TypeError)):
        managed.configuration(c)


@pytest.mark.parametrize('name', managed.SECRETS)
def test_real_crypto_checks_accept_only_the_intended_leaf(inputs, name):
    _, key, ca, pem = inputs
    expected = managed.targets(LEGACY)[name]
    certificate, private = leaf(key, ca, expected)
    result = managed.validate_certificate(certificate, expected, pem, key=private)
    assert result['remaining_seconds'] > 29*86400
    assert not result['renewal_due']
    renewed, replacement = leaf(key, ca, expected)
    other = managed.validate_certificate(renewed, expected, pem, key=replacement)
    assert result['sha256'] != other['sha256']
    assert result['public_key_sha256'] != other['public_key_sha256']
    assert 'PRIVATE' not in json.dumps(result)


@pytest.mark.parametrize('attack', ['wrong_key', 'wrong_issuer', 'extra_name', 'wrong_usage', 'expired', 'too_long'])
def test_certificate_substitution_and_expiry_are_rejected(inputs, attack):
    _, key, ca, pem = inputs
    expected = managed.targets(LEGACY)[managed.SECRETS[0]]
    identity = deepcopy(expected)
    if attack == 'extra_name': identity['dnsNames'].append('other.example.test')
    signing, authority = pki() if attack == 'wrong_issuer' else (key, ca)
    certificate, private = leaf(signing, authority, identity,
        age=31 if attack == 'expired' else 0,
        days=90 if attack == 'too_long' else 30,
        usages=[ExtendedKeyUsageOID.CLIENT_AUTH] if attack == 'wrong_usage' else None)
    if attack == 'wrong_key': _, private = leaf(key, ca, expected)
    with pytest.raises((ValueError, x509.ExtensionNotFound)):
        managed.validate_certificate(certificate, expected, pem, key=private)


def test_sufficient_unexpired_certificate_is_not_blocked_by_renewal_window(inputs):
    _, key, ca, pem = inputs
    expected = managed.targets(LEGACY)[managed.SECRETS[0]]
    certificate, private = leaf(key, ca, expected, age=25)
    assert managed.validate_certificate(certificate, expected, pem, key=private)['renewal_due']
    with pytest.raises(ValueError):
        managed.validate_certificate(certificate, expected, pem, minimum_seconds=6*86400)


def test_issuer_uid_and_readiness_are_verified_without_mutation(inputs):
    config, _, _, _ = inputs
    contract, _ = managed.configuration(config)
    value = {'kind': 'Issuer', 'metadata': {'uid': contract['issuer_uid'], 'generation': 2,
             'name': 'application-pki', 'namespace': LEGACY.core_namespace},
             'status': {'conditions': [{'type': 'Ready', 'status': 'True', 'observedGeneration': 2}]}}
    seen = []
    def read(*args): seen.append(args); return value
    assert managed.issuer(read, LEGACY, contract) == value
    assert seen == [('issuers.cert-manager.io', 'application-pki', LEGACY.core_namespace)]
    value['metadata']['uid'] = str(uuid4())
    with pytest.raises(ValueError): managed.issuer(read, LEGACY, contract)


def test_managed_state_has_no_application_signing_or_leaf_keys(inputs, monkeypatch):
    config, _, _, pem = inputs
    contract, _ = managed.configuration(config)
    monkeypatch.setattr(renderer, '_ca', lambda: pytest.fail('Managed mode generated an issuer'))
    monkeypatch.setattr(renderer, '_leaf', lambda *a, **k: pytest.fail('Managed mode signed a leaf'))
    trust = {name: pem for name in ('service_ca', 'spire_ca', 'upstream_ca_bundle')}
    state = renderer.initial_state(LEGACY, trust, contract, pem)
    renderer.validate_state(state, LEGACY, trust, contract, pem)
    assert 'application_ca_key' not in state
    assert not any(k.split('/')[0] in managed.SECRETS for k in state['secret_data'])
    with pytest.raises(ValueError, match='migration'):
        renderer.validate_state(state, LEGACY, trust)

def test_public_projections_cannot_mount_serving_keys(inputs):
    config,_,_,pem=inputs
    contract,_=managed.configuration(config)
    deployments=[{'spec':{'template':{'spec':{'volumes':[], 'containers':[{'volumeMounts':[]}]}}}} for _ in range(2)]
    policies=[{'data':{'operator':'retained'}},{'data':{'preparer':'retained'}}]
    operations.projections(deployments,policies,contract,pem)
    for value in deployments:
        volume=value['spec']['template']['spec']['volumes'][0]
        assert {s['secret']['name'] for s in volume['projected']['sources']} == set(managed.SECRETS)
        assert all(item['key']=='tls.crt' for s in volume['projected']['sources'] for item in s['secret']['items'])
    assert policies[0]['data']['operator']=='retained' and policies[1]['data']['preparer']=='retained'
    assert 'PRIVATE KEY' not in json.dumps(policies)
    with pytest.raises(ValueError):operations.projections(deployments,policies,contract,pem)


def test_overlap_accepts_both_authorities_then_rejects_retired_root(inputs):
    _,old_key,old_ca,old_pem=inputs
    new_key,new_ca=pki();new_pem=new_ca.public_bytes(serialization.Encoding.PEM).decode()
    identity=managed.targets(LEGACY)[managed.SECRETS[0]]
    old,_=leaf(old_key,old_ca,identity);new,_=leaf(new_key,new_ca,identity)
    for cert in (old,new):managed.validate_certificate(cert,identity,old_pem+new_pem)
    managed.validate_certificate(new,identity,new_pem)
    with pytest.raises(ValueError):managed.validate_certificate(old,identity,new_pem)


@pytest.mark.parametrize('attack',['issuer','identity','not_ready','secret_annotation','ca_as_leaf'])
def test_ready_secret_is_not_proof_of_valid_managed_issuance(inputs,monkeypatch,attack):
    config,key,ca,pem=inputs
    contract,_=managed.configuration(config)
    args=Namespace(profile=LEGACY,certificate_management=contract,certificate_authority_pem=pem)
    objects={}
    for desired in managed.resources(LEGACY,contract):
        name=desired['metadata']['name'];cert=deepcopy(desired)
        cert['metadata'].update(uid='certificate-uid',generation=1)
        cert['status']={'revision':1,'conditions':[{'type':'Ready','status':'True','observedGeneration':1}]}
        identity=deepcopy(managed.targets(LEGACY)[name])
        if attack=='identity':identity['commonName']='substitution'
        signing,issuer = pki() if attack=='issuer' else (key,ca)
        encoded,private=leaf(signing,issuer,identity)
        if attack=='ca_as_leaf':encoded=ca.public_bytes(serialization.Encoding.PEM)
        secret={'type':'kubernetes.io/tls','metadata':{'name':name,'uid':'secret-uid',
            'labels':LEGACY.labels,'annotations':{'cert-manager.io/certificate-name':name,
                'cert-manager.io/issuer-name':contract['issuer_ref']['name']}},
            'data':{'tls.crt':base64.b64encode(encoded).decode(),'tls.key':base64.b64encode(private).decode()}}
        if attack=='secret_annotation':secret['metadata']['annotations']['cert-manager.io/certificate-name']='other'
        if attack=='not_ready':cert['status']['conditions'][0]['status']='False'
        objects['certificates.cert-manager.io',name]=cert;objects['secret',name]=secret
    monkeypatch.setattr(operations,'preflight',lambda *a,**k: {})
    monkeypatch.setattr(operations,'read',lambda a,k,n,ns=None:objects[k,n])
    observed=operations.observe(args)
    assert not observed['ready'] and not observed['consumer_loading_proven']
    assert all(v['loaded']=='not_observed' for v in observed['certificates'])


def test_expiring_public_projection_stops_admission_without_mutation(monkeypatch):
    import identity_demo_console_worker as worker
    class Control:
        readiness={'phase':'ready'}
        def state(self,*values):self.result=values
        def publish(self):self.published=True
    control=Control()
    def failure():raise ValueError('expired synthetic leaf')
    monkeypatch.setattr(managed,'runtime_status',failure)
    monkeypatch.setattr(worker,'guard',lambda a:pytest.fail('Admission continued past invalid certificate'))
    assert worker.readiness_check(Namespace(),control) is False
    assert control.result==('blocked','invalid_configuration') and control.published


def test_active_or_uncertain_migration_stops_before_issuance(monkeypatch):
    import cluster_console_install as install
    import cluster_console_operator as operator
    import identity_demo_execution_setup as execution
    monkeypatch.setattr(install, 'namespaces', lambda *a: None)
    monkeypatch.setattr(operator, 'private_request', lambda *a: {'online': True})
    monkeypatch.setattr(execution, 'inspect_state', lambda *a: {'rollback_quiescent': False})
    monkeypatch.setattr(operations.setup, 'kube', lambda *a, **k: pytest.fail('Mutation before idle fencing'))
    with pytest.raises(ValueError, match='Fenced'):
        operations.apply(Namespace(), LEGACY, {})


def test_independent_client_trust_requires_exact_original_wiring():
    # Exercise the actual source template, not a permissive invented workload.
    values=json.loads((Path(__file__).resolve().parents[3]/'infra/identity-demo/templates/application.json').read_text())
    values=values['objects'] if isinstance(values,dict) else values
    gateway=next(v for v in values if v.get('kind')=='StatefulSet' and v['metadata']['name']=='fixture-openshell')
    before=deepcopy(gateway);after=managed.openshell_trust(gateway)
    assert gateway==before
    pod=after['spec']['template']['spec']
    volume=next(v for v in pod['volumes'] if v['name']=='tls-client-ca')
    assert volume['secret']['secretName']==managed.APPLICATION_TRUST
    with pytest.raises(ValueError, match='Unexpected'):
        managed.openshell_trust(after)


def test_migration_uses_hash_pinned_observation_not_summary_uid(inputs, monkeypatch, tmp_path):
    import hashlib
    import cluster_console_install as install
    import cluster_console_operator as operator
    config,key,ca,pem=inputs;contract,_=managed.configuration(config)
    args=Namespace(certificate_management=contract,certificate_authority_pem=pem,ledger='private',
                   console_ledger_sha256='pinned',output_dir=tmp_path)
    observation_data=json.dumps({'profile':LEGACY.to_dict(),'listener_ca_uid':'public-trust-uid'})
    observation={'kind':'ConfigMap','metadata':{'name':'fixture-console-sender-trust',
        'namespace':LEGACY.core_namespace,'uid':'observation-uid','labels':LEGACY.labels},
        'immutable':True,'data':{'observation.json':observation_data}}
    reference={'uid':'observation-uid','observation_sha256':hashlib.sha256(observation_data.encode()).hexdigest(),
               'automatic_public_refresh':True}
    worker={'data':{'management-ca.crt':base64.b64encode(pem.encode()).decode(),
        'sender-trust.receipt.json':base64.b64encode(json.dumps(reference).encode()).decode()}}
    values={('configmap','fixture-console-sender-trust'):observation}
    trust=managed.public_trust(LEGACY,pem);trust['metadata'].update(name=managed.SPIRE_TRUST,uid='public-trust-uid')
    values['secret',managed.SPIRE_TRUST]=trust
    ledger={'completed':True,'installation_profile':LEGACY.to_dict(),'created':[]}
    for name,identity in managed.targets(LEGACY).items():
        cert,private=leaf(key,ca,identity)
        value={'kind':'Secret','metadata':{'name':name,'namespace':LEGACY.core_namespace,
            'labels':LEGACY.labels,'uid':name},'data':{'tls.crt':base64.b64encode(cert).decode(),
            'tls.key':base64.b64encode(private).decode()}}
        values['secret',name]=value
        ledger['created'].append({'kind':'Secret','namespace':LEGACY.core_namespace,'metadata':value['metadata']})
    template=json.loads((Path(__file__).resolve().parents[3]/'infra/identity-demo/templates/application.json').read_text())
    template=template['objects'] if isinstance(template,dict) else template
    gateway=deepcopy(next(v for v in template if v.get('kind')=='StatefulSet'))
    gateway['metadata'].update(labels=LEGACY.labels,uid='gateway-uid');gateway['spec']['replicas']=1
    values['statefulset','fixture-openshell']=gateway
    ledger['created'].append({'kind':'StatefulSet','namespace':LEGACY.core_namespace,'metadata':gateway['metadata']})
    monkeypatch.setattr(operator,'receipt',lambda *a:ledger)
    monkeypatch.setattr(operations,'configure',lambda *a:{'issuer_ready':True})
    monkeypatch.setattr(operations,'read',lambda a,k,n,ns=None:values.get((k,n),{}))
    monkeypatch.setattr(install,'patch',lambda *a,**k: {'dry':k['dry']})
    calls=[]
    def dry(*a,**k):
        if k.get('value',{}).get('kind')=='SelfSubjectAccessReview':
            assert k['value']['spec']['resourceAttributes']['name'] in managed.SECRETS
            return {'status':{'allowed':True}}
        assert '--dry-run=server' in a
        calls.append(a);return {}
    monkeypatch.setattr(operations.setup,'kube',dry)
    planned=operations.prepare(args,LEGACY,worker)
    assert planned['spire_trust_uid']=='public-trust-uid'
    assert planned['observation_uid']=='observation-uid' and len(calls)==4
    reference['observation_sha256']='0'*64
    worker['data']['sender-trust.receipt.json']=base64.b64encode(json.dumps(reference).encode()).decode()
    with pytest.raises(ValueError,match='Exact current worker'):
        operations.prepare(args,LEGACY,worker)


def test_explicit_migration_renewal_is_cas_scoped_and_never_replayed(inputs,monkeypatch,tmp_path):
    config,_,_,_=inputs;contract,_=managed.configuration(config)
    value=managed.resources(LEGACY,contract)[0]
    value['metadata'].update(uid='exact-certificate',resourceVersion='17',generation=1)
    value['status']={'conditions':[{'type':'Ready','status':'True'}]}
    monkeypatch.setattr(operations,'read',lambda *a:value)
    calls=[]
    def patch(*a,**k):
        calls.append((a,k));return value
    monkeypatch.setattr(operations.setup,'kube',patch)
    args=Namespace(profile=LEGACY,output_dir=tmp_path)
    operations.request_renewal(args,value,0)
    assert len(calls)==2 and '--subresource=status' in calls[0][0]
    body=calls[-1][1]['value']
    assert body[:2]==[{'op':'test','path':'/metadata/uid','value':'exact-certificate'},
                     {'op':'test','path':'/metadata/resourceVersion','value':'17'}]
    conditions=body[-1]['value']['conditions']
    assert conditions[0]['type']=='Ready' and conditions[-1]['reason']=='ManuallyTriggered'
    with pytest.raises(FileExistsError):operations.request_renewal(args,value,0)
    assert len(calls)==3  # A second dry run is harmless; the mutation is not repeated.
    replaced=deepcopy(value);replaced['metadata']['uid']='replacement'
    monkeypatch.setattr(operations,'read',lambda *a:replaced)
    with pytest.raises(ValueError,match='Exact newly created'):operations.request_renewal(args,value,1)


def test_migration_permission_failure_occurs_before_drain(monkeypatch):
    monkeypatch.setattr(operations.setup,'kube',lambda *a,**k:{'status':{'allowed':False}})
    with pytest.raises(ValueError,match='no automatic escalation'):
        operations.renewal_permissions(Namespace(),LEGACY)



@pytest.mark.parametrize('trusted_client',[True,False])
def test_live_mtls_probe_requires_completed_client_authentication(inputs,tmp_path,trusted_client):
    import ssl,socket,threading
    _,key,ca,pem=inputs
    expected=managed.targets(LEGACY)[managed.SECRETS[0]]
    server,server_key=leaf(key,ca,expected)
    pair=pki() if not trusted_client else (key,ca)
    client,client_key=leaf(*pair,managed.targets(LEGACY)[managed.SECRETS[1]])
    certfile=tmp_path/'server.crt';keyfile=tmp_path/'server.key'
    certfile.write_bytes(server);keyfile.write_bytes(server_key)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(certfile,keyfile)
    context.load_verify_locations(cadata=pem);context.verify_mode=ssl.CERT_REQUIRED
    context.set_alpn_protocols(['h2'])
    listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(8)
    observed=[]
    def serve():
        try:
            with listener.accept()[0] as raw:
                with context.wrap_socket(raw,server_side=True) as tls:
                    observed.append(tls.getpeercert(binary_form=True))
                    data=b''
                    while len(data)<33:data+=tls.recv(33-len(data))
                    assert data==b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'+bytes.fromhex('000000040000000000')
                    tls.sendall(bytes.fromhex('000000040000000000'))
        except ssl.SSLError:observed.append('untrusted_client_denied')
        finally:listener.close()
    thread=threading.Thread(target=serve,daemon=True);thread.start()
    if trusted_client:
        result=managed.served('127.0.0.1',listener.getsockname()[1],expected['dnsNames'][0],pem,expected,client=(client,client_key))
        assert result['mutual_tls_verified'] and result['hostname_verified']
    else:
        with pytest.raises(ssl.SSLError):
            managed.served('127.0.0.1',listener.getsockname()[1],expected['dnsNames'][0],pem,expected,client=(client,client_key))
    thread.join(10);assert not thread.is_alive()
    assert bool(observed)
