# SPDX-License-Identifier: Apache-2.0
"""Standard cert-manager resources and strict public-certificate validation.

This module never signs certificates, stores issuer keys or grants runtime RBAC.
The platform issuer owns issuance; the existing installer owns configuration.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from ipaddress import ip_address
from pathlib import Path
import socket
import ssl
import tempfile
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.x509.verification import (PolicyBuilder, Store, ExtensionPolicy,
                                            Criticality, VerificationError)

from deployment_profile import dns_name

MODE = 'certificate_management'
SPIRE_TRUST = 'fixture-mcp-bound-mutual-cacert'
APPLICATION_TRUST = 'fixture-openshell-client-ca'
SECRETS = ('fixture-openshell-server-tls', 'fixture-openshell-client-tls', 'fixture-mcp-bound-mutual')
DURATION = 720
RENEW_BEFORE = 168


def roots(pem: str) -> list[x509.Certificate]:
    """Require current public CA certificates, including an explicit overlap set."""
    if not isinstance(pem, str) or len(pem) > 1_000_000 or 'PRIVATE KEY' in pem:
        raise ValueError('Bounded public application CA required')
    values = x509.load_pem_x509_certificates(pem.encode())
    now = datetime.now(timezone.utc)
    if not 1 <= len(values) <= 16:
        raise ValueError('Bounded application CA set required')
    for cert in values:
        if (not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
                or not cert.not_valid_before_utc <= now < cert.not_valid_after_utc):
            raise ValueError('Currently valid application CA required')
    if len({c.fingerprint(hashes.SHA256()) for c in values}) != len(values):
        raise ValueError('Duplicate application CA')
    return values


def configuration(config: dict) -> tuple[dict, str | None]:
    """Legacy is explicit/backward compatible; managed inputs pin one issuer UID."""
    value = config.get(MODE, {'mode': 'legacy'})
    if value == {'mode': 'legacy'}:
        return {'mode': 'legacy'}, None
    if (not isinstance(value, dict) or set(value) != {'mode', 'issuer_ref', 'issuer_uid', 'ca_file'}
            or value['mode'] != 'managed'):
        raise ValueError('Exact managed certificate configuration required')
    ref = value['issuer_ref']
    if (not isinstance(ref, dict) or set(ref) != {'name', 'kind', 'group'}
            or ref['kind'] not in ('Issuer', 'ClusterIssuer') or ref['group'] != 'cert-manager.io'):
        raise ValueError('Approved cert-manager issuer reference required')
    dns_name(ref['name'], namespace=True)
    uid = value['issuer_uid']
    if not isinstance(uid, str) or str(UUID(uid)) != uid:
        raise ValueError('Exact approved issuer UID required')
    path = Path(value['ca_file'])
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValueError('Absolute public application CA file required')
    pem = path.read_text()
    roots(pem)
    return {'mode': 'managed', 'issuer_ref': dict(ref), 'issuer_uid': uid,
            'ca_sha256': hashlib.sha256(pem.encode()).hexdigest()}, pem


def validate_contract(contract: dict, ca_pem: str) -> None:
    """Validate the portable public contract without reading an operator path."""
    if (not isinstance(contract, dict) or set(contract) != {'mode', 'issuer_ref', 'issuer_uid', 'ca_sha256'}
            or contract.get('mode') != 'managed'
            or contract['ca_sha256'] != hashlib.sha256(ca_pem.encode()).hexdigest()):
        raise ValueError('Exact managed public certificate contract required')
    ref = contract['issuer_ref']
    if (set(ref) != {'name', 'kind', 'group'} or ref['kind'] not in ('Issuer', 'ClusterIssuer')
            or ref['group'] != 'cert-manager.io' or str(UUID(contract['issuer_uid'])) != contract['issuer_uid']):
        raise ValueError('Pinned cert-manager issuer required')
    dns_name(ref['name'], namespace=True)
    roots(ca_pem)


def targets(profile) -> dict[str, dict]:
    ns = profile.core_namespace
    return {
        SECRETS[0]: {'commonName': 'fixture-openshell', 'dnsNames': [
            'fixture-openshell', 'localhost', 'fixture-openshell.localhost',
            'fixture-openshell.' + ns + '.svc', profile.service_host('fixture-openshell')],
            'ipAddresses': ['127.0.0.1', '::1'], 'usages': ['digital signature', 'server auth']},
        SECRETS[1]: {'commonName': 'openshell-client', 'usages': ['digital signature', 'client auth']},
        SECRETS[2]: {'commonName': 'fixture-mcp-bound.' + ns + '.svc',
            'dnsNames': ['fixture-mcp-bound.' + ns + '.svc', profile.service_host('fixture-mcp-bound')],
            'usages': ['digital signature', 'server auth']}}


def resources(profile, contract: dict) -> list[dict]:
    """Three leaf Certificates; never a self-signed issuer or a new root CA."""
    if contract.get('mode') != 'managed':
        return []
    return [{'apiVersion': 'cert-manager.io/v1', 'kind': 'Certificate',
        'metadata': {'name': name, 'namespace': profile.core_namespace, 'labels': dict(profile.labels)},
        'spec': {'secretName': name, 'secretTemplate': {'labels': dict(profile.labels)},
            'duration': '720h', 'renewBefore': '168h',
            'privateKey': {'algorithm': 'ECDSA', 'size': 256, 'rotationPolicy': 'Always'},
            'issuerRef': dict(contract['issuer_ref']), **identity}}
        for name, identity in targets(profile).items()]


def public_trust(profile, pem):
    roots(pem)
    return {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': APPLICATION_TRUST,
        'namespace': profile.core_namespace, 'labels': dict(profile.labels)}, 'type': 'Opaque',
        'data': {'ca.crt': base64.b64encode(pem.encode()).decode()}}


def openshell_trust(statefulset):
    """Keep client trust independent of cert-manager's single-issuer ca.crt."""
    from copy import deepcopy
    if statefulset.get('kind') != 'StatefulSet' or statefulset['metadata']['name'] != 'fixture-openshell':
        raise ValueError('Exact OpenShell trust consumer required')
    result = deepcopy(statefulset)
    pod = result['spec']['template']['spec']
    volume, = [v for v in pod['volumes'] if v['name'] == 'tls-client-ca']
    entry, = [v for v in pod['containers'][0]['env'] if v['name'] == 'OPENSHELL_PEER_TLS_CA_FILE']
    if (volume.get('secret', {}).get('secretName') != SECRETS[0]
            or entry.get('value') != '/etc/openshell-tls/server/ca.crt'):
        raise ValueError('Unexpected OpenShell client-trust wiring')
    volume['secret']['secretName'] = APPLICATION_TRUST
    entry['value'] = '/etc/openshell-tls/client-ca/ca.crt'
    return result


def issuer(read, profile, contract: dict) -> dict:
    """Observe the approved issuer without adopting, updating or trusting its labels."""
    ref = contract['issuer_ref']
    value = read(ref['kind'].lower() + 's.cert-manager.io', ref['name'],
                 profile.core_namespace if ref['kind'] == 'Issuer' else None)
    meta = value.get('metadata', {})
    ready = [c for c in value.get('status', {}).get('conditions', []) if c.get('type') == 'Ready']
    if (value.get('kind') != ref['kind'] or meta.get('name') != ref['name']
            or meta.get('namespace') != (profile.core_namespace if ref['kind'] == 'Issuer' else None)
            or meta.get('uid') != contract['issuer_uid']
            or meta.get('deletionTimestamp') or len(ready) != 1 or ready[0].get('status') != 'True'
            or ready[0].get('observedGeneration', meta.get('generation')) != meta.get('generation')):
        raise ValueError('Exact ready approved certificate issuer required')
    return value


def validate_certificate(pem: bytes, expected: dict, ca_pem: str,
                         *, minimum_seconds: int = 480, key: bytes | None = None) -> dict:
    """Validate actual identity, chain and lifetime; return public metadata only."""
    if not isinstance(pem, bytes) or len(pem) > 131072 or b'PRIVATE KEY' in pem:
        raise ValueError('Bounded public leaf certificate required')
    chain = x509.load_pem_x509_certificates(pem)
    if not chain or len(chain) > 8:
        raise ValueError('Bounded certificate chain required')
    leaf = chain[0]
    now = datetime.now(timezone.utc)
    # Internal TLS leaves may mark EKU critical (the legacy renderer does).
    # Keep the library's chain/algorithm checks; validate the exact EKU below.
    policy = ExtensionPolicy.webpki_defaults_ee().require_present(
        x509.ExtendedKeyUsage, Criticality.AGNOSTIC, None)
    builder = PolicyBuilder().store(Store(roots(ca_pem))).time(now).max_chain_depth(8)
    try:
        if 'client auth' in expected['usages']:
            # The native peer certificate uses its configured CN without a SAN.
            policy = policy.may_be_present(
                x509.SubjectAlternativeName, Criticality.AGNOSTIC, None)
            verifier = builder.extension_policies(ca_policy=ExtensionPolicy.webpki_defaults_ca(),
                ee_policy=policy).build_client_verifier()
            path = verifier.verify(leaf, chain[1:]).chain
        else:
            verifier = builder.extension_policies(ca_policy=ExtensionPolicy.webpki_defaults_ca(),
                ee_policy=policy).build_server_verifier(x509.DNSName(expected['dnsNames'][0]))
            path = verifier.verify(leaf, chain[1:])
    except VerificationError:
        raise ValueError('Certificate chain does not reach approved application trust') from None
    if (leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
            or any(not c.not_valid_before_utc <= now < c.not_valid_after_utc for c in path)
            or leaf.not_valid_after_utc - now < timedelta(seconds=minimum_seconds)
            or leaf.not_valid_after_utc - leaf.not_valid_before_utc > timedelta(hours=DURATION, minutes=10)
            or any(leaf.not_valid_after_utc > c.not_valid_after_utc for c in path[1:])):
        raise ValueError('Usable bounded leaf and issuer lifetime required')
    common = leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(common) != 1 or common[0].value != expected['commonName']:
        raise ValueError('Exact certificate subject required')
    try:
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns = san.get_values_for_type(x509.DNSName)
        ips = [str(v) for v in san.get_values_for_type(x509.IPAddress)]
        if len(san) != len(dns) + len(ips):
            raise ValueError('Unexpected certificate alternative identity')
    except x509.ExtensionNotFound:
        dns, ips = [], []
    if (sorted(dns) != sorted(expected.get('dnsNames', []))
            or sorted(ips) != sorted(str(ip_address(v)) for v in expected.get('ipAddresses', []))):
        raise ValueError('Exact certificate alternative identities required')
    usages = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    intended = (ExtendedKeyUsageOID.CLIENT_AUTH if 'client auth' in expected['usages']
                else ExtendedKeyUsageOID.SERVER_AUTH)
    if (set(usages) != {intended} or not usage.digital_signature
            or any(getattr(usage, k) for k in ('content_commitment', 'key_encipherment', 'data_encipherment',
                                               'key_agreement', 'key_cert_sign', 'crl_sign'))
            or not isinstance(leaf.public_key(), ec.EllipticCurvePublicKey)
            or not isinstance(leaf.public_key().curve, ec.SECP256R1)):
        raise ValueError('Exact certificate key usage required')
    public = leaf.public_key().public_bytes(serialization.Encoding.DER,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)
    if key is not None:
        private = serialization.load_pem_private_key(key, None)
        if private.public_key().public_bytes(serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo) != public:
            raise ValueError('Certificate and private key mismatch')
    return {'sha256': leaf.fingerprint(hashes.SHA256()).hex(),
            'public_key_sha256': hashlib.sha256(public).hexdigest(),
            'expires': leaf.not_valid_after_utc.isoformat(),
            'remaining_seconds': int((leaf.not_valid_after_utc - now).total_seconds()),
            'renewal_due': leaf.not_valid_after_utc - now <= timedelta(hours=RENEW_BEFORE),
            'ca_expiring': min(c.not_valid_after_utc for c in path[1:]) - now <= timedelta(days=45),
            'ca_expires': min(c.not_valid_after_utc for c in path[1:]).isoformat()}


def public_secret(secret: dict, expected: dict, ca_pem: str, *, check_key: bool = False) -> dict:
    data = secret.get('data', {})
    return validate_certificate(base64.b64decode(data['tls.crt'], validate=True), expected, ca_pem,
        key=base64.b64decode(data['tls.key'], validate=True) if check_key else None)


def served(host: str, port: int, server_name: str, ca_pem: str, expected: dict,
           *, client: tuple[bytes, bytes] | None = None) -> dict:
    """Observe strict TLS; optional native mTLS probe sends only HTTP/2 settings."""
    context = ssl.create_default_context(cadata=ca_pem)
    with tempfile.TemporaryDirectory(prefix='identity-tls-') as directory:
        if client is not None:
            cert, key = (Path(directory)/v for v in ('client.crt', 'client.key'))
            cert.write_bytes(client[0]); key.write_bytes(client[1])
            cert.chmod(0o600); key.chmod(0o600)
            context.load_cert_chain(cert, key)
            context.set_alpn_protocols(['h2'])
        with socket.create_connection((host, port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=server_name) as tls:
                der = tls.getpeercert(binary_form=True)
                if client is not None:
                    # Complete TLS 1.3 client authentication before claiming mTLS.
                    # No RPC, URI, token or application action is submitted.
                    tls.sendall(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + bytes.fromhex('000000040000000000'))
                    header = b''
                    while len(header) < 9:
                        part = tls.recv(9-len(header))
                        if not part: raise ValueError('Native mTLS protocol probe closed')
                        header += part
                    if header[3] != 4 or header[5:] != bytes(4):
                        raise ValueError('Native HTTP/2 settings required after client authentication')
    leaf = x509.load_der_x509_certificate(der)
    result = validate_certificate(leaf.public_bytes(serialization.Encoding.PEM), expected, ca_pem)
    return {**result, 'hostname_verified': True, 'mutual_tls_verified': client is not None}


def runtime_status() -> dict | None:
    """Check public Secret projections without granting workers Secret API access."""
    policy = os.environ.get('IDENTITY_DEMO_CERTIFICATE_POLICY')
    if not policy:
        return None  # Existing installations retain their explicit legacy mode.
    from identity_demo_runtime_cli import private_path
    from identity_demo_cluster_bootstrap import mounted
    from deployment_profile import active_profile
    value = json.loads(private_path(policy).read_text())
    if set(value) != {'contract', 'authority'}:
        raise ValueError('Exact public certificate policy required')
    validate_contract(value['contract'], value['authority'])
    results = {}
    for name, expected in targets(active_profile()).items():
        # Covers the maximum browser session/run bound plus projection lag.
        results[name] = validate_certificate(mounted(Path('/application-certificates'), name + '.crt'),
            expected, value['authority'], minimum_seconds=36_300)
    return results
