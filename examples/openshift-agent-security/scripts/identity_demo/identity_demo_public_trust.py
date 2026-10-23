# SPDX-License-Identifier: Apache-2.0
"""Rotate two public-only trust copies; runtime never reads serving keys.

The installer pins the source/target identities and enables Keycloak's existing
HTTPS truststore reload. Istio loads the separate credential-name-cacert Secret
through SDS. Admission and a closed execution lane precede any update.
"""
import base64
import json
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12

CA_SECRET = 'fixture-mcp-bound-mutual-cacert'
ISSUER_TRUST = 'fixture-keycloak-upstream-client-trust'
RELOAD_SECONDS = 210  # Kubelet projection (up to 2m) + 60s issuer reload + margin.


def copies(args, observed):
    from identity_demo_sender_trust import command, certificates, NAMESPACE, LABELS
    result = {}
    for name, identity, keys in ((ISSUER_TRUST, observed['issuer_trust_uid'], {'password','truststore.p12'}),
                                 (CA_SECRET, observed['listener_ca_uid'], {'ca.crt'})):
        item = json.loads(command(args,'get','secret',name,'-n',NAMESPACE,'-o','json'))
        meta = item['metadata']
        if (meta.get('uid') != identity or meta.get('name') != name or meta.get('namespace') != NAMESPACE
                or meta.get('deletionTimestamp') or item.get('type') != 'Opaque'
                or set(item.get('data',{})) != keys
                or any(meta.get('labels',{}).get(k) != v for k,v in LABELS.items())):
            raise ValueError('Exact public-only trust Secret required')
        result[name] = item
    trust = result[ISSUER_TRUST]['data']
    store = pkcs12.load_pkcs12(base64.b64decode(trust['truststore.p12'],validate=True),
                              base64.b64decode(trust['password'],validate=True))
    if store.key is not None or store.cert is not None or not store.additional_certs:
        raise ValueError('Public CA certificates only in issuer truststore')
    fingerprints = lambda roots: {c.fingerprint(hashes.SHA256()) for c in roots}
    installed = fingerprints([c.certificate for c in store.additional_certs])
    listener = fingerprints(certificates(base64.b64decode(result[CA_SECRET]['data']['ca.crt'],validate=True).decode()))
    return result, installed, listener


def source_matches(observed, bundle):
    meta = bundle['metadata']
    if (meta.get('uid') != observed['bundle_uid']
            or meta.get('ownerReferences') != observed['bundle_owners']
            or meta.get('deletionTimestamp')):
        raise ValueError('Recorded operator bundle identity changed')


def current(args, observed, expected, bundle):
    source_matches(observed,bundle)
    _, issuer, listener = copies(args,observed)
    return expected == issuer == listener


def refresh(args):
    """Caller holds the existing maintenance admission stop and durable checkpoint."""
    from identity_demo_sender_trust import command, certificates, public_reference, patch, SPIRE_NAMESPACE, NAMESPACE
    from identity_demo_keycloak_recovery import write_private
    from pathlib import Path
    _, observed = public_reference(args)
    bundle = json.loads(command(args,'get','configmap','spire-bundle','-n',SPIRE_NAMESPACE,'-o','json'))
    source_matches(observed,bundle)
    pem = bundle['data']['bundle.crt']
    roots = certificates(pem)
    targets, installed, listener = copies(args,observed)
    expected = {c.fingerprint(hashes.SHA256()) for c in roots}
    operations = []
    if installed != expected:
        old = targets[ISSUER_TRUST]
        password = base64.b64decode(old['data']['password'],validate=True)
        encoded = pkcs12.serialize_java_truststore(
            [pkcs12.PKCS12Certificate(c,('spire-'+str(i)).encode()) for i,c in enumerate(roots)],
            serialization.BestAvailableEncryption(password))
        operations.append((old,{**old['data'],'truststore.p12':base64.b64encode(encoded).decode()}))
    if listener != expected:
        operations.append((targets[CA_SECRET],{'ca.crt':base64.b64encode(pem.encode()).decode()}))
    # Review every dependent write before the first one; UID/RV/data CAS rejects drift.
    for old,data in operations:
        write_private(Path(args.output_dir)/(old['metadata']['name']+'.before.private.json'),old)
        command(args,'patch','secret',old['metadata']['name'],'-n',NAMESPACE,'--type=json',
                '--dry-run=server','--patch-file=/dev/stdin',value=patch(old,'data',data))
    for old,data in operations:
        command(args,'patch','secret',old['metadata']['name'],'-n',NAMESPACE,'--type=json',
                '--patch-file=/dev/stdin',value=patch(old,'data',data))
    # No issuer/gateway restart. Keep admission closed through the documented
    # projected-volume/reload interval; the next run still proves real mTLS.
    if operations:
        time.sleep(RELOAD_SECONDS)
    return {'issuer_rollout_started':False,'automatic_public_trust':True,
            'changed_copies':len(operations),'shared_foundation_changed':False}
