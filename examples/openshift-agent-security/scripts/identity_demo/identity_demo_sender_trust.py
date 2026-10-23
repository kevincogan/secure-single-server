#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Refresh the owned pilot's public SPIRE client trust without weakening TLS.

Dry-run by default. The issuer restart preserves its PVC and realm. Run before
live acceptance and after CA rotation; this is manual reconciliation, not a
production trust-distribution controller. Secret snapshots remain outside Git.
"""

from __future__ import annotations

import argparse
import base64
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from identity_demo_keycloak_recovery import command, write_private
from identity_demo_keycloak_upstream import IMAGE, NAME as ISSUER
from identity_demo_lab import LABELS
from identity_demo_runtime import NAMESPACE, guard
from identity_demo_spire_network import NAMESPACE as SPIRE_NAMESPACE, SERVER
from deployment_profile import in_source_checkout


def certificates(pem: str) -> list[x509.Certificate]:
    """Require an explicit public CA bundle from our owned SPIRE server."""
    roots = x509.load_pem_x509_certificates(pem.encode())
    if not roots or len(roots) > 16:
        raise ValueError("Bounded SPIRE trust bundle required")
    for root in roots:
        if not root.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError("A leaf cannot be installed as a trust anchor")
    if len({c.fingerprint(hashes.SHA256()) for c in roots}) != len(roots):
        raise ValueError("Duplicate trust anchors")
    return roots


def patch(current: dict, field: str, desired: Any) -> list[dict]:
    """Reject UID, version or exact field drift before an owned mutation."""
    return [
        {"op": "test", "path": "/metadata/uid", "value": current["metadata"]["uid"]},
        {"op": "test", "path": "/metadata/resourceVersion", "value": current["metadata"]["resourceVersion"]},
        {"op": "test", "path": "/" + field, "value": current[field]},
        {"op": "replace", "path": "/" + field, "value": desired},
    ]


def current(args: argparse.Namespace) -> bool:
    """Compare owned trust copies with the operator-managed public SPIRE bundle.

    Caller first verifies the selected cluster with guard(). This check changes
    no trust and accepts neither a foreign owner nor a leaf as a CA.
    """
    namespace = json.loads(command(args, 'get', 'namespace', SPIRE_NAMESPACE, '-o', 'json'))
    if any(namespace['metadata'].get('labels', {}).get(k) != v for k, v in LABELS.items()):
        raise ValueError('Owned SPIRE namespace required')
    bundle = json.loads(command(args, 'get', 'configmap', 'spire-bundle', '-n', SPIRE_NAMESPACE, '-o', 'json'))
    metadata = bundle['metadata']
    if (metadata.get('namespace') != SPIRE_NAMESPACE
            or metadata.get('labels', {}).get('identity-demo-owner') != LABELS['identity-demo-owner']
            or metadata.get('labels', {}).get('app.kubernetes.io/managed-by') != 'zero-trust-workload-identity-manager'
            or not any(v.get('kind') == 'SpireServer' and v.get('name') == 'cluster' and v.get('uid')
                       for v in metadata.get('ownerReferences', []))):
        raise ValueError('Exact operator-managed public SPIRE bundle required')
    expected = {v.fingerprint(hashes.SHA256()) for v in certificates(bundle['data']['bundle.crt'])}
    if os.environ.get('IDENTITY_DEMO_RUNTIME') == 'cluster':
        return public_observation(args, expected, bundle)
    if not getattr(args, 'public_trust_ca_uid', None) and os.environ.get('IDENTITY_DEMO_SENDER_TRUST_RECEIPT'):
        _, observed = public_reference(args)
        if observed.get('listener_ca_uid'):
            args.public_trust_ca_uid = observed['listener_ca_uid']
    listener_name = 'fixture-mcp-bound-mutual-cacert' if getattr(args,'public_trust_ca_uid',None) else 'fixture-mcp-bound-mutual'
    names = {ISSUER + '-client-trust', listener_name}
    response = json.loads(command(args, 'get', 'secret', *sorted(names), '-n', NAMESPACE, '-o', 'json'))
    items = response.get('items')
    if (response.get('kind') != 'List' or not isinstance(items, list) or len(items) != 2
            or {v['metadata']['name'] for v in items} != names):
        raise ValueError('Both exact owned trust copies required')
    for item in items:
        if (item['metadata'].get('namespace') != NAMESPACE
                or any(item['metadata'].get('labels', {}).get(k) != v for k, v in LABELS.items())):
            raise ValueError('Owned trust Secret required')
    trust = next(v for v in items if v['metadata']['name'] == ISSUER + '-client-trust')
    listener = next(v for v in items if v['metadata']['name'] == listener_name)
    if getattr(args,'public_trust_ca_uid',None) and listener['metadata']['uid'] != args.public_trust_ca_uid:
        raise ValueError('Recorded public CA identity changed')
    store = pkcs12.load_pkcs12(base64.b64decode(trust['data']['truststore.p12']), base64.b64decode(trust['data']['password']))
    installed = {v.certificate.fingerprint(hashes.SHA256()) for v in store.additional_certs}
    mutual = {v.fingerprint(hashes.SHA256()) for v in certificates(base64.b64decode(listener['data']['ca.crt']).decode())}
    return expected == installed == mutual


def refresh(args: argparse.Namespace) -> dict[str, Any]:
    """Reconcile only our two trust Secrets and pinned development issuer."""
    if args.expected_server != SERVER:
        raise ValueError("Agreed lab required")
    guard(args)
    output = Path(args.output_dir)
    if (output.is_symlink() or not output.is_dir() or output.stat().st_mode & 0o077
            or in_source_checkout(output)):
        raise ValueError("Private output directory outside Git required")

    def read(kind: str, name: str, namespace: str = NAMESPACE) -> dict:
        value = json.loads(command(args, "get", kind, name, "-n", namespace, "-o", "json"))
        if (value["metadata"].get("namespace") != namespace
                or any(value["metadata"].get("labels", {}).get(k) != v for k, v in LABELS.items())):
            raise ValueError("Exact owned resource required")
        return value

    ns = json.loads(command(args, "get", "namespace", SPIRE_NAMESPACE, "-o", "json"))
    if any(ns["metadata"].get("labels", {}).get(k) != v for k, v in LABELS.items()):
        raise ValueError("Owned SPIRE namespace required")
    pem = command(args, "exec", "spire-server-0", "-n", SPIRE_NAMESPACE, "-c", "spire-server",
                  "--", "/spire-server", "bundle", "show", "-format", "pem")
    roots = certificates(pem)
    bundle_hash = hashlib.sha256(pem.encode()).hexdigest()
    trust = read("secret", ISSUER + "-client-trust")
    listener = read("secret", "fixture-mcp-bound-mutual")
    deployment = read("deployment", ISSUER)
    pod = deployment["spec"]["template"]["spec"]
    if (pod["containers"][0]["image"] != IMAGE
            or deployment["spec"]["replicas"] != 1
            or deployment["spec"]["strategy"]["type"] != "Recreate"
            or not any(v.get("persistentVolumeClaim", {}).get("claimName") == ISSUER + "-data"
                       for v in pod["volumes"])):
        raise ValueError("Pinned single-replica development issuer with preserved PVC required")
    password = base64.b64decode(trust["data"]["password"])
    previous = pkcs12.load_pkcs12(base64.b64decode(trust["data"]["truststore.p12"]), password)
    desired_fingerprints = {c.fingerprint(hashes.SHA256()) for c in roots}
    previous_fingerprints = {c.certificate.fingerprint(hashes.SHA256())
                             for c in previous.additional_certs}
    encoded = pkcs12.serialize_java_truststore(
        [pkcs12.PKCS12Certificate(c, ("spire-" + str(i)).encode()) for i, c in enumerate(roots)],
        serialization.BestAvailableEncryption(password),
    )
    trust_data = dict(trust["data"], **{"truststore.p12": base64.b64encode(encoded).decode()})
    listener_data = dict(listener["data"], **{"ca.crt": base64.b64encode(pem.encode()).decode()})
    spec = deepcopy(deployment["spec"])
    spec["template"].setdefault("metadata", {}).setdefault("annotations", {})[
        "demo-identity-trust-sha256"] = bundle_hash
    if getattr(args,'enable_public_trust_refresh',False):
        from cluster_console_public_trust import issuer_reload
        issuer_reload(spec)
    operations = ([
        ("secret", trust, "data", trust_data),
    ] if previous_fingerprints != desired_fingerprints else []) + [
        ("deployment", deployment, "spec", spec)]
    if not getattr(args, 'public_trust_ca_uid', None):
        operations.append(("secret", listener, "data", listener_data))
    operations = [v for v in operations if v[1][v[2]] != v[3]]
    if getattr(args,'public_trust_ca_uid',None):
        ca_copy=read('secret','fixture-mcp-bound-mutual-cacert')
        if ca_copy['metadata']['uid']!=args.public_trust_ca_uid or set(ca_copy.get('data',{}))!={'ca.crt'}:
            raise ValueError('Exact recorded public CA copy required')
        ca_data={'ca.crt':base64.b64encode(pem.encode()).decode()}
        if ca_copy['data']!=ca_data:
            operations.append(('secret',ca_copy,'data',ca_data))
    # Dry-run the entire dependent change before applying any part.
    for kind, current, field, desired in operations:
        write_private(output / (current["metadata"]["name"] + ".before.private.json"), current)
        command(args, "patch", kind, current["metadata"]["name"], "-n", NAMESPACE,
                "--type=json", "--dry-run=server", "-p", json.dumps(patch(current, field, desired)))
    if args.apply:
        for kind, current, field, desired in operations:
            command(args, "patch", kind, current["metadata"]["name"], "-n", NAMESPACE,
                    "--type=json", "-p", json.dumps(patch(current, field, desired)))
    summary = {"applied": args.apply, "bundle_sha256": bundle_hash,
               "root_sha256": [c.fingerprint(hashes.SHA256()).hex() for c in roots],
               "issuer_rollout_started": args.apply and spec != deployment["spec"],
               "tls_verification_preserved": True,
               "manual_trust_reconciliation": True, "live_acceptance_required": True}
    write_private(output / "sender-trust.summary.json", summary)
    return summary


def main() -> None:
    """Refresh only explicitly selected, owned development resources."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--expected-server", required=True)
    parser.add_argument("--credentials-file", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--namespace", default=NAMESPACE)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        print(json.dumps(refresh(args)))
    except Exception as error:
        print(json.dumps({"passed": False, "failure_kind": type(error).__name__,
                          "details_withheld": True}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()


def public_reference(args):
    """Check immutable public installer evidence, never read serving-key Secrets.

    This detects approved-root changes and issuer reference drift. A protected
    native exchange/read still proves the current live cryptographic path;
    this observation alone does not inspect the live Secret contents.
    """
    from identity_demo_runtime_cli import private_path
    reference = json.loads(private_path(os.environ['IDENTITY_DEMO_SENDER_TRUST_RECEIPT']).read_text())
    live = json.loads(command(args, 'get', 'configmap', 'fixture-console-sender-trust', '-n', NAMESPACE, '-o', 'json'))
    if (live['metadata'].get('namespace') != NAMESPACE or live.get('immutable') is not True
            or live['metadata']['uid'] != reference['uid']
            or any(live['metadata'].get('labels', {}).get(k) != v for k,v in LABELS.items())
            or set(live.get('data', {})) != {'observation.json'}
            or hashlib.sha256(live['data']['observation.json'].encode()).hexdigest() != reference['observation_sha256']):
        raise ValueError('Exact immutable public trust observation required')
    observed = json.loads(live['data']['observation.json'])
    from deployment_profile import active_profile
    if observed.get('profile') != active_profile().to_dict() or len(observed.get('issuer_trust_volumes', [])) != 1:
        raise ValueError('Exact installation trust observation required')
    return reference, observed


def public_observation(args, expected, bundle=None):
    reference, observed = public_reference(args)
    deployment = json.loads(command(args, 'get', 'deployment', ISSUER, '-n', NAMESPACE, '-o', 'json'))
    if (deployment['metadata']['uid'] != observed['issuer_uid']
            or any(deployment['metadata'].get('labels', {}).get(k) != v for k,v in LABELS.items())):
        raise ValueError('Exact observed owned issuer required')
    pod = deployment['spec']['template']
    if (pod.get('metadata', {}).get('annotations', {}).get('demo-identity-trust-sha256') != observed['issuer_annotation']
            or [v for v in pod['spec']['volumes'] if v.get('secret', {}).get('secretName') == ISSUER+'-client-trust'] != observed['issuer_trust_volumes']):
        raise ValueError('Issuer trust reference changed; guarded operator maintenance required')
    if observed.get('automatic_public_refresh') is True:
        if reference.get('automatic_public_refresh') is not True or bundle is None:
            raise ValueError('Explicit automatic public trust policy required')
        env = deployment['spec']['template']['spec']['containers'][0].get('env',[])
        if [v for v in env if v['name']=='KC_HTTPS_CERTIFICATES_RELOAD_PERIOD'] != [
                {'name':'KC_HTTPS_CERTIFICATES_RELOAD_PERIOD','value':'60s'}]:
            raise ValueError('Reviewed issuer trust reload configuration required')
        from identity_demo_public_trust import current
        return current(args,observed,expected,bundle)
    return (sorted(v.hex() for v in expected) == observed['spire_fingerprints']
            == observed['issuer_fingerprints'] == observed['listener_fingerprints'])
