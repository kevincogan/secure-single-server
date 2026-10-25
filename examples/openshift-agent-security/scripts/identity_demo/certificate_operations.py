# SPDX-License-Identifier: Apache-2.0
"""Managed leaf integration in the existing installer and idle maintenance flow.

Only the installer reads serving Secrets. Workers receive public projections,
not API permission to read signing keys or mutate workloads.
"""
from copy import deepcopy
from datetime import datetime, timezone
import base64
import hashlib
import json
import re
import subprocess
import time

import identity_demo_setup as setup
import managed_certificates as managed


def read(args, kind, name, namespace=None):
    return setup.kube(args, 'get', kind, name, *(['-n', namespace] if namespace else []),
                      '--ignore-not-found', '-o', 'json')


def preflight(args, *, fresh=False):
    contract, profile = args.certificate_management, args.profile
    managed.validate_contract(contract, args.certificate_authority_pem)
    definition = read(args, 'crd', 'certificates.cert-manager.io')
    if (definition.get('metadata', {}).get('deletionTimestamp')
            or not any(c.get('type') == 'Established' and c.get('status') == 'True'
                       for c in definition.get('status', {}).get('conditions', []))
            or not any(v.get('served') and v['name'] == 'v1'
                       for v in definition.get('spec', {}).get('versions', []))):
        raise ValueError('Platform-approved cert-manager v1 API required')
    authority = managed.issuer(lambda *v: read(args, *v), profile, contract)
    if fresh:
        for name in managed.SECRETS:
            if read(args, 'secret', name, profile.core_namespace):
                raise ValueError('Managed target Secret collision; explicit migration required')
    return {'issuer_uid': authority['metadata']['uid'], 'issuer_ready': True,
            'issuer_fingerprint': setup.fingerprint(authority)}


def observe(args):
    """Read-only public report; Ready never implies a consumer loaded the Secret."""
    preflight(args)
    profile = args.profile
    results = []
    for desired in managed.resources(profile, args.certificate_management):
        name = desired['metadata']['name']
        live = read(args, 'certificates.cert-manager.io', name, profile.core_namespace)
        status = {'name': name, 'ready': False, 'loaded': 'not_observed'}
        try:
            setup.owned(live, profile)
            if (live['metadata'].get('deletionTimestamp') or not matches(live, desired)
                    or not setup.reconciled(live)):
                raise ValueError('Current exact Certificate must be ready')
            secret = read(args, 'secret', name, profile.core_namespace)
            setup.owned(secret, profile)
            annotations = secret['metadata'].get('annotations', {})
            if (secret.get('type') != 'kubernetes.io/tls' or secret['metadata'].get('deletionTimestamp')
                    or annotations.get('cert-manager.io/certificate-name') != name
                    or annotations.get('cert-manager.io/issuer-name') != args.certificate_management['issuer_ref']['name']):
                raise ValueError('Exact cert-manager target required')
            result = managed.public_secret(secret, managed.targets(profile)[name], args.certificate_authority_pem,
                                           check_key=True)
            status.update(result, ready=True, certificate_uid=live['metadata']['uid'],
                          revision=live['status'].get('revision'), secret_uid=secret['metadata']['uid'],
                          renewing=any(c.get('type') == 'Issuing' and c.get('status') == 'True'
                                       for c in live['status'].get('conditions', [])),
                          renewal_time=live['status'].get('renewalTime'))
        except (ValueError, KeyError):
            status['failure'] = 'issuance_or_identity_verification'
        results.append(status)
    return {'ready': all(v['ready'] for v in results), 'certificates': results,
            'cluster_changed': False, 'consumer_loading_proven': False,
            'ca_rollover_automatic': False}


def recorded_secret(args, profile, ledger, secret):
    """Trace a controller-issued leaf through the original Certificate identity.

    Fresh managed installs record the Certificate, not its controller-created
    Secret. Renewed leaf bytes must still satisfy the approved issuer contract.
    """
    name = secret['metadata']['name']
    contract, pem = args.certificate_management, args.certificate_authority_pem
    managed.validate_contract(contract, pem)
    if (contract.get('mode') != 'managed' or name not in managed.SECRETS
            or not ledger.get('completed') or ledger.get('installation_profile') != profile.to_dict()):
        raise ValueError('Recorded managed certificate contract required')
    managed.issuer(lambda *words: read(args, *words), profile, contract)
    certificate = read(args, 'certificates.cert-manager.io', name, profile.core_namespace)
    setup.owned(certificate, profile)
    records = [v for v in ledger['created'] if v['kind'] == 'Certificate'
        and v.get('namespace') == profile.core_namespace and v['metadata']['name'] == name]
    desired = next(v for v in managed.resources(profile, contract) if v['metadata']['name'] == name)
    annotations = secret['metadata'].get('annotations', {})
    if (len(records) != 1 or certificate['metadata']['uid'] != records[0]['metadata']['uid']
            or certificate['metadata'].get('deletionTimestamp') or not matches(certificate, desired)
            or not setup.reconciled(certificate) or secret['metadata'].get('deletionTimestamp')
            or secret['metadata'].get('namespace') != profile.core_namespace
            or secret.get('type') != 'kubernetes.io/tls'
            or annotations.get('cert-manager.io/certificate-name') != name
            or annotations.get('cert-manager.io/issuer-name') != contract['issuer_ref']['name']
            or any(owner.get('kind') != 'Certificate' or owner.get('uid') != certificate['metadata']['uid']
                   for owner in secret['metadata'].get('ownerReferences', []))):
        raise ValueError('Original managed Certificate and issued Secret required')
    setup.owned(secret, profile)
    return managed.public_secret(secret, managed.targets(profile)[name], pem, check_key=True)


def matches(live, desired):
    """Permit only cert-manager's documented revision-history default."""
    spec = deepcopy(live.get('spec', {}))
    if 'revisionHistoryLimit' not in desired['spec'] and spec.get('revisionHistoryLimit') == 1:
        spec.pop('revisionHistoryLimit')
    return spec == desired['spec']


def renewal_permissions(args, profile):
    """Check installer-only access before fencing an existing installation."""
    for name in managed.SECRETS:
        for verb in ('get', 'patch'):
            review = {'apiVersion': 'authorization.k8s.io/v1', 'kind': 'SelfSubjectAccessReview',
                'spec': {'resourceAttributes': {'group': 'cert-manager.io', 'resource': 'certificates',
                    'subresource': 'status', 'namespace': profile.core_namespace, 'name': name, 'verb': verb}}}
            result = setup.kube(args, 'create', '-f', '-', '-o', 'json', value=review)
            if result.get('status', {}).get('allowed') is not True:
                raise ValueError('Migration installer needs named get/patch certificates/status access; no automatic escalation')


def request_renewal(args, certificate, index):
    """Use cert-manager's public Issuing condition, as cmctl renew does.

    UID/version tests and exclusive receipts prevent adopting or replaying an
    uncertain renewal. The controller alone generates and stores the new key.
    """
    name = certificate['metadata']['name']
    live = read(args, 'certificates.cert-manager.io', name, args.profile.core_namespace)
    setup.owned(live, args.profile)
    if (live['metadata']['uid'] != certificate['metadata']['uid']
            or live['spec'] != certificate['spec'] or live['metadata'].get('deletionTimestamp')):
        raise ValueError('Exact newly created Certificate required for migration renewal')
    status = deepcopy(live.get('status', {}))
    conditions = status.get('conditions', [])
    if any(c.get('type') == 'Issuing' and c.get('status') == 'True' for c in conditions):
        return  # The controller has already started this same issuance.
    status['conditions'] = [c for c in conditions if c.get('type') != 'Issuing'] + [{
        'type': 'Issuing', 'status': 'True', 'reason': 'ManuallyTriggered',
        'message': 'Certificate re-issuance manually triggered',
        'observedGeneration': live['metadata']['generation'],
        'lastTransitionTime': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')}]
    patch = [{'op': 'test', 'path': '/metadata/uid', 'value': live['metadata']['uid']},
             {'op': 'test', 'path': '/metadata/resourceVersion', 'value': live['metadata']['resourceVersion']},
             {'op': 'add', 'path': '/status', 'value': status}]
    words = ('patch', 'certificates.cert-manager.io', name, '-n', args.profile.core_namespace,
             '--subresource=status', '--type=json', '--patch-file=/dev/stdin')
    setup.kube(args, *words, '--dry-run=server', '-o', 'json', value=patch)
    setup.write(args.output_dir / f'renewal-{index}.pending.json', patch)
    result = setup.kube(args, *words, '-o', 'json', value=patch)
    setup.write(args.output_dir / f'renewal-{index}.receipt.private.json', result)


def wait_issued(args):
    if getattr(args, '_certificates_issued', False):
        return
    deadline = time.monotonic() + min(max(getattr(args, 'readiness_timeout', 600), 1), 900)
    while True:
        observed = observe(args)
        if (observed['ready'] and all(not v['renewing'] and type(v['revision']) is int
                                     and v['revision'] > 0 for v in observed['certificates'])):
            setup.write(args.output_dir / 'certificates-issued.public.json', observed)
            args._certificates_issued = True
            return
        if time.monotonic() >= deadline:
            setup.write(args.output_dir / 'certificates-incomplete.public.json', observed)
            raise TimeoutError('Managed issuance incomplete; no dependent workload activation')
        time.sleep(2)


def configure(args, profile):
    """Bind explicit private configuration to the existing installation profile."""
    from source_render import read_json
    contract, pem = managed.configuration(read_json(setup.private_file(args.managed_certificate_config)))
    if contract['mode'] != 'managed':
        raise ValueError('Explicit managed certificate configuration required')
    args.certificate_management, args.certificate_authority_pem, args.profile = contract, pem, profile
    return preflight(args)


def projections(deployments, inputs, contract, pem):
    """Mount only public leaf PEM; never expose tls.key to coordinator/preparer."""
    managed.validate_contract(contract, pem)
    for item in inputs:
        item['data']['certificate-management.json'] = base64.b64encode(json.dumps(
            {'contract': contract, 'authority': pem}).encode()).decode()
    for value in deployments:
        pod = value['spec']['template']['spec']
        if any(v['name'] == 'application-certificates' for v in pod['volumes']):
            raise ValueError('Certificate projection collision')
        pod['volumes'].append({'name': 'application-certificates', 'projected': {
            'defaultMode': 0o444, 'sources': [{'secret': {'name': name, 'items': [
                {'key': 'tls.crt', 'path': name + '.crt'}]}} for name in managed.SECRETS]}})
        pod['containers'][0]['volumeMounts'].append({'name': 'application-certificates',
            'mountPath': '/application-certificates', 'readOnly': True})


def run(args):
    from deployment_profile import DeploymentProfile
    from source_render import read_json
    profile = DeploymentProfile.from_dict(read_json(setup.private_file(args.installation_profile)))
    args.profile = profile
    setup.target(args)
    configure(args, profile)
    result = observe(args)
    if result['ready'] and getattr(args, 'verify_certificate_loading', False):
        result['loading'] = loading(args)
        result['consumer_loading_proven'] = True
    return result


def loading(args):
    """Match actual TLS peers to issued leaves over installer-owned forwards."""
    profile = args.profile
    results = []
    client = read(args, 'secret', managed.SECRETS[1], profile.core_namespace)
    client_public = managed.public_secret(client, managed.targets(profile)[managed.SECRETS[1]],
                                          args.certificate_authority_pem, check_key=True)
    client_pair = tuple(base64.b64decode(client['data'][k], validate=True) for k in ('tls.crt', 'tls.key'))
    consumer = read(args, 'statefulset', 'fixture-openshell', profile.core_namespace)
    setup.owned(consumer, profile)
    peer, = [v for v in consumer['spec']['template']['spec']['volumes'] if v['name'] == 'peer-client-tls']
    if peer.get('secret', {}).get('secretName') != managed.SECRETS[1]:
        raise ValueError('Exact native peer-client Secret reference required')
    for service, port, name in (('fixture-openshell', 8080, managed.SECRETS[0]),
                                ('fixture-mcp-bound', 443, managed.SECRETS[2])):
        value = read(args, 'service', service, profile.core_namespace)
        setup.owned(value, profile)
        leaf = managed.public_secret(read(args, 'secret', name, profile.core_namespace),
            managed.targets(profile)[name], args.certificate_authority_pem)
        path = args.output_dir / (service + '-tls-forward.private.log')
        with path.open('x+') as log:
            process = subprocess.Popen([args.oc, '--kubeconfig', args.kubeconfig, '-n', profile.core_namespace,
                'port-forward', '--address=127.0.0.1', 'service/' + service, '0:' + str(port)],
                stdout=log, stderr=subprocess.STDOUT, text=True)
            try:
                deadline = time.monotonic() + 180
                while True:
                    log.flush(); log.seek(0)
                    match = re.search(r'Forwarding from 127\.0\.0\.1:(\d+)', log.read(65536))
                    if process.poll() is not None:
                        raise RuntimeError('Owned TLS observation forward exited')
                    if match:
                        actual = managed.served('127.0.0.1', int(match[1]),
                            profile.service_host(service), args.certificate_authority_pem,
                            managed.targets(profile)[name],
                            client=client_pair if service == 'fixture-openshell' else None)
                        if actual['sha256'] == leaf['sha256']:
                            results.append({'name': name, 'loaded': True, **actual})
                            break
                    if time.monotonic() >= deadline:
                        raise TimeoutError('Issued replacement not observed on live TLS listener')
                    time.sleep(2)
            finally:
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=5)
    results.append({'name': managed.SECRETS[1], 'gateway_mtls_handshake_verified': True,
                    'consumer_secret_reference_verified': True,
                    'native_peer_channel_handshake': 'not_exercised_single_replica', **client_public})
    setup.write(args.output_dir / 'certificate-loading.public.json', results)
    return results



def prepare(args, profile, inputs):
    """Plan only receipt-proven legacy Secrets under the unchanged approved CA."""
    from cluster_console_operator import receipt
    authority = configure(args, profile)
    renewal_permissions(args, profile)
    ledger = receipt(args.ledger, args.console_ledger_sha256)
    if not ledger.get('completed') or ledger.get('installation_profile') != profile.to_dict():
        raise ValueError('Completed same-installation application ledger required')
    # Changing public roots is a separate rollover, not routine leaf migration.
    old_ca = base64.b64decode(inputs['data']['management-ca.crt'], validate=True).decode()
    if hashlib.sha256(old_ca.encode()).hexdigest() != args.certificate_management['ca_sha256']:
        raise ValueError('CA rollover requires reviewed overlap and native trust repackaging')
    reference = json.loads(base64.b64decode(inputs['data']['sender-trust.receipt.json'], validate=True))
    observation = read(args, 'configmap', 'fixture-console-sender-trust', profile.core_namespace)
    from cluster_console_trust import observation_reference
    observation_reference(inputs, observation, profile)
    observed = json.loads(observation['data']['observation.json'])
    trust = read(args, 'secret', managed.SPIRE_TRUST, profile.core_namespace)
    setup.owned(trust, profile)
    if (reference.get('automatic_public_refresh') is not True
            or trust['metadata']['uid'] != observed.get('listener_ca_uid')
            or trust.get('type') != 'Opaque' or set(trust.get('data', {})) != {'ca.crt'}):
        raise ValueError('Recorded separate public SPIRE trust required before migration')
    before = []
    for name, expected in managed.targets(profile).items():
        old = read(args, 'secret', name, profile.core_namespace)
        setup.owned(old, profile)
        recorded = [v for v in ledger['created'] if v['kind'] == 'Secret'
                    and v.get('namespace') == profile.core_namespace and v['metadata']['name'] == name]
        if (len(recorded) != 1 or old['metadata']['uid'] != recorded[0]['metadata']['uid']
                or old['metadata'].get('deletionTimestamp') or old['metadata'].get('ownerReferences')):
            raise ValueError('Exact original TLS target required; no adoption')
        managed.public_secret(old, expected, old_ca, check_key=True)
        before.append(old)
    objects = managed.resources(profile, args.certificate_management)
    public = managed.public_trust(profile, old_ca)
    if read(args, 'secret', managed.APPLICATION_TRUST, profile.core_namespace):
        raise ValueError('Application public-trust collision; no adoption')
    gateway = read(args, 'statefulset', 'fixture-openshell', profile.core_namespace)
    setup.owned(gateway, profile)
    original = [v for v in ledger['created'] if v['kind'] == 'StatefulSet'
        and v.get('namespace') == profile.core_namespace and v['metadata']['name'] == 'fixture-openshell']
    if (len(original) != 1 or original[0]['metadata']['uid'] != gateway['metadata']['uid']
            or gateway['spec'].get('replicas') != 1 or gateway['metadata'].get('deletionTimestamp')):
        raise ValueError('Exact single receipt-proven OpenShell gateway required')
    after_gateway = managed.openshell_trust(gateway)
    from cluster_console_install import patch
    patch(args, profile, gateway, after_gateway, dry=True)
    setup.kube(args, 'create', '--dry-run=server', '-f', '-', '-o', 'json', value=public)
    for obj in objects:
        if read(args, 'certificates.cert-manager.io', obj['metadata']['name'], profile.core_namespace):
            raise ValueError('Certificate collision; inspect pending receipt rather than replay')
        setup.kube(args, 'create', '--dry-run=server', '-f', '-', '-o', 'json', value=obj)
    plan = {'authority': authority, 'before': before, 'objects': objects, 'public_trust': public,
            'gateway_before': gateway, 'gateway_after': after_gateway,
            'spire_trust_uid': trust['metadata']['uid'], 'spire_trust_data': trust['data'],
            'observation_uid': observation['metadata']['uid'], 'observation_data': observation['data']}
    setup.write(args.output_dir / 'certificate-migration.plan.private.json', plan)
    return plan


def apply(args, profile, planned):
    """Called only by the existing fenced idle worker update; never replay writes."""
    from cluster_console_operator import private_request
    from identity_demo_execution_setup import inspect_state
    from cluster_console_install import namespaces
    namespaces(args, profile)
    if private_request(args, profile, 'state').get('online') or not inspect_state(args)['rollback_quiescent']:
        raise ValueError('Fenced certain idle maintenance required')
    if preflight(args) != planned['authority']:
        raise ValueError('Issuer changed during drain; retain maintenance stop')
    observation = read(args, 'configmap', 'fixture-console-sender-trust', profile.core_namespace)
    if (observation['metadata']['uid'] != planned['observation_uid']
            or observation['data'] != planned['observation_data']):
        raise ValueError('Recorded trust observation changed during drain')
    trust = read(args, 'secret', managed.SPIRE_TRUST, profile.core_namespace)
    if trust['metadata']['uid'] != planned['spire_trust_uid'] or trust['data'] != planned['spire_trust_data']:
        raise ValueError('SPIRE trust changed during drain')
    for old in planned['before']:
        live = read(args, 'secret', old['metadata']['name'], profile.core_namespace)
        if live['metadata']['uid'] != old['metadata']['uid'] or setup.fingerprint(live) != setup.fingerprint(old):
            raise ValueError('TLS target changed during drain')
    made = []
    public = planned['public_trust']
    if read(args, 'secret', managed.APPLICATION_TRUST, profile.core_namespace):
        raise ValueError('Application public trust appeared during drain')
    setup.write(args.output_dir / 'application-client-trust.pending.json', public)
    result = setup.kube(args, 'create', '-f', '-', '-o', 'json', value=public)
    setup.write(args.output_dir / 'application-client-trust.receipt.private.json', result)
    made.append(result)
    for index, obj in enumerate(planned['objects']):
        if read(args, 'certificates.cert-manager.io', obj['metadata']['name'], profile.core_namespace):
            raise ValueError('Uncertain issuance target; never replay creation')
        setup.write(args.output_dir / f'certificate-{index}.pending.json', obj)
        result = setup.kube(args, 'create', '-f', '-', '-o', 'json', value=obj)
        setup.write(args.output_dir / f'certificate-{index}.receipt.private.json', result)
        made.append(result)
        request_renewal(args, result, index)
    wait_issued(args)
    for old in planned['before']:
        name = old['metadata']['name']
        identity = managed.targets(profile)[name]
        before = managed.public_secret(old, identity, args.certificate_authority_pem)
        after = managed.public_secret(read(args, 'secret', name, profile.core_namespace),
                                      identity, args.certificate_authority_pem, check_key=True)
        if before['public_key_sha256'] == after['public_key_sha256']:
            raise ValueError('Migration requires verified replacement keys before activation')
    from cluster_console_install import patch
    old = planned['gateway_before']
    live = read(args, 'statefulset', 'fixture-openshell', profile.core_namespace)
    if live['metadata']['uid'] != old['metadata']['uid'] or live['spec'] != old['spec']:
        raise ValueError('OpenShell gateway changed during maintenance')
    setup.write(args.output_dir / 'application-client-trust-rollout.pending.json', planned['gateway_after'])
    result = patch(args, profile, live, planned['gateway_after'])
    setup.write(args.output_dir / 'application-client-trust-rollout.receipt.private.json', result)
    made.append(result)
    rollout = subprocess.run([args.oc, '--kubeconfig', args.kubeconfig, '-n', profile.core_namespace,
        'rollout', 'status', 'statefulset/fixture-openshell', '--timeout=300s'], capture_output=True, timeout=310)
    if rollout.returncode:
        raise ValueError('OpenShell trust rollout incomplete; workers remain fenced')
    loading(args)
    return made
