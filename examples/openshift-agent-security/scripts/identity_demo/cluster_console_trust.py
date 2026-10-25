# SPDX-License-Identifier: Apache-2.0
"""Installer-only trust maintenance inside the existing guarded worker update.

No runtime grants or shared foundation mutations. The caller drains workers and
waits for lease expiry before applying. An interrupted operation stays offline;
private pending receipts must be reconciled rather than replayed blindly.
"""
from argparse import Namespace
import base64
import hashlib
import json
import subprocess

import identity_demo_setup as setup
from source_render import read_json


def observation_reference(inputs, observation, profile):
    """A name/label is not sufficient evidence for replacing a public receipt."""
    setup.owned(observation,profile)
    reference = json.loads(base64.b64decode(inputs['data']['sender-trust.receipt.json'],validate=True))
    if (observation['metadata'].get('namespace') != profile.core_namespace
            or observation['metadata']['name'] != 'fixture-console-sender-trust'
            or observation.get('immutable') is not True or observation['metadata'].get('deletionTimestamp')
            or observation['metadata']['uid'] != reference.get('uid')
            or set(observation.get('data',{})) != {'observation.json'}
            or hashlib.sha256(observation['data']['observation.json'].encode()).hexdigest() != reference.get('observation_sha256')
            or json.loads(observation['data']['observation.json']).get('profile') != profile.to_dict()):
        raise ValueError('Exact current worker public trust observation required')


def recorded(args,profile):
    """Bind mutable trust copies to the original application creation identities."""
    path = setup.private_file(args.ledger)
    if setup.sha(path) != args.console_ledger_sha256:
        raise ValueError('Exact application creation ledger required for trust maintenance')
    ledger = read_json(path)
    if ledger.get('installation_profile') != profile.to_dict():
        raise ValueError('Same installation trust ledger required')
    result = []
    for kind,name in (('Secret','fixture-keycloak-upstream-client-trust'),
                      ('Secret','fixture-mcp-bound-mutual'),('Deployment','fixture-keycloak-upstream')):
        live = setup.kube(args,'get',kind,name,'-n',profile.core_namespace,'-o','json')
        setup.owned(live,profile)
        matches = [v for v in ledger['created'] if v['kind']==kind and v['metadata']['name']==name
                   and v.get('namespace')==profile.core_namespace]
        if name == 'fixture-mcp-bound-mutual' and not matches and getattr(args, 'certificate_management', {}).get('mode') == 'managed':
            from certificate_operations import recorded_secret
            recorded_secret(args, profile, ledger, live)
            result.append(live)
            continue
        if len(matches)!=1 or matches[0]['metadata']['uid']!=live['metadata']['uid'] or live['metadata'].get('deletionTimestamp'):
            raise ValueError('Exact original owned trust resource required')
        result.append(live)
    return result


def prepare(args,profile,inputs):
    from identity_demo_sender_trust import refresh
    live = setup.kube(args,'get','configmap','fixture-console-sender-trust','-n',profile.core_namespace,'-o','json')
    observation_reference(inputs,live,profile)
    observed = json.loads(live['data']['observation.json'])
    if observed.get('listener_ca_uid'):
        args.public_trust_ca_uid = observed['listener_ca_uid']
    if 'certificate-management.json' in inputs['data']:
        import managed_certificates
        policy = json.loads(base64.b64decode(inputs['data']['certificate-management.json'], validate=True))
        managed_certificates.validate_contract(policy['contract'], policy['authority'])
        args.certificate_management = policy['contract']
        args.certificate_authority_pem = policy['authority']
    targets = recorded(args,profile)
    setup.write(args.output_dir/'trust-resources-before.private.json',targets)
    setup.write(args.output_dir/'trust-observation-before.private.json',live)
    directory = args.output_dir/'trust-refresh-plan'
    directory.mkdir(mode=0o700)
    repair = Namespace(**{**vars(args),'output_dir':str(directory),'apply':False})
    refresh(repair)  # Existing complete dry-run, pinned issuer and UID/RV checks.
    automatic = None
    if getattr(args,'enable_public_trust_refresh',False):
        from cluster_console_public_trust import prepare
        automatic = prepare(args,profile,targets)
    return {'targets':targets,'observation':live,'automatic':automatic}


def refresh(args,profile,planned):
    """Run only after the caller has stopped/fenced both exact idle workers."""
    from identity_demo_execution_setup import inspect_state
    from cluster_console_operator import private_request
    from identity_demo_sender_trust import refresh as reconcile, current
    from cluster_console_install import trust_observation
    if private_request(args,profile,'state').get('online') or not inspect_state(args)['rollback_quiescent']:
        raise ValueError('Offline fenced workers and certain idle history required')
    live = recorded(args,profile)
    if any(setup.fingerprint(a)!=setup.fingerprint(b) for a,b in zip(live,planned['targets'],strict=True)):
        raise ValueError('Trust inputs changed during maintenance; do not adopt changes')
    directory = args.output_dir/'trust-refresh-applied'
    directory.mkdir(mode=0o700)
    setup.write(directory/'maintenance.pending.json',{'phase':'owned-trust-refresh','shared_changes':False})
    repair = Namespace(**{**vars(args),'output_dir':str(directory),'apply':True})
    result = reconcile(repair)
    if planned.get('automatic') is not None:
        from cluster_console_public_trust import apply
        planned['automatic_created'] = apply(args,profile,planned['automatic'])
    if result['issuer_rollout_started'] or planned.get('automatic') is not None:
        rollout = subprocess.run([args.oc,'--kubeconfig',args.kubeconfig,'-n',profile.core_namespace,
            'rollout','status','deployment/fixture-keycloak-upstream','--timeout=300s'],
            capture_output=True,text=True,timeout=310)
        setup.write(directory/'issuer-rollout.receipt.json',{'exit_code':rollout.returncode})
        if rollout.returncode:
            raise ValueError('Owned issuer rollout failed; workers remain stopped')
    if not current(args):
        raise ValueError('Approved bundle changed during reconciliation; retain offline recovery')
    observed = args.output_dir/'trust-observation-refreshed'
    observed.mkdir(mode=0o700)
    capture = Namespace(**{**vars(args),'output_dir':observed,'apply':True})
    trust_observation(capture,profile,previous=planned['observation'])
    reference = read_json(observed/'sender-trust.receipt.json')
    setup.write(directory/'maintenance.receipt.json',{'owned_trust_aligned':True,
        'public_observation_refreshed':True,'shared_foundation_changed':False,'live_acceptance_still_required':True})
    return reference
