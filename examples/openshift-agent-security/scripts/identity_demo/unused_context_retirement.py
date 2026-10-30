# SPDX-License-Identifier: Apache-2.0
"""Installer-only retirement of reviewed unused identities through existing helpers.

No runtime HTTP operation or new controller is added. Native deletion is issued
once; interrupted operations remain quarantined. Resume only verifies absence.
"""
from dataclasses import asdict
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from types import SimpleNamespace

from deployment_profile import active_profile
from identity_demo_run_store import strict_json


def evidence(record):
    from identity_demo_runtime_cli import private_path
    if not isinstance(record, dict) or set(record) != {'path', 'sha256'}:
        raise ValueError('Pinned private maintenance evidence required')
    path = private_path(record['path'])
    if (not isinstance(record['sha256'], str) or not re.fullmatch('[a-f0-9]{64}', record['sha256'])
            or hashlib.sha256(path.read_bytes()).hexdigest() != record['sha256']):
        raise ValueError('Maintenance evidence changed')
    return path


def fencing(args, value):
    """Recheck actual process/lease absence, not a label or stale heartbeat alone."""
    import identity_demo_execution_setup as execution
    profile = active_profile()
    if value.get('schema_version') != 1 or value.get('profile') != profile.to_dict():
        raise ValueError('Exact installation worker-fencing receipt required')
    if value.get('runtime') == 'cluster':
        workers = value.get('workers', [])
        if len(workers) != 2 or {v['name'] for v in workers} != {
                'fixture-console-coordinator', 'fixture-console-preparer'}:
            raise ValueError('Two exact stopped worker identities required')
        for worker in workers:
            name = worker['name']
            deployment = execution.read(args, 'deployment', name, profile.core_namespace)
            execution.owned(deployment)
            lease = execution.read(args, 'lease', name, profile.core_namespace)
            execution.owned(lease)
            pods = execution.native.kube(args, 'get', 'pods', '-n', profile.core_namespace,
                                        '-l', 'app='+name, '-o', 'json')['items']
            expiry = datetime.fromisoformat(lease['spec']['renewTime'].replace('Z', '+00:00')).timestamp()
            expiry += lease['spec']['leaseDurationSeconds']
            if (deployment['metadata']['uid'] != worker['uid'] or deployment['spec']['replicas'] != 0
                    or pods or lease['metadata']['uid'] != worker['lease_uid']
                    or deployment['metadata'].get('deletionTimestamp') or lease['metadata'].get('deletionTimestamp')
                    or lease['spec'].get('holderIdentity') != worker['holder'] or time.time() <= expiry):
                raise ValueError('Worker process exit and original lease expiry required')
    elif value.get('runtime') == 'local' and sys.platform == 'darwin':
        services = value.get('services', [])
        if len(services) != 2 or {v['label'] for v in services} != {
                'org.example.agent-security-console', 'org.example.agent-security-console-preparer'}:
            raise ValueError('Two exact local presenter services required')
        for service in services:
            if type(service['pid']) is not int or service['pid'] <= 1:
                raise ValueError('Recorded local process identity required')
            try:
                os.kill(service['pid'], 0)
            except ProcessLookupError:
                pass
            else:
                raise ValueError('Recorded presenter process is still present')
            state = subprocess.run(['launchctl', 'print', 'gui/'+str(os.getuid())+'/'+service['label']],
                                   capture_output=True, timeout=10)
            if state.returncode != 113:
                raise ValueError('Presenter service must be unloaded, not merely idle')
    else:
        raise ValueError('Supported exact worker-fencing mode required')


def review(args, context):
    """Bind trusted review, installation receipts, backup and exact native UIDs."""
    import identity_demo_execution_setup as execution
    import identity_demo_setup as setup
    from cluster_console_install import namespaces
    from deployment_backup import verify_backup
    if os.environ.get('IDENTITY_DEMO_RUNTIME') == 'cluster':
        raise ValueError('Unused retirement requires a human installer, not a runtime Pod')
    path = execution.private_path(args.review_receipt)
    if (not re.fullmatch('[a-f0-9]{64}', args.review_sha256 or '')
            or hashlib.sha256(path.read_bytes()).hexdigest() != args.review_sha256):
        raise ValueError('Exact unused-retirement review hash required')
    value = strict_json(path.read_bytes())
    profile = active_profile()
    if args.expected_server.rstrip('/') != profile.expected_server.rstrip('/'):
        raise ValueError('Reviewed installation API endpoint required')
    if (set(value) != {'schema_version', 'decision', 'profile', 'reviewed_by', 'reservation',
                      'context', 'pool_context_sha256', 'resources', 'evidence'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['decision'] != 'retire_verified_unused'
            or value['profile'] != profile.to_dict() or value['context'] != asdict(context)
            or not isinstance(value['reservation'], str) or not re.fullmatch('[a-f0-9]{32}', value['reservation'])
            or not isinstance(value['pool_context_sha256'], str)
            or not re.fullmatch('[a-f0-9]{64}', value['pool_context_sha256'])):
        raise ValueError('Exact installation and unused-context review required')
    actor = subprocess.run(['oc', '--kubeconfig', args.kubeconfig, 'whoami'],
                           capture_output=True, text=True, timeout=20)
    if (actor.returncode or actor.stdout.strip() != value['reviewed_by']
            or value['reviewed_by'].startswith('system:serviceaccount:')):
        raise ValueError('Exact human installer review identity required')
    required = {'namespace_creation', 'backup', 'fencing'}
    if not required.issubset(value['evidence']) or set(value['evidence']) - required - {'disposable_workspace'}:
        raise ValueError('Namespace, backup and worker-fencing evidence required')
    pinned = {k: evidence(v) for k, v in value['evidence'].items()}
    if 'disposable_workspace' in pinned:
        args.disposable_workspace_receipt = str(pinned['disposable_workspace'])
    nsargs = SimpleNamespace(oc=shutil.which('oc'), kubeconfig=args.kubeconfig,
        namespace_creation_receipt=str(pinned['namespace_creation']),
        namespace_creation_sha256=value['evidence']['namespace_creation']['sha256'])
    if not nsargs.oc:
        raise ValueError('Installer oc executable required')
    namespaces(nsargs, profile)
    expected = value['resources']
    if set(expected) != {'driver', 'code', 'sandbox', 'workload', 'supervisor', 'registration'}:
        raise ValueError('Exact native and driver creation UIDs required')
    driver = execution.read(args, 'deployment', 'fixture-identity-driver', profile.core_namespace)
    execution.owned(driver)
    code_name, = [v['configMap']['name'] for v in driver['spec']['template']['spec']['volumes'] if v['name'] == 'code']
    code = execution.read(args, 'configmap', code_name, profile.core_namespace)
    execution.owned(code)
    if (driver['metadata']['uid'] != expected['driver'] or code['metadata']['uid'] != expected['code']
            or code.get('immutable') is not True or driver['metadata'].get('deletionTimestamp')):
        raise ValueError('Reviewed versioned driver identity changed')
    for key, kind, name in (('sandbox', 'sandboxes.agents.x-k8s.io', context.resource_name),
                            ('workload', 'pod', context.resource_name),
                            ('supervisor', 'pod', 'os-supervisor-'+context.sandbox_id)):
        obj = execution.read(args, kind, name, context.namespace, optional=True)
        if not isinstance(expected[key], str) or not expected[key] or obj and obj['metadata']['uid'] != expected[key]:
            raise ValueError('Reviewed native resource identity changed')
    from identity_demo_controller_identity import enabled
    if enabled():
        if expected['registration'] is not None:
            raise ValueError('Controller identities must not authorize static-registration deletion')
    else:
        entry = execution.read(args, 'clusterstaticentries.spire.spiffe.io', context.registration_name, optional=True)
        if (not isinstance(expected['registration'], str) or not expected['registration']
                or entry and entry['metadata']['uid'] != expected['registration']):
            raise ValueError('Reviewed static registration identity changed')
    fencing(args, strict_json(pinned['fencing'].read_bytes()))
    backup = strict_json(pinned['backup'].read_bytes())
    if (backup.get('kind') != 'identity-demo-application-data' or backup.get('profile') != profile.to_dict()
            or backup['databases']['driver']['controller_uid'] != expected['driver']):
        raise ValueError('Same-installation application backup required')
    if not getattr(args, '_unused_backup_verified', False):
        destination = args.output_dir/'backup-copy-verification'
        destination.mkdir(mode=0o700)
        verify_backup(SimpleNamespace(backup_manifest=str(pinned['backup']),
            backup_sha256=value['evidence']['backup']['sha256'], output_dir=destination))
        args._unused_backup_verified = True
    return value


def state(args, context, value, phase, absence_sha256=''):
    """Invoke only reviewed live store methods with existing installer exec access."""
    import identity_demo_execution_setup as execution
    root = execution.ROOT/'scripts/identity_demo'
    modules = {'identity_demo_warm_pool':root/'identity_demo_warm_pool.py',
               'identity_demo_run_store':root/'identity_demo_run_store.py',
               'agent_security':execution.ROOT/'runtime/agent_security.py',
               'agent_security_contracts':execution.ROOT/'runtime/agent_security_contracts.py'}
    hashes = {n: hashlib.sha256(p.read_bytes()).hexdigest() for n,p in modules.items()}
    payload = {'phase': phase, 'workload': context.workload, 'identity': asdict(context),
               'reservation': value['reservation'], 'context_sha256': value['pool_context_sha256'],
               'review_sha256': args.review_sha256, 'absence_sha256': absence_sha256,
               'profile': value['profile'], 'modules': hashes}
    program = '''import hashlib,json,os,sys
from pathlib import Path
import identity_demo_warm_pool as warm
import identity_demo_run_store as runs
import agent_security,agent_security_contracts
value=runs.strict_json(sys.stdin.buffer.read())
assert json.loads(Path(os.environ['IDENTITY_DEMO_CONFIG']).read_text())==value['profile']
for module in (warm,runs,agent_security,agent_security_contracts):
 assert hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()==value['modules'][module.__name__], 'Reviewed durable guards must be deployed first'
store=runs.RunStore.__new__(runs.RunStore);store.path=Path(os.environ['DRIVER_DATABASE'])
phase=value['phase'];assert phase in ('plan','begin','eligible','finish')
with (store.transaction() if phase in ('begin','finish') else store.read_transaction()) as db:
 row=db.execute('SELECT id,context FROM console_pool_items WHERE workload=?',(value['workload'],)).fetchone()
 assert row and all(json.loads(row['context']).get(k)==v for k,v in value['identity'].items())
 if phase=='plan':
  warm.unused_retirement_gate(db);warm.unused_context(db,value['workload'],value['context_sha256'])
 elif phase=='begin':
  warm.quarantine_unused(db,value['workload'],value['context_sha256'],value['reservation'],value['review_sha256'])
 else:
  target=warm.unused_retirement(db,value['reservation'],value['review_sha256'])
  assert target['workload']==value['workload'] and target['context_sha256']==value['context_sha256']
  if phase=='finish':warm.complete_unused_retirement(db,value['reservation'],value['review_sha256'],value['absence_sha256'])
print(json.dumps({'eligible':True,'phase':phase,'reservation':value['reservation'],'business_run_created':False,'native_mutation_replayed':False,'item_id':row['id']}))
'''
    execution.native.private_write(args.output_dir/('unused-'+phase+'.pending.private.json'), payload)
    result = subprocess.run(['oc', '--kubeconfig', args.kubeconfig, '-n', active_profile().core_namespace,
        'exec', '-i', 'deployment/fixture-identity-driver', '--', 'python', '-c', program],
        input=json.dumps(payload), capture_output=True, text=True, timeout=35)
    if result.returncode:
        raise ValueError('Unused-retirement state check stopped; inspect durable quarantine, never replay automatically')
    observed = strict_json(result.stdout.encode())
    execution.native.private_write(args.output_dir/('unused-'+phase+'.result.private.json'), observed)
    return observed


def eligible(args, context):
    return state(args, context, review(args, context), 'eligible')


def run(args):
    """Plan, retire once, or reconcile an interrupted operation without replay."""
    import identity_demo_execution_setup as execution
    execution.require(len(args.context_file) == 1, 'One exact unused context required')
    execution.guard(args)
    context = execution.context_identity(strict_json(execution.private_path(args.context_file[0]).read_bytes()))
    value = review(args, context)
    resume = getattr(args, 'resume_unused_retirement', False)
    if resume:
        checked = state(args, context, value, 'eligible')
    else:
        execution.resolve_context(args.context_file[0], lambda k, n, ns=None: execution.read(args, k, n, ns))
        checked = state(args, context, value, 'plan')
    scratch = None
    if getattr(args, 'disposable_workspace_receipt', None):
        scratch = strict_json(Path(args.disposable_workspace_receipt).read_bytes())
        args.disposable_workspace_reservation = checked['item_id']
        if (scratch.get('kind') != 'new-synthetic-pool-scratch'
                or scratch.get('context') != asdict(context)
                or scratch.get('reservation') != checked['item_id']
                or scratch.get('sandbox_uid') != value['resources']['sandbox']
                or scratch.get('installation') != active_profile().installation_id
                or scratch.get('owner') != active_profile().owner):
            raise ValueError('Disposable scratch must match the original pool reservation')
    if not args.apply:
        return {'applied': False, 'unused_retirement_planned': True, 'resume_is_read_only': resume}
    result = {}
    if not resume:
        state(args, context, value, 'begin')
        args.unused_retirement = True
        result = execution.retire(args)
    absent = []
    for kind, name in (('sandboxes.agents.x-k8s.io', context.resource_name),
                       ('pod', context.resource_name), ('pod', 'os-supervisor-'+context.sandbox_id)):
        if execution.read(args, kind, name, context.namespace, optional=True):
            raise ValueError('Retirement incomplete; reservation remains quarantined; resume never repeats deletion')
        absent.append({'kind': kind, 'name': name, 'namespace': context.namespace})
    from identity_demo_controller_identity import enabled
    if not enabled() and execution.read(args, 'clusterstaticentries.spire.spiffe.io', context.registration_name, optional=True):
        raise ValueError('Reviewed registration remains; explicit guarded cleanup required before read-only resume')
    if scratch is not None:
        from identity_demo_workspace_retention import verify_absent
        verify_absent(args, context, scratch['claims'], execution.read)
    path = args.output_dir/'unused-absence.private.json'
    execution.native.private_write(path, {'reservation': value['reservation'], 'absent': absent,
        'review_sha256': args.review_sha256, 'resources': value['resources']})
    # Recheck fencing and identity before completing the durable tombstone.
    review(args, context)
    state(args, context, value, 'finish', hashlib.sha256(path.read_bytes()).hexdigest())
    return {**result, 'applied': True, 'unused_identity_retired': True,
            'resume_native_mutations': 0, 'business_run_created': False,
            'history_preserved': True, 'reservation': value['reservation']}
