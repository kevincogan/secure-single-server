# SPDX-License-Identifier: Apache-2.0
"""Update receipt-proven workers while preserving state and fencing old processes.

Use the existing installer/patch path. Stop both idle workers, observe offline
admission and expired exact leases, then change only the reviewed image and
gateway observation input. Unknown mutations stop; rollback never replaces data.
"""
from copy import deepcopy
from datetime import datetime
import base64
import json
import time

import identity_demo_setup as setup
from cluster_console_operator import receipt, recorded, private_request, worker
from deployment_artifacts import IMAGE_REFERENCE


def desired(profile, image, deployments, inputs, gateway):
    prefix = 'image-registry.openshift-image-registry.svc:5000/'+profile.core_namespace+'/'
    if not image.startswith(prefix) or not IMAGE_REFERENCE.fullmatch(image):
        raise ValueError('Published digest in this installation registry required')
    changes = []
    for role, old in zip(('coordinator','preparer'), deployments, strict=True):
        meta, spec = old['metadata'], old['spec']
        if (meta.get('namespace') != profile.core_namespace or meta['name'] != 'fixture-console-'+role
                or spec.get('replicas') != 1 or spec['strategy']['type'] != 'Recreate'
                or spec['template']['spec'].get('serviceAccountName') != 'fixture-console-'+role
                or len(spec['template']['spec']['containers']) != 1):
            raise ValueError('Exact single-instance scoped workers required')
        new = deepcopy(old)
        new['spec']['template']['spec']['containers'][0]['image'] = image
        changes.append(new)
    if (inputs['metadata'].get('namespace') != profile.core_namespace
            or inputs['metadata']['name'] != 'fixture-console-coordinator-inputs' or inputs.get('type') != 'Opaque'):
        raise ValueError('Exact coordinator input Secret required')
    old_gateway = json.loads(base64.b64decode(inputs['data']['gateway.receipt.json'],validate=True))
    if ({k:v for k,v in old_gateway.items() if k!='runtime_observation'}
            != {k:v for k,v in gateway.items() if k!='runtime_observation'}
            or gateway.get('profile') != profile.to_dict() or not gateway.get('runtime_observation')):
        raise ValueError('Worker update cannot adopt changed routing, trust or authorization')
    new_inputs = deepcopy(inputs)
    new_inputs['data']['gateway.receipt.json'] = base64.b64encode(json.dumps(gateway).encode()).decode()
    return changes, new_inputs


def secret_patch(args, profile, before, after, *, dry=False):
    operations = [{'op':'test','path':'/metadata/uid','value':before['metadata']['uid']},
        {'op':'test','path':'/metadata/resourceVersion','value':before['metadata']['resourceVersion']},
        {'op':'test','path':'/type','value':'Opaque'}, {'op':'test','path':'/data','value':before['data']},
        {'op':'replace','path':'/data','value':after['data']}]
    return setup.kube(args,'patch','secret',before['metadata']['name'],'-n',profile.core_namespace,
        '--type=json','--patch-file=/dev/stdin',*(['--dry-run=server'] if dry else []),'-o','json',value=operations)


def wait_stopped(args, profile, proofs):
    """No process/claim can survive the observed Pod exit and original lease expiry."""
    deadline = time.monotonic()+150
    while True:
        stopped = True
        for role, proof in zip(('coordinator','preparer'),proofs,strict=True):
            name = 'fixture-console-'+role
            pods = setup.kube(args,'get','pods','-n',profile.core_namespace,'-l','app='+name,'-o','json')['items']
            lease = setup.kube(args,'get','lease',name,'-n',profile.core_namespace,'-o','json')
            setup.owned(lease,profile)
            if lease['metadata']['uid'] != proof['lease_uid'] or lease['spec'].get('holderIdentity') != proof['holder']:
                raise ValueError('Worker ownership changed during maintenance; do not resume automatically')
            expiry = datetime.fromisoformat(lease['spec']['renewTime'].replace('Z','+00:00')).timestamp()+lease['spec']['leaseDurationSeconds']
            stopped = stopped and not pods and time.time()>expiry
        if stopped and not private_request(args,profile,'state').get('online'):
            return
        if time.monotonic()>=deadline:
            raise TimeoutError('Worker exit/lease expiry not established; inputs remain unchanged')
        time.sleep(2)


def run(args, profile):
    from cluster_console_install import patch, namespaces
    from identity_demo_execution_setup import inspect_state
    from identity_demo_gateway_observation import current
    from source_render import read_json
    args.namespace = profile.core_namespace
    if getattr(args,'resume_worker_update',None):
        return resume(args,profile)
    initial = inspect_state(args)
    if not initial['rollback_quiescent']:
        raise ValueError('Idle certain installation required for worker update')
    previous = receipt(args.console_worker_receipt,args.console_worker_sha256)
    publication = receipt(args.runtime_publication_receipt,args.runtime_publication_sha256)
    if (previous.get('applied') is not True or previous.get('runtime') != 'cluster'
            or publication.get('published') is not True or publication.get('build_phases') != {'runtime':'Complete'}):
        raise ValueError('Completed worker and image publication receipts required')
    records = previous['created']
    before = [recorded(args,profile,records,'Deployment','fixture-console-'+r) for r in ('coordinator','preparer')]
    inputs = recorded(args,profile,records,'Secret','fixture-console-coordinator-inputs')
    for obj in [*before,inputs]:
        expected, = [v for v in records if v['kind']==obj['kind'] and v['name']==obj['metadata']['name']]
        if setup.fingerprint(obj) != expected['fingerprint']:
            raise ValueError('Current worker differs from its exact prior receipt')
    proofs = [worker(args,profile,records,r) for r in ('coordinator','preparer')]
    setup.write(args.output_dir/'worker-proofs-before.private.json',proofs)
    trust_refresh = None
    if getattr(args,'enable_public_trust_refresh',False) and not getattr(args,'refresh_sender_trust',False):
        raise ValueError('Automatic public trust requires the guarded idle trust refresh')
    if getattr(args,'refresh_sender_trust',False):
        from cluster_console_trust import prepare
        trust_refresh = prepare(args,profile,inputs)
    path = setup.private_file(args.runtime_gateway_receipt)
    if path.stat().st_size>2_000_000:
        raise ValueError('Bounded private gateway receipt required')
    gateway = read_json(path)
    args.gateway_receipt = str(path)
    ca = setup.kube(args,'get','configmap','fixture-service-ca','-n',profile.core_namespace,'-o','json')['data']['service-ca.crt']
    isolate_host = getattr(args,'isolate_private_authorizer',False)
    current(args,ca,allow_unlinked_private_host=True) if isolate_host else current(args,ca)
    gateway_repair = None
    if isolate_host:
        from cluster_console_gateway import prepare
        gateway_repair = prepare(args,profile,gateway)
    after, new_inputs = desired(profile,publication['images']['console_runtime'],before,inputs,gateway)
    adapter_update = prepare_adapter(args,profile,previous) if getattr(args,'refresh_adapter_code',False) else None
    certificate_update = None
    preparer_inputs = None
    if getattr(args, 'managed_certificate_config', None):
        from certificate_operations import prepare, projections
        certificate_update = prepare(args, profile, inputs)
        old = recorded(args, profile, records, 'Secret', 'fixture-console-preparer-inputs')
        record, = [r for r in records if r['kind'] == 'Secret' and r['name'] == old['metadata']['name']]
        if setup.fingerprint(old) != record['fingerprint']:
            raise ValueError('Preparer inputs differ from their exact receipt')
        new = deepcopy(old)
        projections(after, [new_inputs, new], args.certificate_management, args.certificate_authority_pem)
        secret_patch(args, profile, old, new, dry=True)
        setup.write(args.output_dir / 'certificate-preparer-inputs.plan.private.json', [old, new])
        preparer_inputs = old, new
    stopped = deepcopy(before)
    for obj in stopped:obj['spec']['replicas']=0
    setup.write(args.output_dir/'workers-before.private.json', [*before,inputs])
    setup.write(args.output_dir/'workers-plan.private.json', [*after,new_inputs])
    setup.write(args.output_dir/'idle-before.private.json',initial)
    for old,new,halted in zip(before,after,stopped,strict=True):
        patch(args,profile,old,new,dry=True)
        patch(args,profile,old,halted,dry=True)
    secret_patch(args,profile,inputs,new_inputs,dry=True)
    if not args.apply:
        return {'applied':False,'stage':'update-workloads','workers':2,'history_restore_used':False}
    halted = {}
    # Pause replenishment first; then let public admission observe coordinator
    # offline. No image/credential input changes occur until both leases expire.
    for index in (1,0):
        if not inspect_state(args)['rollback_quiescent']:
            raise ValueError('Installation became active; inspect maintenance receipts')
        namespaces(args,profile)
        setup.write(args.output_dir/f'stop-{index}.pending.json',stopped[index])
        halted[index] = patch(args,profile,before[index],stopped[index])
        setup.write(args.output_dir/f'stop-{index}.receipt.private.json',halted[index])
    wait_stopped(args,profile,proofs)
    if not inspect_state(args)['rollback_quiescent']:
        raise ValueError('A request arrived during drain; reconcile before resuming')
    live_inputs = recorded(args,profile,records,'Secret','fixture-console-coordinator-inputs')
    if live_inputs['data'] != inputs['data']:
        raise ValueError('Worker inputs changed during drain')
    if gateway_repair is not None:
        from cluster_console_gateway import repair
        gateway = repair(args,profile,gateway,gateway_repair)
        new_inputs['data']['gateway.receipt.json'] = base64.b64encode(json.dumps(gateway).encode()).decode()
        secret_patch(args,profile,live_inputs,new_inputs,dry=True)
    if trust_refresh is not None:
        from cluster_console_trust import refresh
        reference = refresh(args,profile,trust_refresh)
        if trust_refresh.get('automatic_created'):
            previous = deepcopy(previous)
            previous['created'] += [{'kind':v['kind'],'name':v['metadata']['name'],'namespace':v['metadata'].get('namespace'),
                'uid':v['metadata']['uid'],'fingerprint':setup.fingerprint(v)} for v in trust_refresh['automatic_created']]
        new_inputs['data']['sender-trust.receipt.json'] = base64.b64encode(json.dumps(reference).encode()).decode()
        secret_patch(args,profile,live_inputs,new_inputs,dry=True)
    if adapter_update is not None:
        changed = apply_adapter(args,profile,adapter_update)
        previous = deepcopy(previous)
        for record in changed:
            previous['created']=[v for v in previous['created'] if (v['kind'],v['name'])!=(record['kind'],record['name'])]
            previous['created'].append(record)
    if certificate_update is not None:
        from certificate_operations import apply
        certificates = apply(args, profile, certificate_update)
        previous = deepcopy(previous)
        previous['created'] += [{'kind': v['kind'], 'name': v['metadata']['name'],
            'namespace': v['metadata'].get('namespace'), 'uid': v['metadata']['uid'],
            'fingerprint': setup.fingerprint(v)} for v in certificates]
    return activate(args,profile,previous,before,after,halted,live_inputs,new_inputs,initial,preparer_inputs)


def prepare_adapter(args,profile,previous):
    """Extend the same idle update for one fixed receipt-proven adapter module."""
    from cluster_console_configuration import adapter_code_update
    from cluster_console_install import patch
    configured=receipt(args.console_configuration_receipt,args.console_configuration_sha256)
    if configured.get('stage')!='configure' or configured.get('applied') is not True:
        raise ValueError('Completed private application configuration required')
    ledger=receipt(args.ledger,args.console_ledger_sha256)
    if ledger.get('completed') is not True or ledger.get('installation_profile')!=profile.to_dict():
        raise ValueError('Completed exact application ledger required for catalog source')
    original=[{'kind':v['kind'],'name':v['metadata']['name'],'uid':v['metadata']['uid'],
        'fingerprint':v['fingerprint']} for v in ledger['created'] if v.get('namespace')==profile.core_namespace]
    records={(v['kind'],v['name']):v for v in [*original,*configured['created'],*configured['updated'],*previous['created']]}
    records=list(records.values())
    adapter=recorded(args,profile,records,'Deployment','fixture-protected-adapter')
    name, = [v['configMap']['name'] for v in adapter['spec']['template']['spec']['volumes'] if v['name']=='catalog-code']
    code=recorded(args,profile,records,'ConfigMap',name)
    for obj in (adapter,code):
        record, = [v for v in records if v['kind']==obj['kind'] and v['name']==obj['metadata']['name']]
        if setup.fingerprint(obj)!=record['fingerprint']:
            raise ValueError('Protected adapter/code differs from its exact receipt')
    source=setup.ROOT/'tests/identity_demo/adapter_discovery.py'
    if source.is_symlink():raise ValueError('Regular fixed catalog module required')
    action_source=setup.ROOT/'scripts/identity_demo/identity_demo_jira_action_adapter.py'
    if action_source.is_symlink():raise ValueError('Regular fixed action module required')
    new,changed=adapter_code_update(profile,adapter,code,source.read_text(),action_source=action_source.read_text())
    if setup.kube(args,'get','configmap',new['metadata']['name'],'-n',profile.core_namespace,'--ignore-not-found','-o','json'):
        raise ValueError('Adapter code collision; inspect prior receipts')
    setup.kube(args,'create','--dry-run=server','-f','-','-o','json',value=new)
    patch(args,profile,adapter,changed,dry=True)
    setup.write(args.output_dir/'adapter-before.private.json',adapter)
    setup.write(args.output_dir/'adapter-code-plan.private.json',new)
    return adapter,new,changed


def apply_adapter(args,profile,planned):
    from cluster_console_install import namespaces,patch
    from identity_demo_execution_setup import inspect_state
    before,code,after=planned
    namespaces(args,profile)
    if private_request(args,profile,'state').get('online') or not inspect_state(args)['rollback_quiescent']:
        raise ValueError('Fenced idle workers required before adapter update')
    live=setup.kube(args,'get','deployment',before['metadata']['name'],'-n',profile.core_namespace,'-o','json')
    setup.owned(live,profile)
    if live['metadata']['uid']!=before['metadata']['uid'] or live['spec']!=before['spec']:
        raise ValueError('Adapter changed during drain; do not adopt')
    setup.write(args.output_dir/'adapter-code-create.pending.json',code)
    made=setup.kube(args,'create','-f','-','-o','json',value=code)
    setup.write(args.output_dir/'adapter-code-create.receipt.private.json',made)
    setup.owned(made,profile)
    if setup.fingerprint(made)!=setup.fingerprint(code):
        raise ValueError('Created adapter code differs from the reviewed source')
    namespaces(args,profile)
    setup.write(args.output_dir/'adapter-update.pending.json',after)
    changed=patch(args,profile,live,after)
    setup.write(args.output_dir/'adapter-update.receipt.private.json',changed)
    deadline=time.monotonic()+120
    while True:
        current=setup.kube(args,'get','deployment',before['metadata']['name'],'-n',profile.core_namespace,'-o','json')
        setup.owned(current,profile)
        if current['metadata']['uid']!=changed['metadata']['uid'] or current['spec']!=changed['spec']:
            raise ValueError('Adapter changed during rollout; workers remain fenced')
        status=current.get('status',{})
        if (status.get('observedGeneration',0)>=current['metadata']['generation'] and status.get('readyReplicas')==1
                and status.get('updatedReplicas')==1 and status.get('replicas')==1):break
        if time.monotonic()>=deadline:raise TimeoutError('Adapter rollout unverified; workers remain fenced')
        time.sleep(2)
    return [{'kind':o['kind'],'name':o['metadata']['name'],'uid':o['metadata']['uid'],
             'fingerprint':setup.fingerprint(o)} for o in (made,changed)]


def activate(args,profile,previous,before,after,halted,live_inputs,new_inputs,initial,preparer_inputs=None):
    """Shared final activation path after exact drain and configuration checks."""
    from cluster_console_install import patch,namespaces
    from identity_demo_execution_setup import inspect_state
    records = previous['created']
    namespaces(args,profile)
    checked = inspect_state(args)
    if not checked['rollback_quiescent'] or checked['tables']!=initial['tables']:
        raise ValueError('History or idle state changed before activation')
    setup.write(args.output_dir/'inputs-update.pending.json',new_inputs)
    made_inputs = secret_patch(args,profile,live_inputs,new_inputs)
    setup.write(args.output_dir/'inputs-update.receipt.private.json',made_inputs)
    made = []
    if preparer_inputs is not None:
        old, new = preparer_inputs
        live = setup.kube(args, 'get', 'secret', old['metadata']['name'], '-n', profile.core_namespace, '-o', 'json')
        if live['metadata']['uid'] != old['metadata']['uid'] or live['data'] != old['data']:
            raise ValueError('Preparer inputs changed during maintenance; workers remain fenced')
        setup.write(args.output_dir / 'certificate-preparer-inputs.pending.json', new)
        updated = secret_patch(args, profile, live, new)
        setup.write(args.output_dir / 'certificate-preparer-inputs.receipt.private.json', updated)
        made.append(updated)
    for index in (0,1):
        namespaces(args,profile)
        live = setup.kube(args,'get','deployment',before[index]['metadata']['name'],'-n',profile.core_namespace,'-o','json')
        if live['metadata']['uid'] != halted[index]['metadata']['uid'] or live['spec'] != halted[index]['spec']:
            raise ValueError('Stopped worker changed before activation')
        setup.write(args.output_dir/f'start-{index}.pending.json',after[index])
        updated = patch(args,profile,live,after[index])
        setup.write(args.output_dir/f'start-{index}.receipt.private.json',updated)
        made.append(updated)
    refreshed = deepcopy(records)
    for obj in [*made,made_inputs]:
        record, = [v for v in refreshed if v['kind']==obj['kind'] and v['name']==obj['metadata']['name']]
        record['fingerprint'] = setup.fingerprint(obj)
    final = inspect_state(args)
    setup.write(args.output_dir/'idle-after.private.json',final)
    if final['tables'] != initial['tables']:
        raise ValueError('History changed during maintenance; inspect without restoring older data')
    return {'applied':True,'stage':'update-workloads','runtime':'cluster','created':refreshed,
        'prior_receipt_sha256':args.console_worker_sha256,
        'publication_receipt_sha256':args.runtime_publication_sha256,
        'history_preserved':True,'history_restore_used':False,'worker_readiness_still_required':True}


def recovery_plan(args,profile,previous,publication,gateway):
    """Validate pinned stopped-update evidence before any recovery mutation.

    Only the known host migration, interrupted before input/worker activation,
    is resumable. A pending input or start operation requires separate review.
    The manifest pins the exact files rather than trusting a directory name.
    """
    from pathlib import Path
    manifest = receipt(args.resume_worker_update,args.resume_worker_update_sha256)
    required = {'before','plan','idle','proofs','stop0','stop1','AuthConfig','EnvoyFilter'}
    if (manifest.get('kind')!='private-host-update-recovery-v1' or manifest.get('profile')!=profile.to_dict()
            or set(manifest.get('files',{}))!=required or not args.isolate_private_authorizer
            or getattr(args,'refresh_sender_trust',False) or getattr(args,'refresh_adapter_code',False)):
        raise ValueError('Exact private-host-only recovery manifest required')
    saved = {}
    for key,value in manifest['files'].items():
        path = setup.private_file(value['path'])
        if path.stat().st_size>4_000_000 or setup.sha(path)!=value['sha256']:
            raise ValueError('Exact bounded recovery evidence hash required')
        saved[key] = json.loads(path.read_text())
    directory = Path(manifest['files']['before']['path']).parent
    expected_names = {'before':'workers-before.private.json','plan':'workers-plan.private.json',
        'idle':'idle-before.private.json','stop0':'stop-0.receipt.private.json','stop1':'stop-1.receipt.private.json',
        'AuthConfig':'host-AuthConfig.receipt.private.json','EnvoyFilter':'host-EnvoyFilter.receipt.private.json'}
    if any(Path(manifest['files'][key]['path'])!=directory/name for key,name in expected_names.items()):
        raise ValueError('Recovery evidence must come from one stopped update')
    if any((directory/name).exists() for name in ('inputs-update.pending.json','inputs-update.receipt.private.json',
            'start-0.pending.json','start-1.pending.json')):
        raise ValueError('Activation may already have started; do not replay uncertain updates')
    if len(saved['before'])!=3 or len(saved['plan'])!=3 or len(saved['proofs'])!=2:
        raise ValueError('Exact worker pair and inputs required')
    before,inputs = saved['before'][:2],saved['before'][2]
    for obj in saved['before']:
        record, = [v for v in previous['created'] if v['kind']==obj['kind'] and v['name']==obj['metadata']['name']]
        if obj['metadata']['uid']!=record['uid'] or setup.fingerprint(obj)!=record['fingerprint']:
            raise ValueError('Recovery before-state differs from completed worker receipt')
    after,new_inputs = desired(profile,publication['images']['console_runtime'],before,inputs,gateway)
    if saved['plan']!=[*after,new_inputs] or not saved['idle']['rollback_quiescent']:
        raise ValueError('Recovery plan differs from the reviewed update')
    for index in (0,1):
        stopped = deepcopy(before[index]);stopped['spec']['replicas']=0
        actual = saved['stop'+str(index)]
        proof = saved['proofs'][index]
        if (actual['metadata']['uid']!=stopped['metadata']['uid'] or actual['spec']!=stopped['spec']
                or not proof.get('projected_api_identity_verified') or not proof.get('management_profile_verified')
                or not proof['holder'].startswith(proof['pod_uid']+'/')):
            raise ValueError('Exact stopped worker and prior lease proof required')
    return saved,before,after,inputs,new_inputs


def resume(args,profile):
    """Resume a proven host repair; preserve history and fence original workers."""
    from cluster_console_install import namespaces,patch
    from cluster_console_gateway import recovered
    from identity_demo_execution_setup import inspect_state
    from source_render import read_json
    previous = receipt(args.console_worker_receipt,args.console_worker_sha256)
    publication = receipt(args.runtime_publication_receipt,args.runtime_publication_sha256)
    if (previous.get('applied') is not True or previous.get('runtime')!='cluster'
            or publication.get('published') is not True or publication.get('build_phases')!={'runtime':'Complete'}):
        raise ValueError('Completed worker and image publication receipts required')
    gateway = read_json(setup.private_file(args.runtime_gateway_receipt))
    saved,before,after,inputs,new_inputs = recovery_plan(args,profile,previous,publication,gateway)
    namespaces(args,profile)
    halted = {}
    for index in (0,1):
        live = recorded(args,profile,previous['created'],'Deployment',before[index]['metadata']['name'])
        if live['spec']!=saved['stop'+str(index)]['spec']:
            raise ValueError('Stopped worker changed; no recovery adoption')
        halted[index] = live
    live_inputs = recorded(args,profile,previous['created'],'Secret','fixture-console-coordinator-inputs')
    if setup.fingerprint(live_inputs)!=setup.fingerprint(inputs):
        raise ValueError('Worker inputs changed after drain; no recovery adoption')
    wait_stopped(args,profile,saved['proofs'])
    initial = inspect_state(args)
    if not initial['rollback_quiescent'] or initial['tables']!=saved['idle']['tables']:
        raise ValueError('History changed or outcome uncertain; inspect without restoring data')
    # Full TLS/filter inspection observes only the exact completed host repair.
    gateway = recovered(args,profile,gateway,[saved['AuthConfig'],saved['EnvoyFilter']])
    new_inputs['data']['gateway.receipt.json'] = base64.b64encode(json.dumps(gateway).encode()).decode()
    secret_patch(args,profile,live_inputs,new_inputs,dry=True)
    for old,new in zip(halted.values(),after,strict=True):patch(args,profile,old,new,dry=True)
    setup.write(args.output_dir/'recovery-plan.private.json',{'original_tables':initial['tables'],
        'source_manifest_sha256':args.resume_worker_update_sha256,'gateway_mutations_replayed':False})
    if not args.apply:
        return {'applied':False,'stage':'update-workloads','recovery_verified':True,'history_restore_used':False}
    if not inspect_state(args)['rollback_quiescent']:
        raise ValueError('Installation became active during recovery validation')
    return {**activate(args,profile,previous,before,after,halted,live_inputs,new_inputs,initial),
            'recovered':True,'gateway_mutations_replayed':False}
