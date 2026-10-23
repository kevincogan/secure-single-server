# SPDX-License-Identifier: Apache-2.0
"""Repair only the recorded legacy Authorino host collision while workers drain.

Authorino indexes hosts across namespaces. Retain the HTTP route, token/certificate
checks and network isolation; use Envoy's trusted context to select the exact
installation policy. No shared controller or other installation is changed.
"""
from argparse import Namespace
from copy import deepcopy
import time

import identity_demo_setup as setup
from source_render import read_json


def changes(profile,receipt):
    from gateway_credential_route import READ_NAME, READ_HOST, FILTER
    host = profile.private_mcp_authorization_host
    if receipt.get('profile') != profile.to_dict() or host == READ_HOST:
        raise ValueError('Parallel installation private authorizer boundary required')
    before = []
    for kind in ('AuthConfig','EnvoyFilter'):
        item, = [v for v in receipt['created'] if v['kind']==kind and v['metadata']['name']==READ_NAME]
        if item['metadata'].get('namespace') != profile.core_namespace:
            raise ValueError('Exact recorded private gateway resources required')
        before.append(item)
    after = deepcopy(before)
    if after[0]['spec'].get('hosts') != [READ_HOST]:
        raise ValueError('Only the known legacy private host may be migrated')
    after[0]['spec']['hosts'] = [host]
    count = 0
    for item in after[1]['spec']['configPatches']:
        if item['applyTo'] != 'VIRTUAL_HOST':continue
        match = item['match']['routeConfiguration']
        port = match.get('portNumber')
        if port not in (8080,8443) or match.get('vhost',{}).get('name') != READ_HOST+':'+str(port):continue
        value = item['patch']['value']['typed_per_filter_config'][FILTER+'-step4']
        if set(value) != {'@type','disabled'} or value['disabled'] is not False:
            raise ValueError('Exact enabled legacy filter required; no adoption')
        value.pop('disabled')
        value['check_settings'] = {'context_extensions':{'host':host}}
        count += 1
    if count != 2:
        raise ValueError('Both exact private/bound listener mediation hooks required')
    return before,after


def prepare(args,profile,receipt):
    from identity_demo_gateway_persistence import patch
    before,after = changes(profile,receipt)
    live = []
    for old,new in zip(before,after,strict=True):
        current = setup.kube(args,'get',old['kind'],old['metadata']['name'],'-n',profile.core_namespace,'-o','json')
        setup.owned(current,profile)
        if current['metadata']['uid']!=old['metadata']['uid'] or setup.fingerprint(current)!=setup.fingerprint(old):
            raise ValueError('Recorded private authorizer changed')
        patch(args,current,new,dry=True)
        live.append(current)
    setup.write(args.output_dir/'private-host-before.private.json',live)
    setup.write(args.output_dir/'private-host-plan.private.json',after)
    return {'before':live,'after':after}


def wait_linked(args,profile,expected):
    """One owned metadata hint can wake a stale status queue; never fake Ready.

    Reconciliation and status reporting are separate controller queues. Keep
    workers fenced, preserve spec/UID, and observe the actual indexed-host status.
    An uncertain annotation patch is inspected, never replayed.
    """
    from cluster_console_operator import private_request
    from identity_demo_execution_setup import inspect_state
    from identity_demo_gateway_observation import authorizer_linked
    if (expected['kind']!='AuthConfig' or expected['metadata']['name']!='fixture-step4-read-route'
            or expected['metadata'].get('namespace')!=profile.core_namespace
            or expected['spec'].get('hosts')!=[profile.private_mcp_authorization_host]
            or private_request(args,profile,'state').get('online')
            or not inspect_state(args)['rollback_quiescent']):
        raise ValueError('Exact owned policy and offline certain workers required')
    pending = args.output_dir/'host-status-hint.pending.json'
    marker = setup.fingerprint(expected)
    hinted = False
    deadline = time.monotonic()+90
    while True:
        live = setup.kube(args,'get','authconfig',expected['metadata']['name'],'-n',profile.core_namespace,'-o','json')
        setup.owned(live,profile)
        if live['metadata']['uid']!=expected['metadata']['uid'] or live['spec']!=expected['spec']:
            raise ValueError('Private policy changed while waiting for host linkage')
        if authorizer_linked(live):return live
        if not hinted:
            annotations = live['metadata'].get('annotations',{})
            if annotations.get('identity-demo/authorizer-reconcile') != marker:
                if pending.exists():raise ValueError('Uncertain reconciliation hint; inspect rather than repeat')
                operations = [{'op':'test','path':'/metadata/uid','value':live['metadata']['uid']},
                    {'op':'test','path':'/metadata/resourceVersion','value':live['metadata']['resourceVersion']},
                    {'op':'test','path':'/spec','value':live['spec']}]
                if 'annotations' not in live['metadata']:
                    operations.append({'op':'add','path':'/metadata/annotations','value':{}})
                operations.append({'op':'add','path':'/metadata/annotations/identity-demo~1authorizer-reconcile','value':marker})
                words = ('patch','authconfig',expected['metadata']['name'],'-n',profile.core_namespace,
                         '--type=json','--patch-file=/dev/stdin','-o','json')
                setup.kube(args,*words,'--dry-run=server',value=operations)
                setup.write(pending,{'uid':live['metadata']['uid'],'operations':operations})
                made = setup.kube(args,*words,value=operations)
                setup.write(args.output_dir/'host-status-hint.receipt.json',{
                    'uid':made['metadata']['uid'],'spec_unchanged':made['spec']==expected['spec']})
            hinted = True
        if time.monotonic()>=deadline:raise TimeoutError('Private host linkage not established; workers remain stopped')
        time.sleep(1)


def repair(args,profile,receipt,planned):
    from cluster_console_operator import private_request
    from identity_demo_execution_setup import inspect_state
    from identity_demo_gateway_persistence import patch
    from cluster_console_install import gateway_observation
    if private_request(args,profile,'state').get('online') or not inspect_state(args)['rollback_quiescent']:
        raise ValueError('Offline fenced workers and certain idle history required')
    updated = deepcopy(receipt)
    for old,new in zip(planned['before'],planned['after'],strict=True):
        live = setup.kube(args,'get',old['kind'],old['metadata']['name'],'-n',profile.core_namespace,'-o','json')
        setup.owned(live,profile)
        if live['metadata']['uid']!=old['metadata']['uid'] or setup.fingerprint(live)!=setup.fingerprint(old):
            raise ValueError('Private authorizer changed during drain; stop recovery')
        setup.write(args.output_dir/('host-'+old['kind']+'.pending.json'),new)
        made = patch(args,live,new)
        setup.write(args.output_dir/('host-'+old['kind']+'.receipt.private.json'),made)
        index, = [i for i,v in enumerate(updated['created']) if v['kind']==made['kind']
                  and v['metadata']['uid']==made['metadata']['uid']]
        updated['created'][index] = made
    expected, = [v for v in updated['created'] if v['kind']=='AuthConfig' and v['metadata']['name']=='fixture-step4-read-route']
    wait_linked(args,profile,expected)
    pending = args.output_dir/'gateway-host-updated.pending.private.json'
    setup.write(pending,updated)
    directory = args.output_dir/'private-host-observation'
    directory.mkdir(mode=0o700)
    observe = Namespace(**{**vars(args),'output_dir':directory,'runtime_gateway_receipt':str(pending)})
    gateway_observation(observe,profile)
    return read_json(directory/'persistent-gateway.receipt.private.json')


def recovered(args,profile,original,completed):
    """Observe receipt-proven completed patches; never replay a gateway mutation."""
    from cluster_console_install import gateway_observation
    _,planned = changes(profile,original)
    updated = deepcopy(original)
    for expected,made in zip(planned,completed,strict=True):
        if (made['metadata']['uid']!=expected['metadata']['uid']
                or made['kind']!=expected['kind'] or made['spec']!=expected['spec']):
            raise ValueError('Completed gateway patch differs from the reviewed repair')
        live = setup.kube(args,'get',expected['kind'],expected['metadata']['name'],
                          '-n',profile.core_namespace,'-o','json')
        setup.owned(live,profile)
        if live['metadata']['uid']!=expected['metadata']['uid'] or live['spec']!=expected['spec']:
            raise ValueError('Completed gateway repair changed; do not adopt or repeat')
        index, = [i for i,v in enumerate(updated['created']) if v['kind']==live['kind']
                  and v['metadata']['uid']==live['metadata']['uid']]
        updated['created'][index] = live
    expected = updated['created'][next(i for i,v in enumerate(updated['created'])
        if v['kind']=='AuthConfig' and v['metadata']['name']=='fixture-step4-read-route')]
    wait_linked(args,profile,expected)
    pending = args.output_dir/'gateway-host-recovered.pending.private.json'
    setup.write(pending,updated)
    directory = args.output_dir/'private-host-observation'
    directory.mkdir(mode=0o700)
    gateway_observation(Namespace(**{**vars(args),'output_dir':directory,
        'runtime_gateway_receipt':str(pending)}),profile)
    return read_json(directory/'persistent-gateway.receipt.private.json')
