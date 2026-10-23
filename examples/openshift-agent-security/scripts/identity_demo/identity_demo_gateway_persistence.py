# SPDX-License-Identifier: Apache-2.0
"""Install the existing live-decision gateway once; verify exact resources per run.

The private immutable creation receipt is required for use and rollback. Runtime
verification never creates, repairs, adopts or removes an existing object.
Only catalog-token rotation is mutable, with its exact UID and active trust proof.
"""
from __future__ import annotations

import argparse
import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import time

from deployment_profile import active_profile
from identity_demo_runtime_cli import private_path


def frontend_policy(args):
    import probe_broker_discovery as shared
    return shared.owned(args, 'authpolicy', 'fixture-mcp-bound')


def policies(args):
    """Render stable cryptographic guards; live hooks remain the run/action authority."""
    import probe_broker_discovery as shared
    from run_binding import live_sender_authorization
    from identity_demo_keycloak_upstream import BASE
    from sender_listener import HOST
    issuer, audience = BASE + '/realms/identity-demo', 'https://' + HOST + '/mcp'
    before = [frontend_policy(args), shared.owned(args, 'authpolicy', 'fixture-mcp-tools-auth')]
    after = deepcopy(before)
    after[0]['spec']['rules'] = {
        'authentication': {'keycloak': {'jwt': {'issuerUrl': issuer, 'issuer': issuer, 'audiences': [audience], 'ttl': 60}}},
        'authorization': {'native-live-bound': live_sender_authorization(issuer, audience, active_profile().trust_domain)}}
    tool = after[1]['spec']['rules']
    if set(tool.get('authentication', {})) != {'keycloak'} or not {'issuer', 'audience'}.issubset(tool.get('authorization', {})):
        raise ValueError('Exact existing tool policy contract required')
    tool['authentication']['keycloak']['jwt']['issuerUrl'] = issuer
    if 'issuer' in tool['authentication']['keycloak']['jwt']:
        tool['authentication']['keycloak']['jwt']['issuer'] = issuer
    tool['authorization']['issuer']['patternMatching']['patterns'] = [{'predicate': 'has(auth.identity.iss) && auth.identity.iss == ' + json.dumps(issuer)}]
    tool['authorization']['audience']['patternMatching']['patterns'] = [{'predicate':
        'has(auth.identity.aud) && (auth.identity.aud == ' + json.dumps(audience)
        + ' || (type(auth.identity.aud) == list && ' + json.dumps(audience) + ' in auth.identity.aud))'}]
    return before, after


def patch(args, before, desired, *, dry=False):
    import probe_broker_discovery as shared
    from native_backend import resource_kind
    shared.require_owned(before)
    operations = [{'op': 'test', 'path': '/metadata/uid', 'value': before['metadata']['uid']},
        {'op': 'test', 'path': '/metadata/resourceVersion', 'value': before['metadata']['resourceVersion']},
        {'op': 'test', 'path': '/spec', 'value': before['spec']}, {'op': 'replace', 'path': '/spec', 'value': desired['spec']}]
    return shared.kube(args, 'patch', resource_kind(before), before['metadata']['name'], '-n', active_profile().core_namespace,
        '--type=json', '--patch-file=/dev/stdin', *(['--dry-run=server'] if dry else []), '-o', 'json', payload=operations)


def catalog_valid(args, live, *, require_fresh=True):
    import probe_broker_discovery as shared
    from identity_demo_adapter_catalog import TRUST
    if live.get('type') != 'Opaque' or set(live.get('data', {})) != {'token'}:
        raise ValueError('Exact catalog credential shape required')
    token = base64.b64decode(live['data']['token'], validate=True).decode()
    if not token.startswith('Bearer discovery_') or len(token) > 512:
        raise ValueError('Bounded catalog-only credential required')
    trust = shared.owned(args, 'secret', TRUST)
    digests = json.loads(base64.b64decode(trust['data']['digests.json'], validate=True))
    expiry = digests.get(hashlib.sha256(token.removeprefix('Bearer ').encode()).hexdigest())
    if type(expiry) is not int or (require_fresh and expiry <= time.time() + 120):
        raise ValueError('Active catalog trust with sufficient lifetime required')


def verify(args, ca, *, require_catalog_fresh=True):
    import probe_broker_discovery as shared
    from native_backend import resource_kind
    profile = active_profile()
    path = Path(private_path(args.gateway_receipt))
    receipt = json.loads(path.read_text())
    if (receipt.get('kind') != 'persistent-live-gateway-v1' or receipt.get('profile') != profile.to_dict()
            or receipt.get('service_ca_sha256') != hashlib.sha256(ca.encode()).hexdigest()):
        raise ValueError('Exact target and current trust gateway receipt required')
    for expected in [*receipt['created'], *receipt['policies_after']]:
        live = shared.owned(args, resource_kind(expected), expected['metadata']['name'])
        if live['metadata']['uid'] != expected['metadata']['uid']:
            raise ValueError('Persistent gateway resource replaced')
        if expected['kind'] == 'Secret' and expected['metadata']['name'].endswith('-catalog'):
            catalog_valid(args, live, require_fresh=require_catalog_fresh)
        elif any(live.get(k) != expected.get(k) for k in ('spec', 'data', 'type')):
            raise ValueError('Persistent gateway configuration changed')
    gateway = shared.owned(args, 'gateway', 'fixture-mcp')
    if gateway['metadata']['uid'] != receipt['gateway_before']['metadata']['uid'] or gateway['spec'] != receipt['gateway_spec']:
        raise ValueError('Persistent gateway listener drift')
    return receipt


def catalog_before_rotation(args):
    import probe_broker_discovery as shared
    receipt = json.loads(Path(private_path(args.gateway_receipt)).read_text())
    if receipt.get('kind') != 'persistent-live-gateway-v1' or receipt.get('profile') != active_profile().to_dict():
        raise ValueError('Exact persistent installation receipt required')
    expected = [v for v in receipt['created'] if v['kind'] == 'Secret' and v['metadata']['name'].endswith('-catalog')]
    if len(expected) != 1:
        raise ValueError('Recorded persistent catalog required')
    live = shared.owned(args, 'secret', expected[0]['metadata']['name'])
    if live['metadata']['uid'] != expected[0]['metadata']['uid']:
        raise ValueError('Catalog Secret replaced')
    catalog_valid(args, live, require_fresh=False)
    return live


def rotate_catalog(args, previous=None, *, before_mutation=None):
    """Idle only: update one recorded catalog Secret after adapter trust rotation."""
    import probe_broker_discovery as shared
    from probe_native_exchange import private_write
    receipt = json.loads(Path(private_path(args.gateway_receipt)).read_text())
    expected = [v for v in receipt['created'] if v['kind'] == 'Secret' and v['metadata']['name'].endswith('-catalog')]
    if len(expected) != 1:
        raise ValueError('Recorded persistent catalog Secret required')
    live = shared.owned(args, 'secret', expected[0]['metadata']['name'])
    if live['metadata']['uid'] != expected[0]['metadata']['uid']:
        raise ValueError('Catalog Secret replaced')
    if previous is not None:
        if previous['metadata']['uid'] != live['metadata']['uid'] or previous['data'] != live['data']:
            raise ValueError('Catalog changed during credential rotation')
    else:
        catalog_valid(args, live, require_fresh=False)
    credential = json.loads(Path(private_path(args.catalog_credential_file)).read_text())
    data = {'token': base64.b64encode(('Bearer '+credential['token']).encode()).decode()}
    desired = {**live, 'data': data}
    catalog_valid(args, desired)
    if live['data'] == data:
        return
    if before_mutation is not None and not before_mutation():
        return False
    private_write(args.output_dir / ('persistent-catalog-before-'+str(int(time.time_ns()))+'.private.json'), live)
    operations = [{'op':'test','path':'/metadata/uid','value':live['metadata']['uid']},
        {'op':'test','path':'/metadata/resourceVersion','value':live['metadata']['resourceVersion']},
        {'op':'test','path':'/data','value':live['data']}, {'op':'replace','path':'/data','value':data}]
    shared.kube(args,'patch','secret',live['metadata']['name'],'-n',active_profile().core_namespace,
                '--type=json','--patch-file=/dev/stdin','-o','json',payload=operations)


def install(args):
    """Existing setup entry point calls this explicit idle plan/install stage."""
    from identity_demo_execution_setup import inspect_state
    from identity_demo_runtime import guard
    import probe_broker_discovery as shared
    from native_backend import NativeBackend
    from run_binding import ReadRun
    from sender_listener import HOST
    from identity_demo_keycloak_upstream import BASE
    from probe_native_exchange import private_write
    if not inspect_state(args)['rollback_quiescent']:
        raise ValueError('Idle certain installation required')
    _, credentials, _ = guard(args)
    from identity_demo_console_worker import recover_catalog_reference
    if not args.catalog_credential_file or not recover_catalog_reference(args):
        raise ValueError('Current approved private catalog credential required')
    ca = shared.owned(args,'configmap','fixture-service-ca')['data']['service-ca.crt']
    before, desired = policies(args)
    for old, new in zip(before, desired, strict=True):
        patch(args, old, new, dry=True)
    class RenderingFlow:
        def progress(self, *a, **kw):
            pass
    request = argparse.Namespace(**vars(args))
    request.permission_flow, request.enable_create, request.gateway_mode = RenderingFlow(), True, 'temporary'
    request.gateway_plan_only = not args.apply
    backend = NativeBackend(request)
    binding = ReadRun('persistent-template', BASE+'/realms/identity-demo', 'unassigned',
        'spiffe://'+active_profile().trust_domain+'/openshell/sandbox/unassigned', 'https://'+HOST+'/mcp', 1, 2)
    private_write(args.output_dir/'gateway-policies-before.private.json',before)
    private_write(args.output_dir/'gateway-policies-desired.private.json',desired)
    backend.prepare(ca, credentials['adapter_clients']['fixture-gateway-service'], binding, args.catalog_credential_file)
    if not args.apply:
        private_write(args.output_dir/'gateway-plan.private.json', {'objects':backend.planned_values,'gateway_spec':backend.planned_gateway_spec})
        return {'planned':True,'applied':False,'persistent_objects':len(backend.planned_values)}
    changed=[]
    # A partial install retains exact before/creation receipts; never silently
    # repeat it, adopt collisions, or hide an uncertain shared-policy mutation.
    for old,new in zip(before,desired,strict=True):
        current=shared.owned(args,'authpolicy',old['metadata']['name'])
        if current['metadata']['uid']!=old['metadata']['uid'] or current['spec']!=old['spec']:
            raise ValueError('Policy changed during persistent install')
        made=patch(args,current,new);changed.append(made)
        private_write(args.output_dir/(made['metadata']['name']+'.installed.private.json'),made)
    from identity_demo_gateway_observation import capture
    observation=capture(args,ca,backend.ready)
    checks=observation['checks']
    receipt={'kind':'persistent-live-gateway-v1','profile':active_profile().to_dict(),'created':backend.ledger,
        'policies_before':before,'policies_after':changed,'gateway_before':backend.gateway_before,
        'gateway_spec':backend.gateway_spec,'service_ca_sha256':hashlib.sha256(ca.encode()).hexdigest(),
        'checks':checks,'runtime_observation':observation}
    path=args.output_dir/'persistent-gateway.receipt.private.json'
    private_write(path,receipt)
    return {'applied':True,'persistent_gateway_installed':True,'objects':len(backend.ledger),'receipt':str(path),
            'live_run_and_exact_action_checks_retained':True}


def remove(args):
    """Explicit idle rollback, never a per-run cleanup or database restore."""
    from identity_demo_execution_setup import inspect_state
    from native_backend import NativeBackend
    import probe_broker_discovery as shared
    if not inspect_state(args)['rollback_quiescent']:
        raise ValueError('Idle certain installation required')
    ca=shared.owned(args,'configmap','fixture-service-ca')['data']['service-ca.crt']
    receipt=verify(args,ca)
    if receipt.get('profile') != active_profile().to_dict():
        raise ValueError('Exact rollback target required')
    for old,installed in zip(receipt['policies_before'],receipt['policies_after'],strict=True):
        patch(args,shared.owned(args,'authpolicy',installed['metadata']['name']),old,dry=True)
    if not args.apply:
        return {'planned': True, 'applied': False, 'rollback_guard_checks_passed': True}
    for old,installed in zip(receipt['policies_before'],receipt['policies_after'],strict=True):
        patch(args,shared.owned(args,'authpolicy',installed['metadata']['name']),old)
    backend=NativeBackend(args);backend.persistent=False
    backend.ledger=[shared.owned(args,v['kind'],v['metadata']['name']) for v in receipt['created']]
    backend.gateway_before,backend.gateway_spec=receipt['gateway_before'],receipt['gateway_spec']
    backend.cleanup()
    return {'persistent_gateway_removed':True,'historical_databases_unchanged':True}
