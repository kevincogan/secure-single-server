# SPDX-License-Identifier: Apache-2.0
"""Installer-only Keycloak permission for the two existing demo realm roles.

Keycloak 26.8 FGAP v2 separates mapping a realm role into client scope from
managing clients. Use its existing authorization service, never manage-realm
on the runtime account. All installer credentials stay outside worker inputs.
"""
import json
from urllib.parse import urlencode
from uuid import UUID

import identity_demo_setup as setup
from source_render import read_json


ACTOR = 'fixture-console-role-scope-actor'
PERMISSION = 'fixture-console-role-scope'


def grants(subject, roles):
    """Only the exact service account may map Analyst/Viewer into client scope."""
    if str(UUID(subject)) != subject or set(roles) != {'analyst', 'viewer'}:
        raise ValueError('Exact coordinator subject and two demo roles required')
    if any(str(UUID(v)) != v for v in roles.values()) or len(set(roles.values())) != 2:
        raise ValueError('Distinct canonical role identities required')
    policy = {'name': ACTOR, 'type': 'user', 'logic': 'POSITIVE', 'users': [subject]}
    permission = {'name': PERMISSION, 'type': 'scope', 'logic': 'POSITIVE',
        'decisionStrategy': 'UNANIMOUS', 'resourceType': 'Roles',
        'resources': sorted(roles.values()), 'scopes': ['map-role-client-scope'],
        'policies': [ACTOR]}
    return policy, permission


def run(args, profile):
    from identity_demo_realm_access import realm_token
    from identity_demo_keycloak_upstream import issuer_request
    ledger_path = setup.private_file(args.ledger)
    if setup.sha(ledger_path) != args.console_ledger_sha256:
        raise ValueError('Exact original application creation ledger required')
    ledger = read_json(ledger_path)
    if ledger.get('installation_profile') != profile.to_dict():
        raise ValueError('Same installation creation ledger required')
    records = [r for r in ledger['created'] if r['kind'] == 'Deployment'
               and r['metadata']['name'] == 'fixture-keycloak-upstream'
               and r.get('namespace') == profile.core_namespace]
    live = setup.kube(args, 'get', 'deployment', 'fixture-keycloak-upstream', '-n', profile.core_namespace, '-o', 'json')
    setup.owned(live, profile)
    if len(records) != 1 or live['metadata']['uid'] != records[0]['metadata']['uid'] or live['metadata'].get('deletionTimestamp'):
        raise ValueError('Exact owned exchange issuer required')
    from identity_demo_execution_setup import inspect_state
    args.namespace = profile.core_namespace
    state = inspect_state(args)
    # A failed pre-write acceptance can require review while the issuer remains
    # idle. This changes no run/recovery decision and cannot clear that gate.
    if any(state[k] for k in ('active_runs', 'active_console_jobs', 'executing_or_unknown_actions', 'active_preparations')):
        raise ValueError('Idle issuer and certain writes required')
    credentials = read_json(setup.private_file(args.credentials_file))
    base = profile.origin('fixture-keycloak-upstream')
    token = realm_token(issuer_request, base, credentials)
    prefix = '/admin/realms/identity-demo'
    def request(path, method='GET', value=None):
        return issuer_request(base, prefix+path, method=method, token=token, value=value)[1]
    realm = request('/')
    if realm.get('realm') != 'identity-demo' or realm.get('enabled') is not True:
        raise ValueError('Exact enabled owned realm required')
    accounts = request('/clients?'+urlencode({'clientId':'fixture-console-realm-coordinator'}))
    if len(accounts) != 1 or accounts[0].get('serviceAccountsEnabled') is not True:
        raise ValueError('Exact coordinator service client required')
    subject = request('/clients/'+accounts[0]['id']+'/service-account-user')
    # This fixed client endpoint supplies the association. Keycloak's GET user
    # representation omits serviceAccountClientId on some supported versions.
    if (subject.get('username') != 'service-account-fixture-console-realm-coordinator'
            or subject.get('serviceAccountClientId', 'fixture-console-realm-coordinator') != 'fixture-console-realm-coordinator'
            or subject.get('enabled') is not True):
        raise ValueError('Exact enabled coordinator service account required')
    roles = {name: request('/roles/'+name)['id'] for name in ('analyst', 'viewer')}
    policy, permission = grants(subject['id'], roles)
    setup.write(args.output_dir/'realm-before.private.json', realm)
    setup.write(args.output_dir/'role-scope-plan.json', {'issuer_uid':live['metadata']['uid'],
        'realm_id':realm['id'], 'enable_admin_permissions':not realm.get('adminPermissionsEnabled', False),
        'policy':policy, 'permission':permission, 'runtime_manage_realm_granted':False})
    existing = request('/clients?'+urlencode({'clientId':'admin-permissions'}))
    def collision(client):
        root = '/clients/'+client['id']+'/authz/resource-server'
        for name in (ACTOR, PERMISSION):
            if request(root+'/policy?'+urlencode({'name':name, 'exact':'true'})):
                raise ValueError('Existing role-scope permission; inspect prior receipt, do not replay')
        return root
    if existing:
        if len(existing) != 1 or not realm.get('adminPermissionsEnabled'):
            raise ValueError('Uncertain existing admin permission service')
        collision(existing[0])
    if not args.apply:
        return {'applied':False,'stage':'realm-permissions','roles':sorted(roles),'runtime_manage_realm_granted':False}
    current = setup.kube(args,'get','deployment','fixture-keycloak-upstream','-n',profile.core_namespace,'-o','json')
    if current['metadata']['uid'] != live['metadata']['uid'] or current['spec'] != live['spec']:
        raise ValueError('Issuer changed during planning')
    if not realm.get('adminPermissionsEnabled'):
        setup.write(args.output_dir/'enable-admin-permissions.pending.json', {'realm_id':realm['id']})
        request('/', 'PUT', {'realm':'identity-demo','adminPermissionsEnabled':True})
        setup.write(args.output_dir/'enable-admin-permissions.receipt.json', {'enabled':request('/').get('adminPermissionsEnabled') is True})
    clients = request('/clients?'+urlencode({'clientId':'admin-permissions'}))
    if len(clients) != 1:
        raise ValueError('Admin permission service creation needs review')
    root = collision(clients[0])
    setup.write(args.output_dir/'actor.pending.json',policy)
    request(root+'/policy/user','POST',policy)
    actors = request(root+'/policy?'+urlencode({'name':ACTOR,'exact':'true'}))
    if len(actors) != 1 or actors[0].get('name') != ACTOR:
        raise ValueError('Actor policy creation needs review')
    setup.write(args.output_dir/'actor.receipt.private.json',actors[0])
    permission['policies'] = [actors[0]['id']]
    setup.write(args.output_dir/'permission.pending.json',permission)
    request(root+'/permission/scope','POST',permission)
    found = request(root+'/permission?'+urlencode({'name':PERMISSION,'exact':'true'}))
    if len(found) != 1 or found[0].get('name') != PERMISSION:
        raise ValueError('Role scope permission creation needs review')
    setup.write(args.output_dir/'permission.receipt.private.json',found[0])
    return {'applied':True,'stage':'realm-permissions','roles':sorted(roles),
        'scope':'map-role-client-scope','runtime_manage_realm_granted':False,
        'run_or_recovery_decisions_changed':False}
