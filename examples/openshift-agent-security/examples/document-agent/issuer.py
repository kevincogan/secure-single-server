# SPDX-License-Identifier: Apache-2.0
"""Operator-only, receipt-bound public PKCE client for the optional proof."""
from argparse import Namespace
from copy import deepcopy
import json
import re
from urllib.parse import urlencode


def admin_api(config, output):
    from proof import private
    from deployment_profile import active_profile
    from identity_demo_runtime import guard
    from identity_demo_keycloak_upstream import issuer_request
    from identity_demo_realm_access import realm_token
    settings = json.loads(private(config['native_inputs']).read_bytes())
    profile = active_profile()
    if profile.to_dict() != config['profile']:
        raise ValueError('Exact active candidate profile required')
    args = Namespace(**{**settings['arguments'], 'namespace': profile.core_namespace, 'output_dir': output})
    _, credentials, _ = guard(args)
    base = profile.origin('fixture-keycloak-upstream')
    def request(path, method='GET', value=None):
        return issuer_request(base, '/admin/realms/identity-demo' + path,
            token=realm_token(issuer_request, base, credentials), method=method, value=value)[1]
    return request


def client_definition(config, original, name):
    from deployment_profile import DeploymentProfile
    profile = DeploymentProfile.from_dict(config['profile'])
    if (not re.fullmatch(r'document-proof-ui(?:-[a-z0-9]{1,8})?', name)
            or config['control_origin'] != profile.origin('fixture-document-control')
            or original.get('clientId') != 'identity-demo-driver'
            or original.get('attributes', {}).get('identity-demo-owner') != config['profile']['owner']
            or not original.get('publicClient') or not original.get('standardFlowEnabled')
            or original.get('fullScopeAllowed') is not False
            or original['attributes'].get('pkce.code.challenge.method') != 'S256'):
        raise ValueError('Reviewed owned public PKCE client required')
    value = deepcopy(original)
    for field in ('id', 'secret', 'registrationAccessToken', 'access'):
        value.pop(field, None)
    origin = config['control_origin']
    value.update(clientId=name, name='Isolated document reuse proof', rootUrl=origin,
        baseUrl='/', adminUrl='', redirectUris=[origin + '/callback'], webOrigins=[origin])
    value['attributes']['identity-demo-document-proof'] = 'true'
    for mapper in value.get('protocolMappers', []):
        mapper.pop('id', None)
        for field in ('included.client.audience', 'included.custom.audience'):
            if mapper.get('config', {}).get(field) == 'identity-demo-driver':
                mapper['config'][field] = name
    return value


class ProofClient:
    def __init__(self, request, config, output, name='document-proof-ui'):
        self.request, self.config, self.output, self.name = request, config, output, name

    def named(self, name):
        return self.request('/clients?' + urlencode({'clientId': name}))

    def plan(self):
        if self.named(self.name):
            raise ValueError('Existing proof client refused; original receipts must be inspected')
        original, = self.named('identity-demo-driver')
        roles = [self.request('/roles/' + name) for name in ('analyst', 'viewer')]
        if {r.get('name') for r in roles} != {'analyst', 'viewer'}:
            raise ValueError('Exact existing demo roles required')
        return {'original_driver': original, 'definition': client_definition(self.config, original, self.name),
            'roles': [{'id': r['id'], 'name': r['name']} for r in roles]}

    def install(self, plan):
        from proof import save
        pending = self.output / 'issuer-client.pending.private.json'
        created = self.output / 'issuer-client.created.private.json'
        if pending.exists() or created.exists():
            raise ValueError('Issuer creation checkpoint exists; never replay an uncertain request')
        if self.named(self.name) or self.named('identity-demo-driver') != [plan['original_driver']]:
            raise ValueError('Issuer plan changed before creation')
        if plan['definition'] != client_definition(self.config, plan['original_driver'], self.name):
            raise ValueError('Issuer plan definition differs from fixed candidate contract')
        roles = [self.request('/roles/' + name) for name in ('analyst', 'viewer')]
        if {(r['id'], r['name']) for r in roles} != {(r['id'], r['name']) for r in plan['roles']}:
            raise ValueError('Only the exact existing Analyst/Viewer roles may be scoped')
        save(pending, plan)
        self.request('/clients', 'POST', plan['definition'])
        record, = self.named(self.name)
        save(created, record)  # Preserve its exact ID before granting any role scope.
        self.request('/clients/' + record['id'] + '/scope-mappings/realm', 'POST', plan['roles'])
        scopes = self.request('/clients/' + record['id'] + '/scope-mappings/realm')
        if {(r['id'], r['name']) for r in scopes} != {(r['id'], r['name']) for r in plan['roles']}:
            raise ValueError('Issuer role scope mismatch; inspect original checkpoint')
        save(self.output / 'issuer-client.scoped.private.json', scopes)
        if self.named('identity-demo-driver') != [plan['original_driver']]:
            raise ValueError('Original driver client changed')
        return record

    def cleanup(self):
        from proof import private, save
        created = self.output / 'issuer-client.created.private.json'
        if not created.exists():
            if (self.output / 'issuer-client.pending.private.json').exists():
                raise ValueError('Uncertain issuer creation; reconcile original response first')
            return
        record = json.loads(private(created).read_bytes())
        plan = json.loads(private(self.output / 'issuer-client.pending.private.json').read_bytes())
        marker = self.output / 'issuer-client.deleted.json'
        pending = self.output / 'issuer-client.delete.pending.json'
        if marker.exists() or pending.exists():
            raise ValueError('Issuer deletion checkpoint exists; inspect without replay')
        current = self.request('/clients/' + record['id'])
        scopes = self.request('/clients/' + record['id'] + '/scope-mappings/realm')
        if (current != record or record['clientId'] != self.name
                or current.get('attributes', {}).get('identity-demo-owner') != self.config['profile']['owner']
                or not {(r['id'], r['name']) for r in scopes} <= {(r['id'], r['name']) for r in plan['roles']}):
            raise ValueError('Proof client identity/configuration/scope changed; cleanup stopped')
        save(pending, {'client_id': record['id'], 'client_name': self.name})
        self.request('/clients/' + record['id'], 'DELETE')
        if self.named(self.name):
            raise ValueError('Proof client deletion not confirmed')
        save(marker, {'removed_exact_client_id': record['id'], 'original_driver_unchanged':
            self.named('identity-demo-driver') == [plan['original_driver']]})
