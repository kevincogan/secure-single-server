# SPDX-License-Identifier: Apache-2.0
"""Operator-only deployed acceptance; no synthetic identities or write retries.

The runner uses the installed native CLI and normal browser PKCE. Private
credentials remain in the browser, trusted host and native provider store.
"""
from argparse import Namespace
from contextlib import contextmanager
import json
import os
from pathlib import Path
import time

from agent_security_runtime import strict_json
from contract import DOCUMENTS


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


class Journal:
    """A lost operation response stops the run instead of resubmitting it."""
    def __init__(self, directory):
        self.directory = directory
        directory.mkdir(mode=0o700, exist_ok=True)

    def once(self, name, operation):
        from proof import save, private
        path = self.directory / (name + '.json')
        pending = self.directory / (name + '.pending.json')
        if path.exists():
            return strict_json(private(path).read_bytes())
        require(not pending.exists(), 'Uncertain proof operation: ' + name)
        save(pending, {'operation': name, 'started_at': int(time.time())})
        result = operation()
        save(path, result)
        return result


class Browser:
    def __init__(self, browser, origin, issuer, user, password, directory, resume_state=None):
        self.origin = origin
        if resume_state is not None:
            from proof import private
            self.context = browser.new_context(storage_state=str(private(resume_state)))
        else:
            self.context = browser.new_context()
            page = self.context.new_page()
            page.set_default_timeout(25000)
            page.goto(origin + '/login')
            require(page.url.startswith(issuer + '/protocol/openid-connect/auth'), 'Fixed candidate issuer required')
            page.locator('#username').fill(user)
            page.locator('#password').fill(password)
            page.locator('#kc-login').click()
            page.wait_for_url(origin + '/')
        self.home = self.get('/')
        self.state = directory / (user + '.browser.private.json')
        self.context.storage_state(path=str(self.state))
        self.state.chmod(0o600)

    def get(self, path, expected=200):
        response = self.context.request.get(self.origin + path, max_redirects=0)
        require(response.status == expected, 'Unexpected authenticated control response')
        return response.json() if expected == 200 else {'status': response.status}

    def post(self, path, fields, expected=200):
        response = self.context.request.post(self.origin + path,
            form={**fields, 'csrf': self.home['csrf']}, headers={'Origin': self.origin}, max_redirects=0)
        require(response.status == expected, 'Unexpected authenticated control mutation response')
        return response.json() if expected in (200, 201, 403) else {'status': response.status}

    def approve(self, run, action, expected=200, digest=None):
        return self.post('/runs/' + run + '/approve',
            {'action': action['action_id'], 'digest': digest or action['digest']}, expected)


@contextmanager
def issuer_clients(request, config, contexts, output):
    """Own the missing native-exchange clients, never adopt existing names.

    The normal Jira qualification creates these transient clients too. Merely
    attaching a native provider does not configure the issuer's exchange chain.
    """
    from proof import save
    from deployment_profile import active_profile
    from probe_token_exchange import configuration
    from urllib.parse import urlencode, quote
    profile = active_profile()
    alias = 'document-proof-native'
    gateway = 'spiffe://' + profile.trust_domain + '/openshell/gateway/' + profile.gateway_id
    resource = config['audience']
    workloads = [c.workload for c in contexts.values()]
    names = [resource, *workloads, gateway]
    before = request('/clients')
    providers = request('/identity-provider/instances')
    require(not any(v['clientId'] in names for v in before)
        and not any(v['alias'] == alias for v in providers), 'Existing native issuer names refused')
    save(output / 'issuer-before.private.json', {'clients': before, 'providers': providers})
    made, provider = [], None
    try:
        value = {'alias': alias, 'providerId': 'spiffe', 'enabled': True, 'config': {
            'trustDomain': 'spiffe://' + profile.trust_domain,
            'bundleEndpoint': 'https://spire-spiffe-oidc-discovery-provider.' + profile.identity_namespace + '.svc:8443/keys',
            'identity-demo-owner': profile.owner, 'identity-demo-experiment': alias}}
        save(output / 'issuer-provider.pending.json', value)
        request('/identity-provider/instances', 'POST', value)
        provider = request('/identity-provider/instances/' + alias)
        save(output / 'issuer-provider.created.private.json', provider)
        roles = [request('/roles/' + role) for role in ('analyst', 'viewer')]
        for number, name in enumerate(names):
            audience = resource if name in workloads else workloads[0] if name == gateway else None
            client = configuration(name, '', audience)
            client.pop('secret', None)
            client['attributes']['identity-demo-experiment'] = alias
            if name != resource:
                client['clientAuthenticatorType'] = 'federated-jwt'
                client['attributes'].update({'jwt.credential.issuer': alias,
                    'jwt.credential.sub': name, 'standard.token.exchange.enabled': 'true'})
                if name in workloads:
                    client['attributes'].update({'access.token.lifespan': '30'})
                else:
                    client['protocolMappers'] += [{'name': 'bound-workload-' + str(i),
                        'protocol': 'openid-connect', 'protocolMapper': 'oidc-audience-mapper',
                        'config': {'included.custom.audience': w, 'access.token.claim': 'true',
                            'id.token.claim': 'false'}} for i, w in enumerate(workloads[1:])]
            save(output / ('issuer-client-' + str(number) + '.pending.json'), client)
            request('/clients', 'POST', client)
            record, = request('/clients?' + urlencode({'clientId': name}))
            made.append(record)
            save(output / ('issuer-client-' + str(number) + '.created.private.json'), record)
            request('/clients/' + record['id'] + '/scope-mappings/realm', 'POST',
                [{'id': r['id'], 'name': r['name']} for r in roles])
        yield
    finally:
        for record in reversed(made):
            current = request('/clients/' + record['id'])
            require(current == record, 'Issuer client changed; cleanup stopped')
            request('/clients/' + record['id'], 'DELETE')
        if provider is not None:
            current = request('/identity-provider/instances/' + quote(alias, safe=''))
            require(current == provider, 'Issuer provider changed; cleanup stopped')
            request('/identity-provider/instances/' + alias, 'DELETE')
        require(request('/clients') == before and request('/identity-provider/instances') == providers,
            'Issuer inventory changed beyond proof resources')
        save(output / 'issuer-cleanup.json', {'removed_exact_clients': len(made), 'provider_removed': provider is not None})


@contextmanager
def native_agents(cluster, config, output, credentials_for):
    """Use existing guarded CLI plumbing with independently verified contexts."""
    from proof import private, save
    from deployment_profile import active_profile
    from execution_context import resolve_context
    from identity_demo_runtime import guard
    import native_exchange as native
    import yaml

    settings = strict_json(private(config['native_inputs']).read_bytes())
    require(active_profile().to_dict() == config['profile'], 'Exact active installation profile required')
    contexts = {name: resolve_context(item['context_file'],
        lambda kind, name, ns=None: cluster.call(['get', kind, name, *(['-n', ns] if ns else []), '-o', 'json']),
        contract=item['contract']) for name, item in settings['contexts'].items()}
    args = Namespace(**{**settings['arguments'], 'namespace': config['profile']['core_namespace'],
        'output_dir': output, 'label': 'document-native', 'execution_context': contexts['publisher'],
        'concurrent_contexts': [v for k, v in contexts.items() if k != 'publisher'],
        'reuse_management_session': True})
    _, credentials, _ = guard(args)
    from issuer import admin_api
    admin = admin_api(config, output)
    ledger = []
    with issuer_clients(admin, config, contexts, output), native.native_session(args, credentials, initialize_profile=True) as execute:
        try:
            for name, context in contexts.items():
                retained = credentials_for(name)
                prefix = context.provider_prefix
                before = native.inventory(execute(['provider', 'list', '-o', 'json'], json_output=True,
                    execution_context=context), 'providers')
                profiles = native.inventory(execute(['provider', 'profile', 'list', '-o', 'json'],
                    json_output=True, execution_context=context), 'profiles')
                require(not any(v.get('name') == prefix for v in before)
                    and not any(v.get('id') == prefix for v in profiles), 'Native proof name collision')
                profile = {'id': prefix, 'display_name': 'Isolated document proof', 'category': 'other',
                    'credentials': [{'name': 'subject_token', 'required': True}, {'name': 'access_token',
                        'auth_style': 'bearer', 'header_name': 'Authorization', 'token_grant': {
                            'grant_type': 'token_exchange', 'token_endpoint': native.provider_token_endpoint(config['issuer'], True),
                            'audience': config['audience'], 'jwt_svid_audience': config['issuer'],
                            'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-spiffe',
                            'cache_ttl': '0s', 'subject_token': {'source': 'provider_credential',
                                'credential': 'subject_token', 'subject_token_type': 'urn:ietf:params:oauth:token-type:access_token'}}}],
                    'endpoints': [{'host': config['endpoint'].split('/')[2], 'port': 443, 'protocol': 'mcp',
                        'enforcement': 'enforce', 'path': '/_document_proof/mcp',
                        'mcp': {'versions': ['2025-11-25'], 'allow_all_known_mcp_methods': False},
                        'rules': [{'allow': {'method': v}} for v in ('initialize', 'notifications/initialized', 'tools/list')]
                        + [{'allow': {'method': 'tools/call', 'tool': v}} for v in
                            ['documents.read', 'documents.propose', DOCUMENTS.tool]]}],
                    'binaries': ['/usr/bin/python3.12']}
                path = output / (name + '.provider.private.yaml')
                path.write_text(yaml.safe_dump(profile)); path.chmod(0o600)
                execute(['provider', 'profile', 'lint', '-f', str(path)], execution_context=context)
                execute(['provider', 'profile', 'import', '-f', str(path)], execution_context=context)
                entry = {'context': context, 'prefix': prefix, 'profile': True, 'provider_id': None, 'attached': False}
                ledger.append(entry)
                execute(['provider', 'create', '--name', prefix, '--type', prefix,
                    '--credential', 'subject_token', '--config', 'identity-demo-owner=' + config['profile']['owner']],
                    subject=retained['access_token'], execution_context=context)
                records = native.inventory(execute(['provider', 'list', '-o', 'json'],
                    json_output=True, execution_context=context), 'providers')
                created = native.require_native_provider_id(records,
                    next((v.get('id') for v in records if v.get('name') == prefix), None), prefix)
                entry['provider_id'] = created['id']
                save(output / (name + '.provider-created.private.json'), created)
                execute(['provider', 'update', prefix, '--credential-expires-at',
                    'subject_token=' + str(retained['expires_at'] * 1000)], execution_context=context)
                execute(['sandbox', 'provider', 'attach', context.sandbox_name, prefix,
                    '--wait', '--timeout', '30', '--output', 'json'], execution_context=context)
                entry['attached'] = True
            def call(name, tool, arguments, *, copies=1):
                context = contexts[name]
                words = ['sandbox', 'exec', '--name', context.sandbox_name, '--no-login-shell',
                    '--timeout', '60', '--no-tty', '--', '/usr/bin/python3.12',
                    '/app/document-agent/live_agent.py', '--endpoint', config['endpoint'],
                    '--tool', tool, '--arguments', json.dumps(arguments, separators=(',', ':')), '--copies', str(copies)]
                return execute(words, execution_context=context, json_output=True)
            def isolation(name, destinations):
                context = contexts[name]
                return execute(['sandbox', 'exec', '--name', context.sandbox_name, '--no-login-shell',
                    '--timeout', '60', '--no-tty', '--', '/usr/bin/python3.12',
                    '/app/document-agent/isolation_probe.py', '--destinations', json.dumps(destinations)],
                    execution_context=context, json_output=True)
            call.isolation = isolation
            def override(name, run, forged_workload):
                context = contexts[name]
                program = """import json,sys
sys.path.insert(0,'/app/document-agent')
import live_agent
endpoint,run,workload=INPUT
original=live_agent.Request
def chosen(*args,**kwargs):
 kwargs['headers']={**kwargs.get('headers',{}),'Authorization':'Bearer synthetic-agent-selected-token','X-Forwarded-Client-Cert':'URI='+workload,'X-User':'forged-user','X-Run-ID':'forged-run'}
 return original(*args,**kwargs)
live_agent.Request=chosen
print(json.dumps(live_agent.call(endpoint,'documents.read',{'run_id':run,'collection':'engineering'})))
""".replace('INPUT', repr((config['endpoint'], run, forged_workload)))
                return execute(['sandbox', 'exec', '--name', context.sandbox_name, '--no-login-shell',
                    '--timeout', '60', '--no-tty', '--', '/usr/bin/python3.12', '-c', program],
                    execution_context=context, json_output=True)
            call.override = override
            def renew(name):
                retained = credentials_for(name, current=True)
                entry = next(v for v in ledger if v['context'] == contexts[name])
                execute(['provider', 'update', entry['prefix'], '--credential', 'subject_token'],
                    subject=retained['access_token'], execution_context=contexts[name])
                execute(['provider', 'update', entry['prefix'], '--credential-expires-at',
                    'subject_token=' + str(retained['expires_at'] * 1000)], execution_context=contexts[name])
                execute(['sandbox', 'provider', 'attach', contexts[name].sandbox_name, entry['prefix'],
                    '--wait', '--timeout', '30', '--output', 'json'], execution_context=contexts[name])
            call.renew = renew
            def controls(runs):
                from delegation_controls import run_controls
                previous = native.components.ISSUER, native.components.KEYCLOAK
                native.components.ISSUER = config['issuer']
                native.components.KEYCLOAK = config['issuer'].removesuffix('/realms/identity-demo')
                try:
                    return run_controls(args, contexts, credentials_for, runs, output)
                finally:
                    native.components.ISSUER, native.components.KEYCLOAK = previous
            call.controls = controls
            yield call, contexts
        finally:
            # Check exact recorded native IDs before every destructive operation.
            for entry in reversed(ledger):
                context, prefix = entry['context'], entry['prefix']
                if entry['provider_id']:
                    records = native.inventory(execute(['provider', 'list', '-o', 'json'],
                        json_output=True, execution_context=context), 'providers')
                    native.require_native_provider_id(records, entry['provider_id'], prefix)
                    if entry['attached']:
                        execute(['sandbox', 'provider', 'detach', context.sandbox_name, prefix], execution_context=context)
                    execute(['provider', 'delete', prefix], execution_context=context)
                if entry['profile']:
                    execute(['provider', 'profile', 'delete', prefix], execution_context=context)


def tool_value(response, expected=200):
    require(response.get('status') == expected, 'Unexpected native document response')
    if expected != 200:
        return response['body']
    return strict_json(response['body']['result']['content'][0]['text'])



def recorded_pod(cluster, output, name):
    """Follow the exact recorded Deployment UID/spec through its controller."""
    from proof import private, fingerprint
    records = [strict_json(private(p).read_bytes()) for p in (output / 'created').glob('*.json')
        if '.pending.' not in p.name]
    original, = [v for v in records if v['kind'] == 'Deployment' and v['metadata']['name'] == name]
    current = cluster.call(['get', '--raw', cluster.uri(original)])
    require(current['metadata']['uid'] == original['metadata']['uid']
        and fingerprint(current) == fingerprint(original), 'Recorded proof service changed')
    ns = cluster.config['profile']['core_namespace']
    pods = cluster.call(['get', 'pods', '-n', ns, '-l', 'app=' + name, '-o', 'json'])['items']
    pod, = [p for p in pods if p.get('status', {}).get('phase') == 'Running' and not p['metadata'].get('deletionTimestamp')]
    owner, = [v for v in pod['metadata']['ownerReferences'] if v.get('controller') and v['kind'] == 'ReplicaSet']
    replica = cluster.call(['get', 'replicaset', owner['name'], '-n', ns, '-o', 'json'])
    require(replica['metadata']['uid'] == owner['uid'] and any(v.get('uid') == current['metadata']['uid']
        and v.get('controller') for v in replica['metadata'].get('ownerReferences', [])), 'Proof service controller association changed')
    return current, pod


def observe_backend(cluster, output):
    """Independent, query-only SQLite observation in the recorded backend Pod."""
    current, pod = recorded_pod(cluster, output, 'fixture-document-backend')
    ns = cluster.config['profile']['core_namespace']
    program = """import json,sqlite3
with sqlite3.connect('file:/state/private/history.db?mode=ro',uri=True) as db:
 db.execute('PRAGMA query_only=ON')
 print(json.dumps({'revisions':[{'reference':r,'operation_id':o,'effects':json.loads(e),'digest':d}
  for r,o,e,d in db.execute('SELECT reference,operation,effects,digest FROM revisions ORDER BY reference')]}))
"""
    return {'pod_uid': pod['metadata']['uid'], 'deployment_uid': current['metadata']['uid'],
        'query_only': True, 'revisions': cluster.call(['exec', '-n', ns, pod['metadata']['name'],
            '--', 'python3.12', '-c', program])['revisions']}


def isolation_destinations(cluster):
    ns = cluster.config['profile']['core_namespace']
    values = []
    for name, ports in [('fixture-document-backend', (8443,)), ('fixture-document-host', (443, 8444)),
                        ('fixture-keycloak-upstream', (8443,)), ('fixture-openshell', (8080,))]:
        service = cluster.call(['get', 'service', name, '-n', ns, '-o', 'json'])
        if name.startswith('fixture-document-'):
            cluster.uri(service)
        else:
            meta = service.get('metadata', {})
            require(service.get('kind') == 'Service' and meta.get('name') == name
                and meta.get('namespace') == ns and meta.get('uid')
                and not meta.get('deletionTimestamp')
                and meta.get('labels', {}).get('identity-demo-owner') == cluster.config['profile']['owner'],
                'Exact owned application service required for isolation observation')
        hosts = [name + '.' + ns + '.svc.cluster.local', service['spec']['clusterIP']]
        pods = cluster.call(['get', 'pods', '-n', ns, '-l', 'app=' + name, '-o', 'json'])['items']
        hosts += [p['status']['podIP'] for p in pods if p.get('status', {}).get('phase') == 'Running']
        values += [{'host': h, 'port': port} for h in hosts for port in ports]
    from urllib.parse import urlparse
    # The public control Route is another possible path to host authority.
    values += [{'host': urlparse(cluster.config[key]).hostname, 'port': 443}
               for key in ('control_origin', 'issuer')]
    return values


def validate_setup_recovery(directory):
    """Only the exact pre-provider setup checkpoint can resume; never a write."""
    allowed={'started.json','backend-before.json','analyst.browser.private.json','viewer.browser.private.json',
        *{'start-'+n+s for n in ('publisher','viewer','reader') for s in ('.json','.pending.json')}}
    require({p.name for p in directory.iterdir()} == allowed,
        'Setup recovery refuses partial providers, actions or additional acceptance operations')


def run(cluster, config, output, *, resume_setup=False):
    """Bounded real positive/negative proof, retaining private operation receipts."""
    from proof import private, save
    from playwright.sync_api import sync_playwright
    journal = Journal(output / 'qualification')
    started = (journal.directory / 'started.json').exists()
    require(started == resume_setup, 'Existing proof requires explicit pre-dispatch setup recovery')
    if resume_setup:
        validate_setup_recovery(journal.directory)
        require(not observe_backend(cluster, output)['revisions'], 'Setup recovery requires an empty backend')
    else:
        save(journal.directory / 'started.json', {'time': int(time.time()), 'mutation_budget': 3})
    planned = strict_json(private(output / 'plan.private.json').read_bytes())
    keys = next(v['stringData'] for v in planned['objects'] if v['metadata']['name'] == 'fixture-document-host-keys')
    users = strict_json(private(config['browser_users']).read_bytes())
    origin, issuer = config['control_origin'], config['issuer']
    runs, browsers = {}, {}
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=config['browser_executable'], headless=True, chromium_sandbox=True)
        try:
            for name in ('analyst', 'viewer'):
                browsers[name] = Browser(browser, origin, issuer, name, users[name], journal.directory,
                    resume_state=journal.directory / (name + '.browser.private.json') if resume_setup else None)
            for name, user in [('publisher', 'analyst'), ('viewer', 'viewer'), ('reader', 'analyst')]:
                runs[name] = journal.once('start-' + name,
                    lambda n=name, u=user: browsers[u].post('/runs', {'context': n}, 201))['run_id']
            if resume_setup:
                for name, user in [('publisher', 'analyst'), ('viewer', 'viewer'), ('reader', 'analyst')]:
                    retained = browsers[user].get('/runs/' + runs[name])
                    context = next(v for v in config['contexts'] if v['name'] == name)
                    start = strict_json(private(journal.directory / ('start-' + name + '.json')).read_bytes())
                    require(retained['run']['active'] and retained['run']['expires'] == start['expires']
                        and start['expires'] > time.time() + 300 and not retained['actions']
                        and retained['run']['workload'] == context['workload']
                        and retained['run']['user'] == browsers[user].home['user'],
                        'Original authenticated, unmodified, empty active run required')
                save(journal.directory / ('setup-recovery-' + str(int(time.time())) + '.json'),
                    {'reused_original_runs_and_pkce_sessions': True, 'backend_revisions': 0})
            def credentials_for(name, current=False):
                response = browsers['analyst'].context.request.get(origin + '/internal/credentials/' + runs[name] + ('?current=true' if current else ''),
                    headers={'Authorization': 'Bearer ' + keys['operator']}, max_redirects=0)
                require(response.status == 200, 'Private retained native credential unavailable')
                return response.json()
            before = observe_backend(cluster, output)
            require(not before['revisions'], 'Fresh empty document backend required')
            save(journal.directory / ('backend-before-recovery.json' if resume_setup else 'backend-before.json'), before)
            with native_agents(cluster, config, journal.directory, credentials_for) as (call, contexts):
                isolation = call.isolation('publisher', isolation_destinations(cluster))
                require(not any(v['connected'] for v in isolation['destinations'])
                    and not any(isolation['sensitive_mounts'].values()), 'Sandbox backend or credential bypass found')
                custody = isolation['credential_access']
                require(not any(custody['private_files_readable'].values())
                    and not any(custody['privileged_sockets_connected'].values())
                    and not custody['sensitive_environment_names']
                    and not custody['supervisor_process_visible']
                    and not custody['supervisor_environment_readable']
                    and not custody['supervisor_memory_readable'], 'Sandbox supervisor credential access found')
                save(journal.directory / 'sandbox-isolation.json', isolation)
                def request(name, tool, arguments, status=200):
                    return tool_value(call(name, tool, arguments), status)
                for name in runs:
                    request(name, 'documents.read', {'run_id': runs[name], 'collection': 'engineering'})
                    request(name, 'documents.read', {'run_id': runs[name], 'collection': 'research'}, 403)
                header_controls = {'own_reader_run': call.override('reader', runs['reader'], contexts['publisher'].workload),
                    'other_publisher_run': call.override('reader', runs['publisher'], contexts['publisher'].workload)}
                require(header_controls['own_reader_run']['status'] == 200
                    and header_controls['other_publisher_run']['status'] == 403,
                    'Agent-selected Authorization or identity headers bypassed native delegation')
                save(journal.directory / 'agent-header-controls.json', header_controls)
                request('viewer', 'documents.read', {'run_id': runs['publisher'], 'collection': 'engineering'}, 403)
                request('reader', 'documents.read', {'run_id': runs['publisher'], 'collection': 'engineering'}, 403)
                # Approval records consent; it must never grant a missing role.
                for name, user in [('viewer', 'viewer'), ('reader', 'analyst')]:
                    action = request(name, 'documents.propose', {'run_id': runs[name], 'effects': {
                        'collection': 'engineering', 'document': 'runbook', 'revision': 1, 'content': 'Denied synthetic publication'}})
                    browsers[user].approve(runs[name], action)
                    request(name, DOCUMENTS.tool, {'run_id': runs[name], 'action_id': action['action_id'], **action['arguments']}, 403)
                require(not observe_backend(cluster, output)['revisions'], 'A denial mutated the backend')
                call.controls(runs)
                for revision in (1, 2, 3):
                    run_id = runs['publisher']
                    action = request('publisher', 'documents.propose', {'run_id': run_id, 'effects': {
                        'collection': 'engineering', 'document': 'runbook', 'revision': revision,
                        'content': 'Synthetic publication ' + str(revision)}})
                    args = {'run_id': run_id, 'action_id': action['action_id'], **action['arguments']}
                    request('publisher', DOCUMENTS.tool, args, 403)
                    browsers['viewer'].approve(run_id, action, 403)
                    browsers['analyst'].approve(run_id, action, 403, '0' * 64)
                    journal.once('approval-' + str(revision), lambda: browsers['analyst'].approve(run_id, action))
                    request('publisher', DOCUMENTS.tool, {**args, 'content': 'Altered after approval'}, 403)
                    result = journal.once('dispatch-' + str(revision),
                        lambda: call('publisher', DOCUMENTS.tool, args, copies=2 if revision == 2 else 1))
                    if revision == 2:
                        attempts = result.get('attempts', [])
                        require(len(attempts) == 2, 'Two concurrent native requests required')
                        successful = [tool_value(v) for v in attempts if v.get('status') == 200]
                        require(sum(v.get('dispatched') is True for v in successful) == 1
                            and all(v.get('status') in (200, 403) for v in attempts), 'Concurrent dispatch was not singular')
                    else:
                        tool_value(result, 403 if revision == 3 else 200)
                    observation = observe_backend(cluster, output)
                    require(len(observation['revisions']) == revision, 'Unexpected number of backend mutations')
                    latest = next(v for v in observation['revisions'] if v['reference'] == 'engineering/runbook@' + str(revision))
                    require(latest['operation_id'] == action['action_id']
                        and latest['effects'] == action['arguments'] and latest['digest'] == action['digest'],
                        'Independent backend effect/digest/marker mismatch')
                    save(journal.directory / ('backend-' + str(revision) + '.json'), observation)
                    if revision == 3:
                        request('publisher', DOCUMENTS.tool, args, 403)
                        browsers['analyst'].post('/runs/' + run_id + '/reconcile',
                            {'action': action['action_id'], 'reference': 'engineering/runbook@2'}, 403)
                        browsers['analyst'].post('/runs/' + run_id + '/reconcile',
                            {'action': action['action_id'], 'reference': 'engineering/runbook@3'})
                    repeated = request('publisher', DOCUMENTS.tool, args)
                    require(repeated.get('dispatched') is False, 'Replay dispatched again')
                    state = browsers['analyst'].get('/runs/' + run_id)
                    events = [v for v in state['audit'] if v['action_id'] == action['action_id']]
                    require(sum(v['event'] == 'claimed' for v in events) == 1, 'Atomic claim audit mismatch')
                    require(sum(v['event'] == ('reconciled' if revision == 3 else 'succeeded') for v in events) == 1,
                        'Outcome audit mismatch')
                    peers = [strict_json(v['detail']) for v in state['audit'] if v['event'] == 'authenticated_request']
                    require(peers and all(v['user'] == state['run']['user'] and v['workload'] == contexts['publisher'].workload
                        and v['delegation'] == 'short-lived-bearer' for v in peers), 'Verified delegated identity audit mismatch')
                    save(journal.directory / ('revision-' + str(revision) + '.audit.private.json'), state)
                security_lifecycle(cluster, config, output, journal, browsers, runs, call, credentials_for, delegation_checked=True)
            save(output / 'qualification.json', {'proof_passed': True,
                'real_pkce_attested_workload_exact_approval': True,
                'independent_backend_revisions': 3, 'concurrent_single_dispatch': True,
                'unknown_outcome_reconciled_without_replay': True,
                'identity_scope_role_envelope_and_bypass_negatives': True,
                'renewal_preserved_original_deadline_and_history': True,
                'fresh_execution': True, 'broader_candidate_readiness': 'pending'})
        finally:
            for value in browsers.values():
                value.context.close()
            browser.close()


def security_lifecycle(cluster, config, output, journal, browsers, runs, call, credentials_for, *, delegation_checked=False):
    """No backend writes: sender, consent expiry, revocation and original deadlines."""
    from proof import save
    request = lambda name, tool, arguments, status=200: tool_value(call(name, tool, arguments), status)
    if not delegation_checked:
        call.controls(runs)
    expired_action = request('publisher', 'documents.propose', {'run_id': runs['publisher'], 'effects': {
        # Reuse an immutable reference: even an expiry regression cannot exceed
        # the three-revision fixture budget. Require the specific host denial.
        'collection': 'engineering', 'document': 'runbook', 'revision': 3,
        'content': 'Must never be published after approval expiry'}})
    browsers['analyst'].approve(runs['publisher'], expired_action)
    approval_deadline = int(time.time()) + 121
    require(approval_deadline + 35 < credentials_for('publisher')['expires_at'],
        'Insufficient original lifetime for an independent approval-expiry test')
    while time.time() <= approval_deadline:
        time.sleep(max(.01, min(2, approval_deadline + .1 - time.time())))
    expired = request('publisher', DOCUMENTS.tool, {'run_id': runs['publisher'],
        'action_id': expired_action['action_id'], **expired_action['arguments']}, 403)
    require(expired.get('reason') == 'approval_expired', 'Approval-expiry denial was not specific')
    save(journal.directory / 'approval-expiry.json', {'denied': True, 'run_still_active': True,
        'backend_revisions': len(observe_backend(cluster, output)['revisions'])})
    # Cancellation and logout close future access, including fresh delegated requests.
    browsers['analyst'].post('/runs/' + runs['reader'] + '/cancel', {})
    request('reader', 'documents.read', {'run_id': runs['reader'], 'collection': 'engineering'}, 403)
    before_logout = int(time.time()) - 1
    browsers['viewer'].post('/logout', {}, 303)
    response = call('viewer', 'documents.read', {'run_id': runs['viewer'], 'collection': 'engineering'})
    verify_logout(cluster, output, journal.directory, runs['viewer'], response, before_logout)
    # A healthy authorized path rules out treating a general outage as revocation.
    request('publisher', 'documents.read', {'run_id': runs['publisher'], 'collection': 'engineering'})
    require(len(observe_backend(cluster, output)['revisions']) == 3, 'Negative lifecycle check mutated backend')
    renewal_deadline(cluster, output, journal, browsers, runs, call, credentials_for)


def renewal_deadline(cluster, output, journal, browsers, runs, call, credentials_for):
    """Prove renewed credentials cannot extend an existing run deadline."""
    from proof import save
    request = lambda name, tool, arguments, status=200: tool_value(call(name, tool, arguments), status)
    # Keep the original wall-clock deadline while the browser renews.
    deadline = credentials_for('publisher')['expires_at']
    while time.time() < deadline - 25:
        time.sleep(max(.01, min(5, deadline - 25 - time.time())))
    renewed = browsers['analyst'].get('/')
    require(renewed['credential_expires'] > deadline, 'Real browser renewal was not observed')
    state = browsers['analyst'].get('/runs/' + runs['publisher'])
    require(state['run']['expires'] == deadline, 'Renewal extended the original run deadline')
    save(journal.directory / 'renewal-original-deadline.json', {
        'original_run_deadline': deadline, 'renewed_credential_deadline': renewed['credential_expires'],
        'persisted_deadline_unchanged': True})
    while time.time() <= deadline:
        time.sleep(max(.01, min(2, deadline + .1 - time.time())))
    # Supply genuinely renewed credentials in trusted native storage;
    # the original run must still deny them at the protected boundary.
    call.renew('publisher')
    expired = request('publisher', 'documents.read', {'run_id': runs['publisher'], 'collection': 'engineering'}, 403)
    require(expired.get('reason') == 'run_inactive', 'Renewed credentials did not reach original run expiry enforcement')
    history = browsers['analyst'].get('/runs/' + runs['publisher'])
    require(history['run']['expires'] == deadline and len(observe_backend(cluster, output)['revisions']) == 3,
        'Expiry changed history or backend state')
    save(journal.directory / 'expired-run-history.json', history)


def verify_logout(cluster, output, directory, run, response, since):
    """Verify durable revocation, including native 502 on issuer token rejection."""
    from datetime import datetime, timezone
    from deployment_profile import DeploymentProfile
    from proof import save
    require(response.get('status') in (403, 502), 'Native revoked request was not denied')
    _, pod = recorded_pod(cluster, output, 'fixture-document-host')
    ns = cluster.config['profile']['core_namespace']
    program = """import json,sqlite3,sys
with sqlite3.connect('file:/state/private/history.db?mode=ro',uri=True) as db:
 db.execute('PRAGMA query_only=ON')
 row=db.execute('SELECT active,expires FROM runs WHERE id=?',(sys.argv[1],)).fetchone()
 print(json.dumps({'active':row[0],'expires':row[1]}))
"""
    state = cluster.call(['exec','-n',ns,pod['metadata']['name'],'--','python3.12','-c',program,run])
    require(state['active'] == 0 and state['expires'] > time.time(),
        'Logout must revoke a still-unexpired run independently of transport status')
    issuer_rejection = False
    if response['status'] == 502:
        # Native v0.1.3 reports failed subject-token exchange as Bad Gateway.
        # That status alone cannot establish an authentication denial.
        logs = cluster.call(['logs','deployment/fixture-keycloak-upstream','-n',ns,
            '--since-time',datetime.fromtimestamp(since,timezone.utc).isoformat(), '--tail=100'],raw=True)
        require(len(logs) <= 131072, 'Bounded owned issuer diagnostics required')
        profile = DeploymentProfile.from_dict(cluster.config['profile'])
        gateway = 'spiffe://' + profile.trust_domain + '/openshell/gateway/' + profile.gateway_id
        issuer_rejection = any(all(marker in line for marker in (
            'type="TOKEN_EXCHANGE_ERROR"','error="invalid_token"',
            'reason="subject_token validation failure"','client_assertion_sub="'+gateway+'"'))
            for line in logs.decode(errors='replace').splitlines())
        require(issuer_rejection, 'A generic native 502 is not revocation evidence')
    save(directory/'logout-revocation.json', {'revoked_unexpired_run':True,
        'native_status':response['status'],'issuer_subject_token_rejected':issuer_rejection,
        'query_only':True,'host_pod_uid':pod['metadata']['uid']})
