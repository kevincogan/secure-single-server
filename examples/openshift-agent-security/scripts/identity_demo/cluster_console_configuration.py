# SPDX-License-Identifier: Apache-2.0
"""Render the existing console's private listener and fixed historical issue view."""
from copy import deepcopy
import hashlib
import json
from uuid import UUID

from cluster_console_resources import resource


def configure(profile, driver, code, adapter, presenters, role_keys):
    """Change only the reviewed console mounts, flags and fixed adapter route."""
    if (driver['metadata'].get('namespace') != profile.core_namespace
            or driver['metadata']['name'] != 'fixture-identity-driver'
            or adapter['metadata'].get('namespace') != profile.core_namespace
            or adapter['metadata']['name'] != 'fixture-protected-adapter'
            or set(role_keys) != {'coordinator_secret', 'preparer_secret'}
            or any(not isinstance(v, str) or len(v) < 40 for v in role_keys.values())
            or len(set(role_keys.values())) != 2):
        raise ValueError('Exact installation resources and separate role keys required')
    if not presenters or any(str(UUID(v)) != v for v in presenters):
        raise ValueError('Explicit canonical presenter subjects required')
    desired_driver, desired_adapter = deepcopy(driver), deepcopy(adapter)
    desired_code = deepcopy(code)
    data = desired_code['data']
    config = json.loads(data['config.json'])
    if config['origin'] != profile.origin('fixture-identity-driver'):
        raise ValueError('Exact console origin required')
    config.update(coordinator_enabled=True, presenter_subjects=presenters, stateless_login=True,
                  private_operator_api=True,
                  jira_view_url='https://'+profile.service_host('fixture-protected-adapter')+':8443',
                  jira_view_ca='/issuer-ca/service-ca.crt')
    data['config.json'] = json.dumps(config)
    name = 'fixture-identity-driver-code-'+hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:10]
    desired_code['metadata'] = {'name': name, 'namespace': profile.core_namespace, 'labels': dict(profile.labels)}
    desired_code['immutable'] = True
    pod = desired_driver['spec']['template']['spec']
    container, = pod['containers']
    code_volumes = [v for v in pod['volumes'] if v['name'] == 'code']
    if len(code_volumes) != 1 or code_volumes[0]['configMap']['name'] != code['metadata']['name']:
        raise ValueError('Exact current console code reference required')
    code_volumes[0]['configMap']['name'] = name
    names = {v['name'] for v in pod['volumes']}
    if names.intersection({'operator-tls', 'runtime-private'}):
        raise ValueError('Private listener is already configured; inspect prior receipt')
    pod['volumes'] += [
        {'name': 'operator-tls', 'secret': {'secretName': 'fixture-identity-operator-tls', 'defaultMode': 0o440}},
        {'name': 'runtime-private', 'secret': {'secretName': 'fixture-console-role-credentials', 'defaultMode': 0o440}}]
    container['volumeMounts'] += [{'name': 'operator-tls', 'mountPath': '/operator-tls', 'readOnly': True},
                                {'name': 'runtime-private', 'mountPath': '/runtime-private', 'readOnly': True}]
    settings = {'DRIVER_PRIVATE_TLS_CERT': '/operator-tls/tls.crt', 'DRIVER_PRIVATE_TLS_KEY': '/operator-tls/tls.key',
                'COORDINATOR_SECRET_FILE': '/runtime-private/coordinator_secret',
                'PREPARER_SECRET_FILE': '/runtime-private/preparer_secret'}
    if set(settings).intersection(v['name'] for v in container['env']):
        raise ValueError('Unexpected existing private-listener environment')
    container['env'] += [{'name': k, 'value': v} for k, v in settings.items()]
    container['ports'].append({'name': 'operator-https', 'containerPort': 8444, 'protocol': 'TCP'})
    selected = [c for c in desired_adapter['spec']['template']['spec']['containers'] if c['name'] == 'adapter-https']
    if len(selected) != 1 or any(e['name'] == 'JIRA_HISTORY_VIEW_ENABLED' for e in selected[0]['env']):
        raise ValueError('One unchanged protected HTTPS adapter required')
    selected[0]['env'].append({'name': 'JIRA_HISTORY_VIEW_ENABLED', 'value': '1'})
    secret = resource(profile, 'v1', 'Secret', 'fixture-console-role-credentials', profile.core_namespace,
                      type='Opaque', stringData=role_keys)
    return [desired_code, secret], [desired_adapter, desired_driver]


def adapter_code_update(profile,adapter,code,source,*,action_source=None):
    """Replace fixed catalog/action modules and their immutable code reference."""
    if (adapter['metadata'].get('namespace')!=profile.core_namespace
            or adapter['metadata']['name']!='fixture-protected-adapter'
            or code['metadata'].get('namespace')!=profile.core_namespace or code.get('immutable') is not True
            or 'adapter_discovery.py' not in code.get('data',{}) or not source.startswith('# SPDX-License-Identifier:')):
        raise ValueError('Exact protected adapter and existing catalog module required')
    desired,changed = deepcopy(code),deepcopy(adapter)
    desired['data']['adapter_discovery.py'] = source
    if action_source is not None:
        if ('identity_demo_jira_action_adapter.py' not in code['data']
                or not action_source.startswith('# SPDX-License-Identifier:')):
            raise ValueError('Existing fixed action module and reviewed source required')
        desired['data']['identity_demo_jira_action_adapter.py'] = action_source
    if desired['data']==code['data']:raise ValueError('Catalog module already matches; no update required')
    from source_render import canonical_hash
    name='fixture-adapter-action-code-'+canonical_hash(desired['data'])[:10]
    desired['metadata']={'name':name,'namespace':profile.core_namespace,'labels':dict(profile.labels)}
    volumes=[v for v in changed['spec']['template']['spec']['volumes'] if v['name']=='catalog-code']
    if len(volumes)!=1 or volumes[0].get('configMap',{}).get('name')!=code['metadata']['name']:
        raise ValueError('Exact adapter code mount required')
    volumes[0]['configMap']['name']=name
    return desired,changed
