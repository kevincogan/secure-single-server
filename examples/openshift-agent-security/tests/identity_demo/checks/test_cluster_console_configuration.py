# SPDX-License-Identifier: Apache-2.0
"""Private console wiring preserves application state and limits role credentials."""
from copy import deepcopy
import json
from uuid import uuid4

import pytest

from checks.test_source_render import config
from source_render import render
from deployment_profile import DeploymentProfile
from cluster_console_configuration import configure,adapter_code_update
from cluster_console_resources import private_network


def inputs(config):
    bundle, _, _ = render(config)
    profile = DeploymentProfile.from_dict(bundle['installation_profile'])
    objects = {(o['kind'], o['metadata']['name']): o for o in bundle['objects']}
    driver = objects['Deployment', 'fixture-identity-driver']
    adapter = objects['Deployment', 'fixture-protected-adapter']
    name, = [v['configMap']['name'] for v in driver['spec']['template']['spec']['volumes'] if v['name'] == 'code']
    return profile, driver, objects['ConfigMap', name], adapter


def test_private_listener_wiring_preserves_state_and_public_route(config):
    profile, driver, code, adapter = inputs(config)
    before = deepcopy((driver, code, adapter))
    new, updated = configure(profile, driver, code, adapter, [str(uuid4())],
                             {'coordinator_secret': 'c'*48, 'preparer_secret': 'p'*48})
    assert before == (driver, code, adapter)
    changed_adapter, changed_driver = updated
    old = {v['name']: v for v in driver['spec']['template']['spec']['volumes']}
    after = {v['name']: v for v in changed_driver['spec']['template']['spec']['volumes']}
    for name in ('state', 'credentials', 'tls', 'installation-profile'):
        assert after[name] == old[name]
    flags = json.loads(new[0]['data']['config.json'])
    assert flags['contexts'] == [] and flags['private_operator_api'] and flags['stateless_login']
    assert flags['jira_view_url'] == 'https://'+profile.service_host('fixture-protected-adapter')+':8443'
    assert set(new[1]['stringData']) == {'coordinator_secret', 'preparer_secret'}
    enabled = [c for c in changed_adapter['spec']['template']['spec']['containers']
               if any(e['name'] == 'JIRA_HISTORY_VIEW_ENABLED' for e in c['env'])]
    assert [c['name'] for c in enabled] == ['adapter-https']
    with pytest.raises(ValueError, match='already configured'):
        configure(profile, changed_driver, new[0], changed_adapter, [str(uuid4())], new[1]['stringData'])


def test_foreign_resources_and_reused_role_keys_are_refused(config):
    profile, driver, code, adapter = inputs(config)
    keys = {'coordinator_secret': 'c'*48, 'preparer_secret': 'c'*48}
    with pytest.raises(ValueError): configure(profile, driver, code, adapter, [str(uuid4())], keys)
    keys['preparer_secret'] = 'p'*48
    adapter['metadata']['namespace'] = 'foreign'
    with pytest.raises(ValueError): configure(profile, driver, code, adapter, [str(uuid4())], keys)


def test_existing_context_and_permission_configuration_survives_private_listener_migration(config):
    profile, driver, code, adapter = inputs(config)
    original = json.loads(code['data']['config.json'])
    original['contexts'] = [{'role': 'reader', 'workflow': 'cve', 'project': 'TEST',
                             'workload': 'spiffe://example.test/openshell/sandbox/'+str(uuid4())}]
    code['data']['config.json'] = json.dumps(original)
    new, changed = configure(profile, driver, code, adapter, [str(uuid4())],
                             {'coordinator_secret': 'c'*48, 'preparer_secret': 'p'*48})
    after = json.loads(new[0]['data']['config.json'])
    updated_flags = {'coordinator_enabled', 'presenter_subjects', 'stateless_login',
                     'private_operator_api', 'jira_view_url', 'jira_view_ca'}
    assert {k: v for k, v in after.items() if k not in updated_flags} == {
        k: v for k, v in original.items() if k not in updated_flags}
    before_volumes = {v['name']: v for v in driver['spec']['template']['spec']['volumes']}
    after_volumes = {v['name']: v for v in changed[1]['spec']['template']['spec']['volumes']}
    assert all(after_volumes[k] == v for k, v in before_volumes.items() if k != 'code')


def catalog_inputs(config):
    bundle,_,_=render(config);profile=DeploymentProfile.from_dict(bundle['installation_profile'])
    adapter=next(o for o in bundle['objects'] if o['kind']=='Deployment' and o['metadata']['name']=='fixture-protected-adapter')
    name,=[v['configMap']['name'] for v in adapter['spec']['template']['spec']['volumes'] if v['name']=='catalog-code']
    code=next(o for o in bundle['objects'] if o['kind']=='ConfigMap' and o['metadata']['name']==name)
    return profile,code,adapter


def test_catalog_code_update_changes_only_one_module_and_its_adapter_mount(config):
    profile,code,adapter=catalog_inputs(config);before=deepcopy((code,adapter))
    replacement='# SPDX-License-Identifier: Apache-2.0\n# reviewed catalog guard\n'
    new,changed=adapter_code_update(profile,adapter,code,replacement)
    assert before==(code,adapter) and new['immutable'] is True
    restored=deepcopy(new);restored['data']['adapter_discovery.py']=code['data']['adapter_discovery.py']
    assert restored['data']==code['data']
    restored=deepcopy(changed)
    for volume in restored['spec']['template']['spec']['volumes']:
        if volume['name']=='catalog-code':volume['configMap']['name']=code['metadata']['name']
    assert restored==adapter and new['metadata']['labels']==profile.labels
    assert new['metadata']['name']!=code['metadata']['name']


@pytest.mark.parametrize('change',['namespace','mutable','mount','missing-module','unchanged'])
def test_catalog_update_refuses_foreign_or_unrecorded_inputs(config,change):
    profile,code,adapter=catalog_inputs(config)
    source='# SPDX-License-Identifier: Apache-2.0\n# candidate\n'
    if change=='namespace':adapter['metadata']['namespace']='foreign'
    elif change=='mutable':code['immutable']=False
    elif change=='mount':
        for v in adapter['spec']['template']['spec']['volumes']:
            if v['name']=='catalog-code':v['configMap']['name']='foreign'
    elif change=='missing-module':code['data'].pop('adapter_discovery.py')
    else:source=code['data']['adapter_discovery.py']
    with pytest.raises(ValueError):adapter_code_update(profile,adapter,code,source)


def test_internal_oidc_path_survives_removing_broad_isolation_allowance(config):
    bundle, _, _ = render(config)
    profile = DeploymentProfile.from_dict(bundle['installation_profile'])
    isolation, = [o for o in bundle['objects'] if o['kind'] == 'NetworkPolicy'
                  and o['metadata']['name'] == 'fixture-isolation']
    before = deepcopy(isolation)
    resources, changed = private_network(profile, isolation)
    assert isolation == before
    rules = {o['metadata']['name']: o['spec'] for o in resources if o['kind'] == 'NetworkPolicy'}
    egress = rules['fixture-driver-issuer-egress']
    ingress = rules['fixture-driver-issuer-ingress']
    assert egress == {'podSelector': {'matchLabels': {'app': 'fixture-identity-driver'}},
        'policyTypes': ['Egress'], 'egress': [{'to': [{'podSelector': {'matchLabels': {'app': 'fixture-keycloak-upstream'}}}],
                                             'ports': [{'port': 8443, 'protocol': 'TCP'}]}]}
    assert ingress == {'podSelector': {'matchLabels': {'app': 'fixture-keycloak-upstream'}},
        'policyTypes': ['Ingress'], 'ingress': [{'from': [{'podSelector': {'matchLabels': {'app': 'fixture-identity-driver'}}}],
                                               'ports': [{'port': 8443, 'protocol': 'TCP'}]}]}
    # Private operator access stays limited to the two runtime services.
    private = rules['fixture-identity-operator']
    assert private['ingress'][0]['ports'] == [{'port': 8444, 'protocol': 'TCP'}]
    assert {v['podSelector']['matchLabels']['app'] for v in private['ingress'][0]['from']} == {
        'fixture-console-coordinator', 'fixture-console-preparer'}
    excluded = next(e['values'] for e in changed['spec']['podSelector']['matchExpressions'] if e['key'] == 'app')
    assert 'fixture-identity-driver' in excluded


def test_fixed_action_module_update_preserves_catalog_and_every_other_input(config):
    profile,code,adapter=catalog_inputs(config);before=deepcopy((code,adapter))
    replacement='# SPDX-License-Identifier: Apache-2.0\n# reviewed project-existence guard\n'
    new,changed=adapter_code_update(profile,adapter,code,code['data']['adapter_discovery.py'],action_source=replacement)
    assert before==(code,adapter)
    restored=deepcopy(new['data'])
    restored['identity_demo_jira_action_adapter.py']=code['data']['identity_demo_jira_action_adapter.py']
    assert restored==code['data']
    assert new['immutable'] is True and new['metadata']['labels']==profile.labels
    for volume in changed['spec']['template']['spec']['volumes']:
        if volume['name']=='catalog-code':volume['configMap']['name']=code['metadata']['name']
    assert changed==adapter


@pytest.mark.parametrize('missing',[False,True])
def test_fixed_action_update_cannot_add_a_module_or_use_unreviewed_source(config,missing):
    profile,code,adapter=catalog_inputs(config)
    if missing:code['data'].pop('identity_demo_jira_action_adapter.py')
    with pytest.raises(ValueError):
        adapter_code_update(profile,adapter,code,code['data']['adapter_discovery.py'],
                            action_source='# SPDX-License-Identifier: Apache-2.0\n' if missing else 'unreviewed')
