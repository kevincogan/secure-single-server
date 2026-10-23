# SPDX-License-Identifier: Apache-2.0
"""Parallel installations cannot select another installation's Authorino policy."""
from copy import deepcopy

import pytest

from deployment_profile import DeploymentProfile, LEGACY
import gateway_credential_route as route
import identity_demo_action_policy as action
from run_binding import ReadRun
import native_backend


def profile(namespace):
    return DeploymentProfile.from_dict({**LEGACY.to_dict(),'core_namespace':namespace,'installation_id':'parallel'})


def configured_filter(selected):
    return {'kind':'EnvoyFilter','metadata':{'name':route.READ_NAME,'namespace':selected.core_namespace,
        'uid':'original-filter'},'spec':{'configPatches':[
            {'applyTo':'VIRTUAL_HOST','match':{'routeConfiguration':{'portNumber':port,
                'vhost':{'name':route.READ_HOST+':'+str(port)}}},'patch':{'value':{'typed_per_filter_config':{
                    route.FILTER+'-step4':{'check_settings':{'context_extensions':{
                        'host':selected.private_mcp_authorization_host}}}}}}} for port in (8080,8443)]}}


def test_private_authorization_key_is_namespace_specific_without_profile_schema_change():
    assert profile('customer-a').private_mcp_authorization_host != profile('customer-b').private_mcp_authorization_host
    assert LEGACY.private_mcp_authorization_host == route.READ_HOST
    assert DeploymentProfile.from_dict(profile('customer-a').to_dict()) == profile('customer-a')


def test_full_envoy_observation_requires_both_contexts_and_rejects_wrong_selection(monkeypatch):
    selected=profile('customer-a')
    monkeypatch.setattr(native_backend,'active_profile',lambda:selected)
    configs=[{'route_config':{'name':'http.8080' if port==8080 else 'https.8443.bound','virtual_hosts':[{'domains':[route.READ_HOST],
        'typed_per_filter_config':{route.FILTER+'-step4':{'check_settings':{
            'context_extensions':{'host':selected.private_mcp_authorization_host}}}}}]}} for port in (8080,8443)]
    dump={'configs':configs}
    assert native_backend.private_authorizer_context(dump)
    assert not native_backend.private_authorizer_context({'configs':configs[:1]})
    configs[1]['route_config']['virtual_hosts'][0]['typed_per_filter_config'][route.FILTER+'-step4']['check_settings']['context_extensions']['host']='another-installation'
    assert not native_backend.private_authorizer_context(dump)


def test_redacted_context_requires_exact_source_and_cannot_hide_a_route_override(monkeypatch):
    selected=profile('customer-a');expected=configured_filter(selected)
    monkeypatch.setattr(native_backend,'active_profile',lambda:selected)
    hosts=[{'domains':[route.READ_HOST],'typed_per_filter_config':{route.FILTER+'-step4':{
        'check_settings':{'context_extensions':{'host':'[redacted]'}}}}} for _ in range(2)]
    dump={'configs':[{'route_config':{'name':name,'virtual_hosts':[h]}} for name,h in zip(('http.8080','https.8443.bound'),hosts,strict=True)]}
    assert not native_backend.private_authorizer_context(dump)
    assert native_backend.private_authorizer_context(dump,expected)
    changed=deepcopy(expected);changed['spec']['configPatches'][0]['patch']['value']['typed_per_filter_config'][route.FILTER+'-step4']['check_settings']['context_extensions']['host']='foreign'
    assert not native_backend.private_authorizer_context(dump,changed)
    hosts[1]['routes']=[{'typed_per_filter_config':{route.FILTER+'-step4':{'disabled':False}}}]
    assert not native_backend.private_authorizer_context(dump,expected)


def test_changed_receipt_backed_filter_cannot_use_redaction_fallback(monkeypatch):
    from argparse import Namespace
    selected=profile('customer-a');expected=configured_filter(selected)
    probe=native_backend.NativeBackend(Namespace());probe.ledger=[expected]
    changed=deepcopy(expected);changed['metadata']['uid']='replacement'
    monkeypatch.setattr(native_backend.shared,'owned',lambda *a:changed)
    with pytest.raises(ValueError,match='source changed'):probe.authorizer_context({})


@pytest.mark.parametrize('namespace',['customer-a','customer-b'])
def test_trusted_envoy_context_selects_own_policy_without_changing_receiver(namespace,monkeypatch):
    selected=profile(namespace)
    monkeypatch.setattr(route,'active_profile',lambda:selected)
    monkeypatch.setattr(route,'NS',namespace)
    monkeypatch.setattr(action,'active_profile',lambda:selected)
    run=ReadRun('synthetic',selected.origin('fixture-keycloak-upstream')+'/realms/identity-demo',
        'human','spiffe://'+selected.trust_domain+'/openshell/sandbox/synthetic',
        'https://'+selected.service_host('fixture-mcp-bound')+'/mcp',1,2)
    values=route.native_manifests('-----BEGIN CERTIFICATE-----','synthetic-service-secret',run)
    assert values[1]['spec']['hosts']==[selected.private_mcp_authorization_host]
    assert values[2]['spec']['hostnames']==[route.READ_HOST]
    before=deepcopy(values[1]['spec']);secured=action.adapter_rules(before,write_scope=True)
    assert secured['metadata']['adapter-token']['when']==[{'predicate':action.ALLOWED}]
    assert secured['metadata']['driver-decision']['priority'] < secured['metadata']['adapter-token']['priority']
    enabled=[]
    for item in values[3]['spec']['configPatches']:
        if item['applyTo']!='VIRTUAL_HOST':continue
        configs=item['patch']['value']['typed_per_filter_config']
        for config in configs.values():
            if config.get('disabled') is True:continue
            enabled.append(config)
            assert 'disabled' not in config
            assert config['check_settings']=={'context_extensions':{'host':selected.private_mcp_authorization_host}}
    assert len(enabled)==2  # Both private broker and bound listeners retain mediation.
    before['hosts']=[route.READ_HOST]
    with pytest.raises(ValueError,match='receiving route'):action.adapter_rules(before)
