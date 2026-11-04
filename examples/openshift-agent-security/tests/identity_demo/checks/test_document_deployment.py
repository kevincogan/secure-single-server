# SPDX-License-Identifier: Apache-2.0
"""Pure resources cannot grant the document agent host/backend authority."""
import importlib.util
from pathlib import Path
from uuid import uuid4

import pytest


@pytest.fixture
def module():
    source=Path(__file__).resolve().parents[3]/'examples/document-agent/deployment.py'
    spec=importlib.util.spec_from_file_location('document_deployment',source)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


def rendered(module):
    config={'profile':{'core_namespace':'fresh-core','owner':'test-owner','installation_id':'fresh',
        'storage_class':'approved','route_domain':'apps.example.test','trust_domain':'test.example.test'},
        'image':'registry.example.test/documents@sha256:'+'a'*64,
        'contexts':[{'name':name,'workload':'spiffe://test.example.test/openshell/sandbox/'+str(uuid4()),
            'role':role,'collection':'engineering'} for name,role in [('publisher','publisher'),('viewer','publisher'),('reader','reader')]],
        'issuer':'https://issuer.example.test/realms/evaluation','issuer_service':'https://issuer.fresh-core.svc:8443/realms/evaluation',
        'service_ca':'PUBLIC SERVICE CA','issuer_ca':'PUBLIC ISSUER CA'}
    return module.render(config,{'operator':'operator-key-'*4,'write':'write-key-'*4,'observe':'observe-key-'*4})


def test_separate_authority_mounts_and_tokenless_restricted_execution(module):
    values=rendered(module)
    deployments=[v for v in values if v['kind']=='Deployment']
    assert len(deployments)==2
    for item in deployments:
        pod=item['spec']['template']['spec'];container=pod['containers'][0]
        assert pod['automountServiceAccountToken'] is False
        assert pod['securityContext']['runAsNonRoot'] and container['securityContext']['readOnlyRootFilesystem']
        assert all(not any(k in volume for k in ['hostPath','csi','projected']) for volume in pod['volumes'])
    backend=next(v for v in deployments if v['metadata']['name']=='fixture-document-backend')
    refs=[v.get('secret',{}).get('secretName') for v in backend['spec']['template']['spec']['volumes']]
    assert 'fixture-document-host-keys' not in refs
    assert not any(v['kind'] in {'Role','RoleBinding','ClusterRole','ClusterRoleBinding'} for v in values)
    routes=[v for v in values if v['kind']=='Route']
    assert len(routes)==1 and routes[0]['spec']['port']['targetPort']=='control'
    assert routes[0]['spec']['tls']['termination']=='reencrypt'


def test_only_gateway_can_reach_tools_and_only_host_can_reach_backend(module):
    values=rendered(module)
    policies={v['metadata']['name']:v['spec'] for v in values if v['kind']=='NetworkPolicy'}
    backend=policies['fixture-document-backend']
    assert backend['egress']==[]
    assert backend['ingress']==[{'from':[{'podSelector':{'matchLabels':{'app':'fixture-document-host'}}}],
        'ports':[{'protocol':'TCP','port':8443}]}]
    host=policies['fixture-document-host']
    assert host['ingress'][0]['from']==[{'podSelector':{'matchLabels':{'gateway.networking.k8s.io/gateway-name':'fixture-mcp'}}}]
    assert all(p['port']==8443 for p in host['ingress'][0]['ports'])


def test_document_route_rewrites_only_its_own_path_and_uses_verified_tls(module):
    values=rendered(module)
    route=next(v for v in values if v['kind']=='HTTPRoute')
    assert route['spec']['rules'][0]['matches']==[{'path':{'type':'Exact','value':'/_document_proof/mcp'}}]
    assert route['spec']['rules'][0]['backendRefs']==[{'name':'fixture-document-host','port':443}]
    tls=next(v for v in values if v['kind']=='DestinationRule')
    assert tls['spec']['host']=='fixture-document-host.fresh-core.svc.cluster.local'
    policy=tls['spec']['trafficPolicy']['tls']
    assert policy['mode']=='SIMPLE' and policy['subjectAltNames']==[tls['spec']['host']]
    assert policy['sni']==tls['spec']['host'] and policy['caCertificates'].endswith('/service-ca.crt')
    assert tls['spec']['workloadSelector']=={'matchLabels':{'gateway.networking.k8s.io/gateway-name':'fixture-mcp'}}
    for key in ('/', '/mcp', 'unrelated-route'):
        with pytest.raises(ValueError):module.isolated_route_filter('fresh-core','test-owner',key)
    envoy=module.isolated_route_filter('fresh-core','test-owner','fresh-core/fixture-document-proof/rule/0/match/0')
    patch,=envoy['spec']['configPatches']
    assert set(patch['patch']['value']['typed_per_filter_config']) == {
        'envoy.filters.http.ext_proc', 'envoy.filters.http.ext_authz.step56_identity',
        'identity-demo.adapter-credential-step4'}
    assert patch['applyTo']=='HTTP_ROUTE'
    match=patch['match']['routeConfiguration']
    assert match['portNumber']==8443 and match['vhost']['route']['name'].startswith('fresh-core/fixture-document-proof/')


@pytest.mark.parametrize('workers', [[], ['fixture-identity-driver', 'fixture-console-coordinator', 'fixture-console-preparer']])
def test_optional_services_are_excluded_from_additive_namespace_allow(module, workers):
    original = {'spec': {'podSelector': {'matchExpressions': [{'key': 'app', 'operator': 'NotIn',
        'values': ['fixture-protected-adapter', 'fixture-jira'] + workers}]},
        'policyTypes': ['Ingress', 'Egress'], 'ingress': [{'from': [{'podSelector': {}}]}],
        'egress': [{'to': [{'podSelector': {}}]}]}}
    desired = module.narrow_namespace_policy(original)
    assert desired['podSelector']['matchExpressions'][0]['values'][-2:] == ['fixture-document-host', 'fixture-document-backend']
    assert original['spec']['podSelector']['matchExpressions'][0]['values'] == ['fixture-protected-adapter', 'fixture-jira'] + workers
    assert desired['egress'] == original['spec']['egress']
    original['spec']['ingress'] = [{}]
    with pytest.raises(ValueError):
        module.narrow_namespace_policy(original)
