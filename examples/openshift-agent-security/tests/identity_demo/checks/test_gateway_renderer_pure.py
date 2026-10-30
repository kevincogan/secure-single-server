from copy import deepcopy
from types import SimpleNamespace
from pathlib import Path
import json,time
from unittest.mock import patch
import native_backend as backend
import gateway_credential_route as route
import probe_broker_discovery as shared
from run_binding import ReadRun
from sender_listener import HOST
from identity_demo_keycloak_upstream import BASE
from deployment_profile import active_profile


def inputs():
    authorizer={'spec':{'priority':-1,'configPatches':[{'applyTo':'CLUSTER','patch':{'operation':'ADD','value':{'name':'kuadrant-auth-service','load_assignment':{'endpoints':[{'lb_endpoints':[{'endpoint':{'address':{'socket_address':{'address':route.AUTHORIZER+'.cluster.local','port_value':50051}}}}]}]}}}}]}}
    ext_proc={'applyTo':'HTTP_FILTER','match':{'listener':{'portNumber':8443}},'patch':{'operation':'INSERT_BEFORE','value':{'name':'envoy.filters.http.ext_proc','typed_config':{'failure_mode_allow':False,'grpc_service':{'envoy_grpc':{'cluster_name':'outbound|50051||mcp-gateway.'+shared.NS+'.svc.cluster.local'}}}}}}
    generated={'metadata':{'labels':{'mcp.kuadrant.io/extension-name':'fixture-mcp','mcp.kuadrant.io/extension-namespace':shared.NS}},'spec':{'workloadSelector':{'labels':{'gateway.networking.k8s.io/gateway-name':'fixture-mcp'}},'configPatches':[ext_proc]}}
    gateway={'metadata':{'name':'fixture-mcp','uid':'fixture-uid','resourceVersion':'1'},'spec':{'listeners':[{'name':'bound','hostname':HOST,'protocol':'HTTPS','port':8443,'tls':{'mode':'Terminate'}}]}}
    return {'baseline':authorizer,'extension':{'spec':{'targetRef':{'sectionName':'bound'}}},'generated':generated,'gateway':gateway,'driver':{'data':{'gateway_secret':'synthetic-only'}}}


def binding():
    return ReadRun('persistent-template',BASE+'/realms/identity-demo','unassigned','spiffe://'+active_profile().trust_domain+'/openshell/sandbox/unassigned','https://'+HOST+'/mcp',1,2)



def test_pure_gateway_renderer_matches_baseline_and_does_not_read_api(monkeypatch):
    import hashlib
    import gateway_renderer
    def forbidden(*args,**kwargs):
        raise AssertionError('renderer performed an API operation')
    monkeypatch.setattr(shared,'owned',forbidden)
    monkeypatch.setattr(shared,'kube',forbidden)
    values,gateway,spec,operations=gateway_renderer.render(
        '-----BEGIN CERTIFICATE-----synthetic-----END CERTIFICATE-----',
        'synthetic-service-credential',binding(),{'token':'discovery_'+'a'*43},inputs(),
        action_driver=True,enable_create=True)
    actual={'objects':values,'gateway':gateway,'spec':spec}
    assert len(values)==11
    assert hashlib.sha256(json.dumps(actual,sort_keys=True,separators=(',',':')).encode()).hexdigest() == '484e94170a296ddbf535b8b4bcbbc02188e3be7546f329736c15eead92afc32a'
    assert operations[0] == {'op':'test','path':'/metadata/uid','value':'fixture-uid'}


def test_pure_renderer_rejects_changed_generated_router():
    import pytest
    import gateway_renderer
    bad=inputs();bad['generated']['spec']['configPatches'][0]['patch']['value']['typed_config']['failure_mode_allow']=True
    with pytest.raises(ValueError,match='router transport'):
        gateway_renderer.render('-----BEGIN CERTIFICATE-----synthetic','synthetic-service-credential',binding(),{'token':'discovery_'+'a'*43},bad,action_driver=True,enable_create=True)
