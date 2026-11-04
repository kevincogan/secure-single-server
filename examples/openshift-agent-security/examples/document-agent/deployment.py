# SPDX-License-Identifier: Apache-2.0
"""Pure, optional document proof resources; no cluster operations or credentials."""
from copy import deepcopy
import json
import re
from urllib.parse import urlparse


def render(config, credentials):
    p=config['profile'];ns=p['core_namespace'];owner=p['owner']
    image=config['image']
    if (not re.fullmatch(r'[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}',image)
            or len(config['contexts'])!=3
            or any(c['role'] not in {'publisher','reader'} for c in config['contexts'])):
        raise ValueError('Immutable reviewed image and three exact execution contexts required')
    labels={'identity-demo-owner':owner,'identity-demo-installation':p['installation_id'],
        'identity-demo-document-proof':'true','app.kubernetes.io/part-of':'identity-demo-preflight'}
    def obj(api,kind,name,**fields):
        return {'apiVersion':api,'kind':kind,'metadata':{'name':name,'namespace':ns,'labels':dict(labels)},**fields}
    values=[]
    def append(api,kind,name,**fields):
        v=obj(api,kind,name,**fields);values.append(v);return v
    append('v1','ServiceAccount','fixture-document-proof',automountServiceAccountToken=False)
    host='fixture-document-host';backend='fixture-document-backend'
    def dns(name):return name+'.'+ns+'.svc.cluster.local'
    for name,ports in [(host,[('tools',443,8443),('control',8444,8444)]),(backend,[('https',8443,8443)])]:
        service=append('v1','Service',name,spec={'selector':{'app':name},'ports':[
            {'name':n,'port':a,'targetPort':b} for n,a,b in ports]})
        service['metadata']['annotations']={'service.beta.openshift.io/serving-cert-secret-name':name+'-tls'}
        append('v1','PersistentVolumeClaim',name,spec={'accessModes':['ReadWriteOnce'],
            'storageClassName':p['storage_class'],'resources':{'requests':{'storage':'1Gi'}}})
    for name,data in [('fixture-document-host-keys',credentials),
                      ('fixture-document-backend-write',{'write':credentials['write']}),
                      ('fixture-document-backend-observe',{'observe':credentials['observe']})]:
        append('v1','Secret',name,type='Opaque',stringData=data)
    append('v1','ConfigMap','fixture-document-trust',data={
        'service-ca.pem':config['service_ca'],'issuer-ca.pem':config['issuer_ca']})
    origin='https://fixture-document-control-'+ns+'.'+p['route_domain']
    audience='https://'+dns('fixture-mcp-bound')+'/mcp'
    common={'database':'/state/private/history.db','certificate':'/tls/tls.crt','private_key':'/tls/tls.key'}
    host_config={**common,'host':{'issuer':config['issuer'],'issuer_service':config['issuer_service'],
        'issuer_ca':'/trust/issuer-ca.pem','client':'document-proof-ui','origin':origin,'audience':audience,
        'trust_domain':p['trust_domain'],'contexts':config['contexts']},
        'operator_key_file':'/keys/operator','backend_write_key_file':'/keys/write',
        'backend_observe_key_file':'/keys/observe','backend_origin':'https://'+dns(backend)+':8443',
        'backend_ca':'/trust/service-ca.pem'}
    backend_config={**common,'port':8443,'write_key_file':'/write/write','observe_key_file':'/observe/observe',
        'lose_response_revision':3}
    for name,module,cfg in [(host,'service',host_config),(backend,'backend',backend_config)]:
        append('v1','ConfigMap',name+'-configuration',data={'configuration.json':json.dumps(cfg,sort_keys=True)})
        mounts=[{'name':'state','mountPath':'/state'},{'name':'temporary','mountPath':'/tmp'},
            {'name':'tls','mountPath':'/tls','readOnly':True},{'name':'configuration','mountPath':'/configuration','readOnly':True}]
        volumes=[{'name':'state','persistentVolumeClaim':{'claimName':name}},
            {'name':'temporary','emptyDir':{}},{'name':'tls','secret':{'secretName':name+'-tls'}},
            {'name':'configuration','configMap':{'name':name+'-configuration'}}]
        if name==host:
            for key,kind,resource in [('keys','secret','fixture-document-host-keys'),('trust','configMap','fixture-document-trust')]:
                volumes.append({'name':key,kind:{'secretName' if kind=='secret' else 'name':resource}})
                mounts.append({'name':key,'mountPath':'/'+key,'readOnly':True})
        else:
            for key in ['write','observe']:
                volumes.append({'name':key,'secret':{'secretName':'fixture-document-backend-'+key}})
                mounts.append({'name':key,'mountPath':'/'+key,'readOnly':True})
        container={'name':module,'image':image,'command':['python3.12','/app/document-agent/'+module+'.py'],
            'env':[{'name':'DOCUMENT_'+('HOST' if name==host else 'BACKEND')+'_CONFIG','value':'/configuration/configuration.json'}],
            'ports':[{'containerPort':8443}]+([{'containerPort':8444}] if name==host else []),
            'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},
            'resources':{'requests':{'cpu':'50m','memory':'128Mi'},'limits':{'cpu':'500m','memory':'512Mi'}},
            'volumeMounts':mounts,'readinessProbe':{'tcpSocket':{'port':8443},'initialDelaySeconds':3,'periodSeconds':3}}
        append('apps/v1','Deployment',name,spec={'replicas':1,'strategy':{'type':'Recreate'},
            'selector':{'matchLabels':{'app':name}},'template':{'metadata':{'labels':{**labels,'app':name}},
            'spec':{'serviceAccountName':'fixture-document-proof','automountServiceAccountToken':False,
                'securityContext':{'runAsNonRoot':True,'seccompProfile':{'type':'RuntimeDefault'}},
                'containers':[container],'volumes':volumes}}})
    append('route.openshift.io/v1','Route','fixture-document-control',spec={
        'host':urlparse(origin).hostname,'to':{'kind':'Service','name':host},'port':{'targetPort':'control'},
        'tls':{'termination':'reencrypt','insecureEdgeTerminationPolicy':'Redirect','destinationCACertificate':config['service_ca']}})
    append('gateway.networking.k8s.io/v1','HTTPRoute','fixture-document-proof',spec={
        'parentRefs':[{'name':'fixture-mcp','sectionName':'bound'}],
        'hostnames':[dns('fixture-mcp-bound')],
        'rules':[{'matches':[{'path':{'type':'Exact','value':'/_document_proof/mcp'}}],
            'filters':[{'type':'URLRewrite','urlRewrite':{'path':{'type':'ReplaceFullPath','replaceFullPath':'/mcp'}}}],
            'backendRefs':[{'name':host,'port':443}]}]})
    append('networking.istio.io/v1beta1','DestinationRule','fixture-document-proof-tls',spec={
        'host':dns(host),'workloadSelector':{'matchLabels':{'gateway.networking.k8s.io/gateway-name':'fixture-mcp'}},
        'trafficPolicy':{'tls':{'mode':'SIMPLE','sni':dns(host),'subjectAltNames':[dns(host)],
            'caCertificates':'/var/run/secrets/kubernetes.io/serviceaccount/service-ca.crt'}}})
    # Policies are additive. Existing default-deny remains in force. The agent
    # namespaces receive no ingress grant to either document service.
    gateway={'podSelector':{'matchLabels':{'gateway.networking.k8s.io/gateway-name':'fixture-mcp'}}}
    router={'namespaceSelector':{'matchLabels':{'kubernetes.io/metadata.name':'openshift-ingress'}}}
    dns_peer={'namespaceSelector':{'matchLabels':{'kubernetes.io/metadata.name':'openshift-dns'}}}
    for name,ingress,egress in [
        (backend,[{'from':[{'podSelector':{'matchLabels':{'app':host}}}],'ports':[{'protocol':'TCP','port':8443}]}],[]),
        (host,[{'from':[gateway],'ports':[{'protocol':'TCP','port':8443}]},
               {'from':[router],'ports':[{'protocol':'TCP','port':8444}]}],
              [{'to':[{'podSelector':{'matchLabels':{'app':backend}}},
                      {'podSelector':{'matchLabels':{'app':'fixture-keycloak-upstream'}}}],
                'ports':[{'protocol':'TCP','port':8443}]},
               {'to':[dns_peer],'ports':[{'protocol':'UDP','port':5353},{'protocol':'TCP','port':5353}]}])]:
        append('networking.k8s.io/v1','NetworkPolicy',name,spec={'podSelector':{'matchLabels':{'app':name}},
            'policyTypes':['Ingress','Egress'],'ingress':ingress,'egress':egress})
    append('networking.k8s.io/v1', 'NetworkPolicy', 'fixture-document-gateway-egress', spec={
        'podSelector': gateway['podSelector'], 'policyTypes': ['Egress'], 'egress': [{
            'to': [{'podSelector': {'matchLabels': {'app': host}}}],
            'ports': [{'protocol': 'TCP', 'port': 8443}]}]})
    return values


def isolated_route_filter(namespace,owner,route_name):
    """Apply only to the independently observed exact document route.

    This route has its own complete JWT/run/peer/effect enforcement in the host.
    Jira's unchanged authorization and MCP broker filters remain on /mcp.
    """
    if (not route_name or len(route_name)>256 or 'fixture-document-proof' not in route_name
            or namespace not in route_name):
        raise ValueError('Observed exact owned document route required')
    return {'apiVersion':'networking.istio.io/v1alpha3','kind':'EnvoyFilter','metadata':{
        'name':'fixture-document-proof-route','namespace':namespace,
        'labels':{'identity-demo-owner':owner,'identity-demo-document-proof':'true','istio.io/rev':'openshift-gateway'}},
        'spec':{'priority':10,'workloadSelector':{'labels':{'gateway.networking.k8s.io/gateway-name':'fixture-mcp'}},
        'configPatches':[{'applyTo':'HTTP_ROUTE','match':{'context':'GATEWAY','routeConfiguration':{
            'portNumber':8443,'vhost':{'name':'fixture-mcp-bound.'+namespace+'.svc.cluster.local:8443','route':{'name':route_name}}}},'patch':{'operation':'MERGE','value':{
                'route': {'retry_policy': {'num_retries': 0}},
                'typed_per_filter_config':{
                    'envoy.filters.http.ext_proc':{'@type':'type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExtProcPerRoute','disabled':True},
                    'envoy.filters.http.ext_authz.step56_identity':{'@type':'type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute','disabled':True},
                    'identity-demo.adapter-credential-step4':{'@type':'type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute','disabled':True}
                }}}}]}}


def narrow_namespace_policy(current):
    """Exclude only the new services from the candidate's additive broad allow."""
    desired = deepcopy(current['spec'])
    expressions = desired.get('podSelector', {}).get('matchExpressions', [])
    app, = [v for v in expressions if v.get('key') == 'app' and v.get('operator') == 'NotIn']
    reviewed = ['fixture-protected-adapter', 'fixture-jira']
    if (app.get('values') not in (reviewed, reviewed + ['fixture-identity-driver',
                'fixture-console-coordinator', 'fixture-console-preparer'])
            or desired.get('ingress') != [{'from': [{'podSelector': {}}]}]
            or set(desired.get('policyTypes', [])) != {'Ingress', 'Egress'}):
        raise ValueError('Exact reviewed candidate broad-allow policy required')
    app['values'] += ['fixture-document-host', 'fixture-document-backend']
    return desired
