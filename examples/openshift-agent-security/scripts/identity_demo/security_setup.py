# SPDX-License-Identifier: Apache-2.0
"""Guided security setup: render reviewed manifests and inspect readiness only.

This module never creates, patches, approves or deletes a cluster resource.
Controller installation remains an explicit platform-administrator operation.
"""
from __future__ import annotations
import json
from ipaddress import ip_network
from deployment_profile import DeploymentProfile
from identity_demo_setup import ROOT, kube, private_file, write, owned


def object_for(profile, api, kind, name, spec=None, namespace=None):
    obj = {'apiVersion': api, 'kind': kind, 'metadata': {'name': name, 'labels': dict(profile.labels)}}
    if namespace: obj['metadata']['namespace'] = namespace
    if spec is not None: obj['spec'] = spec
    return obj


def validate_network(network):
    if not isinstance(network, dict) or set(network) != {'api_cidrs', 'worker_cidrs'}:
        raise ValueError('Exact API and worker host-CIDR lists required')
    for values in network.values():
        if not isinstance(values, list) or not 0 < len(values) <= 200 or any(not isinstance(v, str) for v in values) or len(set(values)) != len(values):
            raise ValueError('Bounded unique host-CIDR lists required')
        for value in values:
            address = ip_network(value, strict=True)
            if address.prefixlen != address.max_prefixlen or address.is_unspecified or address.is_multicast:
                raise ValueError('Exact unicast host CIDRs required; broad ranges refused')
    return network


def render(profile, network):
    if profile.identity_namespace in {"agent-sandbox-system", "kuadrant-system"}:
        raise ValueError("Identity namespace must be distinct from other operator namespaces")
    network = validate_network(network)
    lock = json.loads((ROOT/'infra/identity-demo/prerequisites.lock.json').read_text())
    namespaces = [object_for(profile, 'v1', 'Namespace', n) for n in (profile.identity_namespace, 'agent-sandbox-system', 'kuadrant-system')]
    namespaces[0]['metadata']['labels']['pod-security.kubernetes.io/enforce'] = 'privileged'
    operators = []
    for ns in (profile.identity_namespace, 'agent-sandbox-system', 'kuadrant-system'):
        spec = {'targetNamespaces': [ns]} if ns == profile.identity_namespace else {}
        operators.append(object_for(profile, 'operators.coreos.com/v1', 'OperatorGroup', 'identity-demo-operators', spec, ns))
    for entry in lock['operators']:
        ns = entry['namespace'].replace('{identity_namespace}', profile.identity_namespace)
        if entry['package'] == 'rhcl-operator': ns = 'kuadrant-system'
        operators.append(object_for(profile, 'operators.coreos.com/v1alpha1', 'Subscription', 'identity-demo-'+entry['package'],
            {'name':entry['package'], 'channel':entry['channel'], 'startingCSV':entry['csv'], 'installPlanApproval':'Manual',
             'source':lock['catalog']['name'], 'sourceNamespace':lock['catalog']['namespace']}, ns))
    templates = (ROOT/'infra/identity-demo/security-foundation.json').read_text()
    for key, value in profile.to_dict().items(): templates = templates.replace('{'+key+'}', str(value))
    foundation = json.loads(templates)
    for obj in foundation:
        if obj['kind'] == 'ResourceQuota': obj['spec']['hard']['pods'] = str(8+2*len(network['worker_cidrs']))
    policies = [o for o in foundation if o['kind'] in ('NetworkPolicy','ResourceQuota')]+networking(profile, network)
    identity = [o for o in foundation if o['kind'] in ('ZeroTrustWorkloadIdentityManager','SpireServer','SpireAgent','SpiffeCSIDriver')]
    discovery = [o for o in foundation if o not in identity and o['kind'] not in ('NetworkPolicy','ResourceQuota')]
    gateway = [object_for(profile,'gateway.networking.k8s.io/v1','GatewayClass',lock['gateway_class'],{'controllerName':lock['gateway_controller']}),
               object_for(profile,'kuadrant.io/v1beta1','Kuadrant','kuadrant',{},'kuadrant-system')]
    return {'namespaces':namespaces,'operators':operators,'network':policies,'identity':identity,'discovery':discovery,'gateway':gateway}


def ready(value, *, daemon=False):
    status=value.get('status',{});spec=value.get('spec',{})
    if status.get('observedGeneration',0) < value['metadata']['generation']: return False
    if daemon:
        desired=status.get('desiredNumberScheduled',0)
        return desired > 0 and status.get('numberReady') == desired and status.get('updatedNumberScheduled') == desired
    desired=spec.get('replicas',1)
    return desired > 0 and status.get('readyReplicas',0) >= desired and status.get('updatedReplicas',status.get('currentReplicas',0)) >= desired


def validate_ca_bundle(value):
    from cryptography import x509
    from datetime import datetime, timezone
    certs=x509.load_pem_x509_certificates(value.encode());now=datetime.now(timezone.utc)
    # SPIRE overlap bundles may retain an expired retiring CA. TLS validates the
    # actual presented chain; require CA-only contents and an active trust anchor.
    if not certs or any(not c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca for c in certs) or not any(c.not_valid_before_utc <= now < c.not_valid_after_utc for c in certs):
        raise ValueError('CA-only bundle with a current trust anchor required')
    return certs


def verify(args, profile):
    from identity_demo_setup import target
    args.profile=profile
    write(args.output_dir/"00-target.pending.json", {"check":"API, TLS, ownership, matching domain and required APIs"})
    target(args)
    write(args.output_dir/"00-target.receipt.json", {"passed":True})
    checks=[]
    for kind,name,ns,daemon in [('statefulset','spire-server',profile.identity_namespace,False),
          ('daemonset','spire-agent',profile.identity_namespace,True),('daemonset','spire-spiffe-csi-driver',profile.identity_namespace,True),
          ('deployment','identity-demo-oidc-discovery',profile.identity_namespace,False),
          ('deployment','authorino','kuadrant-system',False),('deployment','istiod-openshift-gateway','openshift-ingress',False)]:
        write(args.output_dir/('controller-'+name+'.pending.json'),{'kind':kind,'name':name,'namespace':ns})
        value=kube(args,'get',kind,name,'-n',ns,'-o','json')
        if ns == profile.identity_namespace and value.get('metadata',{}).get('labels',{}).get('identity-demo-owner') != profile.owner: raise ValueError('Owned identity controller required')
        if not ready(value,daemon=daemon): raise ValueError('A required security controller is not ready')
        write(args.output_dir/('controller-'+name+'.receipt.json'),{'passed':True})
        checks.append(kind+'/'+name)
    write(args.output_dir/'discovery.pending.json',{'check':'issuer and exact current Pod attestation'})
    issuer='https://spire-spiffe-oidc-discovery-provider.'+profile.identity_namespace+'.svc:8443'
    server=kube(args,'get','spireserver','cluster','-o','json')
    if server.get('metadata',{}).get('labels',{}).get('identity-demo-owner') != profile.owner: raise ValueError('Owned SPIRE server required')
    if server.get('spec',{}).get('jwtIssuer') != issuer: raise ValueError('Discovery issuer contract mismatch')
    operands=kube(args,'get','spireoidcdiscoveryproviders','-o','json')
    if operands.get('items'): raise ValueError('Do not mix broad operator discovery with this exact-Pod discovery deployment')
    entry=kube(args,'get','clusterstaticentry','identity-demo-oidc-discovery','-o','json');owned(entry,profile)
    if entry.get('spec',{}).get('spiffeID') != 'spiffe://'+profile.trust_domain+'/oidc/discovery': raise ValueError('Discovery SPIFFE identity mismatch')
    # The established attestation helper checks the live Pod, image, selectors and PSAT parent.
    import os,subprocess,sys
    env={**os.environ,'IDENTITY_DEMO_CONFIG':str(args.installation_profile)};env.pop('IDENTITY_DEMO_ARTIFACTS',None)
    registration=args.output_dir/'discovery-observed.private.json'
    result=subprocess.run([sys.executable,str(ROOT/'scripts/identity_demo/identity_demo_discovery_registration.py'),
         '--kubeconfig',args.kubeconfig,'--output',str(registration)],env=env,capture_output=True,timeout=300)
    if result.returncode: raise ValueError('Current exact-Pod discovery attestation could not be verified')
    if json.loads(registration.read_text())['spec'] != entry['spec']: raise ValueError('Discovery registration is stale')
    write(args.output_dir/'discovery.receipt.json',{'passed':True})
    write(args.output_dir/'authorino-tls.pending.json',{'check':'authorization TLS'})
    auth=kube(args,'get','authorinos.operator.authorino.kuadrant.io','authorino','-n','kuadrant-system','-o','json')
    tls=auth.get('spec',{}).get('listener',{}).get('tls',{})
    if tls.get('enabled') is not True or tls.get('certSecretRef',{}).get('name') != 'authorino-server-cert': raise ValueError('Verified Authorino TLS configuration required')
    write(args.output_dir/'authorino-tls.receipt.json',{'passed':True})
    for cm,key,name in [('identity-demo-oidc-service-ca','service-ca.crt','service-ca.pem'),('spire-bundle','bundle.crt','spire-ca.pem')]:
        write(args.output_dir/(name+'.pending.json'),{'check':'CA-only bundle with a current anchor'})
        value=kube(args,'get','configmap',cm,'-n',profile.identity_namespace,'-o','json')['data'][key]
        validate_ca_bundle(value)
        p=args.output_dir/name;p.write_text(value);p.chmod(0o600)
        write(args.output_dir/(name+'.receipt.json'),{'passed':True})
    return {'security_configuration_ready':True,'checked_controllers':checks,'exact_discovery_attestation_verified':True,
            'public_trust_exported':True,'cluster_changed':False,'end_to_end_authorization_proven':False,'fresh_installation_proven':False,
            'manager_status_note':'The intentionally unused operator OIDC operand can leave the aggregate manager NotReady; required operands and exact-Pod discovery are checked individually.'}


def tls_review(profile, kuadrant, authorino, service):
    owned(kuadrant,profile)
    for value,kind,parent in [(authorino,'Kuadrant',kuadrant),(service,'Authorino',authorino)]:
        if value['metadata'].get('namespace') != 'kuadrant-system' or not any(r.get('controller') and r.get('kind')==kind and r.get('uid')==parent['metadata']['uid'] for r in value['metadata'].get('ownerReferences',[])):
            raise ValueError('Exact owned Kuadrant/Authorino/Service chain required')
    annotation='service.beta.openshift.io/serving-cert-secret-name'
    annotations=dict(service['metadata'].get('annotations',{}))
    if annotations.get(annotation) not in (None,'authorino-server-cert'): raise ValueError('Serving certificate collision')
    annotations[annotation]='authorino-server-cert'
    listener=dict(authorino.get('spec',{}).get('listener',{}))
    listener['tls']={'enabled':True,'certSecretRef':{'name':'authorino-server-cert'}}
    result={}
    for name,obj,path,after in [('authorino',authorino,'/spec/listener',listener),('authorization-service',service,'/metadata/annotations',annotations)]:
        patch=[{'op':'test','path':'/metadata/uid','value':obj['metadata']['uid']},{'op':'test','path':'/metadata/resourceVersion','value':obj['metadata']['resourceVersion']},{'op':'add','path':path,'value':after}]
        result[name]=patch
    return result


# API names are explicit: a missing CRD is different from a denied inventory.
FOUNDATION_RESOURCES = {
    'Namespace': 'namespaces', 'OperatorGroup': 'operatorgroups.operators.coreos.com',
    'Subscription': 'subscriptions.operators.coreos.com',
    'NetworkPolicy': 'networkpolicies.networking.k8s.io', 'ResourceQuota': 'resourcequotas',
    'ConfigMap': 'configmaps', 'Service': 'services', 'ServiceAccount': 'serviceaccounts',
    'Deployment': 'deployments.apps', 'GatewayClass': 'gatewayclasses.gateway.networking.k8s.io',
    'Kuadrant': 'kuadrants.kuadrant.io',
    'ZeroTrustWorkloadIdentityManager': 'zerotrustworkloadidentitymanagers.operator.openshift.io',
    'SpireServer': 'spireservers.operator.openshift.io', 'SpireAgent': 'spireagents.operator.openshift.io',
    'SpiffeCSIDriver': 'spiffecsidrivers.operator.openshift.io',
}


def object_key(value):
    meta = value['metadata']
    group = value['apiVersion'].split('/')[0] if '/' in value['apiVersion'] else ''
    return group, value['kind'], meta.get('namespace'), meta['name']


def classify_foundation(profile, groups, objects, subscriptions, csvs):
    """Classify an initial install; never adopt existing identity/application state.

    Shared platform components are retained as prerequisites, not installer-owned
    objects. A version match permits readiness/functional verification, not a
    vendor support claim. Any conflict withholds every create manifest.
    """
    lock = json.loads((ROOT/'infra/identity-demo/prerequisites.lock.json').read_text())
    by_key = {object_key(x): x for x in objects}
    csv_by_key = {(x['metadata']['namespace'], x['metadata']['name']): x for x in csvs}
    operators = {}
    for required in lock['operators']:
        found = [x for x in subscriptions if x.get('spec', {}).get('name') == required['package']]
        compatible = []
        for sub in found:
            status = sub.get('status', {})
            csv = csv_by_key.get((sub['metadata']['namespace'], status.get('installedCSV')))
            if (not sub['metadata'].get('deletionTimestamp') and status.get('installedCSV') == required['csv']
                    and status.get('currentCSV', required['csv']) == required['csv'] and csv
                    and not csv['metadata'].get('deletionTimestamp')
                    and not csv['metadata'].get('labels', {}).get('olm.copiedFrom')
                    and csv.get('status', {}).get('phase') == 'Succeeded'):
                compatible.append(sub)
        operators[required['package']] = ('create' if not found else
            'reuse' if len(compatible) == 1 else 'blocked', found)
    records = []
    creates = {name: [] for name in groups}
    for group, values in groups.items():
        for desired in values:
            meta = desired['metadata'];kind = desired['kind'];ns = meta.get('namespace')
            current = by_key.get(object_key(desired));decision = 'create';reason = 'Absent; create only'
            evidence = []
            if kind == 'Subscription':
                decision, evidence = operators[desired['spec']['name']]
                reason = {'create': 'No existing package subscription', 'reuse': 'Compatible installed package; retain unchanged',
                          'blocked': 'Existing package has no unique healthy baseline installation'}[decision]
                if current and (decision == 'create' or current.get('spec', {}).get('name') != desired['spec']['name']):
                    decision, reason = 'blocked', 'Subscription name collision'
            elif kind == 'OperatorGroup':
                packages = [v['spec']['name'] for v in groups['operators'] if v['kind'] == 'Subscription'
                            and v['metadata']['namespace'] == ns]
                decisions = [operators[p][0] for p in packages]
                existing_groups = [x for x in objects if x['kind'] == kind and x['metadata'].get('namespace') == ns]
                if 'blocked' in decisions:decision, reason = 'blocked', 'Operator prerequisite blocked'
                elif decisions and all(x == 'reuse' for x in decisions):
                    decision, reason, evidence = 'reuse', 'Retained operator scope; do not add another OperatorGroup', existing_groups
                elif existing_groups:decision, reason = 'blocked', 'Existing OperatorGroup requires platform review'
            elif current:
                if kind == 'Namespace' and meta['name'] in {'agent-sandbox-system', 'kuadrant-system'}:
                    decision, reason = 'reuse', 'Existing platform namespace; do not relabel'
                elif kind == 'GatewayClass' and current.get('spec', {}).get('controllerName') == desired['spec']['controllerName']:
                    accepted = any(c.get('type') == 'Accepted' and c.get('status') == 'True'
                                   for c in current.get('status', {}).get('conditions', []))
                    decision, reason = ('reuse', 'Retained accepted GatewayClass') if accepted else ('blocked', 'GatewayClass not accepted')
                elif kind == 'Kuadrant':
                    healthy = any(c.get('type') == 'Ready' and c.get('status') == 'True'
                                  for c in current.get('status', {}).get('conditions', []))
                    decision, reason = ('reuse', 'Retained ready Kuadrant; verify its TLS separately') if healthy else ('blocked', 'Kuadrant not ready')
                else:decision, reason = 'blocked', 'Existing target object; use recorded recovery, never adopt or overwrite'
                evidence = [current]
            if current and current['metadata'].get('deletionTimestamp'):
                decision, reason = 'blocked', 'Target is terminating'
            if decision == 'create':creates[group].append(desired)
            records.append({'group':group, 'apiVersion':desired['apiVersion'], 'kind':kind,
                'namespace':ns, 'name':meta['name'], 'decision':decision, 'reason':reason,
                'existing':[{'name':x['metadata']['name'], 'namespace':x['metadata'].get('namespace'),
                    'uid':x['metadata']['uid'], 'resourceVersion':x['metadata']['resourceVersion']} for x in evidence]})
    blocked = any(x['decision'] == 'blocked' for x in records)
    if blocked:creates = {name: [] for name in groups}
    return {'ready':not blocked, 'resources':records, 'create':creates,
            'shared_prerequisites_are_not_adopted':True}


def live_plan(args, profile, groups):
    """Read the exact TLS-verified cluster; retain denied/unknown cases as stops."""
    args.kubeconfig = str(private_file(args.kubeconfig))
    config = kube(args, 'config', 'view', '--minify', '-o', 'json')['clusters']
    if (not args.expected_server or len(config) != 1
            or config[0]['cluster']['server'].rstrip('/') != profile.expected_server
            or args.expected_server != profile.expected_server
            or config[0]['cluster'].get('insecure-skip-tls-verify')):
        raise ValueError('Explicit matching TLS-verified target required')
    crds = kube(args, 'get', 'customresourcedefinitions', '-o', 'json').get('items') or []
    served = {c['metadata']['name']: c for c in crds}
    subscriptions = kube(args, 'get', 'subscriptions.operators.coreos.com', '-A', '-o', 'json').get('items') or []
    csvs = kube(args, 'get', 'clusterserviceversions.operators.coreos.com', '-A', '-o', 'json').get('items') or []
    objects = []
    missing = []
    for kind in sorted({x['kind'] for values in groups.values() for x in values}):
        resource = FOUNDATION_RESOURCES[kind]
        if (resource not in served and kind in {'Kuadrant','GatewayClass',
                'ZeroTrustWorkloadIdentityManager','SpireServer','SpireAgent','SpiffeCSIDriver'}):
            missing.append(resource);continue
        words = ['get',resource]
        if kind not in {'Namespace','GatewayClass','ZeroTrustWorkloadIdentityManager','SpireServer','SpireAgent','SpiffeCSIDriver'}:
            words.append('-A')
        objects.extend(kube(args,*words,'-o','json').get('items') or [])
    review = classify_foundation(profile,groups,objects,subscriptions,csvs)
    review['apis_pending_operator_installation'] = missing
    write(args.output_dir/'security-review.private.json', {k:v for k,v in review.items() if k != 'create'})
    for name, values in review['create'].items():
        write(args.output_dir/('create-'+name+'.json'), {'apiVersion':'v1','kind':'List','items':values})
    return {'security_plan_ready':review['ready'], 'classification_counts':{
        name:sum(x['decision'] == name for x in review['resources']) for name in ('create','reuse','blocked')},
        'apis_pending_operator_installation':missing, 'create_files_withheld_on_conflict':not review['ready']}


def run(args):
    if args.apply: raise ValueError('Security helpers are read-only; reviewed installation uses explicit administrator commands')
    profile=DeploymentProfile.from_dict(json.loads(private_file(args.installation_profile).read_text()))
    if args.expected_server and args.expected_server != profile.expected_server: raise ValueError('Expected API mismatch')
    if args.action == 'security-tls-plan':
        args.kubeconfig=str(private_file(args.kubeconfig))
        config=kube(args,'config','view','--minify','-o','json')['clusters']
        if not args.expected_server or len(config)!=1 or config[0]['cluster']['server'].rstrip('/')!=profile.expected_server or args.expected_server!=profile.expected_server or config[0]['cluster'].get('insecure-skip-tls-verify'): raise ValueError('Exact TLS-verified target required')
        values=[kube(args,'get',kind,name,'-n','kuadrant-system','-o','json') for kind,name in [('kuadrant','kuadrant'),('authorino','authorino'),('service','authorino-authorino-authorization')]]
        for name,patch in tls_review(profile,*values).items(): write(args.output_dir/(name+'.patch.json'),patch)
        return {'tls_patches_rendered':True,'cluster_changed':False,'exact_uid_resource_version_tests':True}
    if args.action == 'security-check':
        if not args.kubeconfig or not args.expected_server: raise ValueError('Explicit kubeconfig and expected API required')
        return verify(args,profile)
    network=json.loads(private_file(args.security_network).read_text())
    groups = render(profile,network)
    for name,items in groups.items(): write(args.output_dir/(name+'.json'),{'apiVersion':'v1','kind':'List','items':items})
    live = live_plan(args,profile,groups) if args.kubeconfig else {}
    return {**live, 'security_manifests_rendered':True,'cluster_changed':False,'installation_or_readiness_proven':False,
            'manual_operator_approval_required':True,'existing_resources_must_not_be_overwritten':True}


def networking(profile, network):
    policy = lambda name, spec: object_for(profile, 'networking.k8s.io/v1', 'NetworkPolicy',
                                          name, spec, profile.identity_namespace)
    blocks = lambda values: [{'ipBlock': {'cidr': v}} for v in values]
    return [policy('identity-demo-api-dns-egress', {'podSelector': {}, 'policyTypes': ['Egress'], 'egress': [
        {'to': blocks(network['api_cidrs']), 'ports': [{'port': p, 'protocol': 'TCP'} for p in (443, 6443)]},
        {'to': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'openshift-dns'}}}],
         'ports': [{'port': p, 'protocol': protocol} for p in (53, 5353) for protocol in ('UDP', 'TCP')]},
        {'to': [{'podSelector': {}}]}]}),
        policy('identity-demo-same-namespace-ingress', {'podSelector': {}, 'policyTypes': ['Ingress'],
            'ingress': [{'from': [{'podSelector': {}}]}]}),
        policy('identity-demo-kubelet-egress', {'podSelector': {'matchLabels': {'app.kubernetes.io/name': 'spire-agent'}},
            'policyTypes': ['Egress'], 'egress': [{'to': blocks(network['worker_cidrs']),
            'ports': [{'port': 10250, 'protocol': 'TCP'}]}]}),
        policy('identity-demo-webhook-ingress', {'podSelector': {'matchLabels': {'app.kubernetes.io/name': 'spire-server'}},
            'policyTypes': ['Ingress'], 'ingress': [{'ports': [{'port': 9443, 'protocol': 'TCP'}]}]})]
