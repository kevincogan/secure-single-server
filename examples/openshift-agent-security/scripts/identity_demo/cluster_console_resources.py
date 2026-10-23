# SPDX-License-Identifier: Apache-2.0
"""Bounded Kubernetes resources for existing coordinator/preparer services.

Installation uses the existing setup ledger. No runtime identity can create Pods,
execute in privileged containers, read arbitrary Secrets or write SPIRE policies.
"""
from __future__ import annotations

from ipaddress import ip_network, ip_address
from copy import deepcopy
from urllib.parse import urlsplit

from deployment_artifacts import IMAGE_REFERENCE
from deployment_profile import dns_name


def resource(profile, api, kind, name, namespace=None, **fields):
    meta = {'name': name, 'labels': dict(profile.labels)}
    if namespace:
        meta['namespace'] = namespace
    return {'apiVersion': api, 'kind': kind, 'metadata': meta, **fields}


def permissions(profile, catalog_name):
    dns_name(catalog_name, namespace=True)
    if not catalog_name.startswith('fixture-') or not catalog_name.endswith('-catalog'):
        raise ValueError('Exact installed catalog Secret name required')
    result = []
    for role in ('coordinator', 'preparer'):
        name = 'fixture-console-'+role
        sa = {'kind': 'ServiceAccount', 'name': name, 'namespace': profile.core_namespace}
        def bind(namespace, suffix, rules):
            ref = name+'-'+suffix+('-'+profile.installation_id if namespace == profile.identity_namespace else '')
            result.append(resource(profile, 'rbac.authorization.k8s.io/v1', 'Role', ref, namespace, rules=rules))
            result.append(resource(profile, 'rbac.authorization.k8s.io/v1', 'RoleBinding', ref, namespace,
                roleRef={'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'Role', 'name': ref}, subjects=[sa]))
        result.append(resource(profile, 'v1', 'ServiceAccount', name, profile.core_namespace,
                               automountServiceAccountToken=False))
        result.append(resource(profile, 'coordination.k8s.io/v1', 'Lease', name, profile.core_namespace,
                               spec={'leaseDurationSeconds': 45}))
        bind(profile.core_namespace, 'lease', [{'apiGroups': ['coordination.k8s.io'],
            'resources': ['leases'], 'resourceNames': [name], 'verbs': ['get', 'update']}])
        reads = [
            {'apiGroups': [''], 'resources': ['pods'], 'verbs': ['get', 'list']},
            {'apiGroups': [''], 'resources': ['pods/portforward'], 'resourceNames': ['fixture-openshell-0'], 'verbs': ['create']},
            {'apiGroups': [''], 'resources': ['services'], 'resourceNames': ['fixture-openshell'], 'verbs': ['get']},
            {'apiGroups': ['apps'], 'resources': ['statefulsets'], 'resourceNames': ['fixture-openshell'], 'verbs': ['get']},
            {'apiGroups': ['apps'], 'resources': ['deployments'],
             'resourceNames': ['fixture-keycloak', 'fixture-keycloak-upstream', 'fixture-identity-driver'], 'verbs': ['get']},
            {'apiGroups': ['route.openshift.io'], 'resources': ['routes'],
             'resourceNames': ['fixture-keycloak', 'fixture-keycloak-upstream', 'fixture-mcp'], 'verbs': ['get']},
        ]
        if role == 'coordinator':
            reads += [
                {'apiGroups': [''], 'resources': ['configmaps'],
                 'resourceNames': ['fixture-service-ca', 'fixture-console-sender-trust', 'fixture-step4-retired-runs'], 'verbs': ['get']},
                {'apiGroups': [''], 'resources': ['secrets'],
                 'resourceNames': ['fixture-adapter-catalog-trust-v1', catalog_name,
                                   'fixture-step4-read-route', 'fixture-step4-read-route-ca'], 'verbs': ['get']},
                {'apiGroups': [''], 'resources': ['secrets'],
                 'resourceNames': ['fixture-adapter-catalog-trust-v1', catalog_name], 'verbs': ['patch']},
                # The stable backend credential/CA are scoped to the owned MCP
                # service, not an issuer/gateway serving key. Their contents
                # must match the private gateway receipt on every protected run.
                {'apiGroups': ['authorino.kuadrant.io'], 'resources': ['authconfigs'],
                 'resourceNames': ['fixture-step4-read-route', 'fixture-step56-live-identity'], 'verbs': ['get']},
                # Complete read-only filter inventory detects added/replaced
                # gateway configuration. This Role cannot read another namespace.
                {'apiGroups': ['networking.istio.io'], 'resources': ['envoyfilters'], 'verbs': ['get','list']},
                # Other routing observations stay within the owned namespace.
                {'apiGroups': ['gateway.networking.k8s.io'], 'resources': ['gateways', 'httproutes', 'backendtlspolicies'], 'verbs': ['get']},
                {'apiGroups': ['kuadrant.io'], 'resources': ['authpolicies'], 'verbs': ['get']},
                {'apiGroups': ['mcp.kuadrant.io'], 'resources': ['mcpserverregistrations'], 'verbs': ['get']},
                {'apiGroups': ['networking.k8s.io'], 'resources': ['networkpolicies'], 'verbs': ['get']},
            ]
            bind(profile.identity_namespace, 'public-trust', [{'apiGroups': [''], 'resources': ['configmaps'],
                'resourceNames': ['spire-bundle'], 'verbs': ['get']}])
        bind(profile.core_namespace, 'observe', reads)
        for namespace in (profile.triage_namespace, profile.reader_namespace):
            rules = [{'apiGroups': [''], 'resources': ['pods', 'persistentvolumeclaims'], 'verbs': ['get', 'list']},
                     {'apiGroups': ['agents.x-k8s.io'], 'resources': ['sandboxes'], 'verbs': ['get', 'list']}]
            if role == 'preparer':
                rules += [{'apiGroups': [''], 'resources': ['resourcequotas'], 'verbs': ['get', 'list']},
                          {'apiGroups': ['apps'], 'resources': ['deployments', 'statefulsets', 'daemonsets', 'replicasets'], 'verbs': ['get', 'list']},
                          {'apiGroups': [''], 'resources': ['replicationcontrollers'], 'verbs': ['get', 'list']},
                          {'apiGroups': ['batch'], 'resources': ['jobs', 'cronjobs'], 'verbs': ['get', 'list']}]
            bind(namespace, 'workloads', rules)
        cr_name = 'identity-demo-'+profile.installation_id+'-'+role+'-observe'
        result.append(resource(profile, 'rbac.authorization.k8s.io/v1', 'ClusterRole', cr_name,
            rules=[{'apiGroups': [''], 'resources': ['namespaces'], 'resourceNames': [*profile.application_namespaces, profile.identity_namespace], 'verbs': ['get']},
                   {'apiGroups': ['spire.spiffe.io'], 'resources': ['clusterspiffeids'],
                    'resourceNames': ['identity-demo-'+profile.installation_id+'-'+slot+'-native' for slot in ('triage', 'reader', 'gateway')], 'verbs': ['get']}]))
        result.append(resource(profile, 'rbac.authorization.k8s.io/v1', 'ClusterRoleBinding', cr_name,
            roleRef={'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'ClusterRole', 'name': cr_name}, subjects=[sa]))
    return result


def workloads(profile, image, api_cidrs, ingress_address=None):
    if not IMAGE_REFERENCE.fullmatch(image) or image.endswith('0'*64):
        raise ValueError('Pinned console runtime image required')
    for cidr in api_cidrs:
        network = ip_network(cidr, strict=True)
        if network.prefixlen != network.max_prefixlen:
            raise ValueError('Exact API host routes required')
    if not api_cidrs:
        raise ValueError('Reviewed API destinations required')
    if ingress_address is not None:
        ip_address(ingress_address)
    result=[]
    for role in ('coordinator', 'preparer'):
        name='fixture-console-'+role
        labels={**profile.labels, 'app': name, 'identity-demo-runtime-role': role}
        result.append(resource(profile, 'v1', 'PersistentVolumeClaim', name+'-state', profile.core_namespace,
            spec={'accessModes': ['ReadWriteOnce'], 'storageClassName': profile.storage_class,
                  'resources': {'requests': {'storage': '2Gi'}}}))
        container={'name': role, 'image': image, 'args': [role], 'imagePullPolicy': 'IfNotPresent',
            'env': [{'name': 'POD_NAMESPACE', 'valueFrom': {'fieldRef': {'fieldPath': 'metadata.namespace'}}},
                    {'name': 'POD_UID', 'valueFrom': {'fieldRef': {'fieldPath': 'metadata.uid'}}}],
            'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                                'capabilities': {'drop': ['ALL']}},
            'resources': {'requests': {'cpu': '100m', 'memory': '256Mi'},
                          'limits': {'cpu': '1', 'memory': '768Mi'}},
            'volumeMounts': [{'name': 'state', 'mountPath': '/state'},
                {'name': 'inputs', 'mountPath': '/runtime-inputs', 'readOnly': True},
                {'name': 'api-token', 'mountPath': '/var/run/secrets/kubernetes.io/serviceaccount', 'readOnly': True},
                {'name': 'tmp', 'mountPath': '/tmp'}]}
        # Probe only process/lease freshness. It must not mutate state, renew
        # trust, contact the model or treat an operator recovery stop as death.
        container['startupProbe']={'exec': {'command': ['python3.12', '-c',
            'import json,time,os;v=json.load(open("/state/private/worker-lease-health.json"));assert 0<=time.time()-v["at"]<15 and v["holder"].startswith(os.environ["POD_UID"]+"/")']},
            'periodSeconds': 5, 'failureThreshold': 36}
        container['readinessProbe']={**deepcopy(container['startupProbe']), 'failureThreshold': 2}
        result.append(resource(profile, 'apps/v1', 'Deployment', name, profile.core_namespace,
            spec={'replicas': 1, 'strategy': {'type': 'Recreate'},
                  'selector': {'matchLabels': {'app': name}},
                  'template': {'metadata': {'labels': labels}, 'spec': {
                    'serviceAccountName': name, 'automountServiceAccountToken': False,
                    'terminationGracePeriodSeconds': 120,
                    'securityContext': {'runAsNonRoot': True, 'fsGroupChangePolicy': 'OnRootMismatch',
                                        'seccompProfile': {'type': 'RuntimeDefault'}},
                    'containers': [container], 'volumes': [
                        {'name': 'state', 'persistentVolumeClaim': {'claimName': name+'-state'}},
                        {'name': 'inputs', 'secret': {'secretName': name+'-inputs', 'defaultMode': 0o440}},
                        {'name': 'api-token', 'projected': {'defaultMode': 0o440, 'sources': [
                            {'serviceAccountToken': {'path': 'token', 'expirationSeconds': 7200}}]}},
                        {'name': 'tmp', 'emptyDir': {'sizeLimit': '128Mi'}}]}}}))
        if ingress_address is not None:
            result[-1]['spec']['template']['spec']['hostAliases'] = [{'ip': ingress_address,
                'hostnames': [profile.origin(v).removeprefix('https://') for v in ('fixture-keycloak', 'fixture-keycloak-upstream')]}]
        result.append(resource(profile, 'networking.k8s.io/v1', 'NetworkPolicy', name, profile.core_namespace,
            spec={'podSelector': {'matchLabels': {'app': name}}, 'policyTypes': ['Ingress', 'Egress'],
                'ingress': [], 'egress': [
                    {'to': [{'ipBlock': {'cidr': c}} for c in api_cidrs],
                     'ports': [{'protocol': 'TCP', 'port': value} for value in sorted({443,6443,urlsplit(profile.expected_server).port or 443})]},
                    {'to': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'openshift-dns'}}}],
                     'ports': [{'protocol': protocol, 'port': port} for protocol in ('TCP','UDP') for port in (53,5353)]},
                    {'to': [{'podSelector': {'matchLabels': {'app': 'fixture-identity-driver'}}}],
                     'ports': [{'protocol': 'TCP', 'port': 8444}]},
                    {'to': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'openshift-ingress'}},
                             'podSelector': {'matchLabels': {'ingresscontroller.operator.openshift.io/deployment-ingresscontroller': 'default'}}}],
                     'ports': [{'protocol': 'TCP', 'port': 443}]},
                ]}))
    return result


def private_network(profile, isolation):
    """Account for additive policies before exposing the private TLS listener."""
    if isolation['metadata'].get('namespace') != profile.core_namespace or isolation['metadata']['name'] != 'fixture-isolation':
        raise ValueError('Exact owned isolation policy required')
    desired = deepcopy(isolation)
    matches = [e for e in desired['spec']['podSelector']['matchExpressions'] if e['key'] == 'app']
    if len(matches) != 1 or matches[0]['operator'] != 'NotIn':
        raise ValueError('Known baseline isolation selector required')
    baseline = ['fixture-protected-adapter', 'fixture-jira']
    excluded = baseline + ['fixture-identity-driver', 'fixture-console-coordinator', 'fixture-console-preparer']
    if matches[0]['values'] not in (baseline, excluded):
        raise ValueError('Unexpected additive isolation boundary')
    matches[0]['values'] = excluded
    ns = profile.core_namespace
    service = resource(profile, 'v1', 'Service', 'fixture-identity-operator', ns,
        spec={'type': 'ClusterIP', 'selector': {'app': 'fixture-identity-driver'},
              'ports': [{'name': 'operator-https', 'port': 8444, 'targetPort': 8444, 'protocol': 'TCP'}]})
    service['metadata']['annotations'] = {'service.beta.openshift.io/serving-cert-secret-name': 'fixture-identity-operator-tls'}
    private = resource(profile, 'networking.k8s.io/v1', 'NetworkPolicy', 'fixture-identity-operator', ns,
        spec={'podSelector': {'matchLabels': {'app': 'fixture-identity-driver'}}, 'policyTypes': ['Ingress'],
              'ingress': [{'from': [{'podSelector': {'matchLabels': {'app': 'fixture-console-'+role}}}
                                   for role in ('coordinator', 'preparer')],
                           'ports': [{'port': 8444, 'protocol': 'TCP'}]}]})
    backend = resource(profile, 'networking.k8s.io/v1', 'NetworkPolicy', 'fixture-driver-issue-view', ns,
        spec={'podSelector': {'matchLabels': {'app': 'fixture-identity-driver'}}, 'policyTypes': ['Egress'],
              'egress': [{'to': [{'podSelector': {'matchLabels': {'app': 'fixture-protected-adapter'}}}],
                          'ports': [{'port': 8443, 'protocol': 'TCP'}]}]})
    adapter = resource(profile, 'networking.k8s.io/v1', 'NetworkPolicy', 'fixture-adapter-issue-view', ns,
        spec={'podSelector': {'matchLabels': {'app': 'fixture-protected-adapter'}}, 'policyTypes': ['Ingress'],
              'ingress': [{'from': [{'podSelector': {'matchLabels': {'app': 'fixture-identity-driver'}}}],
                           'ports': [{'port': 8443, 'protocol': 'TCP'}]}]})
    business = resource(profile, 'networking.k8s.io/v1', 'NetworkPolicy', 'fixture-driver-business', ns,
        spec={'podSelector': {'matchLabels': {'app': 'fixture-identity-driver'}}, 'policyTypes': ['Ingress'],
              'ingress': [{'from': [
                  {'podSelector': {'matchLabels': {'app': 'fixture-protected-adapter'}}},
                  {'podSelector': {'matchLabels': {'gateway.networking.k8s.io/gateway-name': 'fixture-mcp'}}},
                  {'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'kuadrant-system'}},
                   'podSelector': {'matchLabels': {'authorino-resource': 'authorino'}}}],
                  'ports': [{'port': 8443, 'protocol': 'TCP'}]}]})
    # Removing the broad same-namespace isolation allowance also removes the
    # driver's internal issuer connection. Allow both ends explicitly; the
    # fixed service CA and issuer hostname remain verified by the OIDC client.
    issuer_egress = resource(profile, 'networking.k8s.io/v1', 'NetworkPolicy', 'fixture-driver-issuer-egress', ns,
        spec={'podSelector': {'matchLabels': {'app': 'fixture-identity-driver'}}, 'policyTypes': ['Egress'],
              'egress': [{'to': [{'podSelector': {'matchLabels': {'app': 'fixture-keycloak-upstream'}}}],
                          'ports': [{'port': 8443, 'protocol': 'TCP'}]}]})
    issuer_ingress = resource(profile, 'networking.k8s.io/v1', 'NetworkPolicy', 'fixture-driver-issuer-ingress', ns,
        spec={'podSelector': {'matchLabels': {'app': 'fixture-keycloak-upstream'}}, 'policyTypes': ['Ingress'],
              'ingress': [{'from': [{'podSelector': {'matchLabels': {'app': 'fixture-identity-driver'}}}],
                           'ports': [{'port': 8443, 'protocol': 'TCP'}]}]})
    return [service, private, backend, adapter, business, issuer_egress, issuer_ingress], desired


def capacity(profile):
    """Initial bounded budgets; acceptance must measure active and maximum use."""
    result=[]
    for namespace in (profile.triage_namespace, profile.reader_namespace):
        result.append(resource(profile, 'v1', 'LimitRange', 'fixture-context-resources', namespace,
            spec={'limits': [{'type': 'Container', 'defaultRequest': {'cpu': '25m', 'memory': '128Mi'},
                             'default': {'cpu': '500m', 'memory': '256Mi'}}]}))
        result.append(resource(profile, 'v1', 'ResourceQuota', 'fixture-context-capacity', namespace,
            spec={'hard': {'pods': '24', 'persistentvolumeclaims': '16', 'requests.storage': '32Gi',
                           'requests.cpu': '1500m', 'requests.memory': '4Gi',
                           'limits.cpu': '12', 'limits.memory': '6Gi'}}))
    budget={'schema_version': 1, 'includes_supervisor': True, 'per_context': {
        'pods': '2', 'persistentvolumeclaims': '1', 'requests.storage': '2Gi',
        'requests.cpu': '75m', 'requests.memory': '256Mi', 'limits.cpu': '1', 'limits.memory': '512Mi'}}
    return result, budget
