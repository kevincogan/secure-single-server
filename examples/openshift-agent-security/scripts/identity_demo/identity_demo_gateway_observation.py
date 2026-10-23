# SPDX-License-Identifier: Apache-2.0
"""Bind installer Envoy inspection to an unchanged gateway process/configuration.

The trusted installer performs the existing complete config-dump checks. Runtime
workers have no Pod exec grant: they require the same Pod, container instances,
configuration objects and live controller readiness, then exercise the real
protected path. Gateway replacement or configuration drift requires idle
installer reinspection. Shared platform controllers remain a trusted boundary.
"""
import hashlib
import json
import time
from pathlib import Path

from deployment_profile import active_profile


CHECKS = frozenset((
    'existing-hosts-disable-extra-filter', 'diagnostic-host-enables-extra-filter',
    'filter-after-wasm-before-router', 'adapter-explicit-ca-and-name-check',
    'authorino-explicit-ca-and-name-check', 'baseline-authorino-explicit-ca-and-name-check',
    'bound-authorization-before-mcp-processing', 'owned-live-identity-config-ready',
    'live-identity-before-mcp-processing', 'protected_backend_catalog_discovered'))


class GatewayDiscoveryPending(ValueError):
    """Exact security configuration passed; broker discovery is not ready yet."""

    def __init__(self,registration):
        status = registration.get('status',{})
        self.observation = {'registration_uid':registration.get('metadata',{}).get('uid'),
            'discovered_tools':status.get('discoveredTools') if type(status.get('discoveredTools')) is int else None,
            'ready':any(v.get('type')=='Ready' and v.get('status')=='True' for v in status.get('conditions',[]))}
        super().__init__('Current protected broker discovery is not ready')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def authorizer_current(args, spec):
    """Observe our exact policy; shared generated configs are controller-owned.

    This is reconciliation evidence, not a substitute for installer inspection
    or the subsequent real certificate-bound protected request.
    """
    import probe_broker_discovery as shared
    from identity_demo_runtime_cli import private_path
    receipt = json.loads(Path(private_path(args.gateway_receipt)).read_text())
    if receipt.get('kind') != 'persistent-live-gateway-v1' or receipt.get('profile') != active_profile().to_dict():
        raise ValueError('Exact persistent installation receipt required')
    expected, = [v for v in receipt['policies_after']
                 if v.get('kind') == 'AuthPolicy' and v['metadata']['name'] == 'fixture-mcp-bound']
    live = shared.owned(args, 'authpolicy', 'fixture-mcp-bound')
    meta, status = live['metadata'], live.get('status', {})
    if (meta.get('uid') != expected['metadata']['uid']
            or meta.get('namespace') != active_profile().core_namespace
            or meta.get('deletionTimestamp') or live.get('spec') != expected['spec'] or spec != expected['spec']):
        raise ValueError('Exact unchanged persistent authorization policy required')
    generation = meta.get('generation')
    conditions = status.get('conditions', [])
    return type(generation) is int and generation > 0 and all(
        len(matches := [v for v in conditions if v.get('type') == name]) == 1
        and matches[0].get('status') == 'True'
        and type(observed := matches[0].get('observedGeneration', status.get('observedGeneration'))) is int
        and observed == generation
        for name in ('Accepted', 'Enforced'))


def inventory(args):
    """Read only public configuration in the approved application namespace."""
    import probe_broker_discovery as shared
    pods = shared.kube(args, 'get', 'pods', '-n', shared.NS, '-l',
        'gateway.networking.k8s.io/gateway-name=fixture-mcp', '-o', 'json')['items']
    pods = [p for p in pods if not p['metadata'].get('deletionTimestamp')]
    if len(pods) != 1:
        raise ValueError('One exact observed gateway Pod required')
    pod = pods[0]
    shared.require_owned(pod)
    statuses = pod.get('status', {}).get('containerStatuses', [])
    if (pod['metadata'].get('namespace') != shared.NS or pod.get('status', {}).get('phase') != 'Running'
            or len(statuses) != len(pod['spec']['containers']) or not statuses
            or any(not v.get('ready') or not v.get('containerID') or not v.get('imageID') for v in statuses)):
        raise ValueError('Current ready gateway container instances required')
    filters = shared.kube(args, 'get', 'envoyfilters.networking.istio.io', '-n', shared.NS, '-o', 'json')['items']
    if not filters or len(filters) > 64:
        raise ValueError('Bounded complete gateway filter inventory required')
    records = []
    for item in filters:
        meta = item['metadata']
        if meta.get('namespace') != shared.NS or not meta.get('uid') or meta.get('deletionTimestamp'):
            raise ValueError('Exact current namespace filter required')
        records.append({'name':meta['name'], 'uid':meta['uid'], 'spec_sha256':digest(item['spec'])})
    if len({v['name'] for v in records}) != len(records):
        raise ValueError('Unique current filters required')
    return {'pod': {'name':pod['metadata']['name'], 'uid':pod['metadata']['uid'],
        'owners':pod['metadata'].get('ownerReferences', []), 'spec_sha256':digest(pod['spec']),
        'containers':sorted([{'name':v['name'], 'imageID':v['imageID'], 'containerID':v['containerID']}
                             for v in statuses], key=lambda v:v['name'])},
        'filters':sorted(records, key=lambda v:v['name'])}


def capture(args, ca, checker):
    """Installer only: bracket the existing full Envoy inspection with current reads."""
    import probe_broker_discovery as shared
    from probe_gateway_credential_route import owned_gateway_deployment
    before = inventory(args)
    owner, = [v for v in before['pod']['owners'] if v.get('kind') == 'ReplicaSet' and v.get('controller')]
    replica = shared.kube(args,'get','replicaset',owner['name'],'-n',shared.NS,'-o','json')
    if replica['metadata']['uid'] != owner['uid']:
        raise ValueError('Exact observed gateway ReplicaSet required')
    parent, = [v for v in replica['metadata'].get('ownerReferences', []) if v.get('kind')=='Deployment' and v.get('controller')]
    deployment = shared.kube(args,'get','deployment',parent['name'],'-n',shared.NS,'-o','json')
    gateway = shared.owned(args,'gateway','fixture-mcp')
    if deployment['metadata']['uid'] != parent['uid'] or not owned_gateway_deployment(deployment,gateway):
        raise ValueError('Exact Gateway controller association required')
    checks = checker()
    if set(checks) != CHECKS or any(v is not True for v in checks.values()):
        raise ValueError('Complete effective TLS and authorization-order checks required')
    if inventory(args) != before:
        raise ValueError('Gateway changed during effective configuration inspection')
    return {'kind':'installer-gateway-observation-v1', 'profile':active_profile().to_dict(),
        'service_ca_sha256':hashlib.sha256(ca.encode()).hexdigest(), 'gateway_uid':gateway['metadata']['uid'],
        'observed_at':int(time.time()), 'inventory':before, 'checks':checks}


def authorizer_linked(value):
    """Ready is insufficient unless this exact host is indexed by Authorino."""
    hosts = value.get('spec',{}).get('hosts',[])
    status = value.get('status',{})
    return (isinstance(hosts,list) and len(hosts)==1 and isinstance(hosts[0],str)
            and status.get('summary',{}).get('ready') is True
            and status.get('summary',{}).get('hostsReady')==hosts
            and any(v.get('type')=='Ready' and v.get('status')=='True' for v in status.get('conditions',[])))


def current(args, ca, *, allow_unlinked_private_host=False):
    """Never fall back to shell access or accept an older/restarted gateway instance."""
    import probe_broker_discovery as shared
    from identity_demo_gateway_persistence import verify
    from native_backend import reconciliation_status
    receipt = verify(args,ca)
    observed = receipt.get('runtime_observation', {})
    if (observed.get('kind') != 'installer-gateway-observation-v1'
            or observed.get('profile') != active_profile().to_dict()
            or observed.get('service_ca_sha256') != hashlib.sha256(ca.encode()).hexdigest()
            or observed.get('gateway_uid') != receipt['gateway_before']['metadata']['uid']
            or set(observed.get('checks', {})) != CHECKS
            or any(v is not True for v in observed['checks'].values())):
        raise ValueError('Current installer gateway observation required')
    if inventory(args) != observed.get('inventory'):
        raise ValueError('Gateway instance/configuration changed; idle installer reinspection required')
    auth, registration = reconciliation_status(args)
    frontend = shared.owned(args,'authconfig','fixture-step56-live-identity')
    if allow_unlinked_private_host:
        import os
        if (os.environ.get('IDENTITY_DEMO_RUNTIME')=='cluster'
                or auth.get('spec',{}).get('hosts') != ['fixture-step4-read-route.fixture-mcp.local']
                or active_profile().private_mcp_authorization_host == 'fixture-step4-read-route.fixture-mcp.local'
                or not any(v.get('type')=='Ready' and v.get('status')=='False'
                           and v.get('reason')=='HostsNotLinked' for v in auth.get('status',{}).get('conditions',[]))):
            raise ValueError('Only installer repair of the recorded legacy host collision is permitted')
    if ((not authorizer_linked(auth) and not allow_unlinked_private_host) or not authorizer_linked(frontend)):
        raise ValueError('Current gateway authorization readiness required')
    if (registration.get('status',{}).get('discoveredTools') != 2
            or not any(v.get('type')=='Ready' and v.get('status')=='True' for v in registration.get('status',{}).get('conditions',[]))):
        raise GatewayDiscoveryPending(registration)
    return dict(observed['checks'])
