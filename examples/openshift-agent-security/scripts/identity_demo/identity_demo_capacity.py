# SPDX-License-Identifier: Apache-2.0
"""Runtime quota admission in owned namespaces, without listing other workloads.

The installer/admin must supply a measured complete per-context budget including
the workload and its supervisor. Kubernetes scheduler/admission remain final.
"""
from __future__ import annotations

from collections import Counter
from decimal import Decimal
import json
import re

import native_exchange as native

from deployment_profile import active_profile
from identity_demo_execution_setup import SANDBOX_CPU, SANDBOX_MEMORY, owned, read, require

FIELDS = {'pods','persistentvolumeclaims','requests.storage','requests.cpu',
          'requests.memory','limits.cpu','limits.memory'}


def validate_budget(value):
    if not isinstance(value,dict) or set(value)!={'schema_version','includes_supervisor','per_context'}:
        raise ValueError('Complete measured capacity budget required')
    if value['schema_version']!=1 or value['includes_supervisor'] is not True:
        raise ValueError('Supervisor must be included in capacity accounting')
    if not isinstance(value['per_context'],dict) or set(value['per_context'])!=FIELDS:
        raise ValueError('Complete resource budget required')
    amounts={k:quantity(v) for k,v in value['per_context'].items()}
    if any(v<=0 for v in amounts.values()) or amounts['pods']<2 or amounts['persistentvolumeclaims']<1:
        raise ValueError('Positive workload and supervisor budget required')
    for k in ('cpu','memory'):
        if amounts['requests.'+k]>amounts['limits.'+k]:raise ValueError('Invalid resource budget')
    return amounts


def namespace_capacity(args, additions, by_role):
    from identity_demo_runtime_cli import private_path
    if type(additions)is not int or not 0<=additions<=12 or sum(by_role.values())!=additions:
        raise ValueError('Bounded exact role additions required')
    budget=validate_budget(json.loads(private_path(args.namespace_capacity_budget_file).read_text()))
    accounts=[]
    for role,count in by_role.items():
        require(role in ('triage','reader') and type(count)is int and count>=0,'Exact owned role required')
        ns=active_profile().namespace_for(role)
        owned(read(args,'namespace',ns))
        quotas=native.kube(args,'get','resourcequotas','-n',ns,'-o','json')['items']
        covered=set()
        for quota in quotas:
            status=quota.get('status',{})
            require(status.get('hard')==quota['spec']['hard'],'Current quota admission status required')
            for key,hard in status['hard'].items():
                if key in budget:
                    covered.add(key)
                    require(key in status.get('used',{}),'Quota usage unavailable')
                    require(quantity(status['used'][key])+budget[key]*count<=quantity(hard),
                            'Insufficient owned namespace quota headroom')
        require(FIELDS<=covered,'Complete owned namespace quota coverage required')
        accounts.append({'role':role,'quota_checks':len(quotas),'contexts_requested':count})
    return {'namespace_accounting':accounts,'additional_contexts':additions,
            'cluster_wide_scan':False,'supervisor_included':True,
            'scheduler_and_admission_remain_authoritative':True}


def quantity(value: str | int) -> Decimal:
    """Interpret bounded Kubernetes resource quantities in their base units."""
    match = re.fullmatch(r'([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)([numkKMGTEP]|[KMGTPE]i)?', str(value))
    if not match:
        raise ValueError('Recognized Kubernetes resource quantity required')
    suffix = match[2] or ''
    multipliers = {'': Decimal(1), 'n': Decimal('1e-9'), 'u': Decimal('1e-6'), 'm': Decimal('1e-3'),
                   'k': Decimal(1000), 'K': Decimal(1000)}
    for power, unit in enumerate('MGTPE', start=2):
        multipliers[unit] = Decimal(1000) ** power
    for power, unit in enumerate('KMGTPE', start=1):
        multipliers[unit + 'i'] = Decimal(1024) ** power
    result = Decimal(match[1]) * multipliers[suffix]
    require(result.is_finite() and result >= 0, 'Nonnegative finite quantity required')
    return result


def node_slots(nodes: list[dict], pods: list[dict]) -> dict:
    """Estimate configured workload capacity; supervisor runtime overhead remains unmeasured."""
    usage: dict[str, dict[str, Decimal]] = {}
    for pod in pods:
        if pod.get('status', {}).get('phase') in ('Succeeded', 'Failed'):
            continue
        spec = pod['spec']
        name = spec.get('nodeName')
        if not name:
            continue
        used = usage.setdefault(name, {'cpu': Decimal(0), 'memory': Decimal(0), 'pods': Decimal(0)})
        used['pods'] += 1
        # Summing init and app requests is conservative, including restartable
        # init containers, rather than understating resource reservation.
        for container in (*spec.get('containers', []), *spec.get('initContainers', [])):
            for resource in ('cpu', 'memory'):
                used[resource] += quantity(container.get('resources', {}).get('requests', {}).get(resource, '0'))
        for resource in ('cpu', 'memory'):
            used[resource] += quantity(spec.get('overhead', {}).get(resource, '0'))
    slots, eligible, free_cpu, free_memory = 0, 0, Decimal(0), Decimal(0)
    for node in nodes:
        spec, status = node.get('spec', {}), node.get('status', {})
        if (spec.get('unschedulable') or any(t.get('effect') in ('NoSchedule', 'NoExecute') for t in spec.get('taints', []))
                or not any(c['type'] == 'Ready' and c['status'] == 'True' for c in status.get('conditions', []))):
            continue
        available = status['allocatable']
        used = usage.get(node['metadata']['name'], {})
        cpu = max(Decimal(0), quantity(available['cpu']) - used.get('cpu', 0))
        memory = max(Decimal(0), quantity(available['memory']) - used.get('memory', 0))
        pod_slots = max(Decimal(0), quantity(available['pods']) - used.get('pods', 0))
        slots += int(min(cpu // quantity(SANDBOX_CPU), memory // quantity(SANDBOX_MEMORY), pod_slots // 2))
        eligible += 1
        free_cpu += cpu
        free_memory += memory
    return {'eligible_nodes': eligible, 'estimated_extra_context_slots': slots,
            'free_requested_cpu_millicores': int(free_cpu * 1000),
            'free_requested_memory_mib': int(free_memory / quantity('1Mi')),
            'estimate_only': True, 'supervisor_runtime_overhead_unmeasured': True}


def check_capacity(args, additions: int = 0,
                   by_role: dict[str, int] | None = None) -> dict:
    """Check requests and namespace quotas without exporting other workloads or mutating them."""
    require(type(additions) is int and 0 <= additions <= 12, 'Bounded additions required')
    if getattr(args, 'namespace_capacity_budget_file', None):
        return namespace_capacity(args, additions, by_role or {})
    profile = active_profile()
    nodes = native.kube(args, 'get', 'nodes', '-o', 'json')['items']
    pods = native.kube(args, 'get', 'pods', '-A', '-o', 'json')['items']
    result = node_slots(nodes, pods)
    require(result['estimated_extra_context_slots'] >= additions, 'Insufficient requested CPU, memory or Pod capacity')
    accounts = []
    for role in ('triage', 'reader'):
        namespace = profile.namespace_for(role)
        owned(read(args, 'namespace', namespace))
        count = (by_role or {}).get(role, 0)
        quotas = native.kube(args, 'get', 'resourcequotas', '-n', namespace, '-o', 'json')['items']
        demand = {'pods': Decimal(2 * count), 'persistentvolumeclaims': Decimal(count),
                  'requests.storage': quantity('2Gi') * count,
                  'requests.cpu': quantity(SANDBOX_CPU) * count, 'limits.cpu': quantity(SANDBOX_CPU) * count,
                  'requests.memory': quantity(SANDBOX_MEMORY) * count, 'limits.memory': quantity(SANDBOX_MEMORY) * count}
        for quota in quotas:
            status = quota.get('status', {})
            require(status.get('hard') == quota['spec']['hard'], 'Current namespace quota status required')
            for key, hard in status['hard'].items():
                needed = demand.get(key)
                if needed is None and key.endswith('.storageclass.storage.k8s.io/requests.storage'):
                    needed = demand['requests.storage']
                if needed is not None:
                    require(quantity(status.get('used', {}).get(key, '0')) + needed <= quantity(hard),
                            'Insufficient namespace quota headroom')
        claims = native.kube(args, 'get', 'pvc', '-n', namespace, '-o', 'json')['items']
        sandboxes = native.kube(args, 'get', 'sandboxes.agents.x-k8s.io', '-n', namespace, '-o', 'json')['items']
        native_owned = [s for s in sandboxes if s['metadata'].get('labels', {}).get('openshell.ai/gateway-id') == profile.gateway_id
                        and s['metadata'].get('labels', {}).get('openshell.ai/managed-by') == 'openshell'
                        and s['spec']['podTemplate']['spec'].get('serviceAccountName') == 'fixture-openshell-sandbox']
        accounts.append({'role': role, 'live_native_sandboxes': len(native_owned), 'namespace_pvcs': len(claims),
                         'bound_pvcs': sum(c.get('status', {}).get('phase') == 'Bound' for c in claims),
                         'requested_storage_gib': float(sum((quantity(c['spec']['resources']['requests']['storage'])
                                                           for c in claims), Decimal(0)) / quantity('1Gi')),
                         'quota_checks': len(quotas), 'all_existing_resources_retained': True})
    return {**result, 'additional_contexts': additions, 'additional_workspace_storage_gib': 2 * additions,
            'namespace_accounting': accounts}
