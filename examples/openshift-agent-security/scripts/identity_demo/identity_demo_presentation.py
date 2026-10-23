#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prepare and verify a bounded presentation batch using the existing serial preparer.

No cluster resource is deleted. Private credentials stay in the existing operator
files. Readiness receipts contain aggregate capacity and context hashes, not tokens.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import fields
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import re
import time
from uuid import uuid4

from deployment_profile import active_profile
from execution_context import ExecutionContext
from identity_demo_console_worker import Control
from identity_demo_execution_setup import SANDBOX_CPU, SANDBOX_MEMORY, owned, read, require
from identity_demo_runtime import guard
from identity_demo_runtime_cli import private_path
import probe_native_exchange as native


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


def check_capacity(args: argparse.Namespace, additions: int = 0,
                   by_role: dict[str, int] | None = None) -> dict:
    """Check requests and namespace quotas without exporting other workloads or mutating them."""
    require(type(additions) is int and 0 <= additions <= 12, 'Bounded additions required')
    if getattr(args, 'namespace_capacity_budget_file', None):
        from identity_demo_capacity import namespace_capacity
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


def additions_for(plan: dict, snapshot: dict) -> dict[str, int]:
    """Size targets from the actual presentation sequence, counting current unused spares."""
    counts = Counter((v['workflow'], v['role']) for v in plan['sequence'])
    by_role: Counter = Counter()
    for (workflow, role), count in counts.items():
        available = sum(c.get('workflow', 'cve') == workflow and c['role'] == role for c in snapshot['contexts'])
        by_role[role] += max(0, count + plan['buffer'] - available)
    return dict(by_role)


def verify_batch(args: argparse.Namespace, control: Control, snapshot: dict) -> dict:
    """Prove current sandbox/registration readiness, gateways, trust and pool bounds before sealing."""
    from execution_context import validate_context
    from identity_demo_sender_trust import current
    from probe_gateway_credential_route import owned_gateway_deployment
    profile = active_profile()
    _, credentials, _ = guard(args)
    batch = snapshot['batch']
    require(batch and batch['filled'] and not snapshot['preparation_pending'], 'Complete idle batch required')
    require(current(args), 'Current approved SPIRE trust copies required')
    gateway = read(args, 'gateways.gateway.networking.k8s.io', 'fixture-mcp', profile.core_namespace)
    owned(gateway)
    require(any(c['type'] == 'Programmed' and c['status'] == 'True'
                and c.get('observedGeneration') == gateway['metadata']['generation']
                for c in gateway.get('status', {}).get('conditions', [])), 'Programmed MCP gateway required')
    deployments = native.kube(args, 'get', 'deployments', '-n', profile.core_namespace,
        '-l', 'gateway.networking.k8s.io/gateway-name=fixture-mcp', '-o', 'json')['items']
    require(len(deployments) == 1 and owned_gateway_deployment(deployments[0], gateway), 'Exact owned gateway Deployment required')
    for deployment in deployments:
        count = deployment['spec'].get('replicas', 1)
        require(count > 0 and deployment['status'].get('readyReplicas', 0) == count
                and deployment['status'].get('observedGeneration', 0) >= deployment['metadata']['generation'], 'Ready gateway required')
    native_gateway = read(args, 'statefulset', 'fixture-openshell', profile.core_namespace)
    owned(native_gateway)
    require(native_gateway['status'].get('readyReplicas', 0) == native_gateway['spec'].get('replicas', 1)
            and native_gateway['status'].get('readyReplicas', 0) > 0, 'Ready native gateway required')
    verified = []
    verified_contexts = []
    for value in snapshot['contexts']:
        context = validate_context({f.name: value[f.name] for f in fields(ExecutionContext)},
                                   lambda kind, name, namespace=None: read(args, kind, name, namespace))
        pod = read(args, 'pod', context.resource_name, context.namespace)
        require(pod.get('status', {}).get('phase') == 'Running' and any(
            c['type'] == 'Ready' and c['status'] == 'True' for c in pod.get('status', {}).get('conditions', [])),
            'Prepared workload Pod must be Ready')
        require(not pod['metadata'].get('deletionTimestamp'), 'Terminating context refused')
        verified.append({'workflow': value.get('workflow', 'cve'), 'role': value['role'],
                         'context_sha256': hashlib.sha256(context.workload.encode()).hexdigest()})
        verified_contexts.append(context)
    for role in ('triage', 'reader'):
        contexts = [c for c in verified_contexts if c.role == role]
        if not contexts:
            continue
        request = argparse.Namespace(**vars(args))
        request.execution_context = contexts[0]
        request.output_dir = args.output_dir / ('native-' + role + '-' + uuid4().hex)
        request.output_dir.mkdir(mode=0o700)
        request.label = 'presentation-verify'
        request.reuse_management_session = True
        with native.native_session(request, credentials) as execute:
            for context in contexts:
                state = execute(['sandbox', 'get', context.sandbox_name, '-o', 'json'], json_output=True)
                require(state['id'] == context.sandbox_id and state['phase'] == 'Ready', 'Exact Ready native context required')
                providers = execute(['sandbox', 'provider', 'list', context.sandbox_name, '-o', 'json'], json_output=True)
                require(providers['providers'] == [], 'Unused context must have no attached credentials')
    capacity = check_capacity(args)
    state = control.request('state')
    require(state['online'] and not any(state.get(k) for k in ('busy', 'running', 'uncertain', 'recovery_required')),
            'Healthy idle coordinator required')
    latest = control.request('pool')
    require(latest['batch']['id'] == batch['id'] and latest['batch']['filled'] and not latest['preparation_pending'],
            'Batch changed during verification')
    require({c['workload'] for c in latest['contexts']} == {c['workload'] for c in snapshot['contexts']},
            'Context inventory changed during verification')
    return {'verified_at': int(time.time()), 'batch_id': batch['id'], 'contexts': verified,
            'capacity': capacity, 'gateway_ready': True, 'trust_current': True,
            'single_use_contexts_only': True, 'unused_contexts_have_no_attached_credentials': True,
            'no_resources_deleted': True}



def wait_for_batch(control: Control, snapshot: dict, wait_seconds: int) -> dict:
    """Observe the same serial batch through temporary readiness/credential refreshes.

    This never configures another batch or retries native provisioning. Sealing
    still requires fresh positive readiness after every target is filled.
    """
    deadline = time.monotonic() + wait_seconds
    previous_remaining = None
    while not snapshot['batch']['filled'] or snapshot['preparation_pending']:
        state = control.request('state')
        require(not state.get('recovery_required')
                and state.get('reason') != 'context_preparation_failed',
                'Preparation blocked; inspect the existing private receipt before retrying')
        require(time.monotonic() < deadline,
                'Preparation is still pending; use status, do not restart provisioning')
        remaining = sum(max(0, s['target'] - s['available']) for s in snapshot['batch']['slots'])
        if remaining != previous_remaining:
            print(json.dumps({'preparing': True, 'unused_contexts': snapshot['unused'],
                              'remaining_to_prepare': remaining}), flush=True)
            previous_remaining = remaining
        time.sleep(5)
        latest = control.request('pool')
        require(latest.get('batch') and latest['batch']['id'] == snapshot['batch']['id'],
                'Presentation batch changed; inspect status instead of replaying preparation')
        snapshot = latest
    return snapshot



def wait_for_seal_window(control: Control, snapshot: dict, wait_seconds: int) -> None:
    """Wait for positive coordinator freshness after the longer native verification.

    The server repeats these checks atomically when sealing. Observation never
    rewrites a receipt, changes a lease or authorizes an execution.
    """
    deadline = time.monotonic() + wait_seconds
    identities = {c['workload'] for c in snapshot['contexts']}
    while True:
        state, latest = control.request('state'), control.request('pool')
        require(not any(state.get(k) for k in ('busy', 'running', 'uncertain', 'recovery_required')),
                'Idle coordinator required before sealing')
        require(latest.get('batch') and latest['batch']['id'] == snapshot['batch']['id']
                and latest['batch']['filled'] and not latest['preparation_pending']
                and {c['workload'] for c in latest['contexts']} == identities,
                'Verified presentation inventory changed; inspect before sealing')
        worker = latest.get('worker') or {}
        now = time.time()
        if (state.get('online') and worker.get('phase') == 'ready'
                and worker.get('updated', 0) > now - 20 and worker.get('checked_at', 0) >= now - 90
                and (not worker.get('catalog_expires') or worker['catalog_expires'] > now + 600)):
            return
        require(time.monotonic() < deadline, 'Coordinator readiness still pending; batch remains unsealed')
        time.sleep(2)



def automatic_mode(args: argparse.Namespace, control: Control, snapshot: dict) -> dict:
    """Verify explicit isolated management and exact retired identities before enabling."""
    from identity_demo_warm_pool import SLOTS
    from identity_demo_gateway_persistence import verify
    from identity_demo_management_session import validate_profile
    from execution_context import context_identity
    enable = args.action == 'automatic-enable'
    retired = []
    if enable:
        require(bool(args.gateway_receipt and args.coordinator_cli_config_dir), 'Persistent gateway receipt and coordinator profile required')
        require(Path(args.cli_config_dir).resolve() != Path(args.coordinator_cli_config_dir).resolve()
                and args.management_port != 18443, 'Separate preparer CLI profile and loopback port required')
        _, credentials, _ = guard(args)
        validate_profile(private_path(args.cli_config_dir, directory=True), credentials['keycloak_url'], args.management_port)
        validate_profile(private_path(args.coordinator_cli_config_dir, directory=True), credentials['keycloak_url'], 18443)
        ca = read(args, 'configmap', 'fixture-service-ca', active_profile().core_namespace)['data']['service-ca.crt']
        verify(args, ca)
        for filename in args.retired_context_file:
            context = context_identity(json.loads(Path(private_path(filename)).read_text()))
            for kind, name, namespace in (
                ('sandboxes.agents.x-k8s.io', context.resource_name, context.namespace),
                ('pod', context.resource_name, context.namespace),
                ('pod', 'os-supervisor-' + context.sandbox_id, context.namespace),
                ('clusterstaticentries.spire.spiffe.io', context.registration_name, None)):
                require(not read(args, kind, name, namespace, optional=True), 'Retirement requires exact native and registration absence')
            retired.append(context.workload)
        additions = {role: sum(max(0, 2 - sum(c.get('workflow','cve') == w and c['role'] == role and c.get('project','TEST') == project
                          for c in snapshot['contexts'])) for w, r, project in SLOTS if r == role) for role in ('triage','reader')}
        check_capacity(args, sum(additions.values()), additions)
        known = {c['workload']:c for c in snapshot.get('all_contexts', snapshot['contexts'])}
        from execution_context import validate_context
        # Every live native object must be explained by a trusted mapping.
        for role in ('triage','reader'):
            values = native.kube(args,'get','sandboxes.agents.x-k8s.io','-n',active_profile().namespace_for(role),'-o','json')['items']
            for value in values:
                labels = value['metadata'].get('labels',{})
                require(labels.get('openshell.ai/gateway-id') == active_profile().gateway_id
                    and 'spiffe://' + active_profile().trust_domain + '/openshell/sandbox/' + labels.get('openshell.ai/sandbox-id','') in known,
                    'Unaccounted native context requires review before automatic mode')
                key = 'spiffe://' + active_profile().trust_domain + '/openshell/sandbox/' + labels['openshell.ai/sandbox-id']
                supplied = {f.name: known[key][f.name] for f in fields(ExecutionContext)}
                validate_context(supplied, lambda kind,name,ns=None: read(args,kind,name,ns))
    receipt = {'mode':'automatic' if enable else 'legacy', 'target':8, 'limit':12,
               'management_isolation_verified':enable, 'retired_workloads':retired, 'checked_at':int(time.time())}
    path = args.output_dir/'automatic-pool.receipt.private.json'
    native.private_write(path, receipt)
    result = control.request('pool', {'action':'automatic','enabled':enable,
        'receipt_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'retired_workloads':retired})
    return {'automatic_pool_enabled':enable,'automatic':result.get('automatic')}


def main() -> None:
    """Provide one repeatable operator command; provisioning stays with the existing preparer."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--action', choices=('plan', 'prepare', 'verify', 'status', 'release', 'automatic-enable', 'automatic-disable'), required=True)
    for name in ('kubeconfig', 'expected-server', 'credentials-file', 'driver-credentials-file', 'output-dir',
                 'cli', 'cli-config-dir'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--gateway-receipt')
    parser.add_argument('--management-port', type=int, default=18443)
    parser.add_argument('--coordinator-cli-config-dir')
    parser.add_argument('--retired-context-file', action='append', default=[])
    parser.add_argument('--plan-file', help='Nonsecret presentation sequence and capacity caps')
    parser.add_argument('--wait-seconds', type=int, default=1800)
    args = parser.parse_args()
    require(30 <= args.wait_seconds <= 3600, 'Wait must be between 30 and 3600 seconds')
    os.umask(0o077)
    output = Path(args.output_dir)
    private_path(str(output.parent), directory=True)
    output.mkdir(mode=0o700)
    args.output_dir, args.namespace = output, active_profile().core_namespace
    guard(args)
    credential = json.loads(private_path(args.driver_credentials_file).read_text())
    control = Control(credential['operator_secret'])
    snapshot = control.request('pool')
    if args.action in ('automatic-enable','automatic-disable'):
        result = automatic_mode(args, control, snapshot)
        native.private_write(output / 'result.json', result)
        print(json.dumps(result), flush=True)
        return
    if (snapshot.get('batch') and snapshot['batch'].get('browser_requested')
            and snapshot['batch']['phase'] == 'preparing' and args.action != 'status'):
        raise ValueError('Browser-requested batch is managed by the existing preparer; follow progress in Settings')
    if args.action == 'status':
        summary = {k: snapshot[k] for k in ('mapped', 'consumed', 'unused', 'batch', 'preparation_pending', 'worker')}
        native.private_write(output / 'status.json', summary)
        print(json.dumps(summary), flush=True)
        return
    if args.action in ('plan', 'prepare'):
        require(bool(args.plan_file), 'Explicit presentation plan required')
        plan = json.loads(Path(args.plan_file).read_text())
        by_role = additions_for(plan, snapshot)
        capacity = check_capacity(args, sum(by_role.values()), by_role)
        native.private_write(output / 'capacity-before.json', capacity)
        if args.action == 'plan':
            print(json.dumps({'planned_additions_by_role': by_role, 'capacity': capacity, 'applied': False}), flush=True)
            return
        existing = snapshot['batch']
        same = existing and all(existing['plan'].get(k) == v for k, v in plan.items())
        if not same or existing['phase'] == 'holding':
            snapshot = control.request('pool', {'action': 'configure', 'plan': plan})
        snapshot = wait_for_batch(control, snapshot, args.wait_seconds)
    require(snapshot['batch'] is not None, 'Active presentation batch required')
    if args.action == 'release':
        receipt = {'batch_id': snapshot['batch']['id'], 'release_hold': True,
                   'existing_automatic_replenishment_resumes': True, 'requested_at': int(time.time())}
    else:
        receipt = verify_batch(args, control, snapshot)
    path = output / ('presentation-' + uuid4().hex + '.receipt.json')
    native.private_write(path, receipt)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if args.action == 'verify' and snapshot['batch']['phase'] == 'holding':
        result = snapshot  # A new read-only observation cannot rewrite the original seal receipt.
    else:
        if args.action != 'release':
            wait_for_seal_window(control, snapshot, args.wait_seconds)
        result = control.request('pool', {'action': 'release' if args.action == 'release' else 'seal',
                                         'id': snapshot['batch']['id'], 'receipt_sha256': digest})
    native.private_write(output / 'result.json', {k: result[k] for k in ('mapped', 'consumed', 'unused', 'batch')})
    print(json.dumps({'presentation_ready': args.action != 'release', 'unused_contexts': result['unused'],
                      'receipt_sha256': digest, 'refill_held': args.action != 'release'}), flush=True)


if __name__ == '__main__':
    main()
