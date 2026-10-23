# SPDX-License-Identifier: Apache-2.0
"""Proof of newly created synthetic pool scratch; historical PVCs stay retained."""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import re
import time

from deployment_profile import active_profile
from identity_demo_runtime_cli import private_path


def claims(args, context, read):
    sandbox = read(args, 'sandboxes.agents.x-k8s.io', context.resource_name, context.namespace)
    worker = read(args, 'pod', context.resource_name, context.namespace)
    worker_owners = worker['metadata'].get('ownerReferences', [])
    if len(worker_owners) != 1 or worker_owners[0].get('uid') != sandbox['metadata']['uid'] or worker_owners[0].get('kind') != 'Sandbox':
        raise ValueError('Exact scratch worker required')
    names = {v['persistentVolumeClaim']['claimName'] for v in worker['spec'].get('volumes', []) if 'persistentVolumeClaim' in v}
    if names != {'workspace-' + context.resource_name}:
        raise ValueError('Only the new native synthetic workspace is disposable')
    values = [read(args, 'pvc', name, context.namespace) for name in sorted(names)]
    for value in values:
        refs = value['metadata'].get('ownerReferences', [])
        if len(refs) != 1 or refs[0].get('uid') != sandbox['metadata']['uid'] or refs[0].get('kind') != 'Sandbox':
            raise ValueError('Exclusive exact Sandbox workspace ownership required')
    return sandbox, values


def capture(args, context, reservation, read):
    if not re.fullmatch('[a-f0-9]{32}', reservation):
        raise ValueError('Exact pool reservation required')
    sandbox, values = claims(args, context, read)
    value = {'kind': 'new-synthetic-pool-scratch', 'installation': active_profile().installation_id,
             'owner': active_profile().owner, 'reservation': reservation, 'context': asdict(context),
             'sandbox_uid': sandbox['metadata']['uid'], 'claims': [
                 {'name': v['metadata']['name'], 'uid': v['metadata']['uid'],
                  'spec_sha256': hashlib.sha256(json.dumps(v['spec'], sort_keys=True).encode()).hexdigest()} for v in values]}
    path = args.output_dir / 'disposable-workspaces.private.json'
    from probe_native_exchange import private_write
    private_write(path, value)
    return value


def verify(args, context, sandbox, read):
    path = private_path(args.disposable_workspace_receipt)
    proof = json.loads(Path(path).read_text())
    if (proof.get('kind') != 'new-synthetic-pool-scratch' or proof.get('context') != asdict(context)
            or proof.get('installation') != active_profile().installation_id or proof.get('owner') != active_profile().owner
            or proof.get('reservation') != args.disposable_workspace_reservation
            or proof.get('sandbox_uid') != sandbox['metadata']['uid']):
        raise ValueError('New disposable scratch proof mismatch')
    _, values = claims(args, context, read)
    expected = [{'name': v['metadata']['name'], 'uid': v['metadata']['uid'],
                 'spec_sha256': hashlib.sha256(json.dumps(v['spec'], sort_keys=True).encode()).hexdigest()} for v in values]
    if expected != proof.get('claims'):
        raise ValueError('Disposable workspace identity or specification changed')
    from probe_native_exchange import kube
    pods = kube(args, 'get', 'pods', '-n', context.namespace, '-o', 'json')['items']
    names = {v['name'] for v in expected}
    for pod in pods:
        referenced = {v['persistentVolumeClaim']['claimName'] for v in pod['spec'].get('volumes', []) if 'persistentVolumeClaim' in v}
        refs = pod['metadata'].get('ownerReferences', [])
        same_owner = len(refs) == 1 and refs[0].get('uid') == sandbox['metadata']['uid'] and refs[0].get('kind') == 'Sandbox'
        if referenced & names and not same_owner:
            raise ValueError('Unexpected workspace consumer prevents disposal')
    # Scaled-to-zero controllers and pending PVC clones can still depend on
    # scratch. Namespace permissions must permit this inventory; errors stop disposal.
    resources = 'deployment,statefulset,daemonset,replicaset,replicationcontroller,job,cronjob,pvc,sandboxes.agents.x-k8s.io'
    declared = kube(args, 'get', resources, '-n', context.namespace, '-o', 'json')['items']
    for value in declared:
        spec = value.get('spec', {})
        templates = [spec.get('template', {}).get('spec', {}), spec.get('podTemplate', {}).get('spec', {}),
                     spec.get('jobTemplate', {}).get('spec', {}).get('template', {}).get('spec', {})]
        referenced = {v['persistentVolumeClaim']['claimName'] for t in templates for v in t.get('volumes', [])
                      if 'persistentVolumeClaim' in v}
        for claim_spec in [spec, *(v.get('spec', {}) for v in spec.get('volumeClaimTemplates', []))]:
            for source in ('dataSource', 'dataSourceRef'):
                ref = claim_spec.get(source) or {}
                if ref.get('kind') == 'PersistentVolumeClaim' and ref.get('namespace') in (None, '', context.namespace):
                    referenced.add(ref.get('name'))
        owners = value.get('metadata', {}).get('ownerReferences', [])
        same_sandbox = value.get('metadata', {}).get('uid') == sandbox['metadata']['uid'] or (
            len(owners) == 1 and owners[0].get('uid') == sandbox['metadata']['uid'] and owners[0].get('kind') == 'Sandbox')
        if referenced & names and not same_sandbox:
            raise ValueError('Unexpected declared controller or clone reference prevents disposal')
    return expected


def verify_absent(args, context, names, read):
    deadline = time.monotonic() + 60
    for value in names:
        while True:
            live = read(args, 'pvc', value['name'], context.namespace, optional=True)
            if not live:
                break
            if live['metadata']['uid'] != value['uid'] or time.monotonic() >= deadline:
                raise ValueError('Disposable scratch deletion unconfirmed; quarantine and inspect')
            time.sleep(1)
