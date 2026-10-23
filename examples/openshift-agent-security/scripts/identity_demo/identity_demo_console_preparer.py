# SPDX-License-Identifier: Apache-2.0
"""Replenish exhausted one-use demo contexts while the normal coordinator stays active.

Legacy reservations exclude browser jobs; explicitly enabled isolated warm-pool
operations can overlap one execution. Existing provisioning and retirement guards
remain authoritative. Ambiguous mutations block preparation;
they are never replayed automatically. Workspace data and run history are retained.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, fields
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import threading
import time
import traceback
from uuid import uuid4

from identity_demo_console_worker import Control
from identity_demo_execution_setup import provision, read, require, retire
from identity_demo_runtime_cli import private_path
import probe_native_exchange as native
from execution_context import ExecutionContext, resolve_context


class PreparationCapacityUnavailable(RuntimeError):
    """A read-only capacity gate failed before any native mutation or checkpoint."""


def record(path: Path, value: dict) -> None:
    """Atomically replace only the helper's local checkpoint, keeping receipts immutable."""
    temporary = path.with_suffix('.tmp')
    with open(temporary, 'w', opener=lambda p, f: os.open(p, f, 0o600)) as stream:
        json.dump(value, stream, sort_keys=True)
    temporary.replace(path)


def retire_previous(args: argparse.Namespace, value: dict) -> dict:
    """Retire only the exact closed identity and obsolete registration; retain its PVCs."""
    context = ExecutionContext(**{f.name: value[f.name] for f in fields(ExecutionContext)})
    context_file = args.output_dir / 'previous-context.private.json'
    native.private_write(context_file, asdict(context))
    args.context_file = [str(context_file)]
    if value.get('_disposable_receipt'):
        args.disposable_workspace_receipt = value['_disposable_receipt']
        args.disposable_workspace_reservation = value['_reservation']
    result = retire(args)  # Same closed-run, ownership, workspace and registration checks for every path.
    from identity_demo_controller_identity import enabled as controller_identities
    inactive = (controller_identities() and result.get('controller_managed') is True
                and result.get('pod_absence_verified') is True
                and result.get('registration_inactive') is True)
    require(result['registration_absent'] or inactive, 'Old identity remains active')
    return {'retired_workload': context.workload, 'workspace_data_retained': result['referenced_workspaces_preserved'],
            'disposable_scratch_removed': result.get('disposable_scratch_removed', False),
            'registration_absent': result['registration_absent'],
            'registration_inactive': inactive, 'controller_managed': bool(result.get('controller_managed'))}


def prepare_one(args: argparse.Namespace, control: Control, owner: str, reservation: dict) -> dict:
    """Execute one reserved plan once and commit only an independently validated context."""
    directory = args.output_dir / reservation['id']
    directory.mkdir(mode=0o700, exist_ok=True)
    checkpoint = directory / 'checkpoint.private.json'
    finish = {'owner': owner, 'id': reservation['id']}
    if checkpoint.exists():
        saved = json.loads(private_path(str(checkpoint)).read_text())
        if saved.get('phase') == 'ready_to_commit':
            # This endpoint is idempotent for the identical receipt and mapping.
            control.request('prepare/finish', {**finish, 'context': saved['context'], 'receipt_sha256': saved['receipt_sha256']})
            return {'resumed_commit': True}
        receipt = hashlib.sha256(checkpoint.read_bytes()).hexdigest()
        control.request('prepare/finish', {**finish, 'context': None, 'receipt_sha256': receipt})
        return {'blocked': True, 'ambiguous_mutation_not_replayed': True}
    target = reservation['target']
    started = time.monotonic()
    if getattr(args, 'operator_access_check', False):
        from identity_demo_operator_access import ensure_access
        ensure_access(args)  # No mutation/checkpoint yet: a failed login may safely be checked again.
    capacity = None
    if target.get('batch_id') or (target.get('automatic') and target.get('operation') == 'prepare'):
        require(target['previous'] is None, 'Presentation batching is additive only')
        from identity_demo_presentation import check_capacity
        try:
            capacity = check_capacity(args, 1, {target['role']: 1})
        except Exception:
            raise PreparationCapacityUnavailable('Read-only capacity check unavailable; no mutation attempted') from None
    preflight_done = time.monotonic()
    record(checkpoint, {'phase': 'mutation_pending', 'reservation': reservation})
    try:
        request = argparse.Namespace(**vars(args))
        request.apply = True
        request.isolated_preparation = bool(target.get('automatic'))
        request.action = 'provision'
        request.role = target['role']
        request.namespace = native.NAMESPACE
        request.label = 'console-preparation'
        retirement = directory / 'retirement'
        retirement.mkdir(mode=0o700)
        request.output_dir = retirement
        if target.get('automatic') and target.get('operation') == 'retire':
            previous = dict(target['previous'])
            if target.get('disposable'):
                previous['_disposable_receipt'] = str(args.output_dir / target['item_id'] / 'provision/disposable-workspaces.private.json')
                previous['_reservation'] = target['item_id']
            retired = retire_previous(request, previous)
            path = directory / 'retirement.receipt.private.json'
            native.private_write(path, retired)
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            record(checkpoint, {'phase': 'ready_to_commit', 'context': target['previous'], 'receipt_sha256': digest})
            control.request('prepare/finish', {**finish, 'context': target['previous'], 'receipt_sha256': digest})
            return {'retired': True, **retired}
        if target.get('batch_id') or target.get('automatic'):
            retired = {'retirement_requested': False, 'workspace_data_retained': True}
        else:
            retired = retire_previous(request, target['previous'])
        retired_at = time.monotonic()
        output = directory / 'provision'
        output.mkdir(mode=0o700)
        request.output_dir = output
        request.suffix = target['suffix']
        observed = provision(request)
        context = resolve_context(str(output / 'context.private.json'), lambda k, n, ns=None: read(request, k, n, ns))
        if target.get('automatic'):
            from identity_demo_workspace_retention import capture
            capture(request, context, reservation['id'], read)
        value = {**asdict(context), 'workload': context.workload, 'workflow': target['workflow'],
                 'project': target['project'], 'console_prepared': True}
        receipt = {'reservation': reservation['id'], 'retirement': retired, 'provision': observed,
                   'capacity_before': capacity,
                   'context': value, 'coordinator_stopped': False,
                   'timings_seconds': {'preflight_and_capacity': round(preflight_done - started, 3),
                                       'retirement': 0 if target.get('batch_id') else round(retired_at - preflight_done, 3),
                                       'provision_and_verification': round(time.monotonic() - retired_at, 3),
                                       'total': round(time.monotonic() - started, 3)}}
        native.private_write(directory / 'preparation.receipt.private.json', receipt)
        digest = hashlib.sha256((directory / 'preparation.receipt.private.json').read_bytes()).hexdigest()
        record(checkpoint, {'phase': 'ready_to_commit', 'context': value, 'receipt_sha256': digest})
        control.request('prepare/finish', {**finish, 'context': value, 'receipt_sha256': digest})
        return {'prepared': True, 'workflow': target['workflow'], 'role': target['role'], 'receipt_sha256': digest}
    except Exception:
        # A failed completion request may already have committed. Keep its exact
        # context/receipt for idempotent confirmation, never recreate the sandbox.
        if json.loads(checkpoint.read_text()).get('phase') == 'ready_to_commit':
            raise
        failure = {'failure': 'preparation_failed', 'traceback': traceback.format_exc()}
        native.private_write(directory / ('failure-' + uuid4().hex + '.private.json'), failure)
        control.request('prepare/finish', {**finish, 'context': None,
                        'receipt_sha256': hashlib.sha256(json.dumps(failure, sort_keys=True).encode()).hexdigest()})
        return {'blocked': True, 'ambiguous_mutation_not_replayed': True}



def verify_browser_batch(args: argparse.Namespace, control: Control) -> dict | None:
    """Finish a presenter-requested batch with the existing full verifier, never a new provisioner."""
    snapshot = control.request('pool')
    batch = snapshot.get('batch')
    if (not batch or not batch.get('browser_requested') or batch['phase'] != 'preparing'
            or not batch['filled'] or snapshot['preparation_pending'] or batch.get('verification_state') == 'blocked'):
        return None
    from identity_demo_presentation import verify_batch, wait_for_seal_window
    output = args.output_dir / ('batch-' + batch['id']) / ('verification-' + uuid4().hex)
    output.mkdir(mode=0o700, parents=True)
    request = argparse.Namespace(**vars(args))
    request.output_dir = output
    control.request('pool', {'action': 'verification-status', 'id': batch['id'], 'status': 'verifying'})
    try:
        receipt = verify_batch(request, control, snapshot)
        path = output / 'readiness.receipt.private.json'
        native.private_write(path, receipt)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        wait_for_seal_window(control, snapshot, 120)
        control.request('pool', {'action': 'seal', 'id': batch['id'], 'receipt_sha256': digest})
        return {'presentation_ready': True, 'receipt_sha256': digest}
    except Exception:
        native.private_write(output / 'verification-failure.private.json',
                             {'failure': 'verification_failed', 'traceback': traceback.format_exc(), 'provisioning_replayed': False})
        latest = control.request('pool')
        if latest.get('batch') and latest['batch']['id'] == batch['id'] and latest['batch']['phase'] == 'holding':
            return {'presentation_ready': True, 'seal_observation_recovered': True}
        control.request('pool', {'action': 'verification-status', 'id': batch['id'], 'status': 'blocked'})
        return {'verification_blocked': True, 'provisioning_replayed': False}


def main() -> None:
    """Run one guarded replenisher, with credentials confined to private operator files."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('kubeconfig', 'expected-server', 'credentials-file', 'cli', 'cli-config-dir',
                 'driver-credentials-file', 'output-dir'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--fresh-management-per-command', action='store_true',
                        help='Rollback: reconnect and authenticate before every native command')
    parser.add_argument('--management-port', type=int, default=18443)
    parser.add_argument('--ca-file')
    parser.add_argument('--initialize-management-profile', action='store_true')
    parser.add_argument('--operator-login-file', help='Optional private same-operator login for renewal')
    parser.set_defaults(operator_access_check=True)
    from identity_demo_operator_access import runtime_arguments
    runtime_arguments(parser)
    args = parser.parse_args()
    args.reuse_management_session = not args.fresh_management_per_command
    os.umask(0o077)
    output = Path(args.output_dir)
    private_path(str(output.parent), directory=True)
    output.mkdir(mode=0o700, exist_ok=True)
    args.output_dir = private_path(str(output), directory=True)
    args.namespace = native.NAMESPACE
    lock = (args.output_dir / 'preparer.lock').open('a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    identity = args.output_dir / 'owner.private.json'
    if not identity.exists():
        native.private_write(identity, {'owner': uuid4().hex})
    owner = json.loads(private_path(str(identity)).read_text())['owner']
    credentials = json.loads(private_path(args.driver_credentials_file).read_text())
    control = Control(credentials['operator_secret'])
    from identity_demo_worker_lease import install
    lease = install(args, 'preparer')
    if args.initialize_management_profile:
        from identity_demo_runtime import guard
        if not args.ca_file:
            raise ValueError('Explicit runtime management CA required')
        _, runtime_credentials, _ = guard(args)
        startup = argparse.Namespace(**vars(args))
        startup.output_dir = args.output_dir / ('startup-' + uuid4().hex)
        startup.output_dir.mkdir(mode=0o700)
        startup.label = 'preparer-management'
        with native.native_session(startup, runtime_credentials, initialize_profile=True):
            pass
    stopping = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopping.set())
    signal.signal(signal.SIGINT, lambda *_: stopping.set())
    while not stopping.is_set():
        if lease and lease.lost.is_set():
            raise RuntimeError('Preparer lease ownership lost; recovery required')
        try:
            from managed_certificates import runtime_status
            runtime_status()  # Observe public projections before reserving or mutating a context.
            reservation = control.request('prepare/next', {'owner': owner})['preparation']
            if reservation:
                print(json.dumps(prepare_one(args, control, owner, reservation)), flush=True)
            else:
                verified = verify_browser_batch(args, control)
                if verified:
                    print(json.dumps(verified), flush=True)
        except PreparationCapacityUnavailable:
            print(json.dumps({'preparation_waiting_for_capacity': True, 'mutation_attempted': False}), flush=True)
        except Exception:
            # Control failures may be retried; native mutation cannot be repeated
            # because its durable checkpoint is checked before entering it again.
            print(json.dumps({'preparation_control_unavailable': True}), flush=True)
        stopping.wait(10)


if __name__ == '__main__':
    main()
