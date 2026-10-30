# SPDX-License-Identifier: Apache-2.0
"""Run browser-submitted console jobs through the existing owned native harness.

Start on the authorized operator host with private inputs. No cluster, model or
backend credentials enter the browser. Each job uses its exact pre-registered
context, real user session and durable approval; uncertain writes are not retried.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path
import sys
import threading
import time
from urllib.error import HTTPError
from urllib.request import Request, build_opener, ProxyHandler
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'runtime' / 'identity_demo'))

from identity_demo_action_policy import DRIVER
from identity_demo_operator_access import OperatorAccessUnavailable
from identity_demo_runtime import guard
from identity_demo_runtime_cli import private_path
from permission_flow import PermissionFlow
from gateway_evidence_flow import GatewayEvidenceFlow
from model_execution import ModelExecutionFlow, private_inference
from execution_context import ExecutionContext
import probe_native_exchange as native

READINESS_MAX_AGE = 120


class ControlRejected(RuntimeError):
    """Retain only the HTTP status for safe operator control failures."""

    def __init__(self, status: int) -> None:
        super().__init__('Console control request rejected: HTTP ' + str(status))
        self.status = status


class Control:
    """Keep the existing fixed-origin control channel live without replaying writes."""

    def __init__(self, secret: str) -> None:
        self.secret = secret
        from identity_demo_control_transport import configured_transport
        self.transport = configured_transport()
        self.worker = uuid4().hex
        self.preview = None
        self.stopping = threading.Event()
        self.lost = threading.Event()
        self.ownership_lost = threading.Event()
        self.readiness_lock = threading.Lock()
        self.publish_lock = threading.Lock()
        self.readiness = {'phase': 'preparing', 'reason': '', 'catalog_expires': 0, 'checked_at': 0}

    def request(self, suffix: str, data: dict | None = None) -> dict:
        """Never follow redirects, retry an ambiguous claim, or log response credentials."""
        from identity_demo_worker_lease import assert_current
        assert_current()
        if self.transport:
            status, _, body = self.transport.request('/internal/operator/console/' + suffix, self.secret,
                json.dumps(data).encode() if data is not None else None,
                timeout=5 if suffix == 'heartbeat' else 12)
            if status != 200:
                raise ControlRejected(status)
            return json.loads(body)
        from permission_flow import NoRedirect
        client = build_opener(ProxyHandler({}), NoRedirect())
        request = Request(DRIVER + '/internal/operator/console/' + suffix,
            data=json.dumps(data).encode() if data is not None else None,
            headers={'Authorization': 'Bearer ' + self.secret, 'Content-Type': 'application/json'})
        try:
            with client.open(request, timeout=5 if suffix == 'heartbeat' else 12) as response:
                body = response.read(131073)
                if response.status != 200 or len(body) > 131072:
                    raise RuntimeError('Bounded console response required')
                return json.loads(body)
        except HTTPError as error:
            raise ControlRejected(error.code) from None

    def publish(self) -> None:
        """Publish one atomic, bounded readiness snapshot for this process lease."""
        # A delayed older ready heartbeat must not reopen admission after a
        # maintenance pause has completed. Snapshot AFTER taking the send lock.
        with self.publish_lock:
            with self.readiness_lock:
                snapshot = {'worker': self.worker, **self.readiness}
            self.request('heartbeat', snapshot)

    def state(self, phase: str, reason: str = '', **observed: int) -> None:
        """Replace state atomically so heartbeat never assembles mixed observations."""
        with self.readiness_lock:
            self.readiness = {**self.readiness, 'phase': phase, 'reason': reason, **observed}

    def heartbeat(self) -> None:
        """Tolerate brief network loss; a lost lease never authorizes further execution."""
        last_success = time.monotonic()
        while not self.stopping.wait(3):
            try:
                # A live process cannot keep an old successful observation
                # available indefinitely while a read-only check is stalled.
                with self.readiness_lock:
                    if (self.readiness['phase'] == 'ready'
                            and time.time() - self.readiness['checked_at'] > READINESS_MAX_AGE):
                        self.readiness = {**self.readiness, 'phase': 'preparing', 'reason': ''}
                self.publish()
                last_success = time.monotonic()
                self.lost.clear()
            except ControlRejected as error:
                if error.status in (401, 403):
                    self.lost.set()
                    self.ownership_lost.set()
                    return
                if time.monotonic() - last_success >= 15:
                    self.lost.set()
            except Exception:
                if time.monotonic() - last_success >= 15:
                    self.lost.set()
                # A heartbeat is idempotent for this exact process. Jobs and writes are not retried.

    def update(self, run: str, stage: str, evidence: dict | None = None) -> None:
        """Publish a recorded milestone for the exact claimed run."""
        if self.lost.is_set():
            raise RuntimeError('Console control lease unavailable')
        self.request('update', {'worker': self.worker, 'run_id': run,
                               'stage': stage, 'evidence': evidence or {}})


class AttachedFlow:
    """Use the genuine browser-created association instead of automating sign-in/consent."""

    control: Control
    job: dict

    def http(self, *args: object, **kwargs: object) -> tuple:
        from identity_demo_worker_lease import assert_current
        assert_current()
        if kwargs.get('operator') and self.control.transport:
            url = args[0]
            if not isinstance(url, str) or not url.startswith(DRIVER + '/internal/operator/'):
                raise ValueError('Exact driver operator target required')
            if kwargs.get('fields') is not None:
                raise ValueError('Operator form fields refused')
            data = json.dumps(kwargs['value']).encode() if kwargs.get('value') is not None else None
            return self.control.transport.request(url.removeprefix(DRIVER), self.control.secret, data)
        return PermissionFlow.http(self, *args, **kwargs)

    def login(self, context: ExecutionContext) -> dict:
        """Use only the initiating browser session and immutable trusted association."""
        if context.workload != self.job['workload']:
            raise ValueError('Console workload binding mismatch')
        self.run_id, self.user = self.job['run_id'], self.job['user']
        record = self.control.request('runs/' + self.run_id)
        if (record['run']['user'] != self.user or record['run']['workload'] != context.workload
                or record['run']['user_role'] != self.username):
            raise ValueError('Console authenticated user binding mismatch')
        status, _, body = self.http(DRIVER + '/internal/operator/credentials/' + self.run_id, operator=True)
        if status != 200:
            raise RuntimeError('Human reauthentication required before execution')
        value = json.loads(body)
        if value['user'] != self.user or value['workload'] != context.workload:
            raise ValueError('Console credential association mismatch')
        native.private_write(self.args.output_dir / (self.args.label + '.driver-association.json'),
            {'run_id': self.run_id, 'user': self.user, 'workload': context.workload,
             'real_browser_login': True, 'real_browser_submission': True,
             'expires_at': value['expires_at']})
        return {'access_token': value['access_token']}

    def progress(self, stage: str, evidence: dict | None = None) -> None:
        """Relay observed milestones without performing an authorization decision."""
        evidence = dict(evidence or {})
        if evidence.get('backend_fields_match_approval') is True and evidence.get('verified_issue_key'):
            preview = getattr(self.control, 'preview', None)
            evidence['jira_preview_ready'] = bool(preview and preview.allow_key(evidence['verified_issue_key']))
        self.control.update(self.run_id, stage, evidence)

    def approve_proposal(self, report: dict) -> None:
        """Only persisted consent from the authenticated browser owner releases execution."""
        self.progress('awaiting_approval')
        while not self.control.lost.is_set():
            record = self.control.request('runs/' + self.run_id)
            run = record['run']
            if not run['active'] or run['expires'] <= time.time():
                raise RuntimeError('Console run cancelled or expired')
            matches = [a for a in record['actions'] if a['id'] == self.proposal['action_id']]
            if (len(matches) != 1 or matches[0]['digest'] != self.proposal['digest']
                    or json.loads(matches[0]['payload']) != self.proposal['arguments']):
                raise ValueError('Console exact proposal binding mismatch')
            if matches[0]['state'] == 'approved':
                if matches[0]['approver'] != self.user or matches[0]['approval_expires'] <= time.time():
                    raise RuntimeError('Console approval is no longer valid')
                return
            if matches[0]['state'] != 'proposed':
                raise RuntimeError('Console proposal state changed unexpectedly')
            if self.control.stopping.wait(1):
                break
        raise RuntimeError('Console coordinator stopped before approval')

    def close(self) -> None:
        """Revoke this exact run through the original trusted operator endpoint."""
        if self.run_id:
            status, _, _ = self.http(DRIVER + '/internal/operator/revoke',
                                    value={'run_id': self.run_id}, operator=True)
            if status != 200:
                raise RuntimeError('Console run retirement failed')

    def accept(self, execute: object, resource: str, context: ExecutionContext) -> dict:
        """Record genuine native execution and independent outcome evidence."""
        self.progress('identity_verified', {'native_bound_read': True})
        result = super().accept(execute, resource, context)
        gateway = result.get('gateway_introduction', {})
        evidence = {'gateway_ready': bool(gateway.get('passed') and gateway.get('registration_ready')),
                    'tool_names': [t['name'] for t in gateway.get('published_tool_schemas', [])]}
        if result.get('model_inference'):
            evidence.update(model_inference=True, model=result['model_inference']['model'],
                egress_denied=bool(result.get('restricted_connectivity', {}).get('passed')),
                final_token_renewal=bool(result.get('final_token_renewal', {}).get('passed')))
        self.progress('outcome_verified', evidence)
        return result


class ConsoleCveFlow(AttachedFlow, GatewayEvidenceFlow):
    """Keep the original CVE proposal producer and native permission path."""


class ConsoleModelFlow(AttachedFlow, ModelExecutionFlow):
    """Keep the original native Messages provider and protected Jira path."""


class ConsoleIncidentFlow(ConsoleModelFlow):
    """Apply the same bounded read/draft loop to synthetic operational incidents."""

    workflow = 'incident-triage'
    project = 'OPS'
    agent_scope_probe = 'TEST'
    submission = {'request': 'OPS-0001'}
    start_button = 'Start incident triage'
    agent_task = ('Synthetic incident OPS-0001: the training checkout service has intermittent '
                  'timeouts after a deployment. Inspect the authorized OPS project for related '
                  'incidents or follow-up tasks. Draft a concise investigation task that cites '
                  'actual related issue keys and separates observed Jira facts from hypotheses. '
                  'Use only synthetic information; do not claim that remediation has occurred.')


def safe_after_failure(result: dict, record: dict) -> bool:
    """Require positive cleanup evidence, a closed run and no uncertain action."""
    return (result.get('cleanup_verified') is True and bool(record.get('run'))
            and not record['run']['active']
            and not any(a['state'] in ('executing', 'unknown') for a in record.get('actions', [])))


def execute_job(base: argparse.Namespace, control: Control, job: dict) -> bool:
    """Run a context once; continue service only after positively verified cleanup."""
    output = base.output_dir / ('run-' + job['run_id'])
    output.mkdir(mode=0o700)
    context_file = output / 'context.private.json'
    native.private_write(context_file, {k: job['context'][k] for k in ExecutionContext.__dataclass_fields__})
    args = argparse.Namespace(**vars(base))
    args.output_dir, args.context_file = output, str(context_file)
    args.label = 'walkthrough-console-' + job['run_id'][:12]
    args.protected_backend_catalog_credential_file = args.catalog_credential_file
    args.enable_create, args.presentation_only = True, True
    args.reuse_management_session = not getattr(base, 'fresh_management_per_command', False)
    for name in ('investigate_substitution', 'require_substitution_denial', 'check_sender_rejection',
                 'retain_run_retirement', 'check_key_rollover', 'check_backend_rotation', 'check_renewal'):
        setattr(args, name, False)
    for name in ('upstream_development_issuer', 'check_run_binding', 'bound_sender_listener', 'diagnose_native_grant'):
        setattr(args, name, True)
    flow_type = {'cve': ConsoleCveFlow, 'service-request': ConsoleModelFlow,
                 'incident-triage': ConsoleIncidentFlow}[job['workflow']]
    flow = flow_type(args, Path(args.driver_credentials_file), username=job['user_role'])
    flow.control, flow.job, flow.run_id = control, job, job['run_id']
    diagnostic = getattr(base, 'diagnostic_failure', None)
    if diagnostic == 'model-timeout':
        flow.model_request_timeout = .1
    elif diagnostic == 'read-timeout':
        flow.read_request_timeout = .1
    args.permission_flow = flow
    result: dict = {}
    record: dict = {}
    try:
        record = control.request('runs/' + job['run_id'])
        if record['run']['expires'] <= time.time() + 300:
            flow.close()
            result = {'cleanup_verified': True, 'stopped_before_native_execution': True}
            raise RuntimeError('Fresh sign-in required before native execution')
        if diagnostic and job['workflow'] not in ('service-request', 'incident-triage'):
            flow.close()
            result = {'cleanup_verified': True}
            raise RuntimeError('Diagnostic deadlines require a model workflow')
        if getattr(args, 'operator_access_check', False):
            from identity_demo_operator_access import ensure_access
            try:
                ensure_access(args)
            except Exception:
                flow.close()
                result = {'cleanup_verified':True, 'stopped_before_native_execution':True}
                raise
        flow.progress('preparing_identity')
        try:
            result = native.run(args)
        except native.NativeTunnelStartupError:
            # This typed failure is raised only before native_session yields.
            # Its owned tunnel has already been terminated by the context manager.
            # Revoke only this unused run; do not infer safety from generic errors.
            record = control.request('runs/' + job['run_id'])
            if record['actions']:
                raise RuntimeError('Startup failure with unexpected action requires recovery')
            flow.close()
            record = control.request('runs/' + job['run_id'])
            if record['run']['active'] or record['actions']:
                raise RuntimeError('Startup run retirement requires recovery')
            result = {'cleanup_verified': True, 'native_commands_dispatched': 0}
            raise
        native.private_write(output / 'native-result.private.json', result)
        if (not result['passed'] or not result.get('permission_flow', {}).get('passed')
                or result.get('cleanup_verified') is not True):
            raise RuntimeError('Native console scenario failed; inspect private evidence')
        control.update(job['run_id'], 'completed', {'cleanup_verified': True})
        print(json.dumps({'run_id': job['run_id'], 'passed': True, 'workflow': job['workflow']}), flush=True)
        return True
    except BaseException as error:
        import traceback
        native.private_write(output / 'failure.private.json', {'kind': type(error).__name__, 'traceback': traceback.format_exc()})
        try:
            record = control.request('runs/' + job['run_id'])
            cancelled = any(e['event'] == 'cancelled' for e in record['audit'])
            expired = record['run']['expires'] <= time.time() or result.get('stopped_before_native_execution') is True
            inference = bool(list(output.glob('*.inference-failure.summary.json')))
            agent_files = list(output.glob('*.agent-failure.summary.json'))
            agent_failure = json.loads(agent_files[0].read_text()) if agent_files else {}
            safe = safe_after_failure(result, record)
            stage = 'cancelled' if cancelled else 'expired' if expired else 'agent_failed' if agent_failure else 'inference_failed' if inference else 'execution_failed'
            code = ('recovery_required' if not safe else 'cancelled' if cancelled else 'session_expired' if expired
                    else 'agent_failed' if agent_failure else 'model_unavailable' if inference else 'native_read_failed' if result.get('native_read', {}).get('read_passed') is False else 'preparation_failed')
            evidence = {'cleanup_verified': safe, 'failure_code': code}
            if agent_failure:
                evidence['agent_error_category'] = agent_failure.get('error_category', 'agent_validation_failed')
            control.update(job['run_id'], stage, evidence)
        except Exception:
            safe = False
        print(json.dumps({'run_id': job['run_id'], 'passed': False, 'safe_to_continue': safe,
                          'details_withheld': True}), flush=True)
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        return safe



def recover_catalog_reference(args: argparse.Namespace) -> bool:
    """Reuse a previously issued private key only when live owned trust confirms it."""
    import base64
    import hashlib
    from identity_demo_adapter_catalog import owned, TRUST
    trust = owned(args, 'secret', TRUST)
    digests = json.loads(base64.b64decode(trust['data']['digests.json']))
    if not isinstance(digests, dict) or len(digests) > 2:
        raise ValueError('Bounded catalog trust required')
    root = args.output_dir.parent.resolve()
    paths = [Path(args.catalog_credential_file)]
    # Rotation receipts stay in this installation's private operator directory.
    # Never search the repository, other users or unrelated secret locations.
    paths += sorted(root.glob('console-worker-launch-*/catalog-*.private.json'),
                    key=lambda path: path.stat().st_mtime, reverse=True)[:100]
    if os.environ.get('IDENTITY_DEMO_RUNTIME') == 'cluster':
        paths += sorted(args.output_dir.glob('catalog-*.private.json'),
                        key=lambda path: path.stat().st_mtime, reverse=True)[:100]
    candidates = []
    for path in paths:
        try:
            resolved = Path(private_path(str(path)))
            if path.is_symlink() or resolved.stat().st_size > 4096:
                continue
            value = json.loads(resolved.read_text())
            token, expiry = value.get('token'), value.get('expires_at')
            if (not isinstance(token, str) or not token.startswith('discovery_')
                    or type(expiry) is not int or expiry <= time.time() + 600):
                continue
            digest = hashlib.sha256(token.encode()).hexdigest()
            if digests.get(digest) == expiry:
                candidates.append((expiry, str(resolved)))
        except (OSError, ValueError, TypeError):
            continue
    if not candidates:
        return False
    args.catalog_credential_file = max(candidates)[1]
    return True


def refresh_catalog(args: argparse.Namespace) -> int:
    """Rotate only the existing discovery credential while execution is idle."""
    from identity_demo_adapter_catalog import rotate_or_revoke
    name = 'catalog-' + uuid4().hex[:12]
    path = args.output_dir / (name + '.private.json')
    receipt = args.output_dir / (name + '.receipt.private.json')
    request = argparse.Namespace(kubeconfig=args.kubeconfig, expected_server=args.expected_server,
        action='rotate', catalog_credential_file=str(path), receipt_file=str(receipt))
    previous = None
    if getattr(args, 'gateway_mode', 'temporary') == 'persistent':
        from identity_demo_gateway_persistence import catalog_before_rotation
        previous = catalog_before_rotation(args)
    rotate_or_revoke(request)  # An ambiguous mutation is never automatically retried.
    credential = json.loads(private_path(str(path)).read_text())
    args.catalog_credential_file = str(path)
    if getattr(args, 'gateway_mode', 'temporary') == 'persistent':
        from identity_demo_gateway_persistence import rotate_catalog
        rotate_catalog(args, previous)
    return credential['expires_at']


class SenderTrustMutationUncertain(RuntimeError):
    """An owned trust mutation needs reconciliation and cannot be blindly repeated."""


def reconcile_sender_trust(args: argparse.Namespace, before_mutation=None) -> bool:
    """Repair only changed owned copies while admission is paused and state is idle."""
    from identity_demo_sender_trust import current, refresh
    from identity_demo_execution_setup import inspect_state
    from deployment_profile import active_profile
    installation = active_profile().installation_id
    checkpoint = args.output_dir.parent / ('sender-trust-' + installation + '.pending.private.json')
    if checkpoint.exists() or checkpoint.is_symlink():
        raise SenderTrustMutationUncertain('Prior trust mutation needs explicit reconciliation')
    if current(args):
        return True
    if not getattr(args, 'auto_refresh_sender_trust', False):
        return False
    if before_mutation is not None and not before_mutation():
        return False
    cluster_public = os.environ.get('IDENTITY_DEMO_RUNTIME') == 'cluster'
    if cluster_public:
        # The private control callback already closed admission and checked the
        # durable execution lane; runtime has no installer/Pod-exec credential.
        if before_mutation is None:
            return False
        from identity_demo_public_trust import refresh
    elif not inspect_state(args)['rollback_quiescent']:
        return False
    output = args.output_dir / ('sender-trust-' + uuid4().hex)
    output.mkdir(mode=0o700)
    repair = argparse.Namespace(**vars(args))
    repair.output_dir, repair.apply = str(output), True
    pending = {'installation':installation, 'phase':'started', 'receipt_dir':str(output)}
    native.private_write(checkpoint, pending)
    try:
        result = refresh(repair)  # Existing UID/RV/spec tests, complete dry-run and owned resources only.
        if result['issuer_rollout_started']:
            rollout = subprocess.run(['oc', '--kubeconfig', args.kubeconfig, '-n', native.NAMESPACE,
                'rollout', 'status', 'deployment/fixture-keycloak-upstream', '--timeout=90s'],
                capture_output=True, text=True, timeout=100)
            if rollout.returncode:
                raise RuntimeError('Owned issuer rollout is not ready')
        if not current(args):
            raise RuntimeError('Trust bundle changed during reconciliation')
        native.private_write(output / 'automatic-reconciliation.private.json',
            {'passed':True, 'automatic_owned_refresh':True, 'shared_foundation_changed':False,
             'tls_verification_preserved':True, 'quiescence_verified':True})
        if json.loads(private_path(str(checkpoint)).read_text()) != pending:
            raise RuntimeError('Trust checkpoint changed during reconciliation')
        checkpoint.unlink()
        return True
    except Exception:
        raise SenderTrustMutationUncertain('Owned sender trust needs operator reconciliation; no automatic replay') from None


def pause_for_maintenance(control: Control) -> bool:
    """Close admission before a mutation and recheck the authoritative lane."""
    control.state('preparing')
    control.publish()
    state = control.request('state')
    return not any(state.get(key) for key in ('busy', 'running', 'uncertain', 'recovery_required'))


def readiness_check(args: argparse.Namespace, control: Control) -> bool:
    """Observe prerequisites before accepting jobs; renew only the bounded catalog key."""
    previous = control.readiness
    try:
        from managed_certificates import runtime_status
        runtime_status()
    except Exception:
        control.state('blocked', 'invalid_configuration')
        control.publish()
        print(json.dumps({'application_certificate_check_failed': True,
                          'action': 'run certificate-status; inspect issuer and loaded leaf'}), flush=True)
        return False
    # Browser admission may reuse a recent successful observation. This loop
    # still completes every check before it can claim a queued job. Startup,
    # stale observations and credential/trust mutations keep admission closed.
    if not (previous.get('phase') == 'ready' and not previous.get('reason')
            and 0 <= time.time() - previous.get('checked_at', 0) <= READINESS_MAX_AGE
            and previous.get('catalog_expires', 0) > time.time() + 900):
        control.state('preparing')
        control.publish()
    try:
        if getattr(args, 'operator_access_check', False):
            from identity_demo_operator_access import ensure_access
            ensure_access(args)
        guard(args)
        private_inference(args.inference_config)
    except OperatorAccessUnavailable:
        control.state('blocked', 'operator_login')
        control.publish()
        return False
    except Exception:
        control.state('blocked', 'cluster_unavailable')
        control.publish()
        return False
    state = control.request('state')
    if getattr(control, 'preview', None) is not None:
        control.preview.set_keys(state.get('verified_issue_keys', []))
    if state.get('running') or state.get('uncertain') or state.get('recovery_required'):
        control.state('blocked', 'recovery_required')
        control.publish()
        return False
    try:
        recover_catalog_reference(args)
    except Exception:
        control.state('blocked', 'cluster_unavailable')
        control.publish()
        return False
    credential = json.loads(private_path(args.catalog_credential_file).read_text())
    expiry = credential.get('expires_at', 0)
    if type(expiry) is not int or not isinstance(credential.get('token'), str) or not credential['token'].startswith('discovery_'):
        control.state('blocked', 'invalid_configuration')
        control.publish()
        return False
    if expiry <= time.time() + 900 and args.auto_refresh_catalog:
        if not pause_for_maintenance(control):
            control.state('preparing', 'catalog_expiring', catalog_expires=expiry)
            control.publish()
            return False
        from identity_demo_adapter_catalog import CatalogRotationDeferred
        try:
            expiry = refresh_catalog(args)
        except CatalogRotationDeferred:
            # The read-only capacity check made no credential or cluster change.
            # Keep the existing lifetime gates and observe again next interval.
            pass
        except Exception:
            control.state('blocked', 'catalog_refresh_failed')
            control.publish()
            raise RuntimeError('Catalog refresh needs operator review; do not retry blindly') from None
    if expiry <= time.time() + 600:
        control.state('preparing' if args.auto_refresh_catalog else 'blocked', 'catalog_expiring', catalog_expires=expiry)
        control.publish()
        return False
    state = control.request('state')
    if getattr(control, 'preview', None) is not None:
        control.preview.set_keys(state.get('verified_issue_keys', []))
    if state.get('running') or state.get('uncertain') or state.get('recovery_required'):
        control.state('blocked', 'recovery_required')
        control.publish()
        return False
    # Discovery renewal is independent of workload CA trust. Keep its bounded
    # credential alive while trust admission is stopped, avoiding a second outage.
    try:
        if not reconcile_sender_trust(args, lambda: pause_for_maintenance(control)):
            control.state('blocked', 'sender_trust')
            control.publish()
            return False
    except SenderTrustMutationUncertain:
        control.state('blocked', 'sender_trust')
        control.publish()
        raise
    except Exception:
        control.state('blocked', 'sender_trust')
        control.publish()
        return False  # Observation failed before mutation; safe to observe again.
    # Observe node churn before accepting a run. Policy changes require the
    # explicit guarded operator command; readiness never mutates network rules.
    from identity_demo_spire_network import kubelet_coverage_current
    try:
        if os.environ.get('IDENTITY_DEMO_RUNTIME') == 'cluster':
            # Node/network inventory is an installer responsibility. Runtime
            # observes the installed exact-Pod policy; actual attestation and
            # possession of the SVID are still proved by the protected read.
            from identity_demo_controller_identity import verify_gateway
            from identity_demo_execution_setup import read
            verify_gateway(lambda kind, name, ns=None: read(args, kind, name, ns))
            covered = True
        else:
            covered = kubelet_coverage_current(args.kubeconfig)
    except Exception:
        control.state('blocked', 'cluster_unavailable')
        control.publish()
        return False
    if not covered:
        control.state('blocked', 'identity_network')
        control.publish()
        return False
    if getattr(args, 'gateway_mode', 'temporary') == 'persistent':
        try:
            from identity_demo_gateway_persistence import verify, rotate_catalog
            from identity_demo_execution_setup import read
            # This runs while admission is paused and no run executes. Rotation
            # is limited to the recorded catalog Secret; all other drift blocks.
            if rotate_catalog(args, before_mutation=lambda: pause_for_maintenance(control)) is False:
                control.state('preparing', 'catalog_expiring', catalog_expires=expiry)
                control.publish()
                return False
            ca = read(args, 'configmap', 'fixture-service-ca', native.NAMESPACE)['data']['service-ca.crt']
            verify(args, ca)
            if os.environ.get('IDENTITY_DEMO_RUNTIME') == 'cluster':
                from identity_demo_gateway_observation import current
                current(args, ca)
        except Exception:
            control.state('blocked', 'invalid_configuration')
            control.publish()
            return False
    control.state('ready', catalog_expires=expiry, checked_at=int(time.time()))
    control.publish()
    return True



def recover_reviewed_cleanup(control: Control) -> bool:
    """Resume only after durable operator review cleared recovery and all work is idle."""
    if control.ownership_lost.is_set() or control.lost.is_set():
        return False
    try:
        state = control.request('state')
        return (state.get('enabled') is True and state.get('online') is True and state.get('running') == 0
                and state.get('uncertain') == 0 and state.get('busy') is False
                and state.get('preparing_context') is False
                and state.get('recovery_required') is False)
    except Exception:
        return False


def recover_idle_control(control: Control) -> bool:
    """Recheck a harmless control outage without replaying an ambiguous claimed job."""
    if control.ownership_lost.is_set() or control.lost.is_set():
        return False
    try:
        state = control.request('state')
        if (state.get('enabled') is not True or type(state.get('running')) is not int
                or type(state.get('uncertain')) is not int
                or state.get('recovery_required') is not False):
            return False
        if state['running'] or state['uncertain']:
            control.state('blocked', 'recovery_required')
            return False
        # Queued work is safe: the failed request did not claim it, as proved by
        # running=0. A successful heartbeat revalidates this exact worker lease.
        control.state('preparing')
        control.publish()
        return True
    except ControlRejected as error:
        if error.status in (401, 403):
            control.ownership_lost.set()
        return False
    except Exception:
        return False


def main() -> None:
    """Serve checked fresh runs while keeping failures and recovery visible."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('kubeconfig', 'expected-server', 'credentials-file', 'cli', 'cli-config-dir',
                 'catalog-credential-file', 'driver-credentials-file', 'inference-config', 'output-dir'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--management-port', type=int, default=18443)
    parser.add_argument('--ca-file', help='Explicit native management CA for cluster bootstrap')
    parser.add_argument('--gateway-mode', choices=('temporary','persistent'), default='temporary')
    parser.add_argument('--gateway-receipt')
    parser.add_argument('--operator-login-file', help='Optional private same-operator login for proactive renewal')
    parser.set_defaults(operator_access_check=True)
    parser.add_argument('--auto-refresh-sender-trust', action='store_true',
                        help='Reconcile only owned issuer/listener public SPIRE trust while idle')
    parser.add_argument('--auto-refresh-catalog', action='store_true', help='Renew only catalog discovery access while idle')
    parser.add_argument('--fresh-management-per-command', action='store_true',
                        help='Rollback: reconnect and authenticate before every native command')
    parser.add_argument('--stop-after', type=int, default=0, help='Exit after this many jobs; zero keeps serving')
    parser.add_argument('--diagnostic-failure', choices=('model-timeout', 'read-timeout'),
                        help='Controlled acceptance only: shorten one read-only deadline; requires --stop-after 1')
    from identity_demo_operator_access import runtime_arguments
    runtime_arguments(parser)
    args = parser.parse_args()
    if args.diagnostic_failure and args.stop_after != 1:
        parser.error('Diagnostic failure injection requires exactly --stop-after 1')
    os.umask(0o077)
    args.namespace = native.NAMESPACE
    args.output_dir = Path(args.output_dir)
    private_path(str(args.output_dir.parent), directory=True)
    args.output_dir.mkdir(mode=0o700, exist_ok=os.environ.get('IDENTITY_DEMO_RUNTIME') == 'cluster')
    import fcntl
    process_lock = (args.output_dir / 'coordinator.lock').open('a')
    fcntl.flock(process_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    keys = json.loads(private_path(args.driver_credentials_file).read_text())
    control = Control(keys['operator_secret'])
    from identity_demo_worker_lease import install
    lease = install(args, 'coordinator')
    if lease:
        if not args.ca_file:
            raise ValueError('Cluster coordinator requires management trust')
        from identity_demo_runtime import guard
        _, runtime_credentials, _ = guard(args)
        startup = argparse.Namespace(**vars(args))
        startup.output_dir = args.output_dir / ('startup-' + uuid4().hex)
        startup.output_dir.mkdir(mode=0o700)
        startup.label = 'coordinator-management'
        with native.native_session(startup, runtime_credentials, initialize_profile=True):
            pass
    import signal
    signal.signal(signal.SIGTERM, lambda *_: control.stopping.set())
    signal.signal(signal.SIGINT, lambda *_: control.stopping.set())
    control.publish()
    thread = threading.Thread(target=control.heartbeat, daemon=True)
    thread.start()
    if os.environ.get('IDENTITY_DEMO_RUNTIME', 'local') != 'cluster':
        from jira_ui_preview import ManagedPreview
        control.preview = ManagedPreview(args, control.stopping)
        control.preview.start()
    jobs, checked_at, blocked = 0, 0.0, False
    print(json.dumps({'coordinator_started': True, 'browser_url': DRIVER}), flush=True)
    try:
        while not control.ownership_lost.is_set() and not control.stopping.is_set():
            if control.lost.is_set() or blocked:
                if (blocked and control.readiness['reason'] == 'recovery_required'
                        and recover_reviewed_cleanup(control)):
                    blocked, checked_at = False, 0
                elif (blocked and control.readiness['reason'] == 'control_unavailable'
                        and recover_idle_control(control)):
                    blocked, checked_at = False, 0
                else:
                    control.stopping.wait(3)
                continue
            if time.monotonic() - checked_at >= 60:
                try:
                    ready = readiness_check(args, control)
                    checked_at = time.monotonic()
                    if not ready:
                        control.stopping.wait(3)
                        continue
                except (OSError, ControlRejected):
                    control.state('reconnecting', 'control_unavailable')
                    blocked = True
                    continue
                except Exception:
                    # A failed credential mutation still requires explicit review.
                    control.state('blocked', control.readiness['reason'] if control.readiness['reason'] in ('catalog_refresh_failed', 'sender_trust') else 'recovery_required')
                    blocked = True
                    continue
            if control.readiness['phase'] != 'ready':
                control.stopping.wait(1)
                continue
            try:
                job = control.request('next', {'worker': control.worker})['job']
                if job:
                    safe = execute_job(args, control, job)
                    jobs += 1
                    if not safe:
                        control.state('blocked', 'recovery_required')
                        blocked = True
                    else:
                        checked_at = 0  # Recheck idle prerequisites after restoration.
                    if args.stop_after and jobs >= args.stop_after:
                        break
                elif control.stopping.wait(1):
                    break
            except Exception:
                control.state('reconnecting', 'control_unavailable')
                blocked = True  # Inspect durable claim/write state before resuming.
    finally:
        control.state('stopping')
        try:
            control.publish()
        except Exception:
            pass
        control.stopping.set()
        thread.join(timeout=7)
        if control.preview is not None:
            control.preview.thread.join(timeout=7)
        if lease:
            lease.close()


if __name__ == '__main__':
    main()
