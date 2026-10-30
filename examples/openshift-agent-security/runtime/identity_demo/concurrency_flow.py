# SPDX-License-Identifier: Apache-2.0
"""Native four-context acceptance on the retained driver/gateway architecture."""
from __future__ import annotations

import argparse
from copy import deepcopy
from html import unescape
import json
from pathlib import Path
import time

import yaml

from identity_demo_action_policy import DRIVER
from permission_flow import PermissionFlow
import probe_native_exchange as native
from run_binding import ReadRun
import identity_demo_fixture_http as components
from deployment_profile import active_profile

RESOURCE = 'https://' + active_profile().service_host('fixture-mcp-bound') + '/mcp'


def timed_program(resource: str, tool: str, arguments: dict, success: str, start: float) -> str:
    """Synchronize actual tool calls and return safe request timing evidence."""
    program = native.read_program(resource, tool, arguments, success)
    program = program.replace('import base64, json, os, re,', 'import time, base64, json, os, re,')
    program = program.replace('    request = urllib.request.Request', (
        "    if method == 'tools/call': time.sleep(max(0, " + repr(start) + ' - time.time()))\n'
        '    sent_at = time.time()\n    request = urllib.request.Request'))
    return program.replace('events.append({"method":method,"http_status":response.status})',
        'events.append({"method":method,"http_status":response.status,"sent_at":sent_at,"received_at":time.time()})')


def overlapping(values: list[dict]) -> bool:
    """Require overlapping tool requests, rather than merely simultaneous live runs."""
    calls = [next((e for e in v['events'] if e['method'] == 'tools/call'), None) for v in values]
    return all(c is not None for c in calls) and max(c['sent_at'] for c in calls) < min(
        c['received_at'] for c in calls)


class ConcurrencyFlow(PermissionFlow):
    """Keep independent browser sessions and native providers for four fresh runs."""

    def __init__(self, args: argparse.Namespace, secrets_file: Path) -> None:
        super().__init__(args, secrets_file)
        self.secrets_file = secrets_file
        self.peers: list[tuple[PermissionFlow, object, dict]] = []
        self.peer_bindings: list[ReadRun] = []
        self.runtime_records: list[dict] = []
        self.execute = None

    def login(self, context: object) -> dict:
        """Allocate distinct trusted contexts through real analyst/viewer browser login."""
        login = super().login(context)
        assert [c.role for c in self.extra_contexts] == ['triage', 'triage', 'reader']
        for index, peer in enumerate(self.extra_contexts):
            args = argparse.Namespace(**{**vars(self.args), 'label': self.args.label + '-peer-' + str(index)})
            flow = PermissionFlow(args, self.secrets_file, 'viewer' if index == 0 else 'analyst')
            token = flow.login(peer)
            claims = components.verify(token['access_token'], native.GATEWAY, issuer=components.ISSUER)
            assert claims['sub'] == flow.user and claims['azp'] == 'identity-demo-driver'
            self.peers.append((flow, peer, token))
            self.peer_bindings.append(ReadRun(flow.run_id, claims['iss'], flow.user,
                peer.workload, RESOURCE, int(time.time()), claims['exp']))
        assert self.user == self.peers[1][0].user == self.peers[2][0].user
        assert self.user != self.peers[0][0].user
        return login

    def attach_peers(self, execute: object) -> None:
        """Use separate credentials and independently validated operator workspaces."""
        self.execute = execute
        for flow, context, token in self.peers:
            def peer_exec(words: list[str], **kwargs: object) -> object:
                """Keep profile, provider and attachment in the same validated workspace."""
                return execute(words, execution_context=context, **kwargs)

            prefix = context.provider_prefix
            profiles = native.inventory(peer_exec(['provider', 'profile', 'list', '-o', 'json'], json_output=True), 'profiles')
            providers = native.inventory(peer_exec(['provider', 'list', '-o', 'json'], json_output=True), 'providers')
            assert not any(p.get('id') == prefix for p in profiles)
            assert not any(p.get('name') == prefix for p in providers)
            profile = deepcopy(self.runtime_profile)
            profile['id'] = prefix
            profile['display_name'] = 'Isolated controlled concurrent context'
            filename = self.args.output_dir / (flow.args.label + '.profile.yaml')
            native.private_write(filename, yaml.safe_dump(profile, sort_keys=False))
            peer_exec(['provider', 'profile', 'lint', '-f', str(filename)])
            peer_exec(['provider', 'profile', 'import', '-f', str(filename)])
            record = {'context': context, 'prefix': prefix, 'profile': True, 'provider': False, 'attached': False}
            self.runtime_records.append(record)
            peer_exec(['provider', 'create', '--name', prefix, '--type', prefix,
                     '--credential', 'subject_token', '--config', 'identity-demo-owner=' + active_profile().owner,
                     '--config', 'identity-demo-experiment=' + native.EXPERIMENT], subject=token['access_token'])
            records = native.inventory(peer_exec(['provider', 'list', '-o', 'json'], json_output=True), 'providers')
            created = [p for p in records if p.get('name') == prefix and p.get('type') == prefix]
            assert len(created) == 1 and created[0].get('id')
            record.update(provider=True, provider_id=created[0]['id'])
            claims = components.verify(token['access_token'], native.GATEWAY, issuer=components.ISSUER)
            peer_exec(['provider', 'update', prefix, '--credential-expires-at',
                     'subject_token=' + str(claims['exp'] * 1000)])
            peer_exec(['sandbox', 'provider', 'attach', context.sandbox_name, prefix,
                     '--wait', '--timeout', '30', '--output', 'json'])
            record['attached'] = True

    @staticmethod
    def call(execute: object, context: object, resource: str, arguments: dict, create: bool = False) -> dict:
        """Invoke the actual CVE image without application-supplied credentials."""
        return execute(['sandbox', 'exec', '--name', context.sandbox_name, '--no-login-shell',
            '--timeout', '90', '--no-tty', '--', 'python', '-c', native.read_program(resource,
                'step56_jira_createJiraIssue' if create else 'step56_jira_readJiraProject',
                arguments, 'key' if create else 'project_scope')],
            json_output=True, execution_context=context)

    def accept(self, execute: object, resource: str, context: object) -> dict:
        """Prove simultaneous permissions, substitution denials and single dispatch."""
        assert resource == RESOURCE
        before = self.backend_count()
        self.attach_peers(execute)
        entries = [(self, context, None), *self.peers]
        started = time.time() + 12
        reads = execute.parallel([(c, timed_program(resource, 'step56_jira_readJiraProject',
            {'run_id': f.run_id, 'project': 'TEST'}, 'project_scope', started)) for f, c, _ in entries])
        assert all(v['read_passed'] for v in reads) and overlapping(reads)
        assert self.backend_count() == before
        cases = [{'case': 'four_simultaneous_permitted_reads', 'passed': True, 'request_intervals_overlap': True}]

        fixture = Path(__file__).with_name('cve_runtime_fixture.py').read_text()
        report = execute(['sandbox', 'exec', '--name', context.sandbox_name, '--no-login-shell',
            '--timeout', '90', '--no-tty', '--', 'python', '-c',
            "ns={'__name__':'fixture'};exec(" + repr(fixture) + ",ns);import asyncio,json;print(json.dumps(asyncio.run(ns['assessment_fixture']())))"], json_output=True)
        arguments = []
        for flow, peer, _ in entries:
            status, _, body = flow.http(DRIVER + '/internal/operator/report', operator=True,
                value={'run_id': flow.run_id, 'user': flow.user, 'workload': peer.workload,
                       'assessment': report['assessment'], 'arguments': report['proposed_create']})
            assert status == 200
            flow.proposal = json.loads(body)
            status, _, page = flow.http(DRIVER + '/runs/' + flow.run_id)
            assert status == 200 and report['assessment'] in unescape(page.decode())
            status, _, _ = flow.http(DRIVER + '/runs/' + flow.run_id + '/approve',
                fields={'csrf': flow.csrf, 'action': flow.proposal['action_id'], 'digest': flow.proposal['digest']})
            assert status == 303
            arguments.append({'run_id': flow.run_id, 'action_id': flow.proposal['action_id'], **flow.proposal['arguments']})

        started = time.time() + 12
        denied = execute.parallel([
            (entries[1][1], timed_program(resource, 'step56_jira_createJiraIssue', arguments[1], 'key', started)),
            (entries[3][1], timed_program(resource, 'step56_jira_createJiraIssue', arguments[3], 'key', started)),
        ])
        for value, reason in zip(denied, ('user_permission', 'workload_permission'), strict=True):
            assert not value['read_passed'] and any(e.get('http_status') == 403 and e.get('denial_reason') == reason for e in value['events'])
        assert overlapping(denied) and self.backend_count() == before
        cases.append({'case': 'simultaneous_viewer_reader_approved_denials', 'passed': True, 'request_intervals_overlap': True})

        crossed = self.call(execute, entries[2][1], resource, arguments[0], create=True)
        assert not crossed['read_passed'] and any(e.get('denial_reason') == 'run_binding' for e in crossed['events'])
        changed = deepcopy(arguments[0])
        changed['action_id'] = arguments[2]['action_id']
        crossed = self.call(execute, context, resource, changed, create=True)
        assert not crossed['read_passed'] and any(e.get('denial_reason') == 'action_binding' for e in crossed['events'])
        status, _, _ = entries[1][0].http(DRIVER + '/runs/' + self.run_id)
        assert status == 403 and self.backend_count() == before
        cases.append({'case': 'run_action_and_cross_user_report_substitution_denied', 'passed': True})

        started = time.time() + 12
        creates = execute.parallel([(context, timed_program(resource, 'step56_jira_createJiraIssue', arguments[0], 'key', started))] * 2)
        assert overlapping(creates) and self.backend_count() == before + 1
        successful = [v['verified_tool_result'] for v in creates if v['read_passed']]
        assert successful and sum(v['duplicate'] is False for v in successful) == 1
        key = successful[0]['key']
        assert all(v['key'] == key for v in successful)
        for value in creates:
            if not value['read_passed']:
                assert value.get('mcp_error_reason') == 'action_executing' or any(
                    e.get('http_status') == 403 and e.get('denial_reason') == 'action_executing'
                    for e in value['events'])
        duplicate = self.call(execute, context, resource, arguments[0], create=True)
        assert duplicate['read_passed'] and duplicate['verified_tool_result'] == {'key': key, 'duplicate': True}
        outcome = self.verify_created_outcome(key, context.workload)
        cases.append({'case': 'concurrent_create_single_dispatch_and_safe_retry', 'passed': True, 'request_intervals_overlap': True})

        viewer = entries[1][0]
        audit = """import os,json,sqlite3
d=sqlite3.connect('file:'+os.environ['DRIVER_DATABASE']+'?mode=ro',uri=True)
v=d.execute('SELECT detail FROM audit WHERE run_id=? AND action_id=? AND event=?',(RUN,ACTION,'denied')).fetchall()
assert any(json.loads(row[0])['reason']=='user_permission' for row in v)
print(json.dumps({'live_viewer_denial_audited':True}))""".replace('RUN', repr(viewer.run_id)).replace('ACTION', repr(viewer.proposal['action_id']))
        from recovery_flow import RecoveryFlow
        audited = RecoveryFlow.cluster_python(self, 'fixture-identity-driver', audit)
        assert audited['live_viewer_denial_audited']
        self.close()
        cancelled = self.call(execute, context, resource, {'run_id': self.run_id, 'project': 'TEST'})
        assert not cancelled['read_passed'] and self.backend_count() == before + 1
        summary = {'passed': True, 'cases': cases, 'contexts': len(entries),
                   'two_users_and_two_analyst_triage_runs': True, 'viewer_denial_audited': True,
                   'verified_issue_key': key, 'outcome_checks': outcome,
                   'backend_before': before, 'backend_after': self.backend_count(), 'steps5_and6_complete': False}
        native.private_write(self.args.output_dir / (self.args.label + '.concurrency.summary.json'), summary)
        return summary

    def close(self) -> None:
        """Close every run and remove only the recorded peer provider/profile IDs."""
        for flow, _, _ in self.peers:
            try:
                flow.close()
            except AssertionError:
                flow.authenticate()
                flow.close()
        try:
            super().close()
        except AssertionError:
            self.authenticate()
            super().close()
        if self.execute is None:
            return
        for record in reversed(self.runtime_records):
            prefix, context = record['prefix'], record['context']
            if record['attached']:
                # Detachment is idempotent cleanup, unlike an effectful tool call.
                # A background sandbox revision can race the CLI's CAS lookup.
                for attempt in range(3):
                    attached = native.inventory(self.execute(['sandbox', 'provider', 'list',
                        context.sandbox_name, '-o', 'json'], json_output=True,
                        execution_context=context), 'providers')
                    if not any(p.get('name') == prefix for p in attached):
                        break
                    providers = native.inventory(self.execute(['provider', 'list', '-o', 'json'],
                        json_output=True, execution_context=context), 'providers')
                    native.require_native_provider_id(providers, record['provider_id'], prefix)
                    try:
                        self.execute(['sandbox', 'provider', 'detach', context.sandbox_name, prefix,
                            '--wait', '--timeout', '30'], execution_context=context)
                    except RuntimeError:
                        if attempt == 2:
                            raise
                attached = native.inventory(self.execute(['sandbox', 'provider', 'list',
                    context.sandbox_name, '-o', 'json'], json_output=True,
                    execution_context=context), 'providers')
                assert not any(p.get('name') == prefix for p in attached)
                record['attached'] = False
            if record['provider']:
                providers = native.inventory(self.execute(['provider', 'list', '-o', 'json'], json_output=True, execution_context=context), 'providers')
                native.require_native_provider_id(providers, record['provider_id'], prefix)
                self.execute(['provider', 'delete', prefix], execution_context=context)
                record['provider'] = False
            if record['profile']:
                self.execute(['provider', 'profile', 'delete', prefix], execution_context=context)
                record['profile'] = False
