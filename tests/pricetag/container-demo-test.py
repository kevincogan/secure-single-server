#!/usr/bin/env python3
"""Check that disposable deployment diagnostics cannot publish raw credentials."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch, mock_open
import subprocess
import json
import contextlib
import io

spec = importlib.util.spec_from_file_location('container_demo', Path(__file__).with_name('container-demo.py'))
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)


smoke_spec = importlib.util.spec_from_file_location('database_smoke', Path(__file__).with_name('database-smoke.py'))
smoke = importlib.util.module_from_spec(smoke_spec)
smoke_spec.loader.exec_module(smoke)


class DatabaseSmokeTests(unittest.TestCase):
    def test_failure_logs_only_disposable_database_and_redacts_password(self):
        output = io.StringIO()
        logs = subprocess.CompletedProcess([], 0, 'Permission denied: /dev/null\npassword=synthetic-secret', '')
        with patch.object(smoke.os, 'geteuid', return_value=0), \
                patch.object(smoke.os, 'umask'), \
                patch.object(smoke.secrets, 'token_urlsafe', return_value='synthetic-secret'), \
                patch.object(smoke.demo, 'podman', return_value='runtime info'), \
                patch.object(smoke.demo, 'postgres_identity', return_value=(70, 70)), \
                patch.object(smoke.demo, 'run') as run, \
                patch.object(smoke.demo, 'wait_database', side_effect=RuntimeError('private error')), \
                patch.object(smoke.subprocess, 'run', return_value=logs) as process, \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            with self.assertRaises(SystemExit) as caught:
                smoke.main()
        self.assertEqual(caught.exception.code, 1)
        self.assertIn('Permission denied: /dev/null', output.getvalue())
        self.assertNotIn('synthetic-secret', output.getvalue())
        self.assertNotIn('private error', output.getvalue())
        command = run.call_args.args[0]
        self.assertEqual(command[command.index('--network') + 1], 'none')
        self.assertNotIn('synthetic-secret', command)
        self.assertNotIn('-v', command)
        self.assertNotIn('-p', command)
        self.assertEqual(process.call_args_list[0].args[0][1], 'logs')
        self.assertEqual(process.call_args_list[-1].args[0][1:3], ['rm', '-f'])


class AuditMetadataTests(unittest.TestCase):
    def test_signal_policy_metadata_preserved_but_sensitive_fields_omitted(self):
        line = ('apparmor="DENIED" operation="signal" profile="pricetag-demo-ci" '
                'peer="pricetag-demo-ci//&/usr/bin/crun" comm="pg_ctl" '
                'signal=int requested_mask="send" denied_mask="send" '
                'name="private-file" argv="private-token"')
        rows = smoke.signal_denials(line)
        self.assertEqual(rows[0]['peer'], 'pricetag-demo-ci//&/usr/bin/crun')
        self.assertEqual(rows[0]['signal'], 'int')
        self.assertNotIn('private', json.dumps(rows))
        self.assertEqual(smoke.signal_denials(line + '\n' + line), rows)
        self.assertEqual(smoke.signal_denials(line.replace('operation="signal"', 'operation="open"')), [])
        self.assertEqual(smoke.signal_denials(line.replace('comm="pg_ctl"', 'comm="unrelated"')), [])
        self.assertEqual(smoke.signal_denials(line.replace('apparmor="DENIED"', 'apparmor="ALLOWED"')), [])

    def test_ci_profile_covers_observed_stacked_signal_peers(self):
        policy = Path(__file__).with_name('ci.apparmor').read_text()
        for peer in ('crun//&pricetag-demo-ci', 'pricetag-demo-ci//&crun'):
            with self.subTest(peer=peer):
                audit = ('apparmor="DENIED" operation="signal" profile="pricetag-demo-ci" '
                         f'peer="{peer}" comm="pg_ctl" signal=int denied_mask="send"')
                observed = smoke.signal_denials(audit)[0]['peer']
                self.assertIn(f'signal (send,receive) peer="{observed}",', policy)
        self.assertNotIn('signal (send,receive) peer=*,', policy)
        self.assertIn('deny mount,', policy)

    def test_journal_error_does_not_publish_exception(self):
        output = io.StringIO()
        with patch.object(smoke.subprocess, 'run', side_effect=OSError('private details')), \
                contextlib.redirect_stderr(output):
            smoke.report_signal_denials(123)
        self.assertEqual(output.getvalue().strip(), 'AppArmor audit metadata unavailable')


class DiagnosticTests(unittest.TestCase):
    def test_known_failures_emit_only_fixed_codes(self):
        for message, expected in (
                ('No space left on device', 'database-storage-full'),
                ('Permission denied', 'database-permission-denied'),
                ('Out of memory', 'database-out-of-memory')):
            with self.subTest(message=message):
                diagnostic = f'password=do-not-publish\nFATAL: {message}\npostgres://secret@db'
                self.assertEqual(demo.database_failure_reason(diagnostic), expected)

    def test_unrecognized_failure_does_not_echo_logs(self):
        self.assertEqual(demo.database_failure_reason('secret-key-value'),
                         'database-bootstrap-failed')
        self.assertEqual(demo.database_failure_reason(''), 'database-bootstrap-failed')


class StartupEvidenceTests(unittest.TestCase):
    def test_startup_progress_is_fixed_codes_not_log_text(self):
        logs = ('secret=value\ncreating configuration files ... ok\n'
                'running bootstrap script ... ok\nperforming post-bootstrap initialization ... ok\n'
                'syncing data to disk ... ')
        self.assertEqual(demo.database_startup_progress(logs),
                         ['configuration-created', 'bootstrap-complete', 'post-bootstrap-complete',
                          'data-sync-started'])
        self.assertEqual(demo.database_startup_progress('password=secret'), [])

    def test_complete_startup_and_application_sql_are_distinct(self):
        logs = ('syncing data to disk ... ok\n'
                '/usr/local/bin/docker-entrypoint.sh: running '
                '/docker-entrypoint-initdb.d/10-create-databases.sql\n'
                'PostgreSQL init process complete; ready for start up.\n')
        self.assertEqual(demo.database_startup_progress(logs),
                         ['data-sync-started', 'data-sync-complete', 'application-sql-started',
                          'entrypoint-complete'])

    def test_process_evidence_is_allowlisted_without_arguments(self):
        with patch.object(demo, 'podman', return_value='COMMAND\nbash\ninitdb\nsecret-value\n'):
            self.assertEqual(demo.database_processes('isolated-db'), ['bash', 'initdb', 'other'])


class DatabaseIdentityTests(unittest.TestCase):
    def test_image_account_is_resolved_without_privileges_or_network(self):
        with patch.object(demo, 'podman', return_value='70\n70') as command:
            self.assertEqual(demo.postgres_identity(), (70, 70))
        args=command.call_args.args
        self.assertIn('no-new-privileges', args)
        self.assertIn('--read-only', args)
        self.assertIn('none', args)
        self.assertIn('--cap-drop', args)

    def test_invalid_or_root_account_is_rejected(self):
        for output in ('0\n0', '70', '70\nsecret', '70\n70\nextra', '-1\n70'):
            with self.subTest(output=output), patch.object(demo, 'podman', return_value=output):
                with self.assertRaises(ValueError):
                    demo.postgres_identity()


class BootstrapTests(unittest.TestCase):
    def test_sql_uses_stdin_and_readiness_is_checked_before_and_after(self):
        events = []
        with patch.object(demo, 'wait_database', side_effect=lambda *a, **k: events.append(('ready', k))), \
                patch.object(demo, 'run', side_effect=lambda *a, **k: events.append(('sql', a, k))) as run, \
                patch.object(Path, 'open', mock_open(read_data='private SQL')) as sql:
            demo.bootstrap_database('db')
        self.assertEqual([event[0] for event in events], ['ready', 'sql', 'ready'])
        self.assertEqual(events[0][1], {'database_name': 'postgres'})
        command = run.call_args.args[0]
        self.assertIn('ON_ERROR_STOP=1', command)
        self.assertIn('-i', command)
        self.assertNotIn('private SQL', ' '.join(command))
        self.assertIs(run.call_args.kwargs['stdin'], sql.return_value)

    def test_sql_error_aborts_before_application_readiness(self):
        error = subprocess.CalledProcessError(1, ['psql'])
        with patch.object(demo, 'wait_database') as ready, \
                patch.object(demo, 'run', side_effect=error), \
                patch.object(Path, 'open', mock_open(read_data='bad SQL')):
            with self.assertRaises(subprocess.CalledProcessError):
                demo.bootstrap_database('db')
        ready.assert_called_once_with('db', database_name='postgres')


class ReadinessTests(unittest.TestCase):
    def test_stopped_database_preserves_probe_error(self):
        error = subprocess.CalledProcessError(1, ['podman'], stderr='private diagnostic')
        with patch.object(demo, 'podman', side_effect=[error, 'false']), \
                patch.object(demo.time, 'sleep') as sleep:
            with self.assertRaises(subprocess.CalledProcessError) as caught:
                demo.wait_database('isolated-db')
        self.assertIs(caught.exception, error)
        sleep.assert_not_called()

    def test_running_database_retries_until_tcp_ready(self):
        error = subprocess.CalledProcessError(1, ['podman'])
        with patch.object(demo, 'podman', side_effect=[error, 'true', '1']) as command, \
                patch.object(demo.time, 'sleep'):
            demo.wait_database('isolated-db')
        probe = command.call_args.args
        self.assertIn('-h 127.0.0.1', probe[-3])
        self.assertIn('PGPASSWORD="$POSTGRES_PASSWORD"', probe[-3])
        self.assertEqual(probe[-1], 'maas')

    def test_timeout_preserves_probe_error(self):
        error = subprocess.CalledProcessError(1, ['podman'], stderr='Connection refused')
        with patch.object(demo, 'podman', side_effect=[error, 'true']), \
                patch.object(demo.time, 'sleep'):
            with self.assertRaises(subprocess.CalledProcessError):
                demo.wait_database('isolated-db', attempts=1)

    def test_public_state_excludes_arbitrary_inspect_fields(self):
        data = [{'State': {'Running': False, 'ExitCode': 1, 'OOMKilled': False,
                           'Error': 'secret-value', 'Pid': 123}}]
        with patch.object(demo, 'podman', return_value=json.dumps(data)):
            self.assertEqual(demo.database_state('isolated-db'),
                             {'Running': False, 'ExitCode': 1, 'OOMKilled': False})


if __name__ == '__main__':
    unittest.main()
