#!/usr/bin/env python3
"""Fresh-install and benchmark safety boundaries; no host mutations."""
import importlib.machinery
import importlib.util
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def module(name):
    loader = importlib.machinery.SourceFileLoader(name.replace('-', '_'), str(ROOT / 'scripts/pricetag' / name))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    result = importlib.util.module_from_spec(spec)
    loader.exec_module(result)
    return result


installer = module('install.py')
benchmark = module('benchmark')


class InstallTest(unittest.TestCase):
    def test_bootstrap_failure_stops_before_marker_and_explains_recovery(self):
        source = (ROOT / 'scripts/pricetag/start').read_text()
        start = source.index('  if ! python3 "${SCRIPT_DIR}/metering_admin.py"')
        end = source.index('\nfi', start)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'bootstrap.json').write_text('{}')
            script = root / 'check.sh'
            script.write_text('set -eu\nDEPLOY_DIR="$1"\nSCRIPT_DIR="$1"\n'
                              'python3() { return 1; }\n'
                              'note() { echo "$*"; }\n'
                              'die() { echo "$*"; exit 1; }\n' + source[start:end])
            result = subprocess.run(['bash', str(script), directory], text=True, capture_output=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn('sudo scripts/pricetag/start', result.stdout)
            self.assertFalse((root / 'bootstrap.done').exists())

    def test_summary_shows_all_images_and_provider_choices(self):
        sys.path.insert(0, str(ROOT / 'scripts/pricetag'))
        from prepare import POSTGRES
        for mode in ('real', 'mock'):
            with self.subTest(mode=mode):
                flags = ['--mode', mode, '--hostname', 'gateway.example', '--plan',
                         '--image-mode', 'published', '--metering-image', installer.PUBLISHED_METERING_IMAGE]
                if mode == 'real':
                    flags += ['--provider', 'openai', '--provider', 'external', '--external-api', 'both']
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    installer.install(installer.parse_args(flags))
                text = output.getvalue()
                for image in (POSTGRES, installer.PRAXIS_IMAGE, installer.PUBLISHED_MAAS_IMAGE,
                              installer.PUBLISHED_METERING_IMAGE):
                    self.assertEqual(text.count(image), 1)
                self.assertNotIn('  Mode ', text)
                self.assertIn('Mock providers (benchmark)' if mode == 'mock' else
                              'OpenAI, External (OpenAI-compatible + Anthropic Messages)', text)

    def test_sample_users_can_be_omitted_without_omitting_admin(self):
        args = self.image_args('--no-sample-users')
        self.assertFalse(args.sample_users)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            installer.install(args)
        self.assertIn('admin only', output.getvalue())
        self.assertNotIn('admin, alice, bob', output.getvalue())

    def test_start_respects_sample_user_choice_on_repeated_starts(self):
        # Execute the actual startup provisioning block with a recording Python
        # command; no systemd, database or host configuration is touched.
        version = subprocess.check_output(['bash', '-c', 'printf %s "${BASH_VERSINFO[0]}"'], text=True)
        if int(version) < 4:
            self.skipTest('startup requires Bash 4+, as provided by RHEL')
        source = (ROOT / 'scripts/pricetag/start').read_text()
        block = source[source.index('if [[ ! -f "${DEPLOY_DIR}/sample-users"'):source.index("note 'Praxis")]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / 'check.sh'
            script.write_text('set -euo pipefail\nDEPLOY_DIR="$1"\nadmin_dir="$1"\nSCRIPT_DIR="$1"\n'
                              'python3() { printf "%s\\n" "$*"; }\n' + block)
            for selection, expected in [('no', False), ('yes', True)]:
                (root / 'sample-users').write_text(selection + '\n')
                result = subprocess.run(['bash', str(script), directory], capture_output=True, text=True, check=True)
                self.assertEqual('--subject alice' in result.stdout, expected)
                self.assertEqual('--subject bob' in result.stdout, expected)
            (root / 'alice.key').touch()
            result = subprocess.run(['bash', str(script), directory], capture_output=True, text=True, check=True)
            self.assertNotIn('--subject alice', result.stdout)
            self.assertIn('--subject bob', result.stdout)

    def test_real_is_default_and_mock_requires_explicit_selection(self):
        with patch.object(installer.sys.stdin, 'isatty', return_value=False):
            args = installer.parse_args(['--hostname', 'gateway.example',
                                         '--provider', 'openai', '--plan'])
            self.assertEqual(args.mode, 'real')
            mock = installer.parse_args(['--hostname', 'gateway.example', '--mode', 'mock', '--plan'])
            self.assertEqual(mock.mode, 'mock')
            with self.assertRaises(SystemExit):
                installer.parse_args(['--hostname', 'gateway.example', '--plan'])

    def image_args(self, *extra):
        return installer.parse_args(['--mode', 'mock', '--hostname', 'gateway.example', '--plan', *extra])

    def test_published_defaults_and_optional_source_branches(self):
        args = self.image_args()
        self.assertEqual(args.image_mode, 'published')
        self.assertEqual(args.metering_image, installer.PUBLISHED_METERING_IMAGE)
        self.assertEqual(args.maas_image, installer.PUBLISHED_MAAS_IMAGE)
        self.assertIsNone(args.metering_branch)
        self.assertEqual(installer.METERING_REPO, 'https://github.com/Ladas/pricetag-metering.git')
        source = self.image_args('--image-mode', 'source')
        self.assertEqual(source.maas_branch, installer.MAAS_BRANCH)
        self.assertEqual(source.metering_branch, installer.METERING_BRANCH)
        self.assertEqual(args.metering_revision, installer.METERING_COMMIT)
        self.assertEqual(source.metering_revision, installer.SOURCE_METERING_COMMIT)
        self.assertEqual(module('build-metering').REVISION, installer.SOURCE_METERING_COMMIT)
        for flags in (['--image-mode', 'source', '--maas-branch', '../bad'],
                      ['--image-mode', 'source', '--maas-branch', 'feature', '--maas-revision', 'a' * 40]):
            with self.assertRaises(SystemExit):
                self.image_args(*flags)

    def test_branch_build_records_resolved_commit(self):
        args = self.image_args('--image-mode', 'source', '--maas-branch', 'feature/test')
        resolved = 'c' * 40
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(installer, 'CACHE', Path(directory)), patch.object(installer, 'checkout') as checkout:
            def execute(command, capture=False, **kwargs):
                if command[0] == 'git':
                    return resolved
                if capture:
                    if command[-1] == '{{.Architecture}}':
                        return 'amd64'
                    return {installer.PRAXIS_IMAGE: installer.PRAXIS_REVISION,
                            installer.MAAS_IMAGE: resolved,
                            installer.METERING_IMAGE: args.metering_revision}[command[3]]
            with patch.object(installer, 'run', side_effect=execute) as run:
                installer.acquire_images(args, 'amd64')
            self.assertEqual(checkout.call_args_list[0].args[2], 'refs/heads/feature/test')
            self.assertEqual(args.maas_revision, resolved)
            self.assertEqual(checkout.call_args_list[1].args[2],
                             'refs/heads/feat/standalone-demo-reuse-upstream-ui')
            self.assertEqual(args.metering_revision, resolved)
            self.assertTrue(any('--revision' in c.args[0] and resolved in c.args[0]
                                for c in run.call_args_list))
            self.assertTrue(any('--expected-commit' in c.args[0] and resolved in c.args[0]
                                for c in run.call_args_list))

    def test_demo_fixture_is_mock_only(self):
        self.assertTrue(self.image_args('--demo-fixture').demo_fixture)
        with self.assertRaises(SystemExit):
            installer.parse_args(['--mode', 'real', '--provider', 'openai', '--hostname',
                                  'gateway.example', '--plan', '--demo-fixture'])

    def test_checkout_uses_fetched_head_not_stale_local_branch(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(installer, 'run') as run:
            installer.checkout('https://example.invalid/repo', Path(directory) / 'new', 'refs/heads/feature')
            self.assertEqual(run.call_args.args[0][-3:], ['checkout', '--detach', 'FETCH_HEAD'])

    def test_published_images_require_digests_and_skip_source_builds(self):
        for reference in ('quay.io/example/maas:latest', 'sha256:' + 'a' * 64):
            with self.assertRaises(SystemExit):
                self.image_args('--image-mode', 'published', '--maas-image', reference)
        args = self.image_args('--image-mode', 'published',
                               '--maas-image', 'quay.io/example/maas@sha256:' + 'a' * 64,
                               '--metering-image', 'quay.io/example/metering@sha256:' + 'b' * 64)
        def execute(command, capture=False, **kwargs):
            self.assertEqual(command[0], 'podman')
            if capture:
                if command[-1] == '{{.Architecture}}':
                    return 'amd64'
                return {installer.PRAXIS_IMAGE: installer.PRAXIS_REVISION,
                        args.maas_image: args.maas_revision,
                        args.metering_image: args.metering_revision}[command[3]]
        with patch.object(installer, 'run', side_effect=execute) as runner, \
                patch.object(installer, 'checkout', side_effect=AssertionError('source checkout')):
            self.assertEqual(installer.acquire_images(args, 'amd64'), (args.maas_image, args.metering_image))
            pulls = [c.kwargs['label'] for c in runner.call_args_list if c.args[0][:2] == ['podman', 'pull']]
            self.assertEqual(pulls, ['Pulling MaaS', 'Pulling PriceTag metering', 'Pulling Praxis'])
        with patch.object(installer, 'run', return_value='wrong-source'):
            with self.assertRaisesRegex(ValueError, 'source revision'):
                installer.acquire_images(args, 'amd64')

    def test_source_revision_overrides_reach_checkout_and_build(self):
        args = self.image_args('--image-mode', 'source', '--maas-revision', 'a' * 40,
                               '--metering-revision', 'b' * 40)
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(installer, 'CACHE', Path(directory)), \
                patch.object(installer, 'checkout') as checkout:
            def execute(command, capture=False, **kwargs):
                if capture:
                    if command[-1] == '{{.Architecture}}':
                        return 'amd64'
                    return {installer.PRAXIS_IMAGE: installer.PRAXIS_REVISION,
                            installer.MAAS_IMAGE: args.maas_revision,
                            installer.METERING_IMAGE: args.metering_revision}[command[3]]
            with patch.object(installer, 'run', side_effect=execute) as run:
                installer.acquire_images(args, 'amd64')
            self.assertEqual([call.args[2] for call in checkout.call_args_list], ['a' * 40, 'b' * 40])
            commands = [list(map(str, call.args[0])) for call in run.call_args_list]
            self.assertTrue(any('--revision' in c and 'b' * 40 in c for c in commands))
            self.assertTrue(any('--expected-commit' in c and 'a' * 40 in c for c in commands))

    def test_build_output_is_private_and_capture_still_returns_values(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(installer, 'LOG', None), patch.object(installer, 'LOG_PATH', None):
            screen = io.StringIO()
            try:
                with contextlib.redirect_stdout(screen):
                    installer.open_log(directory)
                    installer.run([sys.executable, '-c', 'print("build detail")'])
                    value = installer.run([sys.executable, '-c', 'print("image-id")'], capture=True)
                self.assertEqual(value, 'image-id')
                self.assertNotIn('build detail', screen.getvalue())
                self.assertIn('build detail', installer.LOG_PATH.read_text())
                self.assertEqual(installer.LOG_PATH.stat().st_mode & 0o777, 0o600)
                with self.assertRaises(subprocess.CalledProcessError):
                    installer.run([sys.executable, '-c', 'raise SystemExit(7)'])
            finally:
                installer.LOG.close()

    def test_long_command_reports_progress_without_losing_exit_status(self):
        from unittest.mock import Mock
        process = Mock()
        process.wait.side_effect = [subprocess.TimeoutExpired('build', 15), 7]
        screen = io.StringIO()
        with contextlib.redirect_stdout(screen):
            self.assertEqual(installer.wait_for(process), 7)
        self.assertIn('Working...', screen.getvalue())

    def test_credentials_fail_before_installation_commands(self):
        args = installer.parse_args(['--mode', 'real', '--hostname', 'gateway.example',
                                     '--provider', 'openai', '--openai-key-file', '/root/key', '--yes'])
        with patch.object(installer, 'preflight'), patch.object(installer, 'provider_module'), \
                patch.object(installer, 'collect_providers', side_effect=ValueError('HTTP 401')), \
                patch.object(installer, 'run', side_effect=AssertionError('installation must not start')):
            with self.assertRaisesRegex(ValueError, 'HTTP 401'):
                installer.install(args)

    def test_cancel_after_discovery_does_not_start_installation(self):
        args = installer.parse_args(['--mode', 'real', '--hostname', 'gateway.example',
                                     '--provider', 'openai', '--plan'])
        args.plan = False
        with patch.object(installer, 'preflight'), patch.object(installer, 'provider_module'), \
                patch.object(installer, 'collect_providers', return_value=[]), \
                patch('builtins.input', return_value='cancel'), \
                patch.object(installer, 'run', side_effect=AssertionError('installation must not start')):
            with self.assertRaisesRegex(ValueError, 'cancelled'):
                installer.install(args)

    def test_interactive_selection_accepts_menu_numbers(self):
        with patch.object(installer.sys.stdin, 'isatty', return_value=True), \
                patch('builtins.input', side_effect=['2', '2', '2', '2']):
            args = installer.parse_args(['--hostname', 'gateway.example'])
        self.assertEqual(args.provider, ['external'])
        self.assertEqual(args.external_api, 'anthropic')
        self.assertFalse(args.sample_users)

    def test_external_selection_requires_one_provider_and_records_api(self):
        with patch.object(installer.sys.stdin, 'isatty', return_value=False):
            with self.assertRaises(SystemExit):
                installer.parse_args(['--mode', 'real', '--hostname', 'gateway.example', '--yes'])
            args = installer.parse_args(['--mode', 'real', '--hostname', 'gateway.example',
                '--provider', 'external', '--external-api', 'anthropic', '--external-key-file', '/root/key',
                '--external-messages-url', 'provider.example', '--yes'])
            self.assertEqual(args.external_api, 'anthropic')
            self.assertEqual(args.provider, ['external'])

    def test_plan_runs_without_privileges_and_does_not_invoke_commands(self):
        with patch.object(sys, 'argv', ['install', '--mode', 'mock', '--hostname', 'gateway.example', '--plan']), \
                patch.object(installer, 'run', side_effect=AssertionError('mutation')), \
                patch.object(installer, 'preflight', side_effect=AssertionError('host inspection')):
            installer.main()

    def test_unattended_real_install_requires_credentials_and_endpoint(self):
        base = ['--mode', 'real', '--hostname', 'gateway.example', '--provider', 'pricetag', '--yes']
        with patch.object(installer.sys.stdin, 'isatty', return_value=False):
            with self.assertRaises(SystemExit):
                installer.parse_args(base)
            with self.assertRaises(SystemExit):
                installer.parse_args(base + ['--pricetag-key-file', '/root/key'])
            args = installer.parse_args(base + ['--pricetag-key-file', '/root/key',
                                               '--pricetag-messages-url', 'provider.example'])
            self.assertEqual(args.pricetag_key_file, Path('/root/key'))

    def test_existing_configuration_refused_without_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(installer.os, 'geteuid', return_value=0), \
                    patch.object(installer.Path, 'read_text', return_value='ID=rhel\n'), \
                    patch.object(installer, 'DEPLOY', Path(directory)), \
                    patch.object(installer, 'run', side_effect=AssertionError('mutation')):
                with self.assertRaisesRegex(ValueError, 'already exists'):
                    installer.preflight('real')

    def test_rejects_url_or_shell_input_as_hostname(self):
        for value in ('https://gateway.example', 'gateway.example:8443', 'a\nb', '-x', 'a/b', 'a;id', ''):
            self.assertFalse(installer.valid_hostname(value), value)
        for value in ('gateway.example', '127.0.0.1'):
            self.assertTrue(installer.valid_hostname(value))

    def test_checkout_commands_use_readable_source_permissions(self):
        from types import SimpleNamespace
        with patch.object(installer.subprocess, 'run', return_value=SimpleNamespace(stdout='')) as execute:
            installer.run(['git', 'clone', 'https://example.invalid/source', '/tmp/source'])
            self.assertEqual(execute.call_args.kwargs['umask'], 0o022)
            installer.run(['true'])
            self.assertEqual(execute.call_args.kwargs['umask'], -1)

    def test_import_looks_up_loaded_image_by_id_not_registry_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            engine = Path(directory) / 'podman'
            engine.write_text('#!/bin/sh\nexit 0\n')
            engine.chmod(0o755)
            import os
            for image_id in ('a' * 64, 'sha256:' + 'a' * 64):
                with patch.dict(os.environ, {'PATH': directory + ':' + os.environ['PATH']}), \
                        patch.object(installer, 'run', side_effect=[image_id, image_id]) as execute, \
                        contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(installer.import_image('registry/image@sha256:manifest', ['true'], 'MaaS'),
                                     'sha256:' + 'a' * 64)
                    self.assertIn(image_id, execute.call_args.args[0])
                    self.assertIn('Importing MaaS into praxis-svc', output.getvalue())
                    self.assertIn('registry/image@sha256:manifest', output.getvalue())
                    self.assertIn('OK: MaaS imported', output.getvalue())

    def test_mock_rejects_provider_flags(self):
        with self.assertRaises(SystemExit):
            installer.parse_args(['--mode', 'mock', '--hostname', 'localhost', '--provider', 'openai'])

    def test_image_export_failure_does_not_prepare_or_inspect(self):
        # Real pipe behavior: exporter failure must survive an importer that exits 0.
        with tempfile.TemporaryDirectory() as directory:
            engine = Path(directory) / 'podman'
            engine.write_text('#!/bin/sh\nexit 7\n')
            engine.chmod(0o755)
            import os
            with patch.dict(os.environ, {'PATH': directory + ':' + os.environ['PATH']}), \
                    patch.object(installer, 'run', side_effect=['a' * 64]):
                with self.assertRaises(RuntimeError):
                    installer.import_image('unused', ['true'])

    def test_benchmark_rejects_real_models_and_provider_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'models.json').write_text('[{"id":"openai/real","model":"real"}]')
            with self.assertRaises(ValueError):
                benchmark.require_mock(path)
            (path / 'models.json').write_text('[{"id":"fixture","model":"fixture"}]')
            (path / 'quadlets').mkdir()
            (path / 'quadlets/pricetag-gateway.container').write_text(
                'Network=pricetag-mock.network\nSecret=real,type=env,target=KEY\n')
            with self.assertRaises(ValueError):
                benchmark.require_mock(path)

    def test_mock_guard_accepts_rendered_fixture_and_rejects_remote_endpoints(self):
        sys.path.insert(0, str(ROOT / 'scripts/pricetag'))
        import prepare
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            config, models = prepare.mock_inputs()
            (path / 'models.json').write_text(json.dumps(models))
            (path / 'quadlets').mkdir()
            (path / 'quadlets/pricetag-gateway.container').write_text(
                prepare.gateway_quadlet_body('sha256:' + 'a' * 64, [], '', True))
            (path / 'gateway').mkdir()
            rendered = prepare.render(config, models)
            (path / 'gateway/gateway.json').write_text(json.dumps(rendered))
            benchmark.require_mock(path)
            for chain in rendered['filter_chains']:
                for item in chain['filters']:
                    if item.get('filter') == 'load_balancer':
                        item['clusters'][0]['endpoints'] = ['remote.example:443']
            (path / 'gateway/gateway.json').write_text(json.dumps(rendered))
            with self.assertRaises(ValueError):
                benchmark.require_mock(path)

    def test_mock_guard_accepts_managed_mock_aliases_only(self):
        sys.path.insert(0, str(ROOT / 'scripts/pricetag'))
        import demo_config
        import gateway
        document = {'providers': [{'name': 'mock', 'urls': {
            'openai': 'http://pricetag-provider:18080/v1',
            'anthropic': 'http://pricetag-provider:18081'}, 'messages_auth': 'x-api-key'}],
            'models': [{'id': 'mock/cheap', 'model': 'fixture-cheap', 'provider': 'mock',
                        'apis': ['openai', 'anthropic'], 'context': 32768, 'output': 4096}]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'quadlets').mkdir(); (path / 'gateway').mkdir()
            (path / 'models.json').write_text(json.dumps(document['models']))
            rendered = gateway.render(demo_config.native_inputs(document), document['models'])
            (path / 'gateway/gateway.json').write_text(json.dumps(rendered))
            unit = path / 'quadlets/pricetag-gateway.container'
            unit.write_text('Network=pricetag-mock.network\nSecret=praxis-mock-api-key-v2,type=env,target=CUSTOM_MOCK_API_KEY\n')
            benchmark.require_mock(path)
            unit.write_text(unit.read_text().replace('praxis-mock-api-key-v2', 'real-provider-key'))
            with self.assertRaises(ValueError):
                benchmark.require_mock(path)

    def test_sampler_errors_and_disk_pressure_fail(self):
        with self.assertRaises(ValueError):
            benchmark.check_sample({'postgres': {'error': 'failed'}})
        with self.assertRaises(ValueError):
            benchmark.check_sample({'disk_available_percent': 29})

    def test_budget_only_rejects_key_rotation(self):
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/pricetag/user'),
                                 '--subject', 'alice', '--no-key', '--rotate'], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('--no-key cannot', result.stderr)


if __name__ == '__main__':
    unittest.main()
