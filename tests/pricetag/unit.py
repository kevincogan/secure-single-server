#!/usr/bin/env python3
"""Client contracts for the authenticated unified PriceTag gateway."""
import contextlib
import copy
import importlib.machinery
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import ipaddress

ROOT = Path(__file__).resolve().parents[2]
loader = importlib.machinery.SourceFileLoader('pricetag_harness', str(ROOT / 'scripts/pricetag/harness'))
spec = importlib.util.spec_from_loader(loader.name, loader)
client = importlib.util.module_from_spec(spec)
loader.exec_module(client)
sys.path.insert(0, str(ROOT / 'scripts/pricetag'))
import prepare
network_loader = importlib.machinery.SourceFileLoader(
    'pricetag_private_network', str(ROOT / 'scripts/pricetag/private-network.py'))
network_spec = importlib.util.spec_from_loader(network_loader.name, network_loader)
private_network = importlib.util.module_from_spec(network_spec)
network_loader.exec_module(private_network)
perf_loader = importlib.machinery.SourceFileLoader('pricetag_perf', str(ROOT / 'scripts/pricetag/perf'))
perf_spec = importlib.util.spec_from_loader(perf_loader.name, perf_loader)
perf = importlib.util.module_from_spec(perf_spec)
perf_loader.exec_module(perf)
maas_loader = importlib.machinery.SourceFileLoader('pricetag_maas_key', str(ROOT / 'scripts/pricetag/maas-key'))
maas_spec = importlib.util.spec_from_loader(maas_loader.name, maas_loader)
maas_key = importlib.util.module_from_spec(maas_spec)
maas_loader.exec_module(maas_key)


class PreparationTest(unittest.TestCase):
    def test_demo_installer_plan_and_input_validation(self):
        command = [sys.executable, str(ROOT / 'scripts/pricetag/install-demo'), '--plan',
                   '--hostname', 'gateway.example']
        for component in ('praxis', 'maas', 'metering'):
            command += ['--' + component + '-image', 'sha256:' + 'a' * 64]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('synthetic providers', result.stdout)
        command[4] = 'https://invalid.example/path'
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)


    def test_managed_mock_supports_authenticated_ui_routes(self):
        original, models = prepare.mock_inputs(managed=True)
        self.assertEqual([m['id'] for m in models], ['mock/fixture', 'mock/demo-cheap'])
        self.assertTrue(all(m['provider'] == 'mock' for m in models))
        result = prepare.render(original, models)
        for chain in result['filter_chains']:
            if chain['name'] not in ('openai', 'anthropic'):
                continue
            injection = next(f for f in chain['filters'] if f['filter'] == 'credential_injection')
            self.assertEqual(injection['clusters'][0]['env_var'], 'CUSTOM_MOCK_API_KEY')
            self.assertNotIn('synthetic-anthropic', json.dumps(result))


    def test_access_policy_checks_rewritten_model_and_routes_require_alias(self):
        original, models = prepare.mock_inputs()
        models[0]['id'] = 'mock/fixture'
        result = prepare.render(original, models)
        for chain in result['filter_chains']:
            if chain['name'] not in ('openai', 'anthropic'):
                continue
            access = next(f for f in chain['filters'] if f['filter'] == 'model_access')
            self.assertEqual(access['models'], ['fixture'])
            rejection = next(f for f in chain['filters'] if f.get('body') == 'Unknown model')
            self.assertEqual(rejection['conditions'],
                             [{'unless': {'headers': {'X-Gateway-Model': 'mock/fixture'}}}])

    def test_admission_checks_the_requested_model(self):
        original, models = prepare.mock_inputs()
        result = prepare.render(original, models)
        for chain in result['filter_chains']:
            if chain['name'] in ('openai', 'anthropic'):
                metering = next(f for f in chain['filters'] if f['filter'] == 'external_metering')
                self.assertTrue(metering['model_policy_check'])
                self.assertFalse(metering['fail_open'])

    def test_admin_model_suggestions_use_dashboard_boundary(self):
        original, models = prepare.mock_inputs()
        result = prepare.render(original, models)
        edge = next(c for c in result['filter_chains'] if c['name'] == 'edge')
        guard = next(f for f in edge['filters'] if f.get('body') == 'Route not available')
        self.assertIn({'unless': {'path': '/api/v1/admin/models'}}, guard['conditions'])
        router = next(f for f in edge['filters'] if f['filter'] == 'router')
        self.assertIn({'path': '/api/v1/admin/models', 'cluster': 'dashboard'}, router['routes'])

    def test_pricing_management_routes_use_dashboard_authentication(self):
        original, models = prepare.mock_inputs()
        result = prepare.render(original, models)
        edge = next(c for c in result['filter_chains'] if c['name'] == 'edge')
        router = next(f for f in edge['filters'] if f['filter'] == 'router')
        guard = next(f for f in edge['filters'] if f.get('body') == 'Route not available')
        for path in ('/api/v1/admin/pricing-discounts', '/api/v1/admin/pricing/refresh',
                     '/api/v1/admin/pricing/reprice', '/admin/impersonate'):
            self.assertIn({'path': path, 'cluster': 'dashboard'}, router['routes'])
            self.assertIn({'unless': {'path': path}}, guard['conditions'])
        self.assertIn({'path_prefix': '/api/v1/admin/pricing/reprice/', 'cluster': 'dashboard'}, router['routes'])
        self.assertNotIn({'path_prefix': '/api/v1/admin/', 'cluster': 'dashboard'}, router['routes'])

    def test_postgres_bootstrap_is_idempotent_and_quotes_generated_passwords(self):
        sql = prepare.postgres_bootstrap("metering'pw", 'maas-pw')
        self.assertEqual(sql.count('\\gexec'), 4)
        self.assertIn("metering''pw", sql)
        self.assertIn("ALTER ROLE metering LOGIN PASSWORD 'metering''pw'", sql)
        self.assertIn("ALTER ROLE maas LOGIN PASSWORD 'maas-pw'", sql)
        self.assertIn("rolname='metering'", sql)
        self.assertIn("datname='maas'", sql)

    def test_gateway_quadlet_keeps_required_lines_without_provider_secrets(self):
        body = prepare.gateway_quadlet_body('sha256:' + 'a' * 64, [], 'Volume=/tmp/pricetag-fixture:/etc/praxis:ro,Z\n', True)
        for required in ('Image=sha256:', 'Pull=never', 'NetworkAlias=pricetag-gateway',
                         'Secret=pricetag-m2m,', 'PublishPort=0.0.0.0:8443:8443',
                         'Network=pricetag-mock.network', 'Volume=/tmp/pricetag-fixture:/etc/praxis:ro,Z',
                         'Exec=-c /etc/praxis/gateway.json'):
            self.assertIn(required, body)
        with_secret = prepare.gateway_quadlet_body('sha256:' + 'a' * 64,
            ['Secret=openai-key,type=env,target=OPENAI_API_KEY'], '', False)
        self.assertIn('Secret=openai-key,type=env,target=OPENAI_API_KEY', with_secret)
        self.assertNotIn('Network=pricetag-mock.network', with_secret)

    def test_maas_trusts_only_loopback_and_required_service_containers(self):
        fixture = [{'subnets': [{'subnet': '10.77.0.0/24', 'gateway': '10.77.0.1'}],
                    'containers': {'a': {'name': 'pricetag-gateway',
                                         'interfaces': {'eth0': {'subnets': [
                                             {'ipnet': '10.77.0.10/24'}]}}},
                                   'b': {'name': 'pricetag-metering',
                                         'interfaces': {'eth0': {'subnets': [
                                             {'ipnet': '10.77.0.11/24'}]}}}}}]
        addresses = private_network.service_addresses(fixture)
        self.assertEqual(addresses, {'maas': '10.77.0.12', 'gateway': '10.77.0.10',
                                     'metering': '10.77.0.11'})
        with tempfile.TemporaryDirectory() as directory:
            maas = Path(directory) / 'maas.container'
            gateway = Path(directory) / 'gateway.container'
            metering = Path(directory) / 'metering.container'
            maas.write_text('[Container]\nEnvironment=MAAS_TRUSTED_PROXY_CIDRS=127.0.0.1/32,10.77.0.0/24\n')
            gateway.write_text('[Container]\nNetwork=pricetag.network\nNetwork=pricetag-mock.network\n')
            metering.write_text('[Container]\nNetwork=pricetag.network\n')
            private_network.configure_units(maas, gateway, metering, addresses)
            trusted = next(line.partition('=')[2].partition('=')[2]
                           for line in maas.read_text().splitlines()
                           if line.startswith('Environment=MAAS_TRUSTED_PROXY_CIDRS='))
            networks = [ipaddress.ip_network(item) for item in trusted.split(',')]
            self.assertTrue(any(ipaddress.ip_address('127.0.0.1') in net for net in networks))
            for address in ('10.77.0.10', '10.77.0.11', '10.77.0.12'):
                self.assertTrue(any(ipaddress.ip_address(address) in net for net in networks))
            self.assertFalse(any(ipaddress.ip_address('10.77.0.15') in net for net in networks))
            self.assertIn('IP=10.77.0.12', maas.read_text())
            self.assertIn('Network=pricetag.network:ip=10.77.0.10', gateway.read_text())
            self.assertIn('Network=pricetag.network:ip=10.77.0.11', metering.read_text())

    def test_service_addresses_avoid_other_containers(self):
        fixture = [{'subnets': [{'subnet': '10.77.0.0/24', 'gateway': '10.77.0.1'}],
                    'containers': {'a': {'name': 'other', 'interfaces': {'eth0': {'subnets': [
                        {'ipnet': '10.77.0.10/24'}]}}}}}]
        self.assertEqual(private_network.service_addresses(fixture),
                         {'maas': '10.77.0.11', 'gateway': '10.77.0.12',
                          'metering': '10.77.0.13'})

    def test_mock_deployment_has_native_routes_and_no_provider_credentials(self):
        original, models = prepare.mock_inputs()
        rendered = prepare.render(original, models)
        self.assertEqual(models[0]['id'], 'fixture')
        serialized = json.dumps(rendered)
        self.assertIn('api_key_auth', serialized)
        self.assertIn('external_metering', serialized)
        self.assertNotIn('manual_jwt', serialized)
        self.assertNotIn('M2M_SHARED_SECRET', serialized)
        self.assertNotIn('token_rate_limit', serialized)

    def test_gateway_auth_meters_with_secret_and_separates_native_api_keys(self):
        original, models = prepare.mock_inputs()
        rendered = prepare.render(original, models)
        chains = {chain['name']: chain['filters'] for chain in rendered['filter_chains']}
        for name, header in (('openai', 'authorization'), ('anthropic', 'x-api-key')):
            auth = next(f for f in chains[name] if f['filter'] == 'api_key_auth')
            self.assertEqual(auth['token_header'], header)
            self.assertEqual(auth['cache_ttl_seconds'], 0)
            meter = next(f for f in chains[name] if f['filter'] == 'external_metering')
            self.assertEqual(meter['internal_auth_file'], '/run/secrets/pricetag-m2m')
            self.assertFalse(meter['fail_open'])
        edge = next(f for f in chains['edge'] if f['filter'] == 'router')
        routes = {route['path']: route['cluster'] for route in edge['routes'] if 'path' in route}
        self.assertEqual(routes['/v1/messages'], 'authenticated-anthropic')
        self.assertEqual(routes['/v1/responses'], 'authenticated-openai')
        self.assertTrue(models)

    def test_single_api_keeps_other_api_authenticated_and_disabled(self):
        for enabled in ('openai', 'anthropic'):
            with self.subTest(enabled=enabled):
                original, models = prepare.mock_inputs()
                for model in models:
                    model['apis'] = [enabled]
                rendered = prepare.render(original, models)
                chains = {c['name']: c['filters'] for c in rendered['filter_chains']}
                for api in ('openai', 'anthropic'):
                    filters = chains[api]
                    self.assertEqual(filters[0]['filter'], 'api_key_auth')
                    access = [f for f in filters if f['filter'] == 'model_access']
                    if api == enabled:
                        self.assertEqual(access[0]['models'], [m['id'] for m in models])
                    else:
                        self.assertEqual(access, [])
                        self.assertEqual(filters[-1]['filter'], 'static_response')
                        self.assertEqual(filters[-1]['status'], 404)
                        self.assertTrue(any(f['filter'] == 'static_response' and
                                            f.get('status') == 404 and not f.get('conditions')
                                            for f in filters))
                        self.assertFalse(any(f['filter'] in ('router', 'load_balancer', 'external_metering')
                                             for f in filters))

    def test_internal_model_headers_survive_router_selection_then_are_removed_before_upstream(self):
        original, models = prepare.mock_inputs()
        rendered = prepare.render(original, models)
        for chain in (c for c in rendered['filter_chains'] if c['name'] in ('openai', 'anthropic')):
            names = [item['filter'] for item in chain['filters']]
            self.assertLess(names.index('router'), names.index('headers'))
            self.assertLess(names.index('headers'), names.index('load_balancer'))

    def test_vllm_only_excludes_cloud_routes_and_credentials_without_mutating_source(self):
        original = {'filter_chains': [{'name': api, 'filters': [
            {'filter': 'headers', 'request_remove': ['Authorization']},
            {'filter': 'credential_injection', 'clusters': [{'name': 'openai', 'env_var': 'OPENAI_API_KEY'}]},
            {'filter': 'load_balancer', 'clusters': [
                {'name': 'vllm', 'endpoints': ['vllm:8000']},
                {'name': 'openai', 'endpoints': ['api.openai.com:443']}]}]}
            for api in ('openai', 'anthropic')]}
        models = [{'id': 'local/model', 'provider': 'vllm'}, {'id': 'cloud/model', 'provider': 'openai'}]
        saved = copy.deepcopy(original)
        selected, catalog = prepare.vllm_only(original, models)
        self.assertEqual(original, saved)
        self.assertEqual(catalog, [models[0]])
        for chain in selected['filter_chains']:
            self.assertFalse(any(f['filter'] == 'credential_injection' for f in chain['filters']))
            clusters = next(f['clusters'] for f in chain['filters'] if f['filter'] == 'load_balancer')
            self.assertEqual([c['name'] for c in clusters], ['vllm'])

    def test_vllm_only_requires_a_local_model(self):
        with self.assertRaisesRegex(ValueError, 'vLLM'):
            prepare.vllm_only({'filter_chains': []}, [])


class PerformanceTest(unittest.TestCase):
    def test_stream_must_finish_and_report_expected_usage(self):
        usage = {'usage': {'prompt_tokens': 2, 'completion_tokens': 3, 'total_tokens': 5}}
        frame = b'data: ' + json.dumps(usage).encode() + b'\n\n'
        self.assertFalse(perf.valid_reply(frame, True))
        self.assertTrue(perf.valid_reply(frame + b'data: [DONE]\n\n', True))
        self.assertFalse(perf.valid_reply(b'data: [DONE]\n\n', True))
        self.assertTrue(perf.valid_reply(json.dumps(usage).encode(), False))

    def test_percentiles_use_nearest_rank_and_handle_empty_samples(self):
        self.assertEqual(perf.percentile([4, 2, 3, 1], .5), 2)
        self.assertEqual(perf.percentile([4, 2, 3, 1], .95), 4)
        self.assertIsNone(perf.percentile([], .95))


class MaaSKeyTest(unittest.TestCase):
    def test_create_uses_subject_headers_and_writes_one_time_key_privately(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'alice.key'
            request_seen = []

            def reply(request, timeout):
                request_seen.append(request)
                return io.BytesIO(json.dumps({'id': 'key-1', 'name': 'inference',
                    'key': 'sk-oai-once', 'expiresAt': '2030-01-01T00:00:00Z'}).encode())

            stdout = io.StringIO()
            argv = ['maas-key', 'create', '--subject', 'alice', '--name', 'inference',
                    '--url', 'http://127.0.0.1:18086', '--output', str(output)]
            with patch.object(sys, 'argv', argv), \
                 patch.object(maas_key.urllib.request, 'build_opener', return_value=SimpleNamespace(open=reply)), \
                 contextlib.redirect_stdout(stdout):
                maas_key.main()
            self.assertEqual(request_seen[0].full_url, 'http://127.0.0.1:18086/v1/api-keys')
            self.assertEqual(request_seen[0].get_header('X-maas-username'), 'alice')
            self.assertEqual(json.loads(request_seen[0].get_header('X-maas-group')),
                             ['system:authenticated'])
            self.assertEqual(json.loads(request_seen[0].data), {'name': 'inference', 'expiresIn': '90d'})
            self.assertEqual(output.read_text(), 'sk-oai-once\n')
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertNotIn('sk-oai-once', stdout.getvalue())

    def test_rotate_saves_replacement_before_revoking_previous_key(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'alice-next.key'
            events = []
            replies = [
                {'data': [{'id': 'old-key', 'name': 'inference'}]},
                {'id': 'new-key', 'name': 'inference', 'key': 'sk-oai-next',
                 'expiresAt': '2030-01-01T00:00:00Z'},
                {'id': 'old-key', 'status': 'revoked'},
            ]

            def reply(request, timeout):
                events.append((request.method, request.full_url))
                return io.BytesIO(json.dumps(replies.pop(0)).encode())

            argv = ['maas-key', 'rotate', '--subject', 'alice', '--name', 'inference',
                    '--url', 'http://127.0.0.1:18086', '--output', str(output)]
            with patch.object(sys, 'argv', argv), \
                 patch.object(maas_key.urllib.request, 'build_opener', return_value=SimpleNamespace(open=reply)), \
                 contextlib.redirect_stdout(io.StringIO()):
                maas_key.main()
            self.assertEqual(output.read_text(), 'sk-oai-next\n')
            self.assertEqual([event[0] for event in events], ['POST', 'POST', 'DELETE'])
            self.assertTrue(events[-1][1].endswith('/v1/api-keys/old-key'))


class HarnessTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.token = Path(self.directory.name) / 'caller.key'
        self.token.write_text('sk-oai-0123456789abcdef0123456789abcdef')
        self.token.chmod(0o600)
        self.model = {'id': 'vllm/qwen3.8-27b-int4', 'praxis': {
            'provider': 'vllm', 'upstream_model': 'qwen3.8-27b-int4',
            'context': 32768, 'output': 8192, 'apis': ['openai', 'anthropic']}}

    def preview(self, name, *extra, catalog_rows=None):
        output = io.StringIO()
        catalog = io.BytesIO(json.dumps({'data': catalog_rows or [self.model]}).encode())
        with patch.object(sys, 'argv', ['harness', name, '--url', 'https://localhost:8443',
                '--key-file', str(self.token), '--model', self.model['id'], '--print-config', *extra]), \
             patch.object(client.urllib.request, 'build_opener') as opener, \
             patch.object(client.Path, 'home', return_value=Path(self.directory.name)), \
             contextlib.redirect_stdout(output):
            opener.return_value.open.return_value = catalog
            client.main()
        self.assertNotIn(self.token.read_text(), output.getvalue())
        request = opener.return_value.open.call_args.args[0]
        self.assertEqual(request.full_url, 'https://localhost:8443/v1/models')
        self.assertIsNone(request.get_header('Authorization'))
        return json.loads(output.getvalue())

    def test_unified_alias_uses_catalog_limits_for_every_harness(self):
        openai_model = {'id': 'openai/gpt-6-luna', 'praxis': {
            'provider': 'openai', 'upstream_model': 'gpt-6-luna',
            'context': 1050000, 'output': 128000, 'apis': ['openai']}}
        messages_model = {'id': 'pricetag/claude-sonnet-5', 'praxis': {
            'provider': 'pricetag', 'upstream_model': 'claude-sonnet-5',
            'context': 128000, 'output': 8192, 'apis': ['anthropic']}}
        external_gpt = copy.deepcopy(openai_model)
        external_gpt['id'] = 'pricetag/gpt-6-luna'
        external_gpt['praxis']['provider'] = 'pricetag'
        rows = [self.model, openai_model, messages_model, external_gpt]
        selected = self.preview('opencode', catalog_rows=rows)
        config = json.loads(selected['environment']['OPENCODE_CONFIG_CONTENT'])
        self.assertEqual(config['model'], 'praxis-openai/' + self.model['id'])
        self.assertEqual(config['enabled_providers'], ['praxis-openai', 'praxis-anthropic'])
        self.assertEqual(config['disabled_providers'], [])
        openai = config['provider']['praxis-openai']
        anthropic = config['provider']['praxis-anthropic']
        self.assertEqual(openai['options']['baseURL'], 'https://localhost:8443/v1')
        self.assertEqual(anthropic['options']['baseURL'], 'https://localhost:8443/v1')
        self.assertEqual(openai['models'][openai_model['id']]['limit'],
                         {'context': 1050000, 'output': 128000})
        self.assertEqual(anthropic['models'][messages_model['id']]['limit'],
                         {'context': 128000, 'output': 8192})
        gpt = openai['models'][openai_model['id']]
        self.assertEqual(gpt['provider']['npm'], '@ai-sdk/openai')
        self.assertEqual(openai['models'][external_gpt['id']]['provider'], gpt['provider'])
        self.assertNotIn('provider', anthropic['models'][messages_model['id']])
        self.assertTrue(gpt['reasoning'])
        self.assertFalse(gpt['options']['store'])
        self.assertEqual(gpt['options']['include'], ['reasoning.encrypted_content'])
        self.assertIn(self.model['id'], openai['models'])
        self.assertIn(self.model['id'], anthropic['models'])
        selected = self.preview('codex')
        self.assertIn('model_auto_compact_token_limit=24576', selected['command'])
        entry = next(Path(self.directory.name).rglob('codex-*.json'))
        self.assertEqual(json.loads(entry.read_text())['models'][0]['context_window'], 32768)
        selected = self.preview('claude-code')
        self.assertEqual(selected['environment']['ANTHROPIC_BASE_URL'], 'https://localhost:8443')
        self.assertEqual(selected['environment']['ANTHROPIC_API_KEY'], '[caller]')
        self.assertNotIn('ANTHROPIC_AUTH_TOKEN', selected['environment'])
        self.assertEqual(selected['environment']['CLAUDE_CODE_MAX_OUTPUT_TOKENS'], '8192')
        self.assertEqual(selected['command'][-2:], ['--effort', 'medium'])

    def test_opencode_respects_anthropic_dialect_on_dual_api_model(self):
        selected = self.preview('opencode', '--api', 'anthropic')
        config = json.loads(selected['environment']['OPENCODE_CONFIG_CONTENT'])
        self.assertEqual(config['model'], 'praxis-anthropic/' + self.model['id'])
        self.assertEqual(config['provider']['praxis-anthropic']['npm'], '@ai-sdk/anthropic')

    def test_opencode_selects_anthropic_only_model_and_rejects_codex(self):
        self.model['praxis'].update(provider='external', apis=['anthropic'])
        selected = self.preview('opencode')
        config = json.loads(selected['environment']['OPENCODE_CONFIG_CONTENT'])
        self.assertEqual(config['model'], 'praxis-anthropic/' + self.model['id'])
        self.assertEqual(config['provider']['praxis-anthropic']['npm'], '@ai-sdk/anthropic')
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.preview('codex')

    def test_public_token_file_is_rejected_before_network(self):
        self.token.chmod(0o644)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.preview('opencode')

    def test_redirect_cannot_forward_caller_token(self):
        with self.assertRaisesRegex(ValueError, 'redirected'):
            client.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://other.test')


if __name__ == '__main__':
    unittest.main()
