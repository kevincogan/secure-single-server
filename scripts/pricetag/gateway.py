#!/usr/bin/env python3
"""Render the HTTPS spending gateway from an existing native provider config."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'common'))
from unified_config import active, catalog, render as unified, validate

INFERENCE = ['/v1/chat/completions', '/v1/responses', '/v1/messages']
DASHBOARD = ['/', '/login', '/logout', '/dashboard', '/admin', '/manager', '/me', '/welcome',
             '/management', '/admin/impersonate', '/me/keys', '/whoami', '/api/v1/whoami', '/api/v1/pricing',
             '/api/v1/dashboard/overview', '/api/v1/dashboard/groups',
             '/api/v1/dashboard/users', '/api/v1/dashboard/directory-users',
             '/api/v1/dashboard/models', '/api/v1/dashboard/tools',
             '/api/v1/dashboard/timeline', '/api/v1/dashboard/recent',
             '/api/v1/admin/safety-net', '/api/v1/admin/models', '/api/v1/admin/partner-users',
             '/api/v1/admin/model-policies', '/api/v1/admin/pricing-discounts',
             '/api/v1/admin/pricing/refresh', '/api/v1/admin/pricing/reprice', '/api/v1/org/scope',
             '/api/v1/org/usage', '/api/v1/org/person', '/api/v1/org/charts']
DASHBOARD_PREFIXES = ['/api/v1/management/', '/me/keys/', '/api/v1/admin/partner-users/', '/api/v1/admin/pricing/reprice/']


def render(original, models, origins=None):
    models = validate(models)
    public_catalog = catalog(models, 'openai')
    for entry, model in zip(public_catalog['data'], models):
        entry['praxis']['apis'] = model['apis']
    result = unified(original, models)
    result['admin'] = {'address': '127.0.0.1:9901'}
    result['insecure_options'] = {'allow_private_endpoints': True, 'allow_private_upstreams': True}
    result['listeners'] = [
        {'name': 'https', 'address': '0.0.0.0:8443', 'filter_chains': ['edge'],
         'tls': {'certificates': [{'cert_path': '/etc/praxis/tls.pem',
                                  'key_path': '/etc/praxis/tls-key.pem'}]}},
        {'name': 'authenticated-openai', 'address': '127.0.0.1:18082', 'filter_chains': ['openai']},
        {'name': 'authenticated-anthropic', 'address': '127.0.0.1:18083', 'filter_chains': ['anthropic']},
        {'name': 'dashboard-boundary', 'address': '127.0.0.1:18085', 'filter_chains': ['dashboard']}]
    for chain in result['filter_chains']:
        api = chain['name']
        filters = [f for f in chain['filters'] if f['filter'] not in ('token_rate_limit', 'policy', 'rate_limit')]
        request_headers = next((f for f in filters if f['filter'] == 'headers'), None)
        if request_headers is not None:
            filters.remove(request_headers)
        key_filter = {'filter': 'api_key_auth',
            'validate_url': 'http://pricetag-maas:8080/internal/v1/api-keys/validate',
            'token_header': 'authorization' if api == 'openai' else 'x-api-key',
            'cache_ttl_seconds': 0, 'timeout_seconds': 5}
        filters.insert(0, key_filter)
        filters.insert(1, {'filter': 'identity_header_guard', 'prefix': 'x-tenant-'})
        selected = active(models, original, api)
        # The unified renderer already denies inference for an unused API.
        # model_access rejects an empty allowlist at startup; retain auth and
        # the terminal 404 instead of constructing an invalid filter.
        if selected:
            # json_body rewrites during body pre-read, before model_access's
            # request hook. Check upstream IDs here; the unified renderer
            # separately rejects any unregistered client alias using the
            # original, body-derived X-Gateway-Model header.
            filters.insert(2, {'filter': 'model_access', 'mode': 'allowlist',
                               'models': sorted({model['model'] for model in selected}),
                               'group_metadata_key': 'x-tenant-group', 'max_body_bytes': 33554432})
        for i, item in enumerate(filters):
            if item['filter'] == 'token_count':
                filters.insert(i, {'filter': 'external_metering',
                    'metering_url': 'http://pricetag-metering:8080', 'allow_private_endpoint': True,
                    'internal_auth_file': '/run/secrets/pricetag-m2m',
                    'fail_open': False, 'timeout_seconds': 5, 'source': 'secure-single-server',
                    'default_username': '', 'default_model': 'unknown',
                    'model_policy_check': True,
                    'identity_header_prefix': 'x-tenant-', 'feature_key': 'inference-tokens'})
                break
        if request_headers is not None and selected:
            load_balancer = next((i for i, item in enumerate(filters)
                                  if item['filter'] == 'load_balancer'), len(filters))
            filters.insert(load_balancer, request_headers)
        chain['filters'] = filters

    allowed = [{'path': p} for p in DASHBOARD] + [{'path_prefix': p} for p in DASHBOARD_PREFIXES] + [
        {'path': '/v1/models', 'methods': ['GET']}] + [
        {'path': p, 'methods': ['POST']} for p in [*INFERENCE, '/v1/messages/count_tokens']]
    # The public listener routes protocol paths to different private chains so
    # OpenAI Bearer keys and Anthropic x-api-key credentials validate on
    # separate private chains. The public model catalog contains no secrets.
    public = [
        {'filter': 'request_id'},
        {'filter': 'static_response', 'status': 404, 'body': 'Route not available',
         'conditions': [{'unless': match} for match in allowed]},
        {'filter': 'rate_limit', 'mode': 'global', 'rate': 30, 'burst': 120},
        {'filter': 'static_response', 'status': 200, 'body': json.dumps(public_catalog),
         'headers': [{'name': 'Content-Type', 'value': 'application/json'}],
         'conditions': [{'when': {'path': '/v1/models', 'methods': ['GET']}}]},
        {'filter': 'router', 'routes':
            [{'path': p, 'cluster': 'authenticated-anthropic'}
             for p in ('/v1/messages', '/v1/messages/count_tokens')] +
            [{'path': p, 'cluster': 'authenticated-openai'}
             for p in ('/v1/responses', '/v1/chat/completions')] +
            [{'path': p, 'cluster': 'dashboard'} for p in DASHBOARD] +
            [{'path_prefix': p, 'cluster': 'dashboard'} for p in DASHBOARD_PREFIXES]},
        {'filter': 'load_balancer', 'clusters': [
            {'name': 'authenticated-openai', 'endpoints': ['127.0.0.1:18082']},
            {'name': 'authenticated-anthropic', 'endpoints': ['127.0.0.1:18083']},
            {'name': 'dashboard', 'endpoints': ['127.0.0.1:18085']}]}]
    dashboard = [
            {'filter': 'headers', 'request_remove': ['Authorization', 'X-Api-Key', 'X-MaaS-Username',
                'X-MaaS-Group', 'X-MaaS-Subscription', 'X-Tenant-Username', 'X-Tenant-Group',
                'X-Tenant-Subscription', 'X-Tenant-Model', 'X-Forwarded-User',
                'X-Forwarded-Groups', 'X-Forwarded-Real-User']},
            {'filter': 'router', 'routes': [{'path_prefix': '/', 'cluster': 'metering'}]},
            {'filter': 'load_balancer', 'clusters': [
                {'name': 'metering', 'endpoints': ['pricetag-metering:8080']}]}]
    result['filter_chains'] += [{'name': 'edge', 'filters': public}, {'name': 'dashboard', 'filters': dashboard}]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--providers', type=Path, required=True,
                        help='rendered all-in-one Praxis config in JSON, with two native chains')
    parser.add_argument('--models', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(render(json.loads(args.providers.read_text()),
                                             json.loads(args.models.read_text())), indent=2) + '\n')


if __name__ == '__main__':
    main()
