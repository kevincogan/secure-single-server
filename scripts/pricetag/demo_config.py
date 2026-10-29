"""Static synthetic providers for the opt-in demo; no runtime management API."""
from urllib.parse import urlsplit

def mock_configuration():
    """Synthetic provider contract used only by the opt-in management demo."""
    return {'providers': [{'name': 'mock', 'urls': {
        'openai': 'http://pricetag-provider:18080/v1',
        'anthropic': 'http://pricetag-provider:18081'}, 'messages_auth': 'x-api-key'}],
        'models': [{'id': 'mock/' + alias, 'provider': 'mock', 'model': model,
                    'apis': ['openai', 'anthropic'], 'context': 32768, 'output': output}
                   for alias, model, output in [('fixture', 'fixture', 4096),
                                                ('demo-cheap', 'fixture-cheap', 2048)]]}


def native_inputs(document):
    """Compile narrowly typed settings to native provider inputs for gateway.py."""
    chains = []
    for api in ('openai', 'anthropic'):
        clusters, credentials = [], []
        for provider in document['providers']:
            address = provider['urls'].get(api)
            if not address:
                continue
            parsed = urlsplit(address)
            name = provider['name']
            cluster = name if name == 'openai' else name + '-' + api
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            backend = {'name': cluster, 'endpoints': [f'{parsed.hostname}:{port}'],
                       'http': {'authority': parsed.netloc}}
            if parsed.scheme == 'https':
                backend['tls'] = {'sni': parsed.hostname}
            clusters.append(backend)
            bearer = api == 'openai' or provider['messages_auth'] == 'bearer'
            credentials.append({'name': cluster,
                'env_var': 'OPENAI_API_KEY' if name == 'openai' else 'CUSTOM_' + name.upper().replace('-', '_') + '_API_KEY',
                'header': 'Authorization' if bearer else 'x-api-key',
                'header_prefix': 'Bearer ' if bearer else ''})
        chains.append({'name': api, 'filters': [
            {'filter': 'headers', 'request_remove': ['Authorization', 'X-Api-Key']},
            {'filter': 'credential_injection', 'clusters': credentials},
            {'filter': 'load_balancer', 'clusters': clusters}]})
    return {'filter_chains': chains}
