#!/usr/bin/env python3
"""Refresh native user configs from the local unified Praxis model catalogs."""
import argparse
import copy
import json
import os
import re
from pathlib import Path
import runpy
import shutil
import tempfile
import time
import urllib.request


def models(port):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(f'http://127.0.0.1:{port}/v1/models', timeout=10) as response:
        data = json.load(response)['data']
    for item in data:
        limits = item['praxis']
        if (not isinstance(item['id'], str) or type(limits['context']) is not int
                or type(limits['output']) is not int or not 0 < limits['output'] < limits['context'] <= 2000000):
            raise ValueError('gateway returned invalid model limits')
    return data


def read_json(path):
    value = json.loads(path.read_text()) if path.exists() else {}
    if not isinstance(value, dict):
        raise ValueError(str(path) + ': expected a JSON object')
    return value


def opencode_model(entry, api):
    """Select the SDK from upstream metadata while keeping the gateway alias."""
    meta = entry['praxis']
    model = {'name': entry['id'], 'limit': {k: meta[k] for k in ('context', 'output')}}
    upstream = meta['upstream_model'].lower()
    local_qwen = meta['provider'] == 'vllm' and 'qwen' in upstream
    if api == 'openai' and (local_qwen or upstream.startswith(('gpt-5', 'gpt-6', 'o1', 'o3', 'o4'))):
        # The generic Chat SDK sends max_tokens, rejected by modern GPT.
        model.update(provider={'npm': '@ai-sdk/openai'}, reasoning=True,
                     options={'store': False, 'reasoningEffort': 'medium',
                              'include': ['reasoning.encrypted_content']})
    elif api in ('anthropic', 'messages') and re.match(
            r'^claude-(?:(?:opus|sonnet)-(?:4-[678]|5)(?:-|$)|haiku-5(?:-|$))', upstream):
        # OpenCode's automatic binding control is rejected by some Messages
        # gateways. Keep adaptive thinking explicit: a partial thinking object
        # replaces OpenCode defaults and otherwise drops the thinking type.
        model['options'] = {'thinking': {'type': 'adaptive', 'blockBinding': False}}
    elif api == 'openai' and 'qwen' in upstream:
        model.update(reasoning=True, interleaved={'field': 'reasoning'})
    return model


def files(home, openai, messages, openai_port, messages_port):
    if not openai or not messages:
        raise ValueError('this client setup requires an enabled model on both API listeners')
    opencode_path = home / '.config/opencode/opencode.json'
    if opencode_path.with_suffix('.jsonc').exists():
        raise ValueError('merge opencode.jsonc into opencode.json before refreshing')
    opencode, claude = read_json(opencode_path), read_json(home / '.claude/settings.json')
    source = Path(__file__).with_name('harness.py')
    if not source.exists():
        source = Path('/usr/local/bin/praxis-harness')
    helper = runpy.run_path(str(source), run_name='config_helper')
    with tempfile.TemporaryDirectory() as directory:
        base = json.loads(helper['write_codex_catalog']('qwen3-8b', Path(directory)).read_text())['models'][0]
    entries = []
    for item in openai:
        model, limits = item['id'], item['praxis']
        entry = copy.deepcopy(base)
        entry.update(slug=model, display_name=model, description='Through unified Praxis',
                     context_window=limits['context'], max_context_window=limits['context'],
                     auto_compact_token_limit=limits['context'] - limits['output'])
        entry['supported_reasoning_levels'][0]['description'] = 'Medium reasoning'
        entries.append(entry)
    catalog = home / '.codex/model-catalogs/praxis.json'
    codex = '\n'.join([
        'model = ' + json.dumps(openai[0]['id']), 'model_provider = "praxis"',
        'model_catalog_json = ' + json.dumps(str(catalog)),
        'model_reasoning_effort = "medium"', 'show_raw_agent_reasoning = true',
        'web_search = "disabled"', 'sandbox_mode = "workspace-write"',
        '[model_providers.praxis]', 'name = "Praxis"',
        f'base_url = "http://127.0.0.1:{openai_port}/v1"',
        'wire_api = "responses"', 'requires_openai_auth = false',
        'http_headers = { Authorization = "Bearer local-placeholder" }', ''])
    opencode.update({'$schema': 'https://opencode.ai/config.json',
                     'model': 'praxis-openai/' + openai[0]['id'],
                     'enabled_providers': ['praxis-openai', 'praxis-messages']})
    providers = opencode.setdefault('provider', {})
    for name, data, port, sdk in [('openai', openai, openai_port, 'openai-compatible'),
                                  ('messages', messages, messages_port, 'anthropic')]:
        catalog_models = {m['id']: opencode_model(m, name) for m in data}
        providers['praxis-' + name] = {'npm': '@ai-sdk/' + sdk, 'name': 'Praxis ' + name,
            'options': {'baseURL': f'http://127.0.0.1:{port}/v1', 'apiKey': 'local-placeholder'},
            'models': catalog_models}
    opencode['disabled_providers'] = [p for p in opencode.get('disabled_providers', [])
                                     if p not in opencode['enabled_providers']]
    # Claude's override is process-wide and applies to unrecognized model IDs.
    # Recognized Claude IDs keep their own window. This protects the local Qwen
    # declaration; it does not guarantee that a large cloud history fits Qwen.
    context = min(m['praxis']['context'] for m in messages)
    output = min(m['praxis']['output'] for m in messages)
    env = claude.setdefault('env', {})
    _, previous_env = helper['configuration']('claude-code', 'vllm', 'qwen3.8-27b-int4',
                                              'http://127.0.0.1:8081', 'local-placeholder')
    for key in set(previous_env) | {'ANTHROPIC_MODEL', 'CLAUDE_CODE_USE_VERTEX',
                                    'CLAUDE_CODE_USE_BEDROCK', 'CLAUDE_CODE_USE_FOUNDRY'}:
        env.pop(key, None)
    env.update(ANTHROPIC_BASE_URL=f'http://127.0.0.1:{messages_port}',
        ANTHROPIC_API_KEY='local-placeholder', ANTHROPIC_AUTH_TOKEN='local-placeholder',
        ANTHROPIC_DEFAULT_SONNET_MODEL=messages[0]['id'], ANTHROPIC_DEFAULT_OPUS_MODEL=messages[0]['id'],
        ANTHROPIC_DEFAULT_HAIKU_MODEL=messages[0]['id'],
        CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC='1', CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY='0',
        CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS='1', CLAUDE_CODE_SIMPLE='1',
        CLAUDE_CODE_DISABLE_1M_CONTEXT='1', CLAUDE_CODE_MAX_CONTEXT_TOKENS=str(context),
        CLAUDE_CODE_MAX_OUTPUT_TOKENS=str(output))
    claude.update(model=messages[0]['id'],
                  modelPicker={'options': [{'model': m['id'], 'label': m['id']} for m in messages]})
    claude.setdefault('modelSettings', {}).update({m['id'].lower(): {'effortLevel': 'medium'} for m in messages})
    claude.setdefault('permissions', {})['defaultMode'] = 'default'
    return {home / '.codex/praxis.config.toml': codex,
            catalog: json.dumps({'models': entries}, indent=2) + '\n',
            opencode_path: json.dumps(opencode, indent=2) + '\n',
            home / '.claude/settings.json': json.dumps(claude, indent=2) + '\n'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--openai-port', type=int, default=8080)
    parser.add_argument('--messages-port', type=int, default=8081)
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise ValueError('run as the ordinary harness user, without sudo')
    if any(not 1 <= port <= 65535 for port in (args.openai_port, args.messages_port)):
        raise ValueError('invalid port')
    outputs = files(Path.home(), models(args.openai_port), models(args.messages_port),
                    args.openai_port, args.messages_port)
    if any(path.is_symlink() for path in outputs):
        raise ValueError('a config is a symlink; resolve it before refreshing')
    for path, content in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if path.exists() and path.read_text() == content:
            continue
        if path.exists():
            backup = path.with_name(path.name + '.bak-' + str(time.time_ns()))
            shutil.copy2(path, backup)
            backup.chmod(0o600)
        fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.praxis-')
        with os.fdopen(fd, 'w') as target:
            target.write(content)
        os.replace(temporary, path)
    claude = shutil.which('claude')
    alias = Path.home() / '.local/bin/claude-code'
    if claude and not alias.exists() and not alias.is_symlink():
        alias.parent.mkdir(parents=True, exist_ok=True)
        alias.symlink_to(claude)
    print('Configured: codex --profile praxis | claude-code | opencode')
    print('Menus are configured snapshots. Rerun after changing enabled providers or models.')
    print('Claude uses simple/manual mode; the context override applies to unrecognized model IDs.')
    print('Compact before switching a large cloud conversation to local Qwen; long-context switching is unqualified.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError) as error:
        raise SystemExit('error: ' + str(error)) from None
