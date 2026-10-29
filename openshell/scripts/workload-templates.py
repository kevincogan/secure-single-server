#!/usr/bin/env python3
"""Validated, immutable OpenShell workload templates (Python 3.9+)."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
SLUG = r'[a-z][a-z0-9-]{0,23}'
CPU = r'(?:[1-9][0-9]*(?:[.][0-9]+)?|0[.][0-9]*[1-9][0-9]*|[1-9][0-9]*m)'
MEMORY = r'[1-9][0-9]*(?:Ki|Mi|Gi|Ti|Pi|Ei|K|M|G|T|P|E)?'
PIN = r'ODH_[A-Z0-9_]+_IMAGE'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def catalog():
    directory = Path(os.environ.get('OPENSHELL_TEMPLATE_DIR', ROOT / 'configs/templates'))
    entries = []
    seen = set()
    for path in sorted(directory.glob('*.json')):
        data = json.loads(path.read_text())
        require(isinstance(data, dict) and set(data) == {'version', 'templates'}
                and data['version'] == 1 and isinstance(data['templates'], list),
                f'invalid template catalog: {path.name}')
        for item in data['templates']:
            require(isinstance(item, dict), 'template entry must be an object')
            require(set(item) <= {'harness', 'profile', 'backend', 'image_variable',
                                  'cpu', 'memory', 'environment', 'policy', 'config_dir', 'model_id'},
                    'unknown template field')
            for key in ('harness', 'profile', 'backend'):
                require(isinstance(item.get(key), str) and re.fullmatch(SLUG, item[key]),
                        f'invalid template {key}')
            identity = tuple(item[key] for key in ('harness', 'profile', 'backend'))
            require(identity not in seen, 'duplicate harness/profile/backend template')
            seen.add(identity)
            require(isinstance(item.get('image_variable'), str)
                    and re.fullmatch(PIN, item['image_variable']), 'invalid image pin variable')
            require(isinstance(item.get('cpu'), str) and re.fullmatch(CPU, item['cpu']), 'invalid template CPU')
            require(isinstance(item.get('memory'), str) and re.fullmatch(MEMORY, item['memory']), 'invalid template memory')
            environment = item.get('environment', {})
            require(isinstance(environment, dict), 'environment must be an object')
            for key, value in environment.items():
                require(re.fullmatch(r'[A-Z_][A-Z0-9_]*', key) and isinstance(value, str)
                        and '\x00' not in value, 'invalid template environment')
                require(not any(part in key for part in ('KEY', 'TOKEN', 'SECRET', 'PASSWORD', 'CREDENTIAL')),
                        'credentials cannot be stored in workload templates')
            for key in ('policy', 'config_dir'):
                if key in item:
                    value = item[key]
                    require(isinstance(value, str) and value and not Path(value).is_absolute()
                            and '..' not in Path(value).parts and not any(c in value for c in '\n\r\t\x00'),
                            f'invalid template {key} path')
                    require((ROOT / value).exists(), f'template {key} path does not exist: {value}')
            require(('policy' in item) != ('config_dir' in item), 'set policy or config_dir, exclusively')
            if 'model_id' in item:
                require(isinstance(item['model_id'], str) and item['model_id']
                        and not any(c in item['model_id'] for c in '\n\r\t\x00'), 'invalid default model ID')
            entries.append(item)
    require(entries, 'template catalog is empty')
    return entries


def select(entries, harness, profile, config, backend):
    # Existing cloud bootc commands stay standalone unless --config is explicit.
    if backend and backend != 'cloud':
        require(not config, 'selected backend owns provider configuration; omit --config')
        target = backend
    elif config:
        matches = [item for item in entries if item['harness'] == harness
                   and item['profile'] == profile and item.get('config_dir')
                   and (ROOT / item['config_dir']).resolve() == Path(config).resolve()]
        if matches:
            # vllm and remote-vllm intentionally share a frontend config.
            return next((item for item in matches if item['backend'] == 'vllm'), matches[0])
        target = 'cloud'
    else:
        target = 'standalone'
    matches = [item for item in entries if (item['harness'], item['profile'], item['backend'])
               == (harness, profile, target)]
    require(len(matches) == 1, f'no template for {harness}/{profile}/{target}' + ('; --config is unsupported for this profile' if config else ''))
    return matches[0]


def workload(item):
    """Build a deterministic workload definition from its template and pins."""
    image = os.environ.get(item['image_variable'], '')
    require(re.fullmatch(r'[^\s@]+@sha256:[a-f0-9]{64}', image), 'template image must be digest-pinned')
    cpu = os.environ.get('OPENSHELL_SANDBOX_CPU', item['cpu'])
    memory = os.environ.get('OPENSHELL_SANDBOX_MEMORY', item['memory'])
    require(re.fullmatch(CPU, cpu), 'invalid OPENSHELL_SANDBOX_CPU')
    require(re.fullmatch(MEMORY, memory), 'invalid OPENSHELL_SANDBOX_MEMORY')
    labels = {'managed-by': 'secure-single-server', **{key: item[key] for key in ('harness', 'profile', 'backend')}}
    result = {'image': image, 'resources': {'cpu': cpu, 'memory': memory},
              'environment': item.get('environment', {}), 'labels': labels}
    # v0.1.5 validates templates with the sandbox's 19-character name limit.
    # Human-readable identity lives in labels and sync's catalog/name output.
    digest = hashlib.sha256(json.dumps(result, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    name = 'sss-' + digest[:15]
    return name, result


class Gateway:
    def __init__(self, binary):
        self.binary = binary
        timeout = float(os.environ.get('OPENSHELL_TEMPLATE_TIMEOUT', '120'))
        require(math.isfinite(timeout) and timeout > 0, 'invalid OPENSHELL_TEMPLATE_TIMEOUT')
        self.deadline = time.monotonic() + timeout

    def run(self, *arguments, allow_failure=False):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, 'template synchronization deadline exceeded')
        result = subprocess.run([self.binary, 'sandbox', 'template', *arguments],
                                capture_output=True, text=True, timeout=min(30, remaining))
        if result.returncode and not allow_failure:
            raise RuntimeError(f'template {arguments[0]} failed (exit {result.returncode})')
        return result

    def names(self):
        names, tokens, token = set(), set(), ''
        while True:
            arguments = ['list', '--output', 'json']
            if token:
                arguments += ['--page-token', token]
            data = json.loads(self.run(*arguments).stdout)
            require(isinstance(data, dict) and isinstance(data.get('templates'), list)
                    and isinstance(data.get('next_page_token'), str), 'invalid template listing')
            for item in data['templates']:
                require(isinstance(item, dict) and isinstance(item.get('name'), str)
                        and item['name'] and item['name'] not in names, 'invalid/duplicate listed template')
                names.add(item['name'])
            token = data['next_page_token']
            if not token:
                return names
            require(token not in tokens, 'repeated template page token')
            tokens.add(token)

    def verify(self, name, expected):
        actual = json.loads(self.run('get', name, '--output', 'json').stdout)
        require(isinstance(actual, dict) and actual.get('name') == name, 'invalid template readback')
        require(set(actual) <= {'id', 'name', 'workspace', 'resource_version', 'created_at',
                                'labels', 'annotations', 'image', 'environment', 'resources',
                                'driver_config', 'startup'}, 'unknown template readback field')
        require(all(actual.get(key, {}) == value for key, value in expected.items()),
                f'template drift detected: {name}; review and remove the conflicting template explicitly')
        require(not any(actual.get(key) for key in ('driver_config', 'startup', 'annotations')),
                f'unexpected template configuration: {name}')

    def ensure(self, item, names):
        name, expected = workload(item)
        if name not in names:
            args = ['create', name, '--image', expected['image'], '--cpu', expected['resources']['cpu'],
                    '--memory', expected['resources']['memory']]
            for key, value in sorted(expected['labels'].items()):
                args += ['--label', f'{key}={value}']
            for key, value in sorted(expected['environment'].items()):
                args += ['--env', f'{key}={value}']
            # Another administrator may create the identical template concurrently.
            # Only a successful exact readback can turn that race into success.
            self.run(*args, allow_failure=True)
        self.verify(name, expected)
        names.add(name)
        return name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('pins', 'select', 'ensure', 'sync'))
    parser.add_argument('--harness')
    parser.add_argument('--profile')
    parser.add_argument('--config', default='')
    parser.add_argument('--backend', default='')
    parser.add_argument('--binary', default=os.environ.get('OPENSHELL_BIN', '/usr/local/bin/openshell'))
    args = parser.parse_args()
    entries = catalog()
    require(not any(c in value for value in (args.config, args.backend) for c in '\n\r\t\x00'), 'invalid selector input')
    if args.action == 'pins':
        print('\n'.join(sorted({item['image_variable'] for item in entries})))
        return
    if args.action in ('select', 'ensure'):
        require(args.harness and args.profile, '--harness and --profile are required')
        item = select(entries, args.harness, args.profile, args.config, args.backend)
        if args.action == 'select':
            config = args.config or (str(ROOT / item['config_dir']) if 'config_dir' in item else '')
            policy = str(Path(config) / 'profiles' / args.profile / 'policy.yaml') if config else str(ROOT / item['policy'])
            require(Path(policy).is_file(), f'policy file not found: {policy}')
            # Line protocol; no shell eval and no credentials in the descriptor.
            print('\n'.join((item['backend'], policy, config, item.get('model_id', ''), item['image_variable'])))
            return
        entries = [item]
    # Validate every effective workload before making any mutations.
    for item in entries:
        workload(item)
    gateway = Gateway(args.binary)
    names = gateway.names()
    for item in entries:
        name = gateway.ensure(item, names)
        if args.action == 'ensure':
            print(name)
        else:
            print('/'.join(item[key] for key in ('harness', 'profile', 'backend')) + '\t' + name)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f'workload templates: {error}', file=sys.stderr)
        sys.exit(1)
