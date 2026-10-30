#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build only reviewed agent/provider files against the configured digest base.

The temporary context excludes tests, installer tools, home files and credentials.
This does not push, deploy, choose another base or download Python packages.
"""
from pathlib import Path
import argparse
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'runtime'))
from provider_contract import load


def prepare(context: Path) -> str:
    """Copy a closed set and refuse unconfigured or symlinked input files."""
    files = {
        'Dockerfile': 'workloads/agents/service-request-demo/Dockerfile',
        **{'src/' + name: 'workloads/agents/service-request-demo/src/' + name
           for name in ('client.py', 'agent_loop.py', 'inference.py', 'remediation.json')},
        **{'runtime/' + name: 'runtime/' + name
           for name in ('provider_contract.py', 'provider-contract.json')},
    }
    contract = load((ROOT / 'runtime/provider-contract.json').read_text())
    if not contract['configured']:
        raise ValueError('Configure a reviewed provider and digest base before building')
    for target, name in files.items():
        source = ROOT / name
        if source.is_symlink() or not source.is_file() or not source.resolve().is_relative_to(ROOT):
            raise ValueError('Regular reviewed agent source required')
        destination = context / target
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    return contract['workload_image']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', choices=('docker', 'podman'), default='docker')
    parser.add_argument('--image', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z0-9][a-z0-9._:/-]{0,250}', args.image):
        parser.error('A bounded local image tag is required')
    with tempfile.TemporaryDirectory(prefix='reviewed-agent-build-') as directory:
        context = Path(directory)
        base = prepare(context)
        subprocess.run([args.engine, 'build', '--pull=false', '--build-arg', 'BASE_IMAGE=' + base,
                        '-t', args.image, str(context)], check=True)


if __name__ == '__main__':
    main()
