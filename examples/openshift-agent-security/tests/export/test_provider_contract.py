# SPDX-License-Identifier: Apache-2.0
"""One public configuration feeds source delivery, policy and the packaged agent."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest
import provider_contract as provider

ROOT = Path(__file__).resolve().parents[2]


def load_tool(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    return tool


@pytest.mark.parametrize("change", [
    {"configured": 1}, {"schema_version": True}, {"credential_file": "/private/key"},
    {"chat_request_url": "https://host.example.test:443/v1/messages"},
    {"chat_request_url": "https://host.example.test/v1/messages?destination=other"},
    {"chat_request_url": "https://user:password@host.example.test/v1/messages"},
    {"workload_image": "registry.example.test/demo/image:latest"},
])
def test_public_configuration_cannot_widen_the_fixed_contract(change):
    with pytest.raises(ValueError):
        provider.validate({**provider.DATA, **change})


def test_public_configuration_rejects_duplicate_keys():
    with pytest.raises(ValueError, match="Duplicate"):
        provider.load('{"configured":false,"configured":true}')


def test_configured_export_changes_data_only_and_builds_a_closed_context(tmp_path, monkeypatch):
    source = tmp_path / "export"
    shutil.copytree(ROOT, source, ignore=shutil.ignore_patterns('__pycache__', '.pytest_cache'))
    before = {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in source.rglob('*') if p.is_file()}
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    key = private / "synthetic-key"
    key.write_text("synthetic-test-value")
    key.chmod(0o600)
    config = {'schema_version': 1, 'chat_request_url': 'https://messages.customer.example/v1/messages',
        'chat_model': 'customer-model', 'workload_image': 'registry.customer.example/demo/workload@sha256:' + 'a' * 64,
        'diagnostic_runtime_image': 'registry.customer.example/demo/runtime@sha256:' + 'b' * 64,
        'credential_file': str(key)}
    configuration = private / 'configuration.json'
    configuration.write_text(json.dumps(config))
    configuration.chmod(0o600)
    tool = load_tool('provider_configure_copy', source / 'scripts/configure-demo.py')
    tool.run(SimpleNamespace(config=configuration, output_dir=private/'configured', apply=True))
    changed = {name for name, digest in before.items()
               if hashlib.sha256((source/name).read_bytes()).hexdigest() != digest}
    assert changed == {'runtime/provider-contract.json'}
    builder = load_tool('provider_build_copy', source / 'scripts/build-agent.py')
    context = tmp_path / 'context'
    context.mkdir()
    assert builder.prepare(context) == config['workload_image']
    assert {str(p.relative_to(context)) for p in context.rglob('*') if p.is_file()} == {
        'Dockerfile', 'src/client.py', 'src/agent_loop.py', 'src/inference.py', 'src/remediation.json',
        'runtime/provider_contract.py', 'runtime/provider-contract.json'}
    assert 'synthetic-test-value' not in ''.join(p.read_text() for p in context.rglob('*') if p.is_file())
    # The same data must reach the Python client, native identity image guard,
    # host-scoped network policy, console evidence filter and sandbox delivery.
    code = r'''import json,provider_contract as p,identity_demo_spire_registration as s
from model_execution import profile
from identity_demo_console_store import safe_evidence
from agent_runtime import sandbox_sources
import inference
assert inference.MODEL == p.MODEL == 'customer-model'
assert inference.URL == p.URL == 'https://messages.customer.example/v1/messages'
assert s.CVE_IMAGE == p.WORKLOAD_IMAGE
assert profile('fixture')['endpoints'][0]['host'] == p.HOST == 'messages.customer.example'
assert safe_evidence({'model':p.MODEL}) == {'model':p.MODEL}
exec(compile(sandbox_sources('import provider_contract as p\nprint(p.MODEL)'),'<delivery>','exec'))
'''
    env = {'PATH': os.defpath, 'PYTHONDONTWRITEBYTECODE': '1',
        'TMPDIR': os.environ.get('TMPDIR', '/tmp'),
        'PYTHONPATH': os.pathsep.join(str(source / folder) for folder in (
            'runtime', 'runtime/identity_demo', 'scripts/identity_demo', 'workloads/agents/service-request-demo/src'))}
    result = subprocess.run([sys.executable, '-c', code], cwd=source, env=env,
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'customer-model'


def test_agent_image_build_refuses_pristine_placeholders(tmp_path):
    builder = load_tool('provider_build_unconfigured', ROOT / 'scripts/build-agent.py')
    with pytest.raises(ValueError, match='Configure'):
        builder.prepare(tmp_path)
