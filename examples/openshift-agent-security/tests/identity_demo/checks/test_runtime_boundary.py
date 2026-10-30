# SPDX-License-Identifier: Apache-2.0
"""Runtime imports require neither pytest nor the checks package."""
import json
from pathlib import Path
import subprocess
import sys


def test_operational_sources_do_not_import_qualification_modules():
    """Catch lazy imports that a service-start import smoke check cannot reach."""
    import ast

    root = Path(__file__).resolve().parents[3]
    qualification = {path.stem for path in (root / 'tests/identity_demo').glob('*.py')}
    violations = []
    for directory in ('scripts', 'runtime'):
        for path in (root / directory).rglob('*.py'):
            for node in ast.walk(ast.parse(path.read_text())):
                names = ([alias.name for alias in node.names] if isinstance(node, ast.Import)
                         else [node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
                if any(name.split('.')[0] in qualification for name in names):
                    violations.append(f'{path.relative_to(root)}:{node.lineno}')
    assert not violations, '\n'.join(violations)


def test_runtime_services_import_without_test_packages():
    code = """import sys,importlib.abc
class RejectTests(importlib.abc.MetaPathFinder):
 def find_spec(self, fullname, path=None, target=None):
  if fullname == 'pytest' or fullname == 'checks' or fullname.startswith('checks.'):
   raise ImportError('test dependency in runtime')
sys.meta_path.insert(0,RejectTests())
import identity_demo_driver,identity_demo_console_worker,identity_demo_console_preparer
import probe_native_exchange,identity_demo_fixture_http
"""
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_runtime_source_list_excludes_automated_checks():
    root = Path(__file__).resolve().parents[3]
    manifest = json.loads((root/'config/runtime-sources.json').read_text())
    assert manifest['schema_version'] == 1
    assert len(manifest['files']) == len(set(manifest['files']))
    assert all((root/p).is_file() for p in manifest['files'])
    assert not any('/checks/' in p or p.startswith('tests/export/') or '/service-request-demo/tests/' in p for p in manifest['files'])
    assert 'runtime/identity_demo/probe_native_exchange.py' in manifest['files']
    requirements = (root/'config/requirements-runtime.txt').read_text().lower()
    assert 'pytest==' not in requirements and 'pluggy==' not in requirements
