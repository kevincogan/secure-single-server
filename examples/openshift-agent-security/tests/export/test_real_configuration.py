# SPDX-License-Identifier: Apache-2.0
"""The actual export targets must configure; synthetic fixture hashes are insufficient."""
import ast
import importlib.util
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import pytest


def test_actual_export_targets_plan_and_reject_drift(tmp_path):
    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location('actual_configuration',root/'scripts/configure-demo.py')
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    key = tmp_path/'key'; key.write_text('synthetic-not-a-real-credential'); key.chmod(0o600)
    config = {'schema_version':1,'chat_request_url':'https://messages.customer.example/v1/messages',
        'chat_model':'customer-model','workload_image':'registry.customer.example/workload@sha256:'+'a'*64,
        'diagnostic_runtime_image':'registry.customer.example/runtime@sha256:'+'b'*64,'credential_file':str(key)}
    changes=tool.plan(config)
    assert changes and all(before != after for path,before,after in changes)
    assert all(path.read_bytes()==before for path,before,after in changes)


@pytest.mark.parametrize('optimization',[0,1])
def test_report_validation_survives_optimization(optimization):
    root=Path(__file__).resolve().parents[2]
    tree=ast.parse((root/'runtime/identity_demo/permission_flow.py').read_text())
    method=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='validate_report')
    ns={};exec(compile(ast.Module(body=[method],type_ignores=[]),'<validation>','exec',optimize=optimization),ns)
    with pytest.raises(ValueError):
        ns['validate_report'](SimpleNamespace(project='TEST'),{'assessment_preserved_after_local_denial':False,'proposed_create':{'project':'OTHER'}})


def test_optimized_driver_start_is_explicitly_rejected():
    result=subprocess.run([sys.executable,'-O','-c','import identity_demo_driver'],capture_output=True,text=True)
    assert result.returncode and 'Optimized interpreter is unsupported' in result.stderr
