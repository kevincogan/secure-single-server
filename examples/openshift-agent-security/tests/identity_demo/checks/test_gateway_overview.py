# SPDX-License-Identifier: Apache-2.0
"""Keep the gateway presentation scoped to the selected installation."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from deployment_profile import DeploymentProfile, LEGACY
import gateway_overview


def test_catalog_uses_selected_installation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Catalog credentials stay on stdin and never reach the reference adapter."""
    profile = DeploymentProfile.from_dict({**LEGACY.to_dict(), "core_namespace": "customer-eval"})
    monkeypatch.setattr(gateway_overview, "active_profile", lambda: profile)
    monkeypatch.setattr(gateway_overview.native, "NAMESPACE", profile.core_namespace)
    credential = tmp_path / "catalog.private.json"
    credential.write_text(json.dumps({"token": "synthetic-catalog-credential"}))
    credential.chmod(0o600)
    monkeypatch.setattr(gateway_overview, "private_path", lambda value: value)
    calls = []

    def command(words: list[str], **kwargs: object) -> SimpleNamespace:
        calls.append((words, kwargs))
        return SimpleNamespace(returncode=0, stdout='{"catalog_only_tools_list":true}', stderr="")

    monkeypatch.setattr(gateway_overview.subprocess, "run", command)
    args = SimpleNamespace(protected_backend_catalog_credential_file=str(credential),
                           kubeconfig="private-config", output_dir=tmp_path, label="walkthrough-test")
    assert gateway_overview.catalog_schemas(args)["catalog_only_tools_list"]
    words, kwargs = calls[0]
    program = words[-1]
    assert "https://fixture-protected-adapter.customer-eval.svc.cluster.local:8443/mcp" in program
    assert "demo-core" not in program
    assert "follow_redirects=False" in program and "ssl.create_default_context" in program
    assert "synthetic-catalog-credential" not in " ".join(words)
    assert json.loads(kwargs["input"])["token"] == "synthetic-catalog-credential"
    assert words[words.index("-n") + 1] == profile.core_namespace


def schemas():
    return [{'name':'step56_jira_'+name,'description':'untrusted description must not be displayed',
        'inputSchema':{'properties':{'project':{'type':'string','description':'private-example-value'}},
                       'required':['project']}} for name in ('readJiraProject','createJiraIssue')]


def test_native_projection_retains_only_observed_names_and_argument_shapes():
    safe=gateway_overview.project_schemas(schemas())
    assert {v['name'] for v in safe}=={'readJiraProject','createJiraIssue'}
    assert all(v['arguments']==[{'name':'project','type':'string','required':True}] for v in safe)
    assert 'private-example-value' not in json.dumps(safe) and 'untrusted description' not in json.dumps(safe)
    values=schemas();values[0]['inputSchema']['properties']['api_key']={'type':'string'}
    with pytest.raises(ValueError):gateway_overview.project_schemas(values)


def test_cluster_presentation_uses_actual_native_discovery_without_pod_exec(monkeypatch):
    monkeypatch.setenv('IDENTITY_DEMO_RUNTIME','cluster')
    def forbidden(*a,**k):raise AssertionError('No extra API, credential read or Pod exec')
    monkeypatch.setattr(gateway_overview.subprocess,'run',forbidden)
    monkeypatch.setattr(gateway_overview,'private_path',forbidden)
    args=SimpleNamespace(native_tools_list_observed=True,native_tool_schemas=gateway_overview.project_schemas(schemas()))
    result=gateway_overview.catalog_schemas(args)
    assert result['native_tools_list_observed'] and result['catalog_only_tools_list'] is False
    args.native_tools_list_observed=False
    with pytest.raises(ValueError):gateway_overview.catalog_schemas(args)


def test_native_client_embeds_the_same_bounded_projection_without_extra_calls():
    from probe_native_exchange import read_program
    program=read_program('https://resource.example/mcp')
    compile(program,'native-client','exec')
    assert 'def project_schemas' in program and '"published_tool_schemas":published_schemas' in program
    assert program.count('listed = rpc("tools/list", {})')==1


def test_native_error_cannot_export_a_reflected_body_even_as_base64(monkeypatch,capsys):
    import base64
    import urllib.request
    from probe_native_exchange import read_program
    canary='synthetic-service-credential-canary'
    class Response:
        status=403
        headers={}
        def __enter__(self):return self
        def __exit__(self,*a):return None
        def read(self,limit):return json.dumps({'reflected':canary}).encode()
    class Client:
        def open(self,request,timeout):
            assert not request.has_header('Authorization')
            return Response()
    monkeypatch.setattr(urllib.request,'build_opener',lambda *a:Client())
    monkeypatch.delenv('subject_token',raising=False)
    exec(read_program('https://resource.example/mcp'),{})
    output=capsys.readouterr().out;value=json.loads(output)
    assert value['read_passed'] is False and value['raw_body_withheld'] is True
    assert '_private_response' not in value and canary not in output
    assert base64.b64encode(json.dumps({'reflected':canary}).encode()).decode() not in output
