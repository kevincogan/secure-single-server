# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path
from types import SimpleNamespace
import pytest
import runtime_delivery as tool
from deployment_artifacts import IMAGE_ROLES

@pytest.fixture
def args(tmp_path):
    tmp_path.chmod(0o700)
    images={r:'registry.customer.example/demo/'+r.replace('_','-')+'@sha256:'+'a'*64 for r in IMAGE_ROLES}
    path=tmp_path/'artifacts.json';path.write_text(json.dumps({'schema_version':1,'images':images}));path.chmod(0o600)
    out=tmp_path/'out';out.mkdir(mode=0o700)
    return SimpleNamespace(artifacts_file=str(path),workload_image='registry.customer.example/demo/workload@sha256:'+'b'*64,
        output_dir=out,apply=False,engine='podman')


def test_plan_never_contacts_registry_or_engine(args,monkeypatch):
    monkeypatch.setattr(tool.subprocess,'run',lambda *a,**kw:pytest.fail('unexpected execution'))
    assert not tool.run(args)['executed']


def test_image_checks_have_no_credentials_mounts_or_network_and_do_not_claim_approval(args,monkeypatch):
    commands=[]
    def run(command,**kwargs):
        commands.append(command)
        assert '--network=none' in command and '--pull=never' in command and '--read-only' in command
        assert not any(arg in ('-v','--volume','--mount','--privileged') for arg in command)
        return SimpleNamespace(returncode=0,stdout=b'must never export',stderr=b'must never export')
    monkeypatch.setattr(tool.subprocess,'run',run);args.apply=True
    result=tool.run(args)
    assert len(commands)==2 and result['runtime_interface_checks_passed']
    assert not result['source_and_redistribution_approved'] and not result['functional_scenarios_proven']
    assert all('must never export' not in p.read_text() for p in args.output_dir.iterdir())


def test_failed_image_check_stops_before_next_image_without_raw_output(args,monkeypatch):
    calls=[]
    def run(command,**kwargs):
        calls.append(command);return SimpleNamespace(returncode=1,stdout=b'private-body',stderr=b'private-body')
    monkeypatch.setattr(tool.subprocess,'run',run);args.apply=True
    with pytest.raises(ValueError,match='Runtime contract'):tool.run(args)
    assert len(calls)==1 and all('private-body' not in p.read_text() for p in args.output_dir.iterdir())

@pytest.mark.parametrize('image',['registry.example.test/demo/runtime:latest','registry.example.test/demo/runtime@sha256:'+'0'*64])
def test_placeholder_or_mutable_image_is_refused(args,image):
    args.workload_image=image
    with pytest.raises(ValueError):tool.run(args)


def test_jira_import_uses_only_synthetic_configuration_without_calling_a_tool():
    probe=tool.PROBES['jira_runtime']
    assert 'https://jira.invalid' in probe and 'synthetic-probe-only' in probe
    assert 'getJiraIssue(' not in probe and 'searchJiraIssuesUsingJql(' not in probe
