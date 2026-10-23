# SPDX-License-Identifier: Apache-2.0
"""Configuration is an offline build step, with no secret reading or cluster effects."""
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import pytest
from deployment_artifacts import IMAGE_ROLES

ROOT=Path(__file__).resolve().parents[2]
def module(name,source):
    spec=importlib.util.spec_from_file_location(name,ROOT/source)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

@pytest.fixture
def fixture(tmp_path,monkeypatch):
    tool=module('configure_export_test','scripts/configure-demo.py')
    repo=tmp_path/'source';repo.mkdir();(repo/'config').mkdir()
    private=tmp_path/'private';private.mkdir(mode=0o700)
    key=private/'key';key.write_text('synthetic-local-key');key.chmod(0o600)
    config={'schema_version':1,'chat_request_url':'https://messages.customer.example/v1/messages','chat_model':'customer-model',
            'workload_image':'registry.customer.example/demo/workload@sha256:'+'a'*64,
            'diagnostic_runtime_image':'registry.customer.example/demo/runtime@sha256:'+'b'*64,'credential_file':str(key)}
    tokens={'endpoint_host':'inference.example.test','model':'approved-chat-model',
            'workload_image':'registry.example.test/demo/cve-workload@sha256:'+'0'*64,
            'diagnostic_image':'registry.example.test/demo/jira-runtime@sha256:'+'0'*64}
    source=repo/'source.py';source.write_text('\n'.join(tokens.values()))
    (repo/'config/configuration-targets.json').write_text(json.dumps({'tokens':tokens,'files':[
        {'path':'source.py','sha256':hashlib.sha256(source.read_bytes()).hexdigest()}]}))
    cp=private/'contract.json';cp.write_text(json.dumps(config));cp.chmod(0o600)
    monkeypatch.setattr(tool,'ROOT',repo)
    return SimpleNamespace(tool=tool,repo=repo,private=private,key=key,config=config,cp=cp,source=source)

@pytest.mark.parametrize('url',[
 'http://messages.customer.example/v1/messages','https://u:p@messages.customer.example/v1/messages',
 'https://messages.customer.example:8443/v1/messages','https://messages.customer.example/v1/messages?key=x',
 'https://messages.customer.example/v1/messages#x','https://messages.customer.example/v1/chat/completions',
 'https://messages.customer.example/v1/messages\n','https://inference.example.test/v1/messages',
 'https://127.0.0.1/v1/messages','https://messages.customer.example:443/v1/messages',
 'https://MESSAGES.customer.example/v1/messages','https://messages..customer.example/v1/messages','https://messages.customer.example/\\v1/messages'])
def test_endpoint_configuration_cannot_widen_transport(fixture,url):
    with pytest.raises(ValueError):fixture.tool.validate({**fixture.config,'chat_request_url':url})

@pytest.mark.parametrize('field,value',[
 ('chat_model','approved-chat-model'),('chat_model','model\";bad'),('chat_model','a'*129),
 ('workload_image','registry.customer.example/demo/workload:latest'),
 ('workload_image','registry.customer.example/demo/workload@sha256:'+'0'*64),
 ('diagnostic_runtime_image','https://registry.customer.example/runtime'),('schema_version',True)])
def test_placeholders_and_unpinned_inputs_cannot_apply(fixture,field,value):
    with pytest.raises(ValueError):fixture.tool.validate({**fixture.config,field:value})


def test_plan_has_no_effect_and_never_reads_key_bytes(fixture,monkeypatch):
    before=fixture.source.read_bytes();read=Path.read_text
    def no_key_read(path,*a,**kw):
        assert path!=fixture.key
        return read(path,*a,**kw)
    monkeypatch.setattr(Path,'read_text',no_key_read)
    result=fixture.tool.run(SimpleNamespace(config=fixture.cp,output_dir=fixture.private/'plan',apply=False))
    assert result['planned'] and not result['applied'] and not result['credential_bytes_read']
    assert not (fixture.private/'plan').exists() and fixture.source.read_bytes()==before


def test_apply_binds_all_sources_and_keeps_before_bytes(fixture):
    before=fixture.source.read_bytes();out=fixture.private/'applied'
    result=fixture.tool.run(SimpleNamespace(config=fixture.cp,output_dir=out,apply=True))
    assert result['applied'] and not result['cluster_changed']
    assert (out/'source-before/source.py').read_bytes()==before
    inference=json.loads((out/'inference-config.private.json').read_text())['chat']
    assert inference['request_url']==fixture.config['chat_request_url'] and inference['model']==fixture.config['chat_model']
    assert inference['tls_verify'] and not inference['follow_redirects'] and inference['ca_file'] is None
    assert 'synthetic-local-key' not in (out/'inference-config.private.json').read_text()
    assert not (out/'inference-config.private.json').stat().st_mode & 0o077
    with pytest.raises(ValueError,match='changed or already configured'):
        fixture.tool.run(SimpleNamespace(config=fixture.cp,output_dir=fixture.private/'again',apply=True))


def test_source_drift_refused_before_any_change(fixture):
    fixture.source.write_text(fixture.source.read_text()+'\nuser edit')
    before=fixture.source.read_bytes()
    with pytest.raises(ValueError,match='Source template changed'):
        fixture.tool.run(SimpleNamespace(config=fixture.cp,output_dir=fixture.private/'failed',apply=True))
    assert fixture.source.read_bytes()==before and not (fixture.private/'failed').exists()


def test_private_key_path_must_be_external_private_and_regular(fixture):
    fixture.key.chmod(0o644)
    with pytest.raises(ValueError):fixture.tool.validate(fixture.config)
    fixture.key.chmod(0o600);link=fixture.private/'link';link.symlink_to(fixture.key)
    with pytest.raises(ValueError):fixture.tool.validate({**fixture.config,'credential_file':str(link)})
    inside=fixture.repo/'key';inside.write_text('synthetic');inside.chmod(0o600)
    with pytest.raises(ValueError):fixture.tool.validate({**fixture.config,'credential_file':str(inside)})


def test_duplicate_config_fields_are_rejected(fixture):
    fixture.cp.write_text('{"schema_version":1,"schema_version":2}')
    with pytest.raises(ValueError,match='Duplicate'):fixture.tool.load_json(fixture.cp)


def test_safety_scan_covers_untracked_documentation_and_tests(tmp_path):
    safety=module('safety_export_test','scripts/check-public-safety.py')
    (tmp_path/'docs').mkdir();(tmp_path/'tests').mkdir()
    (tmp_path/'docs/example.md').write_text('https://api.'+'devshift'+'.net/v1')
    (tmp_path/'tests/input.txt').write_text('sha256'+'~'+'A'*40)
    result=safety.scan(tmp_path)
    assert not result['passed']
    assert {v['path'] for v in result['findings']}=={'docs/example.md','tests/input.txt'}
    assert 'A'*40 not in json.dumps(result)


@pytest.mark.parametrize('name',['.env.local','local.crt','.docker/config.json','.kube/config'])
def test_sharing_scan_rejects_ignored_private_input_files(tmp_path,name):
    safety=module('safety_private_inputs','scripts/check-public-safety.py')
    target=tmp_path/name;target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text('synthetic private input')
    report=safety.scan(tmp_path)
    assert not report['passed']
    assert {'path':name,'category':'private/generated file'} in report['findings']


@pytest.mark.parametrize('value',[
    'ey'+'J'+'a'*20+'.'+'b'*20+'.'+'c'*40,
    'gh'+'p_'+'a'*36,
    'AK'+'IA'+'A'*16,
    'https://user:'+'A'*32+'@customer.example',
])
def test_sharing_scan_reports_credentials_without_disclosing_them(tmp_path,value):
    safety=module('safety_provider_inputs','scripts/check-public-safety.py')
    target=tmp_path/'source.txt';target.write_text(value)
    report=safety.scan(tmp_path)
    assert not report['passed'] and report['findings'][0]['path']=='source.txt'
    assert value not in json.dumps(report)


def test_sharing_scanner_cannot_hide_a_credential_in_its_own_source(tmp_path):
    safety=module('safety_self_scan','scripts/check-public-safety.py')
    (tmp_path/'scripts').mkdir()
    (tmp_path/'scripts/check-public-safety.py').write_text('sha256'+'~'+'A'*40)
    assert not safety.scan(tmp_path)['passed']


def test_delivery_inventory_detects_modified_missing_and_unlisted_files(tmp_path):
    verifier=module('source_inventory','scripts/verify-source.py')
    (tmp_path/'source.py').write_text('original source')
    digest=hashlib.sha256((tmp_path/'source.py').read_bytes()).hexdigest()
    (tmp_path/'export-manifest.json').write_text(json.dumps({'schema_version':1,'files':[
        {'path':'source.py','sha256':digest}]}))
    assert not verifier.inventory_errors(tmp_path)
    (tmp_path/'source.py').write_text('modified source')
    (tmp_path/'untracked.txt').write_text('unreviewed addition')
    errors=verifier.inventory_errors(tmp_path)
    assert 'source.py: inventory hash mismatch' in errors
    assert 'untracked.txt: file absent from inventory' in errors
    (tmp_path/'source.py').unlink()
    assert 'source.py: inventory file missing' in verifier.inventory_errors(tmp_path)


@pytest.mark.parametrize('names',[['../outside'],['source.py','source.py'],['/absolute/source.py']])
def test_delivery_inventory_rejects_escaping_or_ambiguous_entries(tmp_path,names):
    verifier=module('source_inventory_invalid','scripts/verify-source.py')
    (tmp_path/'export-manifest.json').write_text(json.dumps({'schema_version':1,'files':[
        {'path':name,'sha256':'a'*64} for name in names]}))
    assert verifier.inventory_errors(tmp_path)==['export-manifest.json: invalid source inventory']


@pytest.mark.parametrize('value',[[],None,{'schema_version':True,'files':[]},
    {'schema_version':1,'files':[None]}, {'schema_version':1,'files':[{'path':None,'sha256':'a'*64}]}])
def test_delivery_inventory_fails_closed_for_malformed_records(tmp_path,value):
    verifier=module('source_inventory_malformed','scripts/verify-source.py')
    (tmp_path/'export-manifest.json').write_text(json.dumps(value))
    assert verifier.inventory_errors(tmp_path)==['export-manifest.json: invalid source inventory']


def test_provisioning_and_validation_share_the_configured_workload_image():
    """A customer image selection must reach every execution identity guard."""
    import execution_context
    import identity_demo_spire_registration
    assert execution_context.CVE_IMAGE == identity_demo_spire_registration.CVE_IMAGE


@pytest.mark.parametrize("role", sorted(IMAGE_ROLES))
def test_example_image_digests_cannot_be_used_as_installation_inputs(role):
    from deployment_artifacts import validate_artifacts
    images = {name: "registry.customer.example/demo/" + name.replace("_", "-") + "@sha256:" + "a" * 64 for name in IMAGE_ROLES}
    images[role] = images[role].split("@sha256:")[0] + "@sha256:" + "0" * 64
    with pytest.raises(ValueError, match="digest-pinned"):
        validate_artifacts({"schema_version": 1, "images": images})


def test_temporary_exchange_clients_use_the_installation_owner(monkeypatch):
    from types import SimpleNamespace
    import probe_token_exchange as exchange
    import probe_spiffe_exchange as spiffe
    monkeypatch.setattr(exchange, "active_profile", lambda: SimpleNamespace(owner="customer-owner"))
    client = spiffe.federated_client(spiffe.GATEWAY, spiffe.SANDBOX)
    assert client["attributes"]["identity-demo-owner"] == "customer-owner"
    assert client["clientAuthenticatorType"] == "federated-jwt"
    assert "secret" not in client


@pytest.mark.parametrize('git_marker', ['directory', 'file'])
def test_configuration_rejects_private_file_in_parent_checkout(fixture, git_marker):
    marker = fixture.repo.parent / '.git'
    if git_marker == 'directory':
        marker.mkdir()
    else:
        marker.write_text('gitdir: /synthetic/worktree-metadata')
    with pytest.raises(ValueError, match='outside source'):
        fixture.tool.validate(fixture.config)
