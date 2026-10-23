# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path
from types import SimpleNamespace
import pytest
import native_build as tool

@pytest.fixture
def cache(tmp_path,monkeypatch):
    tmp_path.chmod(0o700);lock=json.loads((tool.RECIPES/'inputs.lock.json').read_text())
    receipt={'applied':True,'offline_compilation_passed':True,'build_inputs':lock,
        'recipe_sha256':{n:tool.digest(tool.RECIPES/n) for n in ['Builder.Containerfile','build-native.sh']},
        'builder_image_id':'sha256:'+'a'*64}
    path=tmp_path/'receipt.json';path.write_text(json.dumps(receipt));path.chmod(0o600)
    args=SimpleNamespace(compiler_cache_receipt=str(path),compiler_cache_sha256=tool.digest(path),engine='docker')
    monkeypatch.setattr(tool,'capture',lambda words:'sha256:'+'a'*64)
    return args,lock,path,receipt


def test_no_cache_keeps_normal_build_path():
    assert tool.compiler_cache(SimpleNamespace(),{}) is None


def test_reuse_requires_matching_recipe_inputs_and_immutable_local_image(cache):
    args,lock,path,receipt=cache
    assert tool.compiler_cache(args,lock)==receipt['builder_image_id']
    # Endpoint, CA and patch differences do not change the compiler; native code
    # is still compiled later with the new plan and all normal patch checks.
    assert tool.compiler_cache(args,{**lock,'patches':[]})==receipt['builder_image_id']

@pytest.mark.parametrize('field',['builder_base','rust_version','cargo_auditable_version','debian_snapshot','target'])
def test_compiler_input_drift_is_refused(cache,field):
    args,lock,path,receipt=cache
    with pytest.raises(ValueError,match='inputs changed'):tool.compiler_cache(args,{**lock,field:'changed'})


def test_tampered_receipt_and_missing_image_refused(cache,monkeypatch):
    args,lock,path,receipt=cache
    args.compiler_cache_sha256='0'*64
    with pytest.raises(ValueError,match='hash'):tool.compiler_cache(args,lock)
    args.compiler_cache_sha256=tool.digest(path)
    monkeypatch.setattr(tool,'capture',lambda words:'sha256:'+'b'*64)
    with pytest.raises(ValueError,match='not present'):tool.compiler_cache(args,lock)


def test_recipe_drift_refused(cache):
    args,lock,path,receipt=cache
    receipt['recipe_sha256']['build-native.sh']='0'*64;path.write_text(json.dumps(receipt));args.compiler_cache_sha256=tool.digest(path)
    with pytest.raises(ValueError,match='recipes changed'):tool.compiler_cache(args,lock)


def test_compiler_reuse_still_runs_frozen_compilation_and_packaging(tmp_path,monkeypatch):
    lock=json.loads((tool.RECIPES/'inputs.lock.json').read_text())
    (tmp_path/'Cargo.lock').write_text('synthetic-lock');lock['cargo_lock_sha256']=tool.digest(tmp_path/'Cargo.lock')
    plan={'source':str(tmp_path),'images':{r:'localhost/test-'+r for r in ['builder','gateway','supervisor']}}
    monkeypatch.setattr(tool,'prepare',lambda args:(lock,plan))
    monkeypatch.setattr(tool,'compiler_cache',lambda *args:'sha256:'+'a'*64)
    calls=[]
    monkeypatch.setattr(tool,'command',lambda words,*args,**kwargs:calls.append(words))
    monkeypatch.setattr(tool,'capture',lambda *args:'sha256:'+'a'*64)
    monkeypatch.setattr(tool,'runtime_context',lambda *args:tmp_path)
    checked=[]
    monkeypatch.setattr(tool,'validate_runtime',lambda args,role,image:(checked.append(role) or {'packaged_binary_matches':True}))
    result=tool.native_build(SimpleNamespace(output_dir=tmp_path,engine='docker',apply=True))
    assert result['offline_compilation_passed'] and set(checked)=={'gateway','supervisor'}
    assert any(cmd[-1]=='compile' and '--network=none' in cmd for cmd in calls)
    assert not any(cmd[1]=='build' and 'localhost/test-builder' in cmd for cmd in calls)
