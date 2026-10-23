# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path
from types import SimpleNamespace
import pytest
import native_build as tool

@pytest.fixture
def cache(tmp_path):
    tmp_path.chmod(0o700);old=tmp_path/'old';old.mkdir(mode=0o700)
    (old/'cache').mkdir(mode=0o700);(old/'cache/registry').mkdir();(old/'cache/registry/approved-crate').write_text('synthetic-crate')
    (old/'cache/credentials.toml').write_text('must-not-copy')
    (old/'compiled').mkdir(mode=0o700);target=old/'compiled/target/debug';target.mkdir(parents=True)
    (target/'deps').mkdir();(target/'deps/libserde-abc.rlib').write_text('dependency')
    (target/'deps/libopenshell_gateway-abc.rlib').write_text('old-workspace')
    (target/'openshell-gateway').write_text('old-binary')
    (target/'.fingerprint/openshell-gateway-abc').mkdir(parents=True)
    (target/'build/openshell-core-abc').mkdir(parents=True)
    lock={'cargo_lock_sha256':'a'*64,'target':'x86_64-unknown-linux-gnu'};builder='sha256:'+'b'*64
    value={'applied':True,'offline_compilation_passed':True,'builder_image_id':builder,**lock}
    receipt=old/'native-build.receipt.json';receipt.write_text(json.dumps(value));receipt.chmod(0o600)
    out=tmp_path/'new';out.mkdir(mode=0o700)
    args=SimpleNamespace(native_cache_receipt=str(receipt),native_cache_sha256=tool.digest(receipt),output_dir=out)
    return args,lock,builder,old


def test_cache_keeps_only_dependencies_and_forces_workspace_rebuild(cache):
    args,lock,builder,old=cache
    assert tool.seed_dependency_cache(args,lock,builder)
    assert (args.output_dir/'cache/registry/approved-crate').exists()
    assert not (args.output_dir/'cache/credentials.toml').exists()
    target=args.output_dir/'compiled/target/debug'
    assert (target/'deps/libserde-abc.rlib').exists()
    assert not (target/'openshell-gateway').exists() and not (target/'deps/libopenshell_gateway-abc.rlib').exists()
    assert not (target/'.fingerprint/openshell-gateway-abc').exists() and not (target/'build/openshell-core-abc').exists()
    assert (old/'compiled/target/debug/openshell-gateway').exists()

@pytest.mark.parametrize('mode',['hash','compiler','lock','symlink','permissions'])
def test_wrong_cache_is_refused_before_copy(cache,mode):
    args,lock,builder,old=cache
    if mode=='hash':args.native_cache_sha256='0'*64
    if mode=='compiler':builder='sha256:'+'c'*64
    if mode=='lock':lock={**lock,'cargo_lock_sha256':'d'*64}
    if mode=='permissions':(old/'compiled').chmod(0o777)
    if mode=='symlink':
        (old/'compiled/target').rename(old/'compiled/real-target');(old/'compiled/target').symlink_to(old/'compiled/real-target',target_is_directory=True)
    with pytest.raises(ValueError):tool.seed_dependency_cache(args,lock,builder)
    assert not list(args.output_dir.iterdir())
