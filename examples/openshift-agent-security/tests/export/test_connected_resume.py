# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path
import pytest
import connected_install as tool

@pytest.fixture
def checkpoint(tmp_path):
    tmp_path.chmod(0o700);old=tmp_path/'previous';old.mkdir(mode=0o700)
    for name in (*tool.CHECKPOINT_STAGES,'09-discovery-plan'):
        log=old/(name+'.private.log');log.write_text('synthetic stage output');log.chmod(0o600)
        receipt=old/(name+'.receipt.json');receipt.write_text(json.dumps({'stage':name,'exit':1 if name=='09-discovery-plan' else 0,'log_sha256':tool.setup.sha(log)}));receipt.chmod(0o600)
    install=old/'07-install';install.mkdir(mode=0o700)
    ledger=install/'creation-ledger.private.json';ledger.write_text(json.dumps({'completed':True,'pending':None}));ledger.chmod(0o600)
    return old,ledger


def test_only_confirmed_read_failure_checkpoint_is_accepted(checkpoint):
    old,ledger=checkpoint
    assert tool.read_checkpoint(str(old))==(old,ledger)

@pytest.mark.parametrize('mode',['changed-log','failed-create','pending-create','later-pending','later-complete','wrong-stage','public-directory','already-succeeded'])
def test_unsafe_checkpoint_never_enters_completion(checkpoint,mode):
    old,ledger=checkpoint
    if mode=='changed-log':(old/'07-install.private.log').write_text('changed')
    if mode=='failed-create':
        path=old/'07-install.receipt.json';value=json.loads(path.read_text());value['exit']=1;path.write_text(json.dumps(value))
    if mode=='pending-create':ledger.write_text(json.dumps({'completed':False,'pending':{'kind':'Secret'}}))
    if mode=='later-pending':(old/'09-discovery-apply.pending.json').write_text('{}')
    if mode=='later-complete':(old/'11-trust').mkdir()
    if mode=='wrong-stage':
        path=old/'09-discovery-plan.receipt.json';value=json.loads(path.read_text());value['stage']='different';path.write_text(json.dumps(value))
    if mode=='public-directory':old.chmod(0o755)
    if mode=='already-succeeded':
        path=old/'09-discovery-plan.receipt.json';value=json.loads(path.read_text());value['exit']=0;path.write_text(json.dumps(value))
    with pytest.raises(ValueError):tool.read_checkpoint(str(old))


@pytest.mark.parametrize('failure',['source-drift','uid-replacement'])
def test_resume_validation_failure_stops_before_any_completion_stage(checkpoint,tmp_path,monkeypatch,failure):
    from types import SimpleNamespace
    import source_render
    old,ledger=checkpoint
    rendered=old/'02-render';rendered.mkdir(mode=0o700)
    bundle={'installation_profile':{'synthetic':'profile'},'objects':[{'kind':'Secret','metadata':{'name':'fixture-example'}}],
            'native_ca_bundle_sha256':'a'*64,'native_build_contract_matches':True}
    for name,value in [('stack.private.json',bundle),('installation-state.private.json',{})]:
        path=rendered/name;path.write_text(json.dumps(value));path.chmod(0o600)
    expected=dict(bundle)
    if failure=='source-drift':expected['objects']=[]
    monkeypatch.setattr(source_render,'render',lambda *args:(expected,{},{}))
    monkeypatch.setattr(tool.setup,'validate',lambda value:value['objects'])
    def reconcile(*args):raise ValueError('replaced UID')
    monkeypatch.setattr(tool.setup,'reconcile_creation',reconcile)
    args=SimpleNamespace(resume_installation=str(old),output_dir=tmp_path/'new')
    def no_stage(*args,**kwargs):pytest.fail('completion stage started after failed validation')
    with pytest.raises(ValueError):tool.resume_discovery(args,{},None,no_stage,Path('/unused'),None,None)
