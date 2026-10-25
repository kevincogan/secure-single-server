#!/usr/bin/env python3
"""Behavioral tests for immutable workload catalogs and gateway synchronization."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('templates', ROOT / 'openshell/scripts/workload-templates.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class TemplatesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.state = self.directory / 'state.json'
        self.log = self.directory / 'calls.jsonl'
        self.binary = self.directory / 'openshell'
        self.binary.write_text('''#!/usr/bin/env python3
import json,os,pathlib,sys,time
a=sys.argv[3:]; state=pathlib.Path(os.environ['TEMPLATE_STATE'])
data=json.loads(state.read_text()) if state.exists() else {}
with open(os.environ['TEMPLATE_LOG'],'a') as stream: stream.write(json.dumps(a)+'\\n')
mode=os.environ.get('TEMPLATE_FAILURE','')
if mode=='hung': time.sleep(10)
if mode=='list-error' and a[0]=='list': sys.exit(2)
if a[0]=='list':
 if mode=='malformed': print('{}'); sys.exit()
 names=sorted(data)
 if len(names)>1 and '--page-token' not in a:
  print(json.dumps({'templates':[data[names[0]]], 'next_page_token':'next'}))
 else:
  selected=names[1:] if '--page-token' in a else names
  print(json.dumps({'templates':[data[n] for n in selected], 'next_page_token': 'next' if mode=='repeat' else ''}))
elif a[0]=='create':
 name=a[1]
 if len(name)>19: sys.exit(5)
 if mode=='create-error': sys.exit(3)
 value={'name':name,'image':a[a.index('--image')+1], 'resources':{'cpu':a[a.index('--cpu')+1], 'memory':a[a.index('--memory')+1]}, 'labels':{}, 'environment':{}}
 for flag,key in [('--label','labels'),('--env','environment')]:
  for i,arg in enumerate(a):
   if arg==flag:
    k,v=a[i+1].split('=',1); value[key][k]=v
 if mode=='race-bad': value['resources']['cpu']='999'
 data[name]=value; state.write_text(json.dumps(data))
 if mode in ('race','race-bad'): sys.exit(1)
 print(json.dumps(value))
elif a[0]=='get':
 if mode=='get-error' or a[1] not in data: sys.exit(4)
 print(json.dumps(data[a[1]]))
''')
        self.binary.chmod(0o755)
        self.env = {**os.environ, 'TEMPLATE_STATE':str(self.state), 'TEMPLATE_LOG':str(self.log),
                    'ODH_OPENCODE_IMAGE':'quay.io/test/image@sha256:'+'a'*64,
                    'ODH_OPENCLAW_IMAGE':'quay.io/test/claw@sha256:'+'b'*64,
                    'ODH_CODEX_IMAGE':'quay.io/test/codex@sha256:'+'c'*64}
        for key in ('OPENSHELL_TEMPLATE_DIR','OPENSHELL_SANDBOX_CPU','OPENSHELL_SANDBOX_MEMORY'):
            self.env.pop(key,None)

    def run_tool(self, *arguments, **environment):
        return subprocess.run(['python3', str(ROOT / 'openshell/scripts/workload-templates.py'),
                               *arguments, '--binary',str(self.binary)],
                              env={**self.env,**environment},text=True,capture_output=True,timeout=15)

    def ensure(self, **environment):
        return self.run_tool('ensure','--harness','opencode','--profile','dev',**environment)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def test_sync_is_idempotent_and_labels_inventory(self):
        first=self.run_tool('sync'); self.assertEqual(first.returncode,0,first.stderr)
        second=self.run_tool('sync'); self.assertEqual(second.returncode,0,second.stderr)
        self.assertEqual(first.stdout,second.stdout)
        records=json.loads(self.state.read_text())
        self.assertEqual(len(records),25)
        self.assertEqual(len([call for call in self.calls() if call[0]=='create']),25)
        self.assertTrue(any('--page-token' in call for call in self.calls()))
        for record in records.values():
            self.assertLessEqual(len(record['name']),19)
            self.assertEqual(record['labels']['managed-by'],'secure-single-server')
            self.assertNotIn('policy',record); self.assertNotIn('provider',record)

    def test_resource_overrides_create_new_template_without_mutating_old(self):
        first=self.ensure(); self.assertEqual(first.returncode,0,first.stderr)
        second=self.ensure(OPENSHELL_SANDBOX_CPU='500m', OPENSHELL_SANDBOX_MEMORY='512Mi')
        self.assertEqual(second.returncode,0,second.stderr)
        self.assertNotEqual(first.stdout,second.stdout)
        records=json.loads(self.state.read_text())
        self.assertEqual(records[first.stdout.strip()]['resources'],{'cpu':'2','memory':'4Gi'})
        self.assertEqual(records[second.stdout.strip()]['resources'],{'cpu':'500m','memory':'512Mi'})

    def test_existing_template_drift_is_rejected(self):
        result=self.ensure(); self.assertEqual(result.returncode,0,result.stderr)
        records=json.loads(self.state.read_text())
        for field,value in [('resources',{'cpu':'99','memory':'4Gi'}), ('labels',{}),
                            ('environment',{'API_KEY':'bad'}), ('driver_config',{'podman':{}}),
                            ('resources',{'cpu':'2','memory':'4Gi','gpu':1}), ('command',['unreviewed'])]:
            original=json.loads(json.dumps(records)); original[result.stdout.strip()][field]=value
            self.state.write_text(json.dumps(original))
            failed=self.ensure(); self.assertNotEqual(failed.returncode,0,field)
        self.assertEqual(len([call for call in self.calls() if call[0]=='create']),1)

    def test_failures_never_prove_sync_and_exact_concurrent_creation_is_safe(self):
        for mode in ('list-error','malformed','create-error','get-error','race-bad'):
            self.state.unlink(missing_ok=True)
            failed=self.ensure(TEMPLATE_FAILURE=mode)
            self.assertNotEqual(failed.returncode,0,mode)
        self.state.unlink(missing_ok=True)
        success=self.ensure(TEMPLATE_FAILURE='race')
        self.assertEqual(success.returncode,0,success.stderr)
        failed=self.ensure(TEMPLATE_FAILURE='repeat')
        self.assertNotEqual(failed.returncode,0)

    def test_invalid_resources_fail_before_gateway_calls(self):
        for environment in ({'OPENSHELL_SANDBOX_CPU':'0'}, {'OPENSHELL_SANDBOX_MEMORY':'1024B'}):
            failed=self.ensure(**environment); self.assertNotEqual(failed.returncode,0)
        self.assertEqual(self.calls(),[])

    def test_new_profile_and_defaults_need_only_manifest_entry(self):
        with patch.dict(os.environ,self.env,clear=True): entries=module.catalog()
        item=next(record.copy() for record in entries if record['harness']=='opencode' and record['backend']=='standalone')
        item.update(profile='tiny',cpu='500m',memory='512Mi',environment={'FEATURE_FLAG':'on'})
        manifest=self.directory/'new'; manifest.mkdir()
        (manifest/'opencode.json').write_text(json.dumps({'version':1,'templates':[item]}))
        result=self.run_tool('ensure','--harness','opencode','--profile','tiny',OPENSHELL_TEMPLATE_DIR=str(manifest))
        self.assertEqual(result.returncode,0,result.stderr)
        record=json.loads(self.state.read_text())[result.stdout.strip()]
        self.assertEqual(record['resources'],{'cpu':'500m','memory':'512Mi'})
        self.assertEqual(record['environment'],{'FEATURE_FLAG':'on'})
        item['environment']['OPENAI_API_KEY']='must-not-persist'
        (manifest/'opencode.json').write_text(json.dumps({'version':1,'templates':[item]}))
        failed=self.run_tool('sync',OPENSHELL_TEMPLATE_DIR=str(manifest))
        self.assertNotEqual(failed.returncode,0)
        self.assertNotIn('must-not-persist',failed.stderr)

    def test_deadline_bounds_hung_cli_and_rejects_invalid_timeout(self):
        failed=self.ensure(TEMPLATE_FAILURE='hung',OPENSHELL_TEMPLATE_TIMEOUT='0.2')
        self.assertNotEqual(failed.returncode,0)
        for timeout in ('0','nan','inf','bad'):
            failed=self.ensure(OPENSHELL_TEMPLATE_TIMEOUT=timeout)
            self.assertNotEqual(failed.returncode,0)

    def test_catalog_validation_and_backend_selection(self):
        with patch.dict(os.environ,self.env,clear=True):
            entries=module.catalog()
            for harness in ('opencode','openclaw'):
                standalone=module.select(entries,harness,'dev','','cloud')
                self.assertEqual(standalone['backend'],'standalone')
                local=module.select(entries,harness,'dev','','remote-vllm')
                self.assertEqual(local['model_id'],'Qwen/Qwen3-8B')
                with self.assertRaises(ValueError): module.select(entries,harness,'dev','/custom','vllm')
            with self.assertRaises(ValueError): module.select(entries,'codex','dev','/custom','')
            with self.assertRaises(ValueError): module.select(entries,'openclaw','review','/custom','')


if __name__=='__main__': unittest.main()
