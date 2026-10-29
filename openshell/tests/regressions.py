#!/usr/bin/env python3
"""Offline behavioral regressions for harness argument, policy and SSH contracts."""
import errno
import json
import hashlib
import io
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import tarfile
import unittest
ROOT = Path(__file__).resolve().parents[2]

class HarnessTests(unittest.TestCase):
    def setUp(self):
        """Create isolated CLI and SSH stubs for regression checks."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.td = Path(self.temp.name)
        self.log = self.td / 'calls'
        mock = self.td / 'openshell'
        mock.write_text('''#!/usr/bin/env python3
import json,os,pathlib,sys
a=sys.argv[1:]

if a[:3] == ["sandbox", "template", "list"]:
    state = pathlib.Path(os.environ['MOCK_LOG'] + '.templates')
    data = json.loads(state.read_text()) if state.exists() else {}
    print(json.dumps({"templates":list(data.values()), "next_page_token":""}))
    sys.exit()
if a[:3] == ["sandbox", "template", "create"]:
    state = pathlib.Path(os.environ['MOCK_LOG'] + '.templates')
    data = json.loads(state.read_text()) if state.exists() else {}
    name = a[3]
    record = {"name":name,"image":a[a.index("--image")+1],
              "resources":{"cpu":a[a.index("--cpu")+1],"memory":a[a.index("--memory")+1]},
              "environment":{},"labels":{}}
    for flag,key in [("--label","labels"),("--env","environment")]:
        for index,argument in enumerate(a):
            if argument == flag:
                k,v=a[index+1].split("=",1);record[key][k]=v
    data[name]=record;state.write_text(json.dumps(data));sys.exit()
if a[:3] == ["sandbox", "template", "get"]:
    print(json.dumps(json.loads(pathlib.Path(os.environ['MOCK_LOG'] + '.templates').read_text())[a[3]]))
    sys.exit()
with open(os.environ['MOCK_LOG'],'a') as f: f.write(json.dumps(a)+'\\n')
if a[:2]==['sandbox','list']:
 print(json.dumps({'sandboxes':[{'name':os.environ['MOCK_NAME'],'phase':'Ready'}]}))
if '--policy' in a:
 p=pathlib.Path(a[a.index('--policy')+1]).read_text()
 assert 'port: "8080"' not in p and '@@' not in p
if a[:2]==['rule','get']:
 print('  Chunk: chunk-123')
 print('  Status: pending')
if a[:3]==['rule','approve','regression']:
 print('approved')
''')
        mock.chmod(0o755)
        ssh = self.td / 'ssh'
        ssh.write_text('''#!/usr/bin/env python3
import json,os,sys
with open(os.environ['MOCK_LOG'],'a') as f: f.write(json.dumps(sys.argv[1:])+'\\n')
sys.stdin.buffer.read()
''')
        ssh.chmod(0o755)
        self.env = {**os.environ, 'PATH': str(self.td)+':'+os.environ['PATH'],
                    'OPENSHELL_BIN':str(mock), 'MOCK_LOG':str(self.log),
                    'OPENSHELL_MODEL_ID':'test-model', 'MOCK_NAME':'regression'}

    def create(self,h,*args):
        return subprocess.run(['bash',str(ROOT/'openshell/harnesses'/h/'create.sh'),
                               '--name','regression',*args], env=self.env,
                              input='', capture_output=True,text=True,timeout=10)

    def test_standalone_detached_and_explicit_provider(self):
        for h in ('codex','opencode','openclaw'):
            r=self.create(h,'--profile','dev','--provider','synthetic')
            self.assertEqual(r.returncode,0,r.stderr)
        calls=[json.loads(s) for s in self.log.read_text().splitlines()]
        for c in calls:
            if c[:2]==['sandbox','create']:
                self.assertIn('--detach',c)
                self.assertIn('--no-auto-providers',c)
                self.assertEqual(c[c.index('--provider')+1],'synthetic')

    def test_policy_advisor_opt_in_is_instance_scoped(self):
        for harness in ('codex','opencode','openclaw'):
            with self.subTest(harness=harness):
                result=self.create(harness,'--profile','dev','--policy-advisor')
                self.assertEqual(result.returncode,0,result.stderr)
        calls=[json.loads(line) for line in self.log.read_text().splitlines()]
        creates=[call for call in calls if call[:2]==['sandbox','create']]
        settings=[call for call in calls if call[:2]==['settings','set']]
        self.assertEqual(len(creates),3)
        self.assertEqual(len(settings),3)
        for call in creates:
            self.assertIn('--approval-mode',call)
            self.assertEqual(call[call.index('--approval-mode')+1],'manual')
        for call in settings:
            self.assertEqual(call[2],'regression')
            self.assertEqual(call[call.index('--key')+1],'agent_policy_proposals_enabled')
            self.assertEqual(call[call.index('--value')+1],'true')

    def test_policy_advisor_remains_off_without_explicit_opt_in(self):
        result=self.create('opencode','--profile','dev')
        self.assertEqual(result.returncode,0,result.stderr)
        calls=[json.loads(line) for line in self.log.read_text().splitlines()]
        create=next(call for call in calls if call[:2]==['sandbox','create'])
        self.assertNotIn('--approval-mode',create)
        self.assertFalse(any(call[:2]==['settings','set'] for call in calls))

    def test_invalid_arguments_never_create(self):
        for h in ('codex','opencode','openclaw'):
            for args in (('--profile',),('--profile','--prepare'),('--profile','../dev'),('--unknown','x'),('--config',),('--backend','anthropic')):
                r=self.create(h,*args)
                self.assertNotEqual(r.returncode,0)
                self.assertNotIn('unbound variable',r.stderr)
        self.assertFalse(self.log.exists())

    def test_integrated_contract(self):
        config=str(ROOT/'configs/openshell-praxis')
        for h in ('codex',):
            self.assertNotEqual(self.create(h,'--profile','dev','--config',config).returncode,0)
        self.env['PRAXIS_PORT']='8080";bad'
        self.assertNotEqual(self.create('opencode','--profile','dev','--config',config).returncode,0)
        self.env['PRAXIS_PORT']='8080'
        self.assertNotEqual(self.create('opencode','--profile','dev','--config',config,'--provider','x').returncode,0)
        r=self.create('opencode','--profile','dev','--config',config)
        self.assertEqual(r.returncode,0,r.stderr)
        calls=[json.loads(s) for s in self.log.read_text().splitlines()]
        self.assertNotIn('--provider',next(call for call in calls if call[:2]==['sandbox','create']))
        ssh=calls[-1]
        self.assertIn('/dev/null',ssh)
        self.assertFalse(any('SendEnv' in x or 'API_KEY' in x for x in ssh))

    def approval(self,*args,audit='approvals.jsonl',confirmation=''):
        return subprocess.run(['bash',str(ROOT/'openshell/scripts/policy-approve.sh'),*args],
                              env={**self.env,'OPENSHELL_APPROVAL_AUDIT_FILE':str(self.td/audit)},
                              input=confirmation,capture_output=True,text=True,timeout=10)

    def test_policy_advisor_can_be_enabled_for_existing_sandbox(self):
        result=self.approval('enable','regression')
        self.assertEqual(result.returncode,0,result.stderr)
        calls=[json.loads(line) for line in self.log.read_text().splitlines()]
        call=next(call for call in calls if call[:2]==['settings','set'])
        self.assertEqual(call[2],'regression')
        self.assertEqual(call[call.index('--key')+1],'agent_policy_proposals_enabled')
        self.assertEqual(call[call.index('--value')+1],'true')

    def test_policy_approval_requires_exact_confirmation(self):
        result=self.approval('approve','regression','--chunk-id','chunk-123',confirmation='no')
        self.assertNotEqual(result.returncode,0,result.stderr)
        calls=[json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertFalse(any(call[:3]==['rule','approve','regression'] for call in calls))
        self.assertFalse((self.td/'approvals.jsonl').exists())

    def test_policy_approval_is_audited(self):
        result=self.approval('approve','regression','--chunk-id','chunk-123','--yes')
        self.assertEqual(result.returncode,0,result.stderr)
        calls=[json.loads(line) for line in self.log.read_text().splitlines()]
        approve=next(call for call in calls if call[:3]==['rule','approve','regression'])
        self.assertEqual(approve[approve.index('--chunk-id')+1],'chunk-123')
        audit_path=self.td/'approvals.jsonl'
        record=json.loads(audit_path.read_text())
        self.assertEqual(record['event'],'openshell.endpoint_grant.approved')
        self.assertEqual(record['sandbox'],'regression')
        self.assertEqual(record['chunk_id'],'chunk-123')
        self.assertTrue(record['reset_on_recreate'])
        self.assertEqual(audit_path.stat().st_mode & 0o777,0o600)

    def test_policy_approval_rejects_unknown_chunk(self):
        result=self.approval('approve','regression','--chunk-id','missing','--yes')
        self.assertNotEqual(result.returncode,0,result.stderr)
        self.assertIn('pending chunk not found',result.stderr)

    def test_policy_approval_rejects_broad_audit_permissions(self):
        audit_path=self.td/'approvals.jsonl'
        audit_path.touch(mode=0o644)
        result=self.approval('approve','regression','--chunk-id','chunk-123','--yes')
        self.assertNotEqual(result.returncode,0,result.stderr)
        self.assertIn('permissions are too broad',result.stderr)

class ReleaseCliTests(unittest.TestCase):
    def test_release_download_is_architecture_matched_and_fails_closed_on_bad_checksum(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            scripts = work / 'openshell/scripts'; scripts.mkdir(parents=True)
            configs = work / 'openshell/configs'; configs.mkdir()
            helper = scripts / 'fetch-cli.sh'
            helper.write_text((ROOT / 'openshell/scripts/fetch-cli.sh').read_text())
            archive = work / 'fixture.tar.gz'
            with tarfile.open(archive, 'w:gz') as stream:
                payload = b'#!/bin/sh\necho fixture\n'
                member = tarfile.TarInfo('openshell'); member.size = len(payload)
                stream.addfile(member, io.BytesIO(payload))
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            def pins(checksum):
                (configs / 'images.env').write_text(
                    f'OPENSHELL_CLI_VERSION=v0.1.4\nOPENSHELL_CLI_SHA256_AMD64={checksum}\n'
                    f'OPENSHELL_CLI_SHA256_ARM64={checksum}\n')
            for name, body in {
                'uname': '#!/bin/sh\nif [ "$1" = -s ]; then echo Linux; else echo "$TEST_ARCH"; fi\n',
                'curl': '#!/bin/sh\nprintf "%s\\n" "$@" > "$DOWNLOAD_LOG"\nwhile [ "$1" != -o ]; do shift; done\ncp "$ARCHIVE" "$2"\n',
            }.items():
                mock = work / name; mock.write_text(body); mock.chmod(0o755)
            env = dict(os.environ, PATH=f'{work}:{os.environ["PATH"]}', ARCHIVE=str(archive),
                       DOWNLOAD_LOG=str(work / 'download'))
            for architecture, target in [('x86_64', 'x86_64'), ('aarch64', 'aarch64')]:
                with self.subTest(architecture=architecture):
                    output = work / architecture; output.mkdir()
                    pins(digest)
                    env['TEST_ARCH'] = architecture
                    result = subprocess.run(['bash', str(helper), str(output)], env=env, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual((output / 'openshell').read_bytes(), payload)
                    self.assertIn(f'/v0.1.4/openshell-{target}-unknown-linux-musl.tar.gz', (work / 'download').read_text())
                    (output / 'openshell').unlink()
                    pins('0' * 64)
                    result = subprocess.run(['bash', str(helper), str(output)], env=env, capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse((output / 'openshell').exists())

class LandlockPreflightTests(unittest.TestCase):
    def setUp(self):
        self.check = runpy.run_path(str(ROOT / 'openshell/scripts/check-landlock.py'))['check_landlock']

    def test_landlock_preflight_accepts_required_abi(self):
        passed, message = self.check(3, lambda: 3)
        self.assertTrue(passed, message)
        self.assertIn('host Landlock ABI 3 meets the required ABI 3', message)

    def test_landlock_preflight_rejects_old_abi_with_actionable_diagnostic(self):
        passed, message = self.check(3, lambda: 2)
        self.assertFalse(passed)
        self.assertIn('host Landlock ABI is 2, but ABI 3 or later is required', message)
        self.assertIn('ContainerExited', message)

    def test_landlock_preflight_rejects_missing_syscall_with_actionable_diagnostic(self):
        error = OSError(errno.ENOSYS, os.strerror(errno.ENOSYS))
        def unavailable():
            raise error
        passed, message = self.check(3, unavailable)
        self.assertFalse(passed)
        self.assertIn('landlock_create_ruleset is unavailable', message)
        self.assertIn('ContainerExited', message)


if __name__=='__main__': unittest.main()
