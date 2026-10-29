#!/usr/bin/env python3
"""Exercise build argument validation and context isolation without a registry."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PIN = 'registry.redhat.io/rhel9/rhel-bootc@sha256:' + 'a' * 64


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.log = self.directory / 'calls'
        podman = self.directory / 'podman'
        podman.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ['CALL_LOG'], 'a') as output:
    output.write(json.dumps(args) + '\\n')
if args[0] == 'info':
    print(os.environ.get('TEST_PLATFORM', 'linux/amd64'))
elif args[:2] == ['image', 'inspect']:
    print('b' * 64)
elif args[0] == 'tag':
    pass
elif args[0] == 'build':
    file_index = args.index('-f') + 1
    context = pathlib.Path(args[-1])
    assert not (context / '.git').exists()
    assert not (context / '.state').exists()
    assert not (context / 'evidence').exists()
    assert not (context / 'rhsm_org').exists()
    assert not (context / 'rhsm_activation_key').exists()
    if args[file_index].endswith('/bootc/Containerfile'):
        assert (context / 'bootc/openshell').is_file()
        assert (context / 'openshell/configs/images.env').is_file()
        assert (context / 'bootc/scripts/reconcile').is_file()
        assert (context / 'bootc/scripts/vllm-common').is_file()
        assert (context / 'bootc/vllm-profile').read_text() == 'any\\n'
        assert not (context / 'bootc/scripts/praxis').exists()
        assert not (context / 'bootc/install-nvidia').exists()
        assert not (context / 'openshell/harnesses').exists()
    elif args[file_index].endswith('/bootc/Containerfile.praxis'):
        assert (context / 'bootc/scripts/praxis').is_file()
        assert (context / 'scripts/common/secret-set').is_file()
        assert (context / 'configs/all-in-one/shared-gateway.yaml').is_file()
        assert not (context / 'bootc/install-nvidia').exists()
        assert not (context / 'openshell').exists()
        assert not (context / 'configs/vllm/images.env').exists()
    elif args[file_index].endswith('/bootc/Containerfile.vllm.cpu'):
        assert not (context / 'bootc/install-nvidia').exists()
        assert (context / 'bootc/vllm-profile').read_text() == 'cpu\\n'
        assert (context / 'bootc/scripts/vllm-common').is_file()
        assert (context / 'scripts/common/lib.sh').is_file()
        assert (context / 'configs/vllm/images.env').is_file()
        assert not (context / 'openshell/configs').exists()
        assert not (context / 'openshell').exists()
    elif args[file_index].endswith('/bootc/Containerfile.vllm.gpu'):
        assert (context / 'bootc/install-nvidia').is_file()
        assert (context / 'bootc/vllm-profile').read_text() == 'gpu\\n'
        assert (context / 'bootc/scripts/vllm-common').is_file()
        assert (context / 'scripts/common/lib.sh').is_file()
        assert (context / 'configs/vllm/images.env').is_file()
        assert not (context / 'openshell/configs').exists()
        assert not (context / 'openshell').exists()
    elif args[file_index].endswith('/bootc/Containerfile.harness'):
        assert (context / 'bootc/harnesses').is_dir()
        assert (context / 'openshell/harnesses').is_dir()
        catalog = list((context / 'configs/templates').glob('*.json'))
        assert len(catalog) == 1
        assert json.loads(catalog[0].read_text())['templates']
        assert not list((context / 'openshell/harnesses/codex').glob('.test-secret.*.secret'))
        assert not (context / 'openshell/configs').exists()
    else:
        sys.exit(3)
else:
    sys.exit(3)
''')
        podman.chmod(0o755)
        # Build/context tests use a synthetic download; fetch-cli tests exercise
        # checksum enforcement independently.
        for name, body in {
            'uname': '#!/bin/sh\nif [ "$1" = -s ]; then echo Linux; else echo x86_64; fi\n',
            'sha256sum': '#!/bin/sh\ncat >/dev/null\n',
            'curl': '''#!/usr/bin/env python3
import io, sys, tarfile
with tarfile.open(sys.argv[sys.argv.index('-o') + 1], 'w:gz') as archive:
    payload = b'#!/bin/sh\\necho openshell 0.1.5\\n'
    member = tarfile.TarInfo('openshell'); member.size = len(payload)
    archive.addfile(member, io.BytesIO(payload))
''',
        }.items():
            script = self.directory / name
            script.write_text(body)
            script.chmod(0o755)
        self.env = {
            **{key: value for key, value in os.environ.items()
               if key not in {'RHSM_ORG_ID', 'RHSM_ACTIVATION_KEY'}},
            'PATH': str(self.directory) + ':' + os.environ['PATH'],
            'CALL_LOG': str(self.log),
            'RHEL_BOOTC_IMAGE': PIN,
        }

    def run_build(self, *args):
        return subprocess.run([str(ROOT / 'bootc/build'), *args], env=self.env,
                              capture_output=True, text=True)

    def test_all_builds_direct_images_and_common_base(self):
        import json
        result = self.run_build('all')
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(row) for row in self.log.read_text().splitlines()]
        builds = [call for call in calls if call[0] == 'build']
        self.assertEqual(len(builds), 7)
        source = (ROOT / 'bootc/Containerfile').read_text()
        self.assertNotRegex(source, r'dnf install[^\n]*ripgrep')
        self.assertIn('rg_version=14.1.1', source)
        self.assertIn('4cf9f2741e6c465ffdb7c26f38056a59e2a2544b51f7cc128ef28337eeae4d8e', source)
        self.assertIn('BurntSushi/ripgrep/releases/download', source)
        self.assertIn('/usr/local/bin/rg', source)
        self.assertIn('RHEL_BOOTC_IMAGE=' + PIN, builds[0])
        self.assertIn('RHSM=0', builds[0])
        self.assertIn('--secret', builds[0])
        self.assertIn('RHEL_BOOTC_IMAGE=' + PIN, builds[1])
        self.assertIn('RHSM=0', builds[1])
        self.assertIn('RHEL_BOOTC_IMAGE=' + PIN, builds[2])
        self.assertIn('RHSM=0', builds[2])
        self.assertIn('RHEL_BOOTC_IMAGE=' + PIN, builds[3])
        self.assertIn('RHSM=0', builds[3])
        for harness, call in zip(('codex', 'opencode', 'openclaw'), builds[4:]):
            self.assertIn('BASE_IMAGE=' + 'b' * 64, call)
            self.assertIn('HARNESS=' + harness, call)
            self.assertIn('--pull=never', call)

    def test_praxis_builds_directly_from_rhel_bootc(self):
        import json
        result = self.run_build('praxis', 'localhost/praxis-test')
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(row) for row in self.log.read_text().splitlines()]
        builds = [call for call in calls if call[0] == 'build']
        self.assertEqual(len(builds), 1)
        self.assertIn('RHEL_BOOTC_IMAGE=' + PIN, builds[0])
        self.assertIn('RHSM=0', builds[0])
        self.assertTrue(any('Containerfile.praxis' in arg for arg in builds[0]))
        self.assertFalse(any(call[:2] == ['image', 'inspect'] for call in calls))

    def test_vllm_profiles_build_directly_from_rhel_bootc(self):
        import json
        for profile in ('cpu', 'gpu'):
            with self.subTest(profile=profile):
                self.log.write_text('')
                result = self.run_build('vllm-' + profile, 'localhost/vllm-test')
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = [json.loads(row) for row in self.log.read_text().splitlines()]
                builds = [call for call in calls if call[0] == 'build']
                self.assertEqual(len(builds), 1)
                self.assertIn('RHEL_BOOTC_IMAGE=' + PIN, builds[0])
                self.assertIn('RHSM=0', builds[0])
                self.assertTrue(any(f'Containerfile.vllm.{profile}' in arg for arg in builds[0]))
                self.assertIn(f'localhost/vllm-test:vllm-{profile}', builds[0])
                self.assertFalse(any(call[:2] == ['image', 'inspect'] for call in calls))

    def test_gpu_installers_pin_epel_release(self):
        expected_url = 'https://download.fedoraproject.org/pub/epel/9/Everything/x86_64/Packages/e/epel-release-9-11.el9.noarch.rpm'
        expected_digest = 'b434245bffd8b40ea486157e72363d08b36e38145c8f917c5c00adfca3f2101b'
        for relative in ('bootc/install-nvidia', 'scripts/vllm/prepare-gpu'):
            with self.subTest(installer=relative):
                source = (ROOT / relative).read_text()
                self.assertIn(expected_url, source)
                self.assertIn(expected_digest, source)
                self.assertIn('sha256sum -c -', source)
                self.assertNotIn('epel-release-latest-9', source)
                if relative == 'scripts/vllm/prepare-gpu':
                    self.assertIn('[[ -d "/lib/modules/$(uname -r)/build" ]]', source)

    def test_rejects_ambiguous_vllm_target(self):
        result = self.run_build('vllm', 'localhost/vllm-test')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unknown target: vllm', result.stderr)

    def test_rhsm_secrets_are_mounted_without_baking_values(self):
        import json
        self.env['RHSM_ORG_ID'] = 'test-org'
        self.env['RHSM_ACTIVATION_KEY'] = 'test-key'
        result = self.run_build('base')
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(row) for row in self.log.read_text().splitlines()]
        build = next(call for call in calls if call[0] == 'build')
        self.assertIn('RHSM=1', build)
        secret_args = [arg for arg in build if arg.startswith('id=rhsm_')]
        self.assertEqual(len(secret_args), 2)
        self.assertTrue(all('src=' in arg for arg in secret_args))

    def test_rhsm_credentials_must_be_paired(self):
        self.env['RHSM_ORG_ID'] = 'test-org'
        result = self.run_build('base')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('RHSM_ORG_ID and RHSM_ACTIVATION_KEY must be set together', result.stderr)

    def test_harness_build_ignores_rhsm_and_excludes_local_secrets(self):
        import json
        descriptor, secret_name = tempfile.mkstemp(
            prefix='.test-secret.', suffix='.secret',
            dir=ROOT / 'openshell/harnesses/codex')
        os.close(descriptor)
        secret = Path(secret_name)
        secret.write_text('local secret\n')
        self.addCleanup(secret.unlink)
        self.env['RHSM_ORG_ID'] = 'test-org'
        result = self.run_build('codex', 'localhost/harness-test')
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(row) for row in self.log.read_text().splitlines()]
        build = next(call for call in calls if call[0] == 'build')
        self.assertNotIn('RHSM=1', build)
        self.assertFalse(any(arg.startswith('id=rhsm_') for arg in build))

    def test_rejects_unpinned_or_wrong_distribution(self):
        for image in ('registry.redhat.io/rhel9/rhel-bootc:latest',
                      'registry.redhat.io/rhel10/rhel-bootc@sha256:' + 'a' * 64):
            self.env['RHEL_BOOTC_IMAGE'] = image
            self.assertNotEqual(self.run_build('base').returncode, 0)
        self.assertNotIn('"build"', self.log.read_text())

    def test_rejects_arm_builder(self):
        self.env['TEST_PLATFORM'] = 'linux/arm64'
        self.assertNotEqual(self.run_build('base').returncode, 0)
        self.assertNotIn('"build"', self.log.read_text())

    def test_rejects_path_traversal_before_podman(self):
        self.assertNotEqual(self.run_build('../codex').returncode, 0)
        self.assertFalse(self.log.exists())


class HarnessScriptTests(unittest.TestCase):
    def test_profile_validation_after_loading_shared_libraries(self):
        # Regression: CONFIG_DIR collided with a readonly variable in the Praxis library.
        for harness in ('codex', 'opencode', 'openclaw'):
            with self.subTest(harness=harness):
                result = subprocess.run(
                    ['bash', str(ROOT / 'openshell/harnesses' / harness / 'create.sh'),
                     '--profile', 'invalid'], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f'no template for {harness}/invalid/standalone', result.stderr)
                self.assertNotIn('readonly variable', result.stderr)


if __name__ == '__main__':
    unittest.main()
