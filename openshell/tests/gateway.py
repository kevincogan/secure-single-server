#!/usr/bin/env python3
"""Check shared gateway behavior without changing host services or ownership."""
import os
import re
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]

class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.td = Path(self.temp.name)
        (self.td / 'home/.config/openshell').mkdir(parents=True)
        (self.td / 'units').mkdir()
        self.env = {**os.environ, 'TEST_ROOT': str(ROOT), 'TEST_TMP': str(self.td)}

    def run_shell(self, body):
        return subprocess.run(['bash', '-c', '''
set -euo pipefail
source "$TEST_ROOT/openshell/scripts/lib.sh"
source "$TEST_ROOT/openshell/scripts/gateway-lib.sh"
''' + body], env=self.env, capture_output=True, text=True)

    def test_config_preserves_workload_and_startup_contracts(self):
        """Keep generated gateway configuration within the pinned schema."""
        for autostart in ('yes', 'no'):
            self.env['AUTOSTART'] = autostart
            result = self.run_shell('''
id() { if [[ "$1" == -u ]]; then echo 1234; else echo owner; fi; }
install() {
  printf '%s\n' "$*" >>"$TEST_TMP/install.log"
  local src="${@: -2:1}" dst="${@: -1}"
  [[ "$dst" != /etc/* ]] || dst="$TEST_TMP/units/${dst##*/}"
  cp "$src" "$dst"
}
gateway_install_config owner "$TEST_TMP/home" "$TEST_TMP" 'example/harness@sha256:abc' "$AUTOSTART"
''')
            self.assertEqual(result.returncode, 0, result.stderr)
            config = (self.td / 'home/.config/openshell/gateway.toml').read_text()
            unit = (self.td / 'units/openshell-gateway.container').read_text()
            self.assertIn('default_image     = "example/harness@sha256:abc"', config)
            self.assertIn('sandbox_runtime_image = "ghcr.io/nvidia/openshell/sandbox@sha256:', config)
            self.assertIn('guest_tls_ca = "/var/lib/openshell/tls/ca.crt"', config)
            self.assertNotIn('guest_tls_cert', config)
            self.assertNotIn('guest_tls_key', config)
            self.assertIn('[openshell.gateway.gateway_jwt]', config)
            self.assertIn('[openshell.gateway.tls]', config)
            self.assertIn('client_ca_path = "/var/lib/openshell/tls/ca.crt"', config)
            self.assertIn('allow_unauthenticated_users = false', config)
            # Public v0.1.5 GatewayTlsFileConfig rejects internal TLS fields.
            tls = re.search(r'\[openshell.gateway.tls\]\n(.*?)(?=\n\[|\Z)', config, re.S).group(1)
            fields = set(re.findall(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=', tls, re.M))
            self.assertLessEqual(fields, {'cert_path', 'key_path', 'client_ca_path',
                                         'external_cert_path', 'external_key_path', 'external_server_names'})
            self.assertIn('[openshell.gateway.mtls_auth]', config)
            self.assertNotIn('disable_tls', config)
            self.assertNotIn('grpc_endpoint', config)
            self.assertNotIn('@@', config + unit)
            self.assertEqual('[Install]' in unit, autostart == 'yes')
            self.assertIn('Exec=--bind-address 127.0.0.1 --port 8090', unit)
            self.assertIn('PodmanArgs=--userns=keep-id:uid=1001,gid=1001', unit)
            calls = (self.td / 'install.log').read_text()
            self.assertIn('-m 0600', calls)
            self.assertIn('-m 0644', calls)

    def test_restart_retains_cli_registration(self):
        result = self.run_shell('''
runner() {
  printf '%s\n' "$*" >>"$TEST_TMP/calls"
  [[ "$1" != tee ]] || { cat >"$2"; return; }
}
curl() { return 0; }
gateway_start runner /native/openshell "$TEST_TMP/registered"
gateway_start runner /native/openshell "$TEST_TMP/registered"
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = (self.td / 'calls').read_text()
        self.assertEqual(calls.count('gateway remove'), 1)
        self.assertEqual(calls.count('gateway add'), 1)
        self.assertIn('gateway add https://127.0.0.1:8090 --local --name local', calls)
        self.assertIn('OPENSHELL_LOCAL_TLS_DIR=/var/lib/openshell/tls', calls)
        self.assertEqual(calls.count('gateway select'), 1)
        self.assertEqual(calls.count('sandbox list'), 2)
        self.assertEqual(calls.count('restart openshell-gateway.service'), 2)

    def test_tls_registration_migration_replaces_legacy_marker(self):
        marker = self.td / 'registered'
        marker.write_text('')
        result = self.run_shell('''
runner() {
  printf '%s\n' "$*" >>"$TEST_TMP/calls"
  [[ "$1" != tee ]] || { cat >"$2"; return; }
}
curl() { return 0; }
gateway_start runner /native/openshell "$TEST_TMP/registered"
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(marker.read_text(), '2\n')
        calls = (self.td / 'calls').read_text()
        self.assertIn('gateway remove local', calls)
        self.assertIn('gateway add https://127.0.0.1:8090 --local --name local', calls)

    def test_failed_health_does_not_register_cli(self):
        result = self.run_shell('''
runner() { printf '%s\n' "$*" >>"$TEST_TMP/calls"; }
curl() { return 22; }
sleep() { :; }
gateway_start runner /native/openshell "$TEST_TMP/registered"
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('gateway add', (self.td / 'calls').read_text())
        self.assertFalse((self.td / 'registered').exists())

if __name__ == '__main__':
    unittest.main()
