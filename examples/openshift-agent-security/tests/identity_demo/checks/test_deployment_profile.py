# SPDX-License-Identifier: Apache-2.0
"""Installation configuration is an explicit boundary, never an implicit context."""

import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from deployment_profile import DeploymentProfile, LEGACY, read_profile


@pytest.mark.parametrize('collision', [False, True])
def test_private_cli_profile_reuse_is_exact(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, collision: bool) -> None:
    """Repeatable setup may log in again; it must not overwrite another issuer."""
    import probe_runtime_management as management
    tmp_path.chmod(0o700)
    base = 'https://issuer.example.org'
    gateway = tmp_path / 'openshell/gateways/identity-demo-runtime'
    (gateway / 'mtls').mkdir(parents=True)
    (gateway / 'mtls/ca.crt').write_text('synthetic-public-root')
    saved = {'name': 'identity-demo-runtime', 'gateway_endpoint': 'https://127.0.0.1:18443',
             'auth_mode': 'oidc', 'oidc_issuer': base + '/realms/identity-demo',
             'oidc_client_id': 'fixture-runtime-operator', 'oidc_audience': management.AUDIENCE}
    if collision:
        saved['oidc_issuer'] = 'https://other.invalid/realms/identity-demo'
    metadata = gateway / 'metadata.json'
    metadata.write_text(json.dumps(saved))
    original = metadata.read_bytes()
    ca = tmp_path / 'public-ca.pem'
    ca.write_text('synthetic-public-root')
    calls = []
    def command(words: list[str], **kw: object) -> SimpleNamespace:
        calls.append(words)
        return SimpleNamespace(returncode=0, stderr='')
    monkeypatch.setattr(management.subprocess, 'run', command)
    args = SimpleNamespace(cli_config_dir=str(tmp_path), ca_file=str(ca), cli='synthetic-cli')
    if collision:
        with pytest.raises(ValueError, match='different gateway'):
            management.initialize_cli(args, {'runtime_management': {'client_secret': 'synthetic'}}, base)
        assert not calls
    else:
        management.initialize_cli(args, {'runtime_management': {'client_secret': 'synthetic'}}, base)
        assert calls == [['synthetic-cli', 'gateway', 'login', 'identity-demo-runtime']]
    assert metadata.read_bytes() == original


def test_profile_roundtrip_and_derived_endpoints() -> None:
    """Namespaces, routes and identities derive from one validated profile."""
    value = {**LEGACY.to_dict(), "core_namespace": "customer-eval", "owner": "demo-team"}
    profile = DeploymentProfile.from_dict(value)
    assert profile.origin("fixture-keycloak") == (
        "https://fixture-keycloak-customer-eval." + profile.route_domain)
    assert profile.service_host("fixture-mcp-bound") == "fixture-mcp-bound.customer-eval.svc.cluster.local"
    assert profile.namespace_for("reader") == profile.reader_namespace
    assert profile.labels["identity-demo-owner"] == "demo-team"
    assert profile.to_dict() == value


def test_parallel_gateway_identity_and_registration_do_not_collide() -> None:
    """A new installation never reuses the reference gateway's SPIFFE subject."""
    fresh = DeploymentProfile.from_dict({**LEGACY.to_dict(), "installation_id": "fresh-test"})
    assert fresh.gateway_id != LEGACY.gateway_id
    assert fresh.gateway_registration_name != LEGACY.gateway_registration_name


def test_native_provider_endpoint_matches_compiled_sender_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    """A public issuer and the internal mTLS token destination are distinct."""
    import probe_native_exchange as native
    profile = DeploymentProfile.from_dict({**LEGACY.to_dict(), 'core_namespace': 'new-core'})
    monkeypatch.setattr(native, 'active_profile', lambda: profile)
    assert native.provider_token_endpoint('https://public-issuer.invalid/realms/demo', True) == (
        profile.native_build_contract['OPENSHELL_DEMO_TOKEN_ENDPOINT'])
    assert native.provider_token_endpoint('https://public-issuer.invalid/realms/demo', False) == (
        'https://public-issuer.invalid/realms/demo/protocol/openid-connect/token')


@pytest.mark.parametrize("field,value", [
    ("core_namespace", "openshift-operators"), ("core_namespace", "default"),
    ("core_namespace", "wild.card"), ("core_namespace", "../identity-demo"),
    ("reader_namespace", LEGACY.triage_namespace), ("expected_server", "http://api.example.org"),
    ("expected_server", "https://user:password@api.example.org"),
    ("expected_server", "https://api.example.org?token=secret"),
    ("expected_server", "https://api.example.org\\@other.example.org"),
    ("trust_domain", "*.example.org"), ("owner", "bad owner"),
    ("installation_id", "../demo"), ("schema_version", True),
])
def test_invalid_profile_refused(field: str, value: object) -> None:
    """Ambiguous URLs and namespaces cannot expand the installation scope."""
    with pytest.raises((ValueError, TypeError)):
        DeploymentProfile.from_dict({**LEGACY.to_dict(), field: value})


def test_profile_rejects_unknown_missing_and_duplicate_fields(tmp_path: Path) -> None:
    """Typos and duplicate JSON fields must not silently change configuration."""
    with pytest.raises(ValueError):
        DeploymentProfile.from_dict({**LEGACY.to_dict(), "secret": "not-allowed"})
    path = tmp_path / "profile.json"
    text = json.dumps(LEGACY.to_dict())
    path.write_text(text[:-1] + ',"owner":"someone-else"}')
    path.chmod(0o600)
    with pytest.raises(ValueError):
        read_profile(str(path))


def test_profile_file_permissions_and_limits(tmp_path: Path) -> None:
    """Configuration can be read-only mounted but must not be publicly writable."""
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(LEGACY.to_dict()))
    path.chmod(0o444)
    assert read_profile(str(path)) == LEGACY
    path.chmod(0o666)
    with pytest.raises(ValueError):
        read_profile(str(path))


@pytest.mark.parametrize('workspace', ['default', LEGACY.triage_namespace, LEGACY.reader_namespace])
def test_native_management_selector_uses_owned_workspace(workspace: str) -> None:
    """The pinned protobuf selector must encode the selected namespace exactly."""
    from probe_runtime_management import list_message
    encoded = workspace.encode('ascii')
    assert list_message(workspace) == b'\x22' + bytes([len(encoded) + 2]) + b'\x0a' + bytes([len(encoded)]) + encoded
    with pytest.raises(ValueError, match='Owned configured workspace'):
        list_message('someone-elses-project')


def test_runtime_components_use_explicit_profile_together(tmp_path: Path) -> None:
    """A fresh process must derive both sides of each trusted integration equally."""
    value = {**LEGACY.to_dict(), "installation_id": "portable-check", "owner": "test-owner",
             "core_namespace": "portable-core", "triage_namespace": "portable-triage",
             "reader_namespace": "portable-reader", "identity_namespace": "portable-spire",
             "route_domain": "apps.example.org", "trust_domain": "agents.example.org"}
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    program = '''import json
import identity_demo_jira_action_adapter as adapter
import identity_demo_action_policy as policy
import identity_demo_workspaces as workspaces
import identity_demo_spire_network as spire
import identity_demo_step4_isolation as isolation
import identity_demo_execution_setup as execution
import sender_listener as listener
import gateway_credential_route as route
import execution_context as context
import concurrency_flow as concurrency
import probe_native_identity as identity
from argparse import Namespace
from contextlib import nullcontext
from types import SimpleNamespace
import identity_demo_fixture_http as components
import identity_demo_runtime as runtime
import identity_demo_offline_inventory as offline
import probe_runtime_management as management
from deployment_profile import active_profile
assert isolation.SUPERVISOR['openshell.ai/gateway-id'] == 'fixture-portable-check'
assert isolation.policies()[0]['spec']['ingress'][0]['from'][0]['podSelector']['matchLabels'] == isolation.SUPERVISOR
assert runtime.owned_identity({'attributes':{'identity-demo-owner':'test-owner'}})
assert not runtime.owned_identity({'attributes':{'identity-demo-owner':'demo-team'}})
assert offline.NAMESPACES == ('portable-core','portable-triage','portable-reader','portable-spire')
assert management.list_message('portable-triage').endswith(b'portable-triage')
try:
    management.list_message('default')
except ValueError:
    pass
else:
    raise AssertionError('Legacy workspace accepted for a different installation')
components.KEYCLOAK = active_profile().origin('fixture-keycloak-upstream')
opener = SimpleNamespace(open=lambda *a, **k: nullcontext(
    SimpleNamespace(status=200, headers={}, read=lambda n:b'{}')))
assert components.request(components.KEYCLOAK + '/realms/identity-demo',opener=opener)[0] == 200
try:
    components.request('https://fixture-keycloak-upstream-demo-core.apps.example.org',opener=opener)
except ValueError:
    pass
else:
    raise AssertionError('Legacy issuer route accepted for a different installation')
identity.command = lambda *args: spire.SERVER
try:
    identity.probe(Namespace(kubeconfig='synthetic', namespace='demo-core'))
except ValueError as error:
    assert str(error) == 'Exact owned native namespace required'
else:
    raise AssertionError('Legacy namespace accepted for a different installation')
print(json.dumps([adapter.DRIVER,adapter.JIRA,policy.DRIVER,workspaces.PLATFORM,
    list(workspaces.WORKSPACES),spire.NAMESPACE,listener.HOST,route.ADAPTER,
    context.DOMAIN,execution.context_template('triage','a').namespace,
    concurrency.RESOURCE]))'''
    root = Path(__file__).resolve().parents[3]
    env = {**os.environ, "IDENTITY_DEMO_CONFIG": str(path),
           "PYTHONPATH": os.pathsep.join(str(root / p) for p in ("runtime", "runtime/identity_demo", "scripts/identity_demo", "tests/identity_demo"))}
    result = subprocess.run([sys.executable, "-c", program], env=env,
                            text=True, capture_output=True, timeout=15, check=True)
    values = json.loads(result.stdout)
    assert values == [
        "https://fixture-identity-driver.portable-core.svc.cluster.local:8443",
        "https://fixture-jira.portable-core.svc.cluster.local:8080",
        "https://fixture-identity-driver-portable-core.apps.example.org",
        "portable-core", ["portable-triage", "portable-reader"], "portable-spire",
        "fixture-mcp-bound.portable-core.svc.cluster.local",
        "fixture-protected-adapter.portable-core.svc.cluster.local",
        "agents.example.org", "portable-triage",
        "https://fixture-mcp-bound.portable-core.svc.cluster.local/mcp"]


@pytest.mark.parametrize("git_marker", ["directory", "file"])
def test_private_paths_cover_parent_checkout(tmp_path: Path, git_marker: str) -> None:
    """A nested example must not accept private files elsewhere in its checkout."""
    from deployment_profile import in_source_checkout
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    marker = checkout / ".git"
    if git_marker == "directory":
        marker.mkdir()
    else:
        marker.write_text("gitdir: /synthetic/worktree-metadata")
    source = checkout / "examples/demo"
    source.mkdir(parents=True)
    assert in_source_checkout(checkout / "private/new-key", source)
    assert in_source_checkout(source / "generated/key", source)
    assert not in_source_checkout(tmp_path / "private/new-key", source)


def test_private_paths_cover_source_archive_without_git(tmp_path: Path) -> None:
    from deployment_profile import in_source_checkout
    source = tmp_path / "source"
    source.mkdir()
    assert in_source_checkout(source / "private/key", source)
    assert not in_source_checkout(tmp_path / "private/key", source)


@pytest.mark.parametrize("name", [
    "probe_adapter_tls.py", "probe_gateway_denials.py",
    "probe_native_interop.py", "probe_protected_adapter.py",
])
def test_standalone_probe_cli_does_not_require_operator_imports(name: str) -> None:
    """Pod probes and their help entry points must not import checkout-only helpers."""
    root = Path(__file__).resolve().parents[3]
    folder = "runtime/identity_demo" if name in ("probe_adapter_tls.py", "probe_protected_adapter.py") else "tests/identity_demo"
    source = root / folder / name
    env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    result = subprocess.run([sys.executable, str(source), "--help"], env=env,
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
