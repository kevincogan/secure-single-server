# SPDX-License-Identifier: Apache-2.0
"""Source packaging checks use synthetic trust and never contact the lab."""

from copy import deepcopy
import ast
from datetime import datetime, timedelta, timezone
import base64
import json
from pathlib import Path
import socket
import ssl
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import pytest

from deployment_profile import DeploymentProfile, LEGACY
import identity_demo_setup as setup
import source_render as renderer


def ca_file(path: Path, *, expired: bool = False) -> Path:
    """Create a synthetic, currently valid public CA without retaining its key."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic test CA")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=2))
            .not_valid_after(now + timedelta(days=-1 if expired else 1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(key, hashes.SHA256()))
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path


@pytest.fixture
def config(tmp_path: Path) -> Path:
    """Define a different installation, with every native contract input pinned."""
    profile = DeploymentProfile.from_dict({**LEGACY.to_dict(),
        "installation_id": "fresh-test", "owner": "test-owner",
        "expected_server": "https://api.test.example.org:6443",
        "core_namespace": "fresh-core", "identity_namespace": "fresh-identity",
        "triage_namespace": "fresh-triage", "reader_namespace": "fresh-reader",
        "route_domain": "apps.test.example.org", "trust_domain": "test.example.org",
        "cluster_name": "fresh-test", "storage_class": "test-csi"})
    artifacts = tmp_path / "artifacts.json"
    artifacts.write_text(json.dumps({"schema_version": 1,
        "images": {role: "registry.example/" + role + "@sha256:" + "a" * 64
                   for role in renderer.IMAGE_ROLES},
        "native_build_contract": renderer.native_build_contract(profile)}))
    trust = ca_file(tmp_path / "trust.pem")
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"schema_version": 1, "profile": profile.to_dict(),
        "artifacts_file": str(artifacts),
        "public_trust": {name: str(trust) for name in
                         ("service_ca", "spire_ca", "upstream_ca_bundle")},
        "kubernetes_api_cidrs": ["192.0.2.1/32"]}))
    return path


def test_render_from_source_is_complete_and_repeatable(config: Path) -> None:
    """A stable state preserves keys, IDs and configuration across render retries."""
    bundle, state, credentials = renderer.render(config)
    assert not bundle["native_build_contract_matches"]
    artifacts_path = Path(json.loads(config.read_text())["artifacts_file"])
    artifacts = json.loads(artifacts_path.read_text())
    artifacts["native_ca_bundle_sha256"] = bundle["native_ca_bundle_sha256"]
    artifacts_path.write_text(json.dumps(artifacts))
    bundle, state, credentials = renderer.render(config, state)
    assert len(setup.validate(bundle)) == len(bundle["objects"])
    second, second_state, second_credentials = renderer.render(config, deepcopy(state))
    assert second == bundle
    assert second_state == state
    assert second_credentials == credentials
    assert bundle["native_build_contract_matches"]
    assert not bundle["database_contents_included"]
    assert not bundle["shared_platform_reinstalled"]
    assert credentials["namespace"] == "fresh-core"
    assert credentials["analyst"] != credentials["viewer"]
    assert credentials["adapter_clients"]["fixture-gateway-service"] != (
        credentials["management_adapter_clients"]["fixture-gateway-service"])
    assert credentials["runtime_denial"]["client_id"] == "fixture-runtime-denied"
    certificate = x509.load_pem_x509_certificate(base64.b64decode(
        state["secret_data"]["fixture-openshell-server-tls/tls.crt"]))
    san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "127.0.0.1" in [str(value) for value in san.get_values_for_type(x509.IPAddress)]
    for item in bundle["objects"]:
        assert item["metadata"].get("namespace", item["metadata"]["name"]) in (
            "fresh-core", "fresh-triage", "fresh-reader")
        assert not item["metadata"].get("uid")
        assert not item["metadata"].get("resourceVersion")
        assert not (item['kind'] in ('Role', 'RoleBinding')
                    and item['metadata']['name'].startswith('identity-demo-pull-'))
        assert all(subject.get("kind") == "ServiceAccount"
                   for subject in item.get("subjects", []))


def test_managed_render_uses_platform_issuance_and_separate_spire_trust(config: Path) -> None:
    from uuid import uuid4
    import managed_certificates as managed
    authority = renderer._ca()[1].public_bytes(serialization.Encoding.PEM)
    path = config.parent/'application-ca.pem';path.write_bytes(authority)
    value = json.loads(config.read_text())
    value['certificate_management'] = {'mode':'managed','ca_file':str(path),'issuer_uid':str(uuid4()),
        'issuer_ref':{'kind':'Issuer','group':'cert-manager.io','name':'fixture-application-ca'}}
    config.write_text(json.dumps(value))
    bundle,state,_ = renderer.render(config)
    setup.validate(bundle)
    assert len([o for o in bundle['objects'] if o['kind']=='Certificate']) == 3
    assert not any(o['kind']=='Secret' and o['metadata']['name'] in managed.SECRETS for o in bundle['objects'])
    trust, = [o for o in bundle['objects'] if o['kind']=='Secret' and o['metadata']['name']==managed.SPIRE_TRUST]
    assert set(trust['data']) == {'ca.crt'}
    assert base64.b64decode(trust['data']['ca.crt']).decode() != authority.decode()
    assert 'application_ca_key' not in state
    gateway, = [o for o in bundle['objects'] if o['kind']=='StatefulSet']
    pod=gateway['spec']['template']['spec']
    volume, = [v for v in pod['volumes'] if v['name']=='tls-client-ca']
    assert volume['secret']['secretName'] == managed.APPLICATION_TRUST
    public, = [o for o in bundle['objects'] if o['kind']=='Secret' and o['metadata']['name']==managed.APPLICATION_TRUST]
    assert set(public['data']) == {'ca.crt'} and public['type']=='Opaque'
    assert base64.b64decode(public['data']['ca.crt']) == authority
    bad = deepcopy(bundle)
    next(o for o in bad['objects'] if o['kind']=='Certificate')['spec']['dnsNames'].append('unapproved.example')
    with pytest.raises(ValueError):setup.validate(bad)
    assert renderer.render(config,state)[0] == bundle


def test_jira_startup_uses_the_mounted_serving_certificate(config: Path) -> None:
    """The source launcher must actually enable TLS on the HTTPS service port."""
    bundle, _, _ = renderer.render(config)
    objects = bundle["objects"]
    deployment = next(o for o in objects if o["kind"] == "Deployment"
                      and o["metadata"]["name"] == "fixture-jira")
    pod = deployment["spec"]["template"]["spec"]
    container = pod["containers"][0]
    mount = next(m for m in container["volumeMounts"] if m["name"] == "rest-tls")
    volume = next(v for v in pod["volumes"] if v["name"] == "rest-tls")
    service = next(o for o in objects if o["kind"] == "Service"
                   and o["metadata"]["name"] == "fixture-jira")
    assert volume["secret"]["secretName"] == service["metadata"]["annotations"][
        "service.beta.openshift.io/serving-cert-secret-name"]
    code_map = next(o for o in objects if o["kind"] == "ConfigMap"
                    and "start_jira_fixture.py" in o.get("data", {}))
    assert code_map["metadata"]["name"] == (
        "fixture-jira-https-code-" + renderer.canonical_hash(code_map["data"])[:10])
    assert any(v.get("configMap", {}).get("name") == code_map["metadata"]["name"]
               for v in pod["volumes"])
    code = code_map["data"]["start_jira_fixture.py"]
    call = next(n for n in ast.walk(ast.parse(code)) if isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)
                and n.func.value.id == "uvicorn" and n.func.attr == "run")
    keywords = {k.arg: ast.literal_eval(k.value) for k in call.keywords}
    assert keywords["ssl_certfile"] == mount["mountPath"] + "/tls.crt"
    assert keywords["ssl_keyfile"] == mount["mountPath"] + "/tls.key"
    assert keywords["port"] == 8080


def test_fresh_state_never_reuses_keys_or_user_passwords(config: Path) -> None:
    """Separate cold installations cannot share generated trust or credentials."""
    _, first, credentials = renderer.render(config)
    _, second, other = renderer.render(config)
    assert first["application_ca_key"] != second["application_ca_key"]
    assert first["secret_data"] != second["secret_data"]
    assert credentials["analyst"] != other["analyst"]


def test_generated_chain_passes_strict_tls_and_hostname_validation(config: Path, tmp_path: Path) -> None:
    """Exercise the generated chain with Python's actual strict TLS client."""
    _, state, _ = renderer.render(config)
    cert, key, ca = (tmp_path / name for name in ('server.pem', 'server.key', 'ca.pem'))
    cert.write_bytes(base64.b64decode(state['secret_data']['fixture-openshell-server-tls/tls.crt']))
    key.write_bytes(base64.b64decode(state['secret_data']['fixture-openshell-server-tls/tls.key']))
    key.chmod(0o600)
    ca.write_text(state['application_ca'])
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(str(cert), str(key))
    client = ssl.create_default_context(cafile=str(ca))
    client.verify_flags |= ssl.VERIFY_X509_STRICT
    failures = []
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(3)
        def serve() -> None:
            try:
                with listener.accept()[0] as raw, server.wrap_socket(raw, server_side=True) as tls:
                    tls.sendall(b'OK')
            except Exception as error:
                failures.append(type(error).__name__)
        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        with socket.create_connection(listener.getsockname(), timeout=3) as raw:
            with client.wrap_socket(raw, server_hostname='127.0.0.1') as tls:
                assert tls.recv(2) == b'OK'
        worker.join(timeout=4)
        assert not worker.is_alive() and not failures


def test_damaged_tls_state_is_rejected(config: Path) -> None:
    """A corrupt saved key cannot be packaged as an apparently usable install."""
    _, state, _ = renderer.render(config)
    key = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    state["secret_data"]["fixture-openshell-server-tls/tls.key"] = base64.b64encode(key).decode()
    with pytest.raises(ValueError, match="TLS state"):
        renderer.render(config, state)


@pytest.mark.parametrize("change", ["profile", "trust"])
def test_state_refuses_cross_installation_or_silent_trust_change(config: Path,
                                                               change: str) -> None:
    """A rerender cannot silently retain keys under a new identity or trust root."""
    _, state, _ = renderer.render(config)
    value = json.loads(config.read_text())
    if change == "profile":
        value["profile"]["trust_domain"] = "other.example.org"
    else:
        value["public_trust"]["spire_ca"] = str(ca_file(config.parent / "other.pem"))
    config.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        renderer.render(config, state)


@pytest.mark.parametrize("cidrs", [["0.0.0.0/0"], ["192.0.2.0/24"], [], ["::/0"]])
def test_api_egress_never_expands_to_networks(config: Path, cidrs: list[str]) -> None:
    """Only explicit Kubernetes API endpoint host routes are allowed."""
    value = json.loads(config.read_text())
    value["kubernetes_api_cidrs"] = cidrs
    config.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        renderer.render(config)


def test_unbuilt_native_artifacts_are_visible(config: Path) -> None:
    """A plan can render before a build, without claiming install eligibility."""
    path = Path(json.loads(config.read_text())["artifacts_file"])
    value = json.loads(path.read_text())
    value.pop("native_build_contract")
    path.write_text(json.dumps(value))
    bundle, _, _ = renderer.render(config)
    assert not bundle["native_build_contract_matches"]


def test_source_installation_refuses_names_exceeding_native_workspace_limit(config: Path) -> None:
    """A valid Kubernetes namespace can still exceed the native API's limit."""
    value = json.loads(config.read_text())
    value['profile']['triage_namespace'] = 'workspace-is-too-long'
    config.write_text(json.dumps(value))
    with pytest.raises(ValueError, match='19 characters'):
        renderer.render(config)


def test_public_ca_input_rejects_private_material(config: Path) -> None:
    """Do not accidentally package an operator's CA signing key as public trust."""
    value = json.loads(config.read_text())
    path = Path(value["public_trust"]["spire_ca"])
    path.write_text(path.read_text() + "\n-----BEGIN PRIVATE KEY-----\n")
    with pytest.raises(ValueError, match="Public certificates only"):
        renderer.render(config)


def test_spire_rollover_bundle_selects_current_anchors(tmp_path: Path) -> None:
    """Expired retained roots do not prevent a fresh install with current roots."""
    current = ca_file(tmp_path / "current.pem").read_bytes()
    expired = ca_file(tmp_path / "expired.pem", expired=True).read_bytes()
    combined = tmp_path / "combined.pem"
    combined.write_bytes(expired + current)
    assert renderer.certificate_bundle(combined).encode() == current
    combined.write_bytes(expired)
    with pytest.raises(ValueError, match="currently valid"):
        renderer.certificate_bundle(combined)


def test_duplicate_input_fields_rejected(tmp_path: Path) -> None:
    """Configuration cannot conceal a second value behind JSON key overwriting."""
    path = tmp_path / "duplicate.json"
    path.write_text('{"owner":"first","owner":"second"}')
    with pytest.raises(ValueError, match="Duplicate"):
        renderer.read_json(path)


def test_rendered_driver_includes_every_local_import(config):
    """Fresh startup must not depend on support files from an older deployment."""
    bundle, _, _ = renderer.render(config)
    maps = [o for o in bundle["objects"] if o["kind"] == "ConfigMap"]
    code = next(o for o in maps if "identity_demo_driver.py" in o.get("data", {}))
    local = {p.stem for p in (renderer.ROOT / "scripts/identity_demo").glob("*.py")}
    data = code["data"]
    assert "identity_demo_console_visuals.py" in data
    for name, text in data.items():
        if not name.endswith(".py"):
            continue
        imports = set()
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, ast.Import):
                imports.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
        assert not {module for module in imports & local if module + ".py" not in data}
    assert code["metadata"]["name"] == "fixture-identity-driver-code-" + renderer.canonical_hash(data)[:10]
    deployment = next(o for o in bundle["objects"] if o["kind"] == "Deployment" and o["metadata"]["name"] == "fixture-identity-driver")
    assert next(v["configMap"]["name"] for v in deployment["spec"]["template"]["spec"]["volumes"] if v["name"] == "code") == code["metadata"]["name"]


def test_offline_render_never_retains_a_lab_router_address(config):
    bundle,state,_=renderer.render(config)
    assert bundle['ingress_aliases_configured'] is False
    assert all(not o['spec']['template']['spec'].get('hostAliases') for o in bundle['objects']
               if o['kind'] in ('Deployment','StatefulSet'))
    values=json.loads(config.read_text());values['ingress_cluster_ip']='192.0.2.77';config.write_text(json.dumps(values))
    configured,_,_=renderer.render(config,state)
    assert configured['native_ca_bundle_sha256']==bundle['native_ca_bundle_sha256']
    assert configured['ingress_aliases_configured'] is True
    aliases=[o['spec']['template']['spec']['hostAliases'] for o in configured['objects']
             if o['kind'] in ('Deployment','StatefulSet') and o['spec']['template']['spec'].get('hostAliases')]
    assert len(aliases)==2 and all(v[0]['ip']=='192.0.2.77' for v in aliases)


def test_driver_mounts_only_the_public_native_artifact_contract(config):
    raw=json.loads(config.read_text())
    path=Path(raw['artifacts_file']);artifacts=json.loads(path.read_text())
    artifacts['operator_note']='private-operator-metadata-must-not-be-mounted'
    path.write_text(json.dumps(artifacts))
    bundle,_,_=renderer.render(config)
    mapping=next(o for o in bundle['objects'] if o['kind']=='ConfigMap' and o['metadata']['name']=='identity-demo-installation')
    actual=json.loads(mapping['data']['artifacts.json'])
    assert set(actual)=={'schema_version','images','native_build_contract'}
    assert 'operator_note' not in actual
    driver=next(o for o in bundle['objects'] if o['kind']=='Deployment' and o['metadata']['name']=='fixture-identity-driver')
    container=driver['spec']['template']['spec']['containers'][0]
    assert {'name':'IDENTITY_DEMO_ARTIFACTS','value':'/configuration/artifacts.json'} in container['env']
    assert any(m.get('subPath')=='artifacts.json' and m.get('readOnly') for m in container['volumeMounts'])


def test_invalid_build_metadata_cannot_enter_the_public_artifact_mount(config):
    raw=json.loads(config.read_text());path=Path(raw['artifacts_file'])
    artifacts=json.loads(path.read_text())
    artifacts['native_build_contract']['unrecognized']='private-note'
    artifacts['native_ca_bundle_sha256']='not-a-public-hash'
    path.write_text(json.dumps(artifacts))
    bundle,_,_=renderer.render(config)
    assert not bundle['native_build_contract_matches']
    mapping=next(o for o in bundle['objects'] if o['kind']=='ConfigMap' and o['metadata']['name']=='identity-demo-installation')
    assert set(json.loads(mapping['data']['artifacts.json']))=={'schema_version','images'}



def test_workspace_only_gateway_cannot_manage_core_pods_or_secrets(config):
    value=json.loads(config.read_text());value['native_management_scope']='workspaces-only'
    config.write_text(json.dumps(value))
    bundle,_,_=renderer.render(config)
    profile=DeploymentProfile.from_dict(bundle['installation_profile'])
    assert bundle['native_management_scope']=='workspaces-only'
    assert not any(o['kind'] in ('Role','RoleBinding') and o['metadata'].get('namespace')==profile.core_namespace
                   and o['metadata']['name']=='fixture-openshell-sandbox' for o in bundle['objects'])
    assert len([o for o in bundle['objects'] if o['kind']=='RoleBinding' and o['metadata']['name']=='identity-demo-runtime'
                and o['metadata']['namespace'] in profile.application_namespaces[1:]])==2
    assert setup.runtime_rules(profile,bundle['objects'])
    assert any(o['kind']=='RoleBinding' and o['metadata']['name']=='identity-demo-workspace-ca'
               for o in bundle['objects'])
    assert any(o['kind']=='RoleBinding' and o['metadata']['name']=='fixture-openshell-peer'
               for o in bundle['objects'])


def test_unknown_native_management_scope_is_rejected(config):
    value=json.loads(config.read_text());value['native_management_scope']='unrestricted'
    config.write_text(json.dumps(value))
    with pytest.raises(ValueError,match='native management scope'):
        renderer.render(config)
