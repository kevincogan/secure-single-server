# SPDX-License-Identifier: Apache-2.0
"""Render the evaluation application from versioned source and fresh private state.

This module performs no network or cluster operation. Trust is supplied explicitly
after platform preparation. A rendered bundle is not evidence of installation,
support, provenance, disconnected operation or functional acceptance.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
from ipaddress import ip_address, ip_network
import json
from pathlib import Path
import re
import secrets
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from deployment_profile import DeploymentProfile
from deployment_artifacts import IMAGE_ROLES as IMAGE_ROLES, validate_artifacts

ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = ROOT / "infra/identity-demo/templates"
TOKENS = re.compile(r"\$\{([a-zA-Z0-9_.-]+)\}")


def encoded(value: str | bytes) -> str:
    """Encode Kubernetes Secret bytes without writing an intermediate file."""
    return base64.b64encode(value.encode() if isinstance(value, str) else value).decode()


def canonical_hash(value: object) -> str:
    """Bind generated keys and immutable installation inputs to their profile."""
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def read_json(path: Path) -> dict:
    """Bound local JSON and reject duplicate fields instead of accepting overrides."""
    if not path.is_file() or path.stat().st_size > 4_000_000:
        raise ValueError("Bounded JSON input required")
    def pairs(values: list[tuple]) -> dict:
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("Duplicate configuration field")
            result[key] = value
        return result
    result = json.loads(path.read_text(), object_pairs_hook=pairs)
    if not isinstance(result, dict):
        raise ValueError("JSON object required")
    return result


def certificate_bundle(path: Path) -> str:
    """Accept explicit bounded public CA certificates, never private key material."""
    if not path.is_file() or path.stat().st_size > 1_000_000:
        raise ValueError("Bounded public CA file required")
    data = path.read_bytes()
    if b"PRIVATE KEY" in data or not data.strip():
        raise ValueError("Public certificates only")
    certificates = x509.load_pem_x509_certificates(data)
    if not certificates:
        raise ValueError("CA certificates required")
    current = []
    now = datetime.now(timezone.utc)
    for cert in certificates:
        if not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError("CA trust anchor required")
        # SPIRE bundles can retain expired rollover roots. A fresh installation
        # uses current anchors only; existing deployments are never changed here.
        if cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
            current.append(cert)
    if not current:
        raise ValueError("At least one currently valid CA trust anchor required")
    return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in current).decode()


def load_inputs(path: Path) -> tuple[DeploymentProfile, dict, dict, list[str]]:
    """Validate the exact source-render configuration before generating secrets."""
    config = read_json(path)
    required = {"schema_version", "profile", "artifacts_file", "public_trust", "kubernetes_api_cidrs"}
    if (not required <= set(config) or set(config) - required - {"ingress_cluster_ip", "certificate_management"}
            or type(config["schema_version"]) is not int or config["schema_version"] != 1):
        raise ValueError("Exact render configuration schema required")
    if config.get('ingress_cluster_ip') is not None:
        address = ip_address(config['ingress_cluster_ip'])
        if address.is_unspecified or address.is_loopback or address.is_multicast:
            raise ValueError('Explicit unicast retained ingress Service address required')
    profile = DeploymentProfile.from_dict(config["profile"])
    from managed_certificates import configuration
    configuration(config)
    if any(len(name) > 19 for name in profile.application_namespaces[1:]):
        raise ValueError("Native workspace names must be at most 19 characters")
    artifact_path = Path(config["artifacts_file"])
    if not artifact_path.is_absolute():
        raise ValueError("Absolute artifacts file required")
    artifacts = validate_artifacts(read_json(artifact_path))
    trust = config["public_trust"]
    if not isinstance(trust, dict) or set(trust) != {"service_ca", "spire_ca", "upstream_ca_bundle"}:
        raise ValueError("Exact public-trust inputs required")
    certificates = {}
    for name, filename in trust.items():
        source = Path(filename)
        if not source.is_absolute():
            raise ValueError("Absolute public-trust file required")
        certificates[name] = certificate_bundle(source)
    cidrs = config["kubernetes_api_cidrs"]
    if not isinstance(cidrs, list) or not 1 <= len(cidrs) <= 16:
        raise ValueError("Bounded explicit API endpoint CIDRs required")
    for cidr in cidrs:
        if not isinstance(cidr, str):
            raise ValueError("Canonical API endpoint CIDR required")
        network = ip_network(cidr, strict=True)
        if str(network) != cidr or network.prefixlen != network.max_prefixlen:
            raise ValueError("Exact API host routes required, never broad network access")
    return profile, artifacts, certificates, cidrs


def native_build_contract(profile: DeploymentProfile) -> dict:
    """Return the exact endpoint/domain inputs required by the native sender build."""
    return profile.native_build_contract


def _key_bytes(key: object) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _ca() -> tuple:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Identity evaluation application CA")])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256()))
    return key, certificate


def _leaf(ca_key: object, ca: x509.Certificate, names: list[str], *, client: bool = False) -> tuple:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "openshell-client" if client else names[0])]))
        .issuer_name(ca.subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, None, None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key()), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH]), critical=True))
    if names:
        alternative_names = []
        for name in names:
            try:
                alternative_names.append(x509.IPAddress(ip_address(name)))
            except ValueError:
                alternative_names.append(x509.DNSName(name))
        builder = builder.add_extension(x509.SubjectAlternativeName(alternative_names), critical=False)
    cert = builder.sign(ca_key, hashes.SHA256())
    return _key_bytes(key), cert.public_bytes(serialization.Encoding.PEM)


def initial_state(profile: DeploymentProfile, trust: dict, certificate_config: dict | None = None,
                  application_ca: str | None = None) -> dict:
    """Generate independent keys/credentials; never seed from the old installation."""
    templates = list(TEMPLATES.glob("*-realm.json"))
    tokens = set()
    for source in templates:
        tokens.update(TOKENS.findall(source.read_text()))
    values = {name: str(uuid4()) if name.startswith("id.") else secrets.token_urlsafe(32)
              for name in tokens if name.startswith(("id.", "credential.", "client_secret."))}
    for name in ("keycloak_admin", "jira_admin"):
        values["credential." + name] = secrets.token_urlsafe(32)
    contract = certificate_config or {'mode': 'legacy'}
    managed = contract['mode'] == 'managed'
    if managed:
        from managed_certificates import roots
        roots(application_ca)
        ca_pem = application_ca.encode()
    else:
        ca_key, ca = _ca()
        ca_pem = ca.public_bytes(serialization.Encoding.PEM)
    secret_data = {}
    def put(name: str, key: str, value: str | bytes) -> None:
        secret_data[name + "/" + key] = encoded(value)
    for name, client, hosts in (
        ("fixture-openshell-server-tls", False, ["fixture-openshell", "localhost", "127.0.0.1", "::1", "fixture-openshell.localhost",
            "fixture-openshell." + profile.core_namespace + ".svc", profile.service_host("fixture-openshell")]),
        ("fixture-openshell-client-tls", True, []),
        ("fixture-mcp-bound-mutual", False, ["fixture-mcp-bound." + profile.core_namespace + ".svc", profile.service_host("fixture-mcp-bound")]),
    ):
        if managed:
            continue  # Issuance and private-key generation belong to the approved controller.
        key, cert = _leaf(ca_key, ca, hosts, client=client)
        put(name, "tls.key", key)
        put(name, "tls.crt", cert)
        put(name, "ca.crt", trust["spire_ca"] if name == "fixture-mcp-bound-mutual" else ca_pem)
    signing = ed25519.Ed25519PrivateKey.generate()
    put("fixture-openshell-jwt-keys", "signing.pem", _key_bytes(signing))
    put("fixture-openshell-jwt-keys", "public.pem", signing.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    put("fixture-openshell-jwt-keys", "kid", uuid4().hex)
    put("fixture-openshell-credential-storage-key-encryption-key", "key-encryption-key", encoded(secrets.token_bytes(32)))
    for name in ("gateway_secret", "operator_secret", "adapter_secret"):
        put("fixture-identity-driver-credentials", name, secrets.token_urlsafe(32))
    put("fixture-adapter-catalog-trust-v1", "digests.json", "{}")
    for name, credential in (("keycloak-admin", "keycloak_admin"), ("jira-admin", "jira_admin")):
        put("fixture-credentials", name, values["credential." + credential])
    password = secrets.token_urlsafe(32)
    public_certs = [pkcs12.PKCS12Certificate(c, b"spire-" + str(i).encode())
                    for i, c in enumerate(x509.load_pem_x509_certificates(trust["spire_ca"].encode()))]
    store = pkcs12.serialize_java_truststore(public_certs, serialization.BestAvailableEncryption(password.encode()))
    put("fixture-keycloak-upstream-client-trust", "password", password)
    put("fixture-keycloak-upstream-client-trust", "truststore.p12", store)
    return {"schema_version": 1, "profile_sha256": canonical_hash(profile.to_dict()),
            "trust_sha256": canonical_hash(trust),
            "certificate_management": contract,
            "values": values, "secret_data": secret_data, "application_ca": ca_pem.decode(),
            **({} if managed else {"application_ca_key": _key_bytes(ca_key).decode()}),
            "created_at": datetime.now(timezone.utc).isoformat(), "leaf_validity_days": 30}


def validate_state(state: dict, profile: DeploymentProfile, trust: dict,
                   certificate_config: dict | None = None, application_ca: str | None = None) -> None:
    """Reject wrong installation, stale trust, damaged keys and expired TLS state."""
    if state.get("schema_version") != 1 or state.get("profile_sha256") != canonical_hash(profile.to_dict()):
        raise ValueError("Private key state belongs to a different installation")
    if state.get("trust_sha256") != canonical_hash(trust):
        raise ValueError("Trust changed; explicit trust rotation is required before rendering")
    contract = certificate_config or {'mode': 'legacy'}
    if state.get('certificate_management', {'mode': 'legacy'}) != contract:
        raise ValueError('Certificate mode/issuer changed; explicit migration required')
    if contract['mode'] == 'managed':
        from managed_certificates import roots, SECRETS
        roots(state['application_ca'])
        if (state['application_ca'] != application_ca or 'application_ca_key' in state
                or any(name.split('/')[0] in SECRETS for name in state['secret_data'])):
            raise ValueError('Managed state must retain public trust only, never generated TLS keys')
        return
    ca = x509.load_pem_x509_certificate(state["application_ca"].encode())
    ca_key = serialization.load_pem_private_key(state["application_ca_key"].encode(), None)
    now = datetime.now(timezone.utc)
    def public(key: object) -> bytes:
        return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if (public(ca.public_key()) != public(ca_key.public_key())
            or not ca.not_valid_before_utc <= now < ca.not_valid_after_utc):
        raise ValueError("Usable application CA state required")
    ski = ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    if ski != x509.SubjectKeyIdentifier.from_public_key(ca.public_key()):
        raise ValueError("Application CA key identifier mismatch")
    for name in ("fixture-openshell-server-tls", "fixture-openshell-client-tls", "fixture-mcp-bound-mutual"):
        data = state["secret_data"]
        cert = x509.load_pem_x509_certificate(base64.b64decode(data[name + "/tls.crt"], validate=True))
        key = serialization.load_pem_private_key(base64.b64decode(data[name + "/tls.key"], validate=True), None)
        cert.verify_directly_issued_by(ca)
        aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
        if aki != x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key()):
            raise ValueError("Application TLS issuer key identifier mismatch")
        if (public(cert.public_key()) != public(key.public_key())
                or not cert.not_valid_before_utc <= now < cert.not_valid_after_utc):
            raise ValueError("Usable application TLS state required; explicit rotation required")


def render(config_file: Path, state: dict | None = None) -> tuple[dict, dict, dict]:
    """Produce a complete private application bundle from checked-in templates."""
    profile, artifacts, trust, cidrs = load_inputs(config_file)
    from managed_certificates import configuration, resources, public_trust, openshell_trust, SECRETS, SPIRE_TRUST
    config = read_json(config_file)
    contract, application_ca = configuration(config)
    ingress = config.get('ingress_cluster_ip')
    state = initial_state(profile, trust, contract, application_ca) if state is None else state
    validate_state(state, profile, trust, contract, application_ca)
    values = {**profile.to_dict(), "gateway_id": profile.gateway_id, "ingress_cluster_ip": ingress or "", **state["values"], **trust,
              **{"image." + k: v for k, v in artifacts["images"].items()}}
    # SPIRE client-auth roots belong to the issuer/listener trust stores. They
    # are not HTTPS server roots for the supervisor's DNS-verified destinations.
    values["runtime_ca_bundle"] = trust["upstream_ca_bundle"] + trust["service_ca"] + state["application_ca"]
    native_ca_sha256 = hashlib.sha256(values["runtime_ca_bundle"].encode()).hexdigest()
    pins = {}
    def substitute(text: str) -> str:
        def replace(match: re.Match) -> str:
            name = match.group(1)
            if name in values:
                return str(values[name])
            if name.startswith(("id.", "credential.", "client_secret.", "image.")):
                raise ValueError("Missing render variable")
            # Native Keycloak localisation/auth variables remain Keycloak inputs.
            return match.group(0)
        return TOKENS.sub(replace, text)
    def walk(value: object) -> object:
        if isinstance(value, dict):
            if set(value) == {"$source"}:
                name = value["$source"]
                source = ROOT / name
                if (not source.resolve().is_relative_to(ROOT) or source.suffix != ".py"
                        or not name.startswith(("scripts/identity_demo/", "tests/identity_demo/"))):
                    raise ValueError("Repository Python source required")
                data = source.read_bytes()
                pins[name] = hashlib.sha256(data).hexdigest()
                return data.decode()
            if set(value) == {"$secret"}:
                return state["secret_data"][value["$secret"]]
            if set(value) == {"$json"}:
                return json.dumps(walk(value["$json"]))
            if set(value) == {"$profile"}:
                return json.dumps(profile.to_dict())
            if set(value) == {"$api_peers"}:
                return [{"ipBlock": {"cidr": cidr}} for cidr in cidrs]
            return {k: walk(v) for k, v in value.items()}
        if isinstance(value, list):
            result = []
            for item in value:
                rendered = walk(item)
                if isinstance(item, dict) and set(item) == {"$api_peers"}:
                    result.extend(rendered)
                else:
                    result.append(rendered)
            return result
        return substitute(value) if isinstance(value, str) else value
    for name, secret_name in (("initial", "fixture-credentials"), ("management", "fixture-keycloak-recovery"),
                              ("exchange", "fixture-keycloak-upstream-realm")):
        state["secret_data"][secret_name + "/realm.json"] = encoded(json.dumps(walk(read_json(TEMPLATES / (name + "-realm.json")))))
    source = read_json(TEMPLATES / "application.json")
    selected = [o for o in source['objects'] if not (contract['mode'] == 'managed'
        and o['kind'] == 'Secret' and o['metadata']['name'] in SECRETS)]
    objects = walk(selected)
    if contract['mode'] == 'managed':
        objects = [openshell_trust(o) if o['kind'] == 'StatefulSet'
            and o['metadata']['name'] == 'fixture-openshell' else o for o in objects]
        objects.append(public_trust(profile, state['application_ca']))
    if contract['mode'] == 'managed':
        objects.extend(resources(profile, contract))
        objects.append({'apiVersion': 'v1', 'kind': 'Secret',
            'metadata': {'name': SPIRE_TRUST, 'namespace': profile.core_namespace,
                         'labels': dict(profile.labels)},
            'type': 'Opaque', 'data': {'ca.crt': encoded(trust['spire_ca'])}})
    if not ingress:
        # Offline native-contract rendering needs no captured router IP. The
        # connected installer resolves this retained prerequisite before install.
        for item in objects:
            if item['kind'] in ('Deployment','StatefulSet'):
                item['spec']['template']['spec'].pop('hostAliases', None)
    # The serving launcher is immutable. A source correction must produce a
    # new map/reference, rather than try to overwrite the historical map.
    for item in objects:
        if (item["kind"] == "ConfigMap" and item.get("immutable") is True
                and any(name in item.get("data", {}) for name in ("start_jira_fixture.py", "identity_demo_driver.py", "adapter_discovery.py"))):
            old_name = item["metadata"]["name"]
            prefix = ("fixture-identity-driver-code-" if "identity_demo_driver.py" in item["data"] else
                      "fixture-adapter-action-code-" if "adapter_discovery.py" in item["data"] else "fixture-jira-https-code-")
            new_name = prefix + canonical_hash(item["data"])[:10]
            item["metadata"]["name"] = new_name
            for workload in objects:
                if workload["kind"] in ("Deployment", "StatefulSet"):
                    for volume in workload["spec"]["template"]["spec"].get("volumes", []):
                        if volume.get("configMap", {}).get("name") == old_name:
                            volume["configMap"]["name"] = new_name
    for source_path in [*TEMPLATES.glob("*.json"), ROOT / "scripts/identity_demo/source_render.py",
                        ROOT / "scripts/identity_demo/deployment_profile.py",
                        ROOT / "scripts/identity_demo/managed_certificates.py",
                        ROOT / "scripts/identity_demo/deployment_artifacts.py"]:
        pins[str(source_path.relative_to(ROOT))] = hashlib.sha256(source_path.read_bytes()).hexdigest()
    bundle = {"schema_version": 2, "expected_server": profile.expected_server,
              "installation_profile": profile.to_dict(), "objects": objects, "source_pins": pins,
              "source_rendered": True, "fresh_driver_contexts": True,
              "certificate_management": contract,
              **({'certificate_authority_pem': state['application_ca']} if contract['mode'] == 'managed' else {}),
              "ingress_aliases_configured": bool(ingress), "database_contents_included": False,
              "shared_platform_reinstalled": False,
              "native_build_contract": native_build_contract(profile),
              "native_ca_bundle_pem": values["runtime_ca_bundle"],
              "native_ca_bundle_sha256": native_ca_sha256,
              "native_build_contract_matches": (
                  artifacts.get("native_build_contract") == native_build_contract(profile)
                  and artifacts.get("native_ca_bundle_sha256") == native_ca_sha256),
              "public_trust_sha256": {k: hashlib.sha256(v.encode()).hexdigest() for k, v in trust.items()}}
    credentials = {"namespace": profile.core_namespace, "keycloak_url": profile.origin("fixture-keycloak"),
                   "gateway_url": profile.origin("fixture-mcp") + "/mcp",
                   **{name: state["values"]["credential." + name] for name in ("keycloak_admin", "jira_admin", "analyst", "viewer")},
                   "realm_management_clients": {profile.origin(name): {
                       "client_id": "fixture-console-realm-coordinator",
                       "client_secret": state["values"]["client_secret." + realm + ".fixture-console-realm-coordinator"]}
                       for name, realm in (("fixture-keycloak", "management"), ("fixture-keycloak-upstream", "exchange"))},
                   "runtime_management": {"client_id": "fixture-runtime-operator", "audience": "identity-demo-runtime",
                       "client_secret": state["values"]["client_secret.management.fixture-runtime-operator"]},
                   "runtime_denial": {"client_id": "fixture-runtime-denied", "audience": "identity-demo-runtime",
                       "client_secret": state["values"]["client_secret.management.fixture-runtime-denied"]},
                   "management_adapter_clients": {name: state["values"]["client_secret.management." + name]
                                       for name in ("fixture-gateway-service", "fixture-other-service")},
                   "adapter_clients": {name: state["values"]["client_secret.exchange." + name]
                                       for name in ("fixture-gateway-service", "fixture-other-service")}}
    return bundle, state, credentials
