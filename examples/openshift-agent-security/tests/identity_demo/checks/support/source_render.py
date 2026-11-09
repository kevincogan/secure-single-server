# SPDX-License-Identifier: Apache-2.0
"""Shared source render test setup; contains no collected tests."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import pytest
from deployment_profile import DeploymentProfile, LEGACY
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
                         ("service_ca", "upstream_ca_bundle")},
        "kubernetes_api_cidrs": ["192.0.2.1/32"]}))
    return path
