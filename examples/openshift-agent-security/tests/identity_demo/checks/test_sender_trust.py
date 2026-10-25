# SPDX-License-Identifier: Apache-2.0
"""Offline guards for public client-trust reconciliation; live TLS is separate."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import pytest

sys.path.insert(
    0, str(Path(__file__).resolve().parents[3] / "scripts" / "identity_demo")
)
from identity_demo_sender_trust import certificates, patch  # noqa: E402


def certificate(ca: bool) -> str:
    """Make a synthetic certificate without using any live key material."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test")])
    now = datetime.now(timezone.utc)
    value = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return value.public_bytes(serialization.Encoding.PEM).decode()


def test_trust_accepts_multiple_public_roots_for_rotation_overlap() -> None:
    """A current and next CA may both remain trusted during supported overlap."""
    assert len(certificates(certificate(True) + certificate(True))) == 2


@pytest.mark.parametrize("value", ["", "not-pem"])
def test_trust_refuses_missing_or_malformed_bundle(value: str) -> None:
    """No fallback to optional client authentication or empty trust exists."""
    with pytest.raises(ValueError):
        certificates(value)


def test_trust_refuses_leaf_certificate() -> None:
    """A public workload certificate cannot become a trust anchor."""
    with pytest.raises(ValueError, match="leaf"):
        certificates(certificate(False))


def test_trust_refuses_duplicate_roots() -> None:
    """Ambiguous or accidentally repeated distribution inputs are rejected."""
    pem = certificate(True)
    with pytest.raises(ValueError, match="Duplicate"):
        certificates(pem + pem)


def test_reconciliation_has_exact_object_and_field_preconditions() -> None:
    """Concurrent edits cannot be overwritten by a previously prepared refresh."""
    before = {
        "metadata": {"uid": "owned", "resourceVersion": "12"},
        "data": {"password": "unchanged", "truststore.p12": "old"},
    }
    after = dict(before["data"], **{"truststore.p12": "new"})
    changes = patch(before, "data", after)
    assert changes[:3] == [
        {"op": "test", "path": "/metadata/uid", "value": "owned"},
        {"op": "test", "path": "/metadata/resourceVersion", "value": "12"},
        {"op": "test", "path": "/data", "value": before["data"]},
    ]
    assert changes[-1]["value"]["password"] == before["data"]["password"]


def test_refresh_refuses_nonidle_installation_before_reading_or_writing_trust(
    tmp_path, monkeypatch
):
    from argparse import Namespace
    import identity_demo_sender_trust as trust
    import identity_demo_execution_setup as execution

    monkeypatch.setattr(trust, "guard", lambda args: None)
    monkeypatch.setattr(
        execution, "inspect_state", lambda args: {"rollback_quiescent": False}
    )
    monkeypatch.setattr(
        trust, "command", lambda *args, **kwargs: pytest.fail("nonidle trust access")
    )
    tmp_path.chmod(0o700)
    with pytest.raises(ValueError, match="verified idle"):
        trust.refresh(
            Namespace(expected_server=trust.SERVER, output_dir=tmp_path, apply=True)
        )


def test_bootstrap_refresh_reads_operator_bundle_without_spire_exec(
    tmp_path, monkeypatch
):
    from argparse import Namespace
    import base64
    import json
    from cryptography.hazmat.primitives.serialization import pkcs12
    import identity_demo_sender_trust as trust
    import identity_demo_execution_setup as execution

    pem = certificate(True)
    root = x509.load_pem_x509_certificate(pem.encode())
    password = b"synthetic-public-store"
    store = pkcs12.serialize_java_truststore(
        [pkcs12.PKCS12Certificate(root, b"test")],
        serialization.BestAvailableEncryption(password),
    )

    def metadata(name, namespace=trust.NAMESPACE):
        return {
            "name": name,
            "namespace": namespace,
            "uid": name + "-uid",
            "resourceVersion": "1",
            "labels": dict(trust.LABELS),
        }

    issuer = {
        "metadata": metadata(trust.ISSUER),
        "spec": {
            "replicas": 1,
            "strategy": {"type": "Recreate"},
            "template": {
                "spec": {
                    "containers": [{"image": trust.IMAGE}],
                    "volumes": [
                        {"persistentVolumeClaim": {"claimName": trust.ISSUER + "-data"}}
                    ],
                }
            },
        },
    }
    source = {
        "metadata": metadata("spire-bundle", trust.SPIRE_NAMESPACE),
        "data": {"bundle.crt": pem},
    }
    source["metadata"]["labels"]["app.kubernetes.io/managed-by"] = (
        "zero-trust-workload-identity-manager"
    )
    source["metadata"]["ownerReferences"] = [
        {"kind": "SpireServer", "name": "cluster", "uid": "approved-server"}
    ]
    truststore = {
        "metadata": metadata(trust.ISSUER + "-client-trust"),
        "data": {
            "password": base64.b64encode(password).decode(),
            "truststore.p12": base64.b64encode(store).decode(),
        },
    }
    listener = {
        "metadata": metadata("fixture-mcp-bound-mutual"),
        "data": {"ca.crt": base64.b64encode(pem.encode()).decode()},
    }
    calls = []

    def command(args, *words, **kwargs):
        calls.append(words)
        assert words[0] in ("get", "patch")  # No exec, registrations or SPIRE mutation.
        if words[:2] == ("get", "namespace"):
            return json.dumps({"metadata": {"labels": dict(trust.LABELS)}})
        if words[:2] == ("get", "configmap"):
            return json.dumps(source)
        if words[:2] == ("get", "deployment"):
            return json.dumps(issuer)
        if words[:3] == ("get", "secret", trust.ISSUER + "-client-trust"):
            return json.dumps(truststore)
        if words[:3] == ("get", "secret", "fixture-mcp-bound-mutual"):
            return json.dumps(listener)
        assert words[:3] == ("patch", "deployment", trust.ISSUER)
        return "{}"

    monkeypatch.setattr(trust, "guard", lambda args: None)
    monkeypatch.setattr(trust, "command", command)
    monkeypatch.setattr(
        execution, "inspect_state", lambda args: {"rollback_quiescent": True}
    )
    tmp_path.chmod(0o700)
    result = trust.refresh(
        Namespace(expected_server=trust.SERVER, output_dir=tmp_path, apply=True)
    )
    assert result["applied"] and result["tls_verification_preserved"]
    assert any(q[:3] == ("get", "configmap", "spire-bundle") for q in calls)
