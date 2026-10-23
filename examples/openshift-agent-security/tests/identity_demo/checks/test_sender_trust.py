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

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts" / "identity_demo"))
from identity_demo_sender_trust import certificates, patch  # noqa: E402


def certificate(ca: bool) -> str:
    """Make a synthetic certificate without using any live key material."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test")])
    now = datetime.now(timezone.utc)
    value = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
             .public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
             .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
             .sign(key, hashes.SHA256()))
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
    before = {"metadata": {"uid": "owned", "resourceVersion": "12"},
              "data": {"password": "unchanged", "truststore.p12": "old"}}
    after = dict(before["data"], **{"truststore.p12": "new"})
    changes = patch(before, "data", after)
    assert changes[:3] == [
        {"op": "test", "path": "/metadata/uid", "value": "owned"},
        {"op": "test", "path": "/metadata/resourceVersion", "value": "12"},
        {"op": "test", "path": "/data", "value": before["data"]},
    ]
    assert changes[-1]["value"]["password"] == before["data"]["password"]
