# SPDX-License-Identifier: Apache-2.0
"""The SPIRE CLI can return a key even when the requested evidence is public."""
import base64
from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

import probe_native_identity as identity


@pytest.mark.parametrize("outcome", ["valid", "no_identity", "malformed"])
def test_diagnostic_retains_only_public_evidence(tmp_path, monkeypatch, capsys, outcome):
    profile = identity.active_profile()
    spiffe_id = f"spiffe://{profile.trust_domain}/test"
    key_marker = "fixture-private-key-must-not-be-retained"
    error_marker = "fixture-sensitive-stderr-must-not-be-retained"
    now = datetime.now(timezone.utc)
    key = Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).serial_number(1)
            .public_key(key.public_key()).not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(minutes=1))
            .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]), False)
            .sign(key, None))
    der = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
    response = json.dumps({"svids": [{"spiffe_id": spiffe_id, "x509_svid": der,
                                      "bundle": der, "x509_svid_key": key_marker}]})

    def metadata(_kubeconfig, command, *args):
        if command == "config":
            return identity.SERVER
        return json.dumps({"metadata": {"labels": profile.labels, "uid": "test-pod"}})

    def run(command, **kwargs):
        if command[0] == "openssl":
            assert outcome == "valid"
            assert (tmp_path / "test.leaf.pem").read_bytes() == cert.public_bytes(serialization.Encoding.PEM)
            return SimpleNamespace(returncode=0)
        assert command[0] == "oc"
        return SimpleNamespace(returncode=int(outcome == "no_identity"),
                               stdout=key_marker if outcome == "malformed" else response,
                               stderr=f"no identity: {error_marker}")

    monkeypatch.setattr(identity, "command", metadata)
    monkeypatch.setattr(identity, "subprocess", SimpleNamespace(run=run))
    monkeypatch.setattr(identity.sys, "argv", ["probe_native_identity.py", "--kubeconfig", "fixture",
                        "--pod", "fixture-openshell-0", "--container", "openshell-gateway",
                        "--binary", "spire-agent", "--expected-spiffe-id", spiffe_id,
                        "--label", "test", "--output-dir", str(tmp_path)])
    with pytest.raises(SystemExit) as exit_result:
        identity.main()
    assert exit_result.value.code == int(outcome != "valid")
    captured = capsys.readouterr()
    assert key_marker not in captured.out + captured.err
    assert error_marker not in captured.out + captured.err
    summary = json.loads(captured.out)
    if outcome == "valid":
        assert summary["spiffe_id"] == spiffe_id and summary["chain_verified"]
        assert {path.name for path in tmp_path.iterdir()} == {
            "test.leaf.pem", "test.bundle.pem", "test.intermediates.pem", "test.public-summary.json"}
        assert json.loads((tmp_path / "test.public-summary.json").read_text()) == summary
        assert all(key_marker.encode() not in path.read_bytes() for path in tmp_path.iterdir())
    else:
        assert not summary["passed"] and not list(tmp_path.iterdir())
        assert summary.get("no_identity") if outcome == "no_identity" else summary.get("details_withheld")
