# SPDX-License-Identifier: Apache-2.0
"""Offline parsing guards for the bounded Step 4 subject diagnostic."""

from __future__ import annotations

import unittest
import pytest
import json
import time

from native_subject_boundary import (
    encode_string, subject_substitution_denied, token_from_response, verify_diagnostic_assertion,
)
from probe_native_exchange import PREFIX, require_native_provider_id


class NativeSubjectBoundaryTests(unittest.TestCase):
    """Keep malformed gRPC evidence from being counted as a successful grant."""

    def test_pinned_request_fields(self) -> None:
        """The assertion occupies field 4 in the released request schema."""
        self.assertEqual(encode_string(4, "svid"), b"\x22\x04svid")

    def test_multibyte_length(self) -> None:
        """JWT-sized fields require a protobuf varint length."""
        self.assertEqual(encode_string(4, "x" * 128)[:3], b"\x22\x80\x01")

    def test_response_with_duration_and_type(self) -> None:
        """Accept only the intermediate access-token field, preserving its value."""
        message = encode_string(1, "synthetic-token") + encode_string(102, "") + encode_string(3, "Bearer")
        data = b"\x00" + len(message).to_bytes(4, "big") + message
        self.assertEqual(token_from_response(data), "synthetic-token")




    def test_duplicate_token(self) -> None:
        """Ambiguous credential fields must fail rather than select the last."""
        message = encode_string(1, "first") + encode_string(1, "second")
        with self.assertRaises(ValueError):
            token_from_response(b"\x00" + len(message).to_bytes(4, "big") + message)

    def test_truncated_field(self) -> None:
        """A claimed protobuf length cannot extend beyond the response."""
        message = b"\x0a\x07short"
        with self.assertRaises(ValueError):
            token_from_response(b"\x00" + len(message).to_bytes(4, "big") + message)

    def test_recorded_cleanup_identity(self) -> None:
        """Only the exact recorded provider is eligible for cleanup."""
        value = {"name": PREFIX, "type": PREFIX, "id": "recorded-id"}
        self.assertEqual(require_native_provider_id([value], "recorded-id"), value)

    def test_replaced_provider_is_preserved(self) -> None:
        """Reusing a name does not transfer permission to delete its replacement."""
        with self.assertRaises(ValueError):
            require_native_provider_id([{"name": PREFIX, "type": PREFIX, "id": "new-id"}], "old-id")

    def test_missing_cleanup_ledger(self) -> None:
        """An ambiguous mutation requires inspection rather than automatic deletion."""
        with self.assertRaises(ValueError):
            require_native_provider_id([{"name": PREFIX, "type": PREFIX, "id": "new-id"}], None)

    def test_ambiguous_cleanup_identity(self) -> None:
        """Duplicate names cannot select a cleanup target."""
        value = {"name": PREFIX, "type": PREFIX, "id": "recorded-id"}
        with self.assertRaises(ValueError):
            require_native_provider_id([value, value], "recorded-id")

    def test_changed_provider_type(self) -> None:
        """Unexpected provider configuration must stop automatic cleanup."""
        with self.assertRaises(ValueError):
            require_native_provider_id([{"name": PREFIX, "type": "different", "id": "recorded-id"}], "recorded-id")


class SubjectDenialEvidenceTests(unittest.TestCase):
    """An outage or missing credential is insufficient evidence of binding."""

    def evidence(self) -> list[dict]:
        """Return synthetic observations for an explicit successful denial."""
        return [
            {"case": "correct_subject", "grpc_status": 0, "verified_intermediate_received": True},
            {"case": "same_domain_different_subject", "grpc_status": 7,
             "verified_intermediate_received": False, "response_message_present": False},
        ]

    def test_explicit_denial_and_positive_control(self) -> None:
        """A valid control and empty permission-denied reply pass this predicate."""
        self.assertTrue(subject_substitution_denied(self.evidence()))

    def test_other_rpc_failures_do_not_prove_binding(self) -> None:
        """Unavailable, invalid input or generic precondition errors do not pass."""
        for status in [0, 3, 9, 14, 16]:
            with self.subTest(status=status):
                value = self.evidence()
                value[1]["grpc_status"] = status
                self.assertFalse(subject_substitution_denied(value))

    def test_failed_control_does_not_prove_binding(self) -> None:
        """Denial of both subjects could just indicate a broken exchange path."""
        value = self.evidence()
        value[0]["verified_intermediate_received"] = False
        self.assertFalse(subject_substitution_denied(value))

    def test_reply_message_on_denial_fails(self) -> None:
        """An error code must not conceal a returned credential message."""
        value = self.evidence()
        value[1]["response_message_present"] = True
        self.assertFalse(subject_substitution_denied(value))

    def test_missing_reply_evidence_fails(self) -> None:
        """Absent response evidence is unproved, not an empty response."""
        value = self.evidence()
        del value[1]["response_message_present"]
        self.assertFalse(subject_substitution_denied(value))

    def test_incomplete_or_duplicate_case_sets_fail(self) -> None:
        """Do not infer a positive or negative control from repeated observations."""
        for value in [[], self.evidence()[:1], self.evidence() * 2,
                      [self.evidence()[0], self.evidence()[0]]]:
            self.assertFalse(subject_substitution_denied(value))


class DiagnosticAssertionVerificationTests(unittest.TestCase):
    """A malformed substituted SVID cannot make the regression gate pass."""

    def setUp(self) -> None:
        """Create only synthetic in-memory signing material for verifier vectors."""
        import jwt
        from cryptography.hazmat.primitives.asymmetric import ec

        self.jwt = jwt
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.other_key = ec.generate_private_key(ec.SECP256R1())
        jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(self.key.public_key()))
        jwk["kid"] = "synthetic-test-key"
        self.bundle = {"keys": [jwk]}
        self.subject = "spiffe://identity-demo.example.test/openshell/sandbox/sandbox-b"
        self.audience = "https://synthetic.example.test/realms/test"

    def assertion(self, **overrides: object) -> str:
        """Sign a synthetic assertion with independently adjustable claims."""
        from probe_discovery import ISSUER

        claims = {"iss": ISSUER, "sub": self.subject, "aud": [self.audience],
                  "exp": int(time.time()) + 60}
        claims.update(overrides)
        return self.jwt.encode(claims, self.key, algorithm="ES256",
                               headers={"kid": "synthetic-test-key"})

    def test_valid_assertion(self) -> None:
        """Expected issuer, subject, audience and signature are accepted."""
        verify_diagnostic_assertion(self.assertion(), self.subject, self.audience, self.bundle)

    def test_invalid_signature(self) -> None:
        """A signed token from another key is not a valid substituted identity."""
        claims = self.jwt.decode(self.assertion(), options={"verify_signature": False})
        value = self.jwt.encode(claims, self.other_key, algorithm="ES256",
                                headers={"kid": "synthetic-test-key"})
        with self.assertRaises(self.jwt.InvalidSignatureError):
            verify_diagnostic_assertion(value, self.subject, self.audience, self.bundle)

    def test_wrong_subject(self) -> None:
        """The independently verified assertion must actually name B."""
        with self.assertRaises(self.jwt.InvalidTokenError):
            verify_diagnostic_assertion(self.assertion(sub="spiffe://other.test/a"),
                                        self.subject, self.audience, self.bundle)

    def test_wrong_audience(self) -> None:
        """A token unusable by this issuer cannot count as a subject denial."""
        with self.assertRaises(self.jwt.InvalidAudienceError):
            verify_diagnostic_assertion(self.assertion(aud=["wrong-audience"]),
                                        self.subject, self.audience, self.bundle)

    def test_wrong_issuer(self) -> None:
        """Issuer equality is checked as well as the signature."""
        with self.assertRaises(self.jwt.InvalidIssuerError):
            verify_diagnostic_assertion(self.assertion(iss="https://other.test"),
                                        self.subject, self.audience, self.bundle)

    def test_expired_assertion(self) -> None:
        """Expiry rejection must not be confused with exact subject binding."""
        with self.assertRaises(self.jwt.ExpiredSignatureError):
            verify_diagnostic_assertion(self.assertion(exp=1), self.subject, self.audience, self.bundle)

    def test_missing_trusted_key(self) -> None:
        """Unmatched key IDs fail rather than trusting assertion key material."""
        value = json.loads(json.dumps(self.bundle))
        value["keys"][0]["kid"] = "other-key"
        with self.assertRaises(ValueError):
            verify_diagnostic_assertion(self.assertion(), self.subject, self.audience, value)


@pytest.mark.parametrize('data',[b'\x00\x00',b'\x01\x00\x00\x00\x00',b'\x00\x00\x00\x00\x00'],ids=['truncated-envelope','unnegotiated-compression','missing-token'])
def test_malformed_grant_envelopes(data):
    """Distinct malformed/compressed/empty grants must all fail closed."""
    with pytest.raises(ValueError):
        token_from_response(data)
