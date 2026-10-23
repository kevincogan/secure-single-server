# SPDX-License-Identifier: Apache-2.0
"""Run JWT rejection vectors in the pinned adapter image using only synthetic keys.

Execute with oc exec -i ... -- python - < this file. No issuer signing key or
real token is read or printed. This does not replace real issuer integration tests.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest


def run_vectors() -> None:
    """Load the verifier only inside the fixture and run deterministic checks."""
    sys.path.insert(0, "/fixtures")
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from adapter_auth import FixtureTokenVerifier

    class VerifierVectors(unittest.TestCase):
        """Assert safe booleans to avoid printing a token on test failure."""

        def setUp(self) -> None:
            """Generate a throwaway key and trusted public snapshot per case."""
            self.directory = tempfile.TemporaryDirectory()
            self.addCleanup(self.directory.cleanup)
            self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            jwk = jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
            jwk.update({"kid": "synthetic-test-key", "use": "sig", "alg": "RS256"})
            self.path = Path(self.directory.name) / "jwks.json"
            self.path.write_text(json.dumps({"keys": [jwk]}))
            self.issuer, self.audience = "https://issuer.example.invalid", "https://adapter.example.invalid/mcp"
            self.verifier = FixtureTokenVerifier(self.issuer, self.audience, "fixture-gateway-service", self.path)
            self.claims = {"iss": self.issuer, "aud": self.audience, "sub": "synthetic-service-subject",
                "exp": int(time.time()) + 60, "iat": int(time.time()) - 1, "azp": "fixture-gateway-service",
                "typ": "Bearer", "scope": "mcp:read"}

        def encode(self, claims: dict, *, key: object | None = None, kid: str = "synthetic-test-key") -> str:
            """Sign only fabricated claims with a disposable local key."""
            return jwt.encode(claims, key or self.key, algorithm="RS256", headers={"kid": kid})

        def accepted(self, token: str) -> bool:
            """Return a boolean so failure output contains no credentials."""
            return asyncio.run(self.verifier.verify_token(token)) is not None

        def test_valid_claims(self) -> None:
            """A well-formed fixture service token verifies."""
            self.assertTrue(self.accepted(self.encode(self.claims)))

        def test_changed_claims_rejected(self) -> None:
            """Correct signatures do not bypass issuer/audience/client/type/time checks."""
            changes = {"issuer": {"iss": "https://other.example.invalid"}, "audience": {"aud": "other"},
                "client": {"azp": "other-client"}, "id-token": {"typ": "ID"},
                "expired": {"exp": int(time.time()) - 5}, "future-iat": {"iat": int(time.time()) + 120},
                "empty-subject": {"sub": ""}, "invalid-scope-type": {"scope": ["mcp:read"]}}
            for name, change in changes.items():
                with self.subTest(case=name):
                    self.assertFalse(self.accepted(self.encode({**self.claims, **change})))

        def test_required_claims_rejected(self) -> None:
            """Every required identity/time/audience claim must be present."""
            for name in ("iss", "aud", "sub", "exp", "iat", "azp", "typ"):
                with self.subTest(missing=name):
                    claims = self.claims.copy()
                    del claims[name]
                    self.assertFalse(self.accepted(self.encode(claims)))

        def test_untrusted_key_algorithm_and_key_id_rejected(self) -> None:
            """Tokens cannot choose a signing key, algorithm or remote key source."""
            other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            self.assertFalse(self.accepted(self.encode(self.claims, key=other)))
            self.assertFalse(self.accepted(self.encode(self.claims, kid="unknown")))
            symmetric = jwt.encode(self.claims, "synthetic-secret-long-enough-for-fixture-tests", algorithm="HS256",
                                   headers={"kid": "synthetic-test-key", "jku": "https://other.example.invalid"})
            self.assertFalse(self.accepted(symmetric))
            self.assertFalse(self.accepted("malformed"))
            self.assertFalse(self.accepted("x" * 16_385))

        def test_missing_or_invalid_snapshot_fails_closed(self) -> None:
            """Public key configuration failures cannot accidentally disable auth."""
            token = self.encode(self.claims)
            self.path.write_text("not-json")
            self.assertFalse(self.accepted(token))
            self.path.unlink()
            self.assertFalse(self.accepted(token))

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(VerifierVectors)
    outcome = unittest.TextTestRunner(verbosity=1).run(suite)
    if not outcome.wasSuccessful():
        raise SystemExit(1)


if __name__ == "__main__":
    run_vectors()
