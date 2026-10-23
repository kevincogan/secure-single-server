# SPDX-License-Identifier: Apache-2.0
"""Offline JWT/cache tests; real HTTPS/rotation requires the separate cluster probe."""

from __future__ import annotations

import copy
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import rsa
import httpx
import jwt

from adapter_live_auth import FIXTURE_ISSUER_HOSTS, LiveFixtureTokenVerifier


class MemoryVerifier(LiveFixtureTokenVerifier):
    """Stub only public-key fetching while exercising real JWT verification."""

    def __init__(self, keys: dict) -> None:
        super().__init__("https://fixture-keycloak-demo-core.apps.cluster.example.test/realms/identity-demo",
                         "https://adapter.example.invalid/mcp", "fixture-gateway-service")
        self.source, self.calls, self.fail = keys, 0, False

    async def fetch_keys(self) -> dict:
        """Return synthetic public keys, or a controlled outage, without network access."""
        self.calls += 1
        if self.fail:
            raise httpx.ConnectError("Synthetic JWKS outage")
        return copy.deepcopy(self.source)


class LiveVerifierTests(unittest.IsolatedAsyncioTestCase):
    """Keep all assertion output free of tokens and signing keys."""

    def setUp(self) -> None:
        """Generate disposable signing material unrelated to any real identity."""
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        jwk.update({"kid": "key-a", "use": "sig", "alg": "RS256"})
        self.verifier = MemoryVerifier({"keys": [jwk]})
        self.claims = {"iss": self.verifier.issuer, "aud": self.verifier.audience,
            "sub": "synthetic-service", "azp": "fixture-gateway-service", "typ": "Bearer",
            "iat": int(time.time()) - 1, "exp": int(time.time()) + 60, "scope": "mcp:read"}

    def token(self, *, key: object | None = None, kid: str = "key-a", changes: dict | None = None) -> str:
        """Sign only synthetic claims, never real user or service data."""
        return jwt.encode({**self.claims, **(changes or {})}, key or self.key,
                          algorithm="RS256", headers={"kid": kid})

    async def accepted(self, token: str) -> bool:
        """Return a boolean so assertion failures never display an AccessToken."""
        return await self.verifier.verify_token(token) is not None

    async def test_known_key_and_claim_validation(self) -> None:
        """A valid token passes; cached keys never bypass identity/time checks."""
        self.assertTrue(await self.accepted(self.token()))
        for change in ({"iss": "https://other.invalid"}, {"aud": "other"},
                       {"azp": "other-client"}, {"exp": int(time.time()) - 5}):
            self.assertFalse(await self.accepted(self.token(changes=change)))
        self.assertEqual(self.verifier.calls, 1)

    async def test_unknown_key_fetches_are_bounded(self) -> None:
        """An unknown-kid flood cannot force one issuer request per token."""
        token = self.token()
        self.assertTrue(await self.accepted(token))
        self.verifier.next_fetch = 0
        for i in range(50):
            self.assertFalse(await self.accepted(self.token(kid=f"unknown-{i}")))
        self.assertEqual(self.verifier.calls, 2)
        self.assertTrue(await self.accepted(token))

    async def test_expired_cache_outage_and_recovery(self) -> None:
        """Expired trust fails closed and recovery fetches keys instead of accepting stale ones."""
        token = self.token()
        self.assertTrue(await self.accepted(token))
        self.verifier.expires, self.verifier.next_fetch, self.verifier.fail = 0, 0, True
        self.assertFalse(await self.accepted(token))
        self.verifier.fail, self.verifier.next_fetch = False, 0
        self.assertTrue(await self.accepted(token))
        self.assertEqual(self.verifier.calls, 3)

    async def test_rotated_key_and_overlap(self) -> None:
        """Configured JWKS refresh accepts the new key while preserving published overlap."""
        old = self.token()
        self.assertTrue(await self.accepted(old))
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
        jwk.update({"kid": "key-b", "use": "sig", "alg": "RS256"})
        self.verifier.source["keys"].append(jwk)
        self.verifier.next_fetch = 0
        renewed = self.token(key=key, kid="key-b")
        self.assertTrue(await self.accepted(renewed))
        self.assertTrue(await self.accepted(old))
        self.verifier.source = {"keys": [jwk]}
        self.verifier.expires, self.verifier.next_fetch = 0, 0
        self.assertFalse(await self.accepted(old))
        self.assertTrue(await self.accepted(renewed))

    async def test_redirect_and_oversize_jwks_rejected(self) -> None:
        """The fetcher neither follows redirects nor accepts unbounded public key data."""
        verifier = LiveFixtureTokenVerifier(self.verifier.issuer, self.verifier.audience, "fixture-gateway-service")
        client_class = httpx.AsyncClient
        for status, headers, body in ((302, {"Location": "https://other.invalid/keys"}, b""),
                                     (200, {"Content-Type": "application/json"}, b"x" * 131_073)):
            seen = []

            def reply(request: httpx.Request) -> httpx.Response:
                """Record destinations without sending a token or real network request."""
                seen.append(str(request.url))
                return httpx.Response(status, headers=headers, content=body)

            def client(**kwargs: object) -> httpx.AsyncClient:
                """Keep the production fetcher's redirect/timeout arguments intact."""
                return client_class(transport=httpx.MockTransport(reply), **kwargs)

            with patch("adapter_live_auth.httpx.AsyncClient", side_effect=client):
                with self.assertRaises(ValueError):
                    await verifier.fetch_keys()
            self.assertEqual(seen, [verifier.url])

    async def test_unapproved_issuer_and_malformed_header_rejected(self) -> None:
        """Trust comes from configured endpoints; rejected headers trigger no fetch."""
        for issuer in ("http://fixture-keycloak-demo-core.example.invalid/realms/identity-demo",
                       "https://attacker.invalid/realms/identity-demo", self.verifier.issuer + "?keys=other"):
            with self.assertRaises(ValueError):
                LiveFixtureTokenVerifier(issuer, self.verifier.audience, "fixture-gateway-service")
        for token in ("not-a-token", "x" * 16_385, jwt.encode(self.claims, "synthetic-key" * 4,
                                                        algorithm="HS256", headers={"kid": "key-a"})):
            self.assertFalse(await self.accepted(token))
        self.assertEqual(self.verifier.calls, 0)

    async def test_both_owned_origins_require_exact_configured_issuer(self) -> None:
        """Either approved fixture can be selected; trust never combines their keys."""
        for host in FIXTURE_ISSUER_HOSTS:
            issuer = "https://" + host + "/realms/identity-demo"
            verifier = LiveFixtureTokenVerifier(issuer, self.verifier.audience,
                                               "fixture-gateway-service")
            self.assertEqual(verifier.url, issuer + "/protocol/openid-connect/certs")
            accepted = verifier.validate_with_keys(self.token(), self.verifier.source) is not None
            self.assertEqual(accepted, issuer == self.verifier.issuer)

    async def test_prefix_lookalikes_and_wrong_realms_rejected_before_fetch(self) -> None:
        """An approved name prefix does not permit an attacker-controlled origin."""
        host = sorted(FIXTURE_ISSUER_HOSTS)[0]
        for issuer in (
            "https://fixture-keycloak-demo-core.attacker.invalid/realms/identity-demo",
            "https://" + host + ".attacker.invalid/realms/identity-demo",
            "https://" + host + "/realms/other",
            "https://" + host + "/realms/identity-demo#other",
            "https://user:password@" + host + "/realms/identity-demo",
        ):
            with self.assertRaises(ValueError):
                LiveFixtureTokenVerifier(issuer, self.verifier.audience,
                                         "fixture-gateway-service")
