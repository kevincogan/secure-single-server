# SPDX-License-Identifier: Apache-2.0
"""Exercise the real PyJWT cache/unknown-key refresh with fixed HTTPS retrieval."""

from contextlib import contextmanager
import json

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

import identity_demo_driver as driver
from identity_demo_run_store import Denied


def jwk(kid: str) -> dict:
    """Make public synthetic signing material; no live issuer keys are changed."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return {**json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key())),
            "kid": kid, "use": "sig", "alg": "RS256"}


def client(monkeypatch: object, replies: list[bytes]) -> tuple:
    """Capture only fixed URL and timeout; emulate the bounded HTTPS response."""
    calls = []

    class Response:
        """One finite byte response with the same read bound as urllib."""

        def __init__(self, body: bytes) -> None:
            self.body = body

        def read(self, limit: int) -> bytes:
            """Respect the exact caller limit."""
            assert limit == 65_537
            return self.body[:limit]

    class Opener:
        """Accept one fixed HTTPS target and finite timeout."""

        @contextmanager
        def open(self, request: object, timeout: float) -> object:
            calls.append((request.full_url, timeout))
            yield Response(replies.pop(0))

    def build(*handlers: object) -> object:
        assert any(isinstance(h, driver.NoIssuerRedirect) for h in handlers)
        return Opener()

    monkeypatch.setattr(driver, "build_opener", build)
    keys = driver.FixedIssuerKeys("https://issuer.example.test/certs", timeout=5)
    return keys, calls


def test_unknown_kid_refreshes_and_retains_published_overlap(monkeypatch: object) -> None:
    """New authority triggers one refresh; published old authority still verifies."""
    old, new = jwk("old"), jwk("new")
    keys, calls = client(monkeypatch, [json.dumps({"keys": [old]}).encode(),
        json.dumps({"keys": [old, new]}).encode()])
    assert keys.get_signing_key("old").key_id == "old"
    assert keys.get_signing_key("new").key_id == "new"
    assert keys.get_signing_key("old").key_id == "old"
    assert calls == [("https://issuer.example.test/certs", 5)] * 2
    with pytest.raises(jwt.PyJWKClientError):
        # Refresh still receives only the published pair, never an attacker URL.
        keys.fetch_data = lambda: {"keys": [old, new]}
        keys.get_signing_key("unknown")


@pytest.mark.parametrize("body", [b" " * 65_537, b'{"keys": "invalid"}', b"[]"])
def test_unbounded_or_invalid_key_set_denied(monkeypatch: object, body: bytes) -> None:
    """No oversized or structurally invalid issuer response can supply a key."""
    keys, _ = client(monkeypatch, [body])
    with pytest.raises(Denied):
        keys.fetch_data()


def test_redirect_rejected_with_safe_reason() -> None:
    """Do not follow even an issuer-origin redirect to an unapproved destination."""
    with pytest.raises(Denied, match="issuer_redirect"):
        driver.NoIssuerRedirect().redirect_request(None, None, 302, "redirect", {},
                                                   "https://unapproved.example.test/")
