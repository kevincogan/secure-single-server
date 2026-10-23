# SPDX-License-Identifier: Apache-2.0
"""Bounded encrypted browser transactions, using the existing cryptography library.

No anonymous server-side reservation is needed. Keycloak still validates the
single-use authorization code; this cookie binds its state, nonce and PKCE
verifier to the initiating browser and is invalidated by a console restart.
"""
import json
import secrets
import time

from cryptography.fernet import Fernet, InvalidToken
from identity_demo_run_store import Denied, strict_json


class LoginState:
    def __init__(self):
        self.cipher = Fernet(Fernet.generate_key())

    def issue(self, state: str, nonce: str, verifier: str) -> str:
        value = {'state': state, 'nonce': nonce, 'verifier': verifier, 'expires': time.time() + 300}
        return self.cipher.encrypt(json.dumps(value).encode()).decode()

    def consume(self, cookie: str, state: str) -> dict:
        # This is not an execution token. Redemption also requires Keycloak's
        # one-use code and the exact PKCE verifier. Never retain raw cookies.
        if not isinstance(cookie, str) or not 1 <= len(cookie) <= 2048:
            raise Denied('login_state')
        try:
            value = strict_json(self.cipher.decrypt(cookie.encode(), ttl=300))
            if (set(value) != {'state', 'nonce', 'verifier', 'expires'}
                    or not isinstance(value['state'], str)
                    or not secrets.compare_digest(value['state'], state)
                    or type(value['expires']) not in (int, float)
                    or value['expires'] <= time.time()
                    or any(not isinstance(value[k], str) or len(value[k]) != 43
                           for k in ('state', 'nonce', 'verifier'))):
                raise Denied('login_state')
            return value
        except (InvalidToken, ValueError, UnicodeError, TypeError, KeyError):
            raise Denied('login_state') from None
