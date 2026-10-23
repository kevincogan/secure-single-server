# SPDX-License-Identifier: Apache-2.0
"""Validate the exact private management profile and observe its original expiry."""

from __future__ import annotations

import json
import math
from pathlib import Path
import socket
import ssl
import time

from identity_demo_runtime_cli import private_path


def validate_profile(directory: Path, issuer: str, port: int = 18443) -> Path:
    """Refuse endpoint/identity substitution; credentials stay in the private CLI profile."""
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError("Bounded loopback management port required")
    private_path(str(directory), directory=True)
    profile = directory / "openshell/gateways/identity-demo-runtime"
    value = json.loads(private_path(str(profile / "metadata.json")).read_text())
    expected = {
        "name": "identity-demo-runtime",
        "auth_mode": "oidc",
        "gateway_endpoint": "https://127.0.0.1:" + str(port),
        "oidc_issuer": issuer + "/realms/identity-demo",
        "oidc_client_id": "fixture-runtime-operator",
        "oidc_audience": "identity-demo-runtime",
    }
    if any(value.get(k) != v for k, v in expected.items()):
        raise ValueError("Exact owned management profile required")
    private_path(str(profile / "mtls/ca.crt"))
    return profile


def remaining_seconds(profile: Path) -> float:
    """Read actual CLI expiry, without extending the token or returning its contents."""
    path = profile / "oidc_token.json"
    if not path.exists():
        return 0
    value = json.loads(private_path(str(path)).read_text())
    expiry = value.get("expires_at")
    if type(expiry) not in (float, int) or not math.isfinite(expiry):
        raise ValueError("Numeric operator expiry required")
    return expiry - time.time()


def verify_transport(profile: Path, port: int = 18443) -> None:
    """Probe strict TLS before dispatch; a live process or open port alone is insufficient."""
    context = ssl.create_default_context(
        cafile=str(private_path(str(profile / "mtls/ca.crt")))
    )
    with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
        with context.wrap_socket(connection, server_hostname="127.0.0.1"):
            pass
