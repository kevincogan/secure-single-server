#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify the owned internal discovery service against SPIRE's live public bundle."""

from __future__ import annotations
from deployment_profile import active_profile

import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "identity_demo"))
from identity_demo_discovery_registration import ISSUER, NAME, prepare  # noqa: E402
from identity_demo_spire_network import command, NAMESPACE  # noqa: E402
from deployment_profile import in_source_checkout

HOST = "spire-spiffe-oidc-discovery-provider.demo-identity.svc"


def private_write(path: Path, value: str) -> None:
    """Preserve evidence with restrictive permissions and no overwriting."""
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
        stream.write(value)


def fetch(port: int, path: str, context: ssl.SSLContext, host: str = HOST) -> tuple[dict, str]:
    """Check the actual service hostname/certificate through our loopback tunnel."""
    with socket.create_connection(("127.0.0.1", port), timeout=8) as raw:
        with context.wrap_socket(raw, server_hostname=host) as connection:
            connection.settimeout(8)
            fingerprint = hashlib.sha256(connection.getpeercert(binary_form=True)).hexdigest()
            connection.sendall((f"GET {path} HTTP/1.1\r\nHost: {HOST}:8443\r\n"
                                "Connection: close\r\n\r\n").encode("ascii"))
            response = http.client.HTTPResponse(connection)
            response.begin()
            body = response.read(1024 * 1024 + 1)
            if response.status != 200 or len(body) > 1024 * 1024:
                raise ValueError("Bounded successful discovery response required")
            return json.loads(body), fingerprint


def jwt_keys(value: dict) -> list[dict]:
    """Compare live JWT verification keys, excluding X.509-only bundle entries."""
    keys = [k for k in value.get("keys", []) if k.get("use") != "x509-svid"]
    if not keys or any(k.get("kty") not in ("EC", "RSA", "OKP") for k in keys):
        raise ValueError("Supported public JWT verification keys required")
    for key in keys:
        if any(name in key for name in ("d", "p", "q", "dp", "dq", "qi")):
            raise ValueError("Private JWK material forbidden")
    # Provider may add `use: sig`; compare the actual public keys and key IDs.
    fields = ("kid", "kty", "crv", "x", "y", "n", "e")
    return sorted([{n: k[n] for n in fields if n in k} for k in keys],
                  key=lambda v: json.dumps(v, sort_keys=True))


def run(args: argparse.Namespace) -> dict:
    """Prove chain/hostname validation, public bundle delivery and exact ownership."""
    registration = prepare(args.kubeconfig)
    live = json.loads(command(args.kubeconfig, "get", "clusterstaticentry", NAME, "-o", "json"))
    if live["metadata"].get("labels", {}).get("identity-demo-owner") != active_profile().owner:
        raise ValueError("Owned exact registration required")
    for field in ("className", "spiffeID", "parentID", "selectors"):
        if live["spec"][field] != registration["spec"][field]:
            raise ValueError("Discovery registration needs trusted Pod refresh")
    directory = args.output_dir.resolve()
    if (not directory.is_dir() or directory.stat().st_mode & 0o077
            or in_source_checkout(directory)
            or Path(args.label).name != args.label):
        raise ValueError("Private output directory and simple label required")
    ca = json.loads(command(args.kubeconfig, "get", "configmap", "identity-demo-oidc-service-ca",
                            "-n", NAMESPACE, "-o", "json"))
    if ca["metadata"].get("labels", {}).get("identity-demo-owner") != active_profile().owner:
        raise ValueError("Owned injected service CA required")
    context = ssl.create_default_context(cadata=ca["data"]["service-ca.crt"])
    # Use an OS-selected loopback port; never reuse/terminate another listener.
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    tunnel = subprocess.Popen(["oc", "--kubeconfig=" + args.kubeconfig, "-n", NAMESPACE,
        "port-forward", "--address", "127.0.0.1", "service/" + HOST.split(".")[0],
        f"{port}:8443"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            if tunnel.poll() is not None:
                raise RuntimeError("Our discovery tunnel failed")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise TimeoutError("Discovery tunnel readiness timed out")
        metadata, fingerprint = fetch(port, "/.well-known/openid-configuration", context)
        if metadata.get("issuer") != ISSUER or metadata.get("jwks_uri") != ISSUER + "/keys":
            raise ValueError("Discovery issuer/JWKS contract mismatch")
        keys, second_fingerprint = fetch(port, "/keys", context)
        if fingerprint != second_fingerprint:
            raise ValueError("Certificate changed during probe; repeat explicitly")
        bundle = json.loads(command(args.kubeconfig, "-n", NAMESPACE, "exec", "spire-server-0",
                                     "-c", "spire-server", "--", "/spire-server",
                                     "bundle", "show", "-format", "spiffe"))
        normalized = jwt_keys(keys)
        if normalized != jwt_keys(bundle):
            raise ValueError("Discovery JWT keys do not match live SPIRE bundle")
        negatives = {}
        for name, ctx, host in (
            ("wrong_hostname", context, "different-service.invalid"),
            ("untrusted_ca", ssl.create_default_context(), HOST),
        ):
            try:
                fetch(port, "/keys", ctx, host)
            except ssl.SSLCertVerificationError:
                negatives[name] = True
            else:
                raise ValueError("TLS negative validation unexpectedly passed")
        result = {"checked_at_utc": datetime.now(timezone.utc).isoformat(), "passed": True,
            "issuer": ISSUER, "standard_vendor_image": True,
            "exact_registration_matches": True, "tls_chain_and_hostname_verified": True,
            "tls_certificate_sha256": fingerprint, "jwt_keys_match_live_spire_bundle": True,
            "jwt_key_ids": [k["kid"] for k in normalized], "tls_denials": negatives,
            "keycloak_tls_trust_proven": False, "jwt_signing_key_rotation_proven": False,
            "native_exchange_proven": False, "local_tunnel_not_network_policy_evidence": True}
        private_write(directory / (args.label + ".json"), json.dumps(result, indent=2))
        return result
    finally:
        tunnel.terminate()
        try:
            tunnel.wait(timeout=5)
        except subprocess.TimeoutExpired:
            tunnel.kill()
            tunnel.wait(timeout=5)


def main() -> None:
    """Print public evidence or a redacted failure category only."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--label", required=True)
    try:
        print(json.dumps(run(parser.parse_args())))
    except Exception as error:
        print(json.dumps({"passed": False, "failure_kind": type(error).__name__,
                          "details_withheld": True}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
