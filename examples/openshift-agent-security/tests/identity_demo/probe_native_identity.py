#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Inspect native-container SVIDs; retain raw Workload API responses privately."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "identity_demo"))
from identity_demo_spire_network import command, SERVER  # noqa: E402
from deployment_profile import active_profile  # noqa: E402
from deployment_profile import in_source_checkout


def certificates(encoded: str) -> list[x509.Certificate]:
    """Frame concatenated DER certificates for the standard X.509 parser."""
    data = base64.b64decode(encoded, validate=True)
    if not data or len(data) > 1024 * 1024:
        raise ValueError("Bounded certificate chain required")
    result = []
    while data:
        if len(data) < 2 or data[0] != 0x30:
            raise ValueError("DER certificate sequence required")
        count = data[1] & 0x7f
        if data[1] & 0x80:
            if not 1 <= count <= 4 or len(data) < 2 + count:
                raise ValueError("Bounded DER length required")
            header = 2 + count
            length = int.from_bytes(data[2:header], "big")
        else:
            header, length = 2, data[1]
        total = header + length
        if total > len(data):
            raise ValueError("Complete DER certificate required")
        result.append(x509.load_der_x509_certificate(data[:total]))
        data = data[total:]
    return result


def private_write(path: Path, value: str | bytes) -> None:
    """Create private evidence without overwriting another artifact."""
    data = value.encode() if isinstance(value, str) else value
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(data)


def probe(args: argparse.Namespace) -> dict:
    """Fetch through the actual native container and verify public certificates."""
    if command(args.kubeconfig, "config", "view", "--minify", "-o",
               "jsonpath={.clusters[0].cluster.server}") != SERVER:
        raise ValueError("Unexpected API server")
    profile = active_profile()
    namespace_name = getattr(args, "namespace", profile.core_namespace)
    if namespace_name not in profile.application_namespaces:
        raise ValueError("Exact owned native namespace required")
    namespace = json.loads(command(args.kubeconfig, "get", "namespace", namespace_name, "-o", "json"))
    if any(namespace["metadata"].get("labels", {}).get(k) != v for k, v in profile.labels.items()):
        raise ValueError("Owned namespace required")
    pod = json.loads(command(args.kubeconfig, "-n", namespace_name, "get", "pod", args.pod, "-o", "json"))
    if (args.pod != "fixture-openshell-0"
            and pod["metadata"].get("labels", {}).get("openshell.ai/gateway-id") != profile.gateway_id):
        raise ValueError("Owned native credential holder required")
    if args.container not in ("openshell-gateway", "supervisor"):
        raise ValueError("Native credential holder required")
    directory = args.output_dir.resolve()
    if (not directory.is_dir() or directory.stat().st_mode & 0o077
            or in_source_checkout(directory)
            or Path(args.label).name != args.label):
        raise ValueError("Private evidence directory and simple label required")
    result = subprocess.run(["oc", "--kubeconfig=" + args.kubeconfig, "--request-timeout=20s",
        "-n", namespace_name, "exec", args.pod, "-c", args.container, "--",
        args.binary, "api", "fetch", "x509", "-socketPath", "/spiffe-workload-api/spire-agent.sock",
        "-timeout", "8s", "-output", "json"], capture_output=True, text=True, timeout=25)
    # The JSON contains private key material. Never emit it or exception bodies.
    private_write(directory / (args.label + ".response.private-json"), result.stdout)
    private_write(directory / (args.label + ".stderr"), result.stderr)
    if result.returncode:
        return {"passed": False, "exit_code": result.returncode,
                "no_identity": "no identity" in result.stderr.lower(), "raw_output_withheld": True}
    response = json.loads(result.stdout)
    if len(response["svids"]) != 1:
        raise ValueError("Exactly one default identity required")
    svid = response["svids"][0]
    chain, bundle = certificates(svid["x509_svid"]), certificates(svid["bundle"])
    leaf = chain[0]
    uris = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.UniformResourceIdentifier)
    if svid["spiffe_id"] != args.expected_spiffe_id or uris != [args.expected_spiffe_id]:
        raise ValueError("Unexpected SPIFFE identity")
    now = datetime.now(timezone.utc)
    if not leaf.not_valid_before_utc <= now < leaf.not_valid_after_utc:
        raise ValueError("Currently valid certificate required")
    paths = {name: directory / (args.label + "." + name + ".pem")
             for name in ("leaf", "bundle", "intermediates")}
    for name, certs in (("leaf", chain[:1]), ("bundle", bundle), ("intermediates", chain[1:])):
        private_write(paths[name], b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs))
    options = ["openssl", "verify", "-purpose", "sslclient", "-CAfile", str(paths["bundle"])]
    if len(chain) > 1:
        options.extend(["-untrusted", str(paths["intermediates"])])
    verification = subprocess.run([*options, str(paths["leaf"])], capture_output=True, timeout=10)
    if verification.returncode:
        raise ValueError("Standard certificate-chain verification failed")
    summary = {"passed": True, "pod": args.pod, "pod_uid": pod["metadata"]["uid"],
        "container": args.container, "spiffe_id": args.expected_spiffe_id,
        "uri_san": uris, "serial": str(leaf.serial_number),
        "not_before": leaf.not_valid_before_utc.isoformat(), "not_after": leaf.not_valid_after_utc.isoformat(),
        "fingerprint_sha256": leaf.fingerprint(hashes.SHA256()).hex(),
        "chain_verified": True, "default_svid_count": 1, "private_key_withheld": True,
        "native_exchange_proven": False}
    private_write(directory / (args.label + ".public-summary.json"), json.dumps(summary, indent=2))
    return summary


def main() -> None:
    """Print only a public summary or a redacted failure category."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("kubeconfig", "pod", "container", "binary", "expected-spiffe-id", "label"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    profile = active_profile()
    parser.add_argument("--namespace", choices=profile.application_namespaces,
                        default=profile.core_namespace)
    try:
        result = probe(parser.parse_args())
        print(json.dumps(result))
        raise SystemExit(0 if result["passed"] else 1)
    except Exception as error:
        print(json.dumps({"passed": False, "failure_kind": type(error).__name__, "details_withheld": True}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
