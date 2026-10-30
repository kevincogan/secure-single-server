# SPDX-License-Identifier: Apache-2.0
"""Controlled native subject-substitution diagnostic, with private evidence.

Assertions are administratively minted for two existing registered identities.
This investigates the gateway's subject check; it is not a second workload's
attestation proof, an adversary capability demonstration, or sender binding.
"""

from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
import socket
import ssl
import subprocess
from typing import Any

import h2.config
import h2.connection
import h2.events


def encode_string(field: int, value: str) -> bytes:
    """Encode a pinned protobuf string field without generated application code."""
    def varint(number: int) -> bytes:
        encoded = bytearray()
        while number >= 128:
            encoded.append((number & 127) | 128)
            number >>= 7
        encoded.append(number)
        return bytes(encoded)

    data = value.encode()
    return varint((field << 3) | 2) + varint(len(data)) + data


def token_from_response(data: bytes) -> str:
    """Require exactly one uncompressed response and its access-token field."""
    if len(data) < 5 or data[0] != 0 or int.from_bytes(data[1:5], "big") != len(data) - 5:
        raise ValueError("One bounded uncompressed gRPC message required")
    message, position, token = data[5:], 0, None

    def varint() -> int:
        nonlocal position
        value = 0
        for shift in range(0, 70, 7):
            if position >= len(message):
                break
            byte = message[position]
            position += 1
            value |= (byte & 127) << shift
            if byte < 128:
                return value
        raise ValueError("Invalid response varint")

    while position < len(message):
        tag = varint()
        if tag & 7 != 2:
            raise ValueError("Unexpected response wire type")
        length = varint()
        if length > len(message) - position:
            raise ValueError("Truncated response field")
        value = message[position:position + length]
        position += length
        if tag >> 3 == 1:
            if token is not None:
                raise ValueError("Repeated access-token field")
            token = value.decode()
    if not token:
        raise ValueError("Missing intermediate access token")
    return token


def exchange(ca: Path, bootstrap: str, sandbox: str, provider: str,
             assertion: str, *, method: str = "ExchangeProviderSubjectToken", port: int = 18443) -> tuple[int, bytes, str]:
    """Call only the existing owned gateway over verified loopback TLS."""
    context = ssl.create_default_context(cafile=str(ca))
    context.set_alpn_protocols(["h2"])
    message = b"".join(encode_string(i, value) for i, value in enumerate(
        (sandbox, provider, "access_token", assertion), 1))
    if method not in ("ExchangeProviderSubjectToken", "IssueSandboxToken"):
        raise ValueError("Only bounded native exchange or bootstrap RPCs are permitted")
    if method == "IssueSandboxToken":
        message = b""
    with socket.create_connection(("127.0.0.1", port), timeout=20) as connection:
        with context.wrap_socket(connection, server_hostname="127.0.0.1") as tls:
            if tls.selected_alpn_protocol() != "h2":
                raise ValueError("Verified HTTP/2 required")
            channel = h2.connection.H2Connection(config=h2.config.H2Configuration(header_encoding="utf-8"))
            channel.initiate_connection()
            channel.send_headers(1, [(":method", "POST"), (":scheme", "https"),
                (":authority", "127.0.0.1:" + str(port)),
                (":path", "/openshell.v1.OpenShell/" + method),
                ("content-type", "application/grpc"), ("te", "trailers"),
                ("grpc-timeout", "20S"), ("authorization", "Bearer " + bootstrap)])
            channel.send_data(1, b"\x00" + len(message).to_bytes(4, "big") + message, end_stream=True)
            tls.sendall(channel.data_to_send())
            headers: dict[str, str] = {}
            data = bytearray()
            while True:
                received = tls.recv(65536)
                if not received:
                    raise ValueError("Incomplete gRPC exchange")
                for event in channel.receive_data(received):
                    if isinstance(event, (h2.events.ResponseReceived, h2.events.TrailersReceived)):
                        headers.update(dict(event.headers))
                    elif isinstance(event, h2.events.DataReceived):
                        data.extend(event.data)
                        channel.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                        if len(data) > 2 * 1024 * 1024:
                            raise ValueError("Oversized response")
                    elif isinstance(event, h2.events.StreamEnded):
                        return int(headers["grpc-status"]), bytes(data), headers.get("grpc-message", "")
                outgoing = channel.data_to_send()
                if outgoing:
                    tls.sendall(outgoing)


def subject_substitution_denied(observations: list[dict[str, Any]]) -> bool:
    """Require a successful control and explicit denial without a reply message."""
    if len(observations) != 2:
        return False
    control, substituted = observations
    return (
        control.get("case") == "correct_subject"
        and control.get("grpc_status") == 0
        and control.get("verified_intermediate_received") is True
        and substituted.get("case") == "same_domain_different_subject"
        and substituted.get("grpc_status") == 7  # PERMISSION_DENIED, not an outage.
        and substituted.get("verified_intermediate_received") is False
        and substituted.get("response_message_present") is False
    )


def verify_diagnostic_assertion(
    assertion: str, subject: str, audience: str, public_bundle: dict[str, Any],
) -> None:
    """Reject an invalid test assertion before it can be mistaken for denial."""
    import jwt
    from probe_discovery import ISSUER, jwt_keys

    header = jwt.get_unverified_header(assertion)
    matches = [key for key in jwt_keys(public_bundle) if key.get("kid") == header.get("kid")]
    if len(matches) != 1:
        raise ValueError("One current trusted diagnostic signing key required")
    key = jwt.PyJWK.from_dict(matches[0])
    jwt.decode(assertion, key.key, algorithms=[key.algorithm_name],
               issuer=ISSUER, audience=audience, subject=subject,
               options={"require": ["iss", "sub", "aud", "exp"]})


def investigate(args: argparse.Namespace, human: dict[str, Any]) -> dict[str, Any]:
    """Use only exact live owned resources; output no credential or raw body."""
    import probe_native_exchange as native
    import probe_keycloak_recovery as recovery

    pod_name = "os-supervisor-" + native.SANDBOX_ID
    pod = native.kube(args, "-n", native.NAMESPACE, "get", "pod", pod_name, "-o", "json")
    volumes = [v for v in pod["spec"]["volumes"] if v["name"] == "bootstrap"]
    if len(volumes) != 1:
        raise ValueError("One current native bootstrap volume required")
    secret = native.kube(args, "-n", native.NAMESPACE, "get", "secret",
                         volumes[0]["secret"]["secretName"], "-o", "json")
    labels = secret["metadata"].get("labels", {})
    if (labels.get("openshell.ai/sandbox-id") != native.SANDBOX_ID
            or labels.get("openshell.ai/managed-by") != "openshell"
            or not any(o.get("uid") == pod["metadata"]["uid"]
                       for o in secret["metadata"].get("ownerReferences", []))):
        raise ValueError("Current owned supervisor bootstrap required")
    bootstrap = json.loads(base64.b64decode(secret["data"]["auth.json"]))["gateway_token"]
    ca = Path(args.cli_config_dir) / "openshell/gateways/identity-demo-runtime/mtls/ca.crt"
    bundle = native.kube(args, "-n", "demo-identity", "exec", "spire-server-0",
                         "-c", "spire-server", "--", "/spire-server", "bundle", "show",
                         "-format", "spiffe")
    observations = []
    for name, subject in (("correct_subject", native.WORKLOAD),
                          ("same_domain_different_subject", native.OTHER_WORKLOAD)):
        process = subprocess.run(["oc", "--kubeconfig=" + args.kubeconfig,
            "--request-timeout=20s", "-n", "demo-identity", "exec", "spire-server-0",
            "-c", "spire-server", "--", "/spire-server", "jwt", "mint", "-spiffeID", subject,
            "-audience", native.components.ISSUER, "-ttl", "60s", "-output", "json"],
            capture_output=True, text=True, timeout=30)
        if process.returncode:
            raise RuntimeError("Bounded diagnostic assertion failed")
        assertions = recovery.strings(json.loads(process.stdout))
        if len(assertions) != 1:
            raise ValueError("One administratively minted assertion required")
        verify_diagnostic_assertion(assertions[0], subject, native.components.ISSUER, bundle)
        status, data, message = exchange(ca, bootstrap, native.SANDBOX_ID, native.PREFIX, assertions[0])
        private = {"grpc_status": status, "grpc_message": message,
                   "raw_response_base64": base64.b64encode(data).decode()}
        native.private_write(args.output_dir / (args.label + ".subject-" + name + ".private.json"), private)
        verified = False
        if status == 0:
            claims = native.components.verify(token_from_response(data), subject,
                                               issuer=native.components.ISSUER)
            verified = claims["sub"] == human["sub"] and claims["azp"] == native.GATEWAY
            if not verified:
                raise ValueError("Unexpected intermediate claims")
        if name == "correct_subject" and not verified:
            raise ValueError("Positive control did not reach the native exchange")
        observations.append({"case": name, "grpc_status": status,
                             "verified_intermediate_received": verified,
                             "response_message_present": bool(data)})
    return {"scope": "Authenticated supervisor RPC with controlled signed assertion substitution",
        "administratively_minted_assertions": True,
        "diagnostic_assertions_independently_verified": True,
        "second_sandbox_attestation_proven": False, "cases": observations,
        "different_subject_received_human_intermediate": observations[1]["verified_intermediate_received"],
        "substitution_rejected_with_permission_denied": subject_substitution_denied(observations),
        "exact_subject_check_proven": False, "raw_credentials_withheld": True}
