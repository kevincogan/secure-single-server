# SPDX-License-Identifier: Apache-2.0
"""Read-only native CLI and HTTP/2 management checks; no sandbox creation."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "identity_demo"))
from identity_demo_adapter import fixture_request
from identity_demo_runtime import guard, admin_token, verify_management, DENIED_CLIENT, AUDIENCE, ADMIN_ROLE, USER_ROLE, NAMESPACE
from identity_demo_lab import LABELS, oc
from deployment_profile import active_profile, LEGACY
from deployment_profile import in_source_checkout


def list_message(workspace: str) -> bytes:
    """Encode the pinned ListSandboxes selector for an owned workspace."""
    allowed = (active_profile().triage_namespace, active_profile().reader_namespace)
    if active_profile() == LEGACY:
        allowed = (*allowed, 'default')
    if workspace not in allowed:
        raise ValueError('Owned configured workspace required')
    value = workspace.encode('ascii')
    # Validated Kubernetes namespace labels are at most 63 bytes, so both
    # nested protobuf lengths fit one byte in the pinned v0.1.3 schema.
    return b'\x22' + bytes([len(value) + 2]) + b'\x0a' + bytes([len(value)]) + value


def list_sandboxes(ca: Path, token: str | None, workspace: str = 'default') -> dict:
    """List the explicit workspace and inspect gRPC trailers."""
    import h2.config
    import h2.connection
    import h2.events

    context = ssl.create_default_context(cafile=str(ca))
    context.set_alpn_protocols(["h2"])
    with socket.create_connection(("127.0.0.1", 18443), timeout=15) as connection:
        with context.wrap_socket(connection, server_hostname="127.0.0.1") as tls:
            if tls.selected_alpn_protocol() != "h2":
                raise ValueError("Verified HTTP/2 transport required")
            channel = h2.connection.H2Connection(config=h2.config.H2Configuration(header_encoding="utf-8"))
            channel.initiate_connection()
            headers = [(":method", "POST"), (":scheme", "https"),
                       (":authority", "127.0.0.1:18443"),
                       (":path", "/openshell.v1.OpenShell/ListSandboxes"),
                       ("content-type", "application/grpc"), ("te", "trailers"),
                       ("grpc-timeout", "15S")]
            if token is not None:
                headers.append(("authorization", "Bearer " + token))
            channel.send_headers(1, headers)
            # Pinned v0.1.3 proto: ListSandboxes.workspace_scope=4,
            # WorkspaceSelector.workspace=1. An absent selector is invalid.
            message = list_message(workspace)
            channel.send_data(1, b"\x00" + len(message).to_bytes(4, "big") + message, end_stream=True)
            tls.sendall(channel.data_to_send())
            status: dict[str, str] = {}
            while True:
                received = tls.recv(65536)
                if not received:
                    raise ValueError("Incomplete gRPC response")
                for event in channel.receive_data(received):
                    if isinstance(event, (h2.events.ResponseReceived, h2.events.TrailersReceived)):
                        status.update({k: v for k, v in event.headers if k in (":status", "grpc-status")})
                    if isinstance(event, h2.events.DataReceived):
                        channel.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    if isinstance(event, h2.events.StreamEnded):
                        return {"verified_tls": True, "http_status": int(status[":status"]),
                                "grpc_status": int(status["grpc-status"])}
                outgoing = channel.data_to_send()
                if outgoing:
                    tls.sendall(outgoing)


def initialize_cli(args: argparse.Namespace, credentials: dict, base: str) -> None:
    """Prepare only the private CLI profile through the verified loopback tunnel."""
    directory = Path(args.cli_config_dir)
    if (directory.is_symlink() or directory.stat().st_mode & 0o077
            or in_source_checkout(directory)):
        raise ValueError("Private isolated CLI configuration required")
    gateway_dir = directory / 'openshell/gateways/identity-demo-runtime'
    metadata = gateway_dir / 'metadata.json'
    port = getattr(args, 'management_port', 18443)
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError('Bounded private management port required')
    endpoint = 'https://127.0.0.1:' + str(port)
    expected = {'name': 'identity-demo-runtime', 'gateway_endpoint': endpoint,
                'auth_mode': 'oidc', 'oidc_issuer': base + '/realms/identity-demo',
                'oidc_client_id': 'fixture-runtime-operator', 'oidc_audience': AUDIENCE}
    if metadata.is_symlink():
        raise ValueError('Symlinked native CLI profile refused')
    exists = metadata.exists()
    if exists:
        saved = json.loads(metadata.read_text())
        if any(saved.get(k) != v for k, v in expected.items()):
            raise ValueError('Existing CLI profile belongs to a different gateway')
    certdir = gateway_dir / 'mtls'
    certdir.mkdir(parents=True, mode=0o700, exist_ok=True)
    ca_path = certdir / 'ca.crt'
    if ca_path.is_symlink() or exists and ca_path.read_bytes() != Path(args.ca_file).read_bytes():
        raise ValueError('Existing native CLI trust differs; use a fresh profile for rotation')
    shutil.copyfile(Path(args.ca_file), ca_path)
    os.chmod(certdir / 'ca.crt', 0o600)
    env = {**os.environ, 'XDG_CONFIG_HOME': str(directory),
           'OPENSHELL_OIDC_CLIENT_SECRET': credentials['runtime_management']['client_secret']}
    for key in ('OPENSHELL_GATEWAY', 'OPENSHELL_GATEWAY_ENDPOINT', 'OPENSHELL_GATEWAY_INSECURE', 'OPENSHELL_WORKSPACE'):
        env.pop(key, None)
    command = [args.cli, 'gateway', 'login', 'identity-demo-runtime'] if exists else [args.cli, 'gateway', 'add', endpoint,
        '--name', 'identity-demo-runtime', '--oidc-issuer', base + '/realms/identity-demo',
        '--oidc-client-id', 'fixture-runtime-operator', '--oidc-audience', AUDIENCE]
    result = subprocess.run(command,
        env=env, capture_output=True, text=True, timeout=45)
    if result.returncode:
        raise RuntimeError('Native CLI initialization failed; raw response withheld')
    if not exists and 'Authenticated via client credentials' not in result.stderr:
        raise ValueError('Native CLI did not establish the intended authentication')


def run(args: argparse.Namespace) -> dict:
    """Exercise only the dedicated fixture gateway with CA verification enabled."""
    args.namespace = NAMESPACE
    workspace = getattr(args, 'workspace',
        'default' if active_profile() == LEGACY else active_profile().triage_namespace)
    _, credentials, base = guard(args)
    gateway = json.loads(oc(args, "get", "statefulset", "fixture-openshell", "-n", args.namespace, "-o", "json"))
    if any(gateway["metadata"].get("labels", {}).get(k) != v for k, v in LABELS.items()):
        raise ValueError("Owned runtime gateway required")
    ca = Path(args.ca_file)
    directory = Path(args.cli_config_dir)
    if (directory.is_symlink() or directory.stat().st_mode & 0o077
            or in_source_checkout(directory)):
        raise ValueError("Private isolated CLI configuration required")
    tls_checks = []
    for case, context, hostname in (
            ("untrusted-ca", ssl.create_default_context(), "127.0.0.1"),
            ("wrong-hostname", ssl.create_default_context(cafile=str(ca)), "not-the-gateway.invalid")):
        try:
            with socket.create_connection(("127.0.0.1", 18443), timeout=15) as connection:
                with context.wrap_socket(connection, server_hostname=hostname):
                    raise ValueError("TLS verification unexpectedly succeeded")
        except ssl.SSLCertVerificationError:
            tls_checks.append({"case": case, "certificate_rejected": True})
    verify_management(base, credentials, admin_token(base, credentials))
    print(json.dumps({"issuer_management_claims_verified": True}), flush=True)
    fields = {"grant_type": "client_credentials", "client_id": "fixture-runtime-operator",
              "client_secret": credentials["runtime_management"]["client_secret"]}
    _, response = fixture_request(base, "/realms/identity-demo/protocol/openid-connect/token",
                                  method="POST", fields=fields)
    cases = []
    for name, token, expected in (("operator", response["access_token"], 0),
                                  ("missing-credentials", None, 16),
                                  ("malformed-credentials", "not-a-valid-jwt", 16)):
        result = list_sandboxes(ca, token, workspace)
        print(json.dumps({"case": name, **result, "passed": result["grpc_status"] == expected}), flush=True)
        if result["grpc_status"] != expected:
            raise ValueError("Unexpected management authorization result")
        cases.append({"case": name, **result})
    _, other = fixture_request(base, "/realms/identity-demo/protocol/openid-connect/token", method="POST",
        fields={"grant_type": "client_credentials", "client_id": "fixture-gateway-service",
                "client_secret": credentials.get("management_adapter_clients", credentials["adapter_clients"])["fixture-gateway-service"]})
    result = list_sandboxes(ca, other["access_token"], workspace)
    print(json.dumps({"case": "wrong-resource-audience", **result, "passed": result["grpc_status"] == 16}), flush=True)
    if result["grpc_status"] != 16:
        raise ValueError("Wrong-resource token accepted")
    cases.append({"case": "wrong-resource-audience", **result})
    _, denied = fixture_request(base, "/realms/identity-demo/protocol/openid-connect/token", method="POST",
        fields={"grant_type": "client_credentials", "client_id": DENIED_CLIENT,
                "client_secret": credentials["runtime_denial"]["client_secret"]})
    import jwt
    _, jwks = fixture_request(base, "/realms/identity-demo/protocol/openid-connect/certs")
    header = jwt.get_unverified_header(denied["access_token"])
    keys = [key for key in jwks["keys"] if key["kid"] == header["kid"]]
    if header["alg"] != "RS256" or len(keys) != 1:
        raise ValueError("Expected signing key required for role denial evidence")
    claims = jwt.decode(denied["access_token"], jwt.PyJWK.from_dict(keys[0]).key,
        algorithms=["RS256"], issuer=base + "/realms/identity-demo", audience=AUDIENCE,
        options={"require": ["exp", "iss", "sub", "aud", "azp"]})
    if claims["azp"] != DENIED_CLIENT or {ADMIN_ROLE, USER_ROLE}.intersection(claims.get("realm_access", {}).get("roles", [])):
        raise ValueError("Role-denial identity unexpectedly privileged")
    result = list_sandboxes(ca, denied["access_token"], workspace)
    print(json.dumps({"case": "valid-token-without-management-role", **result, "passed": result["grpc_status"] == 7}), flush=True)
    if result["grpc_status"] != 7:
        raise ValueError("Unexpected management role denial")
    cases.append({"case": "valid-token-without-management-role", **result})

    initialize_cli(args, credentials, base)
    env = {**os.environ, "XDG_CONFIG_HOME": str(directory),
           "OPENSHELL_OIDC_CLIENT_SECRET": credentials["runtime_management"]["client_secret"]}
    # Keep endpoint/auth overrides from the user's normal shell out of this experiment.
    for key in ("OPENSHELL_GATEWAY", "OPENSHELL_GATEWAY_ENDPOINT", "OPENSHELL_GATEWAY_INSECURE", "OPENSHELL_WORKSPACE"):
        env.pop(key, None)
    for command in (["sandbox", "list", "--output", "json"],):
        prefix = ['--workspace', workspace] if command[0] == 'sandbox' else []
        result = subprocess.run([args.cli, *prefix, *command], env=env, capture_output=True, text=True, timeout=45)
        if result.returncode:
            raise RuntimeError("Native CLI operation failed; raw body withheld")
        if command[0] == "gateway" and "Authenticated via client credentials" not in result.stderr:
            raise ValueError("Native CLI did not establish the intended authentication")
        if command[0] == "sandbox":
            json.loads(result.stdout)
    return {"management_cases": cases, "tls_rejection_cases": tls_checks,
            "native_cli_oidc_list_passed": True,
            "release_baseline": "0.1.3", "workspace": workspace, "sandbox_created": False,
            "actual_cve_acceptance_passed": False, "credentials_output": False}


def main() -> None:
    """Output only sanitized results and exception categories."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("kubeconfig", "expected-server", "credentials-file", "ca-file", "cli", "cli-config-dir"):
        parser.add_argument("--" + name, required=True)
    profile = active_profile()
    parser.add_argument('--workspace', choices=profile.application_namespaces[1:] +
        (('default',) if profile == LEGACY else ()),
        default='default' if profile == LEGACY else profile.triage_namespace)
    try:
        print(json.dumps(run(parser.parse_args()), indent=2))
    except Exception as error:
        print(json.dumps({"completed": False, "failure_kind": type(error).__name__, "details_withheld": True}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
