# SPDX-License-Identifier: Apache-2.0
"""Live sender controls through the owned issuer and gateway, with private evidence.

The native CVE read remains the positive end-to-end acceptance. These controlled
replay requests use operator-only loopback tunnels and real supervisor SVIDs;
they do not demonstrate access to keys by an unprivileged agent.
"""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import http.client
import json
from pathlib import Path
import socket
import ssl
import subprocess
import time
from typing import Iterator
from urllib.parse import urlencode

from cryptography import x509
from cryptography.hazmat.primitives import serialization

import native_subject_boundary as subject
import probe_native_exchange as native
from probe_native_identity import certificates
from sender_listener import HOST, NAME, RESOURCE
from execution_context import context_of
from deployment_profile import active_profile

ISSUER_TLS_HOST = 'fixture-keycloak-upstream.' + active_profile().core_namespace + '.svc'


@dataclass(frozen=True)
class Certificate:
    """An exact leaf/key snapshot kept outside Git and outside the CVE workload."""

    chain: Path
    key: Path
    fingerprint: str
    expires_at: float
    identity: str


def session_header(values: list[str]) -> str | None:
    """Accept one bounded broker JWT session, rejecting conflicting duplicates."""
    if not values:
        return None
    if len(set(values)) != 1:
        raise ValueError("Conflicting MCP session headers")
    session = values[0]
    # The installed gateway uses signed JWTs, which exceed a UUID-sized limit.
    # Keep a finite header bound and refuse whitespace/control characters.
    if not session or len(session) > 4096 or any(ord(c) < 33 or ord(c) > 126 for c in session):
        raise ValueError("Bounded MCP session identifier required")
    return session


class SenderAcceptance:
    """Operate on only the established owned supervisor, issuer and listener."""

    def __init__(self, args: argparse.Namespace, human: dict) -> None:
        self.args, self.human = args, human
        self.directory = args.output_dir
        self.count = 0
        self.ca = self.save("service-ca.pem", native.kube(args, "get", "configmap",
            "fixture-service-ca", "-n", native.NAMESPACE, "-o", "json")["data"]["service-ca.crt"])
        self.native_ca = Path(args.cli_config_dir) / "openshell/gateways/identity-demo-runtime/mtls/ca.crt"
        self.bootstrap = self.supervisor_bootstrap()

    def save(self, name: str, value: object) -> Path:
        """Create immutable private files; never put credentials in console output."""
        path = self.directory / (self.args.label + ".sender-" + name)
        native.private_write(path, value)
        return path

    def supervisor_bootstrap(self) -> str:
        """Follow the current supervisor UID to its managed bootstrap Secret."""
        pod = native.kube(self.args, "get", "pod", "os-supervisor-" + context_of(self.args).sandbox_id,
                          "-n", context_of(self.args).namespace, "-o", "json")
        if (pod["metadata"].get("labels", {}).get("openshell.ai/gateway-id") != active_profile().gateway_id
                or pod["metadata"]["labels"].get("openshell.ai/sandbox-id") != context_of(self.args).sandbox_id):
            raise ValueError("Exact native supervisor required")
        names = [v["secret"]["secretName"] for v in pod["spec"]["volumes"] if v["name"] == "bootstrap"]
        if len(names) != 1:
            raise ValueError("One managed bootstrap required")
        projected = [v for v in pod["spec"]["volumes"] if v["name"] == "sa-token"]
        if (len(projected) != 1 or projected[0]["projected"]["sources"] != [{"serviceAccountToken": {
                "audience": "openshell-gateway", "expirationSeconds": 3600, "path": "token"}}]):
            raise ValueError("Exact native compute-driver token projection required")
        result = subprocess.run(["oc", "--kubeconfig=" + self.args.kubeconfig, "--request-timeout=20s",
            "-n", context_of(self.args).namespace, "exec", pod["metadata"]["name"], "-c", "supervisor", "--",
            "/run/openshell/step4-read-native-projection"], capture_output=True, text=True, timeout=30)
        self.save("compute-token.private.json", {"exit": result.returncode,
                  "stdout": result.stdout, "stderr": result.stderr})
        if result.returncode:
            raise RuntimeError("Native compute credential read failed")
        with self.tunnel("fixture-openshell", 19445, 8080):
            status, data, message = subject.exchange(self.native_ca, result.stdout.strip(),
                context_of(self.args).sandbox_id, context_of(self.args).provider_prefix, "", method="IssueSandboxToken", port=19445)
        self.save("bootstrap-session.private.json", {"status": status, "message": message,
                  "response_base64": base64.b64encode(data).decode()})
        if status != 0:
            raise ValueError("Supported native compute bootstrap rejected")
        return subject.token_from_response(data)

    def fetch(self, kind: str) -> dict:
        """Retrieve a real SVID through the supervisor's own Workload API socket."""
        self.count += 1
        words = ["oc", "--kubeconfig=" + self.args.kubeconfig, "--request-timeout=20s",
            "-n", context_of(self.args).namespace, "exec", "os-supervisor-" + context_of(self.args).sandbox_id, "-c", "supervisor",
            "--", "/run/openshell/step4-spire-agent", "api", "fetch", kind,
            "-socketPath", "/spiffe-workload-api/spire-agent.sock", "-timeout", "8s", "-output", "json"]
        if kind == "jwt":
            words.extend(["-audience", native.components.ISSUER])
        result = subprocess.run(words, capture_output=True, text=True, timeout=30)
        self.save(f"fetch-{self.count}.private.json", {"exit": result.returncode,
                  "stdout": result.stdout, "stderr": result.stderr})
        if result.returncode:
            raise RuntimeError("Native SVID retrieval failed; details withheld")
        value = json.loads(result.stdout)
        if kind == "jwt" and isinstance(value, list):
            responses = [item for item in value if isinstance(item, dict) and "svids" in item]
            if len(responses) != 1:
                raise ValueError("One native JWT response required")
            value = responses[0]
        if len(value["svids"]) != 1 or value["svids"][0]["spiffe_id"] != context_of(self.args).workload:
            raise ValueError("One exact native attested identity required")
        svid = value["svids"][0]
        if kind == "jwt":
            svid = {**svid, "token": svid["svid"]}
        return svid

    def certificate(self, name: str) -> Certificate:
        """Serialize one leaf and matching key; reject malformed identity or lifetime."""
        svid = self.fetch("x509")
        chain = certificates(svid["x509_svid"])
        leaf = chain[0]
        uris = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
            x509.UniformResourceIdentifier)
        if uris != [context_of(self.args).workload] or leaf.not_valid_after_utc.timestamp() <= time.time() + 20:
            raise ValueError("Currently valid exact supervisor certificate required")
        key = serialization.load_der_private_key(base64.b64decode(svid["x509_svid_key"]), password=None)
        if key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != (
            leaf.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)):
            raise ValueError("Certificate/key mismatch")
        pem = "".join(c.public_bytes(serialization.Encoding.PEM).decode() for c in chain)
        private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()).decode()
        return Certificate(self.save(name + ".chain.pem", pem), self.save(name + ".key.pem", private),
            base64.urlsafe_b64encode(hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).digest()).decode().rstrip("="),
            leaf.not_valid_after_utc.timestamp(), context_of(self.args).workload)

    def other_certificate(self) -> Certificate:
        """Mint a bounded administrative negative control, without claiming attestation."""
        result = subprocess.run(["oc", "--kubeconfig=" + self.args.kubeconfig, "--request-timeout=20s",
            "-n", active_profile().identity_namespace, "exec", "spire-server-0", "-c", "spire-server", "--",
            "/spire-server", "x509", "mint", "-spiffeID", native.GATEWAY, "-ttl", "2m", "-output", "json"],
            capture_output=True, text=True, timeout=30)
        self.save("other-certificate.private.json", {"exit": result.returncode,
                  "stdout": result.stdout, "stderr": result.stderr})
        if result.returncode:
            raise RuntimeError("Administrative certificate control failed")
        values = json.loads(result.stdout)
        if not isinstance(values, list) or len(values) != 1:
            raise ValueError("One administrative certificate required")
        value = values[0]
        chain = [x509.load_der_x509_certificate(base64.b64decode(v)) for v in value["x509_svid"]]
        uris = chain[0].extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
            x509.UniformResourceIdentifier)
        if uris != [native.GATEWAY]:
            raise ValueError("Exact negative-control identity required")
        key = serialization.load_der_private_key(base64.b64decode(value["private_key"]), password=None)
        return Certificate(self.save("other.chain.pem", "".join(c.public_bytes(serialization.Encoding.PEM).decode() for c in chain)),
            self.save("other.key.pem", key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                      serialization.NoEncryption()).decode()),
            base64.urlsafe_b64encode(hashlib.sha256(chain[0].public_bytes(serialization.Encoding.DER)).digest()).decode().rstrip("="),
            chain[0].not_valid_after_utc.timestamp(), native.GATEWAY)

    @contextmanager
    def tunnel(self, service: str, port: int, remote: int) -> Iterator[None]:
        """Own only a fresh loopback port, and close it on success and failure."""
        item = native.kube(self.args, "get", "service", service, "-n", native.NAMESPACE, "-o", "json")
        if any(item["metadata"].get("labels", {}).get(k) != v for k, v in native.LABELS.items()):
            raise ValueError("Owned test service required")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                raise ValueError("Occupied test port refused")
        except OSError:
            pass
        self.count += 1
        log = self.save(service + "-" + str(self.count) + ".tunnel.log", "")
        with log.open("a") as stream:
            process = subprocess.Popen(["oc", "--kubeconfig=" + self.args.kubeconfig, "-n", native.NAMESPACE,
                "port-forward", "--address", "127.0.0.1", "service/" + service, f"{port}:{remote}"],
                stdout=stream, stderr=stream)
            try:
                for _ in range(100):
                    if process.poll() is not None:
                        raise RuntimeError("Owned test tunnel failed")
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                            break
                    except OSError:
                        time.sleep(0.1)
                else:
                    raise TimeoutError("Owned test tunnel timeout")
                yield
            finally:
                process.terminate()
                process.wait(timeout=5)

    def request(self, port: int, host: str, path: str, body: bytes,
                certificate: Certificate | None, headers: dict[str, str],
                response_headers: dict[str, str] | None = None) -> tuple[int, bytes]:
        """Open one fresh owned tunnel per request, without replaying operations."""
        endpoints = {
            19443: ("fixture-keycloak-upstream", 8443, ISSUER_TLS_HOST),
            19444: (NAME, 443, HOST),
        }
        if port not in endpoints or host != endpoints[port][2]:
            raise ValueError("Exact owned diagnostic endpoint required")
        service, remote, _ = endpoints[port]
        with self.tunnel(service, port, remote):
            return self._request_once(port, host, path, body, certificate, headers, response_headers)

    def _request_once(self, port: int, host: str, path: str, body: bytes,
                      certificate: Certificate | None, headers: dict[str, str],
                      response_headers: dict[str, str] | None = None) -> tuple[int, bytes]:
        """Send bounded HTTP with CA/name validation and an optional exact TLS leaf."""
        context = ssl.create_default_context(cafile=str(self.ca))
        if port == 19444:
            # Source installations sign the bound Gateway listener with the
            # application CA already trusted by this installation's CLI. The
            # historical listener used the platform service CA. Trust only
            # these explicit operator roots; preserve chain/name verification.
            context.load_verify_locations(cafile=str(self.native_ca))
        context.set_alpn_protocols(["http/1.1"])
        if certificate:
            context.load_cert_chain(str(certificate.chain), str(certificate.key))
        with socket.create_connection(("127.0.0.1", port), timeout=15) as tcp:
            with context.wrap_socket(tcp, server_hostname=host) as tls:
                tls.settimeout(15)
                fields = {"Host": host, "Content-Length": str(len(body)), "Connection": "close", **headers}
                if any("\r" in k + v or "\n" in k + v for k, v in fields.items()):
                    raise ValueError("Invalid test header")
                tls.sendall(("POST " + path + " HTTP/1.1\r\n" + "".join(
                    k + ": " + v + "\r\n" for k, v in fields.items()) + "\r\n").encode() + body)
                response = http.client.HTTPResponse(tls)
                response.begin()
                if response_headers is not None:
                    session = session_header(response.headers.get_all("Mcp-Session-Id", []))
                    if session:
                        response_headers["Mcp-Session-Id"] = session
                data = response.read(2_000_001)
                if len(data) > 2_000_000:
                    raise ValueError("Oversized test response")
                return response.status, data

    def intermediate(self, assertion: str | None = None) -> tuple[int, bytes]:
        """Exercise the real native subject release with a real supervisor assertion."""
        assertion = assertion or self.fetch("jwt")["token"]
        with self.tunnel("fixture-openshell", 19445, 8080):
            status, data, message = subject.exchange(self.native_ca, self.bootstrap,
                context_of(self.args).sandbox_id, context_of(self.args).provider_prefix, assertion, port=19445)
        self.count += 1
        self.save(f"intermediate-{self.count}.private.json", {"grpc_status": status,
            "grpc_message": message, "response_base64": base64.b64encode(data).decode()})
        return status, data

    def final(self, certificate: Certificate | None, assertion: str | None = None) -> tuple[str, dict]:
        """Inspect a signed final token after real native intermediate release."""
        status, data = self.intermediate(assertion)
        if status != 0:
            raise ValueError("Positive native credential release required")
        assertion = assertion or self.fetch("jwt")["token"]
        body = urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": context_of(self.args).workload, "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe",
            "client_assertion": assertion, "subject_token": subject.token_from_response(data),
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token", "audience": RESOURCE}).encode()
        status, data = self.request(19443, ISSUER_TLS_HOST,
            "/realms/identity-demo/protocol/openid-connect/token", body, certificate,
            {"Content-Type": "application/x-www-form-urlencoded"})
        self.count += 1
        self.save(f"final-{self.count}.private.json", {"status": status, "body": data.decode()})
        if status != 200:
            raise ValueError("Final diagnostic exchange rejected")
        token = json.loads(data)["access_token"]
        claims = native.components.verify(token, RESOURCE, issuer=native.components.ISSUER)
        if (claims["sub"] != self.human["sub"] or claims["azp"] != context_of(self.args).workload
                or claims["exp"] - claims["iat"] > 30
                or (certificate and claims.get("cnf", {}).get("x5t#S256") != certificate.fingerprint)):
            raise ValueError("Unexpected signed final token contract")
        return token, claims

    def initialize_session(self, name: str, token: str, certificate: Certificate | None,
                           path: str = "/mcp") -> dict[str, str]:
        """Establish a real broker session before testing credential substitution."""
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   "Authorization": "Bearer " + token}
        session_headers: dict[str, str] = {}
        initialize = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "step4-sender-control", "version": "1"}}}).encode()
        status, data = self.request(19444, HOST, path, initialize, certificate, headers, session_headers)
        self.save(name + ".initialize.private.json", {"status": status,
            "body": data.decode(), "session_headers": session_headers})
        if status != 200 or "Mcp-Session-Id" not in session_headers:
            raise ValueError("Real broker initialization required before tool denial")
        session_headers["MCP-Protocol-Version"] = "2025-11-25"
        headers.update(session_headers)
        notification = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode()
        status, data = self.request(19444, HOST, path, notification, certificate, headers)
        self.save(name + ".initialized.private.json", {"status": status, "body": data.decode()})
        if status not in (200, 202, 204):
            raise ValueError("Broker notification rejected before tool denial")
        return session_headers

    def gateway(self, name: str, token: str | None, certificate: Certificate | None,
                extra: dict[str, str] | None = None, path: str = "/mcp", *, tool_call: bool = False,
                session_headers: dict[str, str] | None = None) -> dict:
        """Retain responses privately; expose only status or actual TLS rejection."""
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "step4-sender-control", "version": "1"}}}).encode()
        if tool_call:
            body = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "step4_read_searchJiraIssuesUsingJql", "arguments": {
                    "jql": "project = TEST", "maxResults": 1}}}).encode()
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   **({"Authorization": "Bearer " + token} if token else {}), **(extra or {})}
        record: dict = {"case": name}
        try:
            if tool_call:
                # The installed broker requires a real initialized session.
                # A bare tools/call receives 400 before authorization and is
                # therefore not evidence of a policy denial.
                if session_headers is None:
                    if token is None:
                        raise ValueError("An authenticated initialization token is required")
                    session_headers = self.initialize_session(name, token, certificate, path)
                if set(session_headers) != {"Mcp-Session-Id", "MCP-Protocol-Version"}:
                    raise ValueError("Only exact established session headers are permitted")
                headers.update(session_headers)
            status, data = self.request(19444, HOST, path, body, certificate, headers)
            self.save(name + ".response.private.json", {"status": status, "body": data.decode()})
            record["http_status"] = status
        except ssl.SSLError as error:
            self.save(name + ".tls.private.json", {"exception": repr(error)})
            record.update(tls_rejected=True, tls_reason=getattr(error, "reason", None))
        return record

    def run(self) -> dict:
        """Prove leaf-specific replay protection and fresh bound grants on renewal."""
        cases = []
        first = self.certificate("first")
        token, claims = self.final(first)
        cases.append(self.gateway("matching_leaf_positive", token, first))
        if cases[-1].get("http_status") != 200:
            raise ValueError("Sender positive control must pass first")
        cases.append(self.gateway("copied_token_without_certificate", token, None))
        other = self.other_certificate()
        cases.append(self.gateway("copied_token_other_identity", token, other))
        fields = token.split(".")
        signature = bytearray(base64.urlsafe_b64decode(fields[2] + "=" * (-len(fields[2]) % 4)))
        signature[0] ^= 1
        fields[2] = base64.urlsafe_b64encode(signature).decode().rstrip("=")
        cases.append(self.gateway("invalid_signature", ".".join(fields), first))
        unbound, unbound_claims = self.final(None)
        if "cnf" in unbound_claims:
            raise ValueError("Unbound negative control unexpectedly has cnf")
        cases.append(self.gateway("missing_cnf", unbound, first))
        cases.append(self.gateway("missing_access_token", None, first))
        print(json.dumps({"stage": "waiting_for_real_native_certificate_renewal"}), flush=True)
        deadline, renewal = time.monotonic() + 180, 0
        while time.monotonic() < deadline:
            renewal += 1
            second = self.certificate("renewal-" + str(renewal))
            if second.fingerprint != first.fingerprint:
                break
            time.sleep(5)
        else:
            raise TimeoutError("Native SVID leaf did not rotate within its configured TTL")
        if first.expires_at <= time.time() + 8:
            raise ValueError("Two valid overlapping leaves required for replay proof")
        old_token, _ = self.final(first)
        cases.append(self.gateway("old_leaf_positive_after_renewal", old_token, first))
        cases.append(self.gateway("copied_token_other_leaf_same_identity", old_token, second))
        cases.append(self.gateway("forged_peer_header_same_identity", old_token, second, {
            "X-Forwarded-Client-Cert": "Hash=" + base64.urlsafe_b64decode(first.fingerprint + "=").hex()
                + ";URI=" + context_of(self.args).workload}))
        new_token, new_claims = self.final(second)
        cases.append(self.gateway("new_leaf_fresh_token_positive", new_token, second))
        cases.append(self.gateway("human_token_wrong_audience", self.human["access_token"], second))
        expired_token, expired_claims = self.final(second)
        remaining = max(0, expired_claims["exp"] - time.time() + 1)
        if remaining > 35:
            raise ValueError("Bounded final lifetime required")
        time.sleep(remaining)
        cases.append(self.gateway("expired_access_token", expired_token, second))
        positive = {"matching_leaf_positive", "old_leaf_positive_after_renewal", "new_leaf_fresh_token_positive"}
        passed = all((v.get("http_status") == 200 if v["case"] in positive else
            v.get("tls_rejected") is True if v["case"] == "copied_token_without_certificate" else
            v.get("http_status") in (401, 403)) for v in cases)
        summary = {"passed": passed, "cases": cases, "actual_native_certificates": True,
            "same_identity_different_leaf_verified": first.fingerprint != second.fingerprint,
            "old_leaf_cnf": claims["cnf"]["x5t#S256"], "new_leaf_cnf": new_claims["cnf"]["x5t#S256"],
            "scope": "Operator-controlled replay tests; native CVE read is separate acceptance"}
        self.save("summary.json", summary)
        if not passed:
            raise ValueError("Sender rejection acceptance failed")
        return summary
