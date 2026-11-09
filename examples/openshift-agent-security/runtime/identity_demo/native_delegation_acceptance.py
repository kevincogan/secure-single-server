# SPDX-License-Identifier: Apache-2.0
"""Live delegated-token controls through the owned issuer and gateway, with private evidence.

The native CVE read remains the positive end-to-end acceptance. These controlled
replay requests use operator-only loopback tunnels and real supervisor SVIDs;
they do not demonstrate access to keys by an unprivileged agent.
"""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import http.client
import hashlib
import jwt
import json
from pathlib import Path
import socket
import ssl
import subprocess
import time
from typing import Iterator
from urllib.parse import urlencode, urlparse

import native_subject_boundary as subject
import native_exchange as native
from openshift_security.artifacts import write_evidence
from probe_native_identity import certificates
from protected_listener import HOST, NAME, RESOURCE
from openshift_security.oidc import valid_delegation
from execution_context import context_of
from deployment_profile import active_profile

ISSUER_TLS_HOST = 'fixture-keycloak-upstream.' + active_profile().core_namespace + '.svc'




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


class DelegationAcceptance:
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
        path = self.directory / (self.args.label + ".delegation-" + name)
        write_evidence(path, value)
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

    def fetch(self, kind: str = "jwt") -> dict:
        """Retrieve a real SVID through the supervisor's own Workload API socket."""
        if kind != "jwt":
            raise ValueError("Only JWT-SVIDs are used for delegated access")
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
                if not native.loopback_ready(process, port,
                        failure=RuntimeError("Owned test tunnel failed")):
                    raise TimeoutError("Owned test tunnel timeout")
                yield
            finally:
                process.terminate()
                process.wait(timeout=5)

    def request(self, port: int, host: str, path: str, body: bytes,
                headers: dict[str, str],
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
            return self._request_once(port, host, path, body, headers, response_headers)

    def _request_once(self, port: int, host: str, path: str, body: bytes,
                      headers: dict[str, str],
                      response_headers: dict[str, str] | None = None) -> tuple[int, bytes]:
        """Send bounded HTTP with CA/name validation and an server-authenticated TLS."""
        context = ssl.create_default_context(cafile=str(self.ca))
        if port == 19444:
            # Source installations sign the bound Gateway listener with the
            # application CA already trusted by this installation's CLI. The
            # historical listener used the platform service CA. Trust only
            # these explicit operator roots; preserve chain/name verification.
            context.load_verify_locations(cafile=str(self.native_ca))
        context.set_alpn_protocols(["http/1.1"])
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

    def identity_snapshot(self) -> dict:
        """Time a real JWT-SVID only after native and issuer validation succeed.

        Decoded assertion fields never authorize a request. Successful exact
        native release and the verified final grant establish the positive control.
        The public digest identifies the snapshot without retaining token bytes.
        """
        assertion = self.fetch()["token"]
        self.final(assertion)
        claims = jwt.decode(assertion, options={"verify_signature": False})
        if (claims.get("sub") != context_of(self.args).workload
                or type(claims.get("exp")) is not int or claims["exp"] <= time.time()):
            raise ValueError("Validated current exact JWT-SVID required")
        return {"sha256": hashlib.sha256(assertion.encode()).hexdigest(), "expires_at": claims["exp"]}

    def final(self, assertion: str | None = None) -> tuple[str, dict]:
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
            "/realms/identity-demo/protocol/openid-connect/token", body,
            {"Content-Type": "application/x-www-form-urlencoded"})
        self.count += 1
        self.save(f"final-{self.count}.private.json", {"status": status, "body": data.decode()})
        if status != 200:
            raise ValueError("Final diagnostic exchange rejected")
        token = json.loads(data)["access_token"]
        claims = native.components.verify(token, RESOURCE, issuer=native.components.ISSUER)
        if (claims["sub"] != self.human["sub"] or claims["azp"] != context_of(self.args).workload
                or not valid_delegation(claims)):
            raise ValueError("Unexpected signed final token contract")
        return token, claims

    def initialize_session(self, name: str, token: str,
                           path: str = "/mcp") -> dict[str, str]:
        """Establish a real broker session before testing credential substitution."""
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   "Authorization": "Bearer " + token}
        session_headers: dict[str, str] = {}
        initialize = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "step4-delegation-control", "version": "1"}}}).encode()
        status, data = self.request(19444, HOST, path, initialize, headers, session_headers)
        self.save(name + ".initialize.private.json", {"status": status,
            "body": data.decode(), "session_headers": session_headers})
        if status != 200 or "Mcp-Session-Id" not in session_headers:
            raise ValueError("Real broker initialization required before tool denial")
        session_headers["MCP-Protocol-Version"] = "2025-11-25"
        headers.update(session_headers)
        notification = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode()
        status, data = self.request(19444, HOST, path, notification, headers)
        self.save(name + ".initialized.private.json", {"status": status, "body": data.decode()})
        if status not in (200, 202, 204):
            raise ValueError("Broker notification rejected before tool denial")
        return session_headers

    def gateway(self, name: str, token: str | None,
                extra: dict[str, str] | None = None, path: str = "/mcp", *, tool_call: bool = False,
                session_headers: dict[str, str] | None = None) -> dict:
        """Retain responses privately; expose only status or actual TLS rejection."""
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "step4-delegation-control", "version": "1"}}}).encode()
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
                    session_headers = self.initialize_session(name, token, path)
                if set(session_headers) != {"Mcp-Session-Id", "MCP-Protocol-Version"}:
                    raise ValueError("Only exact established session headers are permitted")
                headers.update(session_headers)
            status, data = self.request(19444, HOST, path, body, headers)
            self.save(name + ".response.private.json", {"status": status, "body": data.decode()})
            record["http_status"] = status
        except ssl.SSLError as error:
            self.save(name + ".tls.private.json", {"exception": repr(error)})
            record.update(tls_rejected=True, tls_reason=getattr(error, "reason", None))
        return record


    def subject_controls(self, other: "DelegationAcceptance") -> dict:
        """Use two real supervised workloads; deny substitution before release."""
        first = context_of(self.args)
        second = context_of(other.args)
        if (first.workload == second.workload
                or any(urlparse(v.workload).netloc != active_profile().trust_domain
                       for v in (first, second))):
            raise ValueError("Two distinct attested workloads in the same trust domain required")
        for control in (self, other):
            positive, body = control.intermediate()
            if positive != 0 or not subject.token_from_response(body):
                raise ValueError("Both legitimate native releases must pass first")
        status, body = self.intermediate(other.fetch()["token"])
        if status != 7 or body:
            raise ValueError("Different attested subject must be rejected before credential release")
        result = {"passed": True, "real_workload_assertions": True,
            "correct_subject_released": True, "different_subject_grpc_status": status,
            "different_subject_response_message_present": bool(body),
            "first_workload": first.workload, "second_workload": second.workload}
        self.save("exact-subject.summary.json", result)
        return result

    def run(self) -> dict:
        """Measure bearer replay explicitly, then signature/audience/expiry denial.

        Copying a valid bearer token can preserve its existing authority. This
        operator-only test records that residual risk; it does not accept it or
        demonstrate credential access by an untrusted agent.
        """
        token, claims = self.final()
        cases = [self.gateway("legitimate_delegation", token)]
        if cases[-1].get("http_status") != 200:
            raise ValueError("Legitimate control must pass first")
        copied = self.gateway("operator_copied_bearer_token", token)
        if copied.get("http_status") != 200:
            raise ValueError("Bearer replay control did not demonstrate the selected contract")
        cases.append(copied)
        fields = token.split(".")
        signature = bytearray(base64.urlsafe_b64decode(fields[2] + "=" * (-len(fields[2]) % 4)))
        signature[0] ^= 1
        fields[2] = base64.urlsafe_b64encode(signature).decode().rstrip("=")
        for name, credential in (("invalid_signature", ".".join(fields)),
                                 ("missing_access_token", None),
                                 ("human_token_wrong_audience", self.human["access_token"])):
            result = self.gateway(name, credential)
            if result.get("http_status") not in (401, 403):
                raise ValueError("Delegation rejection failed: " + name)
            cases.append(result)
        while time.time() <= claims["exp"]:
            time.sleep(max(.01, min(2, claims["exp"] + .1 - time.time())))
        expired = self.gateway("expired_delegation", token)
        if expired.get("http_status") not in (401, 403):
            raise ValueError("Expired delegated token accepted")
        cases.append(expired)
        summary = {"passed": True, "cases": cases,
            "copied_bearer_token_reusable_before_expiry": True,
            "sender_constrained_protection": False,
            "unprivileged_credential_extraction_proven": False,
            "delegation_lifetime_seconds": claims["exp"] - claims["iat"],
            "scope": "Operator-controlled token tests; native agent and credential isolation are separate gates"}
        self.save("summary.json", summary)
        return summary
