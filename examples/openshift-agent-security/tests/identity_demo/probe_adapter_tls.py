# SPDX-License-Identifier: Apache-2.0
"""Guarded HTTPS/JWKS experiment; real fixture tokens travel only over stdin."""

from __future__ import annotations

import argparse
import asyncio
import base64
from builtins import BaseExceptionGroup
import json
import logging
import os
from pathlib import Path
import ssl
import subprocess
import sys
import time
from urllib.parse import urlparse
from uuid import UUID, uuid4

from response_evidence import sanitized_error_result


async def in_pod(payload: dict) -> dict:
    """Exercise the actual HTTPS adapter without returning credentials or sessions."""
    import httpx
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    logging.disable(logging.CRITICAL)
    url = os.environ["ADAPTER_RESOURCE"]
    ca = ssl.create_default_context(cafile="/service-ca/service-ca.crt")
    case, token = payload["case"], payload.get("token")
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if case == "unknown-key":
        import jwt
        header = jwt.get_unverified_header(token)
        header["kid"] = "unknown-fixture-rotation-key"
        encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
        headers["Authorization"] = "Bearer " + encoded + "." + token.split(".", 1)[1]
    if case in ("untrusted-ca", "wrong-hostname"):
        target = url if case == "untrusted-ca" else "https://127.0.0.1:8443/mcp"
        verify = ssl.create_default_context() if case == "untrusted-ca" else ca
        try:
            async with httpx.AsyncClient(verify=verify, timeout=10, trust_env=False) as client:
                await client.get(target)
        except httpx.ConnectError as error:
            if "CERTIFICATE_VERIFY_FAILED" not in str(error):
                raise RuntimeError("TLS failure was not certificate verification") from None
            return {"case": case, "certificate_rejected": True}
        raise RuntimeError("TLS certificate unexpectedly accepted")
    if case == "read":
        async with httpx.AsyncClient(verify=ca, headers=headers, timeout=15, trust_env=False) as client:
            async with streamable_http_client(url, http_client=client) as streams:
                async with ClientSession(streams[0], streams[1]) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    result = await session.call_tool("searchJiraIssuesUsingJql", {
                        "jql": "project = TEST", "maxResults": 1})
                    values = [json.loads(v.text) for v in result.content if getattr(v, "type", "") == "text"]
                    if (result.isError or {t.name for t in tools.tools} != {"searchJiraIssuesUsingJql", "getJiraIssue"}
                            or not any(isinstance(v, dict) and v.get("total") == 0 and "issues" in v for v in values)):
                        raise RuntimeError("HTTPS read did not return the real empty fixture")
                    return {"case": case, "verified_https": True, "read_tools": 2,
                            "backend_read_ok": True, "issue_count": 0}
    initialize = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-03-26", "capabilities": {},
        "clientInfo": {"name": "identity-demo-tls-probe", "version": "0.1"}}}
    async with httpx.AsyncClient(verify=ca, timeout=10, trust_env=False) as client:
        response = await client.post(url, headers=headers, json=initialize)
        if len(response.content) > 2_000_000:
            raise RuntimeError("HTTPS adapter response exceeded the proof size bound")
        return {"case": case, "http_status": response.status_code,
                "has_result": "result" in sanitized_error_result(response.content)}


def driver(args: argparse.Namespace) -> None:
    """Rotate a receipt-tracked fixture component and restore both temporary changes."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "identity_demo"))
    from deployment_profile import in_source_checkout
    from identity_demo_adapter import fixture_request
    from identity_demo_adapter_tls import owned
    from identity_demo_lab import oc
    import jwt

    args.namespace = "demo-core"
    if oc(args, "config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}").rstrip("/") != args.expected_server.rstrip("/"):
        raise ValueError("Expected fixture cluster required")
    owned(args, "namespace", args.namespace)
    owned(args, "deployment", "fixture-keycloak")
    owned(args, "deployment", "fixture-protected-adapter")
    network = owned(args, "networkpolicy", "fixture-adapter-jwks")
    private = Path(args.credentials_file)
    if private.stat().st_mode & 0o077 or in_source_checkout(private):
        raise ValueError("Private credentials outside repository required")
    credentials = json.loads(private.read_text())
    base = credentials["keycloak_url"]
    if credentials["namespace"] != args.namespace or not credentials.get("adapter_tls_resource"):
        raise ValueError("Owned TLS fixture configuration required")
    original_request = fixture_request
    original_base = base
    if args.upstream_development_issuer:
        if not args.denials_only:
            raise ValueError("Upstream issuer probe currently supports read/denial mode only")
        from identity_demo_keycloak_upstream import BASE, issuer_request
        issuer = owned(args, "deployment", "fixture-keycloak-upstream")
        route = owned(args, "route", "fixture-keycloak-upstream")
        adapter = owned(args, "deployment", "fixture-protected-adapter")
        if (issuer["spec"]["template"]["spec"]["containers"][0]["image"] !=
                "quay.io/keycloak/keycloak@sha256:27b3230fbabb8c9ff3c66c864cf09dcd8a41aca82e5100679d109ef0eeb05741"
                or route["spec"]["host"] != urlparse(BASE).hostname):
            raise ValueError("Approved pinned upstream issuer required")
        tls = next(c for c in adapter["spec"]["template"]["spec"]["containers"]
                   if c["name"] == "adapter-https")
        configured = {e["name"]: e.get("value") for e in tls["env"]}
        if (configured.get("ADAPTER_ISSUER") != BASE + "/realms/identity-demo"
                or configured.get("ADAPTER_LIVE_JWKS") != "1"):
            raise ValueError("HTTPS adapter must select the exact upstream issuer")
        base, fixture_request = BASE, issuer_request
    output: list[dict] = []
    directory = Path(__file__).resolve().parent
    # Execute current test sources without replacing files or restarting the pod.
    # Only non-secret source goes in argv; fixture tokens remain on stdin.
    remote_source = ("import sys, types\n"
        "proof_module = types.ModuleType('response_evidence')\n"
        "sys.modules['response_evidence'] = proof_module\n"
        "exec(" + repr((directory / "response_evidence.py").read_text()) + ", proof_module.__dict__)\n"
        + "exec(" + repr(Path(__file__).read_text())
        + ", {'__name__': '__main__', '__file__': '/fixtures/probe_adapter_tls.py'})\n")
    compile(remote_source, "<identity-demo-tls-probe>", "exec")

    def grant(client: str = "fixture-gateway-service", scope: str | None = "mcp:read") -> str:
        """Obtain a real short-lived service credential without printing it."""
        fields = {"grant_type": "client_credentials", "client_id": client,
                  "client_secret": credentials["adapter_clients"][client]}
        if scope is not None:
            fields["scope"] = scope
        _, value = fixture_request(base, "/realms/identity-demo/protocol/openid-connect/token", method="POST", fields=fields)
        return value["access_token"]

    def probe(case: str, token: str | None = None, expected: int | None = None) -> dict:
        """Run inside the owned TLS container; discard library errors and stdin."""
        result = subprocess.run(["oc", "--kubeconfig=" + args.kubeconfig, "exec", "-i", "-n", args.namespace,
            "deployment/fixture-protected-adapter", "-c", "adapter-https", "--", "python",
            "-c", remote_source, "--in-pod"],
            input=json.dumps({"case": case, "token": token}), capture_output=True, text=True, timeout=35)
        if result.returncode:
            print(json.dumps({"failed_case": case, "child_exit_code": result.returncode}), flush=True)
            raise RuntimeError("Owned TLS probe failed: " + case)
        value = json.loads(result.stdout)
        if expected is not None and value.get("http_status") != expected:
            raise RuntimeError(f"Unexpected TLS probe status for {case}: {value.get('http_status')}")
        if expected in (401, 403) and value.get("has_result"):
            raise RuntimeError("Denied TLS probe returned a result")
        output.append(value)
        print(json.dumps({"check_passed": value}), flush=True)
        return value

    token = grant()
    probe("read", token)
    probe("untrusted-ca")
    probe("wrong-hostname")
    probe("missing", expected=401)
    probe("malformed", "not-a-token", 401)
    probe("wrong-client", grant("fixture-other-service"), 401)
    probe("missing-scope", grant(scope=None), 403)
    probe("unknown-key", grant(), 401)
    if args.denials_only:
        if args.upstream_development_issuer:
            _, old = original_request(original_base,
                "/realms/identity-demo/protocol/openid-connect/token", method="POST", fields={
                    "grant_type": "client_credentials", "client_id": "fixture-gateway-service",
                    "client_secret": credentials["adapter_clients"]["fixture-gateway-service"],
                    "scope": "mcp:read"})
            probe("original-issuer", old["access_token"], 401)
            expiry_token = grant()
            expiry = jwt.decode(expiry_token, options={"verify_signature": False})["exp"]
            wait = expiry - time.time() + 2
            if not 0 < wait <= 35:
                raise RuntimeError("Expected bounded development service-token expiry")
            time.sleep(wait)
            probe("expired", expiry_token, 401)
            probe("read", grant())
        print(json.dumps({"checks": output, "error_bodies_inspected": True,
            "development_issuer": "26.8.0" if args.upstream_development_issuer else "original",
            "actual_gateway_injection_proved": False,
            "scope": "Independent HTTPS reads and rejection bodies only; no key rotation or policy mutation"}))
        return
    def administrative_token() -> str:
        """Reauthenticate the lab administrator; its real token lifetime is only 60 seconds."""
        _, admin = fixture_request(base, "/realms/master/protocol/openid-connect/token", method="POST", fields={
            "grant_type": "password", "client_id": "admin-cli", "username": "fixture-admin",
            "password": credentials["keycloak_admin"]})
        return admin["access_token"]

    admin_token = administrative_token()
    prefix = "/admin/realms/identity-demo"
    _, realm = fixture_request(base, prefix, token=admin_token)
    if credentials.get("tls_rotation_component"):
        raise ValueError("Prior owned rotation receipt requires cleanup before retry")
    name = "identity-demo-rotation-" + uuid4().hex
    _, existing = fixture_request(base, prefix + "/components", token=admin_token)
    if any(item.get("name") == name for item in existing):
        raise ValueError("Prior rotation component requires ownership inspection before retry")
    component_id: str | None = None
    policy_changed = False
    credentials["tls_rotation_component"] = {"name": name, "realm": realm["id"], "state": "creating"}
    private.write_text(json.dumps(credentials))
    try:
        _, created = fixture_request(base, prefix + "/components", method="POST", token=admin_token,
            include_location=True, value={
            "name": name, "parentId": realm["id"], "providerId": "rsa-generated",
            "providerType": "org.keycloak.keys.KeyProvider", "config": {"enabled": ["true"],
                "active": ["true"], "priority": ["200"], "algorithm": ["RS256"], "keySize": ["2048"]}})
        location = urlparse(created["location"])
        expected_path = prefix + "/components/"
        if (location.scheme != "https" or location.hostname != urlparse(base).hostname
                or location.port not in (None, 443) or location.query or location.fragment
                or not location.path.startswith(expected_path)):
            raise RuntimeError("Unexpected owned component creation Location")
        component_id = str(UUID(location.path.removeprefix(expected_path)))
        credentials["tls_rotation_component"] = {"id": component_id, "name": name,
                                                 "realm": realm["id"], "state": "created"}
        private.write_text(json.dumps(credentials))
        renewed = grant()
        if jwt.get_unverified_header(token)["kid"] == jwt.get_unverified_header(renewed)["kid"]:
            raise RuntimeError("Issuer did not rotate its active signing key")
        time.sleep(2.1)
        probe("new-key", renewed, 200)
        probe("overlap-old-key", token, 200)
        # Only the narrow owned JWKS egress is changed. No shared service is stopped.
        policy_changed = True
        oc(args, "patch", "networkpolicy", "fixture-adapter-jwks", "-n", args.namespace,
           "--type=merge", "-p", json.dumps({"spec": {"egress": []}}))
        probe("cached-during-outage", renewed, 200)
        time.sleep(32)
        renewed = grant()
        probe("stale-cache-outage", renewed, 401)
        oc(args, "patch", "networkpolicy", "fixture-adapter-jwks", "-n", args.namespace,
           "--type=merge", "-p", json.dumps({"spec": {"egress": network["spec"]["egress"]}}))
        policy_changed = False
        time.sleep(2.1)
        probe("recovery", grant(), 200)
        retired = grant()
        probe("read", retired)
    finally:
        try:
            if policy_changed:
                oc(args, "patch", "networkpolicy", "fixture-adapter-jwks", "-n", args.namespace,
                   "--type=merge", "-p", json.dumps({"spec": {"egress": network["spec"]["egress"]}}))
        finally:
            if component_id:
                admin_token = administrative_token()
                _, component = fixture_request(base, prefix + "/components/" + component_id, token=admin_token)
                if (component.get("id") != component_id or component.get("name") != name
                        or component.get("parentId") != realm["id"] or component.get("providerId") != "rsa-generated"):
                    raise ValueError("Rotation cleanup ownership mismatch")
                fixture_request(base, prefix + "/components/" + component_id, method="DELETE", token=admin_token)
                credentials.pop("tls_rotation_component", None)
                private.write_text(json.dumps(credentials))
    # Refresh back to the original issuer key after removal, without a pod restart.
    time.sleep(32)
    if jwt.decode(retired, options={"verify_signature": False})["exp"] <= time.time():
        raise RuntimeError("Retired-key token expired before rejection could be demonstrated")
    probe("retired-key-rejected", retired, 401)
    probe("original-key-restored", grant(), 200)
    print(json.dumps({"checks": output, "issuer_key_restored": True, "egress_restored": True,
                      "scope": "Independent HTTPS adapter; gateway delivery and full G5 remain open"}))


def main() -> None:
    """Expose the guarded driver and sanitized in-pod probe modes."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig")
    parser.add_argument("--expected-server")
    parser.add_argument("--credentials-file")
    parser.add_argument("--in-pod", action="store_true")
    parser.add_argument("--denials-only", action="store_true",
                        help="Check reads and denial bodies without rotating keys or changing policy")
    parser.add_argument("--upstream-development-issuer", action="store_true",
                        help="Read/denial mode against the approved pinned 26.8.0 issuer")
    args = parser.parse_args()
    try:
        if args.in_pod:
            print(json.dumps(asyncio.run(asyncio.wait_for(in_pod(json.load(sys.stdin)), timeout=25))))
        else:
            if not all((args.kubeconfig, args.expected_server, args.credentials_file)):
                raise ValueError("Explicit fixture driver inputs required")
            driver(args)
    except KeyboardInterrupt:
        print("TLS/JWKS experiment interrupted; inspect receipt and owned egress before resuming", file=sys.stderr)
        raise SystemExit(130) from None
    except Exception as error:
        # Never emit tracebacks from libraries that may include HTTP credentials.
        def kinds(value: BaseException) -> list[str]:
            """Expose only class names and HTTP status numbers from nested SDK errors."""
            if isinstance(value, BaseExceptionGroup):
                return [kind for child in value.exceptions for kind in kinds(child)]
            import httpx
            if isinstance(value, httpx.HTTPStatusError):
                return ["HTTPStatusError:" + str(value.response.status_code)]
            return [type(value).__name__]
        print("TLS/JWKS experiment failed: " + ",".join(kinds(error)), file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
