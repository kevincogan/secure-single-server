#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check synthetic realm recovery and real pod-to-pod SPIFFE bundle trust.

The SPIFFE assertion for the trust diagnostic is administratively minted. It is
not native attestation or OpenShell exchange evidence. No Jira/model calls occur.
"""

from __future__ import annotations
from deployment_profile import active_profile

import argparse
import http.client
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
from typing import Any
from urllib.parse import urlencode, urlparse
from urllib.error import HTTPError
from urllib.request import Request, build_opener, HTTPSHandler, ProxyHandler

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "identity_demo"))
from identity_demo_keycloak_recovery import (  # noqa: E402
    command, inputs, write_private, POD, LOCAL_PORT, TLS_HOST, CA)
from identity_demo_runtime import owned_identity, NAMESPACE  # noqa: E402
import identity_demo_fixture_http as components


def strings(value: Any) -> list[str]:
    """Locate an issued JWT in the CLI response without emitting its contents."""
    if isinstance(value, dict):
        return [s for v in value.values() for s in strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in strings(v)]
    if isinstance(value, str) and value.startswith("eyJ") and value.count(".") == 2:
        return [value]
    return []


def run(args: argparse.Namespace) -> dict:
    """Compare critical restored state, human PKCE and supported SPIFFE auth."""
    directory, expected, original = inputs(args)
    credentials = json.loads(Path(args.credentials_file).read_text())
    recorded = next(v for v in json.loads((directory / "keycloak-recovery-created.private-json").read_text())
                    if v["kind"] == "Pod" and v["name"] == POD)
    current = json.loads(command(args, "get", "pod", POD, "-n", NAMESPACE, "-o", "json"))
    if (current["metadata"]["uid"] != recorded["uid"]
            or current["metadata"].get("labels", {}).get("app") != POD
            or current["metadata"].get("annotations", {}).get("openshift.io/scc") != "restricted-v2"):
        raise ValueError("Exact restricted rehearsal Pod required")
    result = {"scope": "Synthetic recovery rehearsal and actual internal HTTPS trust",
              "passed": False, "native_exchange_proven": False,
              "administratively_minted_assertion_not_native_attestation": True,
              "cases": [], "temporary_probe_objects_removed": False,
              "original_deployment_changed": False}
    tls = any(v.get("name") == "KC_HOSTNAME" and v.get("value") == f"https://{TLS_HOST}:8443"
              for v in current["spec"]["containers"][0].get("env", []))
    base = f"https://{TLS_HOST}:8443" if tls else f"http://127.0.0.1:{LOCAL_PORT}"
    components.KEYCLOAK, components.ISSUER = base, base + "/realms/identity-demo"
    context = ssl.create_default_context()
    if tls:
        ca = json.loads(command(args, "get", "configmap", CA, "-n", NAMESPACE, "-o", "json"))
        context.load_verify_locations(cadata=ca["data"]["service-ca.crt"])

    class TunnelConnection(http.client.HTTPSConnection):
        """Verify the actual Service DNS identity over our loopback-only tunnel."""

        def connect(self) -> None:
            """Preserve hostname/chain verification; redirect only the TCP address."""
            if self.host != TLS_HOST or self.port != 8443 or self._tunnel_host:
                raise ValueError("Exact rehearsal TLS destination required")
            transport = socket.create_connection(("127.0.0.1", LOCAL_PORT), timeout=self.timeout)
            try:
                self.sock = self._context.wrap_socket(transport, server_hostname=TLS_HOST)
                result["rehearsal_browser_tls_verified"] = True
            except Exception:
                transport.close()
                raise

    class TunnelHandler(HTTPSHandler):
        """Apply the trusted rehearsal connection to urllib and its cookie jar."""

        def https_open(self, request: Request) -> Any:
            """Use service CA verification instead of a TLS bypass."""
            return self.do_open(TunnelConnection, request, context=context)

    def rehearsal_opener(*handlers: Any) -> Any:
        """Disable ambient proxies and preserve requested cookie/redirect handlers."""
        return build_opener(ProxyHandler({}), *([TunnelHandler()] if tls else []), *handlers)

    def browser_request(url: str, *, fields: dict | None = None, headers: dict | None = None,
                        opener: Any = None) -> tuple[int, Any, bytes]:
        """Restrict all browser/JWKS requests to this exact rehearsal realm."""
        parsed = urlparse(url)
        if (parsed.scheme + "://" + parsed.netloc != base
                or not parsed.path.startswith("/realms/identity-demo/")):
            raise ValueError("Exact rehearsal realm destination required")
        data = urlencode(fields).encode() if fields is not None else None
        request_headers = dict(headers or {})
        if fields is not None:
            request_headers["Content-Type"] = "application/x-www-form-urlencoded"
        request = Request(url, data=data, headers=request_headers)
        try:
            with (opener or rehearsal_opener(components.NoRedirect())).open(request, timeout=20) as response:
                raw = response.read(2_000_001)
                if len(raw) > 2_000_000:
                    raise ValueError("Bounded rehearsal browser response required")
                return response.status, response.headers, raw
        except HTTPError as error:
            return error.code, error.headers, error.read(2_000_000)

    components.request, components.build_opener = browser_request, rehearsal_opener
    result["rehearsal_tls_enabled"] = tls
    result["rehearsal_browser_tls_verified"] = False
    try:
        with socket.create_connection(("127.0.0.1", LOCAL_PORT), timeout=0.2):
            raise ValueError("Rehearsal port occupied; existing listener preserved")
    except OSError:
        pass
    tunnel = subprocess.Popen(["oc", "--kubeconfig=" + args.kubeconfig, "-n", NAMESPACE,
        "port-forward", "--address", "127.0.0.1", "pod/" + POD,
        f"{LOCAL_PORT}:{8443 if tls else 8080}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    client_uuid = None
    provider_created = False
    provider = "fixture-recovery-spiffe-probe"
    subject = "spiffe://agents.example.test/oidc/discovery"
    bundle_endpoint = "https://spire-spiffe-oidc-discovery-provider.demo-identity.svc:8443/keys"
    prefix = "/admin/realms/identity-demo"

    def rehearsal_request(path: str, method: str = "GET", value: Any = None,
                          token: str | None = None, fields: dict | None = None) -> tuple[int, Any]:
        """Use only our exact loopback Pod tunnel; keep the main HTTPS guard intact."""
        if not (path.startswith(prefix + "/") or path.startswith("/realms/identity-demo/")
                or path == "/realms/master/protocol/openid-connect/token"):
            raise ValueError("Rehearsal realm path required")
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        body = None
        if fields is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            body = urlencode(fields).encode()
        if value is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(value).encode()
        opener = rehearsal_opener(components.NoRedirect())
        try:
            with opener.open(Request(base + path, data=body, headers=headers, method=method), timeout=20) as response:
                raw = response.read(2_000_001)
                if len(raw) > 2_000_000:
                    raise ValueError("Bounded rehearsal API response required")
                return response.status, json.loads(raw) if raw else None
        except HTTPError as error:
            raw = error.read(2_000_000)
            write_private(directory / (args.label + ".api-failure.private-json"), {
                "http_status": error.code, "method": method, "path": path,
                "body": raw.decode("utf-8", errors="replace")})
            result["rehearsal_api_failure"] = {"http_status": error.code, "method": method,
                                                "operation": "token" if path.endswith("/token") else "admin"}
            return error.code, None

    def admin(path: str, method: str = "GET", value: Any = None) -> Any:
        """Use only the recorded rehearsal's loopback administration tunnel."""
        status, auth = rehearsal_request("/realms/master/protocol/openid-connect/token", "POST", fields={
            "grant_type": "password", "client_id": "admin-cli", "username": "fixture-admin",
            "password": credentials["keycloak_admin"]})
        if status != 200:
            raise RuntimeError("Rehearsal administrator authentication failed")
        status, result = rehearsal_request(prefix + path, method, value, auth["access_token"])
        if status not in (200, 201, 204):
            raise RuntimeError("Rehearsal administration rejected request")
        return result

    def checked(name: str, condition: bool) -> None:
        """Record assertion outcomes without exposing sensitive values."""
        result["cases"].append({"case": name, "passed": bool(condition)})
        if not condition:
            raise ValueError("Recovery assertion failed: " + name)

    try:
        for _ in range(100):
            if tunnel.poll() is not None:
                raise RuntimeError("Own rehearsal tunnel failed")
            try:
                with socket.create_connection(("127.0.0.1", LOCAL_PORT), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise TimeoutError("Own rehearsal tunnel readiness timeout")
        actual = {v["clientId"]: v for v in admin("/clients")}
        checked("client_inventory_and_ids", set(actual) == {v["clientId"] for v in expected["clients"]}
                and all(actual[v["clientId"]]["id"] == v["id"] for v in expected["clients"]))
        # Import adds a legacy logout default: '+' uses registered login
        # redirects. With no registered redirects this adds no destination.
        # Verify that precondition rather than
        # rewriting built-in clients solely to erase a migration default.
        normalized_defaults = []
        for value in expected["clients"]:
            name = value["clientId"]
            attrs = actual[name].get("attributes", {})
            wanted = value.get("attributes", {})
            differing = {k for k in set(attrs) | set(wanted) if attrs.get(k) != wanted.get(k)}
            if (differing == {"post.logout.redirect.uris"}
                    and attrs.get("post.logout.redirect.uris") == "+"
                    and "post.logout.redirect.uris" not in wanted
                    and not actual[name].get("redirectUris")
                    and not value.get("redirectUris")):
                actual[name]["attributes"] = {k: v for k, v in attrs.items()
                                               if k != "post.logout.redirect.uris"}
                normalized_defaults.append(name)
        result["verified_inert_import_logout_defaults"] = normalized_defaults
        fields = ("enabled", "publicClient", "bearerOnly", "clientAuthenticatorType", "fullScopeAllowed",
                  "serviceAccountsEnabled", "standardFlowEnabled", "directAccessGrantsEnabled",
                  "redirectUris", "attributes", "defaultClientScopes", "optionalClientScopes",
                  "protocol", "protocolMappers", "webOrigins", "rootUrl", "baseUrl")
        for value in expected["clients"]:
            name = value["clientId"]
            def matches(field: str) -> bool:
                """Compare mapper behavior independently of generated record IDs."""
                left, right = actual[name].get(field), value.get(field)
                if field == "protocolMappers" and isinstance(left, list) and isinstance(right, list):
                    def effective(mapper: dict) -> str:
                        """Apply only the documented OIDC UserInfo default."""
                        model = {k: x for k, x in mapper.items() if k != "id"}
                        config = dict(model.get("config", {}))
                        if mapper.get("protocol") == "openid-connect" and config.get("id.token.claim") is not None:
                            # AbstractOIDCProtocolMapper.getEffectiveModel uses
                            # includeInIDToken when UserInfo is unspecified.
                            config.setdefault("userinfo.token.claim", config["id.token.claim"])
                        model["config"] = config
                        return json.dumps(model, sort_keys=True)
                    return sorted(effective(v) for v in left) == sorted(effective(v) for v in right)
                return left == right

            different = [k for k in fields if not matches(k)]
            if different:
                result["different_contract_fields"] = different
                write_private(directory / (args.label + ".contract-difference.private-json"), {
                    "expected": {k: value.get(k) for k in different},
                    "actual": {k: actual[name].get(k) for k in different}})
            checked("client_contract:" + name, not different)
            if value.get("secret"):
                checked("retained_secret:" + name,
                        admin("/clients/" + value["id"] + "/client-secret")["value"] == value["secret"])
        operator = credentials["runtime_management"]
        status, grant = rehearsal_request("/realms/identity-demo/protocol/openid-connect/token", "POST",
            fields={"grant_type": "client_credentials", "client_id": operator["client_id"],
                    "client_secret": operator["client_secret"]})
        checked("management_client_grant", status == 200)
        claims = components.verify(grant["access_token"], operator["audience"], issuer=components.ISSUER)
        wanted = next(v for v in expected["users"] if v.get("serviceAccountClientId") == operator["client_id"])
        checked("management_service_identity_and_role", claims["sub"] == wanted["id"]
                and claims["azp"] == operator["client_id"]
                and claims.get("realm_access", {}).get("roles") == ["identity-demo-runtime-admin"])
        providers = admin("/identity-provider/instances")
        checked("probe_name_collision_absent", subject not in actual
                and not any(v["alias"] == provider for v in providers))
        admin("/identity-provider/instances", "POST", {"alias": provider, "providerId": "spiffe",
            "enabled": True, "config": {"trustDomain": "spiffe://agents.example.test",
                "bundleEndpoint": bundle_endpoint, "identity-demo-owner": active_profile().owner}})
        provider_created = True
        admin("/clients", "POST", {"clientId": subject, "enabled": True, "publicClient": False,
            "protocol": "openid-connect", "clientAuthenticatorType": "federated-jwt",
            "serviceAccountsEnabled": True, "standardFlowEnabled": False,
            "directAccessGrantsEnabled": False, "fullScopeAllowed": False,
            "defaultClientScopes": ["basic"], "optionalClientScopes": [],
            "attributes": {"identity-demo-owner": active_profile().owner, "jwt.credential.issuer": provider,
                           "jwt.credential.sub": subject}, "protocolMappers": [{
                "name": "probe-audience", "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper", "config": {
                    "included.custom.audience": "identity-demo-recovery-probe",
                    "access.token.claim": "true", "id.token.claim": "false"}}]})
        matches = admin("/clients?" + urlencode({"clientId": subject}))
        checked("unique_created_probe_client", len(matches) == 1)
        client_uuid = matches[0]["id"]
        response = json.loads(command(args, "-n", "demo-identity", "exec", "spire-server-0",
            "-c", "spire-server", "--", "/spire-server", "jwt", "mint", "-spiffeID", subject,
            "-audience", components.ISSUER, "-ttl", "30s", "-output", "json"))
        assertions = strings(response)
        checked("one_trust_diagnostic_assertion", len(assertions) == 1)
        status, _, body = components.request(components.ISSUER + "/protocol/openid-connect/token", fields={
            "grant_type": "client_credentials",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe",
            "client_assertion": assertions[0]})
        value = json.loads(body)
        result["spiffe_http_status"] = status
        checked("actual_keycloak_internal_bundle_trust", status == 200 and "access_token" in value)
        verified = components.verify(value["access_token"], "identity-demo-recovery-probe", issuer=components.ISSUER)
        checked("spiffe_response_signature_and_client", verified["azp"] == subject)
        result["keycloak_internal_tls_and_bundle_fetch_proven"] = True
        # Browser recovery is an independent required gate. Trust success alone
        # must never promote the fixture or mark recovery complete.
        for name in ("analyst", "viewer"):
            wanted = next(v for v in expected["users"] if v["username"] == name)
            login = components.login(name, credentials[name])
            access = components.verify(login["access_token"], "identity-demo-mcp", issuer=components.ISSUER)
            identity = components.verify(login["id_token"], "identity-demo-ui", issuer=components.ISSUER)
            checked("pkce_identity_and_nonce:" + name,
                    access["sub"] == wanted["id"] == identity["sub"]
                    and identity.get("nonce") == login["expected_nonce"])
            checked("human_permissions:" + name, access.get("realm_access", {}).get("roles") == [name])
        result["passed"] = True
    except Exception as error:
        result["failure_kind"] = type(error).__name__
        result["details_withheld"] = True
        write_private(directory / (args.label + ".exception.private-json"), {
            "kind": type(error).__name__, "message": str(error)})
    finally:
        if client_uuid:
            value = admin("/clients/" + client_uuid)
            if value["clientId"] != subject or not owned_identity(value):
                raise ValueError("Temporary recovery client cleanup ownership mismatch")
            admin("/clients/" + client_uuid, "DELETE")
        if provider_created:
            value = admin("/identity-provider/instances/" + provider)
            if value["config"].get("identity-demo-owner") != active_profile().owner or value["config"]["bundleEndpoint"] != bundle_endpoint:
                raise ValueError("Temporary recovery provider cleanup ownership mismatch")
            admin("/identity-provider/instances/" + provider, "DELETE")
        result["temporary_probe_objects_removed"] = True
        tunnel.terminate()
        try:
            tunnel.wait(timeout=5)
        except subprocess.TimeoutExpired:
            tunnel.kill()
            tunnel.wait(timeout=5)
        live = json.loads(command(args, "get", "deployment", "fixture-keycloak", "-n", NAMESPACE, "-o", "json"))
        result["original_deployment_changed"] = live["metadata"]["uid"] != original["metadata"]["uid"] or live["spec"] != original["spec"]
        result["passed"] = result["passed"] and not result["original_deployment_changed"]
        write_private(directory / (args.label + ".json"), result)
    return result


def main() -> None:
    """Expose sanitized results; keep all secrets and raw errors private."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("kubeconfig", "expected-server", "credentials-file", "workspace-dir", "label"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    if Path(args.label).name != args.label:
        raise SystemExit("Simple evidence label required")
    try:
        result = run(args)
        print(json.dumps(result))
        raise SystemExit(0 if result["passed"] else 1)
    except Exception as error:
        print(json.dumps({"passed": False, "failure_kind": type(error).__name__, "details_withheld": True}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
