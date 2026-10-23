# SPDX-License-Identifier: Apache-2.0
"""Disposable real-SVID/Keycloak exchange in our namespace, without CSI or host access.

This isolates issuer interoperability using join-token node enrollment and unix
workload attestation. It does not prove OpenShell, Kubernetes attestation, run
binding, sender constraint, or supported ZTWIM deployment. No existing Kubernetes
or Keycloak object is updated. Created objects are removed after ownership checks.
"""

from __future__ import annotations
from deployment_profile import active_profile

import argparse
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import secrets
import subprocess
import sys
import time
from typing import Any
from urllib.parse import urlencode
from urllib.parse import urlparse
from urllib.request import urlopen

import jwt

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "identity_demo"))
from identity_demo_adapter import fixture_request
from identity_demo_lab import LABELS, resource
from identity_demo_runtime import guard, admin_token, NAMESPACE
from identity_demo_runtime_grants import SERVER
import probe_token_exchange as issuer_probe
import checks.test_components as components

PREFIX = "fixture-spiffe-probe"
EXPERIMENT = "step3-real-svid"
DOMAIN = "isolated-probe.identity-demo.test"
GATEWAY = f"spiffe://{DOMAIN}/gateway"
SANDBOX = f"spiffe://{DOMAIN}/sandbox"
OTHER = f"spiffe://{DOMAIN}/other"
UI = PREFIX + "-ui"
MCP = PREFIX + "-mcp"
PROVIDER = PREFIX
CLIENTS = (UI, GATEWAY, SANDBOX, OTHER, MCP)
SERVER_IMAGE = "ghcr.io/spiffe/spire-server@sha256:674ae9e81d3a7a13dd750991edf0c984c2d542449687c6243f756f2446f08484"
AGENT_IMAGE = "ghcr.io/spiffe/spire-agent@sha256:d72233c86ebed56181abf86c65573a286b64a9e5ec9bceca81e6a798ea681a51"
ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe"


def command(args: argparse.Namespace, *words: str, payload: dict | None = None,
            allow_failure: bool = False) -> subprocess.CompletedProcess:
    """Keep API/credential output private and bound each subprocess."""
    result = subprocess.run(["oc", "--kubeconfig=" + args.kubeconfig, *words],
        input=json.dumps(payload) if payload is not None else None,
        capture_output=True, text=True, timeout=45)
    if result.returncode and not allow_failure:
        error = RuntimeError("Bounded fixture operation failed: " + words[0])
        error.safe_diagnostics = {"operation": words[0], "exit_code": result.returncode,
            "categories": [label for label, marker in (
                ("unknown_flag", "flag provided but not defined"),
                ("permission_denied", "permission denied"),
                ("no_identity", "no identity"),
                ("no_svid", "no svid"),
                ("not_registered", "not registered"),
                ("unavailable", "unavailable"),
                ("deadline", "deadline"),
                ("not_found", "not found"),
                ("connection_refused", "connection refused"),
                ("dial_error", "dial"),
                ("authorization_denied", "denied"),
                ("workload_attestation", "attestation"),
                ("authentication", "authentication"),
                ("invalid_argument", "invalidargument"),
                ("not_authorized", "not authorized"),
            ) if marker in (result.stderr + result.stdout).lower()]}
        raise error
    return result


def item(kind: str, suffix: str, spec: dict | None = None) -> dict:
    """Label each temporary object separately from retained fixtures."""
    result = resource(kind, PREFIX + suffix, NAMESPACE, spec)
    result["metadata"]["labels"]["identity-demo-experiment"] = EXPERIMENT
    return result


def pod(suffix: str, image: str, executable: str, arguments: list[str],
        volumes: list[dict], mounts: list[dict], env: list[dict] | None = None) -> dict:
    """Use only restricted, short-lived, resource-bounded namespace processes."""
    result = item("Pod", suffix, {"automountServiceAccountToken": False,
        "restartPolicy": "Never", "activeDeadlineSeconds": 1800,
        "securityContext": {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{"name": "probe", "image": image, "imagePullPolicy": "IfNotPresent",
            "command": [executable], "args": arguments, "env": env or [],
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "50m", "memory": "64Mi"},
                          "limits": {"cpu": "300m", "memory": "256Mi"}},
            "volumeMounts": mounts}], "volumes": volumes})
    result["metadata"]["labels"]["app"] = PREFIX + suffix
    return result


def federated_client(client_id: str, audience: str | None) -> dict:
    """Use built-in SPIFFE authentication, without a secret credential fallback."""
    value = issuer_probe.configuration(client_id, secrets.token_urlsafe(32), audience)
    value["attributes"]["identity-demo-experiment"] = EXPERIMENT
    if client_id == UI:
        value.update(publicClient=True, standardFlowEnabled=True,
                     redirectUris=["http://127.0.0.1:18085/callback"])
    if client_id in (GATEWAY, SANDBOX, OTHER):
        value.pop("secret")
        value["clientAuthenticatorType"] = "federated-jwt"
        value["attributes"].update({"jwt.credential.issuer": PROVIDER,
            "jwt.credential.sub": client_id, "standard.token.exchange.enabled": "true"})
    return value


def run(args: argparse.Namespace) -> dict[str, Any]:
    """Prove the issuer boundary and remove exactly this experiment's resources."""
    args.namespace = NAMESPACE
    if args.expected_server != SERVER:
        raise ValueError("Agreed development cluster required")
    _, credentials, base = guard(args)
    components.KEYCLOAK, components.ISSUER = base, base + "/realms/identity-demo"
    endpoint = components.ISSUER + "/protocol/openid-connect/token"
    result: dict[str, Any] = {"checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "Temporary namespace-only SPIRE unix-attestation issuer experiment",
        "spire_version": "1.14.7", "images": {"server": SERVER_IMAGE, "agent": AGENT_IMAGE},
        "trust_domain": DOMAIN, "cases": [], "claims": [], "errors": [],
        "spiffe_client_authentication_proven": False,
        "assertion_based_lookup_without_client_id_proven": False,
        "native_openshell_exchange_proven": False, "kubernetes_attestation_proven": False,
        "run_binding_proven": False, "sender_constraint_proven": False,
        "shared_resources_changed": False}
    created: list[tuple[dict, str]] = []
    clients: list[tuple[str, str]] = []
    provider_created = False

    def admin(path: str, method: str = "GET", value: Any = None) -> Any:
        """Operate only within the guarded fixture realm; never print responses."""
        return fixture_request(base, issuer_probe.PREFIX + path,
            token=admin_token(base, credentials), method=method, value=value)[1]

    def create(value: dict) -> dict:
        """Refuse existing names, validate admission, and record the created UID."""
        kind, name = value["kind"].lower(), value["metadata"]["name"]
        existing = command(args, "get", kind, name, "-n", NAMESPACE,
                           "--ignore-not-found", "-o", "json").stdout
        if existing.strip():
            raise ValueError("Existing experiment resource refused")
        command(args, "create", "--dry-run=server", "-f", "-", "-o", "name", payload=value)
        response = command(args, "create", "-f", "-", "-o", "json", payload=value)
        current = json.loads(response.stdout)
        created.append((value, current["metadata"]["uid"]))
        return current

    def ready(name: str) -> None:
        """Wait in short bounded reads; report only status categories on failure."""
        deadline = time.monotonic() + 150
        while time.monotonic() < deadline:
            current = json.loads(command(args, "get", "pod", name, "-n", NAMESPACE, "-o", "json").stdout)
            if any(v["type"] == "Ready" and v["status"] == "True"
                   for v in current.get("status", {}).get("conditions", [])):
                result.setdefault("pod_security", []).append({"name": name,
                    "scc": current["metadata"].get("annotations", {}).get("openshift.io/scc"),
                    "uid": current["spec"]["containers"][0]["securityContext"].get("runAsUser"),
                    "api_token_mounted": any("serviceAccountToken" in s
                        for v in current["spec"].get("volumes", [])
                        for s in v.get("projected", {}).get("sources", []))})
                return
            statuses = current.get("status", {}).get("containerStatuses", [])
            if any("terminated" in s.get("state", {}) for s in statuses):
                result["errors"].append({"stage": "pod-start", "name": name,
                    "exit_codes": [s["state"]["terminated"]["exitCode"]
                                   for s in statuses if "terminated" in s.get("state", {})]})
                raise RuntimeError("Temporary SPIRE process exited")
            time.sleep(2)
        raise TimeoutError("Temporary SPIRE pod readiness timeout")

    def execute(suffix: str, executable: str, *arguments: str,
                allow_failure: bool = False) -> subprocess.CompletedProcess:
        """Capture CLI output privately, including issued SVIDs and enrollment tokens."""
        return command(args, "exec", "-n", NAMESPACE, PREFIX + suffix, "-c", "probe", "--",
                       executable, *arguments, allow_failure=allow_failure)

    def server(*arguments: str) -> str:
        """Use the server's private administration socket only inside its own pod."""
        return execute("-server", "/opt/spire/bin/spire-server", *arguments).stdout

    def svid(subject: str, audience: str = components.ISSUER) -> str:
        """Fetch a real JWT-SVID from the selected disposable agent."""
        suffix = "-gateway" if subject == GATEWAY else "-sandbox"
        deadline = time.monotonic() + 45
        while True:
            try:
                response = execute(suffix, "/opt/spire/bin/spire-agent", "api", "fetch", "jwt",
                    "-socketPath", "/run/public/api.sock", "-audience", audience,
                    "-spiffeID", subject, "-output", "json")
                break
            except RuntimeError as error:
                if (time.monotonic() >= deadline or "no_identity" not in
                        getattr(error, "safe_diagnostics", {}).get("categories", [])):
                    raise
                # New registrations must propagate to the agent's local cache.
                # Only credential acquisition waits; denial cases are never retried.
                time.sleep(2)
        value = json.loads(response.stdout)
        # The public CLI shape is validated live before tokens are used.
        # The CLI prints each protobuf response as an element of a JSON array.
        return value[0]["svids"][0]["svid"]

    def exchange(subject_token: str, assertion: str, audience: str,
                 client_id: str | None = None) -> tuple[int, dict]:
        """Match native assertion-based lookup: omit client_id on successful exchanges."""
        fields = {"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": subject_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "client_assertion_type": ASSERTION_TYPE, "client_assertion": assertion,
            "audience": audience}
        if client_id is not None:
            fields["client_id"] = client_id
        status, _, body = components.request(endpoint, fields=fields)
        return status, json.loads(body)

    def record(case: str, status: int, value: dict, success: bool) -> None:
        """Expose status and standardized outcomes, never arbitrary error details."""
        passed = (status == 200 and "access_token" in value) if success else (
            status in (400, 401, 403) and "access_token" not in value)
        result["cases"].append({"case": case, "http_status": status,
            "access_token_returned": "access_token" in value, "passed": passed,
            "oauth_error": value.get("error") if value.get("error") in (
                "invalid_request", "invalid_client", "unauthorized_client", "access_denied",
                "invalid_grant", "unsupported_grant_type", "invalid_scope") else None,
            "error_categories": [category for category, marker in (
                ("client_id_required", "missing parameter: client_id"),
                ("client_id_required", "client_id missing"),
                ("client_not_found", "client not found"),
                ("invalid_client", "invalid client"),
                ("client_not_allowed", "client not allowed"),
                ("invalid_client_credentials", "invalid client credentials"),
                ("audience", "audience"),
                ("assertion_type", "assertion type"),
                ("assertion_signature", "signature"),
                ("maximum_expiration", "maximum expiration"),
                ("expired", "expired"),
                ("subject_token", "subject token"),
                ("subject_token", "subject_token"),
            ) if marker in str(value.get("error_description", "")).lower()]})
        if not passed:
            raise ValueError("Unexpected real-SVID exchange outcome")

    before_clients = admin("/clients")
    before_providers = admin("/identity-provider/instances")
    if (any(v["clientId"] in CLIENTS for v in before_clients)
            or any(v["alias"] == PROVIDER for v in before_providers)):
        raise ValueError("Existing issuer experiment names refused")
    try:
        namespace = json.loads(command(args, "get", "namespace", NAMESPACE, "-o", "json").stdout)
        uid = namespace["metadata"]["annotations"]["openshift.io/sa.scc.uid-range"].split("/")[0]
        configuration = item("ConfigMap", "-config")
        configuration["data"] = {"server.conf": f'''server {{
 bind_address = "0.0.0.0"
 bind_port = 8081
 socket_path = "/run/private/api.sock"
 trust_domain = "{DOMAIN}"
 data_dir = "/data"
 log_level = "ERROR"
}}
plugins {{
 DataStore "sql" {{ plugin_data {{ database_type = "sqlite3" connection_string = "/data/datastore.sqlite3" }} }}
 NodeAttestor "join_token" {{ plugin_data {{ }} }}
 KeyManager "memory" {{ plugin_data {{ }} }}
}}
'''}
        create(configuration)
        volumes = [{"name": "config", "configMap": {"name": PREFIX + "-config"}},
                   {"name": "data", "emptyDir": {"sizeLimit": "64Mi"}},
                   {"name": "run", "emptyDir": {"medium": "Memory", "sizeLimit": "8Mi"}}]
        mounts = [{"name": "config", "mountPath": "/config", "readOnly": True},
                  {"name": "data", "mountPath": "/data"}, {"name": "run", "mountPath": "/run"}]
        create(pod("-server", SERVER_IMAGE, "/opt/spire/bin/spire-server",
                   ["run", "-config", "/config/server.conf"], volumes, mounts))
        ready(PREFIX + "-server")
        server("healthcheck", "-socketPath", "/run/private/api.sock")
        root_ca = server("bundle", "show", "-socketPath", "/run/private/api.sock", "-format", "pem")
        service = item("Service", "-server", {"selector": {"app": PREFIX + "-server"},
            "ports": [{"name": "spire", "port": 8081, "targetPort": 8081}]})
        create(service)
        for role, subjects in (("gateway", [GATEWAY]), ("sandbox", [SANDBOX, OTHER])):
            enrollment = json.loads(server("token", "generate", "-socketPath", "/run/private/api.sock",
                "-ttl", "300", "-output", "json"))
            join_token = enrollment["value"]
            parent = f"spiffe://{DOMAIN}/spire/agent/join_token/{join_token}"
            secret = item("Secret", "-" + role + "-join")
            secret.update(type="Opaque", stringData={"token": join_token})
            create(secret)
            config = item("ConfigMap", "-" + role + "-config")
            config["data"] = {"root.pem": root_ca, "agent.conf": f'''agent {{
 data_dir = "/data"
 log_level = "ERROR"
 server_address = "{PREFIX}-server"
 server_port = 8081
 socket_path = "/run/public/api.sock"
 trust_bundle_path = "/config/root.pem"
 trust_domain = "{DOMAIN}"
}}
plugins {{
 NodeAttestor "join_token" {{ plugin_data {{ }} }}
 KeyManager "disk" {{ plugin_data {{ directory = "/data/keys" }} }}
 WorkloadAttestor "unix" {{ plugin_data {{ }} }}
}}
'''}
            create(config)
            for subject in subjects:
                server("entry", "create", "-socketPath", "/run/private/api.sock",
                       "-parentID", parent, "-spiffeID", subject, "-selector", "unix:uid:" + uid)
            agent_volumes = [{**v, "configMap": {"name": config["metadata"]["name"]}}
                             if v["name"] == "config" else v for v in volumes]
            create(pod("-" + role, AGENT_IMAGE, "/opt/spire/bin/spire-agent",
                ["run", "-config", "/config/agent.conf", "-joinToken", "$(JOIN_TOKEN)"],
                agent_volumes, mounts, [{"name": "JOIN_TOKEN", "valueFrom": {
                    "secretKeyRef": {"name": secret["metadata"]["name"], "key": "token"}}}]))
            ready(PREFIX + "-" + role)
        result["checkpoint"] = "fetch-real-svids"
        assertions = {subject: svid(subject) for subject in (GATEWAY, SANDBOX, OTHER)}
        public_bundle = json.loads(server("bundle", "show", "-socketPath", "/run/private/api.sock", "-format", "spiffe"))
        bundle_config = item("ConfigMap", "-bundle")
        bundle_config["data"] = {"bundle.json": json.dumps(public_bundle), "serve.py": '''from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
class Handler(BaseHTTPRequestHandler):
 def log_message(self, *args): pass
 def do_GET(self):
  if self.path != '/bundle.json': self.send_error(404); return
  data=Path('/bundle/bundle.json').read_bytes()
  self.send_response(200); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
HTTPServer(('0.0.0.0',8080),Handler).serve_forever()
'''}
        create(bundle_config)
        jira = json.loads(command(args, "get", "deployment", "fixture-jira", "-n", NAMESPACE, "-o", "json").stdout)
        if any(jira["metadata"].get("labels", {}).get(k) != v for k, v in LABELS.items()):
            raise ValueError("Owned pinned Python fixture image required")
        python_image = jira["spec"]["template"]["spec"]["containers"][0]["image"]
        if "@sha256:" not in python_image:
            raise ValueError("Digest-pinned Python fixture required")
        create(pod("-bundle", python_image, "python", ["-B", "/bundle/serve.py"],
            [{"name": "bundle", "configMap": {"name": PREFIX + "-bundle"}}],
            [{"name": "bundle", "mountPath": "/bundle", "readOnly": True}]))
        ready(PREFIX + "-bundle")
        create(item("Service", "-bundle", {"selector": {"app": PREFIX + "-bundle"},
            "ports": [{"name": "http", "port": 8080, "targetPort": 8080}]}))
        route = create(item("Route", "-bundle", {"to": {"kind": "Service", "name": PREFIX + "-bundle"},
            "port": {"targetPort": "http"},
            "tls": {"termination": "edge", "insecureEdgeTerminationPolicy": "Redirect"}}))
        for suffix, selector, direction, port in (
            ("-bundle-ingress", {"app": PREFIX + "-bundle"}, "ingress", 8080),
            ("-issuer-egress", {"app": "fixture-keycloak"}, "egress", 443)):
            policy = item("NetworkPolicy", suffix)
            policy["apiVersion"] = "networking.k8s.io/v1"
            policy["spec"] = {"podSelector": {"matchLabels": selector},
                "policyTypes": [direction.capitalize()], direction: [{
                    "from" if direction == "ingress" else "to": [{"namespaceSelector": {
                        "matchLabels": {"kubernetes.io/metadata.name": "openshift-ingress"}}}],
                    "ports": [{"protocol": "TCP", "port": port}]}]}
            create(policy)
        bundle_url = "https://" + route["spec"]["host"] + "/bundle.json"
        with urlopen(bundle_url, timeout=20) as response:
            observed = json.loads(response.read(1_000_000))
        if observed != public_bundle:
            raise ValueError("Verified HTTPS bundle differs from SPIRE public bundle")
        result["bundle_https_verified"] = True
        result["checkpoint"] = "keycloak-to-bundle-https"
        java_source = '''import java.net.*;
class BundleProbe {
 public static void main(String[] args) {
  try {
   var connection = (HttpURLConnection) URI.create(URL_VALUE).toURL().openConnection();
   connection.setConnectTimeout(7000); connection.setReadTimeout(7000);
   connection.setInstanceFollowRedirects(false);
   System.out.println("{\\"http_status\\":" + connection.getResponseCode() + "}");
  } catch(Exception error) {
   System.out.println("{\\"failure_kind\\":\\"" + error.getClass().getSimpleName() + "\\"}");
  }
 }
}
'''.replace("URL_VALUE", json.dumps(bundle_url))
        java_runner = '''set -eu
umask 077
bundle_probe_dir=$(mktemp -d /tmp/identity-bundle-probe.XXXXXX)
trap 'rm -rf -- "$bundle_probe_dir"' EXIT
cat > "$bundle_probe_dir/BundleProbe.java"
/usr/bin/java -Xms16m -Xmx64m "$bundle_probe_dir/BundleProbe.java"
'''
        def java_connectivity() -> dict:
            """Use the installed JVM's certificate validation from the actual issuer pod."""
            connection = subprocess.run(["oc", "--kubeconfig=" + args.kubeconfig, "exec", "-i",
                "-n", NAMESPACE, "deployment/fixture-keycloak", "--", "/bin/bash", "-c", java_runner],
                input=java_source, capture_output=True, text=True, timeout=30)
            if connection.returncode:
                raise RuntimeError("Owned issuer Java connectivity probe unavailable")
            return json.loads(connection.stdout)

        result["keycloak_bundle_connectivity"] = java_connectivity()
        if result["keycloak_bundle_connectivity"].get("failure_kind") == "SocketTimeoutException":
            # A public lab route can resolve to load-balancer addresses that do
            # not match an ingress namespace selector. This temporary allowance
            # covers only its exact current DNS addresses, never general egress.
            host = urlparse(bundle_url).hostname
            if not str(host).startswith(PREFIX + "-bundle-" + NAMESPACE + "."):
                raise ValueError("Owned bundle route hostname required")
            addresses = command(args, "exec", "-n", NAMESPACE, "deployment/fixture-keycloak",
                                "--", "/usr/bin/getent", "ahosts", host).stdout
            ips = {ipaddress.ip_address(line.split()[0]) for line in addresses.splitlines()}
            if not ips or any(ip.is_loopback or ip.is_multicast or ip.is_unspecified
                              or ip.is_link_local for ip in ips):
                raise ValueError("Usable owned route addresses required")
            policy = item("NetworkPolicy", "-issuer-route-addresses")
            policy["apiVersion"] = "networking.k8s.io/v1"
            policy["spec"] = {"podSelector": {"matchLabels": {"app": "fixture-keycloak"}},
                "policyTypes": ["Egress"], "egress": [{"to": [
                    {"ipBlock": {"cidr": str(ip) + ("/32" if ip.version == 4 else "/128")}}
                    for ip in sorted(ips, key=str)], "ports": [{"protocol": "TCP", "port": 443}]}]}
            create(policy)
            result["initial_keycloak_bundle_connectivity"] = result["keycloak_bundle_connectivity"]
            result["temporary_exact_route_egress_addresses"] = len(ips)
            time.sleep(2)
            result["keycloak_bundle_connectivity"] = java_connectivity()
        if result["keycloak_bundle_connectivity"].get("http_status") != 200:
            raise RuntimeError("Issuer cannot fetch the HTTPS SPIRE bundle")
        for subject, assertion in assertions.items():
            header = jwt.get_unverified_header(assertion)
            key = next(k for k in public_bundle["keys"] if k.get("kid") == header.get("kid"))
            claims = jwt.decode(assertion, jwt.PyJWK.from_dict(key).key,
                algorithms=["ES256", "ES384", "RS256"], audience=components.ISSUER,
                options={"require": ["sub", "aud", "exp"]})
            if claims["sub"] != subject:
                raise ValueError("SPIRE returned an unexpected identity")
        result["real_svid_signatures_verified"] = True
        result["jwt_svid_audience"] = "owned Keycloak realm issuer; not the token endpoint"
        result["checkpoint"] = "create-spiffe-provider"
        admin("/identity-provider/instances", "POST", {"alias": PROVIDER, "providerId": "spiffe",
            "enabled": True, "config": {"trustDomain": "spiffe://" + DOMAIN,
                "bundleEndpoint": bundle_url, "identity-demo-owner": active_profile().owner,
                "identity-demo-experiment": EXPERIMENT}})
        provider_created = True
        result["checkpoint"] = "create-federated-clients"
        roles = [admin("/roles/" + role) for role in ("analyst", "viewer")]
        audiences = {UI: GATEWAY, GATEWAY: SANDBOX, SANDBOX: MCP, OTHER: MCP}
        for name in (MCP, OTHER, SANDBOX, GATEWAY, UI):
            admin("/clients", "POST", federated_client(name, audiences.get(name)))
            matches = admin("/clients?" + urlencode({"clientId": name}))
            if len(matches) != 1:
                raise ValueError("Temporary client creation ambiguous")
            identifier = matches[0]["id"]
            clients.append((name, identifier))
            admin("/clients/" + identifier + "/scope-mappings/realm", "POST",
                  [{"id": role["id"], "name": role["name"]} for role in roles])
        human_subjects = []
        for user in ("analyst", "viewer"):
            result["checkpoint"] = user + "-pkce-login"
            original = components.login(user, credentials[user], client_id=UI)
            human = components.verify(original["access_token"], GATEWAY, issuer=components.ISSUER)
            human_subjects.append(human["sub"])
            identity = components.verify(original["id_token"], UI, issuer=components.ISSUER)
            if identity.get("nonce") != original["expected_nonce"] or identity["sub"] != human["sub"]:
                raise ValueError("Login nonce/subject mismatch")
            result["checkpoint"] = user + "-gateway-exchange"
            status, intermediate = exchange(original["access_token"], assertions[GATEWAY], SANDBOX)
            if status != 200:
                explicit_status, explicit = exchange(original["access_token"], assertions[GATEWAY],
                                                     SANDBOX, client_id=GATEWAY)
                result["explicit_client_id_control"] = {"http_status": explicit_status,
                    "access_token_returned": "access_token" in explicit,
                    "oauth_error": explicit.get("error") if explicit_status != 200 else None}
            record(user + ":gateway-svid-no-client-id", status, intermediate, True)
            mid = components.verify(intermediate["access_token"], SANDBOX, issuer=components.ISSUER)
            result["checkpoint"] = user + "-sandbox-exchange"
            status, final = exchange(intermediate["access_token"], assertions[SANDBOX], MCP)
            record(user + ":sandbox-svid-no-client-id", status, final, True)
            end = components.verify(final["access_token"], MCP, issuer=components.ISSUER)
            for claims, expected in ((mid, GATEWAY), (end, SANDBOX)):
                if (claims["sub"] != human["sub"] or claims.get("azp") != expected
                        or claims.get("realm_access", {}).get("roles") != [user]):
                    raise ValueError("Human/workload/permission preservation failed")
            result["claims"].append({"user": user, "human_subject_preserved": True,
                "final_azp": end["azp"], "final_aud": end["aud"],
                "roles": end["realm_access"]["roles"], "act_present": "act" in end,
                "cnf_present": "cnf" in end, "lifetime_seconds": end["exp"] - end["iat"]})
            # Both assertions are legitimately signed in the same domain. Audience
            # binding at the issuer must reject the wrong authenticated requester.
            bad_assertion = assertions[SANDBOX].split(".")
            bad_assertion[2] = ("A" if bad_assertion[2][0] != "A" else "B") + bad_assertion[2][1:]
            for case, subject, assertion, audience in (
                ("same-domain-other-requester", intermediate["access_token"], assertions[OTHER], MCP),
                ("wrong-svid-audience", intermediate["access_token"], svid(SANDBOX, "urn:fixture:wrong"), MCP),
                ("token-endpoint-is-not-svid-audience", intermediate["access_token"], svid(SANDBOX, endpoint), MCP),
                ("invalid-svid-signature", intermediate["access_token"], ".".join(bad_assertion), MCP),
                ("malformed-svid", intermediate["access_token"], "not-a-jwt", MCP),
                ("wrong-user-token-recipient", original["access_token"], assertions[SANDBOX], MCP),
                ("unconfigured-target", original["access_token"], assertions[GATEWAY], MCP)):
                result["checkpoint"] = user + ":" + case
                status, denied = exchange(subject, assertion, audience)
                record(user + ":" + case, status, denied, False)
            status, reused = exchange(intermediate["access_token"], assertions[SANDBOX], MCP)
            record(user + ":svid-reuse-is-allowed", status, reused, True)
        if len(set(human_subjects)) != 2:
            raise ValueError("Distinct authenticated human subjects required")
        result["both_users_distinct"] = True
        result["spiffe_client_authentication_proven"] = True
        result["assertion_based_lookup_without_client_id_proven"] = True
    except Exception as error:
        result["errors"].append({"stage": "experiment", "failure_kind": type(error).__name__,
            "missing_key": error.args[0] if isinstance(error, KeyError) else None,
            "diagnostics": getattr(error, "safe_diagnostics", None),
            "details_withheld": True})
    finally:
        for name, identifier in reversed(clients):
            try:
                current = admin("/clients/" + identifier)
                attrs = current.get("attributes", {})
                if (current["clientId"] != name or attrs.get("identity-demo-owner") != active_profile().owner
                        or attrs.get("identity-demo-experiment") != EXPERIMENT):
                    raise ValueError("Client cleanup ownership mismatch")
                admin("/clients/" + identifier, "DELETE")
            except Exception as error:
                result["errors"].append({"stage": "client-cleanup", "failure_kind": type(error).__name__})
        if provider_created:
            try:
                current = admin("/identity-provider/instances/" + PROVIDER)
                if (current["alias"] != PROVIDER or current["config"].get("identity-demo-owner") != active_profile().owner
                        or current["config"].get("identity-demo-experiment") != EXPERIMENT):
                    raise ValueError("Provider cleanup ownership mismatch")
                admin("/identity-provider/instances/" + PROVIDER, "DELETE")
            except Exception as error:
                result["errors"].append({"stage": "provider-cleanup", "failure_kind": type(error).__name__})
        for value, uid in reversed(created):
            try:
                kind, name = value["kind"].lower(), value["metadata"]["name"]
                found = command(args, "get", kind, name, "-n", NAMESPACE,
                                "--ignore-not-found", "-o", "json").stdout
                if not found.strip():
                    continue
                metadata = json.loads(found)["metadata"]
                if (metadata["uid"] != uid or any(metadata.get("labels", {}).get(k) != v
                        for k, v in value["metadata"]["labels"].items())):
                    raise ValueError("Kubernetes cleanup ownership mismatch")
                # UID preconditions prevent deleting a replacement with the same name.
                version = value["apiVersion"]
                root = "/api/v1" if version == "v1" else "/apis/" + version
                plural = {"NetworkPolicy": "networkpolicies"}.get(value["kind"], kind + "s")
                path = root + "/namespaces/" + NAMESPACE + "/" + plural + "/" + name
                command(args, "delete", "--raw", path, "-f", "-", payload={
                    "apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": uid}})
            except Exception as error:
                result["errors"].append({"stage": "resource-cleanup", "kind": value["kind"],
                    "name": value["metadata"]["name"], "failure_kind": type(error).__name__})
        result["existing_clients_unchanged"] = issuer_probe.fingerprint(admin("/clients")) == issuer_probe.fingerprint(before_clients)
        after_providers = admin("/identity-provider/instances")
        result["existing_providers_unchanged"] = (sorted(after_providers, key=lambda v: v["alias"])
            == sorted(before_providers, key=lambda v: v["alias"]))
        result["temporary_resources_created"] = len(created)
        deadline = time.monotonic() + 45
        while True:
            remaining = command(args, "get", "pod,configmap,secret,service,route,networkpolicy",
                "-n", NAMESPACE, "-l", "identity-demo-experiment=" + EXPERIMENT, "-o", "name").stdout
            if not remaining.strip() or time.monotonic() >= deadline:
                break
            time.sleep(2)
        result["temporary_resources_removed"] = not remaining.strip()
        result["cleanup_passed"] = (result["temporary_resources_removed"]
            and not any("cleanup" in e["stage"] for e in result["errors"]))
    result["passed"] = (not result["errors"] and result["existing_clients_unchanged"]
        and result["existing_providers_unchanged"] and result["cleanup_passed"]
        and len(result["cases"]) == 20
        and all(case["passed"] for case in result["cases"]))
    return result


def main() -> None:
    """Print sanitized pass/fail evidence; retain no issued credentials."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("kubeconfig", "expected-server", "credentials-file"):
        parser.add_argument("--" + name, required=True)
    try:
        result = run(parser.parse_args())
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result["passed"] else 1)
    except Exception as error:
        print(json.dumps({"passed": False, "failure_kind": type(error).__name__, "details_withheld": True}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
