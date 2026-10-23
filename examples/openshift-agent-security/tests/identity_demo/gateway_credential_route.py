# SPDX-License-Identifier: Apache-2.0
"""Render an owned, disposable gateway credential-route experiment.

The experiment authenticates a real fixture human, then mediates an adapter
service credential. It does not prove native user/workload/run or sender binding.
No existing HTTPRoute/AuthPolicy is patched; existing virtual hosts disable the
additional filter. Secret material must be applied and retained only privately.
"""

from __future__ import annotations

import base64
from copy import deepcopy
import json

from probe_broker_discovery import NS
from identity_demo_keycloak_upstream import BASE
from identity_demo_lab import LABELS
from run_binding import ReadRun, authorization as run_authorization
from deployment_profile import active_profile

NAME = "fixture-gateway-grant-route"
HOST = NAME + ".fixture-mcp.local"
FILTER = "identity-demo.adapter-credential"
CLUSTER = "identity-demo.adapter-authorino"
ADAPTER = active_profile().service_host("fixture-protected-adapter")
AUTHORIZER = "authorino-authorino-authorization.kuadrant-system.svc"
READ_NAME = "fixture-step4-read-route"
READ_HOST = READ_NAME + ".fixture-mcp.local"
HUMAN_ISSUER = active_profile().origin("fixture-keycloak") + "/realms/identity-demo"


def resource(api: str, kind: str, spec: dict | None = None) -> dict:
    """Render only one exact disposable name in the owned namespace."""
    value = {"apiVersion": api, "kind": kind,
             "metadata": {"name": NAME, "namespace": NS, "labels": dict(LABELS)}}
    if spec is not None:
        value["spec"] = spec
    return value


def tls_context(host: str, ca: str) -> dict:
    """Require a named server and explicit public trust, without a client key."""
    return {"name": "envoy.transport_sockets.tls", "typed_config": {
        "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
        "sni": host, "common_tls_context": {
            "tls_params": {"tls_minimum_protocol_version": "TLSv1_2"},
            "validation_context": {"trusted_ca": {"inline_string": ca},
                "match_typed_subject_alt_names": [{"san_type": "DNS", "matcher": {"exact": host}}]},
        },
    }}


def manifests(ca: str, client_secret: str) -> list[dict]:
    """Build a reviewable bounded integration without weakening existing routes."""
    if not ca.startswith("-----BEGIN CERTIFICATE-----") or not client_secret:
        raise ValueError("Explicit public CA and private fixture credential required")
    secret = resource("v1", "Secret")
    secret.update(type="Opaque", stringData={"basic": base64.b64encode(
        ("fixture-gateway-service:" + client_secret).encode()).decode()})
    allowed = (
        "has(auth.identity.azp) && auth.identity.azp == 'identity-demo-ui' && "
        "has(auth.identity.realm_access) && has(auth.identity.realm_access.roles) && "
        "'analyst' in auth.identity.realm_access.roles && request.path == '/mcp' && "
        "request.method in ['GET', 'POST', 'DELETE']"
    )
    auth = resource("authorino.kuadrant.io/v1beta3", "AuthConfig", {
        "hosts": [HOST],
        "authentication": {"human": {"jwt": {"issuerUrl": HUMAN_ISSUER,
            "issuer": HUMAN_ISSUER, "audiences": ["identity-demo-mcp"], "ttl": 60}}},
        "metadata": {"adapter-token": {"when": [{"predicate": allowed}], "http": {
            "url": BASE + "/realms/identity-demo/protocol/openid-connect/token",
            "method": "POST", "contentType": "application/x-www-form-urlencoded", "timeout": 3000,
            "sharedSecretRef": {"name": NAME, "key": "basic"},
            "credentials": {"authorizationHeader": {"prefix": "Basic"}},
            "bodyParameters": {"grant_type": {"value": "client_credentials"},
                               "scope": {"value": "mcp:read"}},
        }}},
        "authorization": {
            "analyst-read": {"patternMatching": {"patterns": [{"predicate": allowed}]}},
            "grant-result": {"patternMatching": {"patterns": [{"predicate": (
                "has(auth.metadata['adapter-token'].access_token) && "
                "type(auth.metadata['adapter-token'].access_token) == string && "
                "auth.metadata['adapter-token'].access_token != '' && "
                "auth.metadata['adapter-token'].token_type == 'Bearer' && "
                "auth.metadata['adapter-token'].expires_in > 0 && "
                "auth.metadata['adapter-token'].expires_in <= 30"
            )}]}},
        },
        "response": {"success": {"headers": {"Authorization": {
            "plain": {"expression": "'Bearer ' + auth.metadata['adapter-token'].access_token"}}}}},
    })
    route = resource("gateway.networking.k8s.io/v1", "HTTPRoute", {
        "parentRefs": [{"name": "fixture-mcp", "sectionName": "mcps"}], "hostnames": [HOST],
        "rules": [{"matches": [{"path": {"type": "Exact", "value": "/mcp"}}],
                   "filters": [{"type": "URLRewrite", "urlRewrite": {"hostname": ADAPTER}}],
                   "backendRefs": [{"name": "fixture-protected-adapter", "port": 8443}]}],
    })
    disabled = {"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
                "disabled": True}
    enabled = dict(disabled, disabled=False)
    patches = [
        {"applyTo": "CLUSTER", "match": {"context": "GATEWAY"}, "patch": {
            "operation": "ADD", "value": {"name": CLUSTER, "type": "STRICT_DNS",
                "connect_timeout": "3s", "http2_protocol_options": {},
                "load_assignment": {"cluster_name": CLUSTER, "endpoints": [{"lb_endpoints": [{
                    "endpoint": {"address": {"socket_address": {
                        "address": AUTHORIZER, "port_value": 50051}}}}]}]},
                "transport_socket": tls_context(AUTHORIZER, ca),
            }}},
        {"applyTo": "CLUSTER", "match": {"context": "GATEWAY", "cluster": {
            "service": ADAPTER, "portNumber": 8443}}, "patch": {"operation": "MERGE", "value": {
                "transport_socket": tls_context(ADAPTER, ca)}}},
        {"applyTo": "HTTP_FILTER", "match": {"context": "GATEWAY", "listener": {
            "portNumber": 8080, "filterChain": {"filter": {"name": "envoy.filters.network.http_connection_manager",
                "subFilter": {"name": "envoy.filters.http.router"}}}}},
         "patch": {"operation": "INSERT_BEFORE", "value": {"name": FILTER, "typed_config": {
             "@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz",
             "transport_api_version": "V3", "failure_mode_allow": False, "clear_route_cache": False,
             "stat_prefix": "identity_demo_adapter",
             "grpc_service": {"envoy_grpc": {"cluster_name": CLUSTER}, "timeout": "5s"},
             "with_request_body": {"max_request_bytes": 65536, "allow_partial_message": False},
         }}}},
        {"applyTo": "VIRTUAL_HOST", "match": {"context": "GATEWAY", "routeConfiguration": {
            "portNumber": 8080}}, "patch": {"operation": "MERGE", "value": {
                "typed_per_filter_config": {FILTER: disabled}}}},
        {"applyTo": "VIRTUAL_HOST", "match": {"context": "GATEWAY", "routeConfiguration": {
            "portNumber": 8080, "vhost": {"name": HOST + ":8080"}}}, "patch": {
                "operation": "MERGE", "value": {"typed_per_filter_config": {FILTER: enabled}}}},
    ]
    envoy_filter = resource("networking.istio.io/v1alpha3", "EnvoyFilter", {
        "workloadSelector": {"labels": {"gateway.networking.k8s.io/gateway-name": "fixture-mcp",
            **LABELS}},
        "configPatches": patches,
    })
    return [secret, auth, route, envoy_filter]


def native_manifests(ca: str, client_secret: str, run: ReadRun) -> list[dict]:
    """Mediate one native run's read credential on a private broker-only route.

The bound frontend checks the actual TLS certificate. This second boundary
verifies the same signed user/workload/run token before replacing Authorization.
It requires live proof that only the trusted broker can reach the private route;
it must never be exposed as an alternative bearer-only agent entrypoint.
"""
    values = deepcopy(manifests(ca, client_secret))
    replacements = {NAME: READ_NAME, HOST: READ_HOST, FILTER: FILTER + "-step4",
                    CLUSTER: CLUSTER + "-step4", HOST + ":8080": READ_HOST + ":8080"}

    def replace(value: object) -> object:
        if isinstance(value, dict):
            return {replacements.get(k, k): replace(v) for k, v in value.items()}
        if isinstance(value, list):
            return [replace(v) for v in value]
        if isinstance(value, str):
            return replacements.get(value, value)
        return value

    values = replace(values)
    auth = values[1]["spec"]
    authorization_host = active_profile().private_mcp_authorization_host
    auth['hosts'] = [authorization_host]
    if authorization_host != READ_HOST:
        # The broker's HTTPRoute host stays private and stable. Select our
        # namespace-specific AuthConfig through Envoy's trusted context, never
        # through a caller-supplied header. CheckSettings and disabled are oneof.
        for item in values[3]['spec']['configPatches']:
            if item['applyTo'] == 'VIRTUAL_HOST' and item['match']['routeConfiguration'].get('vhost',{}).get('name') == READ_HOST+':8080':
                config = item['patch']['value']['typed_per_filter_config'][FILTER+'-step4']
                config.pop('disabled',None)
                config['check_settings'] = {'context_extensions':{'host':authorization_host}}
    auth["authentication"]["human"]["jwt"].update(
        issuerUrl=run.issuer, issuer=run.issuer, audiences=[run.audience])
    allowed = (
        str(run.active).lower() + " && has(auth.identity.iss) && auth.identity.iss == "
        + json.dumps(run.issuer) + " && has(auth.identity.sub) && auth.identity.sub == "
        + json.dumps(run.user_subject) + " && has(auth.identity.azp) && auth.identity.azp == "
        + json.dumps(run.workload) + " && has(auth.identity.iat) && int(auth.identity.iat) >= "
        + str(run.not_before) + " && has(auth.identity.exp) && int(auth.identity.exp) <= "
        + str(run.expires_at) + " && int(auth.identity.exp) > int(auth.identity.iat)"
        + " && int(auth.identity.exp) - int(auth.identity.iat) <= 30"
        + " && has(auth.identity.cnf) && 'x5t#S256' in auth.identity.cnf"
        + " && has(auth.identity.realm_access) && has(auth.identity.realm_access.roles)"
        + " && 'analyst' in auth.identity.realm_access.roles"
        + " && request.path == '/mcp' && request.method in ['GET', 'POST', 'DELETE']"
    )
    auth["metadata"]["adapter-token"]["when"] = [{"predicate": allowed}]
    del auth["authorization"]["analyst-read"]
    auth["authorization"]["native-read-identity"] = {
        "patternMatching": {"patterns": [{"predicate": allowed}]}}
    # This is the private broker boundary. The mandatory certificate comparison
    # remains on the external bound frontend; topology must enforce this split.
    auth["authorization"]["native-read-run"] = run_authorization(
        [run], require_sender_binding=True)
    # Bounded development diagnostics expose only booleans on denials, never
    # credentials or claims. These disposable resources are removed by the probe.
    auth["response"]["unauthorized"] = {"headers": {
        "x-step4-identity": {"expression": "string(" + allowed + ")"},
        "x-step4-peer": {"expression": "string('x-forwarded-client-cert' in request.headers)"},
        "x-step4-grant": {"expression": "string(has(auth.metadata['adapter-token'].access_token))"},
    }}
    auth["response"]["success"]["dynamicMetadata"] = {"step4-audit": {
        "key": "step4", "json": {"properties": {
            "user": {"selector": "auth.identity.sub"},
            "workload": {"selector": "auth.identity.azp"},
            "cnf": {"expression": "auth.identity.cnf['x5t#S256']"},
            "run": {"value": run.run_id}, "policy": {"value": "step4-protected-read"},
            "expiry": {"selector": "auth.identity.exp"},
        }}}}
    # Original requests retain the actual verified TLS peer. The broker's
    # private initialization forwards that already verified header. Only the
    # trusted broker reaches this HTTP listener; arbitrary Pods are denied.
    values[2]["spec"]["parentRefs"].append({"name": "fixture-mcp", "sectionName": "bound"})
    http = next(p for p in values[3]["spec"]["configPatches"] if p["applyTo"] == "HTTP_FILTER")
    bound_http = deepcopy(http)
    bound_http["match"]["listener"]["portNumber"] = 8443
    values[3]["spec"]["configPatches"].append(bound_http)
    for patch in list(values[3]["spec"]["configPatches"]):
        if patch["applyTo"] == "VIRTUAL_HOST":
            bound_patch = deepcopy(patch)
            config = bound_patch["match"]["routeConfiguration"]
            config["portNumber"] = 8443
            if "vhost" in config:
                config["vhost"]["name"] = READ_HOST + ":8443"
            values[3]["spec"]["configPatches"].append(bound_patch)
    values[3]["spec"]["configPatches"].append({
        "applyTo": "NETWORK_FILTER", "match": {"context": "GATEWAY", "listener": {
            "portNumber": 8080, "filterChain": {"filter": {
                "name": "envoy.filters.network.http_connection_manager"}}}},
        "patch": {"operation": "MERGE", "value": {
            "name": "envoy.filters.network.http_connection_manager", "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
                # Envoy FORWARD_ONLY requires an mTLS downstream connection and
                # strips this verified peer on the broker's private HTTP hop.
                # Only the network-isolated trusted broker reaches port 8080.
                "forward_client_cert_details": "ALWAYS_FORWARD_ONLY",
                "access_log": [{"name": "envoy.access_loggers.stdout", "typed_config": {
                    "@type": "type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog",
                    "log_format": {"json_format": {"event": "step4-private-read",
                        "status": "%RESPONSE_CODE%", "detail": "%RESPONSE_CODE_DETAILS%",
                        "upstream": "%UPSTREAM_CLUSTER%", "request": "%REQ(X-REQUEST-ID)%",
                        "peer_hash": "%DOWNSTREAM_PEER_FINGERPRINT_256%",
                        "denied_identity": "%RESP(X-STEP4-IDENTITY)%",
                        "denied_peer": "%RESP(X-STEP4-PEER)%",
                        "denied_grant": "%RESP(X-STEP4-GRANT)%",
                        "verified": "%DYNAMIC_METADATA(envoy.filters.http.ext_authz:step4)%"}}}}],
            }}}})
    bound_log = deepcopy(values[3]["spec"]["configPatches"][-1])
    bound_log["match"]["listener"]["portNumber"] = 8443
    bound_log["patch"]["value"]["typed_config"].pop("forward_client_cert_details")
    values[3]["spec"]["configPatches"].append(bound_log)
    return values
