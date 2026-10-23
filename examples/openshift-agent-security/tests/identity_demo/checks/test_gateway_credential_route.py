# SPDX-License-Identifier: Apache-2.0
"""Offline ownership and fail-closed checks for the credential-route candidate."""

from __future__ import annotations

import json

import pytest

import gateway_credential_route as route
import probe_gateway_credential_route as probe
from run_binding import ReadRun
from native_backend import resource_kind


def test_native_resource_lookup_pins_api_group() -> None:
    """A same-name CRD in another group cannot hide or bypass owned cleanup."""
    assert resource_kind({"kind": "MCPServerRegistration", "apiVersion": "mcp.kuadrant.io/v1alpha1"}) == (
        "mcpserverregistration.mcp.kuadrant.io")
    assert resource_kind({"kind": "Secret", "apiVersion": "v1"}) == "secret"


def test_candidate_resources_are_namespaced_and_exactly_owned() -> None:
    """No generated AuthConfig or Secret can enter a shared namespace."""
    values = route.manifests("-----BEGIN CERTIFICATE-----\nfixture\n", "synthetic-private-secret")
    assert len(values) == 4
    for value in values:
        assert value["metadata"]["namespace"] == route.NS
        assert value["metadata"]["name"] == route.NAME
        assert all(value["metadata"]["labels"].get(k) == v for k, v in route.LABELS.items())
    assert "stringData" not in values[1]


def test_filter_preserves_public_hosts_and_runs_after_existing_authorization() -> None:
    """Only the new diagnostic virtual host enables credential replacement."""
    spec = route.manifests("-----BEGIN CERTIFICATE-----\nfixture\n", "synthetic")[3]["spec"]
    assert spec["workloadSelector"]["labels"]["identity-demo-owner"] == "demo-team"
    patches = spec["configPatches"]
    http_filter = next(p for p in patches if p["applyTo"] == "HTTP_FILTER")
    assert http_filter["match"]["listener"]["filterChain"]["filter"]["subFilter"]["name"] == (
        "envoy.filters.http.router")
    config = http_filter["patch"]["value"]["typed_config"]
    assert config["failure_mode_allow"] is False
    assert config["clear_route_cache"] is False
    assert config["with_request_body"]["allow_partial_message"] is False
    virtual_hosts = [p for p in patches if p["applyTo"] == "VIRTUAL_HOST"]
    assert len(virtual_hosts) == 2
    assert virtual_hosts[0]["patch"]["value"]["typed_per_filter_config"][route.FILTER]["disabled"] is True
    assert virtual_hosts[1]["match"]["routeConfiguration"]["vhost"]["name"] == route.HOST + ":8080"
    assert virtual_hosts[1]["patch"]["value"]["typed_per_filter_config"][route.FILTER]["disabled"] is False


@pytest.mark.parametrize("host", [route.ADAPTER, route.AUTHORIZER])
def test_tls_always_checks_public_ca_and_exact_server_name(host: str) -> None:
    """An empty TLS validation context is not accepted as verified HTTPS."""
    tls = route.tls_context(host, "public-ca")["typed_config"]
    assert tls["sni"] == host
    validation = tls["common_tls_context"]["validation_context"]
    assert validation["trusted_ca"]["inline_string"] == "public-ca"
    assert validation["match_typed_subject_alt_names"] == [{
        "san_type": "DNS", "matcher": {"exact": host}}]


@pytest.mark.parametrize("ca,secret", [("", "synthetic"), ("public-ca", "synthetic"),
                                       ("-----BEGIN CERTIFICATE-----\n", "")])
def test_missing_trust_or_private_credential_rejected(ca: str, secret: str) -> None:
    """Candidate construction fails before Kubernetes without required inputs."""
    with pytest.raises(ValueError):
        route.manifests(ca, secret)


@pytest.mark.parametrize("change", [None, "uid", "name", "labels"])
def test_gateway_owner_ref_without_controller_flag_still_requires_exact_ownership(change: str | None) -> None:
    """The installed owner-reference shape does not permit unrelated resources."""
    gateway = {"metadata": {"name": "fixture-mcp", "uid": "owned-gateway"}}
    deployment = {"metadata": {"labels": dict(route.LABELS), "ownerReferences": [
        {"kind": "Gateway", "name": "fixture-mcp", "uid": "owned-gateway"}]}}
    if change in ("uid", "name"):
        deployment["metadata"]["ownerReferences"][0][change] = "different-owner"
    elif change == "labels":
        deployment["metadata"]["labels"] = {}
    assert probe.owned_gateway_deployment(deployment, gateway) is (change is None)


def test_missing_effective_filter_cannot_authorize_sending_credentials() -> None:
    """Rendered YAML and server dry-run cannot replace effective Envoy evidence."""
    assert not any(probe.configuration_checks({}, "public-ca").values())


def test_native_backend_requires_verified_run_before_replacing_credentials() -> None:
    """The private grant checks signed user/workload context, lifetime and run state."""
    run = ReadRun("test-run", "https://issuer.example.test/realms/demo", "analyst",
                  "spiffe://demo.example.test/openshell/sandbox/test", "https://mcp.example.test/mcp", 100, 300)
    values = route.native_manifests("-----BEGIN CERTIFICATE-----\nfixture\n", "synthetic", run)
    assert all(v["metadata"]["name"] == route.READ_NAME for v in values)
    spec = values[1]["spec"]
    assert spec["hosts"] == [route.READ_HOST]
    assert spec["authentication"]["human"]["jwt"]["audiences"] == [run.audience]
    predicate = spec["metadata"]["adapter-token"]["when"][0]["predicate"]
    assert run.user_subject in predicate and run.workload in predicate
    assert "int(auth.identity.exp) <= 300" in predicate and "auth.identity.cnf" in predicate
    assert "binding.active == true" in spec["authorization"]["native-read-run"]["opa"]["rego"]
    assert spec["metadata"]["adapter-token"]["http"]["sharedSecretRef"]["name"] == route.READ_NAME
    # The actual TLS peer is checked on both bound hosts; the private listener
    # receives its already verified header only from the trusted broker.
    assert "x-forwarded-client-cert" in spec["authorization"]["native-read-run"]["opa"]["rego"]
    assert values[2]["spec"]["parentRefs"][-1]["sectionName"] == "bound"
    patches = values[3]["spec"]["configPatches"]
    private_hcm = next(p for p in patches if p["applyTo"] == "NETWORK_FILTER"
                       and p["match"]["listener"]["portNumber"] == 8080)
    assert private_hcm["patch"]["value"]["typed_config"]["forward_client_cert_details"] == "ALWAYS_FORWARD_ONLY"
    bound_hcm = next(p for p in patches if p["applyTo"] == "NETWORK_FILTER"
                     and p["match"]["listener"]["portNumber"] == 8443)
    assert "forward_client_cert_details" not in bound_hcm["patch"]["value"]["typed_config"]


def test_broker_initialization_is_not_protected_adapter_evidence() -> None:
    """HTTP 200 and a syntactically valid response cannot promote the wrong backend."""
    response = {"http_status": 200, "body": json.dumps({"jsonrpc": "2.0", "id": 44,
        "result": {"serverInfo": {"name": "Kuadrant MCP Gateway"}}})}
    assert not probe.initialized_expected_adapter(response)
    response["body"] = json.dumps({"jsonrpc": "2.0", "id": 44,
        "result": {"serverInfo": {"name": "identity-demo-protected-jira"}}})
    assert probe.initialized_expected_adapter(response)
    response["http_status"] = 403
    assert not probe.initialized_expected_adapter(response)


@pytest.mark.parametrize("observations,expected", [
    ([{"operation": "tools/call", "http_status": 403, "error_body": '{"error":"Forbidden"}'}], True),
    ([{"operation": "tools/call", "http_status": 403, "error_body": "Forbidden"}], True),
    ([{"operation": "initialize", "http_status": 403}], False),
    ([{"operation": "tools/call", "http_status": 500}], False),
    ([{"operation": "tools/call", "http_status": 200}], False),
    ([{"operation": "tools/call", "http_status": 403, "error_body": '{"result":{"issues":[]}}'}], False),
    ([{"operation": "tools/call", "http_status": 403, "error_body_truncated": True}], False),
    ([], False),
])
def test_viewer_rejection_must_reach_actual_tool_boundary(observations: list[dict], expected: bool) -> None:
    """Initialization failure, bad status and leaked tool results are not acceptance."""
    assert probe.explicit_tool_denial(observations) is expected


def test_disposable_route_targets_the_configured_owner(monkeypatch):
    labels = {"identity-demo-owner": "customer-owner", "app.kubernetes.io/part-of": "identity-demo-preflight"}
    monkeypatch.setattr(route, "LABELS", labels)
    values = route.manifests("-----BEGIN CERTIFICATE-----\nfixture\n", "synthetic")
    selector = values[3]["spec"]["workloadSelector"]["labels"]
    assert all(selector[key] == value for key, value in labels.items())
    assert selector["gateway.networking.k8s.io/gateway-name"] == "fixture-mcp"
    assert values[3]["metadata"]["labels"] == labels
