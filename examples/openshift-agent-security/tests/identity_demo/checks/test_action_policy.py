# SPDX-License-Identifier: Apache-2.0
"""Assert decision sequencing without claiming gateway runtime acceptance."""

from copy import deepcopy

import pytest

from identity_demo_action_policy import ALLOWED, adapter_rules, identity_rules


def test_owned_frontend_selects_the_configured_customer_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    """A portable installation must not select the original lab owner's Pods."""
    import identity_demo_action_policy as policy
    from deployment_profile import DeploymentProfile, LEGACY

    profile = DeploymentProfile.from_dict({**LEGACY.to_dict(), "owner": "demo-team",
                                          "core_namespace": "customer-eval"})
    monkeypatch.setattr(policy, "active_profile", lambda: profile)
    audience = "https://" + profile.service_host("fixture-mcp-bound") + "/mcp"
    config, envoy = policy.owned_frontend("-----BEGIN CERTIFICATE-----", "https://issuer.example", audience)
    assert all(value["metadata"]["namespace"] == profile.core_namespace for value in (config, envoy))
    assert all(value["metadata"]["labels"] == profile.labels for value in (config, envoy))
    assert envoy["spec"]["workloadSelector"]["labels"]["identity-demo-owner"] == profile.owner
    assert config["spec"]["hosts"] == [profile.service_host("fixture-mcp-bound")]


def private_spec() -> dict:
    """Provide only the existing private-route contract needed by the renderer."""
    return {
        "hosts": ["fixture-step4-read-route.fixture-mcp.local"],
        "authentication": {"human": {"jwt": {"issuer": "https://issuer.example"}}},
        "metadata": {
            "adapter-token": {
                "http": {
                    "url": "https://issuer.example/token",
                    "bodyParameters": {"scope": {"value": "mcp:read"}},
                }
            }
        },
        "authorization": {
            "grant-result": {"patternMatching": {"patterns": [{"predicate": "true"}]}},
            "old-diagnostic": {},
        },
        "response": {
            "success": {
                "headers": {
                    "Authorization": {
                        "plain": {
                            "expression": "'Bearer ' + auth.metadata['adapter-token'].access_token"
                        }
                    }
                }
            }
        },
    }


def test_decision_is_uncached_and_precedes_credential_grant() -> None:
    """An independent metadata lookup must complete before credentials are requested."""
    before = private_spec()
    saved = deepcopy(before)
    spec = adapter_rules(before)
    assert before == saved
    decision, grant = (
        spec["metadata"]["driver-decision"],
        spec["metadata"]["adapter-token"],
    )
    assert decision["priority"] < grant["priority"]
    assert "cache" not in decision
    assert grant["when"] == [{"predicate": ALLOWED}]
    assert decision["http"]["sharedSecretRef"]["key"] == "gateway_secret"
    assert "body" not in decision["http"]
    assert decision["http"]["bodyParameters"] == {"context": {"selector": "context"}}
    assert spec["authorization"]["live-action"]["patternMatching"]["patterns"] == [
        {"predicate": ALLOWED}
    ]


def test_frontend_checks_live_identity_and_exact_jwt_recipient() -> None:
    """A frontend check cannot replace the later complete-body action decision."""
    rules = identity_rules("https://issuer.example", "https://mcp.example/mcp")
    assert (
        rules["authentication"]["keycloak"]["jwt"]["issuer"] == "https://issuer.example"
    )
    assert rules["authentication"]["keycloak"]["jwt"]["audiences"] == [
        "https://mcp.example/mcp"
    ]
    assert rules["metadata"]["driver-decision"]["http"]["url"].endswith(
        "/internal/identity"
    )
    assert adapter_rules(private_spec())["metadata"]["driver-decision"]["http"][
        "url"
    ].endswith("/internal/authorize")


def test_write_scope_is_conditional_on_an_authorized_action() -> None:
    """Keep reads read-only; only an allowed action requests the create scope."""
    before = private_spec()
    read = adapter_rules(before)
    write = adapter_rules(before, write_scope=True)
    assert read["metadata"]["adapter-token"]["http"]["bodyParameters"]["scope"] == {
        "value": "mcp:read"
    }
    grant = write["metadata"]["adapter-token"]
    assert grant["when"] == [{"predicate": ALLOWED}]
    assert grant["http"]["bodyParameters"]["scope"] == {
        "expression": "has(auth.metadata['driver-decision'].action_id) ? 'mcp:read mcp:create' : 'mcp:read'"
    }
    assert before == private_spec()


@pytest.mark.parametrize("change", ["host", "grant"])
def test_renderer_refuses_unexpected_receiving_boundary(change: str) -> None:
    """Do not silently convert an unrelated route or grant configuration."""
    spec = private_spec()
    if change == "host":
        spec["hosts"] = ["other-owner.example"]
    else:
        spec["metadata"]["unexpected"] = {}
    with pytest.raises(ValueError):
        adapter_rules(spec)


def test_owned_frontend_keeps_secret_local_and_runs_before_mcp() -> None:
    """Do not move scoped credentials to a shared generated AuthConfig."""
    from identity_demo_action_policy import owned_frontend

    ca = "-----BEGIN CERTIFICATE-----\nsynthetic\n-----END CERTIFICATE-----"
    config, envoy = owned_frontend(
        ca,
        "https://issuer.example",
        "https://fixture-mcp-bound.demo-core.svc.cluster.local/mcp",
    )
    assert config["metadata"]["namespace"] == "demo-core"
    assert config["spec"]["metadata"]["driver-decision"]["http"]["url"].endswith(
        "/internal/authorize"
    )
    assert config["spec"]["metadata"]["driver-decision"]["http"]["bodyParameters"] == {
        "context": {"selector": "context"}
    }
    assert "x-demo-denial" in config["spec"]["response"]["unauthorized"]["headers"]
    assert (
        config["spec"]["metadata"]["driver-decision"]["http"]["sharedSecretRef"]["name"]
        == "fixture-identity-driver-credentials"
    )
    patch, disabled, enabled = envoy["spec"]["configPatches"]
    assert patch["match"]["listener"]["portNumber"] == 8443
    assert (
        patch["match"]["listener"]["filterChain"]["filter"]["subFilter"]["name"]
        == "envoy.filters.http.ext_proc"
    )
    assert patch["patch"]["operation"] == "INSERT_BEFORE"
    assert patch["patch"]["value"]["typed_config"]["failure_mode_allow"] is False
    name = patch["patch"]["value"]["name"]
    assert (
        disabled["patch"]["value"]["typed_per_filter_config"][name]["disabled"] is True
    )
    assert (
        enabled["patch"]["value"]["typed_per_filter_config"][name]["disabled"] is False
    )
    assert (
        enabled["match"]["routeConfiguration"]["vhost"]["name"]
        == "fixture-mcp-bound.demo-core.svc.cluster.local:8443"
    )
