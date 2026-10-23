# SPDX-License-Identifier: Apache-2.0
"""Render durable decision hooks for the existing owned gateway/Authorino path.

The frontend checks live identity before MCP routing. The accepted private
ext_authz filter forwards the complete routed body and checks approval before
credential mediation/adapter execution. Rendering does not establish live proof.
"""

from __future__ import annotations

from copy import deepcopy
from deployment_profile import active_profile

DRIVER = active_profile().origin("fixture-identity-driver")
SECRET = "fixture-identity-driver-credentials"
ALLOWED = "has(auth.metadata['driver-decision'].allowed) && auth.metadata['driver-decision'].allowed == true"


def decision_metadata(endpoint: str) -> dict:
    """Use an uncached live lookup and a referenced scoped Secret, never inline keys."""
    if endpoint not in ("identity", "authorize"):
        raise ValueError("Fixed driver decision endpoint required")
    return {
        "priority": 0,
        "http": {
            "url": DRIVER + "/internal/" + endpoint,
            "method": "POST",
            "contentType": "application/json",
            "timeout": 5000,
            "sharedSecretRef": {"name": SECRET, "key": "gateway_secret"},
            "credentials": {"authorizationHeader": {"prefix": "Bearer"}},
            # Authorino constructs POST JSON from these parameters. An omitted
            # body/parameter map sends {}, not the authorization JSON.
            "bodyParameters": {"context": {"selector": "context"}},
        },
    }


def identity_rules(issuer: str, audience: str) -> dict:
    """Check live user/workload/run state before any broker initialization."""
    if not issuer.startswith("https://") or not audience.startswith("https://"):
        raise ValueError("HTTPS issuer and recipient required")
    return {
        "authentication": {
            "keycloak": {
                "jwt": {
                    "issuerUrl": issuer,
                    "issuer": issuer,
                    "audiences": [audience],
                    "ttl": 60,
                }
            }
        },
        "metadata": {"driver-decision": decision_metadata("identity")},
        "authorization": {
            "live-run": {"patternMatching": {"patterns": [{"predicate": ALLOWED}]}}
        },
    }


def adapter_rules(existing: dict, *, write_scope: bool = False) -> dict:
    """Authorize actual routed arguments before granting the adapter service token."""
    spec = deepcopy(existing)
    if spec.get("hosts") != [active_profile().private_mcp_authorization_host]:
        raise ValueError("Exact owned receiving route required")
    if set(spec.get("metadata", {})) != {"adapter-token"}:
        raise ValueError("Expected single existing credential grant required")
    grant = spec["metadata"]["adapter-token"]
    grant["priority"] = 10
    grant["when"] = [{"predicate": ALLOWED}]
    if write_scope:
        grant["http"]["bodyParameters"]["scope"] = {
            "expression": "has(auth.metadata['driver-decision'].action_id) ? 'mcp:read mcp:create' : 'mcp:read'"
        }
    # Final JWT and certificate proof are independently reverified in the driver.
    # The old single-run diagnostic policy is replaced by durable live state.
    spec["metadata"]["driver-decision"] = decision_metadata("authorize")
    result = spec["authorization"]["grant-result"]
    spec["authorization"] = {
        "live-action": {"patternMatching": {"patterns": [{"predicate": ALLOWED}]}},
        "grant-result": result,
    }
    headers = spec["response"]["success"]["headers"]
    headers.update(
        {
            "x-demo-decision": {
                "plain": {
                    "expression": "has(auth.metadata['driver-decision'].decision_ticket) ? auth.metadata['driver-decision'].decision_ticket : ''"
                }
            },
            "x-demo-run": {
                "plain": {"selector": "auth.metadata.driver-decision.run_id"}
            },
        }
    )
    spec["response"]["unauthorized"] = {
        "headers": {
            "x-demo-denial": {
                "expression": "has(auth.metadata['driver-decision'].reason) ? auth.metadata['driver-decision'].reason : 'decision_unavailable'"
            }
        }
    }
    # Only safe correlation fields reach the existing gateway audit log.
    spec["response"]["success"]["dynamicMetadata"] = {
        "step56-audit": {
            "key": "step4",
            "json": {
                "properties": {
                    "user": {"selector": "auth.identity.sub"},
                    "workload": {"selector": "auth.identity.azp"},
                    "cnf": {"expression": "auth.identity.cnf['x5t#S256']"},
                    "run": {"selector": "auth.metadata.driver-decision.run_id"},
                    "policy": {"value": "step56-live-action-v1"},
                    "actual_body_sha256": {
                        "expression": "has(auth.metadata['driver-decision'].actual_body_sha256) ? auth.metadata['driver-decision'].actual_body_sha256 : ''"
                    },
                }
            },
        }
    }
    return spec


def owned_frontend(ca: str, issuer: str, audience: str) -> list[dict]:
    """Keep live identity lookup and Secret in the owned AuthConfig namespace.

    Kuadrant generates AuthPolicy AuthConfigs in its shared namespace. A Secret
    reference there cannot resolve our namespace-owned credential. This existing
    Authorino ext_authz hook is limited to the owned bound listener/vhost and
    executes before MCP processing; all other virtual hosts disable it.
    """
    profile = active_profile()
    host = profile.service_host("fixture-mcp-bound")
    if audience != "https://" + host + "/mcp" or "BEGIN CERTIFICATE" not in ca:
        raise ValueError("Exact owned mTLS resource and trusted public CA required")
    name = "fixture-step56-live-identity"
    filter_name = "envoy.filters.http.ext_authz.step56_identity"
    metadata = {
        "name": name,
        "namespace": profile.core_namespace,
        "labels": dict(profile.labels),
    }
    config = {
        "apiVersion": "authorino.kuadrant.io/v1beta3",
        "kind": "AuthConfig",
        "metadata": deepcopy(metadata),
        "spec": {"hosts": [host], **identity_rules(issuer, audience)},
    }
    config["spec"]["metadata"]["driver-decision"] = decision_metadata("authorize")
    config["spec"]["response"] = {
        "unauthorized": {
            "headers": {
                "x-demo-denial": {
                    "expression": "has(auth.metadata['driver-decision'].reason) ? auth.metadata['driver-decision'].reason : 'decision_unavailable'"
                }
            }
        }
    }
    per_route = {
        "@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute"
    }
    patches = [
        {
            "applyTo": "HTTP_FILTER",
            "match": {
                "context": "GATEWAY",
                "listener": {
                    "portNumber": 8443,
                    "filterChain": {
                        "filter": {
                            "name": "envoy.filters.network.http_connection_manager",
                            "subFilter": {"name": "envoy.filters.http.ext_proc"},
                        }
                    },
                },
            },
            "patch": {
                "operation": "INSERT_BEFORE",
                "value": {
                    "name": filter_name,
                    "typed_config": {
                        "@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz",
                        "transport_api_version": "V3",
                        "failure_mode_allow": False,
                        "clear_route_cache": False,
                        "grpc_service": {
                            "envoy_grpc": {"cluster_name": "kuadrant-auth-service"},
                            "timeout": "5s",
                        },
                        "with_request_body": {
                            "max_request_bytes": 65536,
                            "allow_partial_message": False,
                        },
                        "stat_prefix": "step56_live_identity",
                    },
                },
            },
        },
        {
            "applyTo": "VIRTUAL_HOST",
            "match": {"context": "GATEWAY", "routeConfiguration": {"portNumber": 8443}},
            "patch": {
                "operation": "MERGE",
                "value": {
                    "typed_per_filter_config": {
                        filter_name: {**per_route, "disabled": True}
                    }
                },
            },
        },
        {
            "applyTo": "VIRTUAL_HOST",
            "match": {
                "context": "GATEWAY",
                "routeConfiguration": {
                    "portNumber": 8443,
                    "vhost": {"name": host + ":8443"},
                },
            },
            "patch": {
                "operation": "MERGE",
                "value": {
                    "typed_per_filter_config": {
                        filter_name: {**per_route, "disabled": False}
                    }
                },
            },
        },
    ]
    envoy = {
        "apiVersion": "networking.istio.io/v1alpha3",
        "kind": "EnvoyFilter",
        "metadata": deepcopy(metadata),
        "spec": {
            "priority": 1,
            "workloadSelector": {
                "labels": {
                    "gateway.networking.k8s.io/gateway-name": "fixture-mcp",
                    "identity-demo-owner": profile.owner,
                }
            },
            "configPatches": patches,
        },
    }
    return [config, envoy]
