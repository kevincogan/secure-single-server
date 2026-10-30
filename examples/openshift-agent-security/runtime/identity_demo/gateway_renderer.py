# SPDX-License-Identifier: Apache-2.0
"""Pure desired gateway resources from fixed, previously observed dependencies."""
from copy import deepcopy
import gateway_credential_route as route
import probe_broker_discovery as shared
from native_backend import router_patches, PREFIX


def render(ca, secret, run, credential, inputs, *, action_driver, enable_create):
    values = route.native_manifests(ca, secret, run)
    if action_driver:
        from identity_demo_action_policy import adapter_rules

        driver = inputs['driver']
        if "gateway_secret" not in driver.get("data", {}):
            raise ValueError("Owned scoped driver credential required")
        values[1]["spec"] = adapter_rules(
            values[1]["spec"],
            write_scope=enable_create,
        )
    if action_driver:
        from identity_demo_action_policy import owned_frontend

        values.extend(owned_frontend(ca, run.issuer, run.audience))
    # The operator ADDs its custom Authorino cluster. Istio MERGE cannot
    # modify a cluster added in that same patch pass. Add the exact cluster
    # earlier, scoped to our gateway; leave generated filters untouched.
    baseline = inputs['baseline']
    patch = deepcopy(baseline["spec"]["configPatches"])
    authorizer_host = route.AUTHORIZER + ".cluster.local"
    expected_address = {
        "socket_address": {"address": authorizer_host, "port_value": 50051}
    }
    if (
        baseline["spec"].get("priority") != -1
        or len(patch) != 1
        or patch[0]["applyTo"] != "CLUSTER"
        or patch[0]["patch"]["operation"] != "ADD"
        or patch[0]["patch"]["value"]["name"] != "kuadrant-auth-service"
        or patch[0]["patch"]["value"]["load_assignment"]["endpoints"][0][
            "lb_endpoints"
        ][0]["endpoint"]["address"]
        != expected_address
    ):
        raise ValueError("Unexpected installed Authorino cluster; refuse override")
    patch[0]["match"] = {"context": "GATEWAY"}
    patch[0]["patch"]["value"]["transport_socket"] = route.tls_context(
        authorizer_host, ca
    )
    tls = route.resource(
        "networking.istio.io/v1alpha3",
        "EnvoyFilter",
        {
            "priority": -2,
            "workloadSelector": {
                "labels": {
                    "gateway.networking.k8s.io/gateway-name": "fixture-mcp",
                    **shared.LABELS,
                }
            },
            "configPatches": patch,
        },
    )
    tls["metadata"]["name"] = route.READ_NAME + "-authorino-tls"
    tls["metadata"]["labels"]["istio.io/rev"] = "openshift-gateway"
    values.append(tls)
    extension = inputs['extension']
    if extension["spec"]["targetRef"].get("sectionName") != "bound":
        raise ValueError("Exact bound-listener extension required")
    generated = inputs['generated']
    labels = generated["metadata"].get("labels", {})
    if (
        labels.get("mcp.kuadrant.io/extension-name") != "fixture-mcp"
        or labels.get("mcp.kuadrant.io/extension-namespace") != shared.NS
        or generated["spec"]["workloadSelector"]
        != {"labels": {"gateway.networking.k8s.io/gateway-name": "fixture-mcp"}}
    ):
        raise ValueError("Exact generated owned-extension router required")
    patches = deepcopy(generated["spec"]["configPatches"])
    if (
        len(patches) != 1
        or patches[0]["applyTo"] != "HTTP_FILTER"
        or patches[0]["match"]["listener"].get("portNumber") != 8443
        or patches[0]["patch"]["value"]["name"] != "envoy.filters.http.ext_proc"
        or patches[0]["patch"]["value"]["typed_config"]["failure_mode_allow"]
        is not False
        or patches[0]["patch"]["value"]["typed_config"]["grpc_service"][
            "envoy_grpc"
        ]["cluster_name"]
        != ("outbound|50051||mcp-gateway." + shared.NS + ".svc.cluster.local")
    ):
        raise ValueError("Unexpected router transport; refuse copy")
    # The installed extension puts ext_proc first. It can initialize a
    # backend before frontend authorization, converting viewer denial to
    # 500. On the owned mTLS listener, authorize the original JWT/run/peer
    # before MCP routing, then mediate credentials on the rewritten route.
    patches = router_patches(patches[0])
    router = route.resource(
        "networking.istio.io/v1alpha3",
        "EnvoyFilter",
        {
            "workloadSelector": {
                "labels": {
                    "gateway.networking.k8s.io/gateway-name": "fixture-mcp",
                    **shared.LABELS,
                }
            },
            "configPatches": patches,
        },
    )
    router["metadata"]["name"] = route.READ_NAME + "-router"
    router["metadata"]["labels"]["istio.io/rev"] = "openshift-gateway"
    values.append(router)
    grant = route.resource("v1", "Secret")
    grant["metadata"]["name"] = route.READ_NAME + "-catalog"
    grant["metadata"]["labels"]["mcp.kuadrant.io/secret"] = "true"
    grant.update(
        type="Opaque", stringData={"token": "Bearer " + credential["token"]}
    )
    trust = route.resource("v1", "Secret")
    trust["metadata"]["name"] = route.READ_NAME + "-ca"
    trust["metadata"]["labels"]["mcp.kuadrant.io/secret"] = "true"
    trust.update(type="Opaque", stringData={"ca.crt": ca})
    registration = route.resource(
        "mcp.kuadrant.io/v1alpha1",
        "MCPServerRegistration",
        {
            "targetRef": {
                "group": "gateway.networking.k8s.io",
                "kind": "HTTPRoute",
                "name": route.READ_NAME,
            },
            "path": "/mcp",
            "prefix": "step56_jira_" if action_driver else PREFIX,
            "state": "Enabled",
            "userSpecificList": "Disabled",
            "credentialRef": {"name": grant["metadata"]["name"], "key": "token"},
            "caCertSecretRef": {"name": trust["metadata"]["name"], "key": "ca.crt"},
        },
    )
    registration["metadata"]["name"] = route.READ_NAME
    values.extend([grant, trust, registration])
    from sender_listener import HOST

    gateway = inputs['gateway']
    desired = deepcopy(gateway["spec"])
    listeners = [v for v in desired["listeners"] if v["name"] == "bound"]
    if (
        len(listeners) != 1
        or listeners[0].get("hostname") != HOST
        or listeners[0]["tls"].get("mode") != "Terminate"
    ):
        raise ValueError("Exact current bound listener required")
    listeners[0].pop("hostname")
    gateway_patch = [
        {
            "op": "test",
            "path": "/metadata/uid",
            "value": gateway["metadata"]["uid"],
        },
        {
            "op": "test",
            "path": "/metadata/resourceVersion",
            "value": gateway["metadata"]["resourceVersion"],
        },
        {"op": "test", "path": "/spec", "value": gateway["spec"]},
        {"op": "replace", "path": "/spec", "value": desired},
    ]
    return values, gateway, desired, gateway_patch
