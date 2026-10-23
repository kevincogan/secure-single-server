# SPDX-License-Identifier: Apache-2.0
"""Offline mutation-boundary checks, distinct from native mTLS acceptance."""

from copy import deepcopy

import pytest

from sender_listener import HOST, LABELS, NS, gateway_patch, resources


def gateway() -> dict:
    """Supply one synthetic owned gateway with two existing listeners."""
    return {"metadata": {"name": "fixture-mcp", "namespace": NS,
                          "labels": dict(LABELS), "uid": "uid-a", "resourceVersion": "42"},
            "spec": {"listeners": [{"name": "mcp", "port": 8080},
                                   {"name": "mcps", "port": 8080}]}}


def test_exact_append_preserves_existing_listeners() -> None:
    """The renderer never reconstructs or overwrites the other listeners."""
    value = gateway()
    before = deepcopy(value)
    patch = gateway_patch(value)
    assert value == before
    assert patch[2]["value"] == before["spec"]
    assert patch[3]["path"] == "/spec/listeners/-"
    assert patch[3]["value"]["tls"]["options"]["gateway.istio.io/tls-terminate-mode"] == "MUTUAL"


@pytest.mark.parametrize("mutation", ["owner", "namespace", "port", "name"])
def test_collision_or_other_owner_refused(mutation: str) -> None:
    """An ambiguous deployment must fail before the API mutation."""
    value = gateway()
    if mutation == "owner":
        value["metadata"]["labels"]["identity-demo-owner"] = "another-owner"
    elif mutation == "namespace":
        value["metadata"]["namespace"] = "shared"
    elif mutation == "port":
        value["spec"]["listeners"].append({"name": "other", "port": 8443})
    else:
        value["spec"]["listeners"].append({"name": "bound", "port": 9443})
    with pytest.raises(ValueError):
        gateway_patch(value)


def test_internal_service_reuses_gateway_and_sanitizes_claimed_peer() -> None:
    """No public endpoint or proxy is added; only validated leaf metadata passes."""
    values = resources()
    assert [v["kind"] for v in values] == ["Service", "HTTPRoute", "EnvoyFilter"]
    assert all(v["metadata"]["namespace"] == NS for v in values)
    assert values[1]["spec"]["hostnames"] == [HOST]
    settings = values[2]["spec"]["configPatches"][0]["patch"]["value"]["typed_config"]
    assert settings["forward_client_cert_details"] == "SANITIZE_SET"
    assert settings["set_current_client_cert_details"] == {"subject": True, "uri": True}
