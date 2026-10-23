# SPDX-License-Identifier: Apache-2.0
"""Offline checks for exact rule selection and generated authorizer readiness."""

from copy import deepcopy

import pytest

from probe_native_exchange import authorizer_ready


def fixture() -> tuple[dict, dict]:
    """Provide synthetic configuration with no tokens or live cluster access."""
    rules = {
        "authentication": {"keycloak": {"jwt": {"issuerUrl": "https://issuer.example.test"}}},
        "authorization": {"run": {"opa": {"rego": "allow = true", "allValues": False}}},
    }
    config = {"spec": deepcopy(rules), "status": {
        "summary": {"ready": True}, "conditions": [{"type": "Ready", "status": "True"}],
    }}
    return config, rules


def test_ready_config_requires_exact_rules_and_issuer() -> None:
    """Only the intended configuration can satisfy the readiness gate."""
    config, rules = fixture()
    assert authorizer_ready(config, rules)
    config["spec"]["authorization"]["run"]["opa"]["rego"] = "allow = false"
    assert not authorizer_ready(config, rules)


@pytest.mark.parametrize("change", ["issuer", "summary", "condition", "missing-rule"])
def test_unready_or_wrong_configuration_rejected(change: str) -> None:
    """A stale success condition cannot conceal an invalid config or rule."""
    config, rules = fixture()
    if change == "issuer":
        config["spec"]["authentication"]["keycloak"]["jwt"]["issuerUrl"] = "https://other.example.test"
    elif change == "summary":
        config["status"]["summary"]["ready"] = False
    elif change == "condition":
        config["status"]["conditions"][0]["status"] = "False"
    else:
        config["spec"]["authorization"] = {}
    assert not authorizer_ready(config, rules)


def test_inherited_ready_configs_can_both_match_same_gateway_policy() -> None:
    """Readiness is not restricted to a single generated Gateway config."""
    config, rules = fixture()
    other = deepcopy(config)
    other["spec"]["authorization"]["route-only-rule"] = {"opa": {"rego": "allow = true"}}
    assert authorizer_ready(config, rules) and authorizer_ready(other, rules)
