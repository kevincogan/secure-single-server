# SPDX-License-Identifier: Apache-2.0
"""Small offline guards; installed-authorizer and native tests remain mandatory."""

from dataclasses import replace

import pytest

from run_binding import ReadRun, authorization


def fixture() -> ReadRun:
    """Return synthetic driver-owned state without credentials."""
    return ReadRun("run-a", "https://issuer.example.test/realms/demo", "user-a",
                   "spiffe://demo.example.test/openshell/sandbox/a",
                   "https://mcp.example.test/mcp", 100, 300)


@pytest.mark.parametrize("field,value", [
    ("run_id", "../other"), ("user_subject", ""), ("workload", "spiffe://demo/a"),
    ("issuer", "http://issuer.example.test"), ("audience", "https://user:secret@mcp.example.test"),
    ("not_before", True), ("expires_at", 100), ("active", "true"),
])
def test_invalid_trusted_state_refused(field: str, value: object) -> None:
    """Invalid inputs cannot become an apparently valid authorization policy."""
    with pytest.raises(ValueError):
        replace(fixture(), **{field: value})


def test_identity_cannot_be_reassigned_even_with_cancelled_record() -> None:
    """A still-valid token must not acquire another run's permissions."""
    with pytest.raises(ValueError):
        authorization([replace(fixture(), active=False), replace(fixture(), run_id="run-b")])


def test_distinct_execution_identities_support_two_runs_of_the_same_user() -> None:
    """The role/image can be shared while the execution identities remain separate."""
    second = replace(fixture(), run_id="run-b",
                     workload="spiffe://demo.example.test/openshell/sandbox/b")
    value = authorization([fixture(), second])["opa"]["rego"]
    assert '"run-a"' in value and '"run-b"' in value
    assert "identity.azp == binding.workload" in value
    assert "run_id" not in value[value.index("allow {"):]


def test_delegation_preserves_exact_authority_and_bounded_bearer_contract() -> None:
    """Signed identity and live run state are mandatory; old cnf tokens fail shut."""
    value = authorization([fixture()])["opa"]["rego"]
    for required in ("not identity_keys[\"cnf\"]", "identity.azp == binding.workload",
                     "binding.active == true", "identity.sub == binding.user",
                     "identity.iss == binding.issuer", "binding.audience == audiences[_]",
                     "now >= binding.not_before", "now < binding.expires_at",
                     "identity.iat >= binding.not_before", "identity.exp > now",
                     "identity.exp <= binding.expires_at", "identity.exp - identity.iat <= 30"):
        assert required in value
    assert "x-forwarded-client-cert" not in value and "contains(" not in value


def test_authorino_owns_the_single_default_deny_rule() -> None:
    """Match the installed Authorino wrapper without duplicate default rules."""
    policy = authorization([fixture()])["opa"]
    assert policy["allValues"] is False
    wrapped = "package fixture\ndefault allow = false\n" + policy["rego"]
    assert wrapped.count("default allow =") == 1
    assert "allow {" in policy["rego"]
    # The installed Authorino query uses object.get over the module; functions
    # make that module a non-JSON object and fail its preparation/type check.
    assert "audience_matches(" not in policy["rego"]
    assert "is_string(identity.aud)" in policy["rego"]
    assert "is_array(identity.aud)" in policy["rego"]
