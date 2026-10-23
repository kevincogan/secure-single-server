# SPDX-License-Identifier: Apache-2.0
"""Small offline guards; installed-authorizer and native tests remain mandatory."""

from dataclasses import replace
import re

import pytest

from run_binding import ReadRun, XFCC_FIELD_PATTERN, authorization


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


def test_sender_binding_is_required_by_default_and_has_no_substring_matching() -> None:
    """Only an exact canonical peer hash and workload can satisfy binding."""
    value = authorization([fixture()])["opa"]["rego"]
    for required in ("identity.cnf", "hex.encode(base64url.decode(thumbprint))",
                     "count(hash_fields) == 1", "count(bad) == 0",
                     "count(names) == count({name", "binding.active == true",
                     "identity.exp <= binding.expires_at"):
        assert required in value
    assert "contains(" not in value


def test_unbound_policy_requires_explicit_component_diagnostic_choice() -> None:
    """Disabling sender checks is observable; it is not the deployment default."""
    value = authorization([fixture()], require_sender_binding=False)["opa"]["rego"]
    assert "identity.azp == binding.workload" in value
    assert "x-forwarded-client-cert" not in value


@pytest.mark.parametrize("field,valid", [
    ('Subject="O=SPIRE,C=US"', True),
    ('Cert="-----BEGIN%20CERTIFICATE-----%0AAbCd%2B%2F%3D%0A-----END%20CERTIFICATE-----"', True),
    ("By=", True),
    ('Subject="C=US",URI=spiffe://attacker/sandbox/b', False),
    ("URI=spiffe://demo.example.test/openshell/sandbox/a,URI=spiffe://attacker/b", False),
    ("Cert=unquoted", False),
    ('Cert="public;URI=spiffe://attacker/b"', False),
    ('Unknown="public"', False),
    ('Subject="escaped\\"value"', False),
])
def test_peer_grammar_accepts_real_envoy_fields_without_accepting_element_injection(
    field: str, valid: bool,
) -> None:
    """Use the same grammar; translate its POSIX space class for Python's engine."""
    pattern = XFCC_FIELD_PATTERN.replace("[:space:]", r"\s")
    assert bool(re.fullmatch(pattern, field)) is valid
    assert XFCC_FIELD_PATTERN in authorization([fixture()])["opa"]["rego"]


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
