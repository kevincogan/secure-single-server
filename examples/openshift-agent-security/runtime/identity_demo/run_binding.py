# SPDX-License-Identifier: Apache-2.0
"""Compile trusted, read-only run bindings for the existing gateway authorizer.

Inputs belong to the authenticated driver/control plane, never the agent request.
The pilot gives each run a distinct sandbox identity and never reassigns it. The
owned AuthConfig is the live authority for active/cancelled run state; no new
database, token issuer or authorization service is required. Rendering is not
evidence of installed request enforcement or credential isolation.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from urllib.parse import urlparse

@dataclass(frozen=True)
class ReadRun:
    """An immutable association created after real user-token verification."""

    run_id: str
    issuer: str
    user_subject: str
    workload: str
    audience: str
    not_before: int
    expires_at: int
    active: bool = True

    def __post_init__(self) -> None:
        """Refuse ambiguous identities, insecure URLs and invalid time bounds."""
        for value in (self.run_id, self.user_subject):
            if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value):
                raise ValueError("A bounded driver-generated identifier is required")
        if not isinstance(self.workload, str) or not re.fullmatch(
            r"spiffe://[a-z0-9._-]+/openshell/sandbox/[A-Za-z0-9_-]{1,128}", self.workload
        ):
            raise ValueError("A canonical protected sandbox identity is required")
        for value in (self.issuer, self.audience):
            parsed = urlparse(value)
            if (parsed.scheme != "https" or not parsed.hostname or parsed.username
                    or parsed.password or parsed.fragment or parsed.query):
                raise ValueError("An explicit HTTPS issuer/resource is required")
        if (type(self.not_before) is not int or type(self.expires_at) is not int
                or self.not_before < 0 or self.expires_at <= self.not_before
                or type(self.active) is not bool):
            raise ValueError("Valid protected run lifetime and state are required")


def authorization(runs: list[ReadRun]) -> dict:
    """Render exact live associations; gateway JWT verification must run first.

    Each identity may appear at most once, including cancelled records. Using
    another run ID with the same identity would let a still-valid old token cross
    the run boundary. The caller must retain retired identity tombstones for the
    pilot and deny management/provider access to untrusted workloads.
    """
    if not runs or len(runs) > 16:
        raise ValueError("A bounded, explicit run set is required")
    if len({run.run_id for run in runs}) != len(runs):
        raise ValueError("Duplicate run identifier")
    if len({run.workload for run in runs}) != len(runs):
        raise ValueError("An execution identity cannot belong to multiple runs")
    bindings = [dict(run_id=r.run_id, issuer=r.issuer, user=r.user_subject,
                     workload=r.workload, audience=r.audience,
                     not_before=r.not_before, expires_at=r.expires_at, active=r.active)
                for r in runs]
    # Authorino supplies its own `default allow = false` in the generated
    # module. Repeating it makes this installed authorizer reject the config.
    rego = '''bindings := BINDINGS

allow {
    binding := bindings[_]
    binding.active == true
    now := time.now_ns() / 1000000000
    now >= binding.not_before
    now < binding.expires_at
    identity := input.auth.identity
    identity.iss == binding.issuer
    identity.sub == binding.user
    identity.azp == binding.workload
    scalar_audiences := {aud | is_string(identity.aud); aud := identity.aud}
    array_audiences := {aud | is_array(identity.aud); aud := identity.aud[_]; is_string(aud)}
    audiences := scalar_audiences | array_audiences
    binding.audience == audiences[_]
    identity.iat >= binding.not_before
    identity.exp > now
    identity.exp <= binding.expires_at
    identity.exp > identity.iat
    identity.exp - identity.iat <= 30
    "analyst" == identity.realm_access.roles[_]
    input.context.request.http.path == "/mcp"
    input.context.request.http.method == {"POST", "GET", "DELETE"}[_]
    identity_keys := object.keys(identity)
    not identity_keys["cnf"]
}

'''.replace("BINDINGS", json.dumps(bindings, separators=(",", ":")))
    return {"opa": {"rego": rego, "allValues": False}}


def live_delegation_authorization(issuer: str, audience: str, trust_domain: str) -> dict:
    """Stable cryptographic gate; the direct driver hooks enforce live run/action state."""
    if (any(not v.startswith('https://') for v in (issuer, audience))
            or not re.fullmatch(r'[a-z0-9._-]+', trust_domain)):
        raise ValueError('Exact HTTPS issuer, audience and trust domain required')
    rego = '''allow {
    now := time.now_ns() / 1000000000
    identity := input.auth.identity
    identity.iss == ISSUER
    is_string(identity.sub)
    count(identity.sub) > 0
    count(identity.sub) <= 128
    regex.match(WORKLOAD, identity.azp)
    scalar_audiences := {aud | is_string(identity.aud); aud := identity.aud}
    array_audiences := {aud | is_array(identity.aud); aud := identity.aud[_]; is_string(aud)}
    audiences := scalar_audiences | array_audiences
    AUDIENCE == audiences[_]
    identity.iat <= now
    identity.exp > now
    identity.exp > identity.iat
    identity.exp - identity.iat <= 30
    identity.realm_access.roles[_] == {"analyst", "viewer"}[_]
    input.context.request.http.path == "/mcp"
    input.context.request.http.method == {"POST", "GET", "DELETE"}[_]
    identity_keys := object.keys(identity)
    not identity_keys["cnf"]
}
'''
    pattern = '^spiffe://' + re.escape(trust_domain) + '/openshell/sandbox/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'
    rego = rego.replace('ISSUER', json.dumps(issuer)).replace('AUDIENCE', json.dumps(audience))
    rego = rego.replace('WORKLOAD', json.dumps(pattern))
    return {'opa': {'rego': rego, 'allValues': False}}
