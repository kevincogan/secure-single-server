# SPDX-License-Identifier: Apache-2.0
"""Compile trusted, read-only run bindings for the existing gateway authorizer.

Inputs belong to the authenticated driver/control plane, never the agent request.
The pilot gives each run a distinct sandbox identity and never reassigns it. The
owned AuthConfig is the live authority for active/cancelled run state; no new
database, token issuer or authorization service is required. Rendering is not
evidence that the installed gateway delivers authenticated TLS-peer metadata.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from urllib.parse import urlparse

# Envoy may include a URL-encoded public certificate and a quoted comma-bearing
# subject DN. Neither authenticates the caller; the hash and URI below do that.
# Refuse unquoted element separators, unknown fields, escapes and duplicates.
XFCC_FIELD_PATTERN = (
    r'^(By=[^,;"[:space:]]*|Hash=[a-f0-9]{64}|Subject="[^;"\\]*"|'
    r'Cert="[-A-Za-z0-9%+/_=]+"|URI=spiffe://[a-z0-9._/-]+)$'
)


SENDER_CHECK = '''peer := input.context.request.http.headers["x-forwarded-client-cert"]
    count(peer) <= 4096
    fields := split(peer, ";")
    bad := [field | field := fields[_]; not regex.match(`FIELD_PATTERN`, field)]
    count(bad) == 0
    names := [name | field := fields[_]; name := split(field, "=")[0]]
    count(names) == count({name | name := names[_]})
    sprintf("URI=%s", [binding.workload]) == fields[_]
    hash_fields := [field | field := fields[_]; startswith(field, "Hash=")]
    count(hash_fields) == 1
    thumbprint := identity.cnf["x5t#S256"]
    regex.match(`^[A-Za-z0-9_-]{43}$`, thumbprint)
    sprintf("Hash=%s", [hex.encode(base64url.decode(thumbprint))]) == hash_fields[0]'''

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


def authorization(runs: list[ReadRun], *, require_sender_binding: bool = True) -> dict:
    """Render exact live associations; gateway JWT verification must run first.

    Each identity may appear at most once, including cancelled records. Using
    another run ID with the same identity would let a still-valid old token cross
    the run boundary. The caller must retain retired identity tombstones for the
    pilot and deny management/provider access to untrusted workloads.
    """
    if not runs or len(runs) > 16 or type(require_sender_binding) is not bool:
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
    identity.exp - identity.iat <= 30
    "analyst" == identity.realm_access.roles[_]
    input.context.request.http.path == "/mcp"
    input.context.request.http.method == {"POST", "GET", "DELETE"}[_]
    SENDER_CHECK
}

'''.replace("BINDINGS", json.dumps(bindings, separators=(",", ":")))
    sender = SENDER_CHECK
    sender = sender.replace("FIELD_PATTERN", XFCC_FIELD_PATTERN)
    rego = rego.replace("SENDER_CHECK", sender if require_sender_binding else "true")
    return {"opa": {"rego": rego, "allValues": False}}


def live_sender_authorization(issuer: str, audience: str, trust_domain: str) -> dict:
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
    binding := {"workload": identity.azp}
    scalar_audiences := {aud | is_string(identity.aud); aud := identity.aud}
    array_audiences := {aud | is_array(identity.aud); aud := identity.aud[_]; is_string(aud)}
    audiences := scalar_audiences | array_audiences
    AUDIENCE == audiences[_]
    identity.iat <= now + 5
    identity.exp > now
    identity.exp > identity.iat
    identity.exp - identity.iat <= 30
    identity.realm_access.roles[_] == {"analyst", "viewer"}[_]
    input.context.request.http.path == "/mcp"
    input.context.request.http.method == {"POST", "GET", "DELETE"}[_]
    SENDER
}
'''
    pattern = '^spiffe://' + re.escape(trust_domain) + '/openshell/sandbox/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'
    rego = rego.replace('ISSUER', json.dumps(issuer)).replace('AUDIENCE', json.dumps(audience))
    rego = rego.replace('WORKLOAD', json.dumps(pattern)).replace('SENDER', SENDER_CHECK.replace('FIELD_PATTERN', XFCC_FIELD_PATTERN))
    return {'opa': {'rego': rego, 'allValues': False}}
