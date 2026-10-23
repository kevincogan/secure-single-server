# SPDX-License-Identifier: Apache-2.0
"""Probe Standard V2 exchange using temporary clients in our owned fixture.

Uses client secrets to isolate issuer semantics from SPIRE/client assertions.
Does not establish SVID authentication, native OpenShell exchange or run binding.
All temporary clients are removed in finally; existing clients remain unchanged.
"""

from __future__ import annotations
from deployment_profile import active_profile

import argparse
import hashlib
import json
from pathlib import Path
import secrets
import sys
from typing import Any
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "identity_demo"))
from identity_demo_adapter import fixture_request
from identity_demo_runtime import guard, admin_token, NAMESPACE
from identity_demo_runtime_grants import SERVER
import checks.test_components as components

UI = "fixture-exchange-ui"
GATEWAY = "fixture-exchange-gateway"
SANDBOX = "spiffe://agents.example.test/openshell/sandbox/step3-compatibility"
MCP = "fixture-exchange-mcp"
OTHER = "fixture-exchange-other"
WRONG = "fixture-exchange-wrong-requester"
CLIENTS = (UI, GATEWAY, SANDBOX, MCP, OTHER, WRONG)
PREFIX = "/admin/realms/identity-demo"


def configuration(client_id: str, secret: str, audience: str | None = None) -> dict:
    """Construct a narrowly scoped disposable client; grant no management role."""
    public = client_id == UI
    mappers: list[dict] = [{"name": "roles", "protocol": "openid-connect",
        "protocolMapper": "oidc-usermodel-realm-role-mapper", "config": {
            "multivalued": "true", "claim.name": "realm_access.roles",
            "jsonType.label": "String", "access.token.claim": "true",
            "id.token.claim": "false", "userinfo.token.claim": "false"}}]
    if audience:
        mappers.append({"name": "next-recipient", "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper", "config": {
                "included.client.audience": audience, "access.token.claim": "true",
                "id.token.claim": "false"}})
    return {"clientId": client_id, "name": "Disposable Step 3 exchange probe",
        "enabled": True, "protocol": "openid-connect", "publicClient": public,
        "clientAuthenticatorType": "client-secret", "secret": secret,
        "standardFlowEnabled": public, "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False, "fullScopeAllowed": False,
        # This build supplies the human 'sub' via its built-in basic scope.
        "defaultClientScopes": ["basic"], "optionalClientScopes": [],
        "redirectUris": ["http://127.0.0.1:18085/callback"] if public else [],
        "attributes": {"identity-demo-owner": active_profile().owner,
            "identity-demo-experiment": "step3-v2",
            "pkce.code.challenge.method": "S256",
            "standard.token.exchange.enabled": "true" if client_id in (GATEWAY, SANDBOX, WRONG) else "false"},
        "protocolMappers": mappers}


def fingerprint(clients: list[dict]) -> str:
    """Hash the existing client inventory without returning configuration."""
    ordered = sorted(clients, key=lambda v: v["id"])
    return hashlib.sha256(json.dumps(ordered, sort_keys=True).encode()).hexdigest()


def run(args: argparse.Namespace) -> dict[str, Any]:
    """Create disposable clients, verify two real users, and remove only ours."""
    args.namespace = NAMESPACE
    if args.expected_server != SERVER:
        raise ValueError("Agreed development cluster required")
    _, credentials, base = guard(args)
    components.KEYCLOAK = base
    components.ISSUER = base + "/realms/identity-demo"

    def admin(path: str, *, method: str = "GET", value: Any = None) -> Any:
        """Obtain fresh short-lived administrator credentials for each call."""
        return fixture_request(base, PREFIX + path, token=admin_token(base, credentials),
                               method=method, value=value)[1]

    before = admin("/clients")
    if any(v["clientId"] in CLIENTS for v in before):
        raise ValueError("Existing experiment names refused; inspect ownership before cleanup")
    before_hash = fingerprint(before)
    roles = [admin("/roles/" + name) for name in ("analyst", "viewer")]
    client_secrets = {name: secrets.token_urlsafe(32) for name in CLIENTS}
    created: list[tuple[str, str]] = []
    result: dict[str, Any] = {"scope": "Issuer-only diagnostic; client-secret authentication",
        "spiffe_client_authentication_proven": False,
        "native_openshell_exchange_proven": False, "run_binding_proven": False,
        "cases": [], "claims": [], "errors": []}

    def exchange(client: str, subject: str, audience: str, *, secret: str | None = None) -> tuple[int, dict]:
        """Keep raw tokens/HTTP bodies in memory; return only to this probe."""
        status, _, body = components.request(components.ISSUER + "/protocol/openid-connect/token",
            fields={"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "client_id": client, "client_secret": client_secrets[client] if secret is None else secret,
                "subject_token": subject,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "audience": audience})
        return status, json.loads(body)

    def record(case: str, status: int, value: dict, expect_success: bool) -> None:
        """Record bounded outcomes without token strings or error descriptions."""
        passed = status == 200 if expect_success else status in (400, 401, 403) and "access_token" not in value
        result["cases"].append({"case": case, "http_status": status,
            "access_token_returned": "access_token" in value,
            "oauth_error": value.get("error") if status != 200 else None, "passed": passed})
        if not passed:
            raise ValueError("Unexpected token endpoint outcome")

    try:
        audiences = {UI: GATEWAY, GATEWAY: SANDBOX, SANDBOX: MCP}
        # Create recipient clients first; audience mappers resolve client IDs.
        for name in (MCP, OTHER, WRONG, SANDBOX, GATEWAY, UI):
            admin("/clients", method="POST", value=configuration(name, client_secrets[name], audiences.get(name)))
            matches = admin("/clients?" + urlencode({"clientId": name}))
            if len(matches) != 1:
                raise ValueError("Created client inventory ambiguous")
            identifier = matches[0]["id"]
            created.append((name, identifier))
            admin("/clients/" + identifier + "/scope-mappings/realm", method="POST",
                  value=[{"id": role["id"], "name": role["name"]} for role in roles])
        subjects = []
        for name in ("analyst", "viewer"):
            original = components.login(name, credentials[name], client_id=UI)
            human = components.verify(original["access_token"], GATEWAY, issuer=components.ISSUER)
            identity = components.verify(original["id_token"], UI, issuer=components.ISSUER)
            if identity.get("nonce") != original["expected_nonce"] or identity["sub"] != human["sub"]:
                raise ValueError("Login nonce/subject verification failed")
            subjects.append(human["sub"])
            if human.get("realm_access", {}).get("roles") != [name]:
                raise ValueError("Unexpected initial human permissions")
            status, intermediate = exchange(GATEWAY, original["access_token"], SANDBOX)
            record(name + ":gateway-to-sandbox", status, intermediate, True)
            mid = components.verify(intermediate["access_token"], SANDBOX, issuer=components.ISSUER)
            status, final = exchange(SANDBOX, intermediate["access_token"], MCP)
            record(name + ":sandbox-to-mcp", status, final, True)
            end = components.verify(final["access_token"], MCP, issuer=components.ISSUER)
            for claims, expected_client in ((mid, GATEWAY), (end, SANDBOX)):
                if (claims["sub"] != human["sub"] or claims.get("azp") != expected_client
                        or claims.get("realm_access", {}).get("roles") != [name]):
                    raise ValueError("Human/requester/permission preservation failed")
            result["claims"].append({"user": name, "human_subject_preserved": True,
                "intermediate_azp": mid["azp"], "intermediate_aud": mid["aud"],
                "final_azp": end["azp"], "final_aud": end["aud"],
                "roles": end["realm_access"]["roles"],
                "final_act_present": "act" in end, "final_cnf_present": "cnf" in end,
                "final_lifetime_seconds": end["exp"] - end["iat"]})
            for case, caller, subject, audience, secret in (
                ("wrong-requester", WRONG, intermediate["access_token"], MCP, None),
                ("unconfigured-audience", GATEWAY, original["access_token"], OTHER, None),
                ("wrong-secret", GATEWAY, original["access_token"], SANDBOX, "invalid-probe-secret"),
                ("malformed-subject", GATEWAY, "not-a-valid-jwt", SANDBOX, None),
                ("wrong-subject-recipient", SANDBOX, original["access_token"], MCP, None)):
                status, denied = exchange(caller, subject, audience, secret=secret)
                record(name + ":" + case, status, denied, False)
        if len(set(subjects)) != 2:
            raise ValueError("Synthetic users do not have distinct subjects")
        result["both_users_distinct"] = True
    except Exception as error:
        result["errors"].append({"failure_kind": type(error).__name__,
            "missing_required_claim": getattr(error, "claim", None), "details_withheld": True})
    finally:
        for name, identifier in reversed(created):
            try:
                current = admin("/clients/" + identifier)
                attrs = current.get("attributes", {})
                if (current["clientId"] != name or attrs.get("identity-demo-owner") != active_profile().owner
                        or attrs.get("identity-demo-experiment") != "step3-v2"):
                    raise ValueError("Cleanup ownership mismatch")
                admin("/clients/" + identifier, method="DELETE")
            except Exception as error:
                result["errors"].append({"stage": "cleanup", "client": name,
                                         "failure_kind": type(error).__name__})
        after = admin("/clients")
        result["temporary_clients_removed"] = not any(v["clientId"] in CLIENTS for v in after)
        result["existing_clients_unchanged"] = fingerprint(after) == before_hash
    result["passed"] = (not result["errors"] and result["temporary_clients_removed"]
        and result["existing_clients_unchanged"] and len(result["cases"]) == 14
        and all(v["passed"] for v in result["cases"]))
    return result


def main() -> None:
    """Print only sanitized observations; do not persist any issued token."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("kubeconfig", "expected-server", "credentials-file"):
        parser.add_argument("--" + name, required=True)
    try:
        result = run(parser.parse_args())
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result["passed"] else 1)
    except Exception as error:
        print(json.dumps({"passed": False, "failure_kind": type(error).__name__, "details_withheld": True}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
