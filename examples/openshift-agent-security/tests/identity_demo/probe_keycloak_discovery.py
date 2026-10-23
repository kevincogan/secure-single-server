#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify the restored owned issuer and its live internal SPIRE HTTPS trust.

Uses an administratively minted diagnostic assertion, not native attestation.
No model calls, sandbox operations, Jira access or shared-resource changes occur.
"""

from __future__ import annotations
from deployment_profile import active_profile

import argparse
import json
from pathlib import Path
import sys
import time
from typing import Any
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "identity_demo"))
from identity_demo_adapter import fixture_request  # noqa: E402
from identity_demo_runtime import admin_token, guard, owned_identity, NAMESPACE  # noqa: E402
from identity_demo_keycloak_recovery import command, write_private, CA, PREFIX  # noqa: E402
from probe_keycloak_recovery import strings
import checks.test_components as components
import jwt
from deployment_profile import in_source_checkout


def run(args: argparse.Namespace) -> dict:
    """Check real public login, retained identities and pod-to-pod trust."""
    args.namespace = NAMESPACE
    _, credentials, base = guard(args)
    directory = Path(args.workspace_dir)
    if (not directory.is_dir() or directory.is_symlink() or directory.stat().st_mode & 0o077
            or in_source_checkout(directory)
            or Path(args.label).name != args.label):
        raise ValueError("Private evidence directory and simple label required")
    if any(directory.glob(args.label + ".*")):
        raise ValueError("Existing probe artifacts refused; inspect previous state")
    expected = json.loads((directory / "keycloak-recovery-realm.private-json").read_text())
    components.KEYCLOAK, components.ISSUER = base, base + "/realms/identity-demo"
    deployment = json.loads(command(args, "get", "deployment", "fixture-keycloak", "-n", NAMESPACE, "-o", "json"))
    spec = deployment["spec"]["template"]["spec"]
    if (not any(v.get("persistentVolumeClaim", {}).get("claimName") == PREFIX + "-data" for v in spec["volumes"])
            or not any(v.get("configMap", {}).get("name") == CA for v in spec["volumes"])
            or not any(v.get("name") == "KC_TLS_HOSTNAME_VERIFIER" and v.get("value") == "DEFAULT"
                       for v in spec["containers"][0]["env"])):
        raise ValueError("Owned durable fixture and verified trust settings required")
    result = {"scope": "Restored fixture issuer and actual internal SPIRE bundle trust",
              "passed": False, "cases": [], "native_exchange_proven": False,
              "sender_constraint_proven": False,
              "administratively_minted_assertion_not_native_attestation": True}
    client_uuid = None
    provider_created = False
    subject = "spiffe://agents.example.test/oidc/discovery"
    provider = "fixture-live-discovery-trust-probe"
    endpoint = "https://spire-spiffe-oidc-discovery-provider.demo-identity.svc:8443/keys"
    prefix = "/admin/realms/identity-demo"

    def admin(path: str, method: str = "GET", value: Any = None) -> Any:
        """Restrict administration to the exact owned fixture realm."""
        return fixture_request(base, prefix + path, method=method,
                               value=value, token=admin_token(base, credentials))[1]

    def checked(name: str, condition: bool) -> None:
        """Record bounded assertions without credential or payload details."""
        result["cases"].append({"case": name, "passed": bool(condition)})
        if not condition:
            raise ValueError("Owned issuer assertion failed: " + name)

    clients_before = sorted((v["id"], v["clientId"]) for v in admin("/clients"))
    providers_before = sorted(v["alias"] for v in admin("/identity-provider/instances"))
    pods_before = json.loads(command(args, "get", "pods", "-n", NAMESPACE,
                                    "-l", "app=fixture-keycloak", "-o", "json"))
    pod_uids_before = sorted(v["metadata"]["uid"] for v in pods_before["items"])
    try:
        checked("retained_client_ids", clients_before == sorted((v["id"], v["clientId"]) for v in expected["clients"]))
        for name in ("analyst", "viewer"):
            wanted = next(v for v in expected["users"] if v["username"] == name)
            login = components.login(name, credentials[name])
            access = components.verify(login["access_token"], "identity-demo-mcp", issuer=components.ISSUER)
            identity = components.verify(login["id_token"], "identity-demo-ui", issuer=components.ISSUER)
            checked("public_pkce_identity_nonce:" + name, access["sub"] == wanted["id"] == identity["sub"]
                    and identity.get("nonce") == login["expected_nonce"])
            checked("public_user_permissions:" + name, access.get("realm_access", {}).get("roles") == [name])
        operator = credentials["runtime_management"]
        _, grant = fixture_request(base, "/realms/identity-demo/protocol/openid-connect/token", method="POST",
            fields={"grant_type": "client_credentials", "client_id": operator["client_id"],
                    "client_secret": operator["client_secret"]})
        claims = components.verify(grant["access_token"], operator["audience"], issuer=components.ISSUER)
        wanted = next(v for v in expected["users"] if v.get("serviceAccountClientId") == operator["client_id"])
        checked("retained_runtime_service_identity_and_role", claims["sub"] == wanted["id"]
                and claims["azp"] == operator["client_id"]
                and claims.get("realm_access", {}).get("roles") == ["identity-demo-runtime-admin"])
        checked("temporary_names_unused", not any(n == subject for _, n in clients_before)
                and provider not in providers_before)
        admin("/identity-provider/instances", "POST", {"alias": provider, "providerId": "spiffe",
            "enabled": True, "config": {"trustDomain": "spiffe://agents.example.test",
                "bundleEndpoint": endpoint, "identity-demo-owner": active_profile().owner}})
        provider_created = True
        admin("/clients", "POST", {"clientId": subject, "enabled": True, "publicClient": False,
            "protocol": "openid-connect", "clientAuthenticatorType": "federated-jwt",
            "serviceAccountsEnabled": True, "standardFlowEnabled": False,
            "directAccessGrantsEnabled": False, "fullScopeAllowed": False,
            "defaultClientScopes": ["basic"], "optionalClientScopes": [],
            "attributes": {"identity-demo-owner": active_profile().owner, "jwt.credential.issuer": provider,
                           "jwt.credential.sub": subject}, "protocolMappers": [{
                "name": "diagnostic-audience", "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper", "config": {
                    "included.custom.audience": "identity-demo-discovery-trust-probe",
                    "access.token.claim": "true", "id.token.claim": "false"}}]})
        matches = admin("/clients?" + urlencode({"clientId": subject}))
        checked("one_temporary_client", len(matches) == 1)
        client_uuid = matches[0]["id"]
        minted = json.loads(command(args, "-n", "demo-identity", "exec", "spire-server-0", "-c",
            "spire-server", "--", "/spire-server", "jwt", "mint", "-spiffeID", subject,
            "-audience", components.ISSUER, "-ttl", "120s" if args.check_key_rollover else "30s", "-output", "json"))
        assertions = strings(minted)
        checked("one_administrative_diagnostic_assertion", len(assertions) == 1)
        status, _, body = components.request(components.ISSUER + "/protocol/openid-connect/token", fields={
            "grant_type": "client_credentials", "client_assertion_type":
                "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe", "client_assertion": assertions[0]})
        result["spiffe_http_status"] = status
        response = json.loads(body)
        checked("actual_issuer_internal_tls_and_bundle_fetch", status == 200 and "access_token" in response)
        verified = components.verify(response["access_token"], "identity-demo-discovery-trust-probe", issuer=components.ISSUER)
        checked("spiffe_response_signature_and_client", verified["azp"] == subject)
        if args.check_key_rollover:
            # Guard the whole foundation before changing its JWT signing key.
            # No authority is revoked/tainted, and the same provider stays active.
            static = json.loads(command(args, "get", "clusterstaticentry", "-o", "json"))["items"]
            checked("rotation_only_exact_owned_registrations", len(static) == 3 and all(
                v["metadata"].get("labels", {}).get("identity-demo-owner") == active_profile().owner
                and v["spec"]["spiffeID"].startswith("spiffe://agents.example.test/") for v in static))
            for kind in ("clusterspiffeid", "spireoidcdiscoveryprovider"):
                checked("rotation_no_broad_" + kind,
                        not json.loads(command(args, "get", kind, "-o", "json"))["items"])

            def authority(operation: str, *parts: str) -> dict:
                """Use only the owned SPIRE server's supported authority API."""
                return json.loads(command(args, "-n", "demo-identity", "exec", "spire-server-0",
                    "-c", "spire-server", "--", "/spire-server", "localauthority", "jwt",
                    operation, *parts, "-output", "json"))

            before = authority("show")
            old_id = before["active"]["authority_id"]
            checked("rotation_no_existing_preparation", not before.get("prepared"))
            checked("warmed_provider_uses_current_key", jwt.get_unverified_header(assertions[0])["kid"] == old_id)
            write_private(directory / (args.label + ".authority-before.private-json"), before)
            prepared = authority("prepare")
            write_private(directory / (args.label + ".authority-prepared.private-json"), prepared)
            new_id = prepared["prepared_authority"]["authority_id"]
            checked("new_prepared_key_is_distinct", new_id != old_id)
            # The actual discovery endpoint must publish the new verification
            # key before activation. The probe also verifies its TLS and live
            # bundle equality; it closes only its own tunnel.
            from argparse import Namespace
            from probe_discovery import run as discovery_run

            published = False
            deadline = time.monotonic() + 60
            poll = 0
            while time.monotonic() < deadline:
                poll += 1
                discovery = discovery_run(Namespace(kubeconfig=args.kubeconfig, output_dir=directory,
                    label=args.label + "-prepared-discovery-" + str(poll)))
                if new_id in discovery["jwt_key_ids"] and old_id in discovery["jwt_key_ids"]:
                    published = True
                    break
                time.sleep(2)
            checked("new_and_prior_keys_published_before_activation", published)
            activated = authority("activate", "-authorityID", new_id)
            write_private(directory / (args.label + ".authority-activated.private-json"), activated)
            checked("prepared_key_activated", activated["activated_authority"]["authority_id"] == new_id)

            accepted = False
            attempts = []
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                minted = json.loads(command(args, "-n", "demo-identity", "exec", "spire-server-0",
                    "-c", "spire-server", "--", "/spire-server", "jwt", "mint", "-spiffeID", subject,
                    "-audience", components.ISSUER, "-ttl", "30s", "-output", "json"))
                current_assertions = strings(minted)
                checked("new_assertion_uses_activated_key", len(current_assertions) == 1
                        and jwt.get_unverified_header(current_assertions[0])["kid"] == new_id)
                status, _, body = components.request(components.ISSUER + "/protocol/openid-connect/token", fields={
                    "grant_type": "client_credentials", "client_assertion_type":
                    "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe", "client_assertion": current_assertions[0]})
                attempts.append({"http_status": status})
                if status == 200:
                    current_response = json.loads(body)
                    current_claims = components.verify(current_response["access_token"],
                        "identity-demo-discovery-trust-probe", issuer=components.ISSUER)
                    checked("new_key_auth_response_verified", current_claims["azp"] == subject)
                    accepted = True
                    break
                if status != 401:
                    break
                time.sleep(10)
            result["key_rollover_http_attempts"] = attempts
            checked("warmed_keycloak_provider_refreshes_new_key", accepted)
            # Check the old assertion only while it remains valid; failure must
            # not be disguised as rollover success after its expiry.
            old_claims = jwt.decode(assertions[0], options={"verify_signature": False})
            checked("prior_diagnostic_assertion_still_unexpired", old_claims["exp"] > time.time())
            status, _, body = components.request(components.ISSUER + "/protocol/openid-connect/token", fields={
                "grant_type": "client_credentials", "client_assertion_type":
                "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe", "client_assertion": assertions[0]})
            checked("prior_key_assertion_accepted_during_overlap", status == 200)
            overlap = components.verify(json.loads(body)["access_token"],
                "identity-demo-discovery-trust-probe", issuer=components.ISSUER)
            checked("prior_key_auth_response_verified", overlap["azp"] == subject)
            current_pods = json.loads(command(args, "get", "pods", "-n", NAMESPACE,
                "-l", "app=fixture-keycloak", "-o", "json"))
            checked("keycloak_not_restarted_for_rollover", pod_uids_before == sorted(
                v["metadata"]["uid"] for v in current_pods["items"]))
            result["keycloak_cache_rotation_proven"] = True
            result["jwt_authority_ids"] = {"prior": old_id, "activated": new_id}
            result["no_jwt_authority_revoked_or_tainted"] = True
        result["passed"] = True
    except Exception as error:
        result["failure_kind"] = type(error).__name__
        write_private(directory / (args.label + ".exception.private-json"), {
            "kind": type(error).__name__, "message": str(error)})
    finally:
        try:
            if client_uuid:
                current = admin("/clients/" + client_uuid)
                if current["clientId"] != subject or not owned_identity(current):
                    raise ValueError("Temporary client cleanup ownership mismatch")
                admin("/clients/" + client_uuid, "DELETE")
            if provider_created:
                current = admin("/identity-provider/instances/" + provider)
                if current["config"].get("identity-demo-owner") != active_profile().owner or current["config"]["bundleEndpoint"] != endpoint:
                    raise ValueError("Temporary provider cleanup ownership mismatch")
                admin("/identity-provider/instances/" + provider, "DELETE")
            checked("client_inventory_preserved", clients_before == sorted((v["id"], v["clientId"]) for v in admin("/clients")))
            checked("provider_inventory_preserved", providers_before == sorted(v["alias"] for v in admin("/identity-provider/instances")))
            result["temporary_probe_objects_removed"] = True
        except Exception as cleanup_error:
            result["passed"] = False
            result["cleanup_failure_kind"] = type(cleanup_error).__name__
        finally:
            write_private(directory / (args.label + ".json"), result)
    return result


def main() -> None:
    """Return sanitized evidence and withhold all credentials/raw responses."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("kubeconfig", "expected-server", "credentials-file", "workspace-dir", "label"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--check-key-rollover", action="store_true",
                        help="Prepare/activate one JWT authority only after exact foundation ownership checks")
    try:
        result = run(parser.parse_args())
        print(json.dumps(result))
        raise SystemExit(0 if result["passed"] else 1)
    except Exception as error:
        print(json.dumps({"passed": False, "failure_kind": type(error).__name__, "details_withheld": True}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
