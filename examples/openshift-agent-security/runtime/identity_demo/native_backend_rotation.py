# SPDX-License-Identifier: Apache-2.0
"""Exercise gateway service-secret rotation and denied grants on the native path."""

from __future__ import annotations
from deployment_profile import active_profile

import base64
from copy import deepcopy
import json
from typing import Callable

import gateway_credential_route as route
import probe_native_exchange as native
from native_backend import NativeBackend


def check(backend: NativeBackend, admin: Callable, execute: Callable, resource: str, tool: str) -> dict:
    """Rotate only the owned development service client and disposable Secret.

    The fixture's original service secret is restored even on failure; no
    unrelated client or Secret is edited. Raw rotation responses remain private.
    Final tool access still requires the bound human/workload/run decision.
    """
    args = backend.args
    clients = admin("/clients?clientId=fixture-gateway-service")
    if len(clients) != 1 or clients[0]["clientId"] != "fixture-gateway-service":
        raise ValueError("One exact gateway service client required")
    client = clients[0]
    attributes = client.get("attributes", {})
    if attributes.get("identity-demo-owner") != active_profile().owner:
        raise ValueError("Owned service client required")
    path = "/clients/" + client["id"]
    old = admin(path + "/client-secret")["value"]
    backend.save("service-client-before.private.json", client)
    index = next(i for i, v in enumerate(backend.ledger) if v["kind"] == "Secret"
                 and v["metadata"]["name"] == route.READ_NAME)
    before = deepcopy(backend.ledger[index])
    rotated = False

    def set_secret(value: str) -> None:
        current = native.kube(args, "get", "secret", route.READ_NAME, "-n", native.NAMESPACE, "-o", "json")
        expected = backend.ledger[index]
        if (current["metadata"]["uid"] != expected["metadata"]["uid"]
                or current["data"] != expected["data"]
                or any(current["metadata"].get("labels", {}).get(k) != v for k, v in native.LABELS.items())):
            raise ValueError("Gateway credential Secret drift; refuse change")
        # The existing data contains a base64-encoded Basic credential which
        # Kubernetes itself base64-encodes once more for Secret representation.
        basic = base64.b64encode(("fixture-gateway-service:" + value).encode()).decode()
        # HTTP sharedSecretRef is resolved when AuthConfig reconciles; the
        # Secret watcher refreshes K8s identity evaluators only. A different
        # reference key creates a real spec change and reloads this grant.
        ref_key = "basic" if value == old else "basic-rotated"
        data = deepcopy(before["data"])
        data[ref_key] = base64.b64encode(basic.encode()).decode()
        operations = [{"op": "test", "path": "/metadata/uid", "value": current["metadata"]["uid"]},
                      {"op": "test", "path": "/metadata/resourceVersion", "value": current["metadata"]["resourceVersion"]},
                      {"op": "test", "path": "/data", "value": current["data"]},
                      {"op": "replace", "path": "/data", "value": data}]
        saved = native.kube(args, "patch", "secret", route.READ_NAME, "-n", native.NAMESPACE,
            "--type=json", "-p", json.dumps(operations), "-o", "json")
        backend.ledger[index] = saved
        backend.save("service-secret-" + str(saved["metadata"]["resourceVersion"]) + ".private.json", saved)
        auth_index = next(i for i, v in enumerate(backend.ledger) if v["kind"] == "AuthConfig")
        expected_auth = backend.ledger[auth_index]
        auth = native.kube(args, "get", "authconfig.authorino.kuadrant.io", route.READ_NAME,
            "-n", native.NAMESPACE, "-o", "json")
        if (auth["metadata"]["uid"] != expected_auth["metadata"]["uid"]
                or auth["spec"] != expected_auth["spec"]
                or any(auth["metadata"].get("labels", {}).get(k) != v for k, v in native.LABELS.items())):
            raise ValueError("Grant configuration drift; refuse credential reload")
        desired = deepcopy(auth["spec"])
        desired["metadata"]["adapter-token"]["http"]["sharedSecretRef"]["key"] = ref_key
        if desired != auth["spec"]:
            operations = [{"op": "test", "path": "/metadata/uid", "value": auth["metadata"]["uid"]},
                          {"op": "test", "path": "/metadata/resourceVersion", "value": auth["metadata"]["resourceVersion"]},
                          {"op": "test", "path": "/spec", "value": auth["spec"]},
                          {"op": "replace", "path": "/spec", "value": desired}]
            saved_auth = native.kube(args, "patch", "authconfig.authorino.kuadrant.io", route.READ_NAME,
                "-n", native.NAMESPACE, "--type=json", "-p", json.dumps(operations), "-o", "json")
            backend.ledger[auth_index] = saved_auth
            backend.save("grant-reload-" + str(saved_auth["metadata"]["resourceVersion"]) + ".private.json", saved_auth)

    def read() -> dict:
        return execute(["sandbox", "exec", "--name", native.SANDBOX, "--no-login-shell", "--timeout", "90",
            "--no-tty", "--", "python", "-c", native.read_program(resource, tool)], json_output=True)

    try:
        new = admin(path + "/client-secret", "POST")["value"]
        rotated = True
        if not new or new == old:
            raise ValueError("Distinct rotated service secret required")
        backend.save("service-rotation.private.json", {"client_id": client["id"], "old": old, "new": new})
        # Invalidate any configured old-secret overlap using Keycloak's supported
        # API, so a stale grant cannot hide failed Secret delivery.
        admin(path + "/client-secret/rotated", "DELETE")
        failed = read()
        if failed.get("read_passed") is not False or not any(
            e.get("http_status", 0) >= 400 for e in failed.get("events", [])
        ):
            raise ValueError("Invalidated gateway credential did not fail closed")
        set_secret(new)
        import time

        deadline = time.monotonic() + 60
        attempts = []
        while time.monotonic() < deadline:
            recovered = read()
            attempts.append(recovered.get("read_passed") is True)
            if attempts[-1]:
                break
            time.sleep(2)
        else:
            raise TimeoutError("Gateway did not recover with the rotated service secret")
        summary = {"passed": True, "invalidated_old_secret_denied": True,
            "new_secret_native_protected_read": True, "recovery_attempts": len(attempts),
            "automatic_service_token_grants": True, "automatic_secret_rotation": False,
            "manual_authconfig_reference_reload": True,
            "original_service_secret_restored": False}
    finally:
        if rotated:
            current = admin(path)
            guarded = ("clientId", "enabled", "clientAuthenticatorType", "publicClient",
                       "serviceAccountsEnabled", "standardFlowEnabled", "directAccessGrantsEnabled",
                       "fullScopeAllowed", "defaultClientScopes", "optionalClientScopes", "protocolMappers")
            original_attrs = {k: v for k, v in client.get("attributes", {}).items()
                              if k != "client.secret.creation.time"}
            current_attrs = {k: v for k, v in current.get("attributes", {}).items()
                             if k != "client.secret.creation.time"}
            if (current["id"] != client["id"] or original_attrs != current_attrs
                    or any(current.get(k) != client.get(k) for k in guarded)):
                raise ValueError("Service client drift; refuse restore")
            # Restore rotation timestamps/attributes too, so the original
            # issuer inventory remains comparable after this bounded test.
            admin(path, "PUT", {"secret": old, "attributes": client.get("attributes", {})})
            if admin(path + "/client-secret")["value"] != old:
                raise ValueError("Original service secret restore not verified")
            # Updating a secret assigns a fresh creation timestamp. A second
            # attributes-only update restores the recorded metadata without
            # generating another timestamp or changing the secret again.
            admin(path, "PUT", {"attributes": client.get("attributes", {})})
            set_secret(old)
            if backend.ledger[index]["data"] != before["data"]:
                raise ValueError("Original gateway credential restore not verified")
    summary["original_service_secret_restored"] = True
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if read().get("read_passed") is True:
            summary["native_read_after_original_secret_restore"] = True
            break
        time.sleep(2)
    else:
        raise TimeoutError("Native route did not recover after the original service secret was restored")
    backend.save("service-rotation.summary.json", summary)
    return summary
