# SPDX-License-Identifier: Apache-2.0
"""Bounded live dependency failures on exact owned Services, with guarded restore."""
from deployment_profile import active_profile

import argparse
from contextlib import contextmanager
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import time
from typing import Callable, Iterator
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener
from uuid import uuid4

from identity_demo_action_policy import DRIVER
from lifecycle_flow import LifecycleFlow
from native_sender_acceptance import SenderAcceptance
from identity_demo_keycloak_upstream import BASE
import probe_native_exchange as native
from sender_listener import HOST
from checks.test_components import NoRedirect


def service_grant(secret: str) -> tuple[int, bytes]:
    """Make the fixed issuer's server-to-server grant, with no browser Origin."""
    client = build_opener(ProxyHandler({}), NoRedirect())
    fields = {"grant_type": "client_credentials", "client_id": "fixture-gateway-service",
              "client_secret": secret}
    request = Request(BASE + "/realms/identity-demo/protocol/openid-connect/token",
        data=urlencode(fields).encode(), headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        response = client.open(request, timeout=8)
    except HTTPError as error:
        response = error
    with response:
        body = response.read(65_537)
        if len(body) > 65_536:
            raise ValueError("Bounded service-grant response required")
        return response.status, body


def ready_endpoints(value: dict) -> bool:
    """Treat Kubernetes' null endpoint lists as empty during Service transitions."""
    return any(e.get("addresses") and e.get("conditions", {}).get("ready", True)
               for item in value.get("items", []) or []
               for e in item.get("endpoints", []) or [])


class IsolatedService:
    """Temporarily select no backend; never stop a pod or change another Service."""

    def __init__(self, read: Callable, patch: Callable, name: str,
                 wait_restored: Callable | None = None) -> None:
        if name not in ("fixture-identity-driver", "fixture-keycloak-upstream", "fixture-protected-adapter"):
            raise ValueError("Exact owned dependency required")
        self.read, self.patch, self.name = read, patch, name
        self.wait_restored = wait_restored
        self.before = read(name)
        if (self.before["metadata"].get("namespace") != native.NAMESPACE
                or any(self.before["metadata"].get("labels", {}).get(k) != v
                       for k, v in native.LABELS.items())):
            raise ValueError("Exact owned Service required")
        if not self.before["spec"].get("selector"):
            raise ValueError("Selector-based Service required")
        self.desired = {**self.before["spec"]["selector"],
                        "identity-demo-unavailable-probe": str(uuid4())}

    def change(self, expected: dict, desired: dict) -> dict:
        """Use UID/version/spec preconditions; refuse independent changes."""
        current = self.read(self.name)
        if (current["metadata"]["uid"] != self.before["metadata"]["uid"]
                or current["spec"] != expected):
            raise ValueError("Dependency Service changed independently")
        return self.patch(self.name, [
            {"op": "test", "path": "/metadata/uid", "value": current["metadata"]["uid"]},
            {"op": "test", "path": "/metadata/resourceVersion", "value": current["metadata"]["resourceVersion"]},
            {"op": "test", "path": "/spec", "value": expected},
            {"op": "replace", "path": "/spec/selector", "value": desired},
        ])

    @contextmanager
    def unavailable(self) -> Iterator[None]:
        """Restore a confirmed change even if its API response was lost."""
        expected = {**deepcopy(self.before["spec"]), "selector": self.desired}
        try:
            self.change(self.before["spec"], self.desired)
            yield
        finally:
            current = self.read(self.name)
            if current["metadata"]["uid"] != self.before["metadata"]["uid"]:
                raise ValueError("Dependency Service replaced; refuse restore")
            if current["spec"] != self.before["spec"]:
                self.change(expected, self.before["spec"]["selector"])
            if self.wait_restored is not None:
                self.wait_restored()


class DependencyFlow(LifecycleFlow):
    """Prove actual approved writes fail closed when live dependencies disappear."""

    def accept(self, execute: Callable, resource: str, context: object) -> dict:
        """Do not dispatch writes; restore Services and verify native read recovery."""
        before = self.backend_count()
        native.private_write(self.args.output_dir / "backend-before.summary.json", {"issues": before})
        fixture = Path(__file__).with_name("cve_runtime_fixture.py").read_text()
        report = execute(["sandbox", "exec", "--name", context.sandbox_name,
            "--no-login-shell", "--timeout", "90", "--no-tty", "--", "python", "-c",
            "ns={'__name__':'fixture'};exec(" + repr(fixture)
            + ",ns);import asyncio,json;print(json.dumps(asyncio.run(ns['assessment_fixture']())))"], json_output=True)
        status, _, body = self.http(DRIVER + "/internal/operator/report", operator=True,
            value={"run_id": self.run_id, "user": self.user, "workload": context.workload,
                   "assessment": report["assessment"], "arguments": report["proposed_create"]})
        assert status == 200
        self.proposal = json.loads(body)
        arguments = {"run_id": self.run_id, "action_id": self.proposal["action_id"], **self.proposal["arguments"]}
        status, _, _ = self.http(DRIVER + "/runs/" + self.run_id + "/approve",
            fields={"csrf": self.csrf, "action": self.proposal["action_id"], "digest": self.proposal["digest"]})
        assert status == 303 and self.action_record()["dispatch_claims"] == 0
        sender = SenderAcceptance(argparse.Namespace(**{**vars(self.args), "label": self.args.label + "-dependencies"}), {"sub": self.user})
        cases = []
        clients = self.issuer_admin("/clients?clientId=fixture-gateway-service")
        assert len(clients) == 1 and clients[0]["attributes"]["identity-demo-owner"] == active_profile().owner
        secret = self.issuer_admin("/clients/" + clients[0]["id"] + "/client-secret")["value"]

        def grant() -> tuple:
            return service_grant(secret)

        assert grant()[0] == 200

        def read(name: str) -> dict:
            return native.kube(self.args, "get", "service", name, "-n", native.NAMESPACE, "-o", "json")

        def patch(name: str, operations: list) -> dict:
            return native.kube(self.args, "patch", "service", name, "-n", native.NAMESPACE,
                               "--type=json", "-p", json.dumps(operations), "-o", "json")

        def endpoints(name: str, present: bool) -> None:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                value = native.kube(self.args, "get", "endpointslices.discovery.k8s.io", "-n", native.NAMESPACE,
                    "-l", "kubernetes.io/service-name=" + name, "-o", "json")
                found = ready_endpoints(value)
                if found == present:
                    return
                time.sleep(.5)
            raise TimeoutError("Dependency endpoint transition not confirmed")

        for name in ("fixture-identity-driver", "fixture-keycloak-upstream", "fixture-protected-adapter"):
            leaf = sender.certificate(name)
            assert leaf.expires_at > time.time() + 50
            token, claims = sender.final(leaf)
            sessions = sender.initialize_session(name, token, leaf)
            isolation = IsolatedService(read, patch, name, lambda: endpoints(name, True))
            native.private_write(self.args.output_dir / (name + "-service-before.private.json"), isolation.before)
            # Acquire fresh credentials after initialization, immediately before interruption.
            token, claims = sender.final(leaf)
            with isolation.unavailable():
                endpoints(name, False)
                started = time.monotonic()
                status, response = sender.request(19444, HOST, "/mcp",
                    json.dumps({"jsonrpc": "2.0", "id": 12, "method": "tools/call",
                        "params": {"name": "step56_jira_createJiraIssue", "arguments": arguments}}).encode(),
                    leaf, {"Authorization": "Bearer " + token, "Content-Type": "application/json",
                           "Accept": "application/json, text/event-stream", **sessions})
                sender.save(name + "-unavailable.private.json", {"status": status, "body": response.decode()})
                assert status in (403, 500, 502, 503, 504), "Unavailable dependency must reject the approved mutation"
                assert claims["exp"] > time.time() and leaf.expires_at > time.time(), "Denial must precede credential expiry"
                assert self.action_record()["dispatch_claims"] == 0
                cases.append({"case": name + "_unavailable", "http_status": status,
                    "valid_bound_credential_at_denial": True, "dispatch_claims": 0,
                    "elapsed_seconds": round(time.monotonic() - started, 3), "passed": True})
                if name == "fixture-keycloak-upstream":
                    grant_status, body = grant()
                    assert grant_status >= 400 and b'"access_token"' not in body
                    cases[-1].update(new_grant_denied=True, grant_http_status=grant_status)
            endpoints(name, True)
            assert read(name)["spec"] == isolation.before["spec"]
            assert self.backend_count() == before
            if name == "fixture-keycloak-upstream":
                assert grant()[0] == 200
            recovered = execute(["sandbox", "exec", "--name", context.sandbox_name,
                "--no-login-shell", "--timeout", "90", "--no-tty", "--", "python", "-c",
                self.read_program(resource)], json_output=True)
            assert recovered["read_passed"]
            cases[-1].update(service_restored=True, native_read_recovered=True, backend_unchanged=True)
            print(json.dumps({"stage": "dependency_gate_passed", **cases[-1]}), flush=True)

        deployment = native.kube(self.args, "get", "deployment", "fixture-protected-adapter", "-n", native.NAMESPACE, "-o", "json")
        assert deployment["metadata"]["labels"]["identity-demo-owner"] == active_profile().owner
        for command in (("restart",), ("status", "--timeout=90s")):
            result = subprocess.run(["oc", "--kubeconfig", self.args.kubeconfig, "-n", native.NAMESPACE,
                "rollout", command[0], "deployment/fixture-protected-adapter", *command[1:]], capture_output=True, timeout=100)
            assert result.returncode == 0
        recovered = execute(["sandbox", "exec", "--name", context.sandbox_name,
            "--no-login-shell", "--timeout", "90", "--no-tty", "--", "python", "-c",
            self.read_program(resource)], json_output=True)
        assert recovered["read_passed"] and self.backend_count() == before
        assert self.action_record()["dispatch_claims"] == 0
        self.close()
        summary = {"passed": True, "cases": cases, "adapter_restart_native_read_recovered": True,
            "backend_before": before, "backend_after": self.backend_count(), "writes_dispatched": 0,
            "driver_process_restart": "carried from accepted lost-response recovery",
            "issuer_new_grant_outage_proven": True, "steps5_and6_complete": False}
        native.private_write(self.args.output_dir / (self.args.label + ".dependency.summary.json"), summary)
        return summary
