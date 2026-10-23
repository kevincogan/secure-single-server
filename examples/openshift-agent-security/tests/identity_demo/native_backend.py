# SPDX-License-Identifier: Apache-2.0
"""Bounded protected-backend integration for the native Step 4 probe.

Use the existing broker, gateway, authorizer and protected adapter. No new
Deployment is introduced. Rendering/readiness is distinct from a successful
native read, and private-route isolation must pass separately.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
from http.client import IncompleteRead
import json
import hashlib
import os
from pathlib import Path
import subprocess
import re
import tempfile
from urllib.error import URLError
from urllib.request import ProxyHandler, build_opener
import time

import gateway_credential_route as route
import probe_broker_discovery as shared
from probe_gateway_credential_route import (
    configuration_checks,
    nested,
    owned_gateway_deployment,
)
from run_binding import ReadRun
from deployment_profile import active_profile

PREFIX = "step4_read_"


def private_authorizer_context(dump,expected_filter=None):
    """Inspect both listeners; redaction needs independently verified source.

    Envoy marks context_extensions sensitive. A redacted value alone proves
    nothing: require the exact receipt-backed filter and no route-level override.
    Actual protected-call acceptance remains separate from this inspection.
    """
    selected = active_profile().private_mcp_authorization_host
    expected = {'host':selected}
    source = []
    if expected_filter is not None:
        for item in expected_filter.get('spec',{}).get('configPatches',[]):
            match = item.get('match',{}).get('routeConfiguration',{})
            port = match.get('portNumber')
            if (item.get('applyTo')=='VIRTUAL_HOST' and port in (8080,8443)
                    and match.get('vhost',{}).get('name')==route.READ_HOST+':'+str(port)):
                value = item['patch']['value'].get('typed_per_filter_config',{}).get(route.FILTER+'-step4',{})
                if (value.get('disabled') is True or value.get('check_settings')!={'context_extensions':expected}):
                    return False
                source.append(port)
    source_verified = sorted(source)==[8080,8443]
    configs,ports = [],[]
    for routes in nested(dump,'route_config'):
        for host in routes.get('virtual_hosts',[]) if isinstance(routes,dict) else []:
            if route.READ_HOST in host.get('domains',[]):
                name = routes.get('name','')
                if name=='http.8080':ports.append(8080)
                elif name.startswith('https.8443.'):ports.append(8443)
                else:return False
                if any(route.FILTER+'-step4' in value for r in host.get('routes',[])
                       for value in nested(r,'typed_per_filter_config')):
                    return False
                value = host.get('typed_per_filter_config',{}).get(route.FILTER+'-step4',{})
                if value.get('disabled') is True:return False
                settings = value.get('check_settings',value.get('checkSettings',{}))
                configs.append(settings.get('context_extensions',settings.get('contextExtensions',{})))
    return sorted(ports)==[8080,8443] and all(v==expected or source_verified and v=={'host':'[redacted]'} for v in configs)
TOOL = PREFIX + "searchJiraIssuesUsingJql"



def reconciliation_status(args: argparse.Namespace, auth_name: str = route.READ_NAME,
                          registration_name: str = route.READ_NAME) -> tuple[dict, dict]:
    """Batch independent current GETs; require every exact owned object separately.

    One CLI invocation still performs two Kubernetes GETs. This saves process and
    discovery overhead; it neither caches an authorization result nor creates an
    atomic snapshot across the two API resources.
    """
    targets = (("authorino.kuadrant.io/v1beta3", "AuthConfig", auth_name),
               ("mcp.kuadrant.io/v1alpha1", "MCPServerRegistration", registration_name))
    references = {'apiVersion': 'v1', 'kind': 'List', 'items': [
        {'apiVersion': api, 'kind': kind, 'metadata': {'name': name, 'namespace': shared.NS}}
        for api, kind, name in targets]}
    live = shared.kube(args, 'get', '-f', '-', '-n', shared.NS, '-o', 'json', payload=references)
    if not isinstance(live, dict) or live.get('kind') != 'List' or not isinstance(live.get('items'), list):
        raise ValueError('Complete current reconciliation inventory required')
    values = {}
    for item in live['items']:
        if not isinstance(item, dict):
            raise ValueError('Exact reconciliation object required')
        metadata = item.get('metadata', {})
        key = (item.get('apiVersion'), item.get('kind'), metadata.get('name'))
        if (key not in targets or key in values or metadata.get('namespace') != shared.NS
                or metadata.get('deletionTimestamp')):
            raise ValueError('Exact current reconciliation object required')
        shared.require_owned(item)
        values[key] = item
    if set(values) != set(targets):
        raise ValueError('Every reconciliation object must be observed')
    return tuple(values[key] for key in targets)


def router_patches(generated: dict) -> list[dict]:
    """Keep private routing and put bound MCP processing after authorization."""
    private = deepcopy(generated)
    private["match"]["listener"]["portNumber"] = 8080
    bound_match = {
        "context": "GATEWAY",
        "listener": {
            "portNumber": 8443,
            "filterChain": {
                "filter": {
                    "name": "envoy.filters.network.http_connection_manager",
                    "subFilter": {"name": "envoy.filters.http.ext_proc"},
                }
            },
        },
    }
    remove = {
        "applyTo": "HTTP_FILTER",
        "match": bound_match,
        "patch": {"operation": "REMOVE"},
    }
    bound = deepcopy(generated)
    bound["match"] = deepcopy(bound_match)
    bound["match"]["listener"]["filterChain"]["filter"]["subFilter"]["name"] = (
        "envoy.filters.http.wasm"
    )
    bound["patch"]["operation"] = "INSERT_AFTER"
    return [private, remove, bound]


def bound_authorization_first(dump: dict) -> bool:
    """Require one bound authorizer before MCP processing in effective Envoy."""
    chains = []
    for listener in nested(dump, "listener"):
        if (
            not isinstance(listener, dict)
            or listener.get("address", {}).get("socket_address", {}).get("port_value")
            != 8443
        ):
            continue
        for filters in nested(listener, "http_filters"):
            if isinstance(filters, list):
                chains.append([f["name"] for f in filters])
    ordered = [
        "envoy.filters.http.wasm",
        "envoy.filters.http.ext_proc",
        route.FILTER + "-step4",
        "envoy.filters.http.router",
    ]
    return bool(chains) and all(
        all(names.count(name) == 1 for name in ordered)
        and [names.index(name) for name in ordered]
        == sorted(names.index(name) for name in ordered)
        for names in chains
    )


def resource_kind(value: dict) -> str:
    """Use the exact API group; installed CRDs can have identical kind names."""
    kind = value["kind"].lower()
    api = value["apiVersion"]
    return kind + "." + api.split("/", 1)[0] if "/" in api else kind


def preflight_resources(args: argparse.Namespace, values: list[dict]) -> None:
    """Batch nonmutating checks; actual create-only writes and UID ledger stay individual."""

    def key(value: dict) -> tuple:
        return (
            value["apiVersion"],
            value["kind"],
            value["metadata"]["name"],
            value["metadata"].get("namespace", shared.NS),
        )

    for value in values:
        shared.require_owned(value)
    expected = {key(v) for v in values}
    if (
        not values
        or len(expected) != len(values)
        or any(k[3] != shared.NS for k in expected)
    ):
        raise ValueError("Unique exact-namespace backend resources required")
    references = {
        "apiVersion": "v1",
        "kind": "List",
        "items": [
            {
                "apiVersion": v["apiVersion"],
                "kind": v["kind"],
                "metadata": {"name": v["metadata"]["name"], "namespace": shared.NS},
            }
            for v in values
        ],
    }
    existing = shared.kube(
        args,
        "get",
        "-n",
        shared.NS,
        "-f",
        "-",
        "--ignore-not-found",
        "-o",
        "json",
        payload=references,
        empty_output={"apiVersion": "v1", "kind": "List", "items": []},
    )
    if (
        not isinstance(existing, dict)
        or existing.get("kind") != "List"
        or not isinstance(existing.get("items"), list)
    ):
        raise ValueError("Explicit collision inventory required")
    if existing["items"]:
        raise ValueError("Existing backend experiment refused")
    admitted = shared.kube(
        args,
        "create",
        "--dry-run=server",
        "-f",
        "-",
        "-o",
        "json",
        payload={"apiVersion": "v1", "kind": "List", "items": values},
        collect_dry_run=True,
    )
    if (
        not isinstance(admitted, dict)
        or admitted.get("kind") != "List"
        or not isinstance(admitted.get("items"), list)
        or len(admitted["items"]) != len(values)
        or {key(v) for v in admitted["items"]} != expected
    ):
        raise ValueError("Complete exact backend admission results required")


class GatewayObservationUnavailable(RuntimeError):
    """A read-only snapshot was incomplete; no protected operation was dispatched."""

    def __init__(self, category: str, body: str = "") -> None:
        super().__init__("Gateway snapshot unavailable: " + category)
        self.summary = {
            "category": category,
            "bytes": len(body.encode()),
            "sha256": hashlib.sha256(body.encode()).hexdigest(),
            "raw_body_withheld": True,
        }


def gateway_http_snapshot(args: argparse.Namespace, pod: str, timeout: float) -> dict:
    """Recover a truncated exec read over an owned, loopback-only API tunnel.

    The caller has just checked Pod ownership. Require the tunnel's own bind
    receipt, bound the complete response, and always terminate our child. No
    gateway configuration, authentication or security validator is changed.
    """
    deadline = time.monotonic() + timeout
    with tempfile.TemporaryFile(mode="w+t") as log:
        process = subprocess.Popen([
            "oc", "--kubeconfig=" + args.kubeconfig, "-n", shared.NS,
            "port-forward", "pod/" + pod, ":15000", "--address=127.0.0.1",
        ], stdout=log, stderr=log)
        try:
            while True:
                log.seek(0)
                text = log.read(8192)
                if any(v in text.lower() for v in ("unauthorized", "forbidden", "x509", "certificate")):
                    raise RuntimeError("Gateway observation authorization/TLS rejected")
                if process.poll() is not None:
                    raise GatewayObservationUnavailable("transport")
                match = re.search(r"Forwarding from 127\.0\.0\.1:(\d+) -> 15000", text)
                if match:
                    port = int(match[1])
                    break
                if time.monotonic() >= deadline:
                    raise GatewayObservationUnavailable("timeout")
                time.sleep(min(.1, max(0, deadline - time.monotonic())))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise GatewayObservationUnavailable("timeout")
            try:
                with build_opener(ProxyHandler({})).open(
                    "http://127.0.0.1:" + str(port) + "/config_dump", timeout=remaining
                ) as response:
                    body = response.read(8 * 1024 * 1024 + 1)
                if len(body) > 8 * 1024 * 1024:
                    raise ValueError("Bounded complete Envoy ConfigDump required")
                dump = json.loads(body)
            except (URLError, TimeoutError, OSError, IncompleteRead, json.JSONDecodeError):
                raise GatewayObservationUnavailable("incomplete_http") from None
            if process.poll() is not None:
                raise GatewayObservationUnavailable("transport")
            if not isinstance(dump, dict) or not isinstance(dump.get("configs"), list):
                raise ValueError("Complete Envoy ConfigDump object required")
            return dump
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


def gateway_snapshot(args: argparse.Namespace, pod: str, timeout: float) -> dict:
    """Read a complete config dump after the caller validates exact Pod ownership.

    Keep the full dump: filtering away listeners/routes could hide a failed
    ordering or TLS check. Only incomplete/transport reads are retryable.
    """
    started = time.monotonic()
    try:
        result = subprocess.run(
            [
                "oc",
                "--kubeconfig=" + args.kubeconfig,
                "--request-timeout=15s",
                "-n",
                shared.NS,
                "exec",
                pod,
                "-c",
                "istio-proxy",
                "--",
                "pilot-agent",
                "request",
                "GET",
                "config_dump",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise GatewayObservationUnavailable("timeout") from None
    if result.returncode:
        error = result.stderr.lower()
        # Permission/TLS failures are terminal, even if their text also says EOF.
        if any(
            v in error for v in ("unauthorized", "forbidden", "x509", "certificate")
        ):
            raise RuntimeError("Gateway observation authorization/TLS rejected")
        if any(
            v in error
            for v in (
                "timeout",
                "timed out",
                "connection reset",
                "broken pipe",
                "unexpected eof",
                "unable to upgrade",
            )
        ):
            raise GatewayObservationUnavailable("transport")
        raise RuntimeError("Gateway observation command failed; details withheld")
    try:
        dump = json.loads(result.stdout)
    except json.JSONDecodeError:
        remaining = timeout - (time.monotonic() - started)
        if remaining <= 0:
            raise GatewayObservationUnavailable("incomplete_json", result.stdout) from None
        return gateway_http_snapshot(args, pod, remaining)
    if not isinstance(dump, dict) or not isinstance(dump.get("configs"), list):
        raise ValueError("Complete Envoy ConfigDump object required")
    return dump


class NativeBackend:
    """Track exact disposable owned resources and their private before-state."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.ledger: list[dict] = []
        self.gateway_before = None
        self.gateway_spec = None
        self.action_driver = bool(getattr(args, "permission_flow", None))
        self.persistent = getattr(args, "gateway_mode", "temporary") == "persistent"
        self.ca: str | None = None

    def save(self, name: str, value: object) -> None:
        """Keep detailed configuration and credential receipts outside Git."""
        shared.write_private(
            Path(self.args.output_dir) / (self.args.label + ".backend-" + name), value
        )

    def authorizer_context(self,dump):
        """Match effective redacted settings to unchanged receipt-proven source."""
        if self.persistent:
            from identity_demo_gateway_persistence import verify
            records = verify(self.args,self.ca)['created']
        else:
            records = self.ledger
        expected, = [v for v in records if v['kind']=='EnvoyFilter' and v['metadata']['name']==route.READ_NAME]
        live = shared.owned(self.args,'envoyfilter.networking.istio.io',route.READ_NAME)
        if live['metadata']['uid']!=expected['metadata']['uid'] or live['spec']!=expected['spec']:
            raise ValueError('Private host source changed; no redaction fallback')
        return private_authorizer_context(dump,expected)

    def prepare(self, ca: str, secret: str, run: ReadRun, credential_file: str) -> None:
        """Dry-run all dependencies; register a separate, read-only broker catalog."""
        if self.persistent:
            if not self.action_driver:
                raise ValueError('Persistent gateway requires live driver authorization')
            self.ca, self.secret = ca, secret
            from identity_demo_gateway_persistence import verify
            self.persistent_receipt = verify(self.args, ca)
            return
        from identity_demo_step4_isolation import policies

        for expected in policies():
            live = shared.owned(
                self.args, "networkpolicy", expected["metadata"]["name"]
            )
            if live["spec"] != expected["spec"]:
                raise ValueError("Exact private-route isolation policies required")
        broad = shared.owned(self.args, "networkpolicy", "fixture-isolation")
        expected_exclusions = {
            "gateway.networking.k8s.io/gateway-name": ["fixture-mcp"],
            "app.kubernetes.io/name": ["mcp-gateway"],
            "app": ["fixture-protected-adapter", "fixture-jira"],
        }
        actual = broad["spec"]["podSelector"].get("matchExpressions", [])
        if (
            len(actual) != 3
            or any(
                e["operator"] != "NotIn"
                or e["values"] != expected_exclusions.get(e["key"])
                for e in actual
            )
            or shared.owned(self.args, "networkpolicy", "fixture-mcp-route-ingress")[
                "spec"
            ].get("ingress", [])
        ):
            raise ValueError("Additive broad/private HTTP bypass must be closed first")
        credential = json.loads(shared.private_path(credential_file).read_text())
        if (
            not credential["token"].startswith("discovery_")
            or credential["expires_at"] <= time.time() + 120
        ):
            raise ValueError(
                "Fresh catalog-only credential with reconciliation time required"
            )
        values = route.native_manifests(ca, secret, run)
        if self.action_driver:
            from identity_demo_action_policy import adapter_rules

            driver = shared.owned(
                self.args, "secret", "fixture-identity-driver-credentials"
            )
            if "gateway_secret" not in driver.get("data", {}):
                raise ValueError("Owned scoped driver credential required")
            values[1]["spec"] = adapter_rules(
                values[1]["spec"],
                write_scope=bool(getattr(self.args, "enable_create", False)),
            )
        if self.action_driver:
            from identity_demo_action_policy import owned_frontend

            values.extend(owned_frontend(ca, run.issuer, run.audience))
        # The operator ADDs its custom Authorino cluster. Istio MERGE cannot
        # modify a cluster added in that same patch pass. Add the exact cluster
        # earlier, scoped to our gateway; leave generated filters untouched.
        baseline = shared.kube(
            self.args,
            "get",
            "envoyfilter.networking.istio.io",
            "fixture-mcp-authn-ssl",
            "-n",
            shared.NS,
            "-o",
            "json",
        )
        patch = deepcopy(baseline["spec"]["configPatches"])
        authorizer_host = route.AUTHORIZER + ".cluster.local"
        expected_address = {
            "socket_address": {"address": authorizer_host, "port_value": 50051}
        }
        if (
            baseline["spec"].get("priority") != -1
            or len(patch) != 1
            or patch[0]["applyTo"] != "CLUSTER"
            or patch[0]["patch"]["operation"] != "ADD"
            or patch[0]["patch"]["value"]["name"] != "kuadrant-auth-service"
            or patch[0]["patch"]["value"]["load_assignment"]["endpoints"][0][
                "lb_endpoints"
            ][0]["endpoint"]["address"]
            != expected_address
        ):
            raise ValueError("Unexpected installed Authorino cluster; refuse override")
        patch[0]["match"] = {"context": "GATEWAY"}
        patch[0]["patch"]["value"]["transport_socket"] = route.tls_context(
            authorizer_host, ca
        )
        tls = route.resource(
            "networking.istio.io/v1alpha3",
            "EnvoyFilter",
            {
                "priority": -2,
                "workloadSelector": {
                    "labels": {
                        "gateway.networking.k8s.io/gateway-name": "fixture-mcp",
                        **shared.LABELS,
                    }
                },
                "configPatches": patch,
            },
        )
        tls["metadata"]["name"] = route.READ_NAME + "-authorino-tls"
        tls["metadata"]["labels"]["istio.io/rev"] = "openshift-gateway"
        values.append(tls)
        extension = shared.owned(
            self.args, "mcpgatewayextension.mcp.kuadrant.io", "fixture-mcp"
        )
        if extension["spec"]["targetRef"].get("sectionName") != "bound":
            raise ValueError("Exact bound-listener extension required")
        generated = shared.kube(
            self.args,
            "get",
            "envoyfilter.networking.istio.io",
            "mcp-ext-proc-" + shared.NS + "-gateway",
            "-n",
            shared.NS,
            "-o",
            "json",
        )
        labels = generated["metadata"].get("labels", {})
        if (
            labels.get("mcp.kuadrant.io/extension-name") != "fixture-mcp"
            or labels.get("mcp.kuadrant.io/extension-namespace") != shared.NS
            or generated["spec"]["workloadSelector"]
            != {"labels": {"gateway.networking.k8s.io/gateway-name": "fixture-mcp"}}
        ):
            raise ValueError("Exact generated owned-extension router required")
        patches = deepcopy(generated["spec"]["configPatches"])
        if (
            len(patches) != 1
            or patches[0]["applyTo"] != "HTTP_FILTER"
            or patches[0]["match"]["listener"].get("portNumber") != 8443
            or patches[0]["patch"]["value"]["name"] != "envoy.filters.http.ext_proc"
            or patches[0]["patch"]["value"]["typed_config"]["failure_mode_allow"]
            is not False
            or patches[0]["patch"]["value"]["typed_config"]["grpc_service"][
                "envoy_grpc"
            ]["cluster_name"]
            != ("outbound|50051||mcp-gateway." + shared.NS + ".svc.cluster.local")
        ):
            raise ValueError("Unexpected router transport; refuse copy")
        # The installed extension puts ext_proc first. It can initialize a
        # backend before frontend authorization, converting viewer denial to
        # 500. On the owned mTLS listener, authorize the original JWT/run/peer
        # before MCP routing, then mediate credentials on the rewritten route.
        patches = router_patches(patches[0])
        router = route.resource(
            "networking.istio.io/v1alpha3",
            "EnvoyFilter",
            {
                "workloadSelector": {
                    "labels": {
                        "gateway.networking.k8s.io/gateway-name": "fixture-mcp",
                        **shared.LABELS,
                    }
                },
                "configPatches": patches,
            },
        )
        router["metadata"]["name"] = route.READ_NAME + "-router"
        router["metadata"]["labels"]["istio.io/rev"] = "openshift-gateway"
        values.append(router)
        grant = route.resource("v1", "Secret")
        grant["metadata"]["name"] = route.READ_NAME + "-catalog"
        grant["metadata"]["labels"]["mcp.kuadrant.io/secret"] = "true"
        grant.update(
            type="Opaque", stringData={"token": "Bearer " + credential["token"]}
        )
        trust = route.resource("v1", "Secret")
        trust["metadata"]["name"] = route.READ_NAME + "-ca"
        trust["metadata"]["labels"]["mcp.kuadrant.io/secret"] = "true"
        trust.update(type="Opaque", stringData={"ca.crt": ca})
        registration = route.resource(
            "mcp.kuadrant.io/v1alpha1",
            "MCPServerRegistration",
            {
                "targetRef": {
                    "group": "gateway.networking.k8s.io",
                    "kind": "HTTPRoute",
                    "name": route.READ_NAME,
                },
                "path": "/mcp",
                "prefix": "step56_jira_" if self.action_driver else PREFIX,
                "state": "Enabled",
                "userSpecificList": "Disabled",
                "credentialRef": {"name": grant["metadata"]["name"], "key": "token"},
                "caCertSecretRef": {"name": trust["metadata"]["name"], "key": "ca.crt"},
            },
        )
        registration["metadata"]["name"] = route.READ_NAME
        values.extend([grant, trust, registration])
        from sender_listener import HOST

        gateway = shared.owned(self.args, "gateway", "fixture-mcp")
        desired = deepcopy(gateway["spec"])
        listeners = [v for v in desired["listeners"] if v["name"] == "bound"]
        if (
            len(listeners) != 1
            or listeners[0].get("hostname") != HOST
            or listeners[0]["tls"].get("mode") != "Terminate"
        ):
            raise ValueError("Exact current bound listener required")
        listeners[0].pop("hostname")
        gateway_patch = [
            {
                "op": "test",
                "path": "/metadata/uid",
                "value": gateway["metadata"]["uid"],
            },
            {
                "op": "test",
                "path": "/metadata/resourceVersion",
                "value": gateway["metadata"]["resourceVersion"],
            },
            {"op": "test", "path": "/spec", "value": gateway["spec"]},
            {"op": "replace", "path": "/spec", "value": desired},
        ]
        shared.kube(
            self.args,
            "patch",
            "gateway",
            "fixture-mcp",
            "-n",
            shared.NS,
            "--type=json",
            "-p",
            json.dumps(gateway_patch),
            "--dry-run=server",
            "-o",
            "json",
        )
        preflight_resources(self.args, values)
        self.planned_values = values
        self.planned_gateway = gateway
        self.planned_gateway_spec = desired
        if getattr(self.args, 'gateway_plan_only', False):
            return
        for value in values:
            made = shared.kube(
                self.args, "create", "-f", "-", "-o", "json", payload=value
            )
            self.ledger.append(made)
            self.save(
                "created-"
                + made["kind"]
                + "-"
                + made["metadata"]["name"]
                + ".private.json",
                made,
            )
        self.save("gateway-before.private.json", gateway)
        # Creating routes updates Gateway status. Refresh only the version after
        # confirming that ownership, UID and the complete spec are unchanged.
        current = shared.owned(self.args, "gateway", "fixture-mcp")
        if (
            current["metadata"]["uid"] != gateway["metadata"]["uid"]
            or current["spec"] != gateway["spec"]
        ):
            raise ValueError("Bound listener changed independently; refuse patch")
        gateway_patch[1]["value"] = current["metadata"]["resourceVersion"]
        made = shared.kube(
            self.args,
            "patch",
            "gateway",
            "fixture-mcp",
            "-n",
            shared.NS,
            "--type=json",
            "-p",
            json.dumps(gateway_patch),
            "-o",
            "json",
        )
        self.gateway_before, self.gateway_spec = gateway, made["spec"]
        self.save("gateway-after.private.json", made)
        deployment = shared.owned(
            self.args, "deployment", "fixture-mcp-openshift-ai-inference"
        )
        if not owned_gateway_deployment(deployment, gateway):
            raise ValueError("Owned gateway controller required")
        self.ca = ca
        self.secret = secret

    def set_run(self, run: ReadRun) -> None:
        """Reconcile cancellation on the private grant with exact state guards."""
        if self.action_driver:
            raise ValueError(
                "Durable driver cancellation cannot use a diagnostic static-policy rewrite"
            )
        index = next(
            i for i, item in enumerate(self.ledger) if item["kind"] == "AuthConfig"
        )
        before = self.ledger[index]
        live = shared.owned(
            self.args, "authconfig.authorino.kuadrant.io", route.READ_NAME
        )
        if (
            live["metadata"]["uid"] != before["metadata"]["uid"]
            or live["spec"] != before["spec"]
        ):
            raise ValueError("Private run policy changed independently")
        desired = route.native_manifests(self.ca, self.secret, run)[1]["spec"]
        operations = [
            {"op": "test", "path": "/metadata/uid", "value": live["metadata"]["uid"]},
            {
                "op": "test",
                "path": "/metadata/resourceVersion",
                "value": live["metadata"]["resourceVersion"],
            },
            {"op": "test", "path": "/spec", "value": live["spec"]},
            {"op": "replace", "path": "/spec", "value": desired},
        ]
        made = shared.kube(
            self.args,
            "patch",
            "authconfig.authorino.kuadrant.io",
            route.READ_NAME,
            "-n",
            shared.NS,
            "--type=json",
            "-p",
            json.dumps(operations),
            "-o",
            "json",
        )
        self.ledger[index] = made
        self.save("run-cancelled.private.json", made)

    def ready(self) -> dict:
        """Require live TLS configuration and real protected backend discovery."""
        if os.environ.get('IDENTITY_DEMO_RUNTIME') == 'cluster':
            if not self.persistent or not self.action_driver or self.ca is None:
                raise ValueError('Cluster runtime requires the prepared persistent gateway')
            from identity_demo_gateway_observation import current,GatewayDiscoveryPending
            deadline,attempt = time.monotonic()+30,0
            while True:
                try:
                    checks = current(self.args,self.ca)
                    break
                except GatewayDiscoveryPending as error:
                    # A catalog reconcile can race admission. Observe only; no
                    # exchange, tool call, claim or mutation has been sent here.
                    attempt += 1
                    self.save('discovery-wait-'+str(attempt)+'.summary.json',error.observation)
                    if time.monotonic()>=deadline:raise
                    time.sleep(min(2,max(0,deadline-time.monotonic())))
            self.save('ready.summary.json', {'checks':checks,
                'scope':'Unchanged installer-observed gateway process/configuration plus live controller readiness; native protected call still required',
                'runtime_pod_exec_used':False})
            return checks
        deadline = time.monotonic() + 120
        notices = 0.0
        dump = {}
        live = {}
        observation_failures = 0
        flow = getattr(self.args, "permission_flow", None)
        if flow is not None:
            flow.progress("waiting_gateway")
        while time.monotonic() < deadline:
            auth, live = reconciliation_status(self.args)
            if any(
                c.get("type") == "Ready" and c.get("reason") in ("Invalid", "HostsNotLinked")
                for c in auth.get("status", {}).get("conditions", [])
            ):
                self.save("invalid-authorizer.private.json", auth)
                raise ValueError("Native backend authorizer configuration was rejected")

            discovered = live.get("status", {}).get("discoveredTools") == 2 and any(
                c.get("type") == "Ready" and c.get("status") == "True"
                for c in live.get("status", {}).get("conditions", [])
            )
            if not discovered:
                if time.monotonic() - notices > 30:
                    print(
                        json.dumps(
                            {
                                "stage": "protected_backend_reconciliation",
                                "catalog_discovered": False,
                            }
                        ),
                        flush=True,
                    )
                    notices = time.monotonic()
                time.sleep(2)
                continue
            pods = shared.kube(
                self.args,
                "get",
                "pods",
                "-n",
                shared.NS,
                "-l",
                "gateway.networking.k8s.io/gateway-name=fixture-mcp",
                "-o",
                "json",
            )["items"]
            pods = [p for p in pods if not p["metadata"].get("deletionTimestamp")]
            if len(pods) != 1 or any(
                pods[0]["metadata"].get("labels", {}).get(k) != v
                for k, v in shared.LABELS.items()
            ):
                raise ValueError("One exact owned gateway Pod required")
            try:
                dump = gateway_snapshot(
                    self.args,
                    pods[0]["metadata"]["name"],
                    min(25, max(0.1, deadline - time.monotonic())),
                )
            except GatewayObservationUnavailable as error:
                observation_failures += 1
                self.save(
                    "observation-" + str(observation_failures) + ".summary.json",
                    error.summary,
                )
                if observation_failures >= 3:
                    raise RuntimeError(
                        "Gateway snapshot remained unavailable after three bounded reads"
                    ) from None
                time.sleep(min(2, max(0, deadline - time.monotonic())))
                continue  # Revalidate current ownership/discovery; never reuse an older snapshot.
            checks = configuration_checks(
                dump,
                self.ca,
                host=route.READ_HOST,
                filter_name=route.FILTER + "-step4",
                cluster_name=route.CLUSTER + "-step4",
            )
            if active_profile().private_mcp_authorization_host != route.READ_HOST:
                checks['diagnostic-host-enables-extra-filter'] = (
                    checks['diagnostic-host-enables-extra-filter'] and self.authorizer_context(dump))
            baseline_clusters = [
                c
                for c in nested(dump, "cluster")
                if isinstance(c, dict) and c.get("name") == "kuadrant-auth-service"
            ]
            checks["baseline-authorino-explicit-ca-and-name-check"] = len(
                baseline_clusters
            ) == 1 and (
                baseline_clusters[0].get("transport_socket")
                == route.tls_context(route.AUTHORIZER + ".cluster.local", self.ca)
            )
            checks["bound-authorization-before-mcp-processing"] = (
                bound_authorization_first(dump)
            )
            if self.action_driver:
                frontend = shared.owned(
                    self.args, "authconfig", "fixture-step56-live-identity"
                )
                checks["owned-live-identity-config-ready"] = (
                    frontend.get("status", {}).get("summary", {}).get("ready") is True
                )
                names = [
                    names
                    for listener in nested(dump, "listener")
                    if isinstance(listener, dict)
                    and listener.get("address", {})
                    .get("socket_address", {})
                    .get("port_value")
                    == 8443
                    for names in nested(listener, "http_filters")
                    if isinstance(names, list)
                ]
                f = "envoy.filters.http.ext_authz.step56_identity"
                checks["live-identity-before-mcp-processing"] = bool(names) and all(
                    [x["name"] for x in chain].count(f) == 1
                    and [x["name"] for x in chain].index(f)
                    < [x["name"] for x in chain].index("envoy.filters.http.ext_proc")
                    for chain in names
                )
            live = shared.owned(
                self.args, "mcpserverregistration.mcp.kuadrant.io", route.READ_NAME
            )
            discovered = live.get("status", {}).get("discoveredTools") == 2 and any(
                c.get("type") == "Ready" and c.get("status") == "True"
                for c in live.get("status", {}).get("conditions", [])
            )
            if all(checks.values()) and discovered:
                self.save("effective-envoy.private.json", dump)
                checks["protected_backend_catalog_discovered"] = True
                self.save("ready.summary.json", checks)
                return checks
            if time.monotonic() - notices > 30:
                print(
                    json.dumps(
                        {
                            "stage": "protected_backend_reconciliation",
                            "tls_checks": checks,
                            "catalog_discovered": discovered,
                        }
                    ),
                    flush=True,
                )
                notices = time.monotonic()
            time.sleep(2)
        self.save("last-envoy.private.json", dump)
        self.save("last-registration.private.json", live)
        raise TimeoutError("Protected backend TLS/discovery gate did not pass")

    def cleanup(self) -> None:
        """Delete only resources with the exact recorded UID, ownership and spec."""
        if self.persistent:
            from identity_demo_gateway_persistence import verify
            # Issuer setup can fail before prepare() receives its public CA.
            # Still positively verify the unchanged persistent installation;
            # absence of per-run setup is not itself cleanup evidence.
            ca = self.ca
            if ca is None:
                ca = shared.owned(self.args, 'configmap', 'fixture-service-ca')['data']['service-ca.crt']
            verify(self.args, ca, require_catalog_fresh=False)
            self.save('cleanup.summary.json', {'persistent_gateway_preserved': True, 'run_authority_closed_separately': True})
            return
        plural = {
            "Secret": "/api/v1/namespaces/" + shared.NS + "/secrets/",
            "AuthPolicy": "/apis/kuadrant.io/v1/namespaces/"
            + shared.NS
            + "/authpolicies/",
            "AuthConfig": "/apis/authorino.kuadrant.io/v1beta3/namespaces/"
            + shared.NS
            + "/authconfigs/",
            "HTTPRoute": "/apis/gateway.networking.k8s.io/v1/namespaces/"
            + shared.NS
            + "/httproutes/",
            "EnvoyFilter": "/apis/networking.istio.io/v1alpha3/namespaces/"
            + shared.NS
            + "/envoyfilters/",
            "MCPServerRegistration": "/apis/mcp.kuadrant.io/v1alpha1/namespaces/"
            + shared.NS
            + "/mcpserverregistrations/",
        }
        for before in reversed(self.ledger):
            live = shared.kube(
                self.args,
                "get",
                resource_kind(before),
                before["metadata"]["name"],
                "-n",
                shared.NS,
                "--ignore-not-found",
                "-o",
                "json",
            )
            if not live:
                continue
            # The first read already carries the exact labels, UID and RV.
            # Preserve every guard without paying for a duplicate oc/API read.
            shared.require_owned(live)
            if live["metadata"]["uid"] != before["metadata"]["uid"] or any(
                live.get(k) != before.get(k) for k in ("spec", "data", "type")
            ):
                raise ValueError("Backend object drift; refuse cleanup")
            name = before["metadata"]["name"]
            for attempt in range(3):
                path = Path(self.args.output_dir) / (
                    self.args.label
                    + ".backend-delete-"
                    + before["kind"]
                    + "-"
                    + name
                    + "-"
                    + str(attempt)
                    + ".private.json"
                )
                shared.write_private(
                    path,
                    {
                        "apiVersion": "v1",
                        "kind": "DeleteOptions",
                        "preconditions": {
                            "uid": live["metadata"]["uid"],
                            "resourceVersion": live["metadata"]["resourceVersion"],
                        },
                    },
                )
                try:
                    shared.kube(
                        self.args,
                        "delete",
                        "--raw",
                        plural[before["kind"]] + name,
                        "-f",
                        str(path),
                    )
                    break
                except RuntimeError:
                    # Status reconciliation can race a conditional delete.
                    # Recheck UID and every protected field; never delete drift.
                    live = shared.kube(
                        self.args,
                        "get",
                        resource_kind(before),
                        name,
                        "-n",
                        shared.NS,
                        "--ignore-not-found",
                        "-o",
                        "json",
                    )
                    if not live:
                        break
                    shared.require_owned(live)
                    if (
                        live["metadata"]["uid"] != before["metadata"]["uid"]
                        or any(
                            live.get(k) != before.get(k)
                            for k in ("spec", "data", "type")
                        )
                        or any(
                            live["metadata"].get("labels", {}).get(k) != v
                            for k, v in shared.LABELS.items()
                        )
                        or attempt == 2
                    ):
                        raise
        self.save(
            "cleanup.summary.json",
            {
                "owned_backend_resources_removed": True,
                "checked_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        if self.gateway_before is not None:
            live = shared.owned(self.args, "gateway", "fixture-mcp")
            if (
                live["metadata"]["uid"] != self.gateway_before["metadata"]["uid"]
                or live["spec"] != self.gateway_spec
            ):
                raise ValueError("Bound listener drift; refuse restore")
            operations = [
                {
                    "op": "test",
                    "path": "/metadata/uid",
                    "value": live["metadata"]["uid"],
                },
                {
                    "op": "test",
                    "path": "/metadata/resourceVersion",
                    "value": live["metadata"]["resourceVersion"],
                },
                {"op": "test", "path": "/spec", "value": live["spec"]},
                {
                    "op": "replace",
                    "path": "/spec",
                    "value": self.gateway_before["spec"],
                },
            ]
            shared.kube(
                self.args,
                "patch",
                "gateway",
                "fixture-mcp",
                "-n",
                shared.NS,
                "--type=json",
                "-p",
                json.dumps(operations),
                "-o",
                "json",
            )
            self.save(
                "gateway-restored.summary.json", {"bound_listener_restored": True}
            )
