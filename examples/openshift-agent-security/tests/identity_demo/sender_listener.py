# SPDX-License-Identifier: Apache-2.0
"""Render the bounded internal mTLS listener on the existing owned gateway.

Rendering is not live sender-binding evidence. Serving certificates come from
the service-CA controller; client trust contains public SPIRE roots only.
"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "identity_demo"))
from identity_demo_lab import LABELS  # noqa: E402
from deployment_profile import active_profile  # noqa: E402

NS = active_profile().core_namespace
NAME = "fixture-mcp-bound"
# Native policy DNS sends an absolute query; it does not append Kubernetes
# search domains. The service certificate covers this full cluster DNS name.
HOST = NAME + "." + NS + ".svc.cluster.local"
RESOURCE = "https://" + HOST + "/mcp"
PORT = 8443


def owned_resource(api: str, kind: str, name: str = NAME) -> dict:
    """Name resources solely within the owned pilot namespace."""
    return {"apiVersion": api, "kind": kind, "metadata": {
        "name": name, "namespace": NS, "labels": dict(LABELS)}}


def listener() -> dict:
    """Require chain-validated client authentication; no optional TLS mode."""
    return {"name": "bound", "protocol": "HTTPS", "port": PORT,
            "hostname": HOST, "allowedRoutes": {"namespaces": {"from": "Same"}},
            "tls": {"mode": "Terminate", "certificateRefs": [{
                "group": "", "kind": "Secret", "name": NAME + "-mutual"}],
                "options": {"gateway.istio.io/tls-terminate-mode": "MUTUAL"}}}


def gateway_patch(current: dict) -> list[dict]:
    """Append only our listener; reject ownership mismatch or configuration drift."""
    meta = current["metadata"]
    if (meta.get("namespace") != NS or meta.get("name") != "fixture-mcp"
            or any(meta.get("labels", {}).get(k) != v for k, v in LABELS.items())):
        raise ValueError("Exact owned gateway required")
    listeners = current["spec"]["listeners"]
    if any(v["name"] == "bound" or v["port"] == PORT for v in listeners):
        raise ValueError("Existing listener/port collision")
    return [{"op": "test", "path": "/metadata/uid", "value": meta["uid"]},
            {"op": "test", "path": "/metadata/resourceVersion", "value": meta["resourceVersion"]},
            {"op": "test", "path": "/spec", "value": deepcopy(current["spec"])},
            {"op": "add", "path": "/spec/listeners/-", "value": listener()}]


def resources() -> list[dict]:
    """Reuse the gateway/broker; add no proxy Deployment or public Route."""
    service = owned_resource("v1", "Service")
    service["metadata"]["annotations"] = {
        "service.beta.openshift.io/serving-cert-secret-name": NAME + "-serving"}
    service["spec"] = {"selector": {"gateway.networking.k8s.io/gateway-name": "fixture-mcp"},
                       "ports": [{"name": "https", "port": 443, "targetPort": PORT}]}
    route = owned_resource("gateway.networking.k8s.io/v1", "HTTPRoute")
    route["spec"] = {"parentRefs": [{"name": "fixture-mcp", "sectionName": "bound"}],
                     "hostnames": [HOST], "rules": [{"matches": [{"path": {
                         "type": "Exact", "value": "/mcp"}}],
                         "backendRefs": [{"name": "mcp-gateway", "port": 8080}]}]}
    xfcc = owned_resource("networking.istio.io/v1alpha3", "EnvoyFilter", NAME + "-peer")
    xfcc["metadata"]["labels"]["istio.io/rev"] = "openshift-gateway"
    xfcc["spec"] = {"workloadSelector": {"labels": {
        "gateway.networking.k8s.io/gateway-name": "fixture-mcp", **LABELS}},
        "configPatches": [{"applyTo": "NETWORK_FILTER", "match": {
            "context": "GATEWAY", "listener": {"portNumber": PORT, "filterChain": {
                "filter": {"name": "envoy.filters.network.http_connection_manager"}}}},
            "patch": {"operation": "MERGE", "value": {
                "name": "envoy.filters.network.http_connection_manager", "typed_config": {
                    "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
                    "forward_client_cert_details": "SANITIZE_SET",
                    "set_current_client_cert_details": {"subject": True, "uri": True}}}}}]}
    return [service, route, xfcc]
