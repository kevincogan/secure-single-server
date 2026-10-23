# SPDX-License-Identifier: Apache-2.0
"""Validated installation boundaries shared by renderers and trusted runtime code.

The legacy profile preserves historical lab commands. A customer installation
mounts a reviewed profile read-only and sets IDENTITY_DEMO_CONFIG explicitly.
Profiles contain endpoints and ownership, never credentials or executable code.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit


def in_source_checkout(path: Path, source_root: Path | None = None) -> bool:
    """Reject private paths inside a source archive or any enclosing Git checkout."""
    resolved = path.resolve()
    root = source_root if source_root is not None else Path(__file__).resolve().parents[2]
    return resolved.is_relative_to(root.resolve()) or any(
        (parent / ".git").exists() for parent in (resolved, *resolved.parents))


def dns_name(value: object, *, namespace: bool = False) -> str:
    """Accept canonical DNS names without URL syntax or wildcard expansion."""
    if not isinstance(value, str) or len(value) > (63 if namespace else 253):
        raise ValueError("Bounded DNS name required")
    if not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
               for label in value.split(".")):
        raise ValueError("Canonical DNS name required")
    if namespace and ("." in value or value in {"default", "kube-system", "kube-public"}
                      or value.startswith(("openshift", "kube-"))):
        raise ValueError("Dedicated application namespace required")
    return value


def https_origin(value: object) -> str:
    """Reject credentials, paths, redirects and ambiguous endpoint encodings."""
    if not isinstance(value, str) or any(c.isspace() for c in value) or "\\" in value:
        raise ValueError("Explicit HTTPS origin required")
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment
            or parsed.path not in ("", "/") or parsed.port not in (None, 443, 6443)):
        raise ValueError("Verified HTTPS origin required")
    dns_name(parsed.hostname)
    return value.rstrip("/")


@dataclass(frozen=True)
class DeploymentProfile:
    """An explicit installation scope, independent of the current kube context."""

    schema_version: int
    installation_id: str
    owner: str
    expected_server: str
    core_namespace: str
    identity_namespace: str
    triage_namespace: str
    reader_namespace: str
    route_domain: str
    trust_domain: str
    cluster_name: str
    storage_class: str

    @classmethod
    def from_dict(cls, value: dict) -> DeploymentProfile:
        """Reject unknown/missing fields and colliding or protected namespaces."""
        if not isinstance(value, dict) or set(value) != set(cls.__dataclass_fields__):
            raise ValueError("Exact installation-profile fields required")
        result = cls(**value)
        if type(result.schema_version) is not int or result.schema_version != 1:
            raise ValueError("Installation profile schema 1 required")
        if not isinstance(result.installation_id, str) or not re.fullmatch(
                r"[a-z][a-z0-9-]{0,19}", result.installation_id):
            raise ValueError("Short canonical installation ID required")
        if not isinstance(result.owner, str) or not re.fullmatch(
                r"[a-zA-Z0-9](?:[a-zA-Z0-9_.-]{0,61}[a-zA-Z0-9])?", result.owner):
            raise ValueError("Explicit Kubernetes ownership label required")
        https_origin(result.expected_server)
        namespaces = (*result.application_namespaces, result.identity_namespace)
        for name in namespaces:
            dns_name(name, namespace=True)
        if len(set(namespaces)) != 4:
            raise ValueError("Four distinct namespaces required")
        for name in (result.route_domain, result.trust_domain, result.cluster_name,
                     result.storage_class):
            dns_name(name)
        for service in ("fixture-keycloak-upstream", "fixture-identity-driver", "fixture-mcp"):
            dns_name(service + "-" + result.core_namespace + "." + result.route_domain)
        return result

    @property
    def application_namespaces(self) -> tuple[str, str, str]:
        """Return only namespaces owned by the application installation."""
        return self.core_namespace, self.triage_namespace, self.reader_namespace

    @property
    def gateway_id(self) -> str:
        """Keep parallel gateways distinct within a shared SPIFFE trust domain."""
        return "fixture-openshell" if self.installation_id == "identity-demo" else "fixture-" + self.installation_id

    @property
    def gateway_registration_name(self) -> str:
        """Avoid collisions between cluster-scoped entries for parallel installs."""
        return ("identity-demo-openshell-gateway" if self.installation_id == "identity-demo"
                else "identity-demo-" + self.installation_id + "-gateway")

    @property
    def private_mcp_authorization_host(self) -> str:
        """Authorino's host index is shared across namespaces, unlike HTTPRoutes."""
        prefix = 'fixture-step4-read-route'
        return (prefix + '.fixture-mcp.local' if self.installation_id == 'identity-demo' and self.core_namespace == 'demo-core'
                else prefix + '.' + self.core_namespace + '.fixture-mcp.local')

    @property
    def native_build_contract(self) -> dict[str, str]:
        """Bind native sender destinations and identity to this installation."""
        return {
            "OPENSHELL_DEMO_SENDER_HOST": self.service_host("fixture-mcp-bound"),
            "OPENSHELL_DEMO_TOKEN_ENDPOINT": "https://" + self.service_host("fixture-keycloak-upstream")
                + ":8443/realms/identity-demo/protocol/openid-connect/token",
            "OPENSHELL_DEMO_JWT_AUDIENCE": self.origin("fixture-keycloak-upstream") + "/realms/identity-demo",
            "OPENSHELL_DEMO_MCP_AUDIENCE": "https://" + self.service_host("fixture-mcp-bound") + "/mcp",
            "OPENSHELL_DEMO_TRUST_DOMAIN": self.trust_domain,
        }

    @property
    def labels(self) -> dict[str, str]:
        """Keep ownership and installation identity explicit on new resources."""
        return {"app.kubernetes.io/part-of": "identity-demo-preflight",
                "identity-demo-owner": self.owner}

    def namespace_for(self, role: str) -> str:
        """Resolve a trusted role; never derive namespaces from a caller string."""
        if role not in ("triage", "reader"):
            raise ValueError("Known workload role required")
        return getattr(self, role + "_namespace")

    def origin(self, service: str) -> str:
        """Construct one fixed route from validated installation configuration."""
        dns_name(service, namespace=True)
        return "https://" + service + "-" + self.core_namespace + "." + self.route_domain

    def service_host(self, service: str, *, identity: bool = False) -> str:
        """Construct an internal service address, preserving hostname validation."""
        dns_name(service, namespace=True)
        namespace = self.identity_namespace if identity else self.core_namespace
        return service + "." + namespace + ".svc.cluster.local"

    def to_dict(self) -> dict:
        """Serialize only nonsecret installation configuration."""
        return asdict(self)


LEGACY = DeploymentProfile.from_dict({
    "schema_version": 1, "installation_id": "identity-demo", "owner": "demo-team",
    "expected_server": "https://api.cluster.example.test:443",
    "core_namespace": "demo-core", "identity_namespace": "demo-identity",
    "triage_namespace": "demo-triage", "reader_namespace": "demo-reader",
    "route_domain": "apps.cluster.example.test",
    "trust_domain": "agents.example.test", "cluster_name": "evaluation-cluster",
    "storage_class": "gp3-csi",
})


def read_profile(path: str) -> DeploymentProfile:
    """Read a protected operator file or read-only mounted profile, never a URL."""
    source = Path(path)
    if not source.is_absolute() or source.is_symlink() or not source.is_file():
        raise ValueError("Absolute regular installation-profile file required")
    if source.stat().st_size > 16_384 or source.stat().st_mode & 0o022:
        raise ValueError("Bounded profile without group/other write access required")
    def pairs(values: list[tuple]) -> dict:
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("Duplicate profile field")
            result[key] = value
        return result
    return DeploymentProfile.from_dict(json.loads(source.read_text(), object_pairs_hook=pairs))


def active_profile() -> DeploymentProfile:
    """Use explicit trusted configuration; preserve lab defaults for old commands."""
    source = os.environ.get("IDENTITY_DEMO_CONFIG")
    return read_profile(source) if source else LEGACY
