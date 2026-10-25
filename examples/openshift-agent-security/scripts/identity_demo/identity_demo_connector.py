# SPDX-License-Identifier: Apache-2.0
"""Reviewed connector semantics; identities, approval and dispatch remain in RunStore.

Descriptors are supplied by trusted application code, never imported from a
request, prompt or configuration path. A connector maps the actual payload to
its resource; it cannot bypass the shared run and execution checks.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Callable


class Denied(ValueError):
    """A deliberate, safe authorization or lifecycle denial."""


def strict_json(data: bytes) -> dict:
    """Refuse incomplete, duplicate-key, oversized and non-object requests."""
    if not data or len(data) > 65_536:
        raise Denied("request_size")

    def pairs(values: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in values:
            if key in result:
                raise Denied("duplicate_field")
            result[key] = value
        return result

    try:
        value = json.loads(
            data,
            object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(Denied("invalid_number")),
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise Denied("malformed_json") from error
    if not isinstance(value, dict):
        raise Denied("object_required")
    return value


def tool_arguments(data: bytes, tool_name: str) -> object:
    """Validate the complete MCP envelope before either read or create parsing."""
    value = strict_json(data)
    if (
        value.keys() != {"jsonrpc", "id", "method", "params"}
        or value["jsonrpc"] != "2.0"
        or value["method"] != "tools/call"
        or type(value["id"]) not in (str, int)
        or len(str(value["id"])) > 128
    ):
        raise Denied("unsupported_rpc")
    params = value["params"]
    if (
        not isinstance(params, dict)
        or params.keys() != {"name", "arguments"}
        or params["name"] != tool_name
    ):
        raise Denied("unsupported_tool")
    return params["arguments"]


@dataclass(frozen=True)
class ConnectorContract:
    """A versioned, explicitly registered action and its reviewed schema hooks."""

    identifier: str
    backend: str
    schema: str
    tool: str
    normalize: Callable[[dict], dict]
    resource: Callable[[dict], str]
    valid_scope: Callable[[object], bool]
    proposal: Callable[[dict, str], dict]
    check_reference: Callable[[str, object], None]
    has_marker: Callable[[dict, str], bool]
    user_roles: frozenset[str] = frozenset({"analyst", "viewer"})
    workload_roles: frozenset[str] = frozenset({"triage", "reader"})
    write_user_roles: frozenset[str] = frozenset({"analyst"})
    write_workload_roles: frozenset[str] = frozenset({"triage"})
    scope_denial: str = "resource_permission"
    read_reason: str = "resource_read"
    legacy_digest: bool = False
    profile_tools: tuple[str, ...] = ()
    profile_write_actions: tuple[str, ...] = ()

    def __post_init__(self):
        for value in (self.identifier, self.backend, self.schema, self.tool):
            if not isinstance(value, str) or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value
            ):
                raise ValueError("Explicit versioned connector identity required")
        if not self.user_roles or not self.workload_roles:
            raise ValueError('Approved user and workload roles required')
        if type(self.legacy_digest) is not bool or self.legacy_digest and (
                self.identifier,self.backend,self.schema,self.tool)!=('jira.create.v1','pilot-jira','jira-create-v1','createJiraIssue'):
            raise ValueError('Legacy digest compatibility is reserved for the original Jira contract')
        for roles in (
            self.user_roles,
            self.workload_roles,
            self.write_user_roles,
            self.write_workload_roles,
        ):
            if (
                not isinstance(roles, frozenset)
                or any(
                    not isinstance(v, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", v)
                    for v in roles
                )
            ):
                raise ValueError("Immutable approved permission roles required")
        if (
            not self.write_user_roles <= self.user_roles
            or not self.write_workload_roles <= self.workload_roles
        ):
            raise ValueError("Write permissions must belong to the approved role contract")

        for labels in (self.profile_tools, self.profile_write_actions):
            if (not isinstance(labels, tuple) or len(labels) > 32
                    or any(not isinstance(v, str) or not re.fullmatch(
                        r"[a-z][a-z0-9_.:-]{0,63}", v) for v in labels)
                    or len(set(labels)) != len(labels)):
                raise ValueError("Immutable reviewed profile action labels required")
        if (not set(self.profile_write_actions) <= set(self.profile_tools)
                or self.profile_tools and bool(self.write_workload_roles)
                    != bool(self.profile_write_actions)):
            raise ValueError("Profile action labels must describe the workload role contract")

    @property
    def fingerprint(self):
        # Profile labels describe the existing role/tool contract; they cannot
        # grant authority or change the fingerprint of historical run grants.
        value = [
            self.identifier,
            self.backend,
            self.schema,
            self.tool,
            sorted(self.user_roles),
            sorted(self.workload_roles),
            sorted(self.write_user_roles),
            sorted(self.write_workload_roles),
            self.legacy_digest,
        ]
        return hashlib.sha256(json.dumps(value, separators=(",", ":")).encode()).hexdigest()

    def canonical(self, arguments):
        normalized = self.normalize(arguments)
        resource = self.resource(normalized)
        if not self.valid_scope(resource):
            raise Denied(self.scope_denial)
        payload = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        # Existing Jira approvals already bind the project inside the payload.
        # Preserve those bytes; new contracts explicitly include the resource.
        material = (
            [self.backend, self.schema, self.tool, payload]
            if self.legacy_digest
            else [self.identifier, self.backend, self.schema, self.tool, resource, payload]
        )
        return payload, hashlib.sha256(
            json.dumps(material, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest()

    @property
    def result_field(self):
        return "issue_key" if self.legacy_digest else "result_ref"


@dataclass(frozen=True)
class ConnectorRegistry:
    """Explicit reviewed descriptors; no imports, URLs or credentials from callers."""

    contracts: tuple[ConnectorContract, ...]

    def __post_init__(self):
        if (
            not isinstance(self.contracts, tuple)
            or not 1 <= len(self.contracts) <= 32
            or any(not isinstance(c, ConnectorContract) for c in self.contracts)
            or len({c.identifier for c in self.contracts}) != len(self.contracts)
        ):
            raise ValueError("Unique reviewed connector descriptors required")

    def resolve(self, identifier):
        for contract in self.contracts:
            if contract.identifier == identifier:
                return contract
        raise Denied("unsupported_connector")


def supported_connectors():
    """Runtime registrations. Additional connectors require a reviewed release."""
    from identity_demo_jira_contract import JIRA

    return ConnectorRegistry((JIRA,))
