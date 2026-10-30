#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Test disposable private-route token mediation; not native binding or broker discovery.

All raw configuration, exceptions and tokens remain in an explicit private output
directory. Existing policies/routes are preserved; exact disposable objects are
removed on success or failure. The official runtime is never changed.
"""

from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import socket
import subprocess
import time
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
import httpx

import gateway_credential_route as candidate
import probe_broker_discovery as shared
import identity_demo_fixture_http as human

PORT = 18982


def owned_gateway_deployment(deployment: dict, gateway: dict) -> bool:
    """Accept the installed controller's owner reference, requiring exact UID and labels."""
    # This vendor controller omits `controller` on its Gateway owner reference.
    # Do not infer ownership from a workload label or deployment name alone.
    return all(deployment["metadata"].get("labels", {}).get(key) == value
               for key, value in shared.LABELS.items()) and any(
        ref.get("uid") == gateway["metadata"]["uid"] and ref.get("kind") == "Gateway"
        and ref.get("name") == gateway["metadata"]["name"]
        for ref in deployment["metadata"].get("ownerReferences", []))


def nested(value: Any, key: str) -> list:
    """Find fields in the live Envoy dump without emitting its contents."""
    result = []
    if isinstance(value, dict):
        if key in value:
            result.append(value[key])
        for item in value.values():
            result.extend(nested(item, key))
    elif isinstance(value, list):
        for item in value:
            result.extend(nested(item, key))
    return result


def configuration_checks(dump: dict, ca: str, *, host: str = candidate.HOST,
                         filter_name: str = candidate.FILTER,
                         cluster_name: str = candidate.CLUSTER,
                         bound_listener: bool = False) -> dict[str, bool]:
    """Require route isolation, ordering and explicit TLS before sending a credential."""
    configs = [x for x in nested(dump, "route_config")
               if isinstance(x, dict) and x.get("name") == "http.8080"]
    filters = [x for x in nested(dump, "http_filters")
               if any(f.get("name") == filter_name for f in x)]
    checks = {"existing-hosts-disable-extra-filter": False,
              "diagnostic-host-enables-extra-filter": False,
              "filter-after-wasm-before-router": False,
              "adapter-explicit-ca-and-name-check": False,
              "authorino-explicit-ca-and-name-check": False}
    if len(configs) == 1 and filters:
        hosts = configs[0]["virtual_hosts"]
        probe = next((v for v in hosts if host in v.get("domains", [])), None)
        bound = [x for x in nested(dump, "route_config") if isinstance(x, dict)
                 and str(x.get("name", "")).startswith("https.8443.")]
        isolated = configs + bound if bound_listener else configs
        others = [v for config in isolated for v in config["virtual_hosts"]
                  if host not in v.get("domains", [])]
        checks["existing-hosts-disable-extra-filter"] = (
            (not bound_listener or len(bound) == 1) and bool(others) and all(
            v.get("typed_per_filter_config", {}).get(filter_name, {}).get("disabled") is True
            for v in others))
        checks["diagnostic-host-enables-extra-filter"] = bool(probe) and (
            filter_name in probe.get("typed_per_filter_config", {})
            and not probe["typed_per_filter_config"][filter_name].get("disabled", False))
        names = [f["name"] for f in filters[0]]
        checks["filter-after-wasm-before-router"] = "envoy.filters.http.wasm" in names and (
            names.index("envoy.filters.http.wasm") < names.index(filter_name)
            < names.index("envoy.filters.http.router"))
        for name, server_name, check in (
            ("outbound|8443||" + candidate.ADAPTER, candidate.ADAPTER, "adapter-explicit-ca-and-name-check"),
            (cluster_name, candidate.AUTHORIZER, "authorino-explicit-ca-and-name-check"),
        ):
            clusters = [c for c in nested(dump, "cluster") if isinstance(c, dict) and c.get("name") == name]
            if len(clusters) == 1:
                tls = clusters[0].get("transport_socket", {}).get("typed_config", {})
                validation = tls.get("common_tls_context", {}).get("validation_context", {})
                checks[check] = validation.get("trusted_ca", {}).get("inline_string") == ca and (
                    validation.get("match_typed_subject_alt_names") == [
                        {"san_type": "DNS", "matcher": {"exact": server_name}}])
    return checks


async def read(token: str, evidence: Path, registered: bool = False) -> dict:
    """Require the intended catalog tools and a genuine protected backend result."""
    observations = []

    async def observe(response: httpx.Response) -> None:
        operation = None
        if response.request.method == "POST":
            try:
                operation = json.loads(response.request.content).get("method")
            except (ValueError, httpx.RequestNotRead):
                operation = "unparseable"
        observations.append({"method": response.request.method, "operation": operation,
            "http_status": response.status_code, "content_type": response.headers.get("content-type"),
            "response_headers": dict(response.headers)})
        # Retain bounded denial details privately. Never consume a successful
        # SSE stream here, or emit response bodies in the public summary.
        if response.status_code >= 400:
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk[:8_193 - len(body)])
                if len(body) > 8_192:
                    break
            observations[-1]["error_body"] = bytes(body[:8_192]).decode(errors="replace")
            observations[-1]["error_body_truncated"] = len(body) > 8_192

    def client_factory(headers: dict | None = None, timeout: httpx.Timeout | None = None,
                       auth: httpx.Auth | None = None) -> httpx.AsyncClient:
        return httpx.AsyncClient(headers=headers, timeout=timeout, auth=auth,
                                 trust_env=False, follow_redirects=False, event_hooks={"response": [observe]})

    try:
        async with streamablehttp_client(f"http://127.0.0.1:{PORT}/mcp", headers={
            "Host": candidate.HOST, "Authorization": "Bearer " + token,
        }, httpx_client_factory=client_factory) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                initialized = await session.initialize()
                expected = "Kuadrant MCP Gateway" if registered else "identity-demo-protected-jira"
                if initialized.serverInfo.name != expected:
                    raise RuntimeError("Unexpected MCP responder")
                tools = await session.list_tools()
                prefix = "grant_probe_" if registered else ""
                selected = [t for t in tools.tools if t.name.startswith(prefix)] if registered else tools.tools
                result = await session.call_tool(prefix + "searchJiraIssuesUsingJql", {
                    "jql": "project = TEST", "maxResults": 1})
                values = [json.loads(v.text) for v in result.content if getattr(v, "type", "") == "text"]
                if result.isError or len(selected) != 2 or not any(
                    isinstance(v, dict) and "issues" in v and "total" in v and not v.get("error")
                    for v in values
                ):
                    raise RuntimeError("Protected adapter did not return its real read result")
                return {"read_tools": len(selected), "actual_backend_result": True,
                        "registered_broker_tool": registered}
    finally:
        shared.write_private(evidence, observations)


def denial(credential: str | None) -> int:
    """Return an actual HTTP result; connection failures cannot prove denial."""
    headers = {"Host": candidate.HOST, "Content-Type": "application/json",
               "Accept": "application/json, text/event-stream"}
    if credential:
        headers["Authorization"] = "Bearer " + credential
    body = json.dumps({"jsonrpc": "2.0", "id": 91, "method": "initialize", "params": {
        "protocolVersion": "2025-11-25", "capabilities": {},
        "clientInfo": {"name": "credential-denial-probe", "version": "1"}}}).encode()
    request = Request(f"http://127.0.0.1:{PORT}/mcp", data=body, headers=headers)
    try:
        with urlopen(request, timeout=10) as response:
            return response.status
    except HTTPError as error:
        return error.code


def explicit_tool_denial(observations: list[dict]) -> bool:
    """Require rejection of the actual action, not initialization or an outage."""
    calls = [v for v in observations if v.get("operation") == "tools/call"]
    if len(calls) != 1 or calls[0].get("http_status") != 403:
        return False
    body = calls[0].get("error_body", "")
    if calls[0].get("error_body_truncated"):
        return False
    try:
        value = json.loads(body)
    except (ValueError, TypeError):
        return body.strip() in ("", "Forbidden", "forbidden")
    return isinstance(value, dict) and "result" not in value and "issues" not in value


def initialization_response(token: str) -> dict:
    """Capture the first actual HTTP boundary before interpreting SDK behavior."""
    request = Request(f"http://127.0.0.1:{PORT}/mcp", data=json.dumps({
        "jsonrpc": "2.0", "id": 44, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "owned-credential-route-probe", "version": "1"},
        }}).encode(), headers={"Host": candidate.HOST, "Authorization": "Bearer " + token,
            "Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
    try:
        response = urlopen(request, timeout=10)
    except HTTPError as error:
        response = error
    with response:
        body = response.read(131073)
        if len(body) > 131072:
            raise ValueError("Bounded MCP initialization response required")
        value = {"http_status": response.code, "headers": dict(response.headers),
                 "body": body.decode(errors="replace")}
        session = response.headers.get("mcp-session-id")
    if session and value["http_status"] == 200:
        cleanup = Request(f"http://127.0.0.1:{PORT}/mcp", method="DELETE", headers={
            "Host": candidate.HOST, "Authorization": "Bearer " + token, "Mcp-Session-Id": session})
        with urlopen(cleanup, timeout=10) as response:
            value["session_delete_status"] = response.code
    return value


def initialized_expected_adapter(response: dict) -> bool:
    """A valid broker initialization cannot count as reaching the protected adapter."""
    if response.get("http_status") != 200:
        return False
    try:
        body = json.loads(response["body"])
        return body.get("jsonrpc") == "2.0" and not body.get("error") and (
            body.get("result", {}).get("serverInfo", {}).get("name") == "identity-demo-protected-jira")
    except (ValueError, KeyError, TypeError, AttributeError):
        return False


def initialized_expected_broker(response: dict) -> bool:
    """Broker initialization is expected only for the explicitly registered probe."""
    try:
        value = json.loads(response["body"])
        return response.get("http_status") == 200 and not value.get("error") and (
            value.get("result", {}).get("serverInfo", {}).get("name") == "Kuadrant MCP Gateway")
    except (ValueError, KeyError, TypeError, AttributeError):
        return False
