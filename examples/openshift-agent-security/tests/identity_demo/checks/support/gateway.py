# SPDX-License-Identifier: Apache-2.0
"""Shared gateway integration-test inputs; actual tests remain collected."""
from __future__ import annotations
import json
import os
import time
from typing import Any
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import pytest
import checks.support.components as components
from checks.support.components import login, verify
from response_evidence import sanitized_error_result

BROKER_HOST = os.environ.get("IDENTITY_DEMO_GATEWAY_HOST", "fixture-mcp.local")

def rpc(method: str, *, token: str | None = None, params: dict | None = None,
        session: str | None = None, extra: dict | None = None,
        host: str = BROKER_HOST) -> tuple[int, Any, dict]:
    """Send JSON-RPC locally, inspecting error bodies without returning contents."""
    headers = {"Host": host, "Content-Type": "application/json",
               "Accept": "application/json, text/event-stream",
               "MCP-Protocol-Version": "2025-03-26"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if session:
        headers["Mcp-Session-Id"] = session
    headers.update(extra or {})
    payload: dict = {"jsonrpc": "2.0", "method": method}
    if method != "notifications/initialized":
        payload["id"] = 1
    if params is not None:
        payload["params"] = params
    request = Request("http://127.0.0.1:18084/mcp", headers=headers,
                      data=json.dumps(payload).encode())
    try:
        response = urlopen(request, timeout=20)
    except HTTPError as error:
        response = error
    with response:
        body = response.read(2_000_001)
        if len(body) > 2_000_000:
            raise RuntimeError("Gateway response exceeded the proof size bound")
        if response.status != 200:
            return response.status, response.headers, sanitized_error_result(body)
        try:
            events = [json.loads(line[5:].strip()) for line in body.decode().splitlines()
                      if line.startswith("data:")]
            value = events[-1] if events else json.loads(body)
        except (ValueError, UnicodeDecodeError):
            raise RuntimeError("Gateway success response was not valid JSON-RPC") from None
        return response.status, response.headers, value

def initialize(token: str | None, *, extra: dict | None = None,
               host: str = BROKER_HOST) -> tuple[int, Any, dict]:
    """Initialize the deterministic MCP client through the real gateway."""
    return rpc("initialize", token=token, extra=extra, host=host, params={
        "protocolVersion": "2025-03-26", "capabilities": {},
        "clientInfo": {"name": "identity-demo-preflight", "version": "0.1"}})
