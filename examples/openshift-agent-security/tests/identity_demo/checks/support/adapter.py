# SPDX-License-Identifier: Apache-2.0
"""Shared adapter integration-test inputs; actual tests remain collected."""
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
from response_evidence import sanitized_error_result

ADAPTER = "http://127.0.0.1:18087"

def adapter_request(path: str, *, token: str | None = None,
                    payload: dict | None = None, session: str | None = None) -> tuple[int, Any, dict]:
    """Inspect denied responses locally, returning only an unexpected result marker."""
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
               "MCP-Protocol-Version": "2025-03-26"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if session:
        headers["Mcp-Session-Id"] = session
    req = Request(ADAPTER + path, headers=headers,
                  data=json.dumps(payload).encode() if payload is not None else None)
    try:
        response = urlopen(req, timeout=20)
    except HTTPError as error:
        response = error
    with response:
        body = response.read(2_000_001)
        if len(body) > 2_000_000:
            raise RuntimeError("Adapter response exceeded the proof size bound")
        if response.status != 200:
            return response.status, response.headers, sanitized_error_result(body)
        try:
            return response.status, response.headers, json.loads(body)
        except (ValueError, UnicodeDecodeError):
            raise RuntimeError("Adapter successful response was not JSON") from None

def rpc(method: str, token: str | None, *, params: dict | None = None,
        session: str | None = None) -> tuple[int, Any, dict]:
    """Submit native Streamable HTTP JSON-RPC without an intermediary gateway."""
    payload = {"jsonrpc": "2.0", "method": method}
    if method != "notifications/initialized":
        payload["id"] = 1
    if params is not None:
        payload["params"] = params
    return adapter_request("/mcp", token=token, payload=payload, session=session)

def initialize(token: str | None) -> tuple[int, Any, dict]:
    """Initialize a real MCP session, returning its server-issued session header."""
    return rpc("initialize", token, params={"protocolVersion": "2025-03-26", "capabilities": {},
        "clientInfo": {"name": "identity-demo-protected-adapter-test", "version": "0.1"}})
