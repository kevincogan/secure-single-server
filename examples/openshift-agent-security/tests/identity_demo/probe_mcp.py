# SPDX-License-Identifier: Apache-2.0
"""Probe the real adapters inside the owned Jira pod using its installed MCP SDK.

Run with oc exec -i ... -c fixture-jira -- python - < this_file.
This performs only initialize, discovery and a project-scoped search.
Successful unauthenticated access is reported as a security gap, not a gate pass.
"""

from __future__ import annotations

import asyncio
import base64
import importlib.metadata
import json
import os
from urllib.request import Request, urlopen

from mcp import ClientSession
from mcp.client.sse import sse_client
from mcp.client.streamable_http import streamablehttp_client


def issue_count() -> int:
    """Read the owned fixture's issue count using its configured synthetic credential."""
    credential = base64.b64encode(f"admin:{os.environ['JIRA_TOKEN']}".encode()).decode()
    req = Request("http://127.0.0.1:8080/rest/api/2/search?jql=project%20%3D%20TEST&maxResults=1",
                  headers={"Authorization": "Basic " + credential})
    with urlopen(req, timeout=10) as response:
        return json.load(response)["total"]


async def probe() -> dict:
    """Return sanitized protocol and authentication observations for both transports."""
    before = issue_count()
    output = {"mcp_sdk": importlib.metadata.version("mcp"), "results": []}
    for mode, url in (("sse", "http://127.0.0.1:8081/sse"),
                      ("streamable-http", "http://127.0.0.1:8082/mcp")):
        client = sse_client(url) if mode == "sse" else streamablehttp_client(url)
        async with client as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                tools = await session.list_tools()
                result = await session.call_tool("searchJiraIssuesUsingJql", {
                    "jql": "project = TEST", "maxResults": 1})
                payloads = [json.loads(item.text) for item in result.content
                            if getattr(item, "type", "") == "text"]
                backend_read_ok = (not result.isError and any(
                    isinstance(item, dict) and "issues" in item and "total" in item
                    and not item.get("error", False) for item in payloads))
                output["results"].append({"transport": mode, "initialized": True,
                    "tool_count": len(tools.tools), "backend_read_ok": backend_read_ok,
                    "supplied_mcp_credential": False,
                    "finding": "Unauthenticated MCP ingress accepted discovery/read"})
    output["issue_count_before"] = before
    output["issue_count_after"] = issue_count()
    output["backend_unchanged"] = output["issue_count_after"] == before
    return output


if __name__ == "__main__":
    print(json.dumps(asyncio.run(asyncio.wait_for(probe(), timeout=45))))
