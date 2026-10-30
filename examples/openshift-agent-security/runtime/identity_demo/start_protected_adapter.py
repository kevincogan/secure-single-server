# SPDX-License-Identifier: Apache-2.0
"""Run the existing Jira read tools with the installed SDK's authentication."""

from __future__ import annotations

import os
from pathlib import Path

from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp_servers.atlassian_jira import getJiraIssue, searchJiraIssuesUsingJql
from pydantic import AnyHttpUrl

from adapter_auth import ADAPTER_ALLOWED_HOSTS, FixtureTokenVerifier
from adapter_live_auth import LiveFixtureTokenVerifier


def main() -> None:
    """Start only read tools; require a valid adapter-specific service token."""
    issuer, resource = os.environ["ADAPTER_ISSUER"], os.environ["ADAPTER_RESOURCE"]
    if os.environ.get("ADAPTER_LIVE_JWKS") == "1":
        verifier = LiveFixtureTokenVerifier(issuer, resource, "fixture-gateway-service")
    else:
        verifier = FixtureTokenVerifier(
            issuer, resource, "fixture-gateway-service", Path("/fixtures/jwks.json")
        )
    discovery = os.environ.get("ADAPTER_DISCOVERY_DIGESTS_FILE")
    if discovery:
        from adapter_discovery import CatalogTokenVerifier

        if os.environ["MCP_TRANSPORT"] != "streamable-http":
            raise ValueError("Catalog integration requires stateless Streamable HTTP")
        verifier = CatalogTokenVerifier(verifier, Path(discovery), resource)
    server = FastMCP(
        "identity-demo-protected-jira",
        host="0.0.0.0",
        port=int(os.environ["MCP_PORT"]),
        log_level="WARNING",
        json_response=True,
        stateless_http=bool(discovery),
        token_verifier=verifier,
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(issuer),
            resource_server_url=AnyHttpUrl(resource),
            required_scopes=[] if discovery else ["mcp:read"],
        ),
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(ADAPTER_ALLOWED_HOSTS),
            allowed_origins=[],
        ),
    )
    actions = os.environ.get("IDENTITY_DEMO_ACTIONS") == "1"
    if actions:
        if not discovery:
            raise ValueError(
                "Action integration requires the guarded HTTPS catalog endpoint"
            )
        from identity_demo_jira_action_adapter import install_tools

        install_tools(server)
    else:
        server.add_tool(searchJiraIssuesUsingJql)
        server.add_tool(getJiraIssue)
    if os.environ.get("MCP_TLS_CERTFILE"):
        import uvicorn

        if os.environ["MCP_TRANSPORT"] != "streamable-http":
            raise ValueError("TLS fixture uses the native Streamable HTTP app")
        app = server.streamable_http_app()
        if discovery:
            from adapter_discovery import install_catalog_guard

            install_catalog_guard(app)
        if actions:
            from identity_demo_jira_action_adapter import ActualBody

            app = ActualBody(app)
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=int(os.environ["MCP_PORT"]),
            ssl_certfile=os.environ["MCP_TLS_CERTFILE"],
            ssl_keyfile=os.environ["MCP_TLS_KEYFILE"],
            log_level="warning",
            access_log=False,
        )
    else:
        if discovery:
            raise ValueError("Catalog integration requires the owned HTTPS endpoint")
        server.run(transport=os.environ["MCP_TRANSPORT"])


if __name__ == "__main__":
    main()
