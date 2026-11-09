# SPDX-License-Identifier: Apache-2.0
"""Pure native provider policy; callers supply the fixed verified endpoints."""
from urllib.parse import urlparse

def render_profile(prefix, resource, token_endpoint, issuer, tool, *, allow_create):
    return {
                "id": prefix,
                "display_name": "Isolated native Step 4 read",
                "category": "other",
                "credentials": [
                    {"name": "subject_token", "required": True},
                    {
                        "name": "access_token",
                        "auth_style": "bearer",
                        "header_name": "Authorization",
                        "token_grant": {
                            "grant_type": "token_exchange",
                            "token_endpoint": token_endpoint,
                            "audience": resource,
                            "jwt_svid_audience": issuer,
                            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe",
                            "cache_ttl": "0s",
                            "subject_token": {
                                "source": "provider_credential",
                                "credential": "subject_token",
                                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                            },
                        },
                    },
                ],
                "endpoints": [
                    {
                        "host": urlparse(resource).hostname,
                        "port": 443,
                        "protocol": "mcp",
                        "enforcement": "enforce",
                        "path": "/mcp",
                        "mcp": {
                            "versions": ["2025-11-25"],
                            "allow_all_known_mcp_methods": False,
                        },
                        "rules": [
                            {"allow": {"method": m}}
                            for m in (
                                "initialize",
                                "notifications/initialized",
                                "tools/list",
                            )
                        ]
                        + [
                            {"allow": {"method": "tools/call", "tool": v}}
                            for v in (
                                [tool, "step56_jira_createJiraIssue"]
                                if allow_create
                                else [tool]
                            )
                        ],
                    }
                ],
                "binaries": ["/workspace/.venv/bin/python", "/usr/bin/python3.12"],
            }
