# SPDX-License-Identifier: Apache-2.0
"""Compare cold/warm gateway denials without changing policies or backend data."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from urllib.parse import urlparse


def main() -> None:
    """Require owned fixtures, then report statuses without credentials or sessions."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--expected-server", required=True)
    parser.add_argument("--credentials-file", required=True)
    args = parser.parse_args()
    args.namespace = "demo-core"
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "identity_demo"))
    from deployment_profile import in_source_checkout
    from identity_demo_lab import LABELS, oc

    actual = oc(args, "config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}")
    if actual.rstrip("/") != args.expected_server.rstrip("/"):
        raise ValueError("Expected fixture cluster required")
    for kind, name in (("namespace", args.namespace), ("gateway", "fixture-mcp"),
                       ("route", "fixture-mcp"), ("route", "fixture-keycloak"),
                       ("deployment", "fixture-jira")):
        scope = [] if kind == "namespace" else ["-n", args.namespace]
        item = json.loads(oc(args, "get", kind, name, *scope, "-o", "json"))
        if any(item["metadata"].get("labels", {}).get(k) != v for k, v in LABELS.items()):
            raise ValueError("Owned fixture resource required")
        if kind == "route" and name == "fixture-mcp":
            gateway_host = item["spec"]["host"]
        if kind == "route" and name == "fixture-keycloak":
            issuer_host = item["spec"]["host"]
    private = Path(args.credentials_file)
    root = Path(__file__).resolve().parents[2]
    if private.stat().st_mode & 0o077 or in_source_checkout(private, root):
        raise ValueError("Private credentials outside repository required")
    credentials = json.loads(private.read_text())
    if (credentials["namespace"] != args.namespace
            or urlparse(credentials["gateway_url"]).hostname != gateway_host
            or urlparse(credentials["keycloak_url"]).hostname != issuer_host):
        raise ValueError("Owned gateway configuration required")
    os.environ.update(IDENTITY_DEMO_KEYCLOAK_URL=credentials["keycloak_url"],
                      IDENTITY_DEMO_GATEWAY_HOST=gateway_host)
    import identity_demo_fixture_http as components
    from checks.test_gateway import initialize, rpc
    from checks.test_gateway_oauth import gateway_request

    def count() -> int:
        """Read the synthetic backend, returning only its issue count."""
        import base64

        header = base64.b64encode(("admin:" + credentials["jira_admin"]).encode()).decode()
        status, _, body = components.request(components.JIRA
            + "/rest/api/2/search?jql=project%20%3D%20TEST&maxResults=1",
            headers={"Authorization": "Basic " + header})
        if status != 200:
            raise RuntimeError("Synthetic backend read failed")
        return int(json.loads(body)["total"])

    tokens = components.login("analyst", credentials["analyst"])
    params = {"name": "jira_searchJiraIssuesUsingJql",
              "arguments": {"jql": "project = TEST", "maxResults": 1}}
    observations: list[dict] = []

    def session() -> str:
        """Create a broker session without initializing its backend session."""
        status, headers, _ = initialize(tokens["access_token"])
        identifier = headers.get("Mcp-Session-Id")
        if status != 200 or not identifier:
            raise RuntimeError("Authenticated broker initialization failed")
        status, _, _ = rpc("notifications/initialized", token=tokens["access_token"], session=identifier)
        if status not in (200, 202, 204):
            raise RuntimeError("Initialized notification failed")
        return identifier

    def prime(identifier: str) -> None:
        """Require a real empty Jira result rather than a successful error envelope."""
        status, _, value = rpc("tools/call", token=tokens["access_token"], session=identifier, params=params)
        result = value.get("result", {})
        if status != 200 or result.get("isError", False):
            raise RuntimeError("Authenticated backend read failed")
        try:
            contents = [json.loads(v["text"]) for v in result.get("content", []) if v.get("type") == "text"]
        except (KeyError, ValueError):
            raise RuntimeError("Backend read returned invalid result content") from None
        if not any(isinstance(v, dict) and v.get("total") == 0 and v.get("issues") == [] for v in contents):
            raise RuntimeError("Expected empty synthetic backend")

    before = count()
    if before != 0:
        raise ValueError("Empty synthetic backend required")
    identifier = session()
    bad = (("missing", None), ("malformed", "not-a-token"), ("wrong-audience", tokens["id_token"]))
    for phase in ("cold-backend", "warm-backend"):
        if phase == "warm-backend":
            prime(identifier)
        for case, token in bad:
            status, _, value = rpc("tools/call", token=token, session=identifier, params=params)
            if "result" in value:
                raise RuntimeError("Invalid credential produced a tool result")
            observations.append({"phase": phase, "case": case, "http_status": status,
                                 "has_result": False, "expected_status_passed": status in (401, 403)})
    for case, token in bad:
        status, _, value = initialize(token, host="jira.fixture-mcp.local")
        if "result" in value:
            raise RuntimeError("Invalid credential initialized the backend listener")
        observations.append({"phase": "direct-backend-listener", "case": case, "http_status": status,
                             "has_result": False, "expected_status_passed": status in (401, 403)})
    payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params}
    for phase, target in (("metadata-warm", identifier), ("metadata-cold", session())):
        status, _, value = gateway_request(credentials["gateway_url"],
            "/.well-known/oauth-protected-resource/mcp", payload=payload, session=target)
        if "result" in value:
            raise RuntimeError("Unauthenticated metadata body returned a tool result")
        observations.append({"phase": phase, "case": "missing", "http_status": status,
                             "has_result": False, "expected_status_passed": status in (400, 401, 403)})
    prime(identifier)
    after = count()
    if before != after:
        raise RuntimeError("Synthetic backend state changed")
    print(json.dumps({"observations": observations, "issue_count_before": before,
        "issue_count_after": after, "baseline_read_restored": True,
        "no_tool_result_returned": True,
        "rejection_status_acceptance_passed": all(v["expected_status_passed"] for v in observations),
        "scope": "Synthetic read-only authentication/error-path diagnostic; no policy or deployment mutation"}))


if __name__ == "__main__":
    main()
