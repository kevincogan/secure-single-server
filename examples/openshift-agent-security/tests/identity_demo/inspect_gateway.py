# SPDX-License-Identifier: Apache-2.0
"""Report sanitized HTTP filter settings from our localhost-only Envoy admin tunnel."""

from __future__ import annotations

import json
from typing import Any
from urllib.request import urlopen


def typed_config(item: dict) -> dict:
    """Unwrap Istio's TypedStruct without exposing its complete configuration."""
    config = item.get("typed_config", {})
    return config.get("value", config) if config.get("@type", "").endswith("TypedStruct") else config


def wasm_summary(config: dict) -> dict:
    """Extract policy coverage and failure policy, omitting services and credentials."""
    plugin = config.get("config", {})
    raw = plugin.get("configuration", {}).get("value", "{}")
    parsed = json.loads(raw) if isinstance(raw, str) else raw
    sets = parsed.get("actionSets", []) if isinstance(parsed, dict) else []
    return {"plugin": plugin.get("name"), "failure_policy": plugin.get("failure_policy"),
            "policy_hostnames": sorted({host for rule in sets for host in
                                        rule.get("routeRuleConditions", {}).get("hostnames", [])}),
            "policy_sources": sorted({source for rule in sets for action in rule.get("actions", [])
                                      for source in action.get("sources", [])})}


def filters(node: Any) -> list[dict]:
    """Extract filter names and safe configuration flags without dumping TLS material."""
    output = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "http_filters":
                for item in value:
                    config = typed_config(item)
                    grpc = config.get("grpc_service", {}).get("envoy_grpc", {})
                    entry = {"filter": item.get("name"),
                        "body_forwarding": config.get("with_request_body"),
                        "failure_mode_allow": config.get("failure_mode_allow"),
                        "processing_mode": config.get("processing_mode"),
                        "grpc_cluster": grpc.get("cluster_name")}
                    if item.get("name") == "envoy.filters.http.wasm":
                        entry.update(wasm_summary(config))
                    output.append(entry)
            else:
                output.extend(filters(value))
    elif isinstance(node, list):
        for item in node:
            output.extend(filters(item))
    return output


def main() -> None:
    """Read the config in memory and output only the explicitly selected fields."""
    with urlopen("http://127.0.0.1:18086/config_dump", timeout=10) as response:
        config = json.load(response)
    result = filters(config)
    if not result:
        raise RuntimeError("No HTTP filters parsed; inspection is incomplete")
    with urlopen("http://127.0.0.1:18086/stats?filter=ext_authz", timeout=10) as response:
        stats = response.read().decode().splitlines()
    print(json.dumps({"http_filters": result, "authorization_counters": stats}, indent=2))


if __name__ == "__main__":
    main()
