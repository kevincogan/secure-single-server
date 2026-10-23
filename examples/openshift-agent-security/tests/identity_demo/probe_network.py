# SPDX-License-Identifier: Apache-2.0
"""Non-invasive TCP spot checks from the owned fixture, not disconnected acceptance."""

from __future__ import annotations

import json
import socket


def main() -> None:
    """Check one allowed service and two denied paths without sending application data."""
    cases = [
        ("owned-jira", "fixture-jira.demo-core.svc.cluster.local", 8080, True),
        ("cluster-api", "kubernetes.default.svc.cluster.local", 443, False),
        ("public-ip", "1.1.1.1", 443, False),
    ]
    results = []
    for name, host, port, expected in cases:
        try:
            address = socket.gethostbyname(host)
        except OSError:
            results.append({"case": name, "resolved": False, "passed": False})
            continue
        try:
            with socket.create_connection((address, port), timeout=3):
                connected = True
        except OSError:
            connected = False
        results.append({"case": name, "resolved": True, "connected": connected,
                        "expected_connected": expected, "passed": connected == expected})
    print(json.dumps({"scope": "one owned fixture pod; TCP spot checks only", "results": results}))


if __name__ == "__main__":
    main()
