# SPDX-License-Identifier: Apache-2.0
"""Temporarily test body visibility on our policy, then restore it in finally.

Do not run concurrently with the gateway suite. Only read tools are exposed.
An explicit deny control proves reconciliation before inspecting real request content.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "identity_demo"))
from identity_demo_lab import LABELS, oc
from checks.test_components import ComponentTests, login
from checks.test_gateway import initialize, rpc

POLICY = "fixture-mcp-tools-auth"
PATH = "/spec/rules/authorization/inspection-required"


def replace(args: argparse.Namespace, operation: str, predicate: str | None = None) -> None:
    """Change only the temporary inspection rule in our verified policy."""
    patch: dict = {"op": operation, "path": PATH}
    if predicate is not None:
        patch["value"] = {"priority": 2, "patternMatching": {"patterns": [{"predicate": predicate}]}}
    oc(args, "patch", "authpolicy.kuadrant.io", POLICY, "-n", args.namespace,
       "--type=json", "-p", json.dumps([patch]))


def main() -> None:
    """Compare full-body requirement with a safe read-only evaluation control."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--expected-server", required=True)
    parser.add_argument("--namespace", default="demo-core", choices=["demo-core"])
    args = parser.parse_args()
    if oc(args, "config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}") != args.expected_server:
        raise ValueError("Target cluster mismatch")
    for kind, name in (("namespace", args.namespace), ("authpolicy.kuadrant.io", POLICY)):
        scope = [] if kind == "namespace" else ["-n", args.namespace]
        item = json.loads(oc(args, "get", kind, name, *scope, "-o", "json"))
        if any(item["metadata"].get("labels", {}).get(k) != v for k, v in LABELS.items()):
            raise ValueError("Owned fixture and policy required")
    if "inspection-required" in item["spec"]["rules"]["authorization"]:
        raise ValueError("Temporary rule already exists; inspect before rerunning")
    ComponentTests.setUpClass()
    credentials = ComponentTests.credentials
    token = login("analyst", credentials["analyst"])["access_token"]
    status, headers, _ = initialize(token)
    if status != 200:
        raise RuntimeError("Baseline authenticated initialization failed")
    session = headers.get("Mcp-Session-Id")
    status, _, _ = rpc("notifications/initialized", token=token, session=session)
    if status not in (200, 202, 204):
        raise RuntimeError("Baseline initialization notification failed")
    params = {"name": "jira_searchJiraIssuesUsingJql", "arguments": {"jql": "project = TEST", "maxResults": 1}}
    status, _, baseline = rpc("tools/call", token=token, session=session, params=params)
    if status != 200 or "result" not in baseline or baseline["result"].get("isError", False):
        raise RuntimeError("Baseline backend read failed")
    changed = {"name": params["name"], "arguments": {"jql": "project = NOT_ALLOWED", "maxResults": 1}}
    observations = []
    control_enforced = False
    list_denied = False
    diagnostic_defined = False
    body_omission_confirmed = False
    added = False
    try:
        replace(args, "add", "false")
        added = True
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            token = login("analyst", credentials["analyst"])["access_token"]
            list_status, _, _ = rpc("tools/list", token=token, session=session, params={})
            status, _, _ = rpc("tools/call", token=token, session=session, params=params)
            list_denied = list_status == 403
            if status == 403:
                control_enforced = True
                break
            time.sleep(1)
        observations.append({"case": "deny-control", "tools_list_status": list_status,
                             "tools_call_status": status})
        if control_enforced:
            replace(args, "replace", "has(auth.authorization['request-inspection'].body_present) && "
                    "has(auth.authorization['request-inspection'].raw_body_present) && "
                    "has(auth.authorization['request-inspection'].raw_body_camel_present)")
            deadline = time.monotonic() + 25
            while time.monotonic() < deadline:
                token = login("analyst", credentials["analyst"])["access_token"]
                status, _, value = rpc("tools/call", token=token, session=session, params=params)
                if status == 200 and "result" in value and not value["result"].get("isError", False):
                    diagnostic_defined = True
                    break
                time.sleep(1)
            observations.append({"case": "body-flags-defined", "status": status})
            if diagnostic_defined:
                replace(args, "replace", "auth.authorization['request-inspection'].body_present || "
                        "auth.authorization['request-inspection'].raw_body_present || "
                        "auth.authorization['request-inspection'].raw_body_camel_present")
                deadline = time.monotonic() + 25
                while time.monotonic() < deadline:
                    token = login("analyst", credentials["analyst"])["access_token"]
                    status, _, _ = rpc("tools/call", token=token, session=session, params=params)
                    if status == 403:
                        body_omission_confirmed = True
                        break
                    time.sleep(1)
                observations.append({"case": "require-body-or-raw-body", "status": status})
            replace(args, "replace", "has(context.request.http.body) && "
                    "context.request.http.body.contains('project = TEST')")
            deadline = time.monotonic() + 25
            while time.monotonic() < deadline:
                token = login("analyst", credentials["analyst"])["access_token"]
                matching, _, value = rpc("tools/call", token=token, session=session, params=params)
                altered, _, _ = rpc("tools/call", token=token, session=session, params=changed)
                backend_ok = ("result" in value and not value["result"].get("isError", False))
                observations = [item for item in observations if not item["case"].startswith("actual-body-")] + [
                    {"case": "actual-body-matches", "status": matching, "tool_ok": backend_ok},
                    {"case": "actual-body-altered", "status": altered}]
                if matching == 200 and backend_ok and altered == 403:
                    break
                time.sleep(1)
    finally:
        if added:
            replace(args, "remove")
    # Confirm restoration by traffic, rather than just successful PATCH.
    deadline = time.monotonic() + 25
    restored = False
    while time.monotonic() < deadline:
        token = login("analyst", credentials["analyst"])["access_token"]
        list_status, _, _ = rpc("tools/list", token=token, session=session, params={})
        status, _, value = rpc("tools/call", token=token, session=session, params=params)
        if list_status == 200 and status == 200 and "result" in value and not value["result"].get("isError", False):
            restored = True
            break
        time.sleep(1)
    print(json.dumps({"observations": observations, "policy_restored_and_read_ok": restored,
                     "deny_control_enforced": control_enforced,
                     "deny_control_enforced_for_tools_list": list_denied,
                     "body_diagnostic_defined": diagnostic_defined,
                     "body_omission_confirmed": body_omission_confirmed,
                     "actual_argument_visible_on_tested_path": (
                         len(observations) >= 3 and observations[-2]["status"] == 200
                         and observations[-2].get("tool_ok", False) and observations[-1]["status"] == 403),
                     "scope": "Body-content visibility only; substring matching is not exact-action authorization; G4 remains open"}))
    if not restored:
        raise RuntimeError("Policy restoration requires attention")


if __name__ == "__main__":
    main()
