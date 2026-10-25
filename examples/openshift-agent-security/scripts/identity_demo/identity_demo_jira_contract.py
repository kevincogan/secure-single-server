# SPDX-License-Identifier: Apache-2.0
"""Jira-only request, resource, approval and result rules for the demo connector."""

from __future__ import annotations

import hashlib
import json
import re

from identity_demo_connector import ConnectorContract, Denied, tool_arguments

SCHEMA = "jira-create-v1"
BACKEND = "pilot-jira"
TOOL = "createJiraIssue"


def normalize_create(arguments: dict) -> dict:
    """Resolve and bind all permitted effectful fields; deny arbitrary Jira fields."""
    required = {"project", "summary", "description"}
    if (
        not isinstance(arguments, dict)
        or not required <= arguments.keys()
        or arguments.keys() - required - {"issue_type", "labels"}
    ):
        raise Denied("unsupported_arguments")
    project = arguments["project"]
    if not isinstance(project, str) or not re.fullmatch(r"[A-Z][A-Z0-9]{1,15}", project):
        raise Denied("invalid_project")
    issue_type = arguments.get("issue_type", "Task")
    if issue_type != "Task":
        raise Denied("unsupported_issue_type")
    for field, limit in (("summary", 200), ("description", 8_000)):
        value = arguments[field]
        if not isinstance(value, str) or not value.strip() or len(value) > limit or "\x00" in value:
            raise Denied("invalid_" + field)
    labels = arguments.get("labels", [])
    if (
        not isinstance(labels, list)
        or len(labels) > 8
        or any(
            not isinstance(v, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", v) for v in labels
        )
        or len(set(labels)) != len(labels)
    ):
        raise Denied("invalid_labels")
    return {
        "project": project,
        "issue_type": issue_type,
        "summary": arguments["summary"],
        "description": arguments["description"],
        "labels": sorted(labels),
    }


def canonical(arguments: dict) -> tuple[str, str]:
    """Bind the normalized payload to the fixed tool/backend/schema contract."""
    payload = json.dumps(
        normalize_create(arguments),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    material = json.dumps(
        [BACKEND, SCHEMA, TOOL, payload], separators=(",", ":"), ensure_ascii=False
    )
    return payload, hashlib.sha256(material.encode()).hexdigest()


def create_call(
    data: bytes, *, tool_name: str = "step56_jira_createJiraIssue"
) -> tuple[str, str, dict]:
    """Parse the complete actual mutation body, never routing headers or hashes.

    The caller supplies a trusted registered tool name. Protocol initialization
    and reads require their own authenticated handling; they are not mutations.
    Run/action references are selectors, not proof of user, workload or approval.
    """
    args = tool_arguments(data, tool_name)
    if not isinstance(args, dict) or not {"run_id", "action_id"} <= args.keys():
        raise Denied("missing_action")
    for field in ("run_id", "action_id"):
        if not isinstance(args[field], str) or not re.fullmatch(r"[a-f0-9]{32}", args[field]):
            raise Denied("invalid_action_reference")
    effects = {k: v for k, v in args.items() if k not in ("run_id", "action_id")}
    return args["run_id"], args["action_id"], normalize_create(effects)


def scoped_read_jql(value: object, project: str) -> str | None:
    """Independently constrain model JQL to this actual run's project and issue."""
    if not isinstance(value, str) or len(value) > 160:
        raise Denied("invalid_jql")
    match = re.fullmatch(
        r'project\s*=\s*(?:"([A-Z][A-Z0-9]{1,15})"|([A-Z][A-Z0-9]{1,15}))'
        r'(?:\s+AND\s+key\s*=\s*(?:"([A-Z][A-Z0-9]{1,15}-[1-9][0-9]*)"|([A-Z][A-Z0-9]{1,15}-[1-9][0-9]*)))?',
        value,
    )
    if not match:
        raise Denied("invalid_jql")
    selected, issue = match[1] or match[2], match[3] or match[4]
    if selected != project or (issue and issue.split("-", 1)[0] != project):
        raise Denied("project_permission")
    return issue


def read_call(
    data: bytes, *, tool_name: str = "step56_jira_readJiraProject"
) -> tuple[str, str, str | None]:
    """Accept one project-scoped read; never expose arbitrary JQL or remote URLs."""
    args = tool_arguments(data, tool_name)
    if (
        not isinstance(args, dict)
        or not {"run_id", "project"} <= args.keys()
        or args.keys() - {"run_id", "project", "issue_key", "jql"}
    ):
        raise Denied("unsupported_arguments")
    run, project, issue = args["run_id"], args["project"], args.get("issue_key")
    if not isinstance(run, str) or not re.fullmatch(r"[a-f0-9]{32}", run):
        raise Denied("invalid_action_reference")
    if not isinstance(project, str) or not re.fullmatch(r"[A-Z][A-Z0-9]{1,15}", project):
        raise Denied("invalid_project")
    if "issue_key" in args and (
        not isinstance(issue, str) or not re.fullmatch(re.escape(project) + r"-[1-9][0-9]*", issue)
    ):
        raise Denied("project_permission")
    if "jql" in args:
        if "issue_key" in args:
            raise Denied("unsupported_arguments")
        issue = scoped_read_jql(args["jql"], project)
    return run, project, issue


def proposal(arguments, action):
    args = normalize_create(arguments)
    if len(args["labels"]) > 7:
        raise Denied("marker_capacity")
    if any(label.startswith("demo-action-") for label in args["labels"]):
        raise Denied("reserved_marker")
    args["labels"].append("demo-action-" + action)
    return args


def check_reference(project, reference):
    if not isinstance(reference, str) or not re.fullmatch(
        r"[A-Z][A-Z0-9]{1,15}-[1-9][0-9]*", reference
    ):
        raise ValueError("Verified bounded backend outcome required")
    if reference.split("-", 1)[0] != project:
        raise Denied("backend_project")


JIRA = ConnectorContract(
    "jira.create.v1",
    BACKEND,
    SCHEMA,
    TOOL,
    normalize_create,
    lambda value: value["project"],
    lambda value: (
        isinstance(value, str) and re.fullmatch(r"[A-Z][A-Z0-9]{1,15}", value) is not None
    ),
    proposal,
    check_reference,
    lambda value, action: "demo-action-" + action in value["labels"],
    scope_denial="project_permission",
    read_reason="project_read",
    legacy_digest=True,
    profile_tools=("jira.issue.read", "jira.issue.create"),
    profile_write_actions=("jira.issue.create",),
)
