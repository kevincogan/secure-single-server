# SPDX-License-Identifier: Apache-2.0
"""Reviewed document effects, shared by the offline and deployed adapters."""
import re

from agent_security_runtime import ConnectorContract, Denied


def normalize(value):
    required = {"collection", "document", "revision", "content"}
    if (not isinstance(value, dict) or not required <= value.keys()
            or value.keys() - required - {"operation_id"}
            or not isinstance(value.get("collection"), str)
            or value["collection"] not in {"engineering", "research"}
            or value.get("document") != "runbook" or type(value.get("revision")) is not int
            or not 1 <= value["revision"] <= 1000
            or not isinstance(value.get("content"), str) or not 1 <= len(value["content"]) <= 2000
            or "\x00" in value["content"]
            or "operation_id" in value and (not isinstance(value["operation_id"], str)
                or not re.fullmatch(r"[a-f0-9]{32}", value["operation_id"]))):
        raise Denied("document_schema")
    return dict(value)


def proposal(value, action):
    if not isinstance(value, dict) or "operation_id" in value:
        raise Denied("reserved_marker")
    return {**normalize(value), "operation_id": action}


def check_reference(resource, reference):
    if (not isinstance(reference, str)
            or not re.fullmatch(re.escape(resource) + r"/runbook@[1-9][0-9]{0,3}", reference)):
        raise Denied("backend_resource")


DOCUMENTS = ConnectorContract(
    "documents.publish.v1", "local-document-fixture", "document-v1", "document.publish",
    normalize, lambda v: v["collection"], lambda v: isinstance(v, str) and v in {"engineering", "research"},
    proposal, check_reference, lambda v, action: v.get("operation_id") == action,
    user_roles=frozenset({"reviewer", "viewer"}),
    workload_roles=frozenset({"publisher", "reader"}),
    write_user_roles=frozenset({"reviewer"}), write_workload_roles=frozenset({"publisher"}))
