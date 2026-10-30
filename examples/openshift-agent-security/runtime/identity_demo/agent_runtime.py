# SPDX-License-Identifier: Apache-2.0
"""Trusted adapter for sandbox model turns and existing certificate-bound MCP reads."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import sys
import time

import probe_native_exchange as native
from native_read_retry import transient_read_failure
from provider_contract import MODEL, sources as provider_sources


class AgentRuntimeFailure(Exception):
    """A fixed agent failure category, never raw upstream text."""


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "workloads/agents/service-request-demo/src"


def module() -> object:
    """Load the reviewed bounded loop, never model-supplied executable content."""
    spec = importlib.util.spec_from_file_location(
        "identity_demo_agent_loop", SOURCE / "agent_loop.py"
    )
    value = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = value
    spec.loader.exec_module(value)
    return value


def sandbox_sources(invoke: str) -> str:
    """Install exact repository sources into a temporary sandbox directory."""
    sources = {
        name: (SOURCE / name).read_text() for name in ("agent_loop.py", "inference.py")
    }
    sources.update(provider_sources())
    return (
        "import tempfile,pathlib,sys\n"
        "with tempfile.TemporaryDirectory(prefix='governed-agent-') as d:\n"
        " for name,source in "
        + repr(sources)
        + ".items(): pathlib.Path(d,name).write_text(source)\n"
        " sys.path.insert(0,d)\n"
        + "\n".join(" " + line for line in invoke.splitlines())
        + "\n"
    )


def program_arguments(program: str) -> list[str]:
    """Respect native exec's 32 KiB per-argument limit without interpreting model text."""
    data = program.encode("utf-8")
    if len(data) <= 32_768:
        return ["python", "-c", program]
    if len(data) > 131_072:
        raise AgentRuntimeFailure("agent_context_limit")
    encoded = base64.b64encode(data).decode("ascii")
    chunks = [
        encoded[index : index + 16_384] for index in range(0, len(encoded), 16_384)
    ]
    bootstrap = (
        "import base64,sys;source=base64.b64decode(''.join(sys.argv[1:]),validate=True);"
        "assert len(source)<=131072;exec(compile(source,'<governed-agent>','exec'))"
    )
    return ["python", "-c", bootstrap, *chunks]


def report(flow: object, execute: object, resource: str, context: object) -> dict:
    """Produce only a draft; the caller retains all identity, consent and write gates."""
    agent = module()
    inference = SOURCE / "inference.py"
    source_hash = hashlib.sha256(
        (SOURCE / "agent_loop.py").read_bytes() + inference.read_bytes()
        + (SOURCE / "remediation.json").read_bytes()
        + json.dumps(provider_sources(), sort_keys=True).encode()
    ).hexdigest()
    # The SERVICE mapping and request ID stay stable; scenario text grants no authority.
    task = getattr(flow, "agent_task", None) or json.loads(
        (SOURCE / "remediation.json").read_text()
    )["task"]
    model_receipts = []
    observed_reads = 0
    scope_feedback = None

    def sandbox(program: str, remaining: float) -> dict:
        if remaining <= 0:
            raise agent.AgentFailure("agent_timeout")
        return execute(
            [
                "sandbox",
                "exec",
                "--name",
                context.sandbox_name,
                "--no-login-shell",
                "--timeout",
                str(min(90, math.ceil(remaining) + 3)),
                "--no-tty",
                "--",
                *program_arguments(program),
            ],
            json_output=True,
        )

    def model(messages: list[dict], tools: list[dict], remaining: float) -> dict:
        timeout = max(
            0.1, min(getattr(flow, "model_request_timeout", 30), 30, remaining)
        )
        body = {
            "model": MODEL,
            "max_tokens": 4096,
            "system": agent.SYSTEM,
            "messages": messages,
            "tools": tools,
            "tool_choice": {"type": "tool", "name": "search_jira", "disable_parallel_tool_use": True}
            if len(messages) == 1
            else {"type": "any", "disable_parallel_tool_use": True},
        }
        program = sandbox_sources(
            "body="
            + repr(body)
            + "\ntimeout="
            + repr(timeout)
            + "\n"
            + """import json
from agent_loop import parse_api_response, AgentFailure
from inference import request_messages, InferenceFailure, MODEL
try:
 action=parse_api_response(request_messages(body,timeout))
 print(json.dumps({'action':action,'inference':{'model':MODEL,'http_status':200,'tls_verified':True,'follow_redirects':False,'credential_in_agent':False}}))
except InferenceFailure as error:
 value={'inference_failed':True,'error_category':str(error)}
 if type(getattr(error,'http_status',None)) is int: value['http_status']=error.http_status
 print(json.dumps(value))
except AgentFailure as error:
 print(json.dumps({'agent_failed':True,'error_category':str(error)}))"""
        )
        value = sandbox(program, remaining)
        if not isinstance(value, dict):
            raise agent.AgentFailure("model_schema")
        if value.get("inference_failed"):
            if value.get("http_status") in (429, 502, 503, 504) or value.get(
                "error_category"
            ) in ("timeout", "transport_unavailable"):
                raise agent.TransientFailure()
            raise agent.AgentFailure("model_unavailable")
        if value.get("agent_failed"):
            category = value.get("error_category")
            # Only parser-owned vocabulary may reach the console, never upstream text.
            allowed = ("model_schema", "one_read_per_turn", "unauthorised_tool", "draft_schema",
                       "invalid_text", "duplicate_field", "invalid_json", "incomplete_output", "model_output_limit")
            raise agent.AgentFailure(category if category in allowed else "model_output_invalid")
        if set(value) != {"action", "inference"}:
            raise agent.AgentFailure("model_schema")
        receipt = value["inference"]
        if (
            not isinstance(receipt, dict)
            or receipt.get("model") != MODEL
            or receipt.get("http_status") != 200
            or receipt.get("tls_verified") is not True
            or receipt.get("credential_in_agent") is not False
            or receipt.get("follow_redirects") is not False
        ):
            raise agent.AgentFailure("inference_receipt")
        model_receipts.append(receipt)
        return value["action"]

    def read(jql: str, remaining: float) -> dict:
        nonlocal scope_feedback
        query = agent.scoped_jql(jql, flow.project)
        started = time.monotonic()
        # Dedicated synthetic boundary test: never relax model JQL validation.
        # This trusted probe uses the same sandbox, run and certificate-bound MCP
        # transport and must observe the gateway's own actual 403 response.
        probe_project = getattr(flow, "agent_scope_probe", None)
        if probe_project is not None and scope_feedback is None:
            if (
                flow.workflow != "incident-triage"
                or flow.project != "OPS"
                or probe_project != "TEST"
            ):
                raise agent.AgentFailure("denial_schema")
            flow.progress("checking_project_boundary")
            probe = sandbox(
                native.read_program(
                    resource,
                    "step56_jira_readJiraProject",
                    {"run_id": flow.run_id, "project": probe_project},
                    "project_scope",
                    request_timeout=max(
                        0.1,
                        min(getattr(flow, "read_request_timeout", 20), 20, remaining),
                    ),
                ),
                remaining,
            )
            if transient_read_failure(probe):
                raise agent.TransientFailure()
            denied = probe.get("read_passed") is False and any(
                event.get("method") == "tools/call"
                and event.get("http_status") == 403
                and event.get("denial_reason") == "project_permission"
                for event in probe.get("events", [])
            )
            if not denied or probe.get("verified_tool_result"):
                raise agent.AgentFailure("scope_probe_failed")
            scope_feedback = {
                "requested_project": probe_project,
                "denied": True,
                "http_status": 403,
                "reason": "project_permission",
                "boundary": "certificate_bound_gateway",
            }
            native.private_write(
                flow.args.output_dir / (flow.args.label + ".scope-probe.summary.json"),
                {
                    **scope_feedback,
                    "run_id": flow.run_id,
                    "workload": context.workload,
                    "same_native_transport": True,
                    "out_of_project_data_returned": False,
                },
            )
            flow.progress(
                "project_boundary_verified",
                {
                    "scope_probe_project": probe_project,
                    "scope_probe_denied": True,
                    "scope_probe_status": 403,
                },
            )
        remaining -= time.monotonic() - started
        if remaining <= 0:
            raise agent.AgentFailure("agent_timeout")
        program = native.read_program(
            resource,
            "step56_jira_readJiraProject",
            {"run_id": flow.run_id, "project": flow.project, "jql": query},
            "project_scope",
            include_issues=True,
            request_timeout=max(
                0.1, min(getattr(flow, "read_request_timeout", 20), 20, remaining)
            ),
        )
        value = sandbox(program, remaining)
        if transient_read_failure(value):
            raise agent.TransientFailure()
        for event in value.get("events", []):
            reason = event.get("denial_reason")
            if reason in (
                "project_permission",
                "user_permission",
                "workload_permission",
                "run_inactive",
            ):
                return {"denied": True, "reason": reason}
        if value.get("read_passed") is not True:
            raise agent.AgentFailure("governed_read_failed")
        observed = value.get("verified_tool_result", {}).get("jira_read")
        if not isinstance(observed, dict):
            raise agent.AgentFailure("read_schema")
        # Reconstruct the minimal schema for independent validation in AgentLoop.
        return {
            **({"scope_probe": scope_feedback} if scope_feedback is not None else {}),
            "project_scope": observed.get("project"),
            "total": observed.get("total"),
            "issues": [
                {
                    "key": item.get("key"),
                    "fields": {
                        "project": {"key": observed.get("project")},
                        "summary": item.get("summary"),
                        "description": item.get("description"),
                        "status": {"name": item.get("status")},
                    },
                }
                for item in observed.get("issues", [])
            ],
        }

    def event(name: str, value: dict) -> None:
        nonlocal observed_reads
        stages = {
            "agent_turn": "agent_reasoning",
            "agent_read_requested": "agent_read_requested",
            "agent_query_rejected": "agent_query_rejected",
            "agent_read_succeeded": "agent_read_complete",
            "agent_read_denied": "agent_read_denied",
            "agent_draft_ready": "agent_draft_ready",
            "agent_retry": "agent_retry",
        }
        fields = (
            {"model_inference": True, "model": MODEL}
            if model_receipts
            else {}
        )
        if "turn" in value:
            fields["agent_turn"] = value["turn"]
        if name == "agent_read_requested":
            fields["agent_query"] = value["jql"]
        elif name == "agent_query_rejected":
            fields["agent_error_category"] = value["reason"]
        elif name == "agent_read_succeeded":
            observed_reads += 1
            fields["agent_read_count"] = observed_reads
            items = [
                {
                    **item,
                    "summary": item["summary"][:160],
                    "status": item["status"][:50],
                }
                for item in value["issues"]
            ]
            while len(json.dumps(items).encode()) > 5000:
                items.pop()
            fields.update(
                jira_issue_count=value["issue_count"],
                jira_project=value["project"],
                jira_query=value["jql"],
                jira_issues=items,
            )
        elif name == "agent_read_denied":
            fields["agent_denial_reason"] = value["reason"]
        elif name == "agent_retry":
            fields.update(
                agent_retry_count=value["retry"], agent_retry_boundary=value["boundary"]
            )
        elif name == "agent_draft_ready":
            fields["agent_read_count"] = value["read_count"]
        flow.progress(stages[name], fields)

    try:
        result = agent.AgentLoop(model, read, event).run(task, flow.project)
    except agent.AgentFailure as error:
        raise AgentRuntimeFailure(str(error)) from None
    except RuntimeError:
        raise AgentRuntimeFailure("agent_transport_failed") from None
    native.private_write(
        flow.args.output_dir / (flow.args.label + ".agent.summary.json"),
        {
            **result,
            "source_sha256": source_hash,
            "model_receipts": model_receipts,
            "writes_available": False,
        },
    )
    receipt = {
        **model_receipts[-1],
        "api": "messages",
        "model_output_is_untrusted": True,
        "input_sha256": hashlib.sha256(task.encode()).hexdigest(),
    }
    observations = result["observations"]
    keys = sorted(
        {item["key"] for observed in observations for item in observed["issues"]}
    )
    summary = (
        "Actual governed Jira read: project "
        + flow.project
        + "; observed issues: "
        + (", ".join(keys) or "none")
        + ".\n\n"
    )
    return {
        "request_id": flow.submission["request"],
        "assessment": summary + result["description"],
        "proposed_create": {
            "project": flow.project,
            "issue_type": "Task",
            "summary": result["summary"],
            "description": result["description"],
            "labels": [
                "synthetic-remediation-change" if getattr(flow, "workflow", "service-request") == "service-request" else "synthetic-incident-triage",
                "model-proposal",
                "agent-read-informed",
            ],
        },
        "source_sha256": source_hash,
        "inference": receipt,
        "agent": {
            "turns": result["turns"],
            "retries": result["retries"],
            "reads": result["reads"],
            "observations": observations,
            "writes_available": False,
        },
    }
