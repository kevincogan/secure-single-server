#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise native two-stage exchange on the exact owned development sandbox.

Temporary issuer clients and native provider state are removed after the probe.
Credentials and raw output remain private. This does not prove sender binding,
the complete run association, NeMo authentication, or protected backend delivery.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import re
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import time
from typing import Any, Iterator
from urllib.parse import urlencode, urlparse

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "identity_demo"))
from identity_demo_adapter import fixture_request  # noqa: E402
from identity_demo_lab import LABELS  # noqa: E402
from identity_demo_runtime import NAMESPACE, admin_token, guard  # noqa: E402
from identity_demo_runtime_cli import private_path  # noqa: E402
from identity_demo_runtime_grants import SERVER  # noqa: E402
import probe_token_exchange as issuer_probe  # noqa: E402
import checks.test_components as components  # noqa: E402
import identity_demo_keycloak_upstream as upstream  # noqa: E402
from run_binding import ReadRun, authorization as run_authorization  # noqa: E402
from execution_context import context_of, resolve_context  # noqa: E402
from deployment_profile import active_profile, LEGACY  # noqa: E402

SANDBOX = "fixture-cve-spiffe"
SANDBOX_ID = "00000000-0000-4000-8000-000000000001"
GATEWAY = "spiffe://" + active_profile().trust_domain + "/openshell/gateway/" + active_profile().gateway_id
WORKLOAD = "spiffe://" + active_profile().trust_domain + "/openshell/sandbox/" + SANDBOX_ID
OTHER_WORKLOAD = (
    "spiffe://" + active_profile().trust_domain + "/openshell/sandbox/fixture-step4-substitution"
)
PREFIX = "fixture-native-exchange-step4"
UI = PREFIX + "-ui"
EXPERIMENT = "native-step4-read"


def provider_token_endpoint(issuer: str, bound_sender: bool) -> str:
    """Use the exact compiled sender destination, including DNS and token path."""
    if not bound_sender:
        return issuer + '/protocol/openid-connect/token'
    if active_profile() == LEGACY:
        # Preserve the historical accepted sender's short service DNS contract.
        return 'https://fixture-keycloak-upstream.demo-core.svc:8443/realms/identity-demo/protocol/openid-connect/token'
    return active_profile().native_build_contract['OPENSHELL_DEMO_TOKEN_ENDPOINT']


def private_write(path: Path, value: Any) -> None:
    """Retain evidence outside Git without overwriting an earlier attempt."""
    text = value if isinstance(value, str) else json.dumps(value, indent=2)
    with os.fdopen(
        os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w"
    ) as stream:
        stream.write(text)


def kube(args: argparse.Namespace, *words: str, payload: Any = None) -> Any:
    """Bound cluster operations and never expose raw API failures."""
    from identity_demo_worker_lease import assert_current
    assert_current()
    result = subprocess.run(
        ["oc", "--kubeconfig=" + args.kubeconfig, "--request-timeout=20s", *words],
        input=json.dumps(payload) if payload is not None else None,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode:
        # Safe categories make a failed gate diagnosable without publishing
        # API stderr (which may contain supplied credentials or request bodies).
        categories = (
            "forbidden",
            "unauthorized",
            "timeout",
            "connection refused",
            "not found",
        )
        category = next(
            (value for value in categories if value in result.stderr.lower()),
            "unclassified",
        )
        error = RuntimeError("Owned namespace API operation failed: " + category)
        error.api_failure_category = category
        raise error
    return json.loads(result.stdout) if result.stdout.strip() else None


def inventory(value: Any, key: str) -> list[dict]:
    """Require an explicit list rather than interpreting a failed read as empty."""
    if isinstance(value, dict):
        value = value.get(key)
    if not isinstance(value, list) or any(not isinstance(v, dict) for v in value):
        raise ValueError("Unrecognized native inventory")
    return value


def require_native_provider_id(
    records: list[dict], expected_id: str | None, prefix: str = PREFIX
) -> dict:
    """Refuse cleanup if the recorded native object was replaced or is ambiguous."""
    matches = [v for v in records if v.get("name") == prefix]
    if (
        not expected_id
        or len(matches) != 1
        or matches[0].get("id") != expected_id
        or matches[0].get("type") != prefix
    ):
        raise ValueError("Recorded native provider cleanup ID mismatch")
    return matches[0]


def authorizer_ready(config: dict, rules: dict) -> bool:
    """Require the intended rules in a reconciled generated authorizer config."""
    actual = config.get("spec", {})
    expected_jwt = rules["authentication"]["keycloak"]["jwt"]["issuerUrl"]
    if (
        actual.get("authentication", {})
        .get("keycloak", {})
        .get("jwt", {})
        .get("issuerUrl")
        != expected_jwt
    ):
        return False
    for key, desired in rules.get("authorization", {}).items():
        matches = [
            value
            for name, value in actual.get("authorization", {}).items()
            if name == key or name.endswith("-" + key)
        ]
        if len(matches) != 1:
            return False
        for mechanism in ("opa", "patternMatching"):
            if mechanism in desired and matches[0].get(mechanism) != desired[mechanism]:
                return False
    status = config.get("status", {})
    return status.get("summary", {}).get("ready") is True and any(
        c.get("type") == "Ready" and c.get("status") == "True"
        for c in status.get("conditions", [])
    )


def wait_authorizer(args: argparse.Namespace, spec: dict) -> None:
    """Wait for configuration reconciliation before interpreting an MCP result.

    Cluster workers observe the recorded owned policy at its current generation.
    Local installer diagnostics retain the generated-config inspection. Neither
    path changes policy or replaces the subsequent real protected request.
    """
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if os.environ.get('IDENTITY_DEMO_RUNTIME') == 'cluster':
            if getattr(args, 'gateway_mode', 'temporary') != 'persistent':
                raise ValueError('Cluster runtime requires persistent gateway authorization')
            from identity_demo_gateway_observation import authorizer_current
            if authorizer_current(args, spec):
                return
            time.sleep(1)
            continue
        configs = kube(
            args, "get", "authconfig", "-n", "kuadrant-system", "-o", "json"
        )["items"]
        matches = [c for c in configs if authorizer_ready(c, spec["rules"])]
        # A Gateway policy can be inherited by multiple generated route configs.
        # Matching configurations are not necessarily a singleton.
        if matches:
            return
        time.sleep(1)
    raise TimeoutError("Intended fixture authorizer rules did not become Ready")


class NativeTunnelStartupError(RuntimeError):
    """Tunnel setup failed before any native command could be dispatched."""


class ProviderAttachmentConflict(RuntimeError):
    """Represent the native CLI's explicit pre-save, safe-to-retry CAS conflict."""


def provider_attachment_conflict(words: list[str], stderr: str) -> bool:
    """Match only the exact pre-save attachment conflict; uncertainty never retries."""
    message = " ".join(stderr.translate(str.maketrans("", "", "│×")).split())
    return (words[:3] == ["sandbox", "provider", "attach"] and message ==
            "Error: Failed to attach provider: sandbox was modified by another operation. "
            "Please retry the command.")


@contextmanager
def native_session(args: argparse.Namespace, credentials: dict, *, initialize_profile: bool = False) -> Iterator[Any]:
    """Own a loopback tunnel and an exact authenticated fixture CLI session."""
    directory = private_path(args.cli_config_dir, directory=True)
    output = private_path(str(args.output_dir), directory=True)
    management_port = getattr(args, 'management_port', 18443)
    if type(management_port) is not int or not 1024 <= management_port <= 65535:
        raise ValueError('Bounded private management port required')
    try:
        with socket.create_connection(("127.0.0.1", management_port), timeout=0.2):
            raise ValueError("Existing loopback listener refused")
    except OSError:
        pass
    env = {
        **os.environ,
        "XDG_CONFIG_HOME": str(directory),
        "OPENSHELL_OIDC_CLIENT_SECRET": credentials["runtime_management"][
            "client_secret"
        ],
    }
    for name in (
        "OPENSHELL_GATEWAY",
        "OPENSHELL_GATEWAY_ENDPOINT",
        "OPENSHELL_GATEWAY_INSECURE",
        "OPENSHELL_WORKSPACE",
        "subject_token",
        "api_key",
    ):
        env.pop(name, None)
    count = 0
    reuse_management = bool(getattr(args, 'reuse_management_session', False))
    management_profile = None
    management_timings: list[dict] = []

    def measured(phase: str, operation: Any) -> Any:
        started, passed = time.monotonic(), False
        try:
            value = operation()
            passed = True
            return value
        finally:
            management_timings.append({'phase': phase, 'seconds': round(time.monotonic() - started, 4),
                                       'passed': passed, 'command_number': count})

    def owned_service() -> None:
        service = kube(args, 'get', 'service', 'fixture-openshell', '-n', NAMESPACE, '-o', 'json')
        if any(service['metadata'].get('labels', {}).get(k) != v for k, v in LABELS.items()):
            raise ValueError('Owned native tunnel target required')

    def authenticate(*, force: bool = False) -> None:
        nonlocal management_profile
        if reuse_management:
            from identity_demo_management_session import remaining_seconds, validate_profile
            management_profile = validate_profile(directory, credentials['keycloak_url'], management_port)
            if not force and remaining_seconds(management_profile) > 30:
                return
        login = measured('operator_login', lambda: subprocess.run(
            [args.cli, 'gateway', 'login', 'identity-demo-runtime'], env=env,
            capture_output=True, timeout=35))
        if login.returncode:
            raise RuntimeError('Native management reauthentication failed')
        if reuse_management and remaining_seconds(management_profile) <= 30:
            raise ValueError('Fresh management authentication has insufficient lifetime')

    def execute_once(
        words: list[str], *, subject: str | None = None, json_output: bool = False,
        execution_context: object | None = None,
        inference_key: str | None = None,
    ) -> Any:
        """Run fixed probe operations; human credentials never enter argv."""
        nonlocal count
        from identity_demo_worker_lease import assert_current
        assert_current()
        if inference_key is not None and (
            words[:2] not in (["provider", "create"], ["provider", "update"])
            or "--credential" not in words
            or words[words.index("--credential") + 1] != "api_key"
            or not isinstance(inference_key, str) or not 16 <= len(inference_key) <= 8192
            or any(c in inference_key for c in "\r\n\x00")
        ):
            raise ValueError("Inference credential only permitted for native provider storage")
        selected = execution_context or context_of(args)
        if selected not in [context_of(args), *getattr(args, "concurrent_contexts", [])]:
            raise ValueError("Native workspace context was not independently validated")
        count += 1
        # Verify a cached channel before dispatch. Never replay a command after
        # a transport error: its mutation outcome may be unknown.
        reconnect_tunnel(force=not reuse_management)
        if reuse_management:
            measured('owned_service_check', owned_service)
        authenticate()
        local_env = {
            **env,
            **({"subject_token": subject} if subject is not None else {}),
            **({"api_key": inference_key} if inference_key is not None else {}),
        }
        command_started = time.monotonic()
        result = subprocess.run(
            [
                args.cli,
                "--gateway",
                "identity-demo-runtime",
                "--workspace",
                selected.workspace,
                *words,
            ],
            env=local_env,
            capture_output=True,
            text=True,
            timeout=100,
        )
        management_timings.append({'phase': 'cli_command', 'seconds': round(time.monotonic() - command_started, 4),
                                   'passed': result.returncode == 0, 'command_number': count})
        prefix = output / f"{args.label}.cli-{count:02d}"
        private_write(Path(str(prefix) + ".command.json"), words)
        private_write(Path(str(prefix) + ".stdout"),
                      "[credential-bearing command output withheld]" if inference_key or subject else result.stdout)
        private_write(Path(str(prefix) + ".stderr"),
                      "[credential-bearing command output withheld]" if inference_key or subject else result.stderr)
        if result.returncode:
            error_type = (ProviderAttachmentConflict
                          if provider_attachment_conflict(words, result.stderr) else RuntimeError)
            error = error_type("Native fixture operation failed")
            error.command_number = count
            error.command_exit_code = result.returncode
            raise error
        if not json_output:
            return result.stdout
        try:
            value = json.loads(result.stdout)
            if isinstance(value, dict):
                value.pop("_private_response", None)
            return value
        except json.JSONDecodeError:
            # The image's Python startup can print a diagnostic before our
            # single bounded result. Never print or reinterpret that prefix.
            if words[:2] != ["sandbox", "exec"]:
                raise
            observations = []
            for line in result.stdout.splitlines():
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if (
                    isinstance(value, dict)
                    and "read_passed" in value
                    and "events" in value
                ):
                    value.pop("_private_response", None)
                    observations.append(value)
            if len(observations) != 1:
                raise ValueError("Exactly one native read observation required")
            return observations[0]

    def execute(
        words: list[str], *, subject: str | None = None, json_output: bool = False,
        execution_context: object | None = None, inference_key: str | None = None,
    ) -> Any:
        """Retry only definitive pre-save provider conflicts, retaining every attempt."""
        for attempt in range(3):
            try:
                return execute_once(words, subject=subject, json_output=json_output,
                                    execution_context=execution_context, inference_key=inference_key)
            except ProviderAttachmentConflict:
                if attempt == 2:
                    raise
                time.sleep(2 ** attempt)

    def parallel(jobs: list[tuple[object, str]]) -> list[dict]:
        """Use one fresh stable session for bounded simultaneous sandbox executions."""
        nonlocal count
        allowed = [context_of(args), *getattr(args, "concurrent_contexts", [])]
        if any(context not in allowed for context, _ in jobs):
            raise ValueError("Parallel execution context was not independently validated")
        reconnect_tunnel(force=not reuse_management)
        if reuse_management:
            measured('owned_service_check', owned_service)
        authenticate(force=True)
        count += 1
        batch = count
        from native_parallel import parallel_exec

        return parallel_exec(args.cli, env, jobs,
            lambda index, value: private_write(
                output / f"{args.label}.parallel-{batch:02d}-{index}.private.json", value))

    execute.parallel = parallel

    with open(
        output / (args.label + ".portforward-log"),
        "x",
        opener=lambda p, f: os.open(p, f, 0o600),
    ) as log:
        measured('owned_service_check', owned_service)
        tunnel = subprocess.Popen(
            [
                "oc",
                "--kubeconfig=" + args.kubeconfig,
                "-n",
                NAMESPACE,
                "port-forward",
                "--address",
                "127.0.0.1",
                "service/fixture-openshell",
                str(management_port) + ":8080",
            ],
            stdout=log,
            stderr=log,
        )

        def reconnect_tunnel(*, force: bool = False) -> None:
            """Replace only our own tunnel, retaining target and port guards."""
            nonlocal tunnel
            if tunnel.poll() is None and not force:
                if not reuse_management:
                    return
                from identity_demo_management_session import validate_profile, verify_transport
                profile = validate_profile(directory, credentials['keycloak_url'], management_port)
                try:
                    measured('tls_health', lambda: verify_transport(profile, management_port))
                    return
                except ssl.SSLError:
                    raise  # Certificate rejection is never downgraded to reconnect/retry.
                except OSError:
                    pass  # No CLI operation was dispatched; safe to replace our own tunnel.
            measured('owned_service_check', owned_service)
            if tunnel.poll() is None:
                tunnel.terminate()
                try:
                    tunnel.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    tunnel.kill()
                    tunnel.wait(timeout=5)
            try:
                with socket.create_connection(("127.0.0.1", management_port), timeout=0.2):
                    raise ValueError("Replaced loopback listener refused")
            except OSError:
                pass
            tunnel = subprocess.Popen(
                [
                    "oc",
                    "--kubeconfig=" + args.kubeconfig,
                    "-n",
                    NAMESPACE,
                    "port-forward",
                    "--address",
                    "127.0.0.1",
                    "service/fixture-openshell",
                    str(management_port) + ":8080",
                ],
                stdout=log,
                stderr=log,
            )
            for _ in range(100):
                if tunnel.poll() is not None:
                    raise RuntimeError("Owned native tunnel reconnect failed")
                try:
                    with socket.create_connection(("127.0.0.1", management_port), timeout=0.2):
                        return
                except OSError:
                    time.sleep(0.1)
            raise TimeoutError("Owned native tunnel reconnect timed out")

        try:
            for _ in range(100):
                if tunnel.poll() is not None:
                    raise NativeTunnelStartupError("Own native tunnel failed before command dispatch")
                try:
                    with socket.create_connection(("127.0.0.1", management_port), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                # No native command has been dispatched. Replace only our own
                # failed tunnel once; never replay a CLI operation or a write.
                try:
                    measured('tunnel_startup_retry', lambda: reconnect_tunnel(force=True))
                except (TimeoutError, RuntimeError) as error:
                    raise NativeTunnelStartupError("Native tunnel unavailable before command dispatch") from error
            if initialize_profile:
                from probe_runtime_management import initialize_cli

                initialize_cli(args, credentials, credentials['keycloak_url'])
            authenticate(force=True)
            yield execute
        finally:
            tunnel.terminate()
            try:
                tunnel.wait(timeout=5)
            except subprocess.TimeoutExpired:
                tunnel.kill()
                tunnel.wait(timeout=5)
            private_write(output / (args.label + '.management-timing.private.json'),
                          {'reuse_enabled': reuse_management, 'events': management_timings,
                           'operation_transport_replays': 0})


def read_program(
    resource: str,
    tool: str = "jira_searchJiraIssuesUsingJql",
    arguments: dict | None = None,
    success_field: str | None = None,
    *, include_issues: bool = False, request_timeout: float = 30,
) -> str:
    """Reuse the credential-free client; optionally project bounded read-only issue data."""
    if type(include_issues) is not bool or not 0 < request_timeout <= 30:
        raise ValueError("Bounded read projection required")
    prelude = ""
    if include_issues:
        project = (arguments or {}).get("project")
        if not isinstance(project, str) or not re.fullmatch(r"[A-Z][A-Z0-9]{1,15}", project):
            raise ValueError("Trusted project required for issue projection")
        source = (Path(__file__).resolve().parents[2] / "workloads/agents/service-request-demo/src/agent_loop.py").read_text()
        prelude = ("import tempfile,pathlib,runpy\n"
            "with tempfile.TemporaryDirectory(prefix='jira-projection-') as d:\n"
            " p=pathlib.Path(d)/'agent_loop.py'\n p.write_text(" + repr(source) + ")\n"
            " _demo_projection=runpy.run_path(str(p))['sanitise_issues']\n"
            "def _demo_project_jira(value):\n"
            " if 'key' in value: value={'project_scope':value.get('project_scope'),'total':1,'issues':[value]}\n"
            " return _demo_projection(value," + repr(project) + ")\n")
    import inspect
    from gateway_overview import project_schemas
    prelude=inspect.getsource(project_schemas)+'\n'+prelude
    return prelude + (
        """import json, os, re, time, urllib.request, urllib.error
resource = RESOURCE
tool = TOOL
session = None
protocol = "2025-11-25"
events = []
observed = {}
last_body = b""
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
client = urllib.request.build_opener(NoRedirect())
def rpc(method, params=None):
    global session, protocol, observed, last_body
    payload = {"jsonrpc":"2.0", "method":method}
    if method != "notifications/initialized": payload["id"] = len(events)+1
    if params is not None: payload["params"] = params
    headers = {"Accept":"application/json, text/event-stream", "Content-Type":"application/json", "MCP-Protocol-Version":protocol}
    if session: headers["Mcp-Session-Id"] = session
    request = urllib.request.Request(resource, data=json.dumps(payload).encode(), headers=headers)
    started = time.monotonic()
    try: response = client.open(request, timeout=READ_TIMEOUT)
    except urllib.error.HTTPError as error: response = error
    with response:
        body = response.read(2000001)
        last_body = body
        if len(body)>2000000: raise ValueError("Response bound exceeded")
        events.append({"method":method,"http_status":response.status})
        events[-1]["elapsed_seconds"] = round(time.monotonic()-started,6)
        denial = response.headers.get("x-demo-denial")
        if isinstance(denial,str) and re.fullmatch(r"[a-z_]{1,80}",denial): events[-1]["denial_reason"] = denial
        if response.status not in (200,202,204): raise ValueError("MCP denied")
        if method == "initialize": session = response.headers.get("Mcp-Session-Id")
        for name in ("sub", "client", "expiry"):
            value = response.headers.get("x-identity-demo-s4-"+name)
            if value is not None: observed[name] = value
        if not body: return {}
        values=[json.loads(line[5:].strip()) for line in body.decode().splitlines() if line.startswith("data:")]
        return values[-1] if values else json.loads(body)
try:
    assert not any(k.lower() == "subject_token" for k in os.environ)
    first = rpc("initialize", {"protocolVersion":protocol,"capabilities":{},"clientInfo":{"name":"native-step4-read","version":"0.1"}})
    protocol = first["result"]["protocolVersion"]
    assert protocol == "2025-11-25"
    rpc("notifications/initialized")
    listed = rpc("tools/list", {})
    try: published_schemas = project_schemas(listed.get("result",{}).get("tools",[]))
    except (ValueError,TypeError,AttributeError): published_schemas = []
    advertised = any(isinstance(v,dict) and v.get("name") == tool for v in listed.get("result",{}).get("tools",[]))
    value = rpc("tools/call", {"name":tool, "arguments":ARGUMENTS})
    result=value.get("result",{})
    tool_error = None
    if result.get("isError",False):
        if any(v.get("type")=="text" and re.search(r"\\baction_executing\\b",v.get("text","")) for v in result.get("content",[])):
            tool_error = "action_executing"
        contents=[]
    else:
        contents=[json.loads(v["text"]) for v in result.get("content",[]) if v.get("type")=="text"]
    passed=not result.get("isError",False) and any(isinstance(v,dict) and (bool(v.get(SUCCESS_FIELD)) if SUCCESS_FIELD else v.get("total")==0 and v.get("issues")==[]) for v in contents)
    rpc_error = value.get("error",{})
    safe_result = {}
    if passed and INCLUDE_ISSUES:
        for content in contents:
            if isinstance(content,dict) and content.get("project_scope"):
                safe_result["jira_read"] = _demo_project_jira(content)
    if passed:
        for content in contents:
            if not isinstance(content,dict): continue
            for name in ("key","duplicate","probe_passed","writes_enabled","run_id","action_id","project_scope","total"):
                value = content.get(name)
                if name == "key" and isinstance(value,str) and re.fullmatch(r"[A-Z][A-Z0-9]{1,15}-[1-9][0-9]*",value): safe_result[name] = value
                elif name in ("duplicate","probe_passed","writes_enabled") and type(value) is bool: safe_result[name] = value
                elif name in ("run_id","action_id") and isinstance(value,str) and re.fullmatch(r"[a-f0-9]{32}",value): safe_result[name] = value
                elif name == "project_scope" and isinstance(value,str) and re.fullmatch(r"[A-Z][A-Z0-9]{1,15}",value): safe_result[name] = value
                elif name == "total" and type(value) is int and value >= 0: safe_result[name] = value
    rpc_code = rpc_error.get("code") if isinstance(rpc_error,dict) else None
    category = None if passed else "rpc_error" if rpc_error else "tool_error" if result.get("isError",False) else "unexpected_tool_result"
    print(json.dumps({"read_passed":passed,"events":events,"verified_tool_result":safe_result,"published_tool_schemas":published_schemas,"mcp_error_reason":tool_error,"mcp_failure_category":category,"mcp_error_code":rpc_code if type(rpc_code) is int else None,"requested_tool_advertised":advertised,"verified_identity_headers":observed,"agent_received_subject_credential":False,"agent_supplied_authorization":False}))
except Exception as error:
    reason = getattr(error, "reason", None)
    words = set(re.findall(r"[a-z]+", str(reason).lower()))
    vocabulary = {"denied","policy","certificate","verify","failed","unknown","issuer","timeout","timed","out","connection","refused","reset","tunnel","proxy","forbidden","no","route","host","network","unreachable","binary","permitted","allowed"}
    print(json.dumps({"read_passed":False,"events":events,"verified_identity_headers":observed,"failure_kind":type(error).__name__,"reason_kind":type(reason).__name__,"reason_markers":sorted(words & vocabulary),"raw_body_withheld":True}))
""".replace("RESOURCE", repr(resource), 1)
        .replace("TOOL", repr(tool), 1)
        .replace("SUCCESS_FIELD", repr(success_field))
        .replace("INCLUDE_ISSUES", repr(include_issues), 1)
        .replace("READ_TIMEOUT", repr(request_timeout), 1)
        .replace(
            "ARGUMENTS",
            repr(
                arguments
                if arguments is not None
                else {"jql": "project = TEST", "maxResults": 1}
            ),
            1,
        )
    )


def run(args: argparse.Namespace) -> dict:
    """Prove the native read path and restore only exact recorded owned state."""
    if getattr(args, "context_file", None):
        if args.investigate_substitution or getattr(args, "check_key_rollover", False):
            raise ValueError(
                "Legacy substitution/rollover diagnostics require their original context"
            )

        def read_context(
            kind: str, name: str, namespace: str | None = NAMESPACE
        ) -> dict:
            """Read only the explicit owned execution contract."""
            scope = ["-n", namespace] if namespace else []
            return kube(args, "get", kind, name, *scope, "-o", "json")

        args.execution_context = resolve_context(args.context_file, read_context)
    flow = getattr(args, "permission_flow", None)
    if getattr(args, "enable_create", False) and flow is None:
        raise ValueError("Real create acceptance requires the authenticated permission flow")
    if flow is not None and any(
        getattr(args, name, False)
        for name in (
            "check_sender_rejection", "check_renewal", "check_key_rollover",
            "check_backend_rotation", "retain_run_retirement",
        )
    ):
        raise ValueError("Use a dedicated driver acceptance flow; Step 4 probe flags cannot be silently skipped")
    if flow is not None and (
        not getattr(args, "bound_sender_listener", False)
        or args.investigate_substitution
        or not getattr(args, "context_file", None)
        or not getattr(args, "protected_backend_catalog_credential_file", None)
    ):
        raise ValueError(
            "Permission flow requires the native bound listener and fresh execution context"
        )
    context = context_of(args)
    extra_contexts = []
    for path in getattr(args, "concurrent_context_files", []):
        extra_contexts.append(resolve_context(path, read_context))
    if extra_contexts and (flow is None or len(extra_contexts) > 3):
        raise ValueError("Concurrent contexts require a bounded authenticated driver flow")
    if len({c.workload for c in [context, *extra_contexts]}) != 1 + len(extra_contexts):
        raise ValueError("Concurrent executions must have distinct validated identities")
    args.concurrent_contexts = extra_contexts
    if flow is not None:
        flow.extra_contexts = extra_contexts
    SANDBOX, SANDBOX_ID = context.sandbox_name, context.sandbox_id
    WORKLOAD, PREFIX = context.workload, context.provider_prefix
    UI = PREFIX + "-ui"
    if args.require_substitution_denial and not args.investigate_substitution:
        raise ValueError(
            "Denial regression requires the controlled substitution diagnostic"
        )
    bound_sender = getattr(args, "bound_sender_listener", False)
    if bound_sender and not (
        args.upstream_development_issuer and args.check_run_binding
    ):
        raise ValueError(
            "Bound probe requires the pinned issuer and mandatory run enforcement"
        )
    protected_backend = getattr(args, "protected_backend_catalog_credential_file", None)
    if protected_backend:
        # Before browser login allocates a permanent execution identity, reject
        # an expired discovery prerequisite. Allow time for live reconciliation.
        catalog = json.loads(private_path(protected_backend).read_text())
        if (
            not isinstance(catalog.get("token"), str)
            or not catalog["token"].startswith("discovery_")
            or type(catalog.get("expires_at")) is not int
            or catalog["expires_at"] <= time.time() + 600
        ):
            raise ValueError("Refresh catalog-only credential before allocating a run")
    if protected_backend and not bound_sender:
        raise ValueError(
            "Combined backend acceptance requires native sender and run enforcement"
        )
    if (
        getattr(args, "check_sender_rejection", False)
        or getattr(args, "retain_run_retirement", False)
        or getattr(args, "check_key_rollover", False)
        or getattr(args, "check_backend_rotation", False)
    ) and not protected_backend:
        raise ValueError(
            "Complete sender/lifecycle checks require the protected native backend"
        )
    from native_run_lifecycle import require_unused_identity

    require_unused_identity(args, WORKLOAD)
    tool = "jira_searchJiraIssuesUsingJql"
    backend = None
    if protected_backend:
        from native_backend import NativeBackend, TOOL

        tool = "step56_jira_readJiraProject" if flow is not None else TOOL
        backend = NativeBackend(args)
    frontend_policy = "fixture-mcp-bound" if bound_sender else "fixture-mcp-auth"
    args.namespace = NAMESPACE
    if args.expected_server != SERVER or Path(args.label).name != args.label:
        raise ValueError("Exact lab and simple evidence label required")
    _, credentials, base = guard(args)
    original_issuer = base + "/realms/identity-demo"
    selected_request = fixture_request
    if getattr(args, "upstream_development_issuer", False):
        for kind in ("deployment", "route"):
            item = kube(args, "get", kind, upstream.NAME, "-n", NAMESPACE, "-o", "json")
            if any(
                item["metadata"].get("labels", {}).get(k) != v
                for k, v in LABELS.items()
            ):
                raise ValueError("Owned upstream development issuer required")
            if kind == "route" and "https://" + item["spec"]["host"] != upstream.BASE:
                raise ValueError("Exact approved upstream issuer origin required")
            if (
                kind == "deployment"
                and item["spec"]["template"]["spec"]["containers"][0]["image"]
                != upstream.IMAGE
            ):
                raise ValueError("Pinned approved development issuer required")
        base = upstream.BASE
        selected_request = upstream.issuer_request
    output = private_path(str(args.output_dir), directory=True)
    if list(output.glob(args.label + ".*")):
        raise ValueError("Existing probe artifacts refused")
    gateway = kube(
        args, "-n", NAMESPACE, "get", "statefulset", "fixture-openshell", "-o", "json"
    )
    if any(
        gateway["metadata"].get("labels", {}).get(k) != v for k, v in LABELS.items()
    ):
        raise ValueError("Owned native gateway required")
    components.KEYCLOAK, components.ISSUER = base, base + "/realms/identity-demo"
    from identity_demo_controller_identity import enabled as controller_identities, verify_gateway
    if controller_identities():
        verify_gateway(lambda kind, name, ns=None: kube(args, 'get', kind, name,
            *(['-n', ns] if ns else []), '-o', 'json'))
    resource = credentials["gateway_url"]
    if bound_sender:
        from sender_listener import HOST, NAME, RESOURCE

        resource = RESOURCE
        route = kube(args, "-n", NAMESPACE, "get", "httproute", NAME, "-o", "json")
        if (
            route["spec"]["hostnames"] != [HOST]
            or route["spec"]["parentRefs"][0].get("sectionName") != "bound"
        ):
            raise ValueError("Exact owned bound MCP resource required")
    else:
        route = kube(args, "-n", NAMESPACE, "get", "route", "fixture-mcp", "-o", "json")
        if resource != "https://" + route["spec"]["host"] + "/mcp":
            raise ValueError("Exact owned MCP resource required")
    if any(route["metadata"].get("labels", {}).get(k) != v for k, v in LABELS.items()):
        raise ValueError("Owned route required")
    result: dict[str, Any] = {
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "Native two-stage SPIFFE exchange and synthetic read only",
        "passed": False,
        "native_exchange_proven": False,
        "run_binding_proven": False,
        "sender_constraint_proven": False,
        "downstream_contract_proven": False,
        "cases": [],
        "errors": [],
        "step4_complete": False,
        "step5_started": bool(getattr(args, "context_file", None)),
    }
    result["workload_issuer"] = components.ISSUER
    result["runtime_management_issuer_changed"] = False
    operator_session: dict[str, Any] = {}

    def admin(path: str, method: str = "GET", value: Any = None) -> Any:
        """Operate only inside the owned synthetic identity realm."""
        from identity_demo_worker_lease import assert_current
        assert_current()
        if operator_session.get("until", 0) <= time.monotonic():
            if selected_request is fixture_request:
                token = admin_token(base, credentials)
            else:
                from identity_demo_realm_access import realm_token
                token = realm_token(selected_request, base, credentials)
            operator_session.update(token=token, until=time.monotonic() + 20)
        token = operator_session["token"]
        return selected_request(
            base, issuer_probe.PREFIX + path, token=token, method=method, value=value
        )[1]

    def progress(stage: str, evidence: dict | None = None) -> None:
        """Relay actual lifecycle boundaries only when a console observer is attached."""
        if flow is not None:
            flow.progress(stage, evidence)

    def checked(name: str, condition: bool) -> None:
        """Expose assertions, never token strings or response contents."""
        result["cases"].append({"case": name, "passed": bool(condition)})
        if not condition:
            raise ValueError("Native assertion failed: " + name)

    before = admin("/clients")
    private_write(output / (args.label + ".issuer-clients-before.private.json"), before)
    before_hash = issuer_probe.fingerprint(before)
    provider_inventory = admin("/identity-provider/instances")
    names = (resource, WORKLOAD, GATEWAY, UI) + (
        (OTHER_WORKLOAD,) if args.investigate_substitution else ()
    ) + tuple(c.workload for c in extra_contexts)
    if any(v["clientId"] in names for v in before) or any(
        v["alias"] == PREFIX for v in provider_inventory
    ):
        raise ValueError("Existing issuer names refused")
    created_clients: list[tuple[str, str]] = []
    issuer_provider_created = False
    policy_before = None
    policy_changed_spec = None
    tool_policy_before = None
    tool_policy_changed_spec = None
    with native_session(args, credentials) as execute:
        profiles_before = None
        providers_before = None
        profile_created = False
        provider_created = False
        provider_id = None
        attached = False
        try:
            state = execute(
                ["sandbox", "get", SANDBOX, "--output", "json"], json_output=True
            )
            checked(
                "native_sandbox_ready",
                state.get("id") == SANDBOX_ID and state.get("phase") == "Ready",
            )
            profiles_before = inventory(
                execute(
                    ["provider", "profile", "list", "-o", "json"], json_output=True
                ),
                "profiles",
            )
            providers_before = inventory(
                execute(["provider", "list", "-o", "json"], json_output=True),
                "providers",
            )
            checked(
                "native_names_unused",
                not any(v.get("id") == PREFIX for v in profiles_before)
                and not any(v.get("name") == PREFIX for v in providers_before),
            )
            profile = {
                "id": PREFIX,
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
                            "token_endpoint": provider_token_endpoint(components.ISSUER, bound_sender),
                            "audience": resource,
                            "jwt_svid_audience": components.ISSUER,
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
                                if flow is not None
                                else [tool]
                            )
                        ],
                    }
                ],
                "binaries": ["/workspace/.venv/bin/python", "/usr/bin/python3.12"],
            }
            filename = output / (args.label + ".profile.yaml")
            private_write(filename, yaml.safe_dump(profile, sort_keys=False))
            execute(["provider", "profile", "lint", "-f", str(filename)])
            progress("configuring_gateway")
            admin(
                "/identity-provider/instances",
                "POST",
                {
                    "alias": PREFIX,
                    "providerId": "spiffe",
                    "enabled": True,
                    "config": {
                        "trustDomain": "spiffe://" + active_profile().trust_domain,
                        "bundleEndpoint": "https://spire-spiffe-oidc-discovery-provider." + active_profile().identity_namespace + ".svc:8443/keys",
                        "identity-demo-owner": active_profile().owner,
                        "identity-demo-experiment": EXPERIMENT,
                    },
                },
            )
            issuer_provider_created = True
            roles = [admin("/roles/" + name) for name in ("analyst", "viewer")]
            clients = ((resource, None), (WORKLOAD, resource), (GATEWAY, WORKLOAD)) + (
                () if flow is not None else ((UI, GATEWAY),)
            )
            clients += tuple((c.workload, resource) for c in extra_contexts)
            if args.investigate_substitution:
                clients += ((OTHER_WORKLOAD, resource),)
            for name, audience in clients:
                client = issuer_probe.configuration(
                    name, secrets.token_urlsafe(32), audience
                )
                client.pop("secret", None)
                client["attributes"]["identity-demo-experiment"] = EXPERIMENT
                if name == UI:
                    client.update(
                        publicClient=True,
                        standardFlowEnabled=True,
                        redirectUris=["http://127.0.0.1:18085/callback"],
                    )
                    # Give this temporary test login enough time for renewal
                    # and substitution checks; final grants remain 30 seconds.
                    client["attributes"]["access.token.lifespan"] = (
                        "600" if protected_backend else "300"
                    )
                elif name in (GATEWAY, WORKLOAD, OTHER_WORKLOAD, *(c.workload for c in extra_contexts)):
                    client["clientAuthenticatorType"] = "federated-jwt"
                    client["attributes"].update(
                        {
                            "jwt.credential.issuer": PREFIX,
                            "jwt.credential.sub": name,
                            "standard.token.exchange.enabled": "true",
                        }
                    )
                    if name in (WORKLOAD, *(c.workload for c in extra_contexts)):
                        # Bound this diagnostic grant independently of the
                        # realm's longer human-login lifetime. Run expiry is
                        # still enforced separately by the trusted gateway.
                        client["attributes"]["access.token.lifespan"] = "30"
                        if bound_sender:
                            client["attributes"][
                                "tls.client.certificate.bound.access.tokens"
                            ] = "true"
                if name == GATEWAY:
                    for peer in extra_contexts:
                        client["protocolMappers"].append({
                            "name": "controlled-peer-" + peer.sandbox_id,
                            "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
                            "config": {"included.custom.audience": peer.workload,
                                       "access.token.claim": "true", "id.token.claim": "false"},
                        })
                if name == GATEWAY and args.investigate_substitution:
                    # Model the expected two-workload issuer configuration.
                    # Both audiences are legitimate; only this native sandbox's
                    # authenticated principal may select its own audience.
                    client["protocolMappers"].append(
                        {
                            "name": "diagnostic-second-workload-audience",
                            "protocol": "openid-connect",
                            "protocolMapper": "oidc-audience-mapper",
                            "config": {
                                "included.custom.audience": OTHER_WORKLOAD,
                                "access.token.claim": "true",
                                "id.token.claim": "false",
                            },
                        }
                    )
                admin("/clients", "POST", client)
                matches = admin("/clients?" + urlencode({"clientId": name}))
                checked("one_client:" + name, len(matches) == 1)
                identifier = matches[0]["id"]
                created_clients.append((name, identifier))
                admin(
                    "/clients/" + identifier + "/scope-mappings/realm",
                    "POST",
                    [{"id": role["id"], "name": role["name"]} for role in roles],
                )
            login = (
                flow.login(context)
                if flow is not None
                else components.login("analyst", credentials["analyst"], client_id=UI)
            )
            human = components.verify(
                login["access_token"], GATEWAY, issuer=components.ISSUER
            )
            if flow is not None:
                checked(
                    "authenticated_driver_login",
                    human["sub"] == flow.user
                    and human.get("azp") == "identity-demo-driver",
                )
            else:
                identity = components.verify(
                    login["id_token"], UI, issuer=components.ISSUER
                )
                checked(
                    "human_pkce_nonce_roles",
                    human["sub"] == identity["sub"]
                    and identity.get("nonce") == login["expected_nonce"]
                    and human.get("realm_access", {}).get("roles") == ["analyst"],
                )
            checked(
                "human_not_mcp_recipient",
                resource
                not in (
                    [human["aud"]] if isinstance(human["aud"], str) else human["aud"]
                ),
            )
            private_write(
                output / (args.label + ".run-record.json"),
                {
                    "user_issuer": human["iss"],
                    "user_subject": human["sub"],
                    "expected_workload": WORKLOAD,
                    "sandbox_id": SANDBOX_ID,
                    "provider_name": PREFIX,
                    "expires_at": human["exp"],
                    "full_run_binding_proven": False,
                },
            )
            protected_run = ReadRun(
                run_id=flow.run_id if flow is not None else secrets.token_urlsafe(16),
                issuer=human["iss"],
                user_subject=human["sub"],
                workload=WORKLOAD,
                audience=resource,
                not_before=int(time.time()),
                expires_at=human["exp"],
            )
            if backend is not None:
                ca = kube(
                    args,
                    "get",
                    "configmap",
                    "fixture-service-ca",
                    "-n",
                    NAMESPACE,
                    "-o",
                    "json",
                )
                if any(
                    ca["metadata"].get("labels", {}).get(k) != v
                    for k, v in LABELS.items()
                ):
                    raise ValueError("Owned public service CA required")
                backend.prepare(
                    ca["data"]["service-ca.crt"],
                    "" if getattr(args, 'gateway_mode', 'temporary') == 'persistent'
                    else credentials["adapter_clients"]["fixture-gateway-service"],
                    protected_run,
                    protected_backend,
                )
                result["protected_backend_configuration_checks"] = backend.ready()
            progress("attaching_credentials")
            execute(["provider", "profile", "import", "-f", str(filename)])
            profile_created = True
            execute(
                [
                    "provider",
                    "create",
                    "--name",
                    PREFIX,
                    "--type",
                    PREFIX,
                    "--credential",
                    "subject_token",
                    "--config",
                    "identity-demo-owner=" + active_profile().owner,
                    "--config",
                    "identity-demo-experiment=" + EXPERIMENT,
                ],
                subject=login["access_token"],
            )
            provider_created = True
            records = inventory(
                execute(["provider", "list", "-o", "json"], json_output=True),
                "providers",
            )
            created = [
                v
                for v in records
                if v.get("name") == PREFIX and v.get("type") == PREFIX
            ]
            if len(created) != 1 or not created[0].get("id"):
                raise ValueError("One created native provider ID required")
            provider_id = created[0]["id"]
            private_write(
                output / (args.label + ".native-provider-ledger.json"), created[0]
            )
            execute(
                [
                    "provider",
                    "update",
                    PREFIX,
                    "--credential-expires-at",
                    "subject_token=" + str(human["exp"] * 1000),
                ]
            )
            execute(
                [
                    "sandbox",
                    "provider",
                    "attach",
                    SANDBOX,
                    PREFIX,
                    "--wait",
                    "--timeout",
                    "30",
                    "--output",
                    "json",
                ]
            )
            attached = True
            if getattr(args, "gateway_mode", "temporary") != "persistent":
                policy_before = kube(
                    args,
                    "-n",
                    NAMESPACE,
                    "get",
                    "authpolicy",
                    frontend_policy,
                    "-o",
                    "json",
                )
                if any(
                    policy_before["metadata"].get("labels", {}).get(k) != v
                    for k, v in LABELS.items()
                ):
                    raise ValueError("Owned frontend policy required")
                spec = json.loads(json.dumps(policy_before["spec"]))
                checked(
                    "gateway_uses_expected_original_issuer",
                    spec["rules"]["authentication"]["keycloak"]["jwt"]["issuerUrl"]
                    == (components.ISSUER if bound_sender else original_issuer),
                )
                if bound_sender:
                    # Preserve the deny-until-validation baseline and install only
                    # the strict temporary signature/audience/run/certificate rule.
                    spec["rules"] = {
                        "authentication": {
                            "keycloak": {
                                "jwt": {
                                    "issuerUrl": components.ISSUER,
                                    "issuer": components.ISSUER,
                                    "audiences": [resource],
                                    "ttl": 60,
                                }
                            }
                        },
                        "authorization": {},
                    }
                if flow is not None:
                    # The owned direct AuthConfig performs the live driver lookup.
                    # Generated Kuadrant configs cannot resolve Secrets in our namespace.
                    # Retain independent exact JWT/run/certificate proof at this boundary.
                    auth = run_authorization([protected_run, *getattr(flow, "peer_bindings", [])], require_sender_binding=True)
                    # Reads are permitted for both demo user roles; create permission
                    # remains a live exact-action decision at the receiving boundary.
                    auth["opa"]["rego"] = auth["opa"]["rego"].replace(
                        '"analyst" == identity.realm_access.roles[_]',
                        'identity.realm_access.roles[_] == {"analyst", "viewer"}[_]',
                    )
                    spec["rules"]["authorization"] = {"native-step56-bound": auth}
                else:
                    authorization = spec["rules"]["authorization"]
                    if (
                        getattr(args, "upstream_development_issuer", False)
                        and not bound_sender
                    ):
                        issuer_patterns = authorization["issuer"]["patternMatching"][
                            "patterns"
                        ]
                        expected = (
                            "has(auth.identity.iss) && auth.identity.iss == "
                            + json.dumps(original_issuer)
                        )
                        if (
                            len(issuer_patterns) != 1
                            or issuer_patterns[0].get("predicate") != expected
                        ):
                            raise ValueError(
                                "Unexpected issuer policy; refuse automatic rewrite"
                            )
                        spec["rules"]["authentication"]["keycloak"]["jwt"]["issuerUrl"] = (
                            components.ISSUER
                        )
                        issuer_patterns[0]["predicate"] = (
                            "has(auth.identity.iss) && auth.identity.iss == "
                            + json.dumps(components.ISSUER)
                        )
                    if "native-step4-identity" in authorization:
                        raise ValueError("Existing native identity rule refused")
                    predicate = (
                        "has(auth.identity.sub) && auth.identity.sub == "
                        + json.dumps(human["sub"])
                        + " && has(auth.identity.azp) && auth.identity.azp == "
                        + json.dumps(WORKLOAD)
                        + " && has(auth.identity.exp) && int(auth.identity.exp) <= "
                        + str(human["exp"])
                        + " && has(auth.identity.iat) && int(auth.identity.exp) > int(auth.identity.iat)"
                        " && int(auth.identity.exp) - int(auth.identity.iat) <= 30"
                        + " && has(auth.identity.realm_access) && has(auth.identity.realm_access.roles)"
                        " && 'analyst' in auth.identity.realm_access.roles"
                    )
                    authorization["native-step4-identity"] = {
                        "patternMatching": {"patterns": [{"predicate": predicate}]}
                    }
                    if getattr(args, "check_run_binding", False):
                        # Isolated component diagnostic only. G6 remains false until
                        # the native certificate path and gateway enforcement pass.
                        authorization["native-step4-run"] = run_authorization(
                            [protected_run], require_sender_binding=bound_sender
                        )
                patch = [
                    {
                        "op": "test",
                        "path": "/metadata/uid",
                        "value": policy_before["metadata"]["uid"],
                    },
                    {
                        "op": "test",
                        "path": "/metadata/resourceVersion",
                        "value": policy_before["metadata"]["resourceVersion"],
                    },
                    {"op": "test", "path": "/spec", "value": policy_before["spec"]},
                    {"op": "replace", "path": "/spec", "value": spec},
                ]
                private_write(output / (args.label + ".policy-before.json"), policy_before)
                updated = kube(
                    args,
                    "-n",
                    NAMESPACE,
                    "patch",
                    "authpolicy",
                    frontend_policy,
                    "--type=json",
                    "-p",
                    json.dumps(patch),
                    "-o",
                    "json",
                )
                policy_changed_spec = updated["spec"]
                if getattr(args, "upstream_development_issuer", False):
                    tool_policy_before = kube(
                        args,
                        "-n",
                        NAMESPACE,
                        "get",
                        "authpolicy",
                        "fixture-mcp-tools-auth",
                        "-o",
                        "json",
                    )
                    if any(
                        tool_policy_before["metadata"].get("labels", {}).get(k) != v
                        for k, v in LABELS.items()
                    ):
                        raise ValueError("Owned tool-route policy required")
                    tool_spec = json.loads(json.dumps(tool_policy_before["spec"]))
                    rules = tool_spec["rules"]
                    expected = (
                        "has(auth.identity.iss) && auth.identity.iss == "
                        + json.dumps(original_issuer)
                    )
                    patterns = rules["authorization"]["issuer"]["patternMatching"][
                        "patterns"
                    ]
                    if (
                        rules["authentication"]["keycloak"]["jwt"]["issuerUrl"]
                        != original_issuer
                        or len(patterns) != 1
                        or patterns[0].get("predicate") != expected
                    ):
                        raise ValueError("Unexpected tool-route issuer policy")
                    rules["authentication"]["keycloak"]["jwt"]["issuerUrl"] = (
                        components.ISSUER
                    )
                    patterns[0]["predicate"] = (
                        "has(auth.identity.iss) && auth.identity.iss == "
                        + json.dumps(components.ISSUER)
                    )
                    if bound_sender:
                        audience_patterns = rules["authorization"]["audience"][
                            "patternMatching"
                        ]["patterns"]
                        original_audience = json.dumps(credentials["gateway_url"])
                        expected_audience = (
                            "has(auth.identity.aud) && (auth.identity.aud == "
                            + original_audience
                            + " || (type(auth.identity.aud) == list && "
                            + original_audience
                            + " in auth.identity.aud))"
                        )
                        if (
                            len(audience_patterns) != 1
                            or audience_patterns[0]["predicate"] != expected_audience
                        ):
                            raise ValueError("Unexpected tool-route audience policy")
                        audience_patterns[0]["predicate"] = expected_audience.replace(
                            original_audience, json.dumps(resource)
                        )
                    private_write(
                        output / (args.label + ".tools-policy-before.json"),
                        tool_policy_before,
                    )
                    patch = [
                        {
                            "op": "test",
                            "path": "/metadata/uid",
                            "value": tool_policy_before["metadata"]["uid"],
                        },
                        {
                            "op": "test",
                            "path": "/metadata/resourceVersion",
                            "value": tool_policy_before["metadata"]["resourceVersion"],
                        },
                        {
                            "op": "test",
                            "path": "/spec",
                            "value": tool_policy_before["spec"],
                        },
                        {"op": "replace", "path": "/spec", "value": tool_spec},
                    ]
                    updated = kube(
                        args,
                        "-n",
                        NAMESPACE,
                        "patch",
                        "authpolicy",
                        "fixture-mcp-tools-auth",
                        "--type=json",
                        "-p",
                        json.dumps(patch),
                        "-o",
                        "json",
                    )
                    tool_policy_changed_spec = updated["spec"]
            print(
                json.dumps(
                    {
                        "stage": "native_provider_attached; starting credential-free MCP read"
                    }
                ),
                flush=True,
            )
            if getattr(args, 'gateway_mode', 'temporary') == 'persistent':
                from identity_demo_gateway_persistence import frontend_policy
                wait_authorizer(args, frontend_policy(args)['spec'])
            else:
                wait_authorizer(args, policy_changed_spec)
            if args.investigate_substitution:
                from native_subject_boundary import investigate

                result["subject_boundary_diagnostic"] = investigate(args, human)
                result["exact_subject_substitution_denied"] = result[
                    "subject_boundary_diagnostic"
                ]["substitution_rejected_with_permission_denied"]
                if args.require_substitution_denial:
                    checked(
                        "same_domain_subject_substitution_denied",
                        result["exact_subject_substitution_denied"],
                    )
            progress("verifying_native_read")
            time.sleep(2)
            from native_read_retry import initial_protected_read

            read_command = ["sandbox", "exec", "--name", SANDBOX, "--no-login-shell",
                            "--timeout", "90", "--no-tty", "--", "python", "-c",
                            flow.read_program(resource) if flow is not None else read_program(resource, tool)]
            def observe_read(value: dict, attempt: int) -> None:
                if value.get('read_passed') is not True:
                    from native_read_diagnostics import capture
                    observation = capture(args, kube)
                    result.setdefault('initial_read_diagnostics', []).append(observation)
                    private_write(output / (args.label + '.read-diagnostic-' + str(attempt) + '.private.json'), observation)

            read, recovery = initial_protected_read(
                lambda: execute(read_command, json_output=True),
                lambda count: progress("retrying_identity", {"native_read_retries": count}),
                observe=observe_read,
            )
            result["initial_read_recovery"] = recovery
            result["native_read"] = read
            if not read.get("read_passed") and getattr(args, "diagnose_native_grant", False):
                from native_grant_diagnostic import diagnose

                try:
                    result["failed_read_grant_diagnostic"] = diagnose(args, human)
                except Exception as error:
                    result["failed_read_grant_diagnostic"] = {
                        "failure_kind": type(error).__name__, "details_withheld": True,
                    }
            checked("actual_synthetic_read", read.get("read_passed") is True)
            if flow is not None:
                args.native_tool_schemas=read.get('published_tool_schemas',[])
                args.native_tools_list_observed=read.get('requested_tool_advertised') is True
                flow.initial_read_monotonic = time.monotonic()
                flow.runtime_profile = profile
                flow.issuer_admin = admin
                result["permission_flow"] = flow.accept(execute, resource, context)
                checked("live_permission_gate", result["permission_flow"]["passed"])
                result["native_exchange_proven"] = True
                result["sender_bound_native_read_proven"] = True
                result["downstream_contract_proven"] = True
            else:
                if backend is not None:
                    from native_audit import check as audit_check

                    result["native_audit"] = audit_check(backend, protected_run)
                checked(
                    "gateway_verified_human_and_workload",
                    policy_changed_spec["rules"]["authorization"][
                        "native-step4-identity"
                    ]["patternMatching"]["patterns"][0]["predicate"]
                    == predicate,
                )
                result["verified_claim_contract"] = {
                    "issuer_signature_audience_validated_by_gateway": True,
                    "exact_human_subject_workload_client_role_and_expiry_enforced": True,
                    "signed_final_token_lifetime_at_most_30_seconds_enforced": True,
                    "workload_client": WORKLOAD,
                    "final_resource": resource,
                    "intermediate_claims_inspected": False,
                    "raw_tokens_withheld": True,
                }
                if getattr(args, "check_sender_rejection", False):
                    from native_sender_acceptance import SenderAcceptance

                    result["sender_rejection"] = SenderAcceptance(
                        args, {**human, "access_token": login["access_token"]}
                    ).run()
                    result["sender_constraint_proven"] = (
                        result["sender_rejection"]["passed"] is True
                    )
                    result["copied_token_rejection_proven"] = result[
                        "sender_constraint_proven"
                    ]
                if args.check_renewal:
                    print(
                        json.dumps(
                            {"stage": "waiting_for_30_second_final_token_lifetime"}
                        ),
                        flush=True,
                    )
                    time.sleep(35)
                    renewed = execute(
                        [
                            "sandbox",
                            "exec",
                            "--name",
                            SANDBOX,
                            "--no-login-shell",
                            "--timeout",
                            "90",
                            "--no-tty",
                            "--",
                            "python",
                            "-c",
                            read_program(resource, tool),
                        ],
                        json_output=True,
                    )
                    result["read_after_final_lifetime"] = renewed
                    checked(
                        "native_read_after_configured_final_token_lifetime",
                        renewed.get("read_passed") is True,
                    )
                    result["renewal_limit"] = (
                        "Successful read after the configured 30-second final lifetime; certificate renewal and bound-token rotation remain unproven."
                    )
                if getattr(args, "check_key_rollover", False):
                    from native_key_rollover import check as rollover_check

                    result["native_key_rollover"] = rollover_check(
                        args, execute, human, resource, tool
                    )
                if getattr(args, "check_backend_rotation", False):
                    from native_backend_rotation import check as backend_rotation_check

                    result["backend_secret_rotation"] = backend_rotation_check(
                        backend, admin, execute, resource, tool
                    )
                if getattr(args, "check_run_binding", False):
                    from dataclasses import replace

                    for name, changed in (
                        ("cancelled", replace(protected_run, active=False)),
                        (
                            "expired",
                            replace(protected_run, expires_at=int(time.time()) - 1),
                        ),
                    ):
                        changed_spec = json.loads(json.dumps(policy_changed_spec))
                        changed_spec["rules"]["authorization"]["native-step4-run"] = (
                            run_authorization(
                                [changed], require_sender_binding=bound_sender
                            )
                        )
                        current = kube(
                            args,
                            "-n",
                            NAMESPACE,
                            "get",
                            "authpolicy",
                            frontend_policy,
                            "-o",
                            "json",
                        )
                        patch = [
                            {
                                "op": "test",
                                "path": "/metadata/uid",
                                "value": policy_before["metadata"]["uid"],
                            },
                            {
                                "op": "test",
                                "path": "/metadata/resourceVersion",
                                "value": current["metadata"]["resourceVersion"],
                            },
                            {
                                "op": "test",
                                "path": "/spec",
                                "value": policy_changed_spec,
                            },
                            {"op": "replace", "path": "/spec", "value": changed_spec},
                        ]
                        updated = kube(
                            args,
                            "-n",
                            NAMESPACE,
                            "patch",
                            "authpolicy",
                            frontend_policy,
                            "--type=json",
                            "-p",
                            json.dumps(patch),
                            "-o",
                            "json",
                        )
                        policy_changed_spec = updated["spec"]
                        wait_authorizer(args, policy_changed_spec)
                        denied = execute(
                            [
                                "sandbox",
                                "exec",
                                "--name",
                                SANDBOX,
                                "--no-login-shell",
                                "--timeout",
                                "90",
                                "--no-tty",
                                "--",
                                "python",
                                "-c",
                                read_program(resource, tool),
                            ],
                            json_output=True,
                        )
                        result[name + "_run_read"] = denied
                        checked(
                            name + "_run_denied",
                            denied.get("read_passed") is False
                            and bool(denied.get("events"))
                            and denied["events"][0]["http_status"] == 403,
                        )
                    # Restore active state before the separate wrong-user test.
                    current = kube(
                        args,
                        "-n",
                        NAMESPACE,
                        "get",
                        "authpolicy",
                        frontend_policy,
                        "-o",
                        "json",
                    )
                    changed_spec = json.loads(json.dumps(policy_changed_spec))
                    changed_spec["rules"]["authorization"]["native-step4-run"] = (
                        run_authorization(
                            [protected_run], require_sender_binding=bound_sender
                        )
                    )
                    patch = [
                        {
                            "op": "test",
                            "path": "/metadata/uid",
                            "value": policy_before["metadata"]["uid"],
                        },
                        {
                            "op": "test",
                            "path": "/metadata/resourceVersion",
                            "value": current["metadata"]["resourceVersion"],
                        },
                        {"op": "test", "path": "/spec", "value": policy_changed_spec},
                        {"op": "replace", "path": "/spec", "value": changed_spec},
                    ]
                    updated = kube(
                        args,
                        "-n",
                        NAMESPACE,
                        "patch",
                        "authpolicy",
                        frontend_policy,
                        "--type=json",
                        "-p",
                        json.dumps(patch),
                        "-o",
                        "json",
                    )
                    policy_changed_spec = updated["spec"]
                    wait_authorizer(args, policy_changed_spec)
                    result["run_binding_component_proven"] = True
                    result["run_binding_component_limit"] = (
                        "Native read/cancellation/expiry only; sender binding, distinct simultaneous runs and complete submission flow remain unproven."
                    )
                other = components.login("viewer", credentials["viewer"], client_id=UI)
                other_claims = components.verify(
                    other["access_token"], GATEWAY, issuer=components.ISSUER
                )
                other_identity = components.verify(
                    other["id_token"], UI, issuer=components.ISSUER
                )
                checked(
                    "distinct_viewer_pkce_identity",
                    other_claims["sub"] != human["sub"]
                    and other_identity.get("nonce") == other["expected_nonce"]
                    and other_claims.get("realm_access", {}).get("roles") == ["viewer"],
                )
                if backend is not None:
                    from native_sender_acceptance import SenderAcceptance

                    analyst_args = argparse.Namespace(
                        **{**vars(args), "label": args.label + "-analyst-session"}
                    )
                    analyst_sender = SenderAcceptance(analyst_args, human)
                    viewer_leaf = analyst_sender.certificate("session")
                    analyst_token, _ = analyst_sender.final(viewer_leaf)
                    analyst_session = analyst_sender.initialize_session(
                        "analyst_for_viewer_test", analyst_token, viewer_leaf
                    )
                execute(
                    [
                        "provider",
                        "update",
                        PREFIX,
                        "--credential",
                        "subject_token",
                        "--credential-expires-at",
                        "subject_token=" + str(other_claims["exp"] * 1000),
                    ],
                    subject=other["access_token"],
                )
                # Negative credentials need not become Ready. Verify the effective
                # signed viewer grant first, then require an actual gateway denial.
                if backend is not None:
                    from native_sender_acceptance import SenderAcceptance

                    viewer_args = argparse.Namespace(
                        **{**vars(args), "label": args.label + "-viewer"}
                    )
                    viewer_sender = SenderAcceptance(viewer_args, other_claims)
                    viewer_token, _ = viewer_sender.final(viewer_leaf)
                    tool_denial = viewer_sender.gateway(
                        "viewer_actual_tool_call",
                        viewer_token,
                        viewer_leaf,
                        tool_call=True,
                        session_headers=analyst_session,
                    )
                    result["viewer_tool_boundary"] = tool_denial
                    checked(
                        "viewer_tool_call_denied_before_backend_initialization",
                        tool_denial.get("http_status") == 403,
                    )
                denied = execute(
                    [
                        "sandbox",
                        "exec",
                        "--name",
                        SANDBOX,
                        "--no-login-shell",
                        "--timeout",
                        "90",
                        "--no-tty",
                        "--",
                        "python",
                        "-c",
                        read_program(resource, tool),
                    ],
                    json_output=True,
                )
                result["substituted_user_read"] = denied
                checked(
                    "different_user_cannot_use_analyst_run",
                    denied.get("read_passed") is False
                    and bool(denied.get("events"))
                    and denied["events"][0]["http_status"] in (401, 403),
                )
                result["native_exchange_proven"] = True
                result["sender_bound_native_read_proven"] = bound_sender
                result["downstream_contract_proven"] = bool(protected_backend)
                result.setdefault("copied_token_rejection_proven", False)
                if getattr(args, "retain_run_retirement", False):
                    from native_run_lifecycle import check as lifecycle_check

                    result["retained_lifecycle"], policy_changed_spec = lifecycle_check(
                        args,
                        execute,
                        human,
                        login,
                        protected_run,
                        frontend_policy,
                        policy_before,
                        policy_changed_spec,
                        backend,
                        provider_id,
                    )
                    attached = False
        except Exception as error:
            import traceback

            private_write(
                output / (args.label + ".failure.private.json"),
                {
                    "failure_kind": type(error).__name__,
                    "traceback": traceback.format_exc(),
                },
            )
            result["errors"].append(
                {
                    "failure_kind": type(error).__name__,
                    "command_number": getattr(error, "command_number", None),
                    "command_exit_code": getattr(error, "command_exit_code", None),
                    "details_withheld": True,
                }
            )
        finally:
            try:
                progress("restoring_environment")
            except Exception:
                pass  # Display transport failure must never prevent native cleanup.
            if flow is not None:
                try:
                    flow.close()
                    result["driver_run_closed"] = True
                except Exception as error:
                    result["errors"].append(
                        {
                            "stage": "close_driver_run",
                            "failure_kind": type(error).__name__,
                        }
                    )
            if backend is not None:
                try:
                    backend.cleanup()
                    result["protected_backend_resources_restored"] = True
                except Exception as error:
                    result["errors"].append(
                        {
                            "stage": "cleanup_backend",
                            "failure_kind": type(error).__name__,
                        }
                    )
            if tool_policy_changed_spec is not None:
                try:
                    current = kube(
                        args,
                        "-n",
                        NAMESPACE,
                        "get",
                        "authpolicy",
                        "fixture-mcp-tools-auth",
                        "-o",
                        "json",
                    )
                    patch = [
                        {
                            "op": "test",
                            "path": "/metadata/uid",
                            "value": tool_policy_before["metadata"]["uid"],
                        },
                        {
                            "op": "test",
                            "path": "/metadata/resourceVersion",
                            "value": current["metadata"]["resourceVersion"],
                        },
                        {
                            "op": "test",
                            "path": "/spec",
                            "value": tool_policy_changed_spec,
                        },
                        {
                            "op": "replace",
                            "path": "/spec",
                            "value": tool_policy_before["spec"],
                        },
                    ]
                    kube(
                        args,
                        "-n",
                        NAMESPACE,
                        "patch",
                        "authpolicy",
                        "fixture-mcp-tools-auth",
                        "--type=json",
                        "-p",
                        json.dumps(patch),
                        "-o",
                        "json",
                    )
                    result["tools_policy_restored"] = True
                except Exception as error:
                    result["errors"].append(
                        {
                            "stage": "restore_tools_policy",
                            "failure_kind": type(error).__name__,
                        }
                    )
            if policy_changed_spec is not None:
                try:
                    current = kube(
                        args,
                        "-n",
                        NAMESPACE,
                        "get",
                        "authpolicy",
                        frontend_policy,
                        "-o",
                        "json",
                    )
                    patch = [
                        {
                            "op": "test",
                            "path": "/metadata/uid",
                            "value": policy_before["metadata"]["uid"],
                        },
                        {
                            "op": "test",
                            "path": "/metadata/resourceVersion",
                            "value": current["metadata"]["resourceVersion"],
                        },
                        {"op": "test", "path": "/spec", "value": policy_changed_spec},
                        {
                            "op": "replace",
                            "path": "/spec",
                            "value": policy_before["spec"],
                        },
                    ]
                    kube(
                        args,
                        "-n",
                        NAMESPACE,
                        "patch",
                        "authpolicy",
                        frontend_policy,
                        "--type=json",
                        "-p",
                        json.dumps(patch),
                        "-o",
                        "json",
                    )
                    result["policy_restored"] = True
                except Exception as error:
                    result["errors"].append(
                        {
                            "stage": "restore_policy",
                            "failure_kind": type(error).__name__,
                        }
                    )
            native_cleanup_allowed = not provider_created
            if provider_created:
                try:
                    current = inventory(
                        execute(["provider", "list", "-o", "json"], json_output=True),
                        "providers",
                    )
                    require_native_provider_id(current, provider_id, PREFIX)
                    native_cleanup_allowed = True
                except Exception as error:
                    result["errors"].append(
                        {
                            "stage": "cleanup_native_ownership",
                            "failure_kind": type(error).__name__,
                        }
                    )
            for enabled, words in (
                (
                    attached,
                    [
                        "sandbox",
                        "provider",
                        "detach",
                        SANDBOX,
                        PREFIX,
                        "--wait",
                        "--timeout",
                        "30",
                    ],
                ),
                (provider_created, ["provider", "delete", PREFIX]),
                (profile_created, ["provider", "profile", "delete", PREFIX]),
            ):
                if enabled and native_cleanup_allowed:
                    try:
                        execute(words)
                    except Exception as error:
                        result["errors"].append(
                            {
                                "stage": "cleanup_native",
                                "command": words[:3],
                                "failure_kind": type(error).__name__,
                            }
                        )
            for name, identifier in reversed(created_clients):
                try:
                    current = admin("/clients/" + identifier)
                    if (
                        current["clientId"] != name
                        or current.get("attributes", {}).get("identity-demo-owner")
                        != active_profile().owner
                        or current.get("attributes", {}).get("identity-demo-experiment")
                        != EXPERIMENT
                    ):
                        raise ValueError("Issuer client cleanup ownership mismatch")
                    admin("/clients/" + identifier, "DELETE")
                except Exception as error:
                    result["errors"].append(
                        {
                            "stage": "cleanup_client",
                            "failure_kind": type(error).__name__,
                        }
                    )
            if issuer_provider_created:
                try:
                    current = admin("/identity-provider/instances/" + PREFIX)
                    if (
                        current.get("config", {}).get("identity-demo-experiment")
                        != EXPERIMENT
                    ):
                        raise ValueError("Issuer provider cleanup ownership mismatch")
                    admin("/identity-provider/instances/" + PREFIX, "DELETE")
                except Exception as error:
                    result["errors"].append(
                        {
                            "stage": "cleanup_issuer_provider",
                            "failure_kind": type(error).__name__,
                        }
                    )
            try:
                clients_after = admin("/clients")
                private_write(
                    output / (args.label + ".issuer-clients-after.private.json"),
                    clients_after,
                )
                checked(
                    "issuer_clients_preserved",
                    issuer_probe.fingerprint(clients_after) == before_hash,
                )
                checked(
                    "issuer_providers_preserved",
                    admin("/identity-provider/instances") == provider_inventory,
                )
                if providers_before is not None:
                    checked(
                        "native_providers_preserved",
                        inventory(
                            execute(
                                ["provider", "list", "-o", "json"], json_output=True
                            ),
                            "providers",
                        )
                        == providers_before,
                    )
                if profiles_before is not None:
                    checked(
                        "native_profiles_preserved",
                        inventory(
                            execute(
                                ["provider", "profile", "list", "-o", "json"],
                                json_output=True,
                            ),
                            "profiles",
                        )
                        == profiles_before,
                    )
            except Exception as error:
                result["errors"].append(
                    {"stage": "preservation", "failure_kind": type(error).__name__}
                )
    preservation = {case["case"] for case in result["cases"] if case["passed"]}
    result["cleanup_verified"] = (
        {"issuer_clients_preserved", "issuer_providers_preserved", "native_providers_preserved",
         "native_profiles_preserved"}.issubset(preservation)
        and (flow is None or result.get("driver_run_closed") is True)
        and (backend is None or result.get("protected_backend_resources_restored") is True)
        and (policy_changed_spec is None or result.get("policy_restored") is True)
        and (tool_policy_changed_spec is None or result.get("tools_policy_restored") is True)
        and not any(error.get("stage") for error in result["errors"]))
    result["passed"] = result["native_exchange_proven"] and not result["errors"]
    private_write(output / (args.label + ".summary.json"), result)
    return result


def driver_flow(args: argparse.Namespace) -> object | None:
    """Select an explicit driver gate without silently ignoring security checks."""
    selection = getattr(args, "driver_check", "permission")
    if not args.driver_credentials_file:
        if selection != "permission":
            raise ValueError("Read-security acceptance requires driver credentials")
        return None
    from permission_flow import PermissionFlow

    flow_type = PermissionFlow
    if selection in ("read-security", "native-renewal"):
        if args.enable_create or args.demo_user != "analyst":
            raise ValueError("Read-only acceptance requires analyst and no create")
        if selection == "read-security":
            from read_security_flow import ReadSecurityFlow

            flow_type = ReadSecurityFlow
        else:
            from native_renewal_flow import NativeRenewalFlow

            flow_type = NativeRenewalFlow
    return flow_type(args, private_path(str(args.driver_credentials_file)), username=args.demo_user)


def main() -> None:
    """Expose only sanitized evidence and categories on unexpected failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "kubeconfig",
        "expected-server",
        "credentials-file",
        "cli",
        "cli-config-dir",
        "label",
    ):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--context-file", help="Private, verified fresh Step 5–6 execution context"
    )
    parser.add_argument(
        "--driver-credentials-file", type=Path,
        help="Use the authenticated driver approval flow with privately held coordination credentials",
    )
    parser.add_argument("--demo-user", choices=("analyst", "viewer"), default="analyst")
    parser.add_argument("--driver-check", choices=("permission", "read-security", "native-renewal"), default="permission",
                        help="Select existing driver permission or read/replay/renewal/revocation acceptance")
    parser.add_argument(
        "--enable-create", action="store_true",
        help="Exercise one approved create and duplicate; requires the driver flow and separately enabled protected adapter",
    )
    parser.add_argument("--check-renewal", action="store_true")
    parser.add_argument(
        "--check-sender-rejection",
        action="store_true",
        help="Exercise actual native SVID leaf renewal and copied-token controls through owned loopback tunnels",
    )
    parser.add_argument(
        "--check-key-rollover",
        action="store_true",
        help="Publish and activate one owned SPIRE JWT authority and repeat the native protected read without issuer restart",
    )
    parser.add_argument(
        "--check-backend-rotation",
        action="store_true",
        help="Rotate and restore only the owned gateway service secret and prove native failure/recovery",
    )
    parser.add_argument(
        "--retain-run-retirement",
        action="store_true",
        help="Prove native expiry and detachment and retain a cancelled run tombstone; this identity cannot be reused",
    )
    parser.add_argument(
        "--upstream-development-issuer",
        action="store_true",
        help="Use only the owned pinned upstream issuer; temporarily switch and restore the owned frontend policy",
    )
    parser.add_argument(
        "--bound-sender-listener",
        action="store_true",
        help="Use only the owned internal mTLS listener; requires strict run checks and pinned upstream issuer",
    )
    parser.add_argument(
        "--protected-backend-catalog-credential-file",
        help="Add scoped-service-token protected adapter delivery to the native bound read; private catalog credential required",
    )
    parser.add_argument('--reuse-management-session', action='store_true',
                        help='Reuse only a verified owned tunnel and a still-valid operator session')
    parser.add_argument('--gateway-mode', choices=('temporary', 'persistent'), default='temporary',
                        help='Use the existing receipt-verified persistent gateway without replacing its configuration')
    parser.add_argument('--gateway-receipt', help='Private exact persistent gateway installation receipt')
    parser.add_argument("--investigate-substitution", action="store_true")
    parser.add_argument(
        "--require-substitution-denial",
        action="store_true",
        help="Fail the probe unless the positive control passes and substitution receives gRPC 7 with no reply message",
    )
    parser.add_argument(
        "--check-run-binding",
        action="store_true",
        help="Diagnose protected run/cancellation/expiry using the existing authorizer; does not prove G6",
    )
    flow = None
    try:
        args = parser.parse_args()
        if args.gateway_mode == 'persistent':
            if not args.gateway_receipt or not args.driver_credentials_file:
                raise ValueError('Persistent CLI requires gateway receipt and authenticated driver flow')
            private_path(args.gateway_receipt)
        elif args.gateway_receipt:
            raise ValueError('Gateway receipt requires explicit persistent mode')
        flow = driver_flow(args)
        if flow is not None:
            args.permission_flow = flow
        result = run(args)
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result["passed"] else 1)
    except Exception as error:
        print(
            json.dumps(
                {
                    "passed": False,
                    "failure_kind": type(error).__name__,
                    "details_withheld": True,
                }
            )
        )
        raise SystemExit(1) from None
    finally:
        transport = getattr(flow, 'operator_transport', None)
        if transport:
            transport.close()


if __name__ == "__main__":
    main()
