#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Read-only, credential-free MCP Gateway introduction during an active rehearsal.

This is a CLI/API management view, not an invented gateway dashboard. The
normal closed baseline has no temporary server registration; capture this
while rehearse_walkthrough.py is running. Never dump Secrets or raw policies.
"""

import argparse
import inspect
import json
import os
from pathlib import Path
import subprocess

from identity_demo_runtime_cli import private_path

from identity_demo_runtime import guard
from deployment_profile import active_profile
import probe_native_exchange as native


def project_schemas(tools):
    """Project only fixed tool names/argument shapes, never descriptions or data."""
    allowed={'run_id','action_id','project','issue_key','jql','issue_type','summary','description','labels'}
    expected={'readJiraProject','createJiraIssue'}
    if not isinstance(tools,list) or len(tools)>128:raise ValueError('Bounded tools list required')
    safe=[]
    for tool in tools:
        name=tool.get('name','').removeprefix('step56_jira_')
        if name not in expected:continue
        schema=tool.get('inputSchema',{});properties=schema.get('properties',{});required=schema.get('required',[])
        if not isinstance(properties,dict) or set(properties)-allowed or not isinstance(required,list) or set(required)-set(properties):
            raise ValueError('Expected public tool arguments required')
        arguments=[]
        for key,value in properties.items():
            kind=value.get('type')
            arguments.append({'name':key,'type':kind if kind in ('string','object','array','integer','number','boolean','null') else 'schema-defined',
                              'required':key in required})
        safe.append({'name':name,'arguments':arguments})
    if len(safe)!=2 or {v['name'] for v in safe}!=expected:raise ValueError('Both exact published tools required')
    return safe


def overview(args: argparse.Namespace) -> dict:
    """Select public configuration/status fields from exact owned resources."""
    guard(args)

    def read(kind: str, name: str) -> dict:
        value = native.kube(args, "get", kind, name, "-n", native.NAMESPACE, "-o", "json")
        assert value["metadata"]["labels"]["identity-demo-owner"] == active_profile().owner
        return value

    gateway = read("gateway", "fixture-mcp")
    registration = read("mcpserverregistrations.mcp.kuadrant.io", "fixture-step4-read-route")
    route = read("httproute", "fixture-step4-read-route")
    identity = read("authconfig", "fixture-step56-live-identity")
    action = read("authconfig", "fixture-step4-read-route")
    return {
        "scope": "Actual owned MCP Gateway management configuration; runtime outcomes are separate.",
        "gateway": gateway["metadata"]["name"],
        "class": gateway["spec"]["gatewayClassName"],
        "registered_server": registration["metadata"]["name"],
        "tool_prefix": registration["spec"]["prefix"],
        "discovered_tools": registration.get("status", {}).get("discoveredTools"),
        "registration_ready": any(c.get("type") == "Ready" and c.get("status") == "True"
            for c in registration.get("status", {}).get("conditions", [])),
        "backend_services": [r["name"] for rule in route["spec"]["rules"] for r in rule.get("backendRefs", [])],
        "verified_user_and_workload": "keycloak" in identity["spec"].get("authentication", {}),
        "live_run_identity_check": "driver-decision" in identity["spec"].get("metadata", {}),
        "actual_arguments_and_approval_check": "live-action" in action["spec"].get("authorization", {}),
        "scoped_adapter_service_token_delivery": "adapter-token" in action["spec"].get("metadata", {}),
        "secret_values_or_tokens_in_view": False,
        "cluster_changed": False,
    }


def main() -> None:
    """Fail deliberately outside the temporary active walkthrough configuration."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("kubeconfig", "expected-server", "credentials-file"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    args.namespace = native.NAMESPACE
    try:
        print(json.dumps(overview(args), indent=2))
    except Exception as error:
        print(json.dumps({"active_management_view_available": False,
            "failure_kind": type(error).__name__, "details_withheld": True}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()


def catalog_schemas(args: argparse.Namespace) -> dict:
    """Inspect only published tool schema shapes using catalog-only credentials."""
    if os.environ.get('IDENTITY_DEMO_RUNTIME')=='cluster':
        # The real, credential-free native client already performed tools/list.
        # Do not grant or attempt runtime Pod exec for a presentation view.
        values=getattr(args,'native_tool_schemas',[])
        if (getattr(args,'native_tools_list_observed',False) is not True or len(values)!=2
                or {v['name'] for v in values}!={'readJiraProject','createJiraIssue'}):
            raise ValueError('Actual native tool discovery evidence required')
        return {'published_tool_schemas':values,'catalog_only_tools_list':False,'native_tools_list_observed':True}
    path = private_path(args.protected_backend_catalog_credential_file)
    credential = json.loads(Path(path).read_text())
    program = 'import asyncio,json,ssl,sys,httpx\n'+inspect.getsource(project_schemas)+'''\n
async def run():
 credential=json.load(sys.stdin)
 async with httpx.AsyncClient(verify=ssl.create_default_context(cafile='/service-ca/service-ca.crt'),timeout=8,follow_redirects=False,trust_env=False) as client:
  response=await client.post(CATALOG_ENDPOINT,headers={'Authorization':'Bearer '+credential['token'],'Accept':'application/json,text/event-stream','Content-Type':'application/json'},json={'jsonrpc':'2.0','id':1,'method':'tools/list'})
  assert response.status_code==200
  tools=response.json()['result']['tools'];assert {x['name'] for x in tools}=={'readJiraProject','createJiraIssue'}
  safe=project_schemas(tools)
  print(json.dumps({'published_tool_schemas':safe,'catalog_only_tools_list':True}))
asyncio.run(run())'''
    endpoint = "https://" + active_profile().service_host("fixture-protected-adapter") + ":8443/mcp"
    program = program.replace("CATALOG_ENDPOINT", repr(endpoint))
    result = subprocess.run(["oc", "--kubeconfig", args.kubeconfig, "-n", native.NAMESPACE,
        "exec", "-i", "deployment/fixture-protected-adapter", "-c", "adapter-https", "--",
        "python", "-c", program], input=json.dumps({"token": credential["token"]}),
        capture_output=True, text=True, timeout=30)
    native.private_write(args.output_dir / (args.label + ".gateway-catalog.private.json"), {
        "exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
    if result.returncode:
        raise RuntimeError("Published schema capture failed; details withheld")
    return json.loads(result.stdout)
