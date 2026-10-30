# SPDX-License-Identifier: Apache-2.0
"""Real browser submission/consent and bounded native sandbox acceptance probes.

Use only the already approved private credentials and owned execution context.
This first gate does not claim the complete two-user/workload or write matrix.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
from html import unescape
from http.cookiejar import CookieJar
import json
from pathlib import Path
import subprocess
from urllib.error import HTTPError
from urllib.parse import urlencode, urlparse
from urllib.request import HTTPCookieProcessor, Request, build_opener

import probe_native_exchange as native
from identity_demo_action_policy import DRIVER
from identity_demo_keycloak_upstream import BASE
from identity_demo_fixture_http import LoginForm, NoRedirect
from deployment_profile import active_profile


class PermissionFlow:
    """Retain one real browser session and its immutable controlled execution run."""

    workflow = "cve"
    project = "TEST"
    submission = {"cve": "CVE-2099-0001"}
    start_button = "Start assessment"

    def proposal_program(self) -> str:
        """Return the existing CVE fixture; reuse workflows override only the proposal."""
        fixture = Path(__file__).with_name("cve_runtime_fixture.py").read_text()
        return (
            "ns={'__name__':'frozen_fixture'};exec("
            + repr(fixture)
            + ",ns);import asyncio,json;print(json.dumps(asyncio.run(ns['assessment_fixture']())))"
        )

    def validate_report(self, report: dict) -> None:
        """Reject invalid CVE handoff evidence even with interpreter optimization."""
        if (report.get('assessment_preserved_after_local_denial') is not True
                or report.get('proposed_create', {}).get('project') != self.project):
            raise ValueError('Preserved assessment and exact project required')

    def __init__(
        self, args: argparse.Namespace, secrets_file: Path, username: str = "analyst"
    ) -> None:
        self.args, self.username = args, username
        if username not in ("analyst", "viewer"):
            raise ValueError("Approved demo user required")
        self.passwords = json.loads(Path(args.credentials_file).read_text())
        self.keys = json.loads(secrets_file.read_text())
        self.client = build_opener(HTTPCookieProcessor(CookieJar()), NoRedirect())
        self.run_id = self.user = self.csrf = ""
        self.proposal: dict = {}
        self.results: list[dict] = []
        from identity_demo_control_transport import configured_transport
        self.operator_transport = configured_transport()

    def http(
        self,
        url: str,
        fields: dict | None = None,
        value: dict | None = None,
        operator: bool = False,
    ) -> tuple[int, object, bytes]:
        """Call fixed HTTPS driver/issuer URLs; never emit token-bearing responses."""
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.hostname not in (
            urlparse(DRIVER).hostname,
            urlparse(BASE).hostname,
        ):
            raise ValueError("Approved HTTPS target required")
        headers = {"Origin": DRIVER}
        data = urlencode(fields).encode() if fields is not None else None
        if value is not None:
            data = json.dumps(value).encode()
            headers["Content-Type"] = "application/json"
        if operator:
            if getattr(self, 'operator_transport', None):
                if not url.startswith(DRIVER + '/internal/operator/') or fields is not None:
                    raise ValueError('Exact JSON operator target required')
                return self.operator_transport.request(url.removeprefix(DRIVER),
                                                       self.keys['operator_secret'], data)
            headers["Authorization"] = "Bearer " + self.keys["operator_secret"]
        try:
            response = self.client.open(
                Request(url, data=data, headers=headers), timeout=12
            )
        except HTTPError as error:
            response = error
        with response:
            body = response.read(131_073)
            if len(body) > 131_072:
                raise ValueError("Bounded driver response required")
            return response.status, response.headers, body

    def authenticate(self) -> None:
        """Establish a real browser session without allocating an execution run."""
        status, headers, _ = self.http(DRIVER + "/login")
        assert status == 302
        status, headers, body = self.http(headers["Location"])
        if status == 200:
            form = LoginForm()
            form.feed(body.decode())
            status, headers, _ = self.http(
                form.action,
                fields={
                    **form.fields,
                    "username": self.username,
                    "password": self.passwords[self.username],
                    "credentialId": "",
                },
            )
        assert status == 302 and headers["Location"].startswith(DRIVER + "/callback?")
        status, _, _ = self.http(headers["Location"])
        assert status == 303
        status, _, body = self.http(DRIVER + "/")
        assert status == 200
        form = LoginForm()
        form.feed(body.decode())
        self.csrf = form.fields["csrf"]

    def login(self, context: object) -> dict:
        """Authenticate, submit a CVE and release credentials only to coordination."""
        self.authenticate()
        status, headers, _ = self.http(
            DRIVER + "/submit",
            fields={"csrf": self.csrf, "role": context.role, **self.submission},
        )
        assert status == 303 and headers["Location"].startswith("/runs/")
        self.run_id = headers["Location"].split("/")[-1]
        status, _, body = self.http(
            DRIVER + "/internal/operator/credentials/" + self.run_id, operator=True
        )
        assert status == 200
        credential = json.loads(body)
        assert credential["workload"] == context.workload
        self.user = credential["user"]
        native.private_write(
            self.args.output_dir / (self.args.label + ".driver-association.json"),
            {
                "run_id": self.run_id,
                "user": self.user,
                "workload": context.workload,
                "real_browser_login": True,
                "expires_at": credential["expires_at"],
            },
        )
        return {"access_token": credential["access_token"]}

    def read_program(self, resource: str) -> str:
        """Run a credential-free own-project read in the actual CVE image."""
        return native.read_program(
            resource,
            "step56_jira_readJiraProject",
            {"run_id": self.run_id, "project": self.project},
            "project_scope",
        )

    def backend_count(self) -> int:
        """Read authoritative backend state using the trusted adapter's held credential."""
        import os
        if os.environ.get('IDENTITY_DEMO_RUNTIME') == 'cluster':
            result = self.control.request('backend-state/' + self.run_id)
            if type(result.get('total')) is not int or result['total'] < 0:
                raise ValueError('Verified run-scoped backend count required')
            return result['total']
        program = """import asyncio,json,os,ssl,httpx
async def run():
 async with httpx.AsyncClient(verify=ssl.create_default_context(cafile='/service-ca/service-ca.crt'),timeout=8,follow_redirects=False,trust_env=False) as client:
  response=await client.get('https://fixture-jira.demo-core.svc.cluster.local:8080/rest/api/2/search',params={'jql':'project = TEST','maxResults':1},auth=httpx.BasicAuth(os.environ['JIRA_USER'],os.environ['JIRA_TOKEN']))
  assert response.status_code==200
  print(json.dumps({'total':response.json()['total']}))
asyncio.run(run())""".replace(
            'fixture-jira.demo-core.svc.cluster.local', active_profile().service_host('fixture-jira')
        ).replace("'project = TEST'", repr("project = " + self.project))
        result = subprocess.run(
            [
                "oc",
                "--kubeconfig",
                self.args.kubeconfig,
                "-n",
                native.NAMESPACE,
                "exec",
                "deployment/fixture-protected-adapter",
                "-c",
                "adapter-https",
                "--",
                "python",
                "-c",
                program,
            ],
            capture_output=True,
            text=True,
            timeout=25,
        )
        if result.returncode:
            raise RuntimeError("Backend outcome read failed; details withheld")
        return json.loads(result.stdout)["total"]

    def generate_report(self, execute: object, resource: str, context: object) -> dict:
        """Produce content through the existing sandbox; approval remains separate."""
        program = self.proposal_program()
        report = execute(
            [
                "sandbox",
                "exec",
                "--name",
                context.sandbox_name,
                "--no-login-shell",
                "--timeout",
                "90",
                "--no-tty",
                "--",
                "python",
                "-c",
                program,
            ],
            json_output=True,
        )
        return report

    def accept(self, execute: object, resource: str, context: object) -> dict:
        """Prove consent/permission controls and, when enabled, one approved write."""
        before = self.backend_count()
        writes = bool(getattr(self.args, "enable_create", False))
        created_key = ""
        self.progress("assessment_running")
        report = self.generate_report(execute, resource, context)
        self.validate_report(report)
        status, _, body = self.http(
            DRIVER + "/internal/operator/report",
            operator=True,
            value={
                "run_id": self.run_id,
                "user": self.user,
                "workload": context.workload,
                "assessment": report["assessment"],
                "arguments": report["proposed_create"],
            },
        )
        assert status == 200
        self.proposal = json.loads(body)
        arguments = {
            "run_id": self.run_id,
            "action_id": self.proposal["action_id"],
            **self.proposal["arguments"],
        }

        def call(name: str, args: dict, allowed: bool) -> None:
            nonlocal created_key
            result = execute(
                [
                    "sandbox",
                    "exec",
                    "--name",
                    context.sandbox_name,
                    "--no-login-shell",
                    "--timeout",
                    "90",
                    "--no-tty",
                    "--",
                    "python",
                    "-c",
                    native.read_program(
                        resource,
                        "step56_jira_createJiraIssue",
                        args,
                        "key" if writes else "probe_passed",
                    ),
                ],
                json_output=True,
            )
            native.private_write(
                self.args.output_dir
                / (self.args.label + ".permission-" + name + ".private.json"),
                result,
            )
            if allowed:
                assert result["read_passed"] is True
                if writes:
                    actual = result["verified_tool_result"]
                    if name == "approved_create":
                        assert actual["duplicate"] is False
                        created_key = actual["key"]
                    else:
                        assert name == "successful_duplicate"
                        assert (
                            actual["duplicate"] is True and actual["key"] == created_key
                        )
            else:
                expected = {
                    "missing_approval": "action_proposed",
                    "changed_arguments": "action_binding",
                    "unauthorized_project": "project_permission",
                    "wrong_run": "run_binding",
                    "approved_user_permission_denied": "user_permission",
                    "approved_workload_permission_denied": "workload_permission",
                }[name]
                assert result["read_passed"] is False and any(
                    e["method"] == "tools/call"
                    and e["http_status"] == 403
                    and e.get("denial_reason") == expected
                    for e in result["events"]
                )
            expected = before + int(bool(created_key))
            assert self.backend_count() == expected
            self.results.append(
                {
                    "case": name,
                    "passed": True,
                    "backend_unchanged": not (writes and name == "approved_create"),
                    "backend_delta": expected - before,
                }
            )

        permission_denied = self.username == "viewer" or context.role == "reader"
        presentation_only = bool(getattr(self.args, "presentation_only", False))
        if not permission_denied and not presentation_only:
            call("missing_approval", arguments, False)
        self.approve_proposal(report)
        self.progress("protected_execution")
        if permission_denied:
            call(
                "approved_user_permission_denied"
                if self.username == "viewer"
                else "approved_workload_permission_denied",
                arguments,
                False,
            )
        else:
            call(
                "approved_create" if writes else "approved_disabled_create",
                arguments,
                True,
            )
            if writes:
                if not presentation_only:
                    call("successful_duplicate", arguments, True)
                outcome = self.verify_created_outcome(created_key, context.workload)
                native.private_write(self.args.output_dir / (self.args.label + ".created-outcome.summary.json"), outcome)
            if not presentation_only:
                changed = deepcopy(arguments)
                changed["description"] += " Changed after consent."
                call("changed_arguments", changed, False)
                changed = deepcopy(arguments)
                changed["project"] = "OTHER"
                call("unauthorized_project", changed, False)
                changed = deepcopy(arguments)
                changed["run_id"] = "f" * 32
                call("wrong_run", changed, False)
        if not presentation_only:
            outside = execute(
                [
                    "sandbox",
                    "exec",
                    "--name",
                    context.sandbox_name,
                    "--no-login-shell",
                    "--timeout",
                    "90",
                    "--no-tty",
                    "--",
                    "python",
                    "-c",
                    native.read_program(
                        resource,
                        "step56_jira_readJiraProject",
                        {"run_id": self.run_id, "project": "OTHER"},
                        "project_scope",
                    ),
                ],
                json_output=True,
            )
            assert outside["read_passed"] is False and any(
                e["method"] == "tools/call"
                and e["http_status"] == 403
                and e.get("denial_reason") == "project_permission"
                for e in outside["events"]
            )
            self.results.append(
                {
                    "case": "unauthorized_project_read",
                    "passed": True,
                    "backend_unchanged": self.backend_count()
                    == before + int(bool(created_key)),
                }
            )
            self.close()
            denied = execute(
                [
                    "sandbox",
                    "exec",
                    "--name",
                    context.sandbox_name,
                    "--no-login-shell",
                    "--timeout",
                    "90",
                    "--no-tty",
                    "--",
                    "python",
                    "-c",
                    self.read_program(resource),
                ],
                json_output=True,
            )
            assert (
                denied["read_passed"] is False and denied["events"][0]["http_status"] == 403
            )
            status, _, retained = self.http(DRIVER + "/runs/" + self.run_id)
            assert status == 200 and report["assessment"] in unescape(retained.decode())
            self.results.append(
                {
                    "case": "cancellation_and_assessment_retention",
                    "passed": True,
                    "backend_unchanged": self.backend_count()
                    == before + int(bool(created_key)),
                }
            )
        else:
            self.close()
        after = self.backend_count()
        self.progress("outcome_verified", {"backend_before": before, "backend_after": after,
            **({"verified_issue_key": created_key, "backend_fields_match_approval": True} if created_key else {})})
        return {
            "passed": True,
            "cases": self.results,
            "writes_enabled": writes,
            "verified_issue_key": created_key or None,
            "backend_before": before,
            "backend_after": after,
            "complete_two_user_workload_matrix": False,
            "username": self.username,
            "workload_role": context.role,
            "workflow": self.workflow,
            "project": self.project,
            "valid_approval_supplied_for_permission_comparison": permission_denied,
        }

    def progress(self, stage: str, evidence: dict | None = None) -> None:
        """Optional trusted console hook; acceptance execution has no display side effects."""

    def approve_proposal(self, report: dict) -> None:
        """Keep the original authenticated approval flow overridable by a human-driven coordinator."""
        status, _, displayed = self.http(DRIVER + "/runs/" + self.run_id)
        assert status == 200 and report["assessment"] in unescape(displayed.decode())
        assert self.proposal["digest"] in displayed.decode()
        status, _, _ = self.http(
            DRIVER + "/runs/" + self.run_id + "/approve",
            fields={
                "csrf": self.csrf,
                "action": self.proposal["action_id"],
                "digest": self.proposal["digest"],
            },
        )
        assert status == 303


    def verify_created_outcome(self, key: str, workload: str) -> dict:
        """Independently match Jira fields and the durable attributed action/audit."""
        import os
        if os.environ.get('IDENTITY_DEMO_RUNTIME') == 'cluster':
            result = self.control.request('backend-state/' + self.run_id).get('outcome')
            if (not isinstance(result, dict) or result.get('verified_issue_key') != key
                    or result.get('workload') != workload or result.get('user') != self.user
                    or result.get('project') != self.project
                    or result.get('action_id') != self.proposal['action_id']
                    or result.get('digest') != self.proposal['digest']):
                raise ValueError('Verified run/action/approval backend outcome required')
            return result
        backend = """import asyncio,json,os,ssl,httpx
async def verify():
 async with httpx.AsyncClient(verify=ssl.create_default_context(cafile='/service-ca/service-ca.crt'),timeout=8,follow_redirects=False,trust_env=False) as client:
  response=await client.get('https://fixture-jira.demo-core.svc.cluster.local:8080/rest/api/2/issue/'+KEY,auth=httpx.BasicAuth(os.environ['JIRA_USER'],os.environ['JIRA_TOKEN']))
  assert response.status_code==200
  issue=response.json();fields=issue['fields'];approved=ARGUMENTS
  assert issue['key']==KEY and fields['project']['key']==approved['project'] and fields['issuetype']['name']==approved['issue_type']
  assert all(fields[name]==approved[name] for name in ('summary','description','labels'))
  print(json.dumps({'backend_fields_match_approval':True,'verified_issue_key':KEY}))
asyncio.run(verify())""".replace(
            'fixture-jira.demo-core.svc.cluster.local', active_profile().service_host('fixture-jira')
        ).replace("KEY", repr(key)).replace(
            "ARGUMENTS", repr(self.proposal["arguments"])
        )
        audit = """import json,os,sqlite3
db=sqlite3.connect('file:'+os.environ['DRIVER_DATABASE']+'?mode=ro',uri=True);db.row_factory=sqlite3.Row
run=db.execute('SELECT * FROM runs WHERE id=?',(RUN,)).fetchone()
action=db.execute('SELECT * FROM actions WHERE id=? AND run_id=?',(ACTION,RUN)).fetchone()
assert run['user']==USER and run['workload']==WORKLOAD and run['project']==PROJECT
assert action['state']=='succeeded' and action['issue_key']==KEY and action['digest']==DIGEST and action['execution_id']
events=[dict(v) for v in db.execute('SELECT * FROM audit WHERE run_id=? AND action_id=? ORDER BY sequence',(RUN,ACTION))]
assert sum(e['event']=='claimed' for e in events)==1 and sum(e['event']=='succeeded' for e in events)==1
assert any(e['event']=='approved' and json.loads(e['detail'])['digest']==DIGEST for e in events)
print(json.dumps({'durable_action_succeeded':True,'one_dispatch_claim':True,'approval_digest_correlated':True,'user_workload_run_action_correlated':True}))"""
        for name, value in {
            "RUN": self.run_id,
            "ACTION": self.proposal["action_id"],
            "USER": self.user,
            "WORKLOAD": workload,
            "KEY": key,
            "DIGEST": self.proposal["digest"],
            "PROJECT": self.project,
        }.items():
            audit = audit.replace(name, repr(value))
        summary = {}
        for deployment, container, program in (
            ("fixture-protected-adapter", "adapter-https", backend),
            ("fixture-identity-driver", None, audit),
        ):
            result = subprocess.run(
                [
                    "oc", "--kubeconfig", self.args.kubeconfig, "-n", native.NAMESPACE,
                    "exec", "deployment/" + deployment,
                    *(["-c", container] if container else []),
                    "--", "python", "-c", program,
                ],
                capture_output=True, text=True, timeout=25,
            )
            if result.returncode:
                raise RuntimeError("Created outcome verification failed; details withheld")
            summary.update(json.loads(result.stdout))
        return summary

    def close(self) -> None:
        """Cancel through the owner's CSRF-protected UI; never reset or reassign identity."""
        if not self.run_id:
            return
        status, _, _ = self.http(
            DRIVER + "/runs/" + self.run_id + "/cancel", fields={"csrf": self.csrf}
        )
        assert status == 303
