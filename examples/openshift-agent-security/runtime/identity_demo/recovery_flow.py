# SPDX-License-Identifier: Apache-2.0
"""Native single-dispatch acceptance with a real create and lost adapter reply."""

from __future__ import annotations
from deployment_profile import active_profile

import json
from html import unescape
from pathlib import Path
import subprocess

from identity_demo_action_policy import DRIVER
from permission_flow import PermissionFlow
import probe_native_exchange as native


class RecoveryFlow(PermissionFlow):
    """Exercise durable unknown state, restart and trusted positive reconciliation."""

    def cluster_python(self, deployment: str, program: str) -> dict:
        """Run bounded trusted diagnostics, keeping all raw output private."""
        result = subprocess.run([
            "oc", "--kubeconfig", self.args.kubeconfig, "-n", native.NAMESPACE,
            "exec", "deployment/" + deployment,
            *(["-c", "adapter-https"] if deployment == "fixture-protected-adapter" else []),
            "--", "python", "-c", program,
        ], capture_output=True, text=True, timeout=30)
        if result.returncode:
            native.private_write(self.args.output_dir / "recovery-diagnostic-failure.private.json",
                                 {"exit": result.returncode, "stderr": result.stderr})
            raise RuntimeError("Recovery diagnostic failed; details withheld")
        return json.loads(result.stdout)

    def action_state(self, state: str) -> dict:
        """Verify durable state, exact association and a single dispatch claim."""
        return self.cluster_python("fixture-identity-driver", """import os,json,sqlite3
db=sqlite3.connect('file:'+os.environ['DRIVER_DATABASE']+'?mode=ro',uri=True);db.row_factory=sqlite3.Row
r=db.execute('SELECT * FROM runs WHERE id=?',(RUN,)).fetchone()
a=db.execute('SELECT * FROM actions WHERE id=? AND run_id=?',(ACTION,RUN)).fetchone()
assert r['user']==USER and r['workload']==WORKLOAD and a['digest']==DIGEST and a['state']==STATE and a['execution_id']
events=list(db.execute('SELECT event FROM audit WHERE run_id=? AND action_id=?',(RUN,ACTION)))
assert sum(v['event']=='claimed' for v in events)==1
assert sum(v['event']=='unknown' for v in events)==1
if STATE=='succeeded':assert sum(v['event']=='reconciled' for v in events)==1
print(json.dumps({'state':a['state'],'issue_key':a['issue_key'],'execution_id':a['execution_id'],'single_dispatch':True}))"""
            .replace("RUN", repr(self.run_id)).replace("ACTION", repr(self.proposal["action_id"]))
            .replace("USER", repr(self.user)).replace("DIGEST", repr(self.proposal["digest"]))
            .replace("WORKLOAD", repr(self.args.execution_context.workload))
            .replace("STATE", repr(state)))

    def accept(self, execute: object, resource: str, context: object) -> dict:
        """Prove uncertain outcome never redispatches and survives driver restart."""
        before = self.backend_count()
        fixture = Path(__file__).with_name("cve_runtime_fixture.py").read_text()

        def sandbox(program: str) -> dict:
            return execute([
                "sandbox", "exec", "--name", context.sandbox_name,
                "--no-login-shell", "--timeout", "90", "--no-tty", "--",
                "python", "-c", program,
            ], json_output=True)

        report = sandbox("ns={'__name__':'fixture'};exec(" + repr(fixture)
                         + ",ns);import asyncio,json;print(json.dumps(asyncio.run(ns['assessment_fixture']())))")
        assert report["assessment_preserved_after_local_denial"]
        status, _, body = self.http(DRIVER + "/internal/operator/report", operator=True,
            value={"run_id": self.run_id, "user": self.user, "workload": context.workload,
                   "assessment": report["assessment"], "arguments": report["proposed_create"]})
        assert status == 200
        self.proposal = json.loads(body)
        action = self.proposal["action_id"]
        arguments = {"run_id": self.run_id, "action_id": action, **self.proposal["arguments"]}
        status, _, _ = self.http(DRIVER + "/runs/" + self.run_id + "/approve",
            fields={"csrf": self.csrf, "action": action, "digest": self.proposal["digest"]})
        assert status == 303

        def call() -> dict:
            return sandbox(native.read_program(resource, "step56_jira_createJiraIssue", arguments, "key"))

        selector = "/tmp/identity-demo-lost-reply-action"
        try:
            self.cluster_python("fixture-protected-adapter",
                "import os,json;f=os.fdopen(os.open(" + repr(selector)
                + ",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w');f.write(" + repr(action)
                + ");f.close();print(json.dumps({'selected_exact_action':True}))")
            lost = call()
            assert lost["read_passed"] is False and self.backend_count() == before + 1
            unknown = self.action_state("unknown")
            blocked = call()
            assert blocked["read_passed"] is False and any(
                e.get("http_status") == 403 and e.get("denial_reason") == "action_unknown"
                for e in blocked["events"])
            assert self.backend_count() == before + 1

            dep = native.kube(self.args, "get", "deployment", "fixture-identity-driver",
                              "-n", native.NAMESPACE, "-o", "json")
            assert dep["metadata"]["labels"]["identity-demo-owner"] == active_profile().owner
            assert dep["spec"]["replicas"] == 1 and dep["spec"]["strategy"]["type"] == "Recreate"
            result = subprocess.run(["oc", "--kubeconfig", self.args.kubeconfig, "-n", native.NAMESPACE,
                "rollout", "restart", "deployment/fixture-identity-driver"], capture_output=True, timeout=15)
            assert result.returncode == 0
            result = subprocess.run(["oc", "--kubeconfig", self.args.kubeconfig, "-n", native.NAMESPACE,
                "rollout", "status", "deployment/fixture-identity-driver", "--timeout=90s"],
                capture_output=True, timeout=100)
            assert result.returncode == 0 and self.action_state("unknown") == unknown
            status, _, _ = self.http(DRIVER + "/internal/operator/credentials/" + self.run_id,
                                     operator=True)
            assert status == 403
            self.authenticate()
            status, _, displayed = self.http(DRIVER + "/runs/" + self.run_id)
            assert status == 200 and report["assessment"] in unescape(displayed.decode())
            blocked = call()
            assert blocked["read_passed"] is False and self.backend_count() == before + 1
            resolved = self.cluster_python("fixture-protected-adapter", """import asyncio,json,os
from pathlib import Path
from identity_demo_jira_action_adapter import JiraTools
t=JiraTools(Path(os.environ['DRIVER_ADAPTER_SECRET_FILE']).read_text().strip(),os.environ['JIRA_USER'],os.environ['JIRA_TOKEN'],os.environ['DRIVER_CA_FILE'])
print(json.dumps(asyncio.run(t.reconcile(RUN,ACTION))))"""
                .replace("RUN", repr(self.run_id)).replace("ACTION", repr(action)))
            assert resolved["resolved"] is True
            state = self.action_state("succeeded")
            assert state["execution_id"] == unknown["execution_id"] and state["issue_key"] == resolved["issue_key"]
            duplicate = call()
            assert duplicate["read_passed"] is True
            assert duplicate["verified_tool_result"] == {"key": resolved["issue_key"], "duplicate": True}
            assert self.backend_count() == before + 1
            summary = {"passed": True, "real_native_create_reply_lost": True,
                "unknown_survives_driver_restart": True, "redispatch_denied": True,
                "trusted_marker_and_fields_reconciled": True, "single_dispatch": True,
                "retry_returns_original_issue": True, "assessment_retained": True,
                "verified_issue_key": resolved["issue_key"], "backend_before": before,
                "backend_after": self.backend_count(), "steps5_and6_complete": False}
            native.private_write(self.args.output_dir / (self.args.label + ".recovery.summary.json"), summary)
            return summary
        finally:
            self.cluster_python("fixture-protected-adapter", "import pathlib,json;p=pathlib.Path(" + repr(selector)
                + ");p.unlink(missing_ok=True);print(json.dumps({'fault_disabled':not p.exists()}))")
            self.close()


class ResumeRecoveryFlow(RecoveryFlow):
    """Resume an active uncertain run after a harness interruption; never reassign it."""

    def login(self, context: object) -> dict:
        """Reauthenticate the original owner and read the original durable proposal."""
        association = json.loads(Path(self.args.resume_association_file).read_text())
        assert association["workload"] == context.workload
        self.run_id, self.user = association["run_id"], association["user"]
        self.authenticate()
        status, _, body = self.http(DRIVER + "/internal/operator/credentials/" + self.run_id,
                                   operator=True)
        assert status == 200
        credential = json.loads(body)
        assert credential["user"] == self.user and credential["workload"] == context.workload
        record = self.cluster_python("fixture-identity-driver", """import os,json,sqlite3
d=sqlite3.connect('file:'+os.environ['DRIVER_DATABASE']+'?mode=ro',uri=True);d.row_factory=sqlite3.Row
r=d.execute('SELECT * FROM runs WHERE id=?',(RUN,)).fetchone()
rows=d.execute('SELECT * FROM actions WHERE run_id=?',(RUN,)).fetchall()
assert r['active']==1 and r['user']==USER and len(rows)==1 and rows[0]['state']=='unknown'
a=rows[0];print(json.dumps({'action_id':a['id'],'arguments':json.loads(a['payload']),'digest':a['digest']}))"""
            .replace("RUN", repr(self.run_id)).replace("USER", repr(self.user)))
        self.proposal = record
        return {"access_token": credential["access_token"]}

    def accept(self, execute: object, resource: str, context: object) -> dict:
        """Complete positive reconciliation and a real native duplicate on the same run."""
        before = self.backend_count()
        unknown = self.action_state("unknown")
        resolved = self.cluster_python("fixture-protected-adapter", """import asyncio,json,os
from pathlib import Path
from identity_demo_jira_action_adapter import JiraTools
t=JiraTools(Path(os.environ['DRIVER_ADAPTER_SECRET_FILE']).read_text().strip(),os.environ['JIRA_USER'],os.environ['JIRA_TOKEN'],os.environ['DRIVER_CA_FILE'])
print(json.dumps(asyncio.run(t.reconcile(RUN,ACTION))))"""
            .replace("RUN", repr(self.run_id)).replace("ACTION", repr(self.proposal["action_id"])))
        assert resolved["resolved"]
        state = self.action_state("succeeded")
        assert state["execution_id"] == unknown["execution_id"] and state["issue_key"] == resolved["issue_key"]
        arguments = {"run_id": self.run_id, "action_id": self.proposal["action_id"], **self.proposal["arguments"]}
        result = execute([
            "sandbox", "exec", "--name", context.sandbox_name, "--no-login-shell",
            "--timeout", "90", "--no-tty", "--", "python", "-c",
            native.read_program(resource, "step56_jira_createJiraIssue", arguments, "key"),
        ], json_output=True)
        assert result["read_passed"] and result["verified_tool_result"] == {
            "key": resolved["issue_key"], "duplicate": True}
        assert self.backend_count() == before
        self.close()
        summary = {"passed": True, "resumed_same_active_run": True,
                   "reconciled_original_unknown_action": True, "single_dispatch": True,
                   "native_duplicate_returned_original_issue": True,
                   "backend_before": before, "backend_after": self.backend_count(),
                   "verified_issue_key": resolved["issue_key"], "steps5_and6_complete": False}
        native.private_write(self.args.output_dir / (self.args.label + ".recovery.summary.json"), summary)
        return summary
