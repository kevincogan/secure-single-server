# SPDX-License-Identifier: Apache-2.0
"""OpenShift/demo admission around the reusable run store; historical imports remain valid."""
import json
import time
from deployment_profile import active_profile
from agent_security import RunStore as SecurityRunStore
RETIRED_WORKLOAD = "spiffe://agents.example.test/openshell/sandbox/00000000-0000-4000-8000-000000000001"
from agent_security_contracts import ConnectorContract, Denied, strict_json, tool_arguments
from identity_demo_jira_contract import JIRA, SCHEMA, BACKEND, TOOL, normalize_create, canonical, create_call, scoped_read_jql, read_call


class RunStore(SecurityRunStore):
    """Preserve the Jira default and atomic pool/job admission for installed records."""

    legacy_fingerprint = JIRA.fingerprint

    def __init__(self, path, *, connector=JIRA):
        super().__init__(path, connector=connector, trust_domain=active_profile().trust_domain,
                         legacy_fingerprint=JIRA.fingerprint if connector == JIRA else None,
                         retired_workloads=frozenset({RETIRED_WORKLOAD}))

    def create_run(self, *, require_console_idle=False, console_workflow=None, **association):
        """Keep the installed console API at this platform edge."""
        return super().create_run(**association, require_context=require_console_idle,
                                  workflow=console_workflow)

    def reserve_context(self, db, workload, require_console_idle, console_workflow):
        from identity_demo_warm_pool import blocked_identity, blocks_execution
        if blocked_identity(db, workload):
            raise Denied('retired_workload')
        if blocks_execution(db):
            raise Denied('context_preparing')
        if console_workflow is not None:
            if db.execute("SELECT 1 FROM console_batches WHERE state='preparing'").fetchone():
                raise Denied('presentation_preparing')
            worker = db.execute('SELECT phase,updated FROM console_worker WHERE id=1').fetchone()
            if not worker or worker['phase'] != 'ready' or worker['updated'] <= time.time()-20:
                raise Denied('coordinator_not_ready')
            if db.execute("SELECT 1 FROM console_jobs WHERE state IN ('queued','running')").fetchone():
                raise Denied('console_busy')
            if (db.execute("SELECT 1 FROM actions WHERE state IN ('executing','unknown')").fetchone()
                    or any(json.loads(v[0]).get('failure_code') == 'recovery_required'
                           and json.loads(v[0]).get('cleanup_verified') is not True
                           for v in db.execute("SELECT evidence FROM console_jobs WHERE state='failed'"))):
                raise Denied('recovery_required')
        if require_console_idle:
            from identity_demo_warm_pool import allocate, blocks_execution, enabled as automatic_pool_enabled
            if blocks_execution(db):
                raise Denied('context_preparing')
            if automatic_pool_enabled(db) and db.execute('SELECT 1 FROM runs WHERE active<>0').fetchone():
                raise Denied('console_busy')
            allocate(db, workload)

    def bind_context(self, db, run, workload, project, workload_role, require_console_idle, console_workflow):
        if require_console_idle:
            from identity_demo_pool_profiles import bind
            bind(db, run, workload, console_workflow, project, workload_role, self.connector.identifier)

    def queue_context(self, db, run, console_workflow):
        if console_workflow is not None:
            # Reserve the lane and identity in the SAME transaction. A racing
            # submission cannot consume a second identity without a job.
            evidence = {"scenario_version": "remediation-v1"} if console_workflow == "service-request" else {}
            db.execute("INSERT INTO console_jobs VALUES (?,?, 'queued','preparing_identity',NULL,?,?)",
                       (run, console_workflow, int(time.time()), json.dumps(evidence)))
            self.event(db, run, None, 'console_queued', {'workflow':console_workflow})
