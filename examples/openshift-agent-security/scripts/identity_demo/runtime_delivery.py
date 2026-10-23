# SPDX-License-Identifier: Apache-2.0
"""Verify supplied runtime interfaces without mounting credentials or contacting tools.

This is an image contract check, not source provenance, licence approval, a scan,
or live acceptance. Images must already be present in the selected local engine.
"""
from __future__ import annotations
import json
import subprocess

from deployment_artifacts import IMAGE_REFERENCE, validate_artifacts
from identity_demo_setup import private_file, write
from source_render import read_json

PROBES = {
    'jira_runtime': '''import os
# Imports require configuration; no request is made and these are not credentials.
os.environ.update(JIRA_SERVER="https://jira.invalid", JIRA_USER="synthetic-probe", JIRA_TOKEN="synthetic-probe-only")
from jira_emulator.app import create_app
from jira_emulator.database import get_session_factory
from jira_emulator.models.api_token import ApiToken
from mcp_servers.atlassian_jira import getJiraIssue, searchJiraIssuesUsingJql, mcp
from sqlalchemy import update
from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP
import uvicorn
assert callable(create_app) and callable(get_session_factory)
assert callable(getJiraIssue) and callable(searchJiraIssuesUsingJql)
''',
    'cve_workload': '''from exploit_iq_commons.data_models.common import AnalysisType, PipelineMode, TargetPackage
from exploit_iq_commons.data_models.info import ExploitIqInfo
from exploit_iq_commons.data_models.input import ExploitIqInput, ImageInfoInput, ScanInfoInput, VulnInfo
from vuln_analysis.data_models.output import CVSSOutput, ExploitIqEngineOutput, ExploitIqOutput, JustificationOutput, OutputPayload
from vuln_analysis.utils.jira_handoff import build_jira_handoff_payload, handoff_to_jira
assert callable(build_jira_handoff_payload) and callable(handoff_to_jira)
''',
}


def run(args):
    artifacts = validate_artifacts(read_json(private_file(args.artifacts_file)))
    workload = args.workload_image
    if (not isinstance(workload, str) or not IMAGE_REFERENCE.fullmatch(workload)
            or workload.endswith('0' * 64)):
        raise ValueError('Actual approved digest-pinned CVE workload image required')
    images = {'jira_runtime': artifacts['images']['jira_runtime'], 'cve_workload': workload}
    if any(value.endswith('0' * 64) for value in images.values()):
        raise ValueError('Placeholder runtime image cannot be accepted')
    if getattr(args, 'runtime_check_target', 'local') == 'cluster':
        from cluster_runtime_delivery import run as cluster_run
        return cluster_run(args, images, PROBES)
    write(args.output_dir / 'runtime-contract.plan.json', {'images': images,
        'probes': PROBES, 'network': 'none', 'host_mounts': [], 'credential_files_read': False})
    if not args.apply:
        return {'runtime_checks_planned': True, 'executed': False, 'cluster_changed': False}
    results = []
    for role, image in images.items():
        command = [args.engine, 'run', '--rm', '--pull=never', '--network=none', '--read-only',
            '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=64', '--memory=512m',
            '--cpus=1', '--user=65532:0', '--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=64m',
            '--env=PYTHONDONTWRITEBYTECODE=1', '--entrypoint=python', image, '-c', PROBES[role]]
        write(args.output_dir / (role + '.pending.json'), {'image': image, 'network_disabled': True})
        result = subprocess.run(command, capture_output=True, timeout=120)
        # Imported external modules may print arbitrary data. Never export that output.
        passed = result.returncode == 0
        write(args.output_dir / (role + '.receipt.json'), {'image': image,
            'interface_imports_passed': passed, 'engine_exit_code': result.returncode, 'stdout_stderr_withheld': True})
        results.append({'role': role, 'interface_imports_passed': passed})
        if not passed:
            raise ValueError('Runtime contract unavailable; inspect approved image privately, no automatic retry')
    return {'runtime_interface_checks_passed': True, 'executed': True, 'results': results,
            'cluster_changed': False, 'credentials_mounted': False, 'network_access': False,
            'source_and_redistribution_approved': False, 'functional_scenarios_proven': False}
