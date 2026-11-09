# SPDX-License-Identifier: Apache-2.0
"""Cluster execution must not inherit browser automation."""
import json
from types import SimpleNamespace

from identity_demo_console_worker import ConsoleRunSession, GatewayEvidenceFlow, ModelExecutionFlow, ConsoleIncidentFlow
from browser_permission_flow import BrowserPermissionFlow
from permission_flow import PermissionFlow
from enmaas_flow import EnmaasFlow
from service_request_flow import ServiceRequestFlow


def test_cluster_flows_share_execution_without_browser_automation():
    for cls in (GatewayEvidenceFlow, ModelExecutionFlow, ConsoleIncidentFlow):
        assert PermissionFlow in cls.__mro__
        assert BrowserPermissionFlow not in cls.__mro__
    assert BrowserPermissionFlow in EnmaasFlow.__mro__
    assert BrowserPermissionFlow in ServiceRequestFlow.__mro__
    assert ConsoleIncidentFlow.project == 'OPS'
    assert ModelExecutionFlow.project == 'SERVICE'

def test_console_session_uses_existing_run_without_browser_passwords(tmp_path):
    run = "a" * 32
    workload = "spiffe://lab.example.test/openshell/sandbox/12345678-1234-4234-8234-123456789abc"
    association = {"user": "user-a", "workload": workload, "user_role": "analyst"}
    calls = []

    def private_request(path, secret, data):
        calls.append((path, secret, data))
        return 200, {}, json.dumps({**association, "access_token": "synthetic", "expires_at": 123}).encode()

    control = SimpleNamespace(
        request=lambda path: {"run": association} if path == "runs/" + run else {},
        secret="coordinator-key",
        transport=SimpleNamespace(request=private_request),
    )
    args = SimpleNamespace(output_dir=tmp_path, label="attached", credentials_file=tmp_path / "absent")
    session = ConsoleRunSession(control, {**association, "run_id": run})
    flow = GatewayEvidenceFlow(args, run_session=session)

    assert flow.login(SimpleNamespace(workload=workload)) == {"access_token": "synthetic"}
    assert calls == [("/internal/operator/credentials/" + run, "coordinator-key", None)]
    assert not hasattr(flow, "passwords")
