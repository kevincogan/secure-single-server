# SPDX-License-Identifier: Apache-2.0
"""Cluster execution must not inherit browser automation."""
from identity_demo_console_worker import ConsoleCveFlow, ConsoleModelFlow, ConsoleIncidentFlow
from browser_permission_flow import BrowserPermissionFlow
from permission_flow import PermissionFlow
from enmaas_flow import EnmaasFlow
from service_request_flow import ServiceRequestFlow


def test_cluster_flows_share_execution_without_browser_automation():
    for cls in (ConsoleCveFlow,ConsoleModelFlow,ConsoleIncidentFlow):
        assert PermissionFlow in cls.__mro__
        assert BrowserPermissionFlow not in cls.__mro__
    assert BrowserPermissionFlow in EnmaasFlow.__mro__
    assert BrowserPermissionFlow in ServiceRequestFlow.__mro__
    assert ConsoleIncidentFlow.project == 'OPS'
    assert ConsoleModelFlow.project == 'SERVICE'
