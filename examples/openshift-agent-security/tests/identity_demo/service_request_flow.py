# SPDX-License-Identifier: Apache-2.0
"""Browser qualification adapter for the shared service execution contract."""
from browser_permission_flow import BrowserPermissionFlow
from service_request_core import ServiceRequestCore


class ServiceRequestFlow(ServiceRequestCore, BrowserPermissionFlow):
    """Keep interactive qualification out of the cluster execution MRO."""
