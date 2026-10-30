# SPDX-License-Identifier: Apache-2.0
"""Demo registrations around the shared reviewed connector contract."""
from agent_security_contracts import ConnectorContract, ConnectorRegistry, Denied, strict_json, tool_arguments


def supported_connectors():
    """Runtime registrations. Additional connectors require a reviewed release."""
    from identity_demo_jira_contract import JIRA

    return ConnectorRegistry((JIRA,))
