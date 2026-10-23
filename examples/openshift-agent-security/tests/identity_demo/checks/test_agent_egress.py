# SPDX-License-Identifier: Apache-2.0
"""Reject weak network evidence when asserting agent socket isolation."""

import json
from unittest.mock import patch

import pytest

from agent_egress import program


@pytest.mark.parametrize("error,expected", [(PermissionError(), True), (TimeoutError(), False), (ConnectionRefusedError(), False)])
def test_only_kernel_permission_denial_passes(error: Exception, expected: bool, capsys: object) -> None:
    """A stopped Service or unreachable network must not masquerade as policy."""
    with patch("socket.create_connection", side_effect=error):
        exec(compile(program(), "agent_egress", "exec"), {})
    value = json.loads(capsys.readouterr().out)
    assert value["passed"] is expected and len(value["cases"]) == 4
