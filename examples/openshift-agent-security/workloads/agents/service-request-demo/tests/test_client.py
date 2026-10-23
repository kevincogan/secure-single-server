# SPDX-License-Identifier: Apache-2.0
"""The bounded reuse client has no CVE, model, identity or mutation capability."""

import importlib.util
from pathlib import Path


def test_deterministic_proposal_and_no_security_fields() -> None:
    """Security context comes from shared infrastructure, never proposal output."""
    source = Path(__file__).parents[1] / "src/client.py"
    spec = importlib.util.spec_from_file_location("service_request_client", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    first = module.proposal()
    assert first == module.proposal()
    assert first["proposed_create"]["project"] == "SERVICE"
    assert len(first["source_sha256"]) == 64
    assert not {"user", "workload", "token", "approved", "run_id", "action_id"} & first.keys()
    assert "import http" not in source.read_text() and "import requests" not in source.read_text()
