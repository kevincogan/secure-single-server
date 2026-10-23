# SPDX-License-Identifier: Apache-2.0
"""Frozen completed-assessment fixture executed inside the actual CVE image.

Calls the shipped CVE handoff code with a local deny-all sink. No model, remote
intelligence feed, MCP server or Jira backend is called. This is runtime evidence,
not a complete CVE analysis or an identity/authorization acceptance test.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib.metadata
import json
import logging
from pathlib import Path
import socket
import sys
import threading


def tcp_accept_fixture() -> None:
    """Exercise a real local TCP accept without an external network destination."""
    result: list[bytes] = []
    with socket.socket() as server:
        server.settimeout(8)
        server.bind(("127.0.0.1", 0))
        server.listen(1)

        def connect() -> None:
            """Send one synthetic marker through the sandbox's loopback stack."""
            with socket.create_connection(server.getsockname(), timeout=8) as client:
                client.sendall(b"runtime-fixture")
                result.append(client.recv(64))

        thread = threading.Thread(target=connect)
        thread.start()
        with server.accept()[0] as client:
            assert client.recv(64) == b"runtime-fixture"
            client.sendall(b"accepted")
        thread.join(timeout=10)
        assert not thread.is_alive() and result == [b"accepted"]


async def assessment_fixture() -> dict:
    """Run real image models/handoff while preserving a denied assessment."""
    from exploit_iq_commons.data_models.common import (
        AnalysisType,
        PipelineMode,
        TargetPackage,
    )
    from exploit_iq_commons.data_models.info import ExploitIqInfo
    from exploit_iq_commons.data_models.input import (
        ExploitIqInput,
        ImageInfoInput,
        ScanInfoInput,
        VulnInfo,
    )
    from vuln_analysis.data_models.output import (
        CVSSOutput,
        ExploitIqEngineOutput,
        ExploitIqOutput,
        JustificationOutput,
        OutputPayload,
    )
    from vuln_analysis.utils import jira_handoff

    logging.disable(logging.CRITICAL)
    analysis = ExploitIqEngineOutput(
        vuln_id="CVE-2099-0001",
        checklist=[],
        summary="Synthetic fixture: vulnerable package is present and reachable.",
        justification=JustificationOutput(
            label="vulnerable", reason="Frozen synthetic assessment.", status="TRUE"
        ),
        intel_score=90,
        cvss=CVSSOutput(
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score="9.8"
        ),
    )
    output = ExploitIqOutput(
        input=ExploitIqInput(
            scan=ScanInfoInput(
                id="runtime-fixture",
                vulns=[
                    VulnInfo(
                        vuln_id=analysis.vuln_id,
                        description="Synthetic vulnerability for isolated runtime testing.",
                        severity="critical",
                        score=9.8,
                        published_date="2026-09-01T00:00:00Z",
                        url="https://example.invalid/synthetic",
                    )
                ],
            ),
            image=ImageInfoInput(
                name="example/synthetic",
                tag="fixture",
                analysis_type=AnalysisType.IMAGE,
                pipeline_mode=PipelineMode.PACKAGE_CHECKER,
                target_package=TargetPackage(name="example-lib", version="1.2.3"),
            ),
        ),
        info=ExploitIqInfo(),
        output=OutputPayload(analysis=[analysis], vex=None),
    )
    payload = jira_handoff.build_jira_handoff_payload(output, analysis)
    assert payload["finding"]["vuln_id"] == analysis.vuln_id
    assert payload["analysis"]["affected_status"] == "TRUE"
    assert payload["target"]["affected_packages"][0]["name"] == "example-lib"
    assert payload["requested_action"] == "create_or_update"
    original_summary = analysis.summary

    class DenyAllSink:
        """Local fixture boundary; does not represent MCP or bank authorization."""

        def __init__(self) -> None:
            self.calls = 0

        async def ainvoke(self, message: str) -> str:
            """Validate the real handoff and deny every mutation request."""
            request = json.loads(message.split("Assessment payload:\n", 1)[1])
            assert request["finding"]["vuln_id"] == analysis.vuln_id
            self.calls += 1
            raise PermissionError("Runtime checkpoint: mutations disabled")

    sink = DenyAllSink()
    completed = await jira_handoff.handoff_to_jira(output, sink)
    assert sink.calls == 1
    assert completed.output.analysis[0].summary == original_summary
    assert completed.output.analysis[0].jira_action.status == "failed"
    assert (
        completed.output.analysis[0].jira_action.error
        == "Runtime checkpoint: mutations disabled"
    )
    source = Path(jira_handoff.__file__)
    return {
        "actionable_findings": 1,
        "real_handoff_calls": sink.calls,
        "assessment_preserved_after_local_denial": True,
        "handoff_source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "assessment": analysis.summary,
        "proposed_create": {
            "project": "TEST",
            "issue_type": "Task",
            "summary": "CVE-2099-0001: review synthetic example-lib 1.2.3",
            "description": analysis.summary
            + " Frozen synthetic input; no live model or intelligence feed.",
            "labels": ["synthetic-cve"],
        },
    }


def main() -> None:
    """Print only deterministic evidence from the supervised runtime process."""
    tcp_accept_fixture()
    result = asyncio.run(assessment_fixture())
    packages = {
        d.metadata["Name"]: d.version
        for d in importlib.metadata.distributions()
        if d.metadata.get("Name", "").startswith(("nvidia-nat", "aiqtoolkit"))
    }
    print(
        json.dumps(
            {
                "runtime_fixture_passed": True,
                "tcp_accept_passed": True,
                "python": sys.version.split()[0],
                "nat_packages": packages,
                **result,
                "model_called": False,
                "mcp_called": False,
                "jira_mutated": False,
                "full_cve_analysis_executed": False,
                "identity_binding_proven": False,
            }
        )
    )


if __name__ == "__main__":
    main()
