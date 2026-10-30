# SPDX-License-Identifier: Apache-2.0
"""Non-CVE proposals through the unchanged native identity/permission harness."""

from pathlib import Path

from permission_flow import PermissionFlow


class ServiceRequestCore(PermissionFlow):
    """Reuse real browser consent and bound MCP transport in the SERVICE project."""

    workflow = "service-request"
    project = "SERVICE"
    submission = {"request": "SERVICE-0001"}
    start_button = "Start remediation request"

    def proposal_program(self) -> str:
        """Execute the actual workload source inside the fresh native sandbox."""
        source = (Path(__file__).resolve().parents[2] / "workloads" / "agents"
                  / "service-request-demo" / "src" / "client.py").read_text()
        return (
            "import tempfile,pathlib,runpy\n"
            "with tempfile.TemporaryDirectory(prefix='service-proposal-') as directory:\n"
            " source=pathlib.Path(directory)/'client.py'\n"
            " source.write_text(" + repr(source) + ")\n"
            " runpy.run_path(str(source),run_name='__main__')\n"
        )

    def validate_report(self, report: dict) -> None:
        """Reject a CVE fixture or caller-provided identity masquerading as reuse."""
        assert report["request_id"] == self.submission["request"]
        assert report["proposed_create"]["project"] == self.project
        assert len(report["source_sha256"]) == 64
        assert not {"user", "workload", "token", "approved", "run_id", "action_id"} & report.keys()
