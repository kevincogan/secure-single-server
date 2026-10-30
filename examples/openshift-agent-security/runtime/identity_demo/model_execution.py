# SPDX-License-Identifier: Apache-2.0
"""Real workload inference using native host-scoped credential injection."""

import hashlib
import json
from pathlib import Path
import time

import yaml

from service_request_core import ServiceRequestCore
from gateway_evidence_flow import GatewayEvidenceFlow
import probe_native_exchange as native
from deployment_profile import active_profile
from provider_contract import MODEL, URL, HOST


def private_inference(path: str) -> dict:
    """Validate operator input without copying a key into receipts or profiles."""
    from identity_demo_runtime_cli import private_path

    config = json.loads(private_path(path).read_text())["chat"]
    if (config["request_url"] != URL
        or config["model"] != MODEL
        or config["tls_verify"] is not True or config["follow_redirects"] is not False
        or config["http_method"] != "POST" or config.get("ca_file") is not None
        or config["authentication"]["header_name"].lower() != "x-api-key"):
        raise ValueError("Exact approved Messages configuration and system trust required")
    private_path(config["credential_file"])
    return config


def profile(name: str) -> dict:
    """Use existing OpenShell header injection with a single POST capability."""
    return {"id": name, "display_name": "Synthetic assessment inference", "category": "inference",
        "credentials": [{"name": "api_key", "required": True,
                         "auth_style": "header", "header_name": "x-api-key"}],
        "endpoints": [{"host": HOST, "port": 443,
            "protocol": "rest", "enforcement": "enforce", "path": "/v1/messages",
            "rules": [{"allow": {"method": "POST", "path": "/v1/messages"}}]}],
        "binaries": ["/workspace/.venv/bin/python", "/usr/bin/python3.12"]}


class ModelExecutionFlow(ServiceRequestCore, GatewayEvidenceFlow):
    """Reuse the same user, run, consent, native MCP and protected backend flow."""

    def proposal_program(self) -> str:
        """Run the actual inference source inside the registered sandbox."""
        self.progress("model_inference")
        from agent_runtime import sandbox_sources
        return sandbox_sources("import inference\ninference.main()")

    def generate_report(self, execute: object, resource: str, context: object) -> dict:
        """Run bounded model turns and real governed reads before proposing content."""
        from agent_runtime import report, AgentRuntimeFailure
        try:
            value = report(self, execute, resource, context)
            if getattr(self.args, 'diagnostic_failure', None):
                # Even if an unexpectedly fast request defeats the short deadline,
                # diagnostic execution must never expose consent or dispatch a write.
                raise AgentRuntimeFailure('diagnostic_not_observed')
            return value
        except AgentRuntimeFailure as error:
            self.progress('agent_stopping', {'agent_error_category': str(error), 'failure_code': 'agent_failed'})
            native.private_write(self.args.output_dir / (self.args.label + '.agent-failure.summary.json'),
                                 {'agent_failed': True, 'error_category': str(error), 'no_fallback': True})
            raise

    def validate_report(self, report: dict) -> None:
        """A failed inference never turns into a fixture or an approvable action."""
        if report.get("inference_failed"):
            native.private_write(self.args.output_dir / (self.args.label + ".inference-failure.summary.json"), report)
            raise RuntimeError("Workload inference failed; sanitized receipt retained")
        super().validate_report(report)
        evidence = report["inference"]
        assert evidence["model"] == MODEL and evidence["http_status"] == 200
        assert evidence["tls_verified"] and not evidence["follow_redirects"] and not evidence["credential_in_agent"]
        self.inference_evidence = {
            **evidence, "run_id": self.run_id, "source_sha256": report["source_sha256"],
            "actual_native_workload": True}
        native.private_write(self.args.output_dir / (self.args.label + ".inference.summary.json"),
                             self.inference_evidence)
        self.progress("draft_validated", {"model_inference": True, "model": evidence["model"]})

    def accept(self, execute: object, resource: str, context: object) -> dict:
        """Attach a scoped native model provider, then remove only its exact ID."""
        config = private_inference(self.args.inference_config)
        name = context.sandbox_name + "-model"
        profiles = native.inventory(execute(["provider", "profile", "list", "-o", "json"], json_output=True), "profiles")
        providers = native.inventory(execute(["provider", "list", "-o", "json"], json_output=True), "providers")
        assert not any(p.get("id") == name for p in profiles)
        assert not any(p.get("name") == name for p in providers)
        location = self.args.output_dir / "enmaas-profile.yaml"
        native.private_write(location, yaml.safe_dump(profile(name), sort_keys=False))
        execute(["provider", "profile", "lint", "-f", str(location)])
        imported = created = attached = False
        provider_id = None
        try:
            # No model provider exists yet. This must fail without producing an
            # action or substituting a deterministic/public-provider response.
            before = self.backend_count()
            if not getattr(self.args, "presentation_only", False):
                unavailable = execute(["sandbox", "exec", "--name", context.sandbox_name,
                    "--no-login-shell", "--timeout", "90", "--no-tty", "--", "python", "-c",
                    self.proposal_program()], json_output=True)
                assert unavailable == {"inference_failed": True, "error_category": "connection_or_tls"}
                assert self.backend_count() == before
                native.private_write(self.args.output_dir / "enmaas-unavailable.summary.json", {
                    **unavailable, "passed": True, "run_id": self.run_id,
                    "no_proposal_or_backend_write": True, "failure_boundary": "native provider absent"})
            execute(["provider", "profile", "import", "-f", str(location)])
            imported = True
            key = Path(config["credential_file"]).read_text().strip()
            try:
                execute(["provider", "create", "--name", name, "--type", name,
                         "--credential", "api_key", "--config",
                         "identity-demo-owner=" + active_profile().owner], inference_key=key)
            finally:
                del key
            created = True
            current = native.inventory(execute(["provider", "list", "-o", "json"], json_output=True), "providers")
            found = [p for p in current if p.get("name") == name and p.get("type") == name]
            assert len(found) == 1
            provider_id = found[0]["id"]
            native.private_write(self.args.output_dir / "enmaas-provider-ledger.json", {
                "name": name, "id": provider_id, "workload": context.workload,
                "profile_sha256": hashlib.sha256(location.read_bytes()).hexdigest(),
                "credential_storage": "owned native gateway; no agent credential"})
            execute(["sandbox", "provider", "attach", context.sandbox_name, name,
                     "--wait", "--timeout", "30", "-o", "json"])
            attached = True
            from agent_egress import program

            egress = execute(["sandbox", "exec", "--name", context.sandbox_name,
                "--no-login-shell", "--timeout", "90", "--no-tty", "--", "python", "-c",
                program()], json_output=True)
            assert egress["passed"]
            native.private_write(self.args.output_dir / "model-agent-egress.summary.json", {
                **egress, "scope": "actual agent direct sockets while model/MCP providers are attached",
                "exceptions": ["trusted supervisor egress", "cluster DNS", "kubelet image pulls",
                               "operator browser and management traffic"],
                "full_disconnected_proven": False})
            self.progress("egress_verified", {"egress_denied": True})
            renewal = {"passed": False, "not_run_in_presentation": True}
            if not getattr(self.args, "presentation_only", False):
                remaining = 35 - (time.monotonic() - self.initial_read_monotonic)
                if remaining > 0:
                    time.sleep(remaining)
                renewed = execute(["sandbox", "exec", "--name", context.sandbox_name,
                    "--no-login-shell", "--timeout", "90", "--no-tty", "--", "python", "-c",
                    self.read_program(resource)], json_output=True)
                assert renewed["read_passed"]
                renewal = {"passed": True, "run_id": self.run_id,
                    "elapsed_since_initial_read_seconds": round(time.monotonic() - self.initial_read_monotonic, 2),
                    "read_after_configured_30_second_final_token_lifetime": True,
                    "certificate_rotation_or_external_api_key_rotation_proven": False}
                native.private_write(self.args.output_dir / "model-path-renewal.summary.json", renewal)
            result = super().accept(execute, resource, context)
            result["model_inference"] = self.inference_evidence
            result["restricted_connectivity"] = egress
            result["final_token_renewal"] = renewal
            return result
        finally:
            if attached:
                execute(["sandbox", "provider", "detach", context.sandbox_name, name,
                         "--wait", "--timeout", "30"])
            if created:
                current = native.inventory(execute(["provider", "list", "-o", "json"], json_output=True), "providers")
                native.require_native_provider_id(current, provider_id, name)
                execute(["provider", "delete", name])
            if imported:
                execute(["provider", "profile", "delete", name])

