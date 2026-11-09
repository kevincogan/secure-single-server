# SPDX-License-Identifier: Apache-2.0
"""Shared cluster installer session test setup; contains no collected tests."""
from types import SimpleNamespace
from cluster_installer_session import CompletedStages
import connected_install
import identity_demo_setup as setup
from deployment_profile import LEGACY

def config():
    return {
        "schema_version": 1,
        "profile": LEGACY.to_dict(),
        "artifacts": {
            "schema_version": 1,
            "images": {
                role: "registry.example/" + role + "@sha256:" + "a" * 64
                for role in (
                    "jira_runtime",
                    "keycloak_management",
                    "keycloak_exchange",
                    "openshell_gateway",
                    "openshell_supervisor",
                )
            },
        },
        "application": dict(
            chat_request_url="https://model.example.org/v1/messages",
            chat_model="reviewed-model",
            workload_image="pinned-by-original-validator",
            diagnostic_runtime_image="pinned-by-original-validator",
        ),
        "public_trust": dict(
            service_ca="service-ca.pem",
            upstream_ca_bundle="upstream-ca.pem",
            kubernetes_ca="kubernetes-ca.pem",
        ),
        "kubernetes_api_cidrs": ["192.0.2.1/32"],
        "certificate_management": {"mode": "legacy"},
        "credentials": {
            "inference": {
                "secret_name": "fixture-installer-inference",
                "key": "api-key",
            }
        },
    }

def completed(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    calls = []
    fence = []
    args = SimpleNamespace(output_dir=tmp_path, stage_fence=lambda: fence.append(True))

    def run(self, name, script, words, **kwargs):
        calls.append((name, script, words))
        setup.write(tmp_path / (name + ".pending.json"), {"submitted": True})
        out = tmp_path / name
        out.mkdir()
        log = tmp_path / (name + ".private.log")
        log.write_text("bounded stage output")
        log.chmod(0o600)
        setup.write(
            tmp_path / (name + ".receipt.json"),
            {"stage": name, "exit": 0, "log_sha256": setup.sha(log)},
        )
        return {"completed": True}, out

    monkeypatch.setattr(connected_install.Stages, "run", run)
    return CompletedStages(args, {}), calls, fence
