# SPDX-License-Identifier: Apache-2.0
"""Shared gateway evidence around the one protected execution lifecycle."""
from permission_flow import PermissionFlow
import probe_native_exchange as native


class GatewayEvidenceFlow(PermissionFlow):
    def accept(self, execute: object, resource: str, context: object) -> dict:
        """Capture real gateway configuration while its temporary route is active."""
        from gateway_overview import overview, catalog_schemas

        self.progress("discovering_tools")
        try:
            gateway = {**overview(self.args), **catalog_schemas(self.args), "passed": True}
        except Exception as error:
            # Presentation capture is independent of security acceptance. Keep
            # the failed receipt visible and still prove the permission flow;
            # the complete walkthrough must resolve this separate gate.
            gateway = {"passed": False, "failure_kind": type(error).__name__,
                "details_withheld": True}
        native.private_write(self.args.output_dir / (self.args.label + ".gateway.summary.json"), gateway)
        if gateway.get("passed") and gateway.get("registration_ready"):
            self.progress("tools_discovered", {"gateway_ready": bool(gateway.get("passed") and gateway.get("registration_ready")),
                "tool_names": [t["name"] for t in gateway.get("published_tool_schemas", [])],
                "tool_schemas": gateway.get("published_tool_schemas", []),
                "gateway_backend_services": gateway.get("backend_services", []),
                **{key: bool(gateway.get(key)) for key in ("live_run_identity_check", "actual_arguments_and_approval_check", "scoped_adapter_service_token_delivery")}})
        result = PermissionFlow.accept(self, execute, resource, context)
        result["gateway_introduction"] = gateway
        return result

