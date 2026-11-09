# SPDX-License-Identifier: Apache-2.0
"""Fixed projection of the immutable console source bundle."""

import json
from pathlib import Path

AUTH_PACKAGE_SOURCES = {
    f"openshift_security.{name}.py": f"scripts/identity_demo/openshift_security/{name}.py"
    for name in ("__init__", "oidc", "login_state")
}


def driver_code(root: Path) -> dict[str, str]:
    """Refresh every reviewed driver source from the same map used for fresh installs."""
    template = json.loads((root / "infra/identity-demo/templates/application.json").read_text())
    data, = (obj["data"] for obj in template["objects"] if obj["kind"] == "ConfigMap"
             and "identity_demo_driver.py" in obj.get("data", {}))
    code = {}
    for key, value in data.items():
        if isinstance(value, dict) and set(value) == {"$source"}:
            source = root / value["$source"]
            if source.is_symlink() or not source.resolve().is_relative_to(root.resolve()):
                raise ValueError("Driver source must stay within the reviewed package")
            code[key] = source.read_text()
    return code


def code_items(data: dict) -> list[dict]:
    """Keep existing flat filenames and project the shared authentication package."""
    return [{"key": name, "path": name.replace("openshift_security.", "openshift_security/", 1)
             if name in AUTH_PACKAGE_SOURCES else name} for name in sorted(data)]
