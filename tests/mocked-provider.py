#!/usr/bin/env python3
"""Local and CI entry point. All inference uses synthetic, private fixtures."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests/common"))
from evidence import save


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=("praxis", "offline", "gateways", "openshell"), default="praxis")
    parser.add_argument("--engine", choices=("docker", "podman"), default=os.environ.get("CONTAINER_ENGINE", "podman"))
    args = parser.parse_args()
    os.environ["CONTAINER_ENGINE"] = args.engine
    commands = []
    if args.suite in ("praxis", "offline"):
        commands += [["bash", "tests/shared-gateway-static.sh"],
                     [sys.executable, "-m", "unittest", "discover", "-s", "tests/common", "-p", "test_*.py"]]
        commands += [[sys.executable, path] for path in ("tests/remote-gateway/credentials.py",
            "tests/remote-gateway/security.py", "tests/aws/plan.py", "tests/aws/session.py", "tests/aws/https-access.py",
            "tests/rhel/smoke.py", "tests/rhel/unit.py", "tests/rhel/users.py", "tests/rhel/providers.py", "tests/rhel/vllm.py", "tests/rhel/clients.py", "tests/rhel/features-test.py", "tests/pricetag/unit.py", "tests/pricetag/providers.py", "tests/pricetag/install.py", "tests/pricetag/metering-admin.py", "tests/pricetag/manage.py", "tests/pricetag/api.py", "tests/pricetag/perf.py", "tests/pricetag/capacity-export.py")]
        commands += [[sys.executable, "tests/llm-d-sc/unit.py"]]
    if args.suite == "praxis":
        commands += [["bash", "tests/shared-gateway-image.sh"], ["bash", "tests/shared-gateway-valkey-image.sh"]]
    if args.suite in ("praxis", "gateways"):
        commands += [[sys.executable, 'tests/rhel/unified-image.py']]
        commands += [[sys.executable, "tests/common/gateway.py", "--scenario", scenario, *backend]
                     for scenario in ("all-in-one", "remote") for backend in ([], ["--valkey"])]
        commands += [[sys.executable, "tests/rhel/provider-image.py", "--scenario", scenario, *backend]
                     for scenario in ("all-in-one", "remote") for backend in ([], ["--valkey"])]
        commands += [[sys.executable, "tests/rhel/provider-image.py", "--scenario", scenario, "--valkey", "--extended"]
                     for scenario in ("all-in-one", "remote")]
        commands += [[sys.executable, "tests/rhel/features-image.py", "--scenario", scenario, *backend]
                     for scenario in ("all-in-one", "remote") for backend in ([], ["--valkey"])]
    if args.suite == "openshell":
        commands += [[sys.executable, "openshell/tests/regressions.py"],
                     [sys.executable, "tests/github/test_upstream_watch.py"],
                     [sys.executable, "openshell/tests/gateway.py"],
                     [sys.executable, "openshell/tests/probe-test.py"],
                     [sys.executable, "tests/openshell-praxis/offline.py"],
                     [sys.executable, "tests/openshell-praxis/schema.py"]]
    result = {"suite": args.suite, "engine": args.engine, "status": "running", "checks": [],
              "openshell_runtime": "not run: separate manual disposable-RHEL qualification lane",
              "roadmap": {"phase_1": "gateway contracts; native RHEL and real harness tasks remain separate",
                          "phase_5": "shared quotas and MaaS API-key checks; no personal/hierarchical quotas",
                          "phase_6": "harness/configuration contracts only; no retained-session or inference qualification"}}
    try:
        for command in commands:
            print("RUN " + " ".join(command), flush=True)
            started = time.monotonic()
            completed = subprocess.run(command, cwd=ROOT, check=False)
            result["checks"].append({"command": " ".join(command), "exit_code": completed.returncode,
                                     "seconds": round(time.monotonic() - started, 2)})
        result["status"] = "failed" if any(item["exit_code"] for item in result["checks"]) else "passed"
    finally:
        if result["status"] == "running":
            result["status"] = "interrupted"
        save(f"suite-{args.suite}-{args.engine}", result)
    return int(result["status"] != "passed")


if __name__ == "__main__":
    # Assertion-based contract tests must never run with optimizations enabled.
    if not __debug__ or os.environ.get("PYTHONOPTIMIZE"):
        raise SystemExit("Run tests without Python -O/PYTHONOPTIMIZE")
    raise SystemExit(main())
