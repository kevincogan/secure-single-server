# SPDX-License-Identifier: Apache-2.0
"""Bounded native execution on one stable operator session for concurrency tests."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import subprocess
from threading import Barrier
from typing import Callable


def parallel_exec(
    cli: str, env: dict, jobs: list[tuple[object, str]],
    record: Callable[[int, dict], None],
) -> list[dict]:
    """Launch only credential-free Python probes on prevalidated owned contexts.

    The caller must reauthenticate and establish its tunnel before entry, then
    keep both unchanged until all jobs finish. No automatic execution retry.
    """
    if not 2 <= len(jobs) <= 4 or any(
        c.namespace != "demo-" + c.role or c.workspace != c.namespace
        or c.role not in ("triage", "reader")
        or not c.sandbox_name.startswith("demo-s56-" + c.role + "-")
        or not isinstance(program, str) or len(program) > 131_072
        for c, program in jobs
    ):
        raise ValueError("Bounded prevalidated owned execution jobs required")
    barrier = Barrier(len(jobs))

    def run(index: int, context: object, program: str) -> dict:
        """Keep command/results private; extract exactly one safe MCP observation."""
        words = [cli, "--gateway", "identity-demo-runtime", "--workspace", context.workspace,
                 "sandbox", "exec", "--name", context.sandbox_name, "--no-login-shell",
                 "--timeout", "90", "--no-tty", "--", "python", "-c", program]
        barrier.wait(timeout=10)
        result = subprocess.run(words, env=env, capture_output=True, text=True, timeout=100)
        record(index, {"exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
        if result.returncode:
            raise RuntimeError("Parallel native execution failed; details withheld")
        observations = []
        for line in result.stdout.splitlines():
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if isinstance(value, dict) and "read_passed" in value and "events" in value:
                value.pop("_private_response", None)
                observations.append(value)
        if len(observations) != 1:
            raise ValueError("One native MCP observation required per parallel job")
        return observations[0]

    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futures = [pool.submit(run, i, c, program) for i, (c, program) in enumerate(jobs)]
        return [future.result() for future in futures]
