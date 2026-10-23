#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run a native fixture command through a fresh, bounded local tunnel.

Uses an already prepared private CLI profile. Credentials and raw command output
remain outside the repository. This is development-test tooling, not a gateway.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import time

from identity_demo_lab import LABELS, oc
from identity_demo_runtime import guard, NAMESPACE
from identity_demo_runtime_grants import SERVER
from deployment_profile import in_source_checkout


def private_path(value: str, directory: bool = False) -> Path:
    """Require existing private artifact paths outside the repository."""
    path = Path(value)
    if (path.is_symlink() or path.stat().st_mode & 0o077
            or in_source_checkout(path)
            or path.is_dir() != directory):
        raise ValueError("Private artifact path required")
    return path


def run(args: argparse.Namespace) -> dict:
    """Authenticate anew, execute the explicit command, and stop our tunnel."""
    args.namespace = NAMESPACE
    if args.expected_server != SERVER:
        raise ValueError("Agreed development cluster required")
    _, credentials, _ = guard(args)
    gateway = json.loads(oc(args, "get", "statefulset", "fixture-openshell",
                            "-n", NAMESPACE, "-o", "json"))
    if any(gateway["metadata"].get("labels", {}).get(k) != v for k, v in LABELS.items()):
        raise ValueError("Owned runtime gateway required")
    directory = private_path(args.cli_config_dir, directory=True)
    output = private_path(args.output_dir, directory=True)
    command = json.loads(private_path(args.command_file).read_text())
    if (not isinstance(command, list) or not command
            or any(not isinstance(v, str) for v in command)):
        raise ValueError("Explicit native command required")
    if command[:4] == ["provider", "profile", "lint", "-f"] and len(command) == 5:
        # Lint validates the private candidate against this exact gateway; it
        # does not register a profile or attach credentials to a sandbox.
        private_path(command[4])
    elif command[0] != "sandbox":
        raise ValueError("Native sandbox command or private profile lint required")
    # Never terminate an existing listener: the operator must stop their tunnel.
    try:
        with socket.create_connection(("127.0.0.1", 18443), timeout=0.2):
            raise ValueError("Loopback port occupied; refused")
    except OSError:
        pass
    env = {**os.environ, "XDG_CONFIG_HOME": str(directory),
           "OPENSHELL_OIDC_CLIENT_SECRET": credentials["runtime_management"]["client_secret"]}
    for key in ("OPENSHELL_GATEWAY", "OPENSHELL_GATEWAY_ENDPOINT",
                "OPENSHELL_GATEWAY_INSECURE", "OPENSHELL_WORKSPACE"):
        env.pop(key, None)
    # The profile was created by probe_runtime_management.py with verified TLS.
    prefix = output / args.output_name
    if Path(args.output_name).name != args.output_name:
        raise ValueError("Simple output name required")
    if any(prefix.with_suffix("." + suffix).exists()
           for suffix in ("portforward-log", "stdout", "stderr")):
        raise ValueError("Existing command output refused")
    with open(prefix.with_suffix(".portforward-log"), "x", opener=lambda p, f: os.open(p, f, 0o600)) as log:
        tunnel = subprocess.Popen(["oc", "--kubeconfig=" + args.kubeconfig,
            "-n", NAMESPACE, "port-forward", "--address", "127.0.0.1",
            "service/fixture-openshell", "18443:8080"], stdout=log, stderr=log)
        try:
            for _ in range(100):
                if tunnel.poll() is not None:
                    raise RuntimeError("Own tunnel failed")
                try:
                    with socket.create_connection(("127.0.0.1", 18443), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                raise TimeoutError("Own tunnel did not become ready")
            login = subprocess.run([args.cli, "gateway", "login", "identity-demo-runtime"],
                env=env, capture_output=True, text=True, timeout=35)
            if login.returncode:
                raise RuntimeError("Management reauthentication failed")
            result = subprocess.run([args.cli, "--gateway", "identity-demo-runtime",
                "--workspace", "default", *command], env=env, capture_output=True,
                text=True, timeout=240)
            for suffix, value in (("stdout", result.stdout), ("stderr", result.stderr)):
                with open(prefix.with_suffix("." + suffix), "x", opener=lambda p, f: os.open(p, f, 0o600)) as stream:
                    stream.write(value)
            return {"command_exit_code": result.returncode, "raw_output_retained_privately": True}
        finally:
            tunnel.terminate()
            try:
                tunnel.wait(timeout=5)
            except subprocess.TimeoutExpired:
                tunnel.kill()
                tunnel.wait(timeout=5)


def main() -> None:
    """Return only status; never print credentials or raw failure bodies."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("kubeconfig", "expected-server", "credentials-file", "cli",
                 "cli-config-dir", "command-file", "output-dir", "output-name"):
        parser.add_argument("--" + name, required=True)
    try:
        result = run(parser.parse_args())
        print(json.dumps(result))
        raise SystemExit(result["command_exit_code"])
    except Exception as error:
        print(json.dumps({"completed": False, "failure_kind": type(error).__name__, "details_withheld": True}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
