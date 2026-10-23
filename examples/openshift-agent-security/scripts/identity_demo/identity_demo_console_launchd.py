# SPDX-License-Identifier: Apache-2.0
"""Install and inspect the user-scoped macOS supervisor for the demo coordinator."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import time

LABEL = "org.example.agent-security-console"
PREPARER_LABEL = LABEL + "-preparer"
SOURCE_DIRS = ("scripts/identity_demo", "tests/identity_demo", "infra/identity-demo", "infra/openshell/patches",
               "workloads/agents/service-request-demo/src")
SOURCE_SUFFIXES = {".py", ".sh", ".yaml", ".yml", ".json", ".md", ".txt", ".patch", ".toml", ".lock", ".Containerfile"}


def service_domain() -> str:
    """Return the current user's launchd GUI domain."""
    return f"gui/{os.getuid()}"


def launchctl(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run launchctl without a shell and without echoing its verbose state."""
    result = subprocess.run(["/bin/launchctl", *arguments], capture_output=True, text=True, check=False)
    if check and result.returncode:
        detail = result.stderr.strip().splitlines()
        message = detail[-1] if detail else "launchctl operation failed"
        raise RuntimeError(message)
    return result


def paths(environment_file: Path, private_root: Path, label: str = LABEL) -> tuple[Path, Path, Path]:
    """Validate private runtime paths and derive this user's service files."""
    env = environment_file.expanduser().resolve(strict=True)
    root = private_root.expanduser().resolve(strict=True)
    if env.stat().st_mode & 0o077:
        raise ValueError("Private operator environment file must have mode 0600")
    if root.stat().st_mode & 0o077:
        raise ValueError("Private output directory must have mode 0700")
    if not root.is_dir():
        raise ValueError("Private output root must be a directory")
    agent_dir = Path.home() / "Library" / "LaunchAgents"
    return env, root, agent_dir / f"{label}.plist"


def source_files(repository: Path) -> list[tuple[Path, Path]]:
    """Select runtime source and reviewed data, excluding caches and private artifacts."""
    selected: list[tuple[Path, Path]] = []
    for directory in SOURCE_DIRS:
        base = repository / directory
        if not base.is_dir():
            raise ValueError(f"Required coordinator source directory is missing: {directory}")
        for source in sorted(base.rglob("*")):
            if not source.is_file() or source.is_symlink():
                continue
            if any(part in ("__pycache__", ".pytest_cache", ".git") for part in source.relative_to(repository).parts):
                continue
            if source.suffix not in SOURCE_SUFFIXES and source.name not in ("TAG", ".gitignore"):
                continue
            if ".private." in source.name or source.suffix in (".key", ".pem", ".crt", ".kubeconfig"):
                continue
            selected.append((source, source.relative_to(repository)))
    if not selected:
        raise ValueError("No coordinator runtime source files were found")
    return selected


def source_digest(repository: Path) -> tuple[str, list[tuple[Path, Path]]]:
    """Hash the exact private runtime bundle inputs, including relative filenames."""
    files = source_files(repository)
    digest = hashlib.sha256()
    for source, relative in files:
        digest.update(str(relative).encode())
        digest.update(b"\0")
        digest.update(source.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest(), files


def stage_source_bundle(repository: Path, private_root: Path) -> tuple[Path, str]:
    """Copy the runtime source under private storage so launchd needs no Documents access."""
    digest, files = source_digest(repository)
    target = private_root / f"console-worker-source-{digest[:16]}"
    if target.exists():
        if target.is_symlink() or not target.is_dir() or target.stat().st_mode & 0o077:
            raise ValueError("Existing coordinator source bundle is not private")
        return target, digest
    temporary = private_root / f".console-worker-source-{digest[:16]}.tmp"
    if temporary.exists():
        raise ValueError("Incomplete coordinator source bundle requires operator review")
    temporary.mkdir(mode=0o700)
    try:
        for source, relative in files:
            destination = temporary / relative
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
            os.chmod(destination, 0o600)
        for directory in (temporary, *(path for path in temporary.rglob("*") if path.is_dir())):
            os.chmod(directory, 0o700)
        temporary.rename(target)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return target, digest


def definition(environment_file: Path, private_root: Path, bundle: Path, label: str = LABEL) -> dict[str, object]:
    """Build a user-only, auto-restarting service definition with path references only."""
    env, root, _ = paths(environment_file, private_root, label)
    launcher = bundle / "scripts" / "identity_demo" / "identity_demo_console_launch.sh"
    if not launcher.is_file():
        raise ValueError("Coordinator launcher is missing from the private source bundle")
    return {
        "Label": label,
        "ProgramArguments": ["/bin/bash", str(launcher)],
        "WorkingDirectory": str(bundle),
        "EnvironmentVariables": {"DEMO_OPERATOR_ENV_FILE": str(env), **({"DEMO_SERVICE_MODE": "preparer"} if label == PREPARER_LABEL else {})},
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 30,
        "ProcessType": "Background",
        "StandardOutPath": str(root / ("console-preparer.launchd.stdout.log" if label == PREPARER_LABEL else "console-worker.launchd.stdout.log")),
        "StandardErrorPath": str(root / ("console-preparer.launchd.stderr.log" if label == PREPARER_LABEL else "console-worker.launchd.stderr.log")),
    }



def ensure_started(plist_path: Path, label: str = LABEL) -> None:
    """Require a positively loaded owned service; never mistake a pending bootout for success."""
    target = f"{service_domain()}/{label}"
    launchctl("enable", target)
    if launchctl("print", target, check=False).returncode != 0:
        launchctl("bootstrap", service_domain(), str(plist_path))
    launchctl("kickstart", target)  # No -k: never interrupt an already-running job.
    if launchctl("print", target, check=False).returncode != 0:
        raise RuntimeError("Coordinator LaunchAgent was not loaded after startup")


def wait_unloaded(label: str = LABEL) -> None:
    """Finish the exact service's removal before replacing its on-disk definition."""
    target = f"{service_domain()}/{label}"
    deadline = time.monotonic() + 20
    while launchctl("print", target, check=False).returncode == 0:
        if time.monotonic() >= deadline:
            raise RuntimeError("Coordinator service removal is still pending; preserve its definition")
        time.sleep(.2)


def install(environment_file: Path, private_root: Path, label: str = LABEL) -> Path:
    """Install only this exact user agent and start it without disrupting an existing one."""
    env, root, plist_path = paths(environment_file, private_root, label)
    bundle, _ = stage_source_bundle(Path(__file__).resolve().parents[2], root)
    target = definition(env, root, bundle, label)
    plist_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if plist_path.exists():
        with plist_path.open("rb") as stream:
            existing = plistlib.load(stream)
        if existing != target:
            raise ValueError(f"Refusing to replace a different launch agent at {plist_path}")
    else:
        temporary = plist_path.with_suffix(".plist.tmp")
        with temporary.open("wb") as stream:
            plistlib.dump(target, stream, fmt=plistlib.FMT_XML, sort_keys=True)
        os.chmod(temporary, 0o600)
        temporary.replace(plist_path)
    ensure_started(plist_path, label)
    return plist_path


def main() -> int:
    """Provide safe install, status, start, stop and uninstall operations."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--service", choices=("coordinator", "preparer"), default="coordinator")
    parser.add_argument("--action", choices=("install", "status", "start", "stop", "uninstall", "plan"), required=True)
    parser.add_argument("--environment-file", type=Path, required=True,
                        help="Private path-only shell environment file; credentials stay in referenced files")
    parser.add_argument("--private-root", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("The persistent user service is supported on macOS only")
    label = PREPARER_LABEL if args.service == "preparer" else LABEL
    try:
        _, _, plist_path = paths(args.environment_file, args.private_root, label)
        domain = service_domain()
        if args.action == "plan":
            env, root, _ = paths(args.environment_file, args.private_root, label)
            digest, _ = source_digest(Path(__file__).resolve().parents[2])
            if not (Path(__file__).resolve().parents[2] / "scripts/identity_demo/identity_demo_console_launch.sh").is_file():
                raise ValueError("Coordinator launcher is missing from the repository")
            print(f"ready: {label} user LaunchAgent; private references validated; source digest {digest[:16]}")
        elif args.action == "install":
            install(args.environment_file, args.private_root, label)
            print(f"installed: {label}; launchd will keep it running in the logged-in user session")
        elif args.action == "status":
            loaded = launchctl("print", f"{domain}/{label}", check=False).returncode == 0
            print(f"{'loaded' if loaded else 'not loaded'}: {label}; plist={'present' if plist_path.is_file() else 'missing'}")
        elif args.action == "start":
            if not plist_path.is_file():
                raise ValueError("LaunchAgent is not installed")
            ensure_started(plist_path, label)
            print(f"started: {label}")
        elif args.action == "stop":
            result = launchctl("bootout", f"{domain}/{label}", check=False)
            if result.returncode and "Could not find service" not in result.stderr:
                raise RuntimeError("Could not stop the coordinator LaunchAgent")
            wait_unloaded(label)
            print(f"stopped: {label}; the agent remains installed for next login")
        else:
            result = launchctl("bootout", f"{domain}/{label}", check=False)
            if result.returncode and "Could not find service" not in result.stderr:
                raise RuntimeError("Could not stop the coordinator LaunchAgent")
            wait_unloaded(label)
            if plist_path.exists():
                plist_path.unlink()
            launchctl("disable", f"{domain}/{label}", check=False)
            print(f"removed: {label}")
    except (OSError, ValueError, RuntimeError, plistlib.InvalidFileException) as error:
        print(f"coordinator service operation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
