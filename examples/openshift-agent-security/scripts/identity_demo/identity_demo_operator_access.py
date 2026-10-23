# SPDX-License-Identifier: Apache-2.0
"""Check exact OpenShift operator-token lifetime; optionally renew private login.

Never changes cluster permissions, human/run deadlines or dispatched operations.
Renewal writes only the selected existing user's token in a private kubeconfig.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time

import yaml
import jwt

from deployment_profile import active_profile
from identity_demo_runtime_cli import private_path

MINIMUM_SECONDS = 1020  # Ten-minute human window + cleanup + preflight margin.
_retry_after: dict[str, float] = {}


def runtime_arguments(parser: argparse.ArgumentParser) -> None:
    """Expose explicit projected-identity inputs without changing local defaults."""
    parser.add_argument("--namespace-capacity-budget-file", help="Complete measured workload and supervisor quota budget")
    for option in ("service-account-token-file", "service-account-token-root",
                   "service-account-namespace", "service-account-name", "pod-uid"):
        parser.add_argument("--" + option)


class OperatorAccessUnavailable(RuntimeError):
    """Access cannot be proved long enough to start and clean up another run."""


def command(args: argparse.Namespace, *words: str, stdin: str | None = None) -> str:
    """Bound CLI calls and withhold all raw credential/error output."""
    result = subprocess.run(
        ["oc", "--kubeconfig", args.kubeconfig, "--request-timeout=20s", *words],
        input=stdin,
        capture_output=True,
        text=True,
        timeout=35,
    )
    if result.returncode:
        raise OperatorAccessUnavailable(
            "Operator access check failed; details withheld"
        )
    if len(result.stdout) > 1048576:
        raise OperatorAccessUnavailable("Bounded operator response required")
    return result.stdout


def selected(args: argparse.Namespace) -> dict:
    """Require a private static-token context on the selected verified TLS server."""
    private_path(args.kubeconfig)
    config = json.loads(
        command(args, "config", "view", "--raw", "--minify", "-o", "json")
    )
    if (
        args.expected_server != active_profile().expected_server
        or len(config.get("clusters", [])) != 1
        or len(config.get("users", [])) != 1
        or len(config.get("contexts", [])) != 1
    ):
        raise OperatorAccessUnavailable("One exact selected operator context required")
    cluster = config["clusters"][0]["cluster"]
    user = config["users"][0]["user"]
    if (
        cluster.get("server") != args.expected_server
        or cluster.get("insecure-skip-tls-verify")
        or cluster.get("proxy-url")
        or user.get("exec")
        or user.get("auth-provider")
    ):
        raise OperatorAccessUnavailable(
            "Exact TLS-verified OpenShift token context required"
        )
    if getattr(args, "service_account_token_file", None):
        if user.get("token") or user.get("tokenFile") != args.service_account_token_file:
            raise OperatorAccessUnavailable("Exact projected token file required")
    elif (not isinstance(user.get("token"), str) or not user["token"].startswith("sha256~")
          or len(user["token"]) != 50 or user.get("tokenFile")):
        raise OperatorAccessUnavailable("Exact TLS-verified OpenShift token context required")
    return config


def projected_expiration(args: argparse.Namespace, config: dict) -> int:
    """API-authenticate the exact Pod-bound identity; never renew or copy its token.

    The unverified JWT supplies lifetime/Pod consistency information only. The
    TLS-verified Kubernetes API authenticates the actual projected credential.
    Kubelet's atomic symlinks are allowed only inside the configured token mount.
    """
    try:
        namespace, name = args.service_account_namespace, args.service_account_name
        pod_uid = args.pod_uid
        if (namespace != active_profile().core_namespace
                or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", name)
                or not re.fullmatch(r"[a-f0-9-]{36}", pod_uid)
                or getattr(args, "operator_login_file", None)):
            raise ValueError("Bound runtime identity required")
        path = Path(args.service_account_token_file)
        root = Path(args.service_account_token_root)
        if not path.is_absolute() or not root.is_absolute() or root.is_symlink():
            raise ValueError("Fixed projected volume required")
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(root.resolve(strict=True)):
            raise ValueError("Projected token escaped its mount")
        info = resolved.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022 or not 1 <= info.st_size <= 16384:
            raise ValueError("Bounded read-only projected token required")
        token = resolved.read_text().strip()
        claims = jwt.decode(token, options={"verify_signature": False})
        identity = "system:serviceaccount:" + namespace + ":" + name
        binding = claims["kubernetes.io"]
        now = time.time()
        if (claims.get("sub") != identity or binding.get("namespace") != namespace
                or binding.get("serviceaccount", {}).get("name") != name
                or binding.get("pod", {}).get("uid") != pod_uid
                or type(claims.get("exp")) is not int or type(claims.get("iat")) is not int
                or claims["iat"] > now + 60 or claims["exp"] <= now + MINIMUM_SECONDS
                or claims["exp"] - now > 86400
                or command(args, "whoami").strip() != identity):
            raise ValueError("Projected identity or remaining lifetime rejected")
        return claims["exp"]
    except Exception:
        raise OperatorAccessUnavailable("Projected runtime identity/lifetime unavailable") from None


def expiration(args: argparse.Namespace, config: dict) -> int:
    """Resolve metadata for this exact token, never another user's newer login."""
    if getattr(args, "service_account_token_file", None):
        return projected_expiration(args, config)
    token = config["users"][0]["user"]["token"]
    # OpenShift hashes the secret suffix, excluding its sha256~ format marker.
    name = "sha256~" + base64.urlsafe_b64encode(
        hashlib.sha256(token.removeprefix("sha256~").encode()).digest()
    ).decode().rstrip("=")
    info = json.loads(command(args, "get", "useroauthaccesstokens", name, "-o", "json"))
    lifetime = info.get("expiresIn")
    if (
        info.get("metadata", {}).get("name") != name
        or type(lifetime) is not int
        or not 0 < lifetime <= 31536000
        or not isinstance(info.get("userName"), str)
        or info.get("inactivityTimeoutSeconds") not in (None, 0)
    ):
        raise OperatorAccessUnavailable("Exact bounded operator expiration required")
    return (
        int(
            datetime.fromisoformat(
                info["metadata"]["creationTimestamp"].replace("Z", "+00:00")
            ).timestamp()
        )
        + lifetime
    )


def renew(args: argparse.Namespace, config: dict) -> None:
    """Authenticate once through stdin and atomically replace only the selected token."""
    credential_path = private_path(args.operator_login_file)
    credential = json.loads(credential_path.read_text())
    if (
        set(credential) != {"server", "username", "password"}
        or credential["server"] != args.expected_server
        or credential["username"] != "platform-eng"
        or not isinstance(credential["password"], str)
        or not credential["password"]
        or any(c in credential["password"] for c in ("\r", "\n", "\0"))
    ):
        raise OperatorAccessUnavailable("Approved private operator login required")
    path = private_path(args.kubeconfig)
    original = path.read_bytes()
    full = yaml.safe_load(original)
    user_name = config["users"][0]["name"]
    targets = [u for u in full["users"] if u["name"] == user_name]
    if len(targets) != 1 or targets[0]["user"] != config["users"][0]["user"]:
        raise OperatorAccessUnavailable("Operator context changed before refresh")
    with tempfile.TemporaryDirectory(
        prefix="identity-demo-login-", dir=path.parent
    ) as directory:
        temporary = Path(directory) / "kubeconfig"
        clean = json.loads(json.dumps(config))
        clean["users"][0]["user"] = {}
        temporary.write_text(json.dumps(clean))
        temporary.chmod(0o600)
        request = argparse.Namespace(
            kubeconfig=str(temporary), expected_server=args.expected_server
        )
        # Password is not an argument, environment variable, receipt or log line.
        command(
            request,
            "login",
            "--server=" + args.expected_server,
            "--username=" + credential["username"],
            stdin=credential["password"] + "\n",
        )
        fresh = selected(request)
        who = command(request, "whoami").strip()
        if (
            who != credential["username"]
            or expiration(request, fresh) < time.time() + MINIMUM_SECONDS
        ):
            raise OperatorAccessUnavailable(
                "Renewed operator identity/lifetime rejected"
            )
        targets[0]["user"]["token"] = fresh["users"][0]["user"]["token"]
        if path.read_bytes() != original:
            raise OperatorAccessUnavailable(
                "Operator kubeconfig changed during refresh"
            )
        fd, candidate = tempfile.mkstemp(prefix="operator-kubeconfig-", dir=path.parent)
        try:
            with os.fdopen(fd, "w") as stream:
                yaml.safe_dump(full, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(candidate, path)
        finally:
            if os.path.exists(candidate):
                os.unlink(candidate)


def ensure_access(args: argparse.Namespace) -> int:
    """Prove remaining lifetime; opt-in renewal never replays a dispatched operation."""
    if getattr(args, "service_account_token_file", None):
        return expiration(args, selected(args))
    path = private_path(args.kubeconfig)
    lock_path = path.with_name(path.name + ".identity-demo-auth.lock")
    if lock_path.is_symlink():
        raise OperatorAccessUnavailable("Private operator lock required")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as lock:
        deadline = time.monotonic() + 45
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise OperatorAccessUnavailable(
                        "Operator renewal lock is busy"
                    ) from None
                time.sleep(0.1)
        config = selected(args)
        try:
            expires = expiration(args, config)
            if expires > time.time() + MINIMUM_SECONDS:
                return expires
        except (OperatorAccessUnavailable, ValueError, KeyError):
            pass
        login = getattr(args, "operator_login_file", None)
        if not login or time.monotonic() < _retry_after.get(str(path), 0):
            raise OperatorAccessUnavailable(
                "Operator login renewal required before starting"
            )
        _retry_after[str(path)] = time.monotonic() + 300
        try:
            renew(args, config)
            expires = expiration(args, selected(args))
            if expires <= time.time() + MINIMUM_SECONDS:
                raise OperatorAccessUnavailable(
                    "Operator renewal lifetime insufficient"
                )
            _retry_after.pop(str(path), None)
            return expires
        except Exception:
            raise OperatorAccessUnavailable(
                "Operator renewal failed; no operation replay"
            ) from None
