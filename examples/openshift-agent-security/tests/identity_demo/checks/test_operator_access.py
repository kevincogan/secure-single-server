# SPDX-License-Identifier: Apache-2.0
"""Operator expiry is checked for the exact token before run admission."""

from argparse import Namespace
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time

import pytest
import yaml

from deployment_profile import active_profile
import identity_demo_operator_access as access
import identity_demo_console_worker as worker
import identity_demo_console as console


def inputs(tmp_path):
    token = "sha256~" + "a" * 43
    server = active_profile().expected_server
    config = {
        "apiVersion": "v1",
        "kind": "Config",
        "current-context": "selected",
        "contexts": [
            {"name": "selected", "context": {"cluster": "owned", "user": "operator"}}
        ],
        "clusters": [{"name": "owned", "cluster": {"server": server}}],
        "users": [{"name": "operator", "user": {"token": token}}],
    }
    path = tmp_path / "kubeconfig"
    path.write_text(json.dumps(config))
    path.chmod(0o600)
    return Namespace(
        kubeconfig=str(path), expected_server=server, operator_login_file=None
    ), config


def metadata(config, remaining=3600):
    token = config["users"][0]["user"]["token"]
    name = "sha256~" + base64.urlsafe_b64encode(
        hashlib.sha256(token[7:].encode()).digest()
    ).decode().rstrip("=")
    return {
        "metadata": {
            "name": name,
            "creationTimestamp": datetime.fromtimestamp(
                int(time.time()) - 100, timezone.utc
            ).isoformat(),
        },
        "userName": "platform-eng",
        "expiresIn": remaining + 100,
    }


def test_exact_token_metadata_not_another_newer_login(tmp_path, monkeypatch):
    args, config = inputs(tmp_path)
    observed = []

    def command(_, *words, **kwargs):
        observed.append(words)
        return json.dumps(config if words[0] == "config" else metadata(config))

    monkeypatch.setattr(access, "command", command)
    assert access.ensure_access(args) > time.time() + 3500
    assert observed[1][:2] == ("get", "useroauthaccesstokens")
    assert config["users"][0]["user"]["token"] not in observed[1]


@pytest.mark.parametrize("remaining", [0, 10, 600, 1010])
def test_insufficient_lifetime_refuses_before_any_renewal_without_opt_in(
    tmp_path, monkeypatch, remaining
):
    args, config = inputs(tmp_path)
    monkeypatch.setattr(
        access,
        "command",
        lambda _, *words, **kw: json.dumps(
            config if words[0] == "config" else metadata(config, remaining)
        ),
    )
    monkeypatch.setattr(
        access, "renew", lambda *a: pytest.fail("no renewal permission")
    )
    with pytest.raises(access.OperatorAccessUnavailable):
        access.ensure_access(args)


@pytest.mark.parametrize("change", ["server", "tls", "proxy", "exec", "token"])
def test_wrong_target_or_insecure_profile_never_reaches_login(
    tmp_path, monkeypatch, change
):
    args, config = inputs(tmp_path)
    if change == "server":
        config["clusters"][0]["cluster"]["server"] = "https://foreign.invalid"
    elif change == "tls":
        config["clusters"][0]["cluster"]["insecure-skip-tls-verify"] = True
    elif change == "proxy":
        config["clusters"][0]["cluster"]["proxy-url"] = "https://foreign.invalid"
    elif change == "exec":
        config["users"][0]["user"]["exec"] = {"command": "untrusted"}
    else:
        config["users"][0]["user"]["token"] = "unknown"
    monkeypatch.setattr(access, "command", lambda *a, **kw: json.dumps(config))
    with pytest.raises(access.OperatorAccessUnavailable):
        access.ensure_access(args)


@pytest.mark.parametrize("change", ["foreign_token", "missing_expiry", "inactivity"])
def test_unknown_expiry_is_not_accepted(tmp_path, monkeypatch, change):
    args, config = inputs(tmp_path)
    info = metadata(config)
    if change == "foreign_token":
        info["metadata"]["name"] = "foreign"
    elif change == "missing_expiry":
        info.pop("expiresIn")
    else:
        info["inactivityTimeoutSeconds"] = 10
    monkeypatch.setattr(access, "command", lambda *a, **kw: json.dumps(info))
    with pytest.raises(access.OperatorAccessUnavailable):
        access.expiration(args, config)


def test_renewal_uses_stdin_preserves_other_contexts_and_atomic_private_file(
    tmp_path, monkeypatch
):
    args, config = inputs(tmp_path)
    full = json.loads(json.dumps(config))
    full["users"].append({"name": "foreign", "user": {"token": "untouched"}})
    Path(args.kubeconfig).write_text(yaml.safe_dump(full))
    login = tmp_path / "login.private.json"
    login.write_text(
        json.dumps(
            {
                "server": args.expected_server,
                "username": "platform-eng",
                "password": "private-password",
            }
        )
    )
    login.chmod(0o600)
    args.operator_login_file = str(login)
    fresh = json.loads(json.dumps(config))
    fresh["users"][0]["user"]["token"] = "sha256~" + "b" * 43
    calls = []

    def command(request, *words, stdin=None):
        calls.append(words)
        if words[0] == "login":
            assert (
                stdin == "private-password\n" and request.kubeconfig != args.kubeconfig
            )
            assert (
                "token"
                not in json.loads(Path(request.kubeconfig).read_text())["users"][0][
                    "user"
                ]
            )
            return ""
        if words[0] == "config":
            return json.dumps(fresh)
        if words[0] == "whoami":
            return "platform-eng\n"
        return json.dumps(metadata(fresh))

    monkeypatch.setattr(access, "command", command)
    access.renew(args, config)
    after = yaml.safe_load(Path(args.kubeconfig).read_text())
    assert (
        after["users"][0]["user"] == fresh["users"][0]["user"]
        and after["users"][1] == full["users"][1]
    )
    assert (
        after["clusters"] == full["clusters"] and after["contexts"] == full["contexts"]
    )
    assert not Path(args.kubeconfig).stat().st_mode & 0o077
    assert "private-password" not in repr(calls)


def test_bad_refresh_is_bounded_and_never_dispatches_operations(tmp_path, monkeypatch):
    args, config = inputs(tmp_path)
    args.operator_login_file = "private"
    monkeypatch.setattr(access, "selected", lambda _: config)
    monkeypatch.setattr(access, "expiration", lambda *a: 0)
    attempts = []

    def renew(*a):
        attempts.append(True)
        raise RuntimeError("private-value")

    monkeypatch.setattr(access, "renew", renew)
    for _ in range(2):
        with pytest.raises(access.OperatorAccessUnavailable) as error:
            access.ensure_access(args)
        assert "private-value" not in str(error.value)
    assert len(attempts) == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("recovery_required", True),
        ("uncertain", 1),
        ("running", 1),
        ("busy", True),
        ("preparing_context", True),
        ("online", False),
    ],
)
def test_reviewed_recovery_does_not_override_unresolved_work(field, value):
    state = {
        "enabled": True,
        "online": True,
        "running": 0,
        "uncertain": 0,
        "busy": False,
        "preparing_context": False,
        "recovery_required": False,
    }
    state[field] = value
    control = worker.Control("synthetic")
    control.request = lambda _: state
    assert worker.recover_reviewed_cleanup(control) is False


def test_reviewed_cleanup_can_resume_without_restarting_or_replaying_job():
    control = worker.Control("synthetic")
    control.request = lambda _: {
        "enabled": True,
        "online": True,
        "running": 0,
        "uncertain": 0,
        "busy": False,
        "preparing_context": False,
        "recovery_required": False,
    }
    assert worker.recover_reviewed_cleanup(control)


def test_missing_sandbox_message_does_not_promise_preparation_during_recovery():
    assert "paused" in console.missing_context_hint(
        {"online": True, "auto_prepare": True, "recovery_required": True}
    )
    assert "automatically" not in console.missing_context_hint(
        {"online": True, "phase": "blocked", "auto_prepare": True}
    )


def test_operator_refresh_lock_wait_is_bounded(tmp_path, monkeypatch):
    args, _ = inputs(tmp_path)
    monkeypatch.setattr(
        access.fcntl, "flock", lambda *a: (_ for _ in ()).throw(BlockingIOError())
    )
    ticks = iter([0, 46])
    monkeypatch.setattr(access.time, "monotonic", lambda: next(ticks))
    with pytest.raises(access.OperatorAccessUnavailable, match="lock is busy"):
        access.ensure_access(args)


def test_readiness_refuses_short_operator_access_before_any_cluster_mutation(
    tmp_path, monkeypatch
):
    args = Namespace(operator_access_check=True)
    control = worker.Control("synthetic")
    control.publish = lambda: None
    monkeypatch.setattr(
        access,
        "ensure_access",
        lambda _: (_ for _ in ()).throw(
            access.OperatorAccessUnavailable("renewal required")
        ),
    )
    monkeypatch.setattr(
        worker,
        "guard",
        lambda _: pytest.fail(
            "no cluster mutation/check should follow failed admission"
        ),
    )
    assert worker.readiness_check(args, control) is False
    assert (
        control.readiness["phase"] == "blocked"
        and control.readiness["reason"] == "operator_login"
    )


def test_preparation_authentication_failure_has_no_mutation_checkpoint(
    tmp_path, monkeypatch
):
    import identity_demo_console_preparer as preparer

    args = Namespace(output_dir=tmp_path, operator_access_check=True)
    monkeypatch.setattr(
        access,
        "ensure_access",
        lambda _: (_ for _ in ()).throw(
            access.OperatorAccessUnavailable("renewal required")
        ),
    )
    reservation = {"id": "owned-reservation", "target": {}}
    with pytest.raises(access.OperatorAccessUnavailable):
        preparer.prepare_one(args, None, "owned", reservation)
    assert not (tmp_path / "owned-reservation/checkpoint.private.json").exists()
