# SPDX-License-Identifier: Apache-2.0
"""Private database capture, restore verification and ownership failure checks."""

import argparse
import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
from types import SimpleNamespace

import pytest

import deployment_backup as backup
from deployment_profile import LEGACY
import identity_demo_setup as setup


def database() -> bytes:
    """Model retired authorization state, including binary audit data."""
    with sqlite3.connect(":memory:") as connection:
        connection.executescript("CREATE TABLE runs(id TEXT, active INTEGER);"
            "CREATE TABLE actions(id TEXT, state TEXT);CREATE TABLE audit(value BLOB);"
            "INSERT INTO runs VALUES('synthetic-retired',0);"
            "INSERT INTO actions VALUES('synthetic-action','succeeded');"
            "INSERT INTO audit VALUES(X'001122');")
        connection.commit()
        return connection.serialize()


def contents(data: bytes) -> dict:
    """Compute the same private logical receipt as the online backup."""
    with sqlite3.connect(":memory:") as connection:
        connection.deserialize(data)
        return backup.inspect_database(connection)


def saved(tmp_path: Path) -> tuple[Path, str]:
    """Prepare synthetic private source backups, never real credentials."""
    tmp_path.chmod(0o700)
    data = database()
    entries = {}
    for label in backup.DATABASES:
        name = label + ".sqlite"
        backup.exclusive_bytes(tmp_path / name, data)
        entries[label] = {"file": name, "bytes": len(data),
                          "sha256": hashlib.sha256(data).hexdigest(), "contents": contents(data)}
    manifest = tmp_path / "backup.private.json"
    setup.write(manifest, {"schema_version": 1, "kind": "identity-demo-application-data",
                          "profile": LEGACY.to_dict(), "databases": entries})
    return manifest, setup.sha(manifest)


@pytest.mark.parametrize("mode", ["valid", "manifest-hash", "database-hash", "filename", "symlink", "active"])
def test_offline_restore_checks_every_artifact(tmp_path: Path, mode: str) -> None:
    """No path traversal, corrupted backup, or live run is accepted."""
    manifest, digest = saved(tmp_path)
    value = json.loads(manifest.read_text())
    if mode == "manifest-hash":
        digest = "0" * 64
    elif mode == "database-hash":
        (tmp_path / "driver.sqlite").write_bytes(b"corrupt")
    elif mode == "filename":
        value["databases"]["driver"]["file"] = "../outside.sqlite"
    elif mode == "symlink":
        target = tmp_path / "driver.sqlite"
        target.rename(tmp_path / "elsewhere.sqlite")
        target.symlink_to(tmp_path / "elsewhere.sqlite")
    elif mode == "active":
        path = tmp_path / "driver.sqlite"
        with sqlite3.connect(path) as connection:
            connection.execute("UPDATE runs SET active=1")
        data = path.read_bytes()
        value["databases"]["driver"].update(bytes=len(data),
            sha256=hashlib.sha256(data).hexdigest(), contents=contents(data))
    if mode in {"filename", "active"}:
        manifest.write_text(json.dumps(value))
        digest = setup.sha(manifest)
    out = tmp_path / "verification"
    out.mkdir(mode=0o700)
    args = argparse.Namespace(backup_manifest=str(manifest), backup_sha256=digest, output_dir=out)
    if mode != "valid":
        with pytest.raises(ValueError):
            backup.verify_backup(args)
        assert not (out / "restore-verification.private.json").exists()
    else:
        result = backup.verify_backup(args)
        assert result["restored_database_copies_verified"] and not result["cluster_contacted"]
        assert not result["complete_platform_recovery_proven"]
        for label in backup.DATABASES:
            target = out / (label + ".restored.sqlite")
            assert target.read_bytes() == (tmp_path / (label + ".sqlite")).read_bytes()
            assert target.stat().st_mode & 0o077 == 0
        with pytest.raises(FileExistsError):
            backup.verify_backup(args)


def test_online_snapshot_includes_committed_wal(tmp_path: Path) -> None:
    """A SQLite backup captures committed WAL rows without copying live files."""
    path = tmp_path / "source.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("CREATE TABLE example(value BLOB)")
        connection.execute("INSERT INTO example VALUES(?)", (b"synthetic",))
        connection.commit()
        assert Path(str(path) + "-wal").is_file()
        # Only replace the fixed reviewed path in this isolated test program.
        program = backup.snapshot_program("/data/jira.db").replace(repr("/data/jira.db"), repr(str(path)))
        result = subprocess.run([sys.executable, "-c", program], capture_output=True, timeout=10)
        assert result.returncode == 0
        capture = json.loads(result.stdout)
        data = base64.b64decode(capture["database_base64"])
        assert contents(data) == capture["contents"]
        assert capture["contents"]["tables"]["example"]["count"] == 1
        assert b"synthetic" not in result.stdout


@pytest.mark.parametrize("mode", ["valid", "unowned", "ephemeral", "wrong-pod", "changed", "busy"])
def test_live_capture_is_owned_durable_and_stable(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    """Only exact application owner chains/PVCs can be read; no mutations occur."""
    args = argparse.Namespace(profile=LEGACY, output_dir=tmp_path)
    reads = []
    def call(options: object, *words: str, value: dict | None = None) -> dict:
        reads.append(words)
        assert words[0] == "get"
        kind, name = words[1:3]
        metadata = {"name": name, "uid": "uid-" + name, "labels": dict(LEGACY.labels)}
        if mode == "unowned":
            metadata["labels"] = {}
        if kind == "namespace":
            return {"metadata": metadata}
        if kind == "deployment":
            _, container, _, volume = next(v for v in backup.DATABASES.values() if v[0] == name)
            mount = "/state" if volume == "state" else "/data"
            storage = {"name": volume, "persistentVolumeClaim": {"claimName": "fixture-data"}}
            if mode == "ephemeral":
                storage = {"name": volume, "emptyDir": {}}
            spec = {"containers": [{"name": container, "image": "example@sha256:" + "a" * 64,
                                   "volumeMounts": [{"name": volume, "mountPath": mount}]}], "volumes": [storage]}
            return {"metadata": metadata, "spec": {"selector": {"matchLabels": {"app": name}},
                                                    "template": {"spec": spec}}}
        if kind == "pvc":
            return {"metadata": metadata, "status": {"phase": "Bound"}}
        if kind == "pods":
            deployment = words[words.index("-l") + 1].split("=", 1)[1]
            pod = call(options, "get", "deployment", deployment)
            return {"items": [{"metadata": {"name": deployment + "-pod", "uid": "uid-pod",
                "ownerReferences": [{"kind": "ReplicaSet", "name": deployment, "uid": "uid-" + deployment}]},
                "spec": pod["spec"]["template"]["spec"],
                "status": {"conditions": [{"type": "Ready", "status": "True"}]}}]}
        if kind == "replicaset":
            return {"metadata": {**metadata, "ownerReferences": [{"kind": "Deployment",
                "uid": "wrong" if mode == "wrong-pod" else "uid-" + name}]}}
        raise AssertionError(kind)
    captures = []
    def snapshot(options: object, pod: dict, container: str, path: str) -> tuple[bytes, dict]:
        captures.append(container)
        data = database()
        result = deepcopy(contents(data))
        if mode == "changed" and len(captures) > 2:
            result["schema_sha256"] = "changed"
        return data, result
    monkeypatch.setattr(setup, "kube", call)
    monkeypatch.setattr(backup, "snapshot_database", snapshot)
    if mode == "busy":
        monkeypatch.setattr(backup, "lifecycle", lambda data: {"active_runs": 1, "uncertain_actions": 0})
    if mode == "valid":
        result = backup.backup_data(args)
        assert result["application_data_captured"] and not result["cluster_resources_changed"]
        assert (tmp_path / "backup.private.json").exists()
        assert len(captures) == 4
    else:
        with pytest.raises(ValueError):
            backup.backup_data(args)
        assert not (tmp_path / "backup.private.json").exists()


@pytest.mark.parametrize("mode", ["plan", "apply", "changed", "wrong-installation", "outage"])
def test_restart_requires_verified_current_backup(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    """Only exact backed-up Deployments restart; errors never imply recovery."""
    source = tmp_path / "source"
    source.mkdir(mode=0o700)
    manifest_path, _ = saved(source)
    manifest = json.loads(manifest_path.read_text())
    for label, value in manifest["databases"].items():
        value.update(controller_uid="controller-" + label, pod_uid="pod-" + label,
                     pvc_uid="pvc-" + label, image="example@sha256:" + "a" * 64)
    manifest_path.write_text(json.dumps(manifest))
    digest = setup.sha(manifest_path)
    out = tmp_path / "restart"
    out.mkdir(mode=0o700)
    args = argparse.Namespace(backup_manifest=str(manifest_path), backup_sha256=digest,
                             output_dir=out, profile=LEGACY, apply=mode != "plan", oc="oc", kubeconfig="private")
    if mode == "wrong-installation":
        from deployment_profile import DeploymentProfile
        args.profile = DeploymentProfile.from_dict({**LEGACY.to_dict(), "core_namespace": "another-eval"})
    events = []
    def capture(options: argparse.Namespace) -> dict:
        value = deepcopy(manifest)
        if mode == "changed":
            value["databases"]["driver"]["contents"]["schema_sha256"] = "changed"
        if options.output_dir.name == "after":
            for entry in value["databases"].values():
                entry["pod_uid"] += "-replacement"
        setup.write(options.output_dir / "backup.private.json", value)
        return {}
    def call(options: object, *words: str, value: dict | list | None = None) -> dict:
        events.append(words)
        name = words[2]
        label = next(k for k, v in backup.DATABASES.items() if v[0] == name)
        obj = {"metadata": {"name": name, "uid": "controller-" + label,
                            "resourceVersion": "1", "labels": dict(LEGACY.labels)},
               "spec": {"replicas": 1, "template": {"metadata": {}}}}
        if words[0] == "patch":
            assert [item["path"] for item in value[:3]] == ["/metadata/uid", "/metadata/resourceVersion", "/spec"]
            assert all(item["op"] == "test" for item in value[:3])
            assert words[words.index("-n") + 1] == LEGACY.core_namespace
        return obj
    monkeypatch.setattr(backup, "backup_data", capture)
    monkeypatch.setattr(setup, "kube", call)
    monkeypatch.setattr(backup.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=1 if mode == "outage" else 0))
    if mode in {"changed", "wrong-installation", "outage"}:
        with pytest.raises((ValueError, RuntimeError)):
            backup.restart_data(args)
        if mode != "outage":
            assert not any(e[0] == "patch" for e in events)
    else:
        result = backup.restart_data(args)
        assert result["applied"] == (mode == "apply")
        mutations = [e for e in events if e[0] == "patch" and "--dry-run=server" not in e]
        assert len(mutations) == (2 if mode == "apply" else 0)
        if mode == "apply":
            assert result["all_tables_and_schema_preserved"] and not result["live_restore_performed"]


def test_idle_backup_exception_never_ignores_audit_or_pool_changes():
    import copy
    before={'schema_sha256':'same','tables':{
        'console_worker':{'count':1,'sha256':'old'},'audit':{'count':4,'sha256':'audit'},
        'runs':{'count':1,'sha256':'runs'},'console_pool_items':{'count':8,'sha256':'pool'}}}
    before['stable_heartbeat']={'console_worker':{'count':1,'sha256':'stable non-timestamp fields'}}
    after=copy.deepcopy(before);after['tables']['console_worker']['sha256']='heartbeat'
    assert not backup.unchanged_backup_data(before,after)
    assert backup.unchanged_backup_data(before,after,idle_heartbeat=True)
    for table in ('audit','runs','console_pool_items'):
        changed=copy.deepcopy(after);changed['tables'][table]['sha256']='changed'
        assert not backup.unchanged_backup_data(before,changed,idle_heartbeat=True)
    changed=copy.deepcopy(after);changed['schema_sha256']='changed'
    assert not backup.unchanged_backup_data(before,changed,idle_heartbeat=True)


def test_idle_backup_still_checks_non_timestamp_worker_fields(tmp_path):
    import sqlite3
    database=sqlite3.connect(':memory:')
    database.executescript("CREATE TABLE console_worker(id,worker,updated,phase); INSERT INTO console_worker VALUES(1,'owner',1,'ready'); CREATE TABLE console_preparer(id,updated); INSERT INTO console_preparer VALUES(1,1);")
    before=backup.inspect_database(database,idle_heartbeat=True)
    database.execute('UPDATE console_worker SET updated=2')
    database.execute('UPDATE console_preparer SET updated=2')
    after=backup.inspect_database(database,idle_heartbeat=True)
    assert backup.unchanged_backup_data(before,after,idle_heartbeat=True)
    database.execute("UPDATE console_worker SET phase='blocked'")
    assert not backup.unchanged_backup_data(before,backup.inspect_database(database,idle_heartbeat=True),idle_heartbeat=True)
