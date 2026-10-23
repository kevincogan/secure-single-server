# SPDX-License-Identifier: Apache-2.0
"""Private SQLite application snapshots and offline restore verification.

This is deliberately not a complete platform backup. Keycloak, native runtime,
keys, configuration and retained workspace volumes require separate recovery.
Never roll a live authorization database back to an older snapshot implicitly.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import uuid

from deployment_profile import DeploymentProfile

LIMIT = 64 * 1024 * 1024
DATABASES = {
    "driver": ("fixture-identity-driver", "driver", "/state/private/runs.db", "state"),
    "jira": ("fixture-jira", "fixture-jira", "/data/jira.db", "data"),
}

# The same manifest implementation runs inside the existing application images
# and on the operator host. Raw rows are hashed privately, never printed.
INSPECT = '''
def inspect_database(connection,idle_heartbeat=False):
    import base64,hashlib,json
    if connection.execute('PRAGMA integrity_check').fetchall()!=[('ok',)]:
        raise ValueError('SQLite integrity check failed')
    if connection.execute('PRAGMA foreign_key_check').fetchone() is not None:
        raise ValueError('SQLite foreign key check failed')
    def normalized(value):
        return {'sqlite_blob_base64':base64.b64encode(value).decode()} if isinstance(value,bytes) else value
    tables={}
    for (name,) in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
        quoted='"'+name.replace('"','""')+'"'
        rows=[json.dumps([normalized(v) for v in row],sort_keys=True,separators=(',',':'))
              for row in connection.execute('SELECT * FROM '+quoted)]
        tables[name]={'count':len(rows),'sha256':hashlib.sha256(json.dumps(sorted(rows),separators=(',',':')).encode()).hexdigest()}
    schema=connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name").fetchall()
    result={'tables':tables,'schema_sha256':hashlib.sha256(json.dumps(schema,separators=(',',':')).encode()).hexdigest()}
    if idle_heartbeat:
        stable={}
        for name in ('console_worker','console_preparer'):
            if name not in tables: continue
            columns=[r[1] for r in connection.execute('PRAGMA table_info('+name+')') if r[1]!='updated']
            query='SELECT '+','.join('"'+c.replace('"','""')+'"' for c in columns)+' FROM '+name
            rows=[json.dumps([normalized(v) for v in row],sort_keys=True,separators=(',',':')) for row in connection.execute(query)]
            stable[name]={'count':len(rows),'sha256':hashlib.sha256(json.dumps(sorted(rows),separators=(',',':')).encode()).hexdigest()}
        result['stable_heartbeat']=stable
    return result
'''


def inspect_database(connection: sqlite3.Connection, *, idle_heartbeat: bool = False) -> dict:
    """Compare all table contents/schema without exposing rows in receipts."""
    scope = {}
    exec(INSPECT, scope)  # Fixed repository source, never configuration input.
    return scope["inspect_database"](connection,idle_heartbeat)


def exclusive_bytes(path: Path, data: bytes) -> None:
    """Write confidential database bytes once with owner-only permissions."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def snapshot_program(path: str, *, idle_heartbeat: bool = False) -> str:
    """Use SQLite's online backup API, including committed WAL data."""
    if path not in {item[2] for item in DATABASES.values()}:
        raise ValueError("Reviewed database path required")
    return ("import sqlite3,json,base64,os,time,tempfile\n" + INSPECT + "\n"
            "path=" + repr(path) + "\n"
            "if not os.path.isfile(path) or os.path.getsize(path)>67108864:\n"
            "    raise ValueError('Bounded database file required')\n"
            "os.umask(0o077)\n"
            "deadline=time.monotonic()+20\n"
            "def progress(status,remaining,total):\n"
            "    if time.monotonic()>deadline: raise TimeoutError('Backup deadline exceeded')\n"
            "with tempfile.TemporaryDirectory(prefix='identity-backup-') as directory:\n"
            "    source=sqlite3.connect('file:'+path+'?mode=ro',uri=True,timeout=5)\n"
            "    copy=sqlite3.connect(directory+'/snapshot.sqlite')\n"
            "    try:\n"
            "        source.backup(copy,pages=128,progress=progress,sleep=0.05)\n"
            "        copy.execute('PRAGMA journal_mode=DELETE')\n"
            "        manifest=inspect_database(copy," + repr(idle_heartbeat) + ")\n"
            "        payload=copy.serialize()\n"
            "        if len(payload)>67108864: raise ValueError('Backup too large')\n"
            "    finally:\n"
            "        copy.close()\n"
            "        source.close()\n"
            "print(json.dumps({'database_base64':base64.b64encode(payload).decode(),'contents':manifest}))\n")


def snapshot_database(args: argparse.Namespace, pod: dict, container: str, path: str) -> tuple[bytes, dict]:
    """Capture only an exact validated Pod/container; withhold raw failures."""
    result = subprocess.run([args.oc, "--kubeconfig", args.kubeconfig, "-n",
        args.profile.core_namespace, "exec", pod["metadata"]["name"], "-c", container,
        "--", "python", "-c", snapshot_program(path, idle_heartbeat=bool(getattr(args,"allow_idle_heartbeat",False)))], capture_output=True, timeout=35)
    if result.returncode or len(result.stdout) > LIMIT * 2:
        raise RuntimeError("Private database snapshot failed; response withheld")
    value = json.loads(result.stdout)
    data = base64.b64decode(value["database_base64"], validate=True)
    if not data.startswith(b"SQLite format 3\x00") or len(data) > LIMIT:
        raise ValueError("Bounded SQLite snapshot required")
    return data, value["contents"]


def driver_quiescent(contents: dict) -> None:
    """Require an explicit lifecycle check, in addition to content hashes."""
    if any(contents.get(key) != 0 for key in (
            "active_runs", "uncertain_actions", "active_console_jobs", "active_preparations", "recovery_required")):
        raise ValueError("Quiescent runs, actions, console jobs, preparation and recovery required for backup")


def lifecycle(data: bytes) -> dict:
    """Inspect the captured authorization state, never a separate live instant."""
    with sqlite3.connect(":memory:") as connection:
        connection.deserialize(data)
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        recovery = any(json.loads(row[0]).get('failure_code') == 'recovery_required'
                       and json.loads(row[0]).get('cleanup_verified') is not True
                       for row in connection.execute("SELECT evidence FROM console_jobs WHERE state='failed'")) if 'console_jobs' in tables else False
        return {
            "active_console_jobs": connection.execute("SELECT count(*) FROM console_jobs WHERE state IN ('queued','running')").fetchone()[0] if 'console_jobs' in tables else 0,
            "active_preparations": connection.execute("SELECT count(*) FROM console_preparations WHERE state IN ('preparing','blocked')").fetchone()[0] if 'console_preparations' in tables else 0,
            "recovery_required": int(recovery),
            "active_runs": connection.execute("SELECT count(*) FROM runs WHERE active<>0").fetchone()[0],
            "uncertain_actions": connection.execute(
                "SELECT count(*) FROM actions WHERE state IN ('executing','unknown')").fetchone()[0],
        }


def unchanged_backup_data(before: dict, after: dict, *, idle_heartbeat: bool = False) -> bool:
    """Allow only explicitly selected idle worker heartbeat timestamps to advance.

    Both snapshots must separately pass quiescence checks. Audit, approvals,
    pool lifecycle, consumed identities, schema and every other table remain
    exact. Restore verification still checks ALL captured tables, including the
    captured heartbeat; this never restores an older snapshot over live data.
    """
    if not idle_heartbeat:
        return before == after
    if before.get('schema_sha256') != after.get('schema_sha256'):
        return False
    heartbeat={'console_worker','console_preparer'} & set(before.get('tables',{}))
    if (set(before.get('stable_heartbeat',{})) != heartbeat
            or before.get('stable_heartbeat') != after.get('stable_heartbeat')):
        return False
    return ({k:v for k,v in before.get('tables',{}).items() if k not in heartbeat} ==
            {k:v for k,v in after.get('tables',{}).items() if k not in heartbeat})


def backup_data(args: argparse.Namespace) -> dict:
    """Export stable quiescent application data; change no persistent resources."""
    from identity_demo_setup import kube, owned, write

    profile = args.profile
    owned(kube(args, "get", "namespace", profile.core_namespace, "-o", "json"), profile)
    receipts = {}
    pods = {}
    for label, (name, container, path, volume_name) in DATABASES.items():
        controller = kube(args, "get", "deployment", name, "-n", profile.core_namespace, "-o", "json")
        owned(controller, profile)
        spec = controller["spec"]["template"]["spec"]
        volumes = [v for v in spec["volumes"] if v["name"] == volume_name]
        if len(volumes) != 1 or "persistentVolumeClaim" not in volumes[0]:
            raise ValueError("Durable owned application PVC required; emptyDir backup refused")
        pvc = kube(args, "get", "pvc", volumes[0]["persistentVolumeClaim"]["claimName"],
                   "-n", profile.core_namespace, "-o", "json")
        owned(pvc, profile)
        if pvc.get("status", {}).get("phase") != "Bound":
            raise ValueError("Bound application PVC required")
        selector = controller["spec"]["selector"]
        if selector.get("matchExpressions"):
            raise ValueError("Exact application label selector required")
        selected = kube(args, "get", "pods", "-n", profile.core_namespace, "-l",
            ",".join(k + "=" + v for k, v in sorted(selector["matchLabels"].items())), "-o", "json")["items"]
        if len(selected) != 1:
            raise ValueError("Exactly one application Pod required")
        pod = selected[0]
        owners = pod["metadata"].get("ownerReferences", [])
        if len(owners) != 1 or owners[0].get("kind") != "ReplicaSet":
            raise ValueError("Owned Deployment Pod required")
        replica = kube(args, "get", "replicaset", owners[0]["name"],
                       "-n", profile.core_namespace, "-o", "json")
        if (replica["metadata"]["uid"] != owners[0]["uid"] or not any(
                r.get("uid") == controller["metadata"]["uid"] and r.get("kind") == "Deployment"
                for r in replica["metadata"].get("ownerReferences", []))):
            raise ValueError("Exact Pod-to-Deployment ownership required")
        if (pod["metadata"].get("deletionTimestamp") or not any(
                c.get("type") == "Ready" and c.get("status") == "True"
                for c in pod.get("status", {}).get("conditions", []))):
            raise ValueError("Stable Ready application Pod required")
        # Validate the actual selected Pod, rather than trusting its selector.
        actual = [c for c in pod["spec"]["containers"] if c["name"] == container]
        wanted = [c for c in spec["containers"] if c["name"] == container]
        actual_volumes = [v for v in pod["spec"]["volumes"] if v["name"] == volume_name]
        mount = next((m for m in actual[0].get("volumeMounts", []) if m["name"] == volume_name), {}) if actual else {}
        if (len(actual) != 1 or len(wanted) != 1 or actual[0]["image"] != wanted[0]["image"]
                or "@sha256:" not in actual[0]["image"] or actual_volumes != volumes
                or not path.startswith(mount.get("mountPath", "__missing__") + "/")):
            raise ValueError("Exact pinned application database mount required")
        data, contents = snapshot_database(args, pod, container, path)
        if label == "driver":
            driver_quiescent(lifecycle(data))
        filename = label + ".sqlite"
        exclusive_bytes(args.output_dir / filename, data)
        receipts[label] = {"file": filename, "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(), "contents": contents,
            "controller_uid": controller["metadata"]["uid"], "pod_uid": pod["metadata"]["uid"],
            "pvc_uid": pvc["metadata"]["uid"], "image": actual[0]["image"]}
        pods[label] = pod
    # A second logical comparison detects concurrent data changes. This is not a
    # distributed transaction or a substitute for an operator maintenance window.
    for label, (_, container, path, _) in DATABASES.items():
        data, after = snapshot_database(args, pods[label], container, path)
        if not unchanged_backup_data(receipts[label]["contents"], after,
                idle_heartbeat=label == 'driver' and getattr(args, 'allow_idle_heartbeat', False)):
            before = receipts[label]["contents"]
            write(args.output_dir / 'concurrent-change.receipt.json', {
                'database': label, 'backup_accepted': False,
                'changed_tables': sorted(k for k in set(before['tables']) | set(after['tables'])
                                        if before['tables'].get(k) != after['tables'].get(k)),
                'schema_changed': before['schema_sha256'] != after['schema_sha256']})
            raise ValueError("Application changed during backup; discard incomplete capture")
        if label == "driver":
            driver_quiescent(lifecycle(data))
    manifest = {"schema_version": 1, "kind": "identity-demo-application-data",
        "profile": profile.to_dict(), "created_at": datetime.now(timezone.utc).isoformat(),
        "databases": receipts, "complete_platform_backup": False,
        "requires_operator_maintenance_window": True,
        "idle_worker_heartbeat_may_advance": bool(getattr(args, 'allow_idle_heartbeat', False)),
        "excludes": ["keycloak", "openshell", "secrets", "configuration", "workspaces", "spire"]}
    write(args.output_dir / "backup.private.json", manifest)
    return {"application_data_captured": True, "databases": list(receipts),
            "manifest_sha256": hashlib.sha256((args.output_dir / "backup.private.json").read_bytes()).hexdigest(),
            "cluster_resources_changed": False, "complete_platform_backup": False,
            "live_restore_performed": False}


def verify_backup(args: argparse.Namespace) -> dict:
    """Restore to new private local files and compare every table/schema/hash."""
    from identity_demo_setup import private_file, sha, write

    manifest_path = private_file(args.backup_manifest)
    if not args.backup_sha256 or sha(manifest_path) != args.backup_sha256:
        raise ValueError("Exact backup manifest hash required")
    manifest = json.loads(manifest_path.read_text())
    if (manifest.get("schema_version") != 1 or manifest.get("kind") != "identity-demo-application-data"
            or set(manifest.get("databases", {})) != set(DATABASES)):
        raise ValueError("Exact application-data backup schema required")
    DeploymentProfile.from_dict(manifest["profile"])
    for label, entry in manifest["databases"].items():
        if entry["file"] != label + ".sqlite":
            raise ValueError("Exact backup filename required")
        path = private_file(str(manifest_path.parent / entry["file"]))
        if path.stat().st_size > LIMIT or path.stat().st_size != entry["bytes"] or sha(path) != entry["sha256"]:
            raise ValueError("Backup bytes or hash mismatch")
        destination = args.output_dir / (label + ".restored.sqlite")
        exclusive_bytes(destination, path.read_bytes())
        with sqlite3.connect(destination.as_uri() + "?mode=ro", uri=True) as connection:
            if inspect_database(connection, idle_heartbeat="stable_heartbeat" in entry["contents"]) != entry["contents"]:
                raise ValueError("Restored contents mismatch")
        if label == "driver":
            driver_quiescent(lifecycle(destination.read_bytes()))
    result = {"restored_database_copies_verified": True, "databases": list(DATABASES),
              "cluster_contacted": False, "live_restore_performed": False,
              "complete_platform_recovery_proven": False}
    write(args.output_dir / "restore-verification.private.json", result)
    return result


def restart_data(args: argparse.Namespace) -> dict:
    """Restart only the two backup-matched owned data Deployments, then compare.

    This proves retained-PVC restart, not disaster restoration. A separate
    recovery procedure must reconcile post-backup actions before any live restore.
    """
    from identity_demo_setup import kube, owned, private_file, sha, write

    # Restore verification is an offline prerequisite and leaves new private
    # copies beside this command's receipts; it never replaces live databases.
    verify_backup(args)
    manifest_path = private_file(args.backup_manifest)
    if sha(manifest_path) != args.backup_sha256:
        raise ValueError("Backup changed during verification")
    manifest = json.loads(manifest_path.read_text())
    if manifest["profile"] != args.profile.to_dict():
        raise ValueError("Backup belongs to another installation")
    before_dir = args.output_dir / "before"
    before_dir.mkdir(mode=0o700)
    before_args = argparse.Namespace(**{**vars(args), "output_dir": before_dir})
    backup_data(before_args)
    before = json.loads((before_dir / "backup.private.json").read_text())
    desired = []
    for label, (name, _, _, _) in DATABASES.items():
        expected, current = manifest["databases"][label], before["databases"][label]
        if any(expected[k] != current[k] for k in ("contents", "controller_uid", "pvc_uid", "pod_uid", "image")):
            raise ValueError("Live data or workload changed since backup; capture again before restart")
        controller = kube(args, "get", "deployment", name, "-n", args.profile.core_namespace, "-o", "json")
        owned(controller, args.profile)
        if controller["metadata"]["uid"] != expected["controller_uid"] or controller["spec"].get("replicas", 1) != 1:
            raise ValueError("Exact single-replica backed-up controller required")
        desired.append(controller)
    write(args.output_dir / "restart-before.private.json", desired)
    patches = []
    for controller in desired:
        metadata = controller["metadata"]
        annotation = dict(controller["spec"]["template"]["metadata"].get("annotations", {}))
        annotation["identity-demo.restart-proof"] = str(uuid.uuid4())
        patch = [{"op": "test", "path": "/metadata/uid", "value": metadata["uid"]},
                 {"op": "test", "path": "/metadata/resourceVersion", "value": metadata["resourceVersion"]},
                 {"op": "test", "path": "/spec", "value": controller["spec"]},
                 {"op": "add", "path": "/spec/template/metadata/annotations", "value": annotation}]
        kube(args, "patch", "deployment", metadata["name"], "-n", args.profile.core_namespace,
             "--type=json", "--dry-run=server", "--patch-file=/dev/stdin", "-o", "json", value=patch)
        patches.append(patch)
    if not args.apply:
        return {"planned": True, "applied": False, "deployments": [v[0] for v in DATABASES.values()],
                "cluster_resources_changed": False, "complete_platform_recovery_proven": False}
    for controller, patch in zip(desired, patches, strict=True):
        metadata = controller["metadata"]
        changed = kube(args, "patch", "deployment", metadata["name"], "-n", args.profile.core_namespace,
            "--type=json", "--patch-file=/dev/stdin", "-o", "json", value=patch)
        write(args.output_dir / (metadata["name"] + ".restarted.private.json"), changed)
        result = subprocess.run([args.oc, "--kubeconfig", args.kubeconfig, "-n", args.profile.core_namespace,
            "rollout", "status", "deployment/" + metadata["name"], "--timeout=120s"],
            capture_output=True, timeout=130)
        if result.returncode:
            raise RuntimeError("Owned application restart not Ready; inspect private receipts before retrying")
    after_dir = args.output_dir / "after"
    after_dir.mkdir(mode=0o700)
    backup_data(argparse.Namespace(**{**vars(args), "output_dir": after_dir}))
    after = json.loads((after_dir / "backup.private.json").read_text())
    for label in DATABASES:
        first, last = before["databases"][label], after["databases"][label]
        if (any(first[k] != last[k] for k in ("contents", "controller_uid", "pvc_uid", "image"))
                or first["pod_uid"] == last["pod_uid"]):
            raise ValueError("Restart data preservation or Pod replacement unproved")
    return {"applied": True, "owned_data_services_restarted": True,
            "all_tables_and_schema_preserved": True, "pvc_uids_preserved": True,
            "pods_replaced_and_ready": True, "complete_platform_recovery_proven": False,
            "live_restore_performed": False}
