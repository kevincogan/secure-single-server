# SPDX-License-Identifier: Apache-2.0
"""Installer access closes only after completion, with original UID preconditions."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[3]


def harness(tmp_path, fault=None, kind="RoleBinding", gateway=False):
    out = tmp_path / "state"
    out.mkdir()
    for name in ("created", "administrator-created", "plan", "administrator-plan"):
        (out / name).mkdir()
    original = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": {
            "name": "identity-demo-owned-install-installer-application",
            "namespace": "owned-core",
            "uid": "22222222-2222-4222-8222-222222222222",
            "resourceVersion": "12",
            "labels": {"identity-demo-owner": "test-owner"},
        },
        "roleRef": {
            "kind": "Role",
            "name": "reviewed",
            "apiGroup": "rbac.authorization.k8s.io",
        },
        "subjects": [
            {
                "kind": "ServiceAccount",
                "name": "fixture-installer",
                "namespace": "owned-core",
            }
        ],
    }
    if gateway:
        original["metadata"]["name"] = "fixture-installer-gateway-access"
        if fault == "gateway-namespace":
            original["metadata"]["namespace"] = "owned-identity"
    original["kind"] = kind
    if kind == "ClusterRoleBinding":
        original["metadata"].pop("namespace")
        original["roleRef"]["kind"] = "ClusterRole"
    runtime = deepcopy(original)
    runtime["metadata"]["name"] = "fixture-console-coordinator-runtime"
    runtime["metadata"]["uid"] = "33333333-3333-4333-8333-333333333333"
    runtime["subjects"][0]["name"] = "fixture-console-coordinator"
    if fault == "runtime-principal":
        original["subjects"][0]["name"] = "fixture-console-coordinator"
    paths = [
        out / "administrator-created/000.json",
        out / "administrator-created/001.json",
    ]
    for path, value in zip(paths, [original, runtime]):
        path.write_text(json.dumps(value))
    for path, value in zip(paths, [original, runtime]):
        (out / "administrator-plan" / path.name).write_text(json.dumps(value))
    (out / "created/application-session.json").write_text(
        json.dumps({"metadata": {"uid": "job-uid"}})
    )
    (out / "parser.json").write_text(
        json.dumps(
            {
                "configuration": {
                    "profile": {
                        "triage_namespace": "owned-triage",
                        "reader_namespace": "owned-reader",
                        "identity_namespace": "owned-identity",
                    }
                }
            }
        )
    )
    for name in ("plan.sha256", "administrator-plan.sha256"):
        (out / name).write_text(
            hashlib.sha256(
                (out / "administrator-plan/000.json").read_bytes()
            ).hexdigest()
            + "  administrator-plan/000.json\n"
        )
    current = deepcopy(original)
    if fault == "uid":
        current["metadata"]["uid"] = "44444444-4444-4444-8444-444444444444"
    if fault == "rules":
        current["subjects"][0]["name"] = "foreign-installer"
    state = tmp_path / "api.json"
    state.write_text(
        json.dumps(
            {
                "current": current,
                "complete": fault != "incomplete",
                "race": fault == "race",
                "deleted": [],
            }
        )
    )
    if fault == "missing":
        paths[0].unlink()
    if fault == "pending":
        Path(str(paths[0]) + ".delete-pending.json").write_text("{}")
    fake = tmp_path / "oc"
    fake.write_text(
        "#!"
        + sys.executable
        + "\n"
        + """import json,sys
from pathlib import Path
state=Path(STATE);data=json.loads(state.read_text());args=sys.argv[1:]
if args[0]=='delete':
 options=json.loads(Path(args[args.index('-f')+1]).read_text())
 if options['preconditions']['resourceVersion']!=data['current']['metadata']['resourceVersion']:
  print('Conflict',file=sys.stderr);raise SystemExit(1)
 data['deleted'].append({'uri':args[2],'preconditions':options['preconditions']})
 state.write_text(json.dumps(data));print(json.dumps({'kind':'Status','status':'Success'}));raise SystemExit(0)
if args[:2]==['get','job']:
 print('True' if data['complete'] else 'False') if 'conditions' in args[-1] else print('job-uid')
 raise SystemExit(0)
value=json.loads(Path(args[args.index('-f')+1]).read_text())
if args[0]=='get':
 if data['deleted'] and '--ignore-not-found' in args:raise SystemExit(0)
 value=data['current']
if args[-1]=='json':
 snapshot=json.dumps(value)
 if data.get('race') and args[0]=='get':
  data['current']['metadata']['resourceVersion']='13';state.write_text(json.dumps(data))
 print(snapshot);raise SystemExit(0)
expression=args[-1]
if 'jsonpath-as-json' in expression:
 print(json.dumps([value.get('roleRef'),value.get('subjects')]));raise SystemExit(0)
if 'subjects[*]' in expression:
 field=expression.split('subjects[*].')[1].split('}')[0];print(' '.join(x[field] for x in value['subjects']))
elif 'roleRef' in expression:print(json.dumps(value.get('roleRef')))
elif 'identity-demo-owner' in expression:print(value['metadata']['labels']['identity-demo-owner'])
else:
 expr=expression.partition('=')[2].strip('{}').lstrip('.');current=value
 for key in expr.split('.'):current=current.get(key,{}) if isinstance(current,dict) else {}
 print('' if current=={} else current)
""".replace("STATE", repr(str(state)))
    )
    fake.chmod(0o700)
    source = (ROOT / "scripts/identity_demo/cluster_install_launch.sh").read_text()

    def function(name, next_name):
        return source[source.index(name + "() {") : source.index(next_name + "() {")]

    functions = (
        function("create_one", "json_list")
        + function("delete_recorded", "retire_build_authority")
        + function("finalize_installer", "observe_application")
    )
    program = "set -euo pipefail\numask 077\n"
    for key, value in {
        "out": out,
        "core": "owned-core",
        "installation": "owned-install",
        "owner": "test-owner",
    }.items():
        program += key + "=" + shlex.quote(str(value)) + "\n"
    program += "api=(" + shlex.quote(str(fake)) + ")\n"
    program += "if command -v sha256sum >/dev/null; then hash=(sha256sum); else hash=(shasum -a 256); fi\n"
    program += 'field() { "${api[@]}" create --dry-run=client --validate=false -f "$1" -o "jsonpath=$2"; }\n'
    program += functions + "\nfinalize_installer\n"
    script = tmp_path / "finalize.sh"
    script.write_text(program)
    return script, state, original, runtime


@pytest.mark.parametrize("kind", ["RoleBinding", "ClusterRoleBinding"])
def test_finalization_retires_only_installer_grants_with_uid_and_version(
    tmp_path, kind
):
    script, state, original, runtime = harness(tmp_path, kind=kind)
    for _ in range(2):
        result = subprocess.run(
            ["bash", str(script)], capture_output=True, text=True, timeout=20
        )
        assert result.returncode == 0, result.stderr
    deleted = json.loads(state.read_text())["deleted"]
    assert deleted == [
        {
            "uri": (
                "/apis/rbac.authorization.k8s.io/v1/namespaces/owned-core/rolebindings/"
                if kind == "RoleBinding"
                else "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/"
            )
            + original["metadata"]["name"],
            "preconditions": {
                "uid": original["metadata"]["uid"],
                "resourceVersion": "12",
            },
        }
    ]
    assert runtime["metadata"]["name"] not in deleted[0]["uri"]


@pytest.mark.parametrize(
    "fault", ["incomplete", "uid", "rules", "runtime-principal", "pending", "missing"]
)
def test_finalization_stops_on_unsafe_or_uncertain_state(tmp_path, fault):
    script, state, _, _ = harness(tmp_path, fault)
    result = subprocess.run(
        ["bash", str(script)], capture_output=True, text=True, timeout=20
    )
    assert result.returncode != 0
    assert not json.loads(state.read_text())["deleted"]


def test_concurrent_binding_change_rejects_delete_and_preserves_pending_receipt(
    tmp_path,
):
    script, state, _, _ = harness(tmp_path, "race")
    result = subprocess.run(
        ["bash", str(script)], capture_output=True, text=True, timeout=20
    )
    assert result.returncode != 0 and "Conflict" in result.stderr
    assert not json.loads(state.read_text())["deleted"]
    receipt = tmp_path / "state/administrator-created/000.json"
    assert Path(str(receipt) + ".delete-pending.json").exists()
    assert not Path(str(receipt) + ".deleted.json").exists()


@pytest.mark.parametrize("fault", [None, "gateway-namespace"])
def test_gateway_installer_authority_is_retired_only_in_the_owned_core(tmp_path, fault):
    script, state, original, _ = harness(tmp_path, fault, gateway=True)
    result = subprocess.run(
        ["bash", str(script)], capture_output=True, text=True, timeout=20
    )
    deleted = json.loads(state.read_text())["deleted"]
    if fault:
        assert result.returncode != 0 and not deleted
    else:
        assert result.returncode == 0, result.stderr
        assert len(deleted) == 1
        assert deleted[0]["uri"].endswith("/rolebindings/fixture-installer-gateway-access")
        assert deleted[0]["preconditions"]["uid"] == original["metadata"]["uid"]
