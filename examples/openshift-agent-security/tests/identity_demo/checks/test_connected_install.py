# SPDX-License-Identifier: Apache-2.0
"""Connected orchestration reuses guarded helpers without implicit retries."""

import argparse
import base64
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import connected_install as connected
from deployment_profile import LEGACY


@pytest.fixture
def harness(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> SimpleNamespace:
    """Replace cluster helpers with bounded synthetic stage results."""
    monkeypatch.setattr(connected.os, "environ", {"PATH": "/usr/bin:/bin"})
    out = tmp_path / "install"
    out.mkdir(mode=0o700)
    cli = tmp_path / "openshell"
    cli.write_text("synthetic")
    cli.chmod(0o700)
    args = argparse.Namespace(output_dir=out, installation_config=str(tmp_path / "config.json"),
        expected_server=LEGACY.expected_server, readiness_timeout=30,
        installer_user="platform-eng", kubeconfig=str(tmp_path / "kubeconfig"),
        cli=str(cli), apply=True, oc="oc", state_file=None)
    state = SimpleNamespace(events=[], fail=None, native_ready=True, verified=True,
                            collision=False, envs=[], commands={})
    objects = [{"kind": "Secret", "metadata": {"name": "fixture-identity-driver-credentials"},
                "data": {"operator_secret": base64.b64encode(b"synthetic").decode()}}]
    objects.append({"kind": "Secret", "metadata": {"name": "fixture-keycloak-upstream-realm"},
        "data": {"realm.json": base64.b64encode(json.dumps({"users": [{"username": "analyst", "enabled": True,
            "id": "12345678-1234-4234-8234-123456789012", "realmRoles": ["analyst"],
            "credentials": [{"value": "must-not-export"}]}]}).encode()).decode()}})
    monkeypatch.setattr(connected, "resolve_ingress", lambda args,path:path)
    monkeypatch.setattr(connected, "load_inputs", lambda path: (LEGACY, {}, {}, []))
    monkeypatch.setattr(connected.setup, "private_file", lambda value: Path(value))
    monkeypatch.setattr(connected.setup, "validate", lambda bundle: objects)
    monkeypatch.setattr(connected, "wait_controllers", lambda *a: state.events.append("wait"))
    original_read = connected.read_json

    def read(path: Path) -> dict:
        if path.name == "config.json":
            return {"artifacts_file": str(tmp_path / "artifacts.json")}
        return original_read(path)
    monkeypatch.setattr(connected, "read_json", read)

    def run(self: object, name: str, script: str, words: list[str], **kwargs: object) -> tuple:
        state.events.append(name)
        state.commands[name] = list(words)
        state.envs.append(dict(self.env))
        if name == state.fail:
            raise RuntimeError("synthetic interrupted stage")
        target = out / name
        target.mkdir(mode=0o700)
        if name == "02-render":
            (target / "stack.private.json").write_text(json.dumps({
                "native_build_contract_matches": state.native_ready}))
        result = {"ready": True, "ready_for_create": not state.collision,
                  "admission_deferred_missing_namespace": 0}
        if name == "10-verify":
            result = {"ready": state.verified, "failures": ["Secret/fixture-unexpected"]}
        return result, target
    monkeypatch.setattr(connected.Stages, "run", run)
    return SimpleNamespace(args=args, state=state, out=out)


def test_ordered_setup_reuses_existing_helpers(harness: SimpleNamespace,
                                             monkeypatch: pytest.MonkeyPatch) -> None:
    """Install, permission, trust, workspaces and catalog each have one stage."""
    monkeypatch.setenv("IDENTITY_DEMO_CONFIG", "/wrong/old-lab")
    result = connected.connected_install(harness.args)
    stages = harness.state.events
    assert result["application_installation_completed"] is True
    assert result["functional_scenarios_proven"] is False
    assert result["production_approved"] is False
    assert stages.index("06-admission") < stages.index("07-install")
    assert stages.index("08-runtime-plan") < stages.index("08-runtime-apply")
    assert stages.index("10-verify") < stages.index("11-trust") < stages.index("12-workspaces")
    assert stages.index("13-project") < stages.index("13-incident-project") < stages.index("14-catalog")
    for stage, project in (("13-project", "SERVICE"), ("13-incident-project", "OPS")):
        words = harness.state.commands[stage]
        assert words[words.index("--project") + 1] == project
        assert "--apply" in words
    assert stages[-1] == "14-catalog"
    assert "IDENTITY_DEMO_CONFIG" not in harness.state.envs[0]
    assert harness.state.envs[-1]["IDENTITY_DEMO_CONFIG"].startswith(str(harness.out))
    paths = json.loads((harness.out / "operator-paths.private.json").read_text())
    assert "catalog_credential" in paths
    assert (harness.out / "cli-config").is_dir()
    assert (harness.out / "cli-config").stat().st_mode & 0o077 == 0
    assert (harness.out / "driver-credentials.private.json").stat().st_mode & 0o077 == 0
    environment = (harness.out / "operator-inputs.env").read_text()
    assert "export IDENTITY_DEMO_CONFIG=" in environment
    assert "export DEMO_CATALOG_CREDENTIAL=" in environment
    assert "export DEMO_PRESENTER_SUBJECT=12345678-1234-4234-8234-123456789012" in environment
    assert "export DEMO_RUNTIME_CA=" in environment and "export DEMO_CORE_NAMESPACE=" in environment
    assert "must-not-export" not in environment
    assert "synthetic" not in environment


def test_native_contract_mismatch_stops_before_cluster_writes(harness: SimpleNamespace) -> None:
    """Keep generated state for the build rather than trying a different image."""
    harness.state.native_ready = False
    result = connected.connected_install(harness.args)
    assert result["ready"] is False
    assert result["cluster_changed"] is False
    assert harness.state.events == ["01-preflight", "02-render"]


def test_plan_has_no_apply_stages(harness: SimpleNamespace) -> None:
    """Planning never provisions workspaces, permissions, catalog keys or projects."""
    harness.args.apply = False
    result = connected.connected_install(harness.args)
    assert result["cluster_changed"] is False
    assert harness.state.events == ["01-preflight", "02-render", "03-access-plan", "04-application-plan"]


@pytest.mark.parametrize("stage", ["01-preflight", "06-admission", "07-install",
                                    "08-runtime-apply", "11-trust", "13-incident-project", "14-catalog"])
def test_failure_never_retries_or_tears_down(harness: SimpleNamespace, stage: str) -> None:
    """Interrupted/unknown mutations retain existing explicit recovery semantics."""
    harness.state.fail = stage
    with pytest.raises(RuntimeError):
        connected.connected_install(harness.args)
    assert harness.state.events[-1] == stage
    assert harness.state.events.count(stage) == 1
    assert not any("cleanup" in name for name in harness.state.events)


def test_configuration_failure_blocks_later_operations(harness: SimpleNamespace) -> None:
    """Do not turn a strict Secret or policy failure into a passing installation."""
    harness.state.verified = False
    with pytest.raises(ValueError, match="verification failed"):
        connected.connected_install(harness.args)
    assert harness.state.events[-1] == "10-verify"


def test_collision_stops_before_application_creation(harness: SimpleNamespace) -> None:
    """Do not adopt an occupied target or replay existing application state."""
    harness.state.collision = True
    with pytest.raises(ValueError, match="Collision"):
        connected.connected_install(harness.args)
    assert "07-install" not in harness.state.events


@pytest.mark.parametrize("change", ["server", "admin", "timeout"])
def test_invalid_inputs_stop_before_helpers(harness: SimpleNamespace, change: str) -> None:
    """Never choose another cluster, admin identity or unbounded wait implicitly."""
    if change == "server":
        harness.args.expected_server = "https://wrong.example.org"
    elif change == "admin":
        harness.args.installer_user = "admin"
    else:
        harness.args.readiness_timeout = 999999
    with pytest.raises(ValueError):
        connected.connected_install(harness.args)
    assert harness.state.events == []


def test_unexpected_failure_cannot_be_dormant_policy() -> None:
    """The inactive catalog exception cannot hide another enforcement failure."""
    assert not connected.inactive_catalog_policy(None, [], {"failures": ["Secret/example"]})


@pytest.mark.parametrize("change", ["none", "spec", "generation", "message", "owner"])
def test_dormant_policy_exception_is_exact(monkeypatch: pytest.MonkeyPatch, change: str) -> None:
    """Current controller status can be top-level; drift still fails closed."""
    from copy import deepcopy
    desired = {"kind": "AuthPolicy", "metadata": {
        "name": "fixture-mcp-auth", "labels": dict(LEGACY.labels)},
        "spec": {"targetRef": {"sectionName": "mcp"}}}
    current = deepcopy(desired)
    current["metadata"]["generation"] = 1
    current["status"] = {"observedGeneration": 1, "conditions": [
        {"type": "Accepted", "status": "True"}, {
        "type": "Enforced", "status": "False", "message":
        "AuthPolicy is not in the path to any existing routes"}]}
    if change == "spec":
        current["spec"]["targetRef"]["sectionName"] = "bound"
    elif change == "generation":
        current["status"]["observedGeneration"] = 0
    elif change == "message":
        current["status"]["conditions"][1]["message"] = "Something else failed"
    elif change == "owner":
        current["metadata"]["labels"] = {}
    monkeypatch.setattr(connected.setup, "get", lambda *a: current)
    args = argparse.Namespace(profile=LEGACY)
    result = {"failures": ["AuthPolicy/fixture-mcp-auth"]}
    if change == "owner":
        with pytest.raises(ValueError):
            connected.inactive_catalog_policy(args, [desired], result)
    else:
        assert connected.inactive_catalog_policy(args, [desired], result) is (change == "none")


def test_stage_exit_failure_keeps_private_receipt(monkeypatch: pytest.MonkeyPatch,
                                                tmp_path: Path) -> None:
    """The wrapper does not print raw subprocess output or retry the call."""
    calls = []
    def run(command: list[str], **kwargs: object) -> SimpleNamespace:
        calls.append(command)
        kwargs["stdout"].write("synthetic private failure")
        return SimpleNamespace(returncode=1)
    monkeypatch.setattr(connected.subprocess, "run", run)
    stages = connected.Stages(argparse.Namespace(output_dir=tmp_path), {})
    with pytest.raises(RuntimeError, match="private stage receipt"):
        stages.run("failed", "scripts/identity_demo/identity_demo_setup.py", [])
    receipt = json.loads((tmp_path / "failed.receipt.json").read_text())
    assert receipt["exit"] == 1 and len(calls) == 1
    assert (tmp_path / "failed.private.log").stat().st_mode & 0o077 == 0


@pytest.mark.parametrize('change',['duplicate','missing','disabled','role','invalid-id'])
def test_presenter_metadata_refuses_ambiguous_or_wrong_user(change):
    user={'username':'analyst','enabled':True,'id':'12345678-1234-4234-8234-123456789012','realmRoles':['analyst']}
    users=[user]
    if change=='duplicate':users.append(dict(user))
    if change=='missing':users=[]
    if change=='disabled':user['enabled']=False
    if change=='role':user['realmRoles']=['viewer']
    if change=='invalid-id':user['id']='not-an-id'
    obj={'kind':'Secret','metadata':{'name':'fixture-keycloak-upstream-realm'},'data':{'realm.json':base64.b64encode(json.dumps({'users':users}).encode()).decode()}}
    with pytest.raises(ValueError):connected.presenter_subject([obj])


def test_optional_inference_check_uses_clean_profile_and_keeps_only_path(harness,monkeypatch):
    harness.args.inference_config='/private/operator/inference-config.json'
    monkeypatch.setenv('IDENTITY_DEMO_CONFIG','/wrong/old-lab')
    monkeypatch.setenv('IDENTITY_DEMO_ARTIFACTS','/wrong/old-images')
    calls=[]
    def run(command,**kwargs):
        assert 'IDENTITY_DEMO_CONFIG' not in kwargs['env'] and 'IDENTITY_DEMO_ARTIFACTS' not in kwargs['env']
        assert command[-1]==harness.args.inference_config
        calls.append(command)
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(connected.subprocess,'run',run)
    assert connected.connected_install(harness.args)['ready']
    assert len(calls)==1
    environment=(harness.out/'operator-inputs.env').read_text()
    assert 'export DEMO_INFERENCE_CONFIG=/private/operator/inference-config.json' in environment
    receipt=json.loads((harness.out/'inference-reference-check.json').read_text())
    assert not receipt['credential_bytes_read'] and not receipt['model_request_made']


def test_resume_branch_never_replays_initial_mutations(harness,monkeypatch):
    harness.args.resume_installation='/private/previous-install'
    monkeypatch.setattr(connected,'resume_discovery',lambda *args:{'ready':True,'applied':False})
    assert connected.connected_install(harness.args)['ready']
    assert harness.state.events==[]


def test_retained_ingress_is_discovered_without_reusing_captured_addresses(tmp_path,monkeypatch):
    source=tmp_path/'config.json';source.write_text(json.dumps({'schema_version':1,'profile':LEGACY.to_dict()}))
    args=argparse.Namespace(output_dir=tmp_path)
    service={'metadata':{'name':'router-default','namespace':'openshift-ingress','uid':'shared-router'},
        'spec':{'clusterIP':'192.0.2.77','selector':{'ingresscontroller.operator.openshift.io/deployment-ingresscontroller':'default'}}}
    calls=[]
    def read(options,*words,**kw):calls.append(words);return service
    monkeypatch.setattr(connected.setup,'kube',read)
    path=connected.resolve_ingress(args,source)
    assert json.loads(path.read_text())['ingress_cluster_ip']=='192.0.2.77'
    assert json.loads((tmp_path/'ingress-prerequisite.receipt.json').read_text())['resource_changed'] is False
    assert len(calls)==1 and calls[0][0]=='get'
    value=json.loads(source.read_text());value['ingress_cluster_ip']='192.0.2.88';source.write_text(json.dumps(value))
    with pytest.raises(ValueError,match='differs'):connected.resolve_ingress(args,source)
