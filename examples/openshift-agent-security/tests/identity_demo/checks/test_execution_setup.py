# SPDX-License-Identifier: Apache-2.0
"""Guard the adopted setup recipe's names, ownership and additive mappings."""

from dataclasses import replace
from pathlib import Path
import argparse
from contextlib import contextmanager
import json
from types import SimpleNamespace

import pytest

from identity_demo_execution_setup import append_contexts, context_template, diagnostic_container, owned
from identity_demo_lab import LABELS


def test_diagnostic_subresource_preserves_pod_scc_and_security_context() -> None:
    """Minimal Pod bodies can fail SCC admission despite valid diagnostic access."""
    from identity_demo_execution_setup import diagnostic_payload
    pod = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'synthetic',
        'uid': 'original', 'resourceVersion': '7', 'managedFields': [],
        'annotations': {'openshift.io/scc': 'restricted-v2'}},
        'spec': {'securityContext': {'seccompProfile': {'type': 'RuntimeDefault'}, 'fsGroup': 1000},
                 'containers': [{'name': 'supervisor'}]}, 'status': {'phase': 'Running'}}
    before = json.loads(json.dumps(pod))
    result = diagnostic_payload(pod, diagnostic_container(1000))
    assert pod == before
    assert result['metadata']['annotations'] == pod['metadata']['annotations']
    assert result['metadata']['resourceVersion'] == '7'
    assert result['spec']['securityContext'] == pod['spec']['securityContext']
    assert result['spec']['containers'] == pod['spec']['containers']
    assert len(result['spec']['ephemeralContainers']) == 1
    assert 'status' not in result and 'managedFields' not in result['metadata']


@pytest.mark.parametrize("role", ["triage", "reader"])
def test_native_context_template_stays_inside_owned_workspace(role: str) -> None:
    """Use existing isolation/principals, with a placeholder until native creation."""
    context = context_template(role, "s7a")
    assert len(context.sandbox_name) <= 19
    assert context.namespace == context.workspace == "demo-" + role
    assert context.service_account == "fixture-openshell-sandbox"
    assert context.sandbox_id == "00000000-0000-0000-0000-000000000000"


@pytest.mark.parametrize("role,suffix", [("admin", "a"), ("triage", "toolong"),
    ("reader", "../"), ("triage", None), ("triage", "")])
def test_unapproved_context_names_rejected(role: str, suffix: object) -> None:
    """Untrusted arguments cannot select other namespaces or native names."""
    with pytest.raises(ValueError):
        context_template(role, suffix)


def test_append_mapping_preserves_existing_context_and_configuration() -> None:
    """No authentication/permission/retirement field changes when onboarding."""
    old = {"contexts": [{"workload": "retired"}], "project": "TEST", "issuer": "fixed"}
    context = replace(context_template("triage", "s7a"), sandbox_id="11111111-1111-4111-8111-111111111111")
    result = append_contexts(old, [context], "service-request", "SERVICE")
    assert old == {"contexts": [{"workload": "retired"}], "project": "TEST", "issuer": "fixed"}
    assert result["contexts"][0] == old["contexts"][0] and result["issuer"] == "fixed"
    assert result["contexts"][1]["project"] == "SERVICE"
    assert result["contexts"][1]["workflow"] == "service-request"
    with pytest.raises(ValueError, match="reassignment"):
        append_contexts(result, [context], "service-request", "SERVICE")


@pytest.mark.parametrize("workflow,project", [("service-request", "TEST"),
    ("service-request", "bad project"), ("unapproved", "SERVICE")])
def test_unapproved_workflow_or_project_rejected(workflow: str, project: str) -> None:
    """Onboarding cannot silently expand the selected workflow contract."""
    with pytest.raises(ValueError):
        append_contexts({"contexts": []}, [context_template("triage", "s7a")], workflow, project)


def test_unowned_resource_refused() -> None:
    """Reviewable updates must still pass the live ownership guard."""
    owned({"metadata": {"labels": dict(LABELS)}})
    with pytest.raises(ValueError):
        owned({"metadata": {"labels": {}}})


def test_staging_mounts_only_shared_run_and_keeps_restricted_security() -> None:
    """A tool-transfer helper must not receive a token or Workload API socket."""
    container = diagnostic_container(1000500000)
    assert container["volumeMounts"] == [{"name": "run", "mountPath": "/run/openshell"}]
    assert container["securityContext"]["allowPrivilegeEscalation"] is False
    assert container["securityContext"]["capabilities"] == {"drop": ["ALL"]}
    with pytest.raises(ValueError):
        diagnostic_container(0)


@pytest.mark.parametrize('mode', ['plan', 'create', 'remove-plan', 'remove'])
def test_diagnostic_grant_is_explicit_and_exact_pod_only(
        monkeypatch: pytest.MonkeyPatch, tmp_path: object, mode: str) -> None:
    """Diagnostics grant only update on one supervisor subresource to one user."""
    import identity_demo_execution_setup as setup
    context = replace(context_template('triage', 'd1'), sandbox_id='11111111-1111-4111-8111-111111111111')
    existing, changes = {}, []
    def read(args: object, kind: str, name: str, namespace: str = None, **kw: object) -> dict:
        if kind == 'namespace':
            return {'metadata': {'labels': dict(LABELS)}}
        if kind == 'pod':
            return {'metadata': {'uid': 'supervisor-uid', 'labels': {
                'openshell.ai/sandbox-id': context.sandbox_id,
                'openshell.ai/gateway-id': setup.active_profile().gateway_id}}}
        return existing.get(kind, {})
    def kube(args: object, *words: str, payload: dict = None) -> dict:
        changes.append((words, payload))
        return {**payload, 'metadata': {**payload.get('metadata', {}), 'uid': 'uid-' + payload['kind'], 'resourceVersion': '7'}}
    monkeypatch.setattr(setup, 'guard', lambda a: (None, {}, None))
    monkeypatch.setattr(setup, 'resolve_context', lambda *a: context)
    monkeypatch.setattr(setup, 'read', read)
    monkeypatch.setattr(setup.native, 'kube', kube)
    monkeypatch.setattr(setup.subprocess, 'run', lambda *a, **kw: SimpleNamespace(returncode=0, stdout='platform-eng\n'))
    options = argparse.Namespace(context_file=['private-context'], installer_user='platform-eng',
        kubeconfig='private-kubeconfig', output_dir=tmp_path, action='diagnostic-access', apply=mode == 'create')
    if mode.startswith('remove'):
        setup.diagnostic_access(options)
        plan = json.loads((tmp_path / 'diagnostic-access.plan.private.json').read_text())
        for o in plan['grants']:
            o['metadata'].update(uid='uid-' + o['kind'], resourceVersion='7')
            existing[o['kind']] = o
        options.output_dir = tmp_path / 'remove'
        options.output_dir.mkdir()
        options.action = 'retire-diagnostic-access'
        options.apply = mode == 'remove'
        changes.clear()
    result = setup.diagnostic_access(options)
    plan = json.loads((options.output_dir / 'diagnostic-access.plan.private.json').read_text())
    assert plan['grants'][0]['rules'] == [{'apiGroups': [''], 'resources': ['pods/ephemeralcontainers'],
        'resourceNames': ['os-supervisor-' + context.sandbox_id], 'verbs': ['update']}]
    assert plan['grants'][1]['subjects'] == [{'kind': 'User', 'apiGroup': 'rbac.authorization.k8s.io', 'name': 'platform-eng'}]
    assert not result['other_pods_or_serviceaccounts_granted']
    if mode == 'plan':
        assert len(changes) == 1 and '--dry-run=server' in changes[0][0]
        assert result['binding_admission_deferred'] == 1
    elif mode == 'create':
        assert len(changes) == 4 and len(result['changed']) == 2
    elif mode == 'remove-plan':
        assert not changes
    else:
        assert len(changes) == 2 and all(c[0][0] == 'delete' for c in changes)
        assert changes[0][1]['preconditions'] == {'uid': 'uid-Role', 'resourceVersion': '7'}


@pytest.mark.parametrize('failure', ['user', 'admin', 'namespace', 'pod', 'grant-owner', 'grant-rules', 'grant-pod-uid'])
def test_diagnostic_grant_refuses_foreign_or_broader_access_before_writes(
        monkeypatch: pytest.MonkeyPatch, tmp_path: object, failure: str) -> None:
    """An exact owned namespace does not permit broad or foreign diagnostic grants."""
    import identity_demo_execution_setup as setup
    context = replace(context_template('triage', 'd1'), sandbox_id='11111111-1111-4111-8111-111111111111')
    calls = []
    def read(args: object, kind: str, name: str, namespace: str = None, **kw: object) -> dict:
        labels = dict(LABELS)
        if kind == 'namespace':
            return {'metadata': {'labels': {} if failure == 'namespace' else labels}}
        if kind == 'pod':
            return {'metadata': {'uid': 'supervisor-uid', 'labels': {
                'openshell.ai/sandbox-id': 'other' if failure == 'pod' else context.sandbox_id,
                'openshell.ai/gateway-id': setup.active_profile().gateway_id}}}
        if kind != 'Role' or not failure.startswith('grant-'):
            return {}
        if failure == 'grant-owner':
            labels = {}
        return {'metadata': {'namespace': context.namespace, 'labels': labels, 'annotations': {
                    'identity-demo-supervisor-uid': 'old' if failure == 'grant-pod-uid' else 'supervisor-uid'}},
                'rules': [{'apiGroups': [''], 'resources': ['pods/ephemeralcontainers'],
                    **({} if failure == 'grant-rules' else {'resourceNames': ['os-supervisor-' + context.sandbox_id]}),
                    'verbs': ['update']}]}
    monkeypatch.setattr(setup, 'guard', lambda a: (None, {}, None))
    monkeypatch.setattr(setup, 'resolve_context', lambda *a: context)
    monkeypatch.setattr(setup, 'read', read)
    monkeypatch.setattr(setup.native, 'kube', lambda *a, **kw: calls.append(a))
    monkeypatch.setattr(setup.subprocess, 'run', lambda *a, **kw: SimpleNamespace(returncode=0, stdout='other' if failure == 'user' else 'platform-eng'))
    options = argparse.Namespace(context_file=['private-context'], installer_user='admin' if failure == 'admin' else 'platform-eng',
        kubeconfig='private-kubeconfig', output_dir=tmp_path, action='diagnostic-access', apply=True)
    with pytest.raises(ValueError):
        setup.diagnostic_access(options)
    assert not calls


@pytest.mark.parametrize('mode', ['plan', 'apply', 'collision'])
def test_native_workspace_setup_is_owned_and_create_only(monkeypatch: pytest.MonkeyPatch, tmp_path: object, mode: str) -> None:
    """Namespace existence never silently substitutes for native workspace state."""
    import identity_demo_execution_setup as setup
    import probe_runtime_management as management
    profile = setup.active_profile()
    records, calls = [], []
    if mode == 'collision':
        records.append({'name': profile.triage_namespace, 'labels': {}})
    def read(*a: object, **kw: object) -> dict:
        value = {'metadata': {'labels': dict(LABELS)}}
        if a[1] == 'configmap':
            value['data'] = {'namespaces.json': json.dumps(list(profile.application_namespaces[1:]))}
        return value
    def execute(words: list[str], **kw: object) -> dict | str:
        calls.append(words)
        if words[:2] == ['workspace', 'list']:
            return {'workspaces': records}
        assert words[:2] == ['workspace', 'create']
        records.append({'name': words[3], 'labels': {
            'identity-demo-owner': profile.owner, 'identity-demo-installation': profile.installation_id}})
        return 'created'
    @contextmanager
    def session(*a: object, **kw: object) -> object:
        yield execute
    monkeypatch.setattr(setup, 'guard', lambda a: (None, {}, 'https://issuer.invalid'))
    monkeypatch.setattr(setup, 'read', read)
    monkeypatch.setattr(setup, 'private_path', lambda p: p)
    monkeypatch.setattr(setup.native, 'native_session', session)
    monkeypatch.setattr(management, 'initialize_cli', lambda *a: None)
    options = argparse.Namespace(output_dir=tmp_path, ca_file='private-ca', apply=mode != 'plan')
    if mode == 'collision':
        with pytest.raises(ValueError, match='ownership collision'):
            setup.prepare_workspaces(options)
        assert all(c[1] == 'list' for c in calls)
    else:
        result = setup.prepare_workspaces(options)
        assert result['native_workspace_records_ready'] == (mode == 'apply')
        assert sum(c[1] == 'create' for c in calls) == (2 if mode == 'apply' else 0)
        assert not result['kubernetes_namespaces_modified']


def test_register_driver_preserves_profile_and_support_modules(monkeypatch: pytest.MonkeyPatch, tmp_path: object) -> None:
    """Adding a mapping must not drop imports or installed configuration files."""
    import identity_demo_execution_setup as setup
    current = {'metadata': {'labels': dict(LABELS)}, 'data': {
        'config.json': json.dumps({'contexts': [], 'project': 'TEST'}),
        'installation-profile.json': 'synthetic-profile', 'support.py': '# synthetic support',
        'identity_demo_console_store.py': (setup.ROOT/'scripts/identity_demo/identity_demo_console_store.py').read_text()}}
    deployment = {'metadata': {'labels': dict(LABELS)}, 'spec': {'template': {'spec': {
        'volumes': [{'name': 'code', 'configMap': {'name': 'fixture-old'}}]}}}}
    def read(args: object, kind: str, name: str, *a: object, **kw: object) -> dict | None:
        if kind == 'deployment':
            return deployment
        return current if name == 'fixture-old' else None
    events = []
    monkeypatch.setattr(setup, 'guard', lambda a: (None, {}, None))
    monkeypatch.setattr(setup, 'resolve_context', lambda *a: context_template('triage', 'f1'))
    monkeypatch.setattr(setup, 'inspect_state', lambda a: {'rollback_quiescent': True})
    monkeypatch.setattr(setup, 'read', read)
    monkeypatch.setattr(setup.native, 'kube', lambda *a, **kw: events.append((a, kw)))
    options = argparse.Namespace(context_file=['synthetic-context'], output_dir=tmp_path,
                                 workflow='cve', project='TEST', apply=False)
    result = setup.register_driver(options)
    desired = json.loads((tmp_path / 'configmap-desired.private.json').read_text())
    assert desired['data']['installation-profile.json'] == 'synthetic-profile'
    assert desired['data']['support.py'] == '# synthetic support'
    assert 'active_profile' in desired['data']['deployment_profile.py']
    assert result['persistent_state_and_credentials_preserved']
    assert all('--dry-run=server' in words for words, _ in events)


@pytest.mark.parametrize("controller_identities", [False, True])
@pytest.mark.parametrize("missing_claim", [False, True])
def test_retirement_retains_generated_worker_claim_before_native_delete(
    monkeypatch: object, tmp_path: object, missing_claim: bool, controller_identities: bool
) -> None:
    """Claim templates are absent from template volumes; never silently lose them."""
    import identity_demo_execution_setup as setup
    import identity_demo_controller_identity as identities
    monkeypatch.setattr(identities, "enabled", lambda: controller_identities)
    monkeypatch.delenv("IDENTITY_DEMO_RUNTIME", raising=False)

    context = context_template("triage", "s7z")
    from dataclasses import asdict
    location = tmp_path / "context.private.json"
    location.write_text(json.dumps(asdict(context)))
    location.chmod(0o600)
    args = argparse.Namespace(context_file=[str(location)], kubeconfig="private",
                              output_dir=tmp_path, apply=True)
    events = []
    sandbox = {"metadata": {"uid": "sandbox-uid"}, "spec": {
        "podTemplate": {"spec": {"volumes": []}},
        "volumeClaimTemplates": [{"metadata": {"name": "workspace"}}]}}
    pvc = {"metadata": {"uid": "pvc-uid", "resourceVersion": "1", "ownerReferences": [
        {"uid": "sandbox-uid", "kind": "Sandbox", "name": context.resource_name}]},
        "status": {"phase": "Bound"}}
    def read(args: object, kind: str, name: str, namespace: str = None,
             optional: bool = False) -> dict:
        if kind in ("deployment", "namespace"):
            return {"metadata": {"labels": dict(LABELS)}}
        if kind == "pod":
            return {"metadata": {"ownerReferences": [{"uid": "sandbox-uid"}]},
                "spec": {"volumes": [] if missing_claim else [
                    {"name": "workspace", "persistentVolumeClaim": {"claimName": "generated-workspace"}}]}}
        if kind == "pvc":
            return pvc
        return None if "deleted" in events else sandbox
    @contextmanager
    def session(args: object, credentials: dict) -> object:
        def execute(words: list, **kwargs: object) -> dict:
            if words[:2] == ["sandbox", "get"]:
                return {"id": context.sandbox_id}
            if words[:3] == ["sandbox", "provider", "list"]:
                return {"providers": []}
            assert words == ["sandbox", "delete", context.sandbox_name]
            assert events == ["retained"]
            events.append("deleted")
            return {}
        yield execute
    def kube(args: object, *words: str, **kwargs: object) -> dict:
        assert words[:3] == ("patch", "pvc", "generated-workspace")
        patch = json.loads(words[words.index("-p") + 1])
        assert patch[0] == {"op": "test", "path": "/metadata/uid", "value": "pvc-uid"}
        assert patch[-1] == {"op": "remove", "path": "/metadata/ownerReferences"}
        pvc["metadata"].pop("ownerReferences")
        events.append("retained")
        return pvc
    monkeypatch.setattr(setup, "guard", lambda args: (None, {}, None))
    monkeypatch.setattr(setup, "resolve_context", lambda *args: context)
    monkeypatch.setattr(setup, "retire_registration", lambda *args: {"registration_absent": True})
    monkeypatch.setattr(setup, "read", read)
    monkeypatch.setattr(setup.native, "native_session", session)
    monkeypatch.setattr(setup.native, "kube", kube)
    monkeypatch.setattr(setup.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(
        returncode=0, stdout='{"eligible":true}', stderr=""))
    if missing_claim:
        with pytest.raises(ValueError, match="accounted"):
            setup.retire(args)
        assert events == []
    else:
        assert setup.retire(args)["referenced_workspaces_preserved"]
        assert events == ["retained", "deleted"]


def test_adapter_update_versions_code_without_changing_credentials_or_mounts(monkeypatch: pytest.MonkeyPatch, tmp_path: object) -> None:
    """The safe updater changes one code reference and retains private rollback inputs."""
    import identity_demo_execution_setup as setup
    dep = {'apiVersion': 'apps/v1', 'kind': 'Deployment',
           'metadata': {'name': 'fixture-protected-adapter', 'namespace': setup.native.NAMESPACE,
                        'labels': dict(LABELS), 'resourceVersion': '7'},
           'spec': {'template': {'spec': {'volumes': [
               {'name': 'catalog-code', 'configMap': {'name': 'old-code'}},
               {'name': 'credentials', 'secret': {'secretName': 'unchanged-private'}}],
               'containers': [{'name': 'adapter-https', 'env': [{'name': 'PRIVATE_REFERENCE', 'value': 'unchanged'}]}]}}}}
    cm = {'metadata': {'name': 'old-code', 'labels': dict(LABELS)}, 'data': {
        'identity_demo_jira_action_adapter.py': 'old', 'identity_demo_run_store.py': 'old',
        'deployment_profile.py': 'old', 'private-config.json': 'unchanged'}}
    before = json.loads(json.dumps(dep))
    calls = []
    monkeypatch.setattr(setup, 'guard', lambda _: None)
    monkeypatch.setattr(setup, 'inspect_state', lambda _: {'rollback_quiescent': True})
    monkeypatch.setattr(setup, 'read', lambda _, kind, name, *a, **kw: dep if kind == 'deployment' else cm if name == 'old-code' else {})
    monkeypatch.setattr(setup.native, 'kube', lambda _, *a, **kw: calls.append((a, kw['payload'])))
    result = setup.update_adapter(argparse.Namespace(output_dir=tmp_path, apply=False))
    assert result['applied'] is False and len(calls) == 2
    assert all('--dry-run=server' in args for args, _ in calls)
    desired_cm, desired_dep = calls[0][1], calls[1][1]
    assert desired_cm['data']['private-config.json'] == 'unchanged'
    desired_dep['spec']['template']['spec']['volumes'][0]['configMap']['name'] = 'old-code'
    assert desired_dep == before and dep == before
    assert json.loads((tmp_path / 'deployment-before.private.json').read_text()) == before


def test_adapter_update_refuses_active_or_uncertain_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    """No rollout is allowed while a run or an unresolved write is present."""
    import identity_demo_execution_setup as setup
    monkeypatch.setattr(setup, 'guard', lambda _: None)
    monkeypatch.setattr(setup, 'inspect_state', lambda _: {'rollback_quiescent': False})
    with pytest.raises(ValueError, match='quiescent'):
        setup.update_adapter(argparse.Namespace())


def rejection_review_harness(tmp_path, monkeypatch):
    """Execute the generated operator program on private synthetic storage."""
    import os
    import hashlib
    import subprocess
    import sys
    from checks.test_run_store import rejected_dispatch
    import identity_demo_execution_setup as setup
    from deployment_profile import LEGACY
    store, run, workload, proposal, claim = rejected_dispatch(tmp_path)
    with store.transaction() as db:
        db.execute('CREATE TABLE console_jobs(run_id TEXT,state TEXT,evidence TEXT)')
        db.execute('INSERT INTO console_jobs VALUES (?,?,?)',
                   (run, 'failed', json.dumps({'failure_code':'recovery_required','cleanup_verified':False})))
    profile = tmp_path / 'profile.json'
    profile.write_text(json.dumps({k:getattr(LEGACY,k) for k in ('installation_id','owner','core_namespace','expected_server')}))
    profile.chmod(0o600)
    evidence={}
    for name in ('terminal_rejection','no_commit_contract','backend_snapshot','credential_cleanup'):
        path=tmp_path/(name+'.private.json');path.write_text(json.dumps({'synthetic_evidence':name}));path.chmod(0o600)
        evidence[name]={'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    image='registry.example.test/fixture@sha256:'+'a'*64
    receipt={'schema_version':1,'decision':'rejected_without_commit','installation_id':LEGACY.installation_id,
        'owner':LEGACY.owner,'expected_server':LEGACY.expected_server,'reviewed_by':'installer',
        'run_id':run,'action_id':proposal['action_id'],'execution_id':claim['execution_id'],
        'action_digest':proposal['digest'],'driver_uid':'driver-uid','jira_uid':'jira-uid','jira_image':image,'evidence':evidence}
    path=tmp_path/'review.private.json';path.write_text(json.dumps(receipt));path.chmod(0o600)
    args=SimpleNamespace(review_receipt=str(path),review_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                         kubeconfig='private-test-kubeconfig',apply=False,confirm_rejected_without_commit=False)
    state=SimpleNamespace(actor='installer',driver_uid='driver-uid',image=image,exec_calls=0)
    monkeypatch.delenv('IDENTITY_DEMO_RUNTIME',raising=False)
    monkeypatch.setattr(setup,'active_profile',lambda:LEGACY)
    monkeypatch.setattr(setup,'guard',lambda a:None)
    def read(a,kind,name,ns):
        return {'metadata':{'name':name,'uid':state.driver_uid if name=='fixture-identity-driver' else 'jira-uid',
                            'labels':dict(LABELS)},'spec':{'template':{'spec':{'containers':
            [{'name':n,'image':state.image} for n in ('fixture-jira','adapter-sse','adapter-streamable-http')]}}}}
    monkeypatch.setattr(setup,'read',read)
    real_run=subprocess.run
    def execute(words,**kwargs):
        if words[-1]=='whoami':return SimpleNamespace(returncode=0,stdout=state.actor+'\n')
        assert 'exec' in words and 'deployment/fixture-identity-driver' in words
        state.exec_calls+=1
        env={**os.environ,'DRIVER_DATABASE':str(store.path),'IDENTITY_DEMO_CONFIG':str(profile),
             'PYTHONPATH':str(Path(setup.__file__).parent)+os.pathsep+str(setup.ROOT/'tests/identity_demo')}
        return real_run([sys.executable,'-c',words[-1]],env=env,**kwargs)
    monkeypatch.setattr(setup.subprocess,'run',execute)
    return setup,args,state,store,run,proposal


def test_rejection_review_plan_is_read_only_and_apply_keeps_cleanup_blocked(tmp_path,monkeypatch):
    setup,args,state,store,run,proposal=rejection_review_harness(tmp_path,monkeypatch)
    before=store.describe(run,'user-a')
    assert setup.review_dispatch_rejection(args)['state']=='unknown'
    assert store.describe(run,'user-a')==before
    args.apply=True;args.confirm_rejected_without_commit=True
    result=setup.review_dispatch_rejection(args)
    assert result['state']=='failed' and result['redispatch'] is False
    assert result['console_recovery_cleared'] is False
    with store.read_transaction() as db:
        job=db.execute('SELECT evidence FROM console_jobs WHERE run_id=?',(run,)).fetchone()
        assert json.loads(job[0])['cleanup_verified'] is False
    assert state.exec_calls==2
    with pytest.raises(ValueError):setup.review_dispatch_rejection(args)
    assert len(store.describe(run,'user-a')['audit'])==len(before['audit'])+1


@pytest.mark.parametrize('change',['receipt','evidence','actor','service_account','uid','image','confirmation','runtime'])
def test_rejection_review_rejects_changed_evidence_or_authority_before_exec(tmp_path,monkeypatch,change):
    setup,args,state,store,run,proposal=rejection_review_harness(tmp_path,monkeypatch)
    args.apply=True;args.confirm_rejected_without_commit=True
    if change=='receipt': args.review_sha256='0'*64
    elif change=='evidence': (tmp_path/'backend_snapshot.private.json').write_text('changed')
    elif change=='actor':state.actor='someone-else'
    elif change=='service_account':state.actor='system:serviceaccount:demo:worker'
    elif change=='uid':state.driver_uid='replacement'
    elif change=='image':state.image='registry.example.test/fixture:latest'
    elif change=='confirmation':args.confirm_rejected_without_commit=False
    else:monkeypatch.setenv('IDENTITY_DEMO_RUNTIME','cluster')
    before=store.describe(run,'user-a')
    with pytest.raises(ValueError):setup.review_dispatch_rejection(args)
    assert state.exec_calls==0 and store.describe(run,'user-a')==before


def test_project_only_recovery_creates_project_without_any_issue_write(tmp_path,monkeypatch):
    """Exercise the real generated provisioning program with a fixed fake backend."""
    import io
    import os
    import ssl
    from contextlib import redirect_stdout
    import httpx
    import identity_demo_execution_setup as setup
    state={'created':False,'posts':[]}
    class Response:
        def __init__(self,status,data):self.status_code,self.data=status,data
        def json(self):return self.data
    class Client:
        def __init__(self,**kwargs):
            assert kwargs['follow_redirects'] is False and kwargs['trust_env'] is False
        async def __aenter__(self):return self
        async def __aexit__(self,*args):pass
        async def get(self,url,params=None):
            if url.endswith('/rest/api/2/project/OPS'):
                return Response(200,{'name':'Synthetic operations incidents'}) if state['created'] else Response(404,{})
            assert url.endswith('/rest/api/2/search')
            return Response(200,{'total':0,'issues':[]})
        async def post(self,url,json):
            state['posts'].append(url)
            assert url.endswith('/api/admin/projects') and json['key']=='OPS'
            state['created']=True
            return Response(201,{'key':'OPS'})
    monkeypatch.setattr(httpx,'AsyncClient',Client)
    monkeypatch.setattr(ssl,'create_default_context',lambda **kwargs:object())
    monkeypatch.setenv('JIRA_USER','synthetic');monkeypatch.setenv('JIRA_TOKEN','synthetic')
    monkeypatch.setattr(setup,'guard',lambda a:None)
    monkeypatch.setattr(setup,'inspect_state',lambda a:{'rollback_quiescent':True})
    monkeypatch.setattr(setup,'read',lambda *a:{'metadata':{'labels':dict(LABELS)}})
    def execute(words,**kwargs):
        assert 'exec' in words and 'adapter-https' in words
        settings=json.loads(kwargs['input']);assert settings['reuse_seeds']==[]
        monkeypatch.setattr(setup.sys,'stdin',io.StringIO(kwargs['input']))
        output=io.StringIO()
        with redirect_stdout(output):exec(words[-1],{})
        return SimpleNamespace(returncode=0,stdout=output.getvalue(),stderr='')
    monkeypatch.setattr(setup.subprocess,'run',execute)
    args=SimpleNamespace(project='OPS',project_only=True,apply=True,kubeconfig='private-test',output_dir=tmp_path)
    result=setup.provision_project(args)
    assert result['created'] and result['project_available'] and result['baseline_preserved']
    assert result['project_seed_mode']=='none' and result['incident_seed_keys']==[]
    assert len(state['posts'])==1


@pytest.mark.parametrize('model',['approved-chat-model','test-provider/example-org/model-1'])
def test_console_contract_is_data_not_executable_code(model):
    from identity_demo_execution_setup import console_model_contract
    source="raise RuntimeError('must never execute')\ndef safe_evidence(value):\n for key,item in value.items():\n  if key == 'model' and item == "+repr(model)+": continue\n"
    assert console_model_contract(source)==model


def test_console_update_cannot_replace_a_different_configured_model_before_admission(tmp_path,monkeypatch):
    import identity_demo_execution_setup as setup
    monkeypatch.setattr(setup,'guard',lambda a:None)
    monkeypatch.setattr(setup,'inspect_state',lambda a:{'rollback_quiescent':True})
    current=setup.console_model_contract((setup.ROOT/'scripts/identity_demo/identity_demo_console_store.py').read_text())
    different='synthetic-other-model' if current!='synthetic-other-model' else 'synthetic-second-model'
    configured="def safe_evidence(value):\n for key,item in value.items():\n  if key == 'model' and item == "+repr(different)+": continue\n"
    data={'config.json':json.dumps({'contexts':[],'project':'TEST'}),'identity_demo_console_store.py':configured}
    deployment={'metadata':{'labels':dict(LABELS)},'spec':{'template':{'spec':{'volumes':[{'name':'code','configMap':{'name':'old-code'}}]}}}}
    monkeypatch.setattr(setup,'read',lambda a,kind,*rest:deployment if kind=='deployment' else {'metadata':{'labels':dict(LABELS)},'data':data})
    calls=[];monkeypatch.setattr(setup.native,'kube',lambda *a,**kw:calls.append(a))
    args=SimpleNamespace(action='update-console',context_file=[],output_dir=tmp_path,apply=True)
    with pytest.raises(ValueError,match='Provider-configured source'):
        setup.register_driver(args)
    assert calls==[] and data['identity_demo_console_store.py']==configured


@pytest.mark.parametrize('source',["def safe_evidence(v): pass", "def safe_evidence(v):\n if key=='model' or item=='arbitrary': pass", "def safe_evidence(v):\n if key=='model' and item=='a': pass\n if key=='model' and item=='b': pass"])
def test_ambiguous_console_model_contract_requires_review(source):
    from identity_demo_execution_setup import console_model_contract
    with pytest.raises(ValueError):console_model_contract(source)


def test_cluster_retirement_cannot_fall_back_to_installer_pod_exec(monkeypatch, tmp_path):
    """The scoped preparer must obtain durable cleanup proof from its private API."""
    import identity_demo_execution_setup as setup
    import identity_demo_controller_identity as identities
    import identity_demo_console_worker as worker
    from dataclasses import asdict
    context = context_template('reader', 'r1')
    location = tmp_path / 'context.private.json'
    location.write_text(json.dumps(asdict(context)))
    location.chmod(0o600)
    credentials = tmp_path / 'driver.private.json'
    credentials.write_text(json.dumps({'operator_secret': 'synthetic-' + 'x' * 40}))
    credentials.chmod(0o600)
    monkeypatch.setenv('IDENTITY_DEMO_RUNTIME', 'cluster')
    monkeypatch.setattr(identities, 'enabled', lambda: True)
    monkeypatch.setattr(setup, 'guard', lambda args: (None, {}, None))
    monkeypatch.setattr(setup, 'read', lambda *a, **kw: None if kw.get('optional') else
                        {'metadata': {'labels': dict(LABELS)}})
    monkeypatch.setattr(setup.subprocess, 'run', lambda *a, **kw: pytest.fail('No runtime Pod exec fallback'))
    requests = []
    class Control:
        def __init__(self, secret):
            assert secret == 'synthetic-' + 'x' * 40
        def request(self, path, body):
            requests.append((path, body))
            return {'eligible': False}
    monkeypatch.setattr(worker, 'Control', Control)
    args = argparse.Namespace(context_file=[str(location)], driver_credentials_file=str(credentials),
                              kubeconfig='scoped-runtime', output_dir=tmp_path, apply=True)
    with pytest.raises(ValueError, match='closed with verified console cleanup'):
        setup.retire(args)
    assert requests == [('prepare/retirement-check', {'workload': context.workload})]
