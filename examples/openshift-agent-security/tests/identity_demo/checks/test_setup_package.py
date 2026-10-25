# SPDX-License-Identifier: Apache-2.0
"""Exercise installer failure, ownership, state retention and API race guards."""

import argparse
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import identity_demo_setup as setup
from identity_demo_lab import LABELS


def obj(kind: str, name: str, **extra: object) -> dict:
    """Build a synthetic owner-labelled object in the reviewed scope."""
    meta = {"name": name, "labels": dict(LABELS)}
    if kind != "Namespace":
        meta["namespace"] = setup.NAMESPACES[0]
    return {"apiVersion": setup.APIS[kind], "kind": kind, "metadata": meta, **extra}


def bundle(*objects: dict) -> dict:
    """No real cluster or credential input is used by these component checks."""
    return {"schema_version": 1, "expected_server": setup.SERVER, "objects": list(objects)}


def controller(name: str = "fixture-app") -> dict:
    """One pinned, restricted synthetic workload."""
    return obj("Deployment", name, spec={"replicas": 1, "template": {"spec": {
        "securityContext": {"runAsUser": 1000, "fsGroup": 1000},
        "containers": [{"name": "app", "image": "registry.example/app@sha256:" + "a" * 64}],
        "volumes": []}}})


class API:
    """Model real create/get/dry-run/DeleteOptions semantics without live mutation."""

    def __init__(self) -> None:
        self.objects = {}
        self.events = []
        self.lose_response = False
        self.denied_resources = set()
        self.username = "platform-eng"

    def call(self, args: object, *words: str, value: dict = None) -> dict:
        self.events.append((words, deepcopy(value)))
        if value and value.get("kind") == "SelfSubjectReview":
            return {"status": {"userInfo": {"username": self.username}}}
        if value and value.get("kind") == "SelfSubjectAccessReview":
            resource = value["spec"]["resourceAttributes"]["resource"]
            return {"status": {"allowed": resource not in self.denied_resources}}
        if words[0] == "get":
            resource, name = words[1:3]
            if resource == "namespace":
                resource = "namespaces"
            if resource == "sandboxes.agents.x-k8s.io":
                return {"items": []}
            kind = next(k for k, r in setup.RESOURCES.items() if r == resource)
            return deepcopy(self.objects.get((kind, name), {}))
        if words[0] == "create":
            result = deepcopy(value)
            result["metadata"]["uid"] = "uid-" + result["metadata"]["name"]
            result["metadata"]["resourceVersion"] = "1"
            if result["kind"] == "Namespace":
                result["metadata"].setdefault("annotations", {})["openshift.io/sa.scc.uid-range"] = "3000/100"
            if result["kind"] in setup.CONTROLLERS:
                result["metadata"]["generation"] = 1
                result["status"] = {"readyReplicas": 1, "observedGeneration": 1}
            if "--dry-run=server" not in words:
                key = result["kind"], result["metadata"]["name"]
                assert key not in self.objects
                self.objects[key] = result
                if self.lose_response:
                    raise RuntimeError("synthetic lost create response")
            return result
        if words[0] == "replace":
            assert "--dry-run=server" in words
            return deepcopy(value)
        if words[0] == "delete":
            assert words[1] == "--raw"
            name = words[2].split("/")[-1]
            key, current = next((k, v) for k, v in self.objects.items() if k[1] == name)
            assert value["preconditions"] == {"uid": current["metadata"]["uid"], "resourceVersion": "1"}
            del self.objects[key]
            return {"status": "Success"}
        raise AssertionError(words)


@pytest.mark.parametrize("mode", ["plan", "apply", "existing", "collision", "unowned"])
def test_discovery_attachment_is_narrow_and_create_only(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: str) -> None:
    """A parallel issuer gets one port to owned discovery without policy adoption."""
    from deployment_profile import DeploymentProfile, LEGACY
    profile = DeploymentProfile.from_dict({**LEGACY.to_dict(), "installation_id": "fresh-check",
                                           "core_namespace": "fresh-core"})
    created = []
    existing = None
    def call(options: object, *words: str, value: dict | None = None) -> dict:
        nonlocal existing
        if words[:2] == ("get", "namespace"):
            return {"metadata": {"labels": dict(profile.labels)}}
        if words[:2] == ("get", "deployment.apps"):
            labels = dict(profile.labels)
            if mode == "unowned":
                labels.pop("identity-demo-owner")
            return {"metadata": {"labels": labels}, "spec": {"template": {"metadata": {
                "labels": {"app": words[2], "identity-demo-owner": profile.owner}}}}}
        if words[:2] == ("get", "networkpolicy"):
            if mode in ("existing", "collision"):
                prior = tmp_path / "discovery-access.plan.json"
                assert not prior.exists()
                # Generate the same policy through a preceding isolated plan.
                return existing or {}
            return {}
        if words[0] == "create":
            assert value["metadata"]["namespace"] == profile.identity_namespace
            rule = value["spec"]["ingress"][0]
            assert rule["ports"] == [{"protocol": "TCP", "port": 8443}]
            assert rule["from"][0]["namespaceSelector"]["matchLabels"] == {
                "kubernetes.io/metadata.name": "fresh-core"}
            assert rule["from"][0]["podSelector"]["matchLabels"] == {
                "app": "fixture-keycloak-upstream", "identity-demo-owner": profile.owner}
            if "--dry-run=server" not in words:
                created.append(deepcopy(value))
            return deepcopy(value)
        raise AssertionError(words)
    monkeypatch.setattr(setup, "kube", call)
    options = argparse.Namespace(profile=profile, output_dir=tmp_path, apply=mode != "plan")
    if mode in ("existing", "collision"):
        # First render without mutation; keep exclusive receipt paths separate.
        pre = tmp_path / "prior"
        pre.mkdir()
        setup.discovery_access(argparse.Namespace(profile=profile, output_dir=pre, apply=False), [])
        existing = json.loads((pre / "discovery-access.plan.json").read_text())
        if mode == "collision":
            existing["spec"]["ingress"][0]["ports"][0]["port"] = 443
    if mode in ("collision", "unowned"):
        with pytest.raises(ValueError):
            setup.discovery_access(options, [])
        assert not created
    else:
        result = setup.discovery_access(options, [])
        assert result["existing_foundation_resources_modified"] is False
        assert len(created) == (1 if mode == "apply" else 0)
        assert result["policy_present"] == (mode != "plan")


def args(tmp_path: Path, **extra: object) -> argparse.Namespace:
    """Use a private local artifact directory with explicit operation flags."""
    return argparse.Namespace(output_dir=tmp_path, apply=True, server_dry_run=False,
        bundle_sha256="synthetic-reviewed-hash", namespace_uid_ranges={setup.NAMESPACES[0]: "1000/100"}, **extra)


def access_objects() -> list[dict]:
    """Select only the synthetic installer's routing and namespace inputs."""
    return [*[obj("Namespace", name) for name in setup.NAMESPACES],
            obj("Gateway", "fixture-mcp", spec={}),
            obj("HTTPRoute", "fixture-jira", spec={}),
            obj("HTTPRoute", "fixture-mcp-bound", spec={})]


@pytest.mark.parametrize("apply", [False, True])
def test_prepare_access_is_explicit_namespaced_and_create_only(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, apply: bool) -> None:
    """No shared grants, group grants, ServiceAccounts or other namespaces change."""
    api = API()
    monkeypatch.setattr(setup, "kube", api.call)
    options = args(tmp_path, installer_user="platform-eng")
    options.apply = apply
    result = setup.prepare_access(options, access_objects())
    assert result["existing_resources_modified"] is False
    assert result["shared_foundation_modified"] is False
    assert len(api.objects) == (5 if apply else 0)
    plan = json.loads((tmp_path / "access.plan.private.json").read_text())["objects"]
    role = next(o for o in plan if o["kind"] == "Role")
    binding = next(o for o in plan if o["kind"] == "RoleBinding")
    assert binding["subjects"] == [{"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": "platform-eng"}]
    assert role["metadata"]["namespace"] == setup.NAMESPACES[0]
    assert {r["resources"][0] for r in role["rules"]} == {"gateways", "httproutes"}
    for rule in role["rules"]:
        assert rule["apiGroups"] == ["gateway.networking.k8s.io"]
        if rule["verbs"] == ["create"]:
            assert "resourceNames" not in rule
        else:
            assert rule["resourceNames"] in (["fixture-mcp"], ["fixture-jira", "fixture-mcp-bound"])
            assert rule["verbs"] == ["get", "update", "patch", "delete"]
    if apply:
        again = tmp_path / "again"
        again.mkdir()
        options.output_dir = again
        assert setup.prepare_access(options, access_objects())["created"] == []
    else:
        assert result["admission_deferred"] == 2


@pytest.mark.parametrize("unsafe", ["admin", "mismatch", "foreign-namespace", "terminating", "broad-role", "other-subject", "denied"])
def test_prepare_access_fails_without_modifying_existing_resources(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unsafe: str) -> None:
    """No admin fallback, silent grant narrowing, foreign adoption or mutation retry."""
    api = API()
    monkeypatch.setattr(setup, "kube", api.call)
    options = args(tmp_path, installer_user="platform-eng")
    if unsafe == "admin":
        options.installer_user = "admin"
    elif unsafe == "mismatch":
        api.username = "somebody-else"
    elif unsafe in ("foreign-namespace", "terminating"):
        ns = obj("Namespace", setup.NAMESPACES[0])
        if unsafe == "foreign-namespace":
            ns["metadata"]["labels"]["identity-demo-owner"] = "somebody-else"
        else:
            ns["metadata"]["deletionTimestamp"] = "2026-01-01T00:00:00Z"
        api.objects[("Namespace", setup.NAMESPACES[0])] = ns
    elif unsafe in ("broad-role", "other-subject"):
        prior = tmp_path / "prior"
        prior.mkdir()
        setup.prepare_access(args(prior, installer_user="platform-eng"), access_objects())
        target = api.objects[("Role" if unsafe == "broad-role" else "RoleBinding", "fixture-installer-gateway-access")]
        if unsafe == "broad-role":
            target["rules"][0]["verbs"].append("*")
        else:
            target["subjects"][0]["name"] = "somebody-else"
        api.events.clear()
    elif unsafe == "denied":
        api.denied_resources.add("roles")
    before = deepcopy(api.objects)
    if unsafe == "denied":
        assert setup.prepare_access(options, access_objects())["ready"] is False
    else:
        with pytest.raises(ValueError):
            setup.prepare_access(options, access_objects())
    assert api.objects == before


def test_prepare_access_stops_after_uncertain_create(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Persist intent before namespace creation; never blindly retry a lost response."""
    api = API()
    api.lose_response = True
    monkeypatch.setattr(setup, "kube", api.call)
    with pytest.raises(RuntimeError):
        setup.prepare_access(args(tmp_path, installer_user="platform-eng"), access_objects())
    assert len(api.objects) == 1
    assert json.loads((tmp_path / "access-0.pending.json").read_text())["kind"] == "Namespace"
    assert not list(tmp_path.glob("access-*.created.json"))
    persisted = [value for words, value in api.events if words[0] == "create"
                 and "--dry-run=server" not in words
                 and value["kind"] not in ("SelfSubjectReview", "SelfSubjectAccessReview")]
    assert len(persisted) == 1


@pytest.mark.parametrize("change", ["namespace", "owner", "api", "kind", "name"])
def test_scope_owner_and_api_cannot_be_selected_by_bundle(change: str) -> None:
    """A familiar name or caller-supplied label alone must not expand scope."""
    item = obj("Service", "fixture-test", spec={})
    if change == "namespace":
        item["metadata"]["namespace"] = "mcp-system"
    elif change == "owner":
        item["metadata"]["labels"] = {}
    elif change == "api":
        item["apiVersion"] = "unreviewed.example/v1"
    elif change == "kind":
        item["kind"] = "ClusterRoleBinding"
    else:
        item["metadata"]["name"] = "../../unrelated"
    with pytest.raises(ValueError):
        setup.validate(bundle(item))


@pytest.mark.parametrize("change", ["tag", "hostNetwork", "hostPath", "privileged"])
def test_image_and_pod_privilege_guards(change: str) -> None:
    item = controller()
    pod = item["spec"]["template"]["spec"]
    if change == "tag":
        pod["containers"][0]["image"] = "registry.example/app:latest"
    elif change == "hostPath":
        pod["volumes"] = [{"name": "root", "hostPath": {"path": "/"}}]
    elif change == "privileged":
        pod["containers"][0]["securityContext"] = {"privileged": True}
    else:
        pod[change] = True
    with pytest.raises(ValueError):
        setup.validate(bundle(item))


def test_duplicate_and_controller_owned_objects_refused() -> None:
    item = obj("Service", "fixture-test", spec={})
    with pytest.raises(ValueError):
        setup.validate(bundle(item, deepcopy(item)))
    item["metadata"]["ownerReferences"] = [{"controller": True}]
    with pytest.raises(ValueError):
        setup.validate(bundle(item))


def test_clean_does_not_rebind_old_service_ip_or_pvc() -> None:
    service = obj("Service", "fixture-test", spec={"clusterIP": "10.0.0.1",
        "clusterIPs": ["10.0.0.1"], "ports": [{"port": 443, "nodePort": 30000}]})
    assert "clusterIP" not in setup.clean(service)["spec"]
    assert "nodePort" not in setup.clean(service)["spec"]["ports"][0]
    claim = obj("PersistentVolumeClaim", "fixture-state", spec={"volumeName": "existing-pv"})
    assert "volumeName" not in setup.clean(claim)["spec"]


def test_plan_cannot_adopt_or_mutate_occupied_objects(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    api = API()
    item = obj("Service", "fixture-test", spec={})
    api.objects[("Service", "fixture-test")] = deepcopy(item)
    api.objects[("Service", "fixture-test")]["metadata"]["resourceVersion"] = "1"
    monkeypatch.setattr(setup, "kube", api.call)
    options = args(tmp_path)
    options.server_dry_run = True
    result = setup.plan(options, [item])
    assert not result["ready_for_create"] and not result["cluster_changed"]
    assert result["admission_blocked_occupied_objects"] == 1
    assert result["admission_checked_absent_objects"] == 0
    assert all(e[0][0] == "get" or "--dry-run=server" in e[0] for e in api.events)
    with pytest.raises(ValueError):
        setup.install(options, [item])


def test_create_uid_rebase_readiness_and_cleanup_preserve_state(tmp_path: Path,
                                                             monkeypatch: pytest.MonkeyPatch) -> None:
    api = API()
    monkeypatch.setattr(setup, "kube", api.call)
    objects = setup.validate(bundle(obj("Namespace", setup.NAMESPACES[0]),
        obj("Secret", "fixture-private", data={"synthetic": "value"}),
        obj("PersistentVolumeClaim", "fixture-state", spec={}),
        obj("Service", "fixture-app", spec={}), controller(), controller("fixture-jira")))
    options = args(tmp_path)
    assert setup.install(options, objects)["completed"]
    assert setup.verify(options, objects)["ready"]
    assert api.objects[("Deployment", "fixture-app")]["spec"]["template"]["spec"]["securityContext"]["runAsUser"] == 3000
    ledger = tmp_path / "creation-ledger.private.json"
    options.ledger = str(ledger)
    options.apply = False
    planned = setup.cleanup(options)
    assert planned["eligible_objects"] == 2
    assert ("Deployment", "fixture-app") in api.objects
    options.apply = True
    assert setup.cleanup(options)["applied"]
    assert ("Deployment", "fixture-app") not in api.objects
    assert all(k in api.objects for k in [("Secret", "fixture-private"),
        ("PersistentVolumeClaim", "fixture-state"), ("Namespace", setup.NAMESPACES[0]), ("Deployment", "fixture-jira")])


def test_install_checks_all_create_permissions_before_persisting(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A late Gateway denial must leave namespaces, keys and workloads absent."""
    api = API()
    api.denied_resources.add("gateways")
    monkeypatch.setattr(setup, "kube", api.call)
    objects = setup.validate(bundle(obj("Namespace", setup.NAMESPACES[0]),
        obj("Secret", "fixture-private", data={"synthetic": "value"}),
        obj("Gateway", "fixture-mcp", spec={})))
    with pytest.raises(ValueError, match="Missing application create permissions"):
        setup.install(args(tmp_path), objects)
    assert not api.objects
    assert not (tmp_path / "creation-ledger.private.json").exists()
    receipt = json.loads((tmp_path / "installation-permissions.json").read_text())
    assert receipt["missing_create_permissions"] == [{"group": "gateway.networking.k8s.io",
        "resource": "gateways", "verb": "create", "namespace": setup.NAMESPACES[0]}]
    assert all(value.get("kind") == "SelfSubjectAccessReview" or "--dry-run=server" in words
               for words, value in api.events if words[0] == "create")


def test_existing_owned_namespace_needs_no_namespace_create_permission(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Retaining an owned namespace must not require permission to recreate it."""
    api = API()
    api.objects[("Namespace", setup.NAMESPACES[0])] = obj("Namespace", setup.NAMESPACES[0])
    api.denied_resources.add("namespaces")
    monkeypatch.setattr(setup, "kube", api.call)
    objects = [obj("Namespace", setup.NAMESPACES[0]), obj("Service", "fixture-app", spec={})]
    assert setup.install(args(tmp_path), objects)["completed"]
    reviews = [value for _, value in api.events
               if value and value.get("kind") == "SelfSubjectAccessReview"]
    assert all(v["spec"]["resourceAttributes"]["resource"] != "namespaces" for v in reviews)


def test_plan_on_empty_target_records_deferred_namespace_admission(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Planning must not mutate an empty target to make dry-run admission work."""
    api = API()
    monkeypatch.setattr(setup, "kube", api.call)
    options = args(tmp_path)
    options.server_dry_run = True
    namespace = obj("Namespace", setup.NAMESPACES[0])
    service = obj("Service", "fixture-app", spec={})
    result = setup.plan(options, [namespace, service])
    assert result["ready_for_create"]
    assert result["admission_checked_absent_objects"] == 1
    assert result["admission_deferred_missing_namespace"] == 1
    assert not api.objects
    api.objects[("Namespace", setup.NAMESPACES[0])] = namespace
    result = setup.plan(options, [namespace, service])
    assert result["admission_checked_absent_objects"] == 1
    assert result["admission_deferred_missing_namespace"] == 0


@pytest.mark.parametrize("change", ["uid", "marker", "spec"])
def test_cleanup_refuses_replacement_or_drift(tmp_path: Path,
                                          monkeypatch: pytest.MonkeyPatch, change: str) -> None:
    api = API()
    monkeypatch.setattr(setup, "kube", api.call)
    options = args(tmp_path)
    setup.install(options, [obj("Service", "fixture-test", spec={})])
    options.ledger = str(tmp_path / "creation-ledger.private.json")
    current = api.objects[("Service", "fixture-test")]
    if change == "uid":
        current["metadata"]["uid"] = "replacement"
    elif change == "marker":
        current["metadata"]["labels"]["identity-demo-installation"] = "unrelated"
    else:
        current["spec"]["ports"] = [{"port": 1234}]
    with pytest.raises(ValueError):
        setup.cleanup(options)
    assert not any(e[0][0] == "delete" for e in api.events)


def test_uncertain_create_is_journaled_and_never_retried_or_deleted(tmp_path: Path,
                                                               monkeypatch: pytest.MonkeyPatch) -> None:
    api = API()
    api.lose_response = True
    monkeypatch.setattr(setup, "kube", api.call)
    options = args(tmp_path)
    with pytest.raises(RuntimeError):
        setup.install(options, [obj("Service", "fixture-test", spec={})])
    options.ledger = str(tmp_path / "creation-ledger.private.json")
    ledger = json.loads(Path(options.ledger).read_text())
    assert ledger["pending"]["metadata"]["name"] == "fixture-test"
    with pytest.raises(ValueError):
        setup.cleanup(options)
    assert len([e for e in api.events if e[0][0] == "create" and "--dry-run=server" not in e[0]
                and e[1].get("kind") != "SelfSubjectAccessReview"]) == 1


def test_resume_reconciles_lost_response_and_preserves_original_ledger(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A confirmed pending create is recorded once, with no overwrite or replay."""
    api = API()
    monkeypatch.setattr(setup, "kube", api.call)
    options = args(tmp_path)
    objects = [obj("Service", "fixture-first", spec={}), obj("Service", "fixture-next", spec={})]
    api.lose_response = True
    with pytest.raises(RuntimeError):
        setup.install(options, objects)
    original = tmp_path / "creation-ledger.private.json"
    before = original.read_bytes()
    output = tmp_path / "resumed"
    output.mkdir(mode=0o700)
    api.lose_response = False
    options.action = "resume"
    options.ledger = str(original)
    options.output_dir = output
    assert setup.install(options, objects)["completed"]
    assert original.read_bytes() == before
    ledger = json.loads((output / original.name).read_text())
    assert len(ledger["created"]) == 2
    assert not ledger["pending"]
    assert ledger["completed"]
    creates = [value for words, value in api.events
               if words[0] == "create" and "--dry-run=server" not in words
               and value.get("kind") != "SelfSubjectAccessReview"]
    assert [item["metadata"]["name"] for item in creates] == ["fixture-first", "fixture-next"]


@pytest.mark.parametrize("change", ["owner", "marker", "spec", "bundle", "uid"])
def test_resume_refuses_replacement_and_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                            change: str) -> None:
    """Continuing an installation cannot claim a changed or unowned resource."""
    api = API()
    monkeypatch.setattr(setup, "kube", api.call)
    options = args(tmp_path)
    objects = [obj("Service", "fixture-test", spec={})]
    setup.install(options, objects)
    original = tmp_path / "creation-ledger.private.json"
    options.action = "resume"
    options.ledger = str(original)
    options.output_dir = tmp_path / "resumed"
    options.output_dir.mkdir(mode=0o700)
    current = api.objects[("Service", "fixture-test")]
    if change == "owner":
        current["metadata"]["labels"]["identity-demo-owner"] = "another-owner"
    elif change == "marker":
        current["metadata"]["labels"]["identity-demo-installation"] = "another-install"
    elif change == "spec":
        current["spec"]["ports"] = [{"port": 1234}]
    elif change == "uid":
        current["metadata"]["uid"] = "replacement"
    else:
        options.bundle_sha256 = "other-bundle"
    before = len(api.events)
    with pytest.raises(ValueError):
        setup.install(options, objects)
    assert all(words[0] == "get" for words, _ in api.events[before:])


def test_api_failures_do_not_expose_response_or_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(setup.subprocess, "run", lambda *a, **k: SimpleNamespace(
        returncode=1, stdout="synthetic-private-body", stderr="synthetic-secret"))
    with pytest.raises(RuntimeError) as error:
        setup.kube(SimpleNamespace(oc="oc", kubeconfig="private"), "get", "secret")
    assert "synthetic-private" not in str(error.value) and "synthetic-secret" not in str(error.value)


def test_private_inputs_reject_other_git_checkout(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    value = tmp_path / "input.json"
    value.write_text("{}")
    value.chmod(0o600)
    with pytest.raises(ValueError):
        setup.private_file(str(value))


@pytest.mark.parametrize("failure", [None, "tls", "version", "unestablished", "trust-domain", "foundation-owner"])
def test_target_checks_served_apis_and_actual_identity_foundation(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str | None) -> None:
    """An installed CRD name alone does not prove the required API is usable."""
    config = tmp_path / "kubeconfig"
    config.write_text("synthetic config")
    config.chmod(0o600)
    def call(options: object, *words: str, value: dict = None) -> dict:
        assert words[0] in ("config", "get")
        if words[0] == "config":
            return {"clusters": [{"cluster": {"server": setup.SERVER,
                        "insecure-skip-tls-verify": failure == "tls"}}]}
        if words[1] == "namespace":
            return obj("Namespace", words[2]) if words[2] == setup.LEGACY.identity_namespace else {}
        if words[1] == "crd":
            versions = ["v1", "v1alpha1", "v1alpha3", "v1beta1"]
            return {"spec": {"versions": [{"name": v, "served": failure != "version"} for v in versions]},
                    "status": {"conditions": [{"type": "Established", "status": "False" if failure == "unestablished" else "True"}]}}
        if words[1] == "zerotrustworkloadidentitymanager.operator.openshift.io":
            return {"metadata": {"labels": {"identity-demo-owner": "other-owner" if failure == "foundation-owner" else setup.LEGACY.owner}},
                    "spec": {"trustDomain": "wrong.example.org" if failure == "trust-domain" else setup.LEGACY.trust_domain,
                             "clusterName": setup.LEGACY.cluster_name}}
        assert words[1] == "storageclass"
        return {}
    monkeypatch.setattr(setup, "kube", call)
    options = argparse.Namespace(kubeconfig=str(config), expected_server=setup.SERVER, profile=setup.LEGACY)
    if failure:
        with pytest.raises(ValueError):
            setup.target(options)
    else:
        assert setup.target(options)["cluster_changed"] is False


@pytest.mark.parametrize('apply', [False, True])
def test_native_runtime_grants_are_separate_and_create_only(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, apply: bool) -> None:
    """Native prerequisites cannot modify an existing shared grant or workload."""
    existing, events = {}, []
    def call(options: object, *words: str, value: dict = None) -> dict:
        events.append((words, deepcopy(value)))
        if words[0] == 'get':
            if words[1] in ('serviceaccount', 'statefulset'):
                return {'metadata': {'name': words[2], 'labels': dict(LABELS)}}
            return deepcopy(existing.get((words[1], words[2]), {}))
        assert words[0] == 'create' and value['kind'] in ('ClusterRole', 'ClusterRoleBinding')
        result = deepcopy(value)
        result['metadata']['uid'] = 'uid-' + result['metadata']['name']
        if '--dry-run=server' not in words:
            existing[(result['kind'], result['metadata']['name'])] = result
        return result
    monkeypatch.setattr(setup, 'kube', call)
    options = args(tmp_path)
    options.apply = apply
    role = obj('Role', 'fixture-openshell-sandbox', rules=[
        {'apiGroups': ['agents.x-k8s.io'], 'resources': ['sandboxes'], 'verbs': ['get', 'create']}])
    result = setup.runtime_permissions(options, [role])
    assert result['required_grants'] == 4
    assert len(result['created']) == (4 if apply else 0)
    assert result['bindings_deferred_until_role_exists'] == (0 if apply else 2)
    assert not result['existing_resources_modified']
    if apply:
        options.output_dir = tmp_path / 'again'
        options.output_dir.mkdir(mode=0o700)
        count = len(events)
        assert setup.runtime_permissions(options, [role])['existing_exact_grants'] == 4
        assert all(words[0] == 'get' for words, _ in events[count:])


@pytest.mark.parametrize('change', ['owner', 'rules'])
def test_native_runtime_grants_refuse_broader_or_unowned_collision(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str) -> None:
    """A name match cannot authorize adoption or repair of a different grant."""
    from identity_demo_runtime_grants import desired
    role, _ = desired()
    role = deepcopy(role)
    if change == 'owner':
        role['metadata']['labels']['identity-demo-owner'] = 'someone-else'
    else:
        role['rules'].append({'apiGroups': [''], 'resources': ['secrets'], 'verbs': ['get']})
    def call(options: object, *words: str, value: dict = None) -> dict:
        assert words[0] == 'get'
        if words[1] in ('serviceaccount', 'statefulset'):
            return {'metadata': {'name': words[2], 'labels': dict(LABELS)}}
        return role if words[1] == 'ClusterRole' and words[2] == role['metadata']['name'] else {}
    monkeypatch.setattr(setup, 'kube', call)
    source = obj('Role', 'fixture-openshell-sandbox', rules=[
        {'apiGroups': ['agents.x-k8s.io'], 'resources': ['sandboxes'], 'verbs': ['get']}])
    with pytest.raises(ValueError):
        setup.runtime_permissions(args(tmp_path), [source])


@pytest.mark.parametrize('repository', ['owned', 'external', 'foreign', 'tag', 'nested'])
def test_native_image_pulls_are_repository_and_serviceaccount_scoped(repository: str) -> None:
    """Internal image access cannot grant broad pulls or reach another namespace."""
    profile = setup.LEGACY
    image = ('image-registry.openshift-image-registry.svc:5000/'
             + profile.core_namespace + '/native-supervisor@sha256:' + 'a' * 64)
    if repository == 'external':
        image = 'registry.example/native-supervisor@sha256:' + 'a' * 64
    elif repository == 'foreign':
        image = image.replace(profile.core_namespace, 'someone-else')
    elif repository == 'tag':
        image = image.split('@')[0] + ':latest'
    elif repository == 'nested':
        image = image.replace('/native-supervisor@', '/nested/native-supervisor@')
    source = obj('ConfigMap', 'fixture-openshell-config', data={
        'gateway.toml': '[openshell.drivers.kubernetes]\nsupervisor_image = "' + image + '"\n'})
    if repository in ('foreign', 'tag', 'nested'):
        with pytest.raises(ValueError):
            setup.runtime_image_grants(profile, [source])
        return
    grants = setup.runtime_image_grants(profile, [source])
    if repository == 'external':
        assert grants == []
        return
    role, binding = grants
    assert role['rules'] == [{'apiGroups': ['image.openshift.io'],
        'resources': ['imagestreams/layers'], 'resourceNames': ['native-supervisor'], 'verbs': ['get']}]
    assert role['metadata']['namespace'] == profile.core_namespace
    assert binding['subjects'] == [{'kind': 'ServiceAccount', 'name': 'fixture-openshell-sandbox',
        'namespace': ns} for ns in profile.application_namespaces[1:]]
    assert binding['roleRef']['kind'] == 'Role'


@pytest.mark.parametrize('failure', [None, 'stream-owner', 'repository', 'account-owner', 'grant-rules'])
def test_native_runtime_image_access_checks_all_ownership_before_creating(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str | None) -> None:
    """Only a new exact namespaced pull grant can extend the four native grants."""
    from identity_demo_runtime_grants import desired
    from identity_demo_workspaces import render
    profile = setup.LEGACY
    source = obj('Role', 'fixture-openshell-sandbox', rules=[
        {'apiGroups': ['agents.x-k8s.io'], 'resources': ['sandboxes'], 'verbs': ['get']}])
    config = obj('ConfigMap', 'fixture-openshell-config', data={'gateway.toml':
        '[openshell.drivers.kubernetes]\nsupervisor_image = "image-registry.openshift-image-registry.svc:5000/'
        + profile.core_namespace + '/native-supervisor@sha256:' + 'a' * 64 + '"\n'})
    existing = {(g['kind'], g['metadata']['name']): g for g in
                [*desired(), *[g for g in render(source['rules']) if g['kind'] in ('ClusterRole', 'ClusterRoleBinding')]]}
    for grant in existing.values():
        grant['metadata']['uid'] = 'existing-' + grant['kind']
    creates = []
    def call(options: object, *words: str, value: dict = None) -> dict:
        if words[0] == 'get':
            kind, name = words[1:3]
            if kind in ('namespace', 'serviceaccount', 'statefulset'):
                result = {'metadata': {'name': name, 'labels': dict(LABELS)}}
                if failure == 'account-owner' and kind == 'serviceaccount' and name == 'fixture-openshell-sandbox':
                    result['metadata']['labels']['identity-demo-owner'] = 'other'
                return result
            if kind == 'imagestream':
                result = {'apiVersion': 'image.openshift.io/v1', 'kind': 'ImageStream',
                    'metadata': {'name': name, 'namespace': profile.core_namespace, 'labels': dict(LABELS)},
                    'status': {'dockerImageRepository':
                        'image-registry.openshift-image-registry.svc:5000/' + profile.core_namespace + '/' + name}}
                if failure == 'stream-owner':
                    result['metadata']['labels']['identity-demo-owner'] = 'other'
                elif failure == 'repository':
                    result['status']['dockerImageRepository'] += '-different'
                return result
            if failure == 'grant-rules' and kind == 'Role':
                result = setup.runtime_image_grants(profile, [config])[0]
                result['rules'][0].pop('resourceNames')
                return result
            return deepcopy(existing.get((kind, name), {}))
        assert words[0] == 'create'
        creates.append((words, deepcopy(value)))
        result = deepcopy(value)
        result['metadata']['uid'] = 'new-' + result['kind']
        return result
    monkeypatch.setattr(setup, 'kube', call)
    options = args(tmp_path)
    options.apply = True
    if failure:
        with pytest.raises(ValueError):
            setup.runtime_permissions(options, [source, config])
        assert not creates
    else:
        result = setup.runtime_permissions(options, [source, config])
        assert result['required_grants'] == 6
        assert result['existing_exact_grants'] == 4
        assert result['exact_repository_pull_grants'] == 2
        assert [v['kind'] for _, v in creates] == ['Role', 'Role', 'RoleBinding', 'RoleBinding']


def test_verify_refuses_stale_generation_and_changed_init_image(tmp_path: Path,
                                                             monkeypatch: pytest.MonkeyPatch) -> None:
    """Old ready replicas cannot stand in for the desired rollout."""
    api = API()
    monkeypatch.setattr(setup, "kube", api.call)
    desired = controller()
    desired['spec']['template']['spec']['initContainers'] = [
        {'name': 'prepare', 'image': 'registry.example/prepare@sha256:' + 'b' * 64}]
    options = args(tmp_path)
    setup.install(options, [obj('Namespace', setup.NAMESPACES[0]), desired])
    current = api.objects[('Deployment', 'fixture-app')]
    current['metadata']['generation'] = 2
    assert not setup.verify(options, [desired])['ready']
    current['status']['observedGeneration'] = 2
    current['spec']['template']['spec']['initContainers'][0]['image'] = 'registry.example/prepare@sha256:' + 'c' * 64
    assert not setup.verify(options, [desired])['ready']


@pytest.mark.parametrize("kind", ["Role", "RoleBinding", "NetworkPolicy"])
def test_verify_checks_actual_rbac_and_network_isolation(tmp_path, monkeypatch, kind) -> None:
    """An owned ready installation with broadened enforcement is not verified."""
    fields = {
        "Role": {"rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}]},
        "RoleBinding": {"roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "fixture-role"},
                        "subjects": [{"kind": "ServiceAccount", "name": "fixture-openshell", "namespace": setup.NAMESPACES[0]}]},
        "NetworkPolicy": {"spec": {"podSelector": {}, "policyTypes": ["Egress"], "egress": []}},
    }
    desired = obj(kind, "fixture-enforcement", **fields[kind])
    current = deepcopy(desired)
    monkeypatch.setattr(setup, "get", lambda *_: current)
    assert setup.verify(args(tmp_path), [desired])["ready"]
    if kind == "Role":
        current["rules"][0]["verbs"] = ["*"]
    elif kind == "RoleBinding":
        current["subjects"].append({"kind": "User", "name": "unrelated"})
    else:
        current["spec"]["egress"] = [{}]
    result = setup.verify(args(tmp_path), [desired])
    assert not result["ready"] and kind + "/fixture-enforcement" in result["failures"]


@pytest.mark.parametrize("kind,conditions", [
    ("Gateway", ["Accepted", "Programmed"]),
    ("AuthPolicy", ["Accepted", "Enforced"]),
    ("MCPGatewayExtension", ["Ready"]),
])
def test_verify_requires_current_policy_and_gateway_conditions(kind: str,
                                                              conditions: list[str]) -> None:
    """Ready Pods alone cannot establish functioning gateway/policy controllers."""
    value = obj(kind, "fixture-test", spec={})
    value["metadata"]["generation"] = 2
    value["status"] = {"observedGeneration": 2, "conditions": [
        {"type": name, "status": "True"} for name in conditions]}
    assert setup.reconciled(value)
    value["status"]["observedGeneration"] = 1
    assert not setup.reconciled(value)
    value["status"]["observedGeneration"] = 2
    value["status"]["conditions"][0]["status"] = "False"
    assert not setup.reconciled(value)


def test_route_requires_exact_reconciled_parent() -> None:
    """An accepted different listener does not prove the intended route works."""
    value = obj("HTTPRoute", "fixture-test", spec={"parentRefs": [
        {"name": "fixture-mcp", "sectionName": "bound"}]})
    value["metadata"]["generation"] = 2
    parent = {"parentRef": {"name": "fixture-mcp", "sectionName": "bound"},
              "conditions": [{"type": name, "status": "True", "observedGeneration": 2}
                             for name in ("Accepted", "ResolvedRefs")]}
    value["status"] = {"parents": [parent]}
    assert setup.reconciled(value)
    parent["parentRef"]["sectionName"] = "other"
    assert not setup.reconciled(value)


@pytest.mark.parametrize('unsafe', ['disable_tls = true', 'allow_unauthenticated_users = true'])
def test_gateway_config_cannot_disable_authentication_or_tls(unsafe: str) -> None:
    """Installation cannot weaken the native runtime's entry boundary."""
    config = '[openshell.gateway]\ndisable_tls = false\n[openshell.gateway.auth]\nallow_unauthenticated_users = false\n'
    name = unsafe.split(' = ')[0]
    config = config.replace(name + ' = false', unsafe)
    with pytest.raises(ValueError):
        setup.validate(bundle(obj('ConfigMap', 'fixture-openshell-config', data={'gateway.toml': config})))


def test_realm_export_preserves_roles_and_skips_bearer_only_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keycloak's default bearer-only clients have no retrievable secret."""
    import identity_demo_adapter
    import identity_demo_keycloak_upstream
    calls = []
    def request(base: str, path: str, **kwargs: object) -> tuple:
        calls.append(path)
        if path.endswith('/token'):
            return 200, {'access_token': 'synthetic'}
        if '/partial-export?' in path:
            return 200, {'clients': [
                {'id': 'bearer', 'clientId': 'realm-management', 'clientAuthenticatorType': 'client-secret', 'bearerOnly': True},
                {'id': 'service', 'clientId': 'service', 'clientAuthenticatorType': 'client-secret', 'serviceAccountsEnabled': True}]}
        if '/users?username=' in path:
            return 200, [{'id': path.split('username=')[1].split('&')[0]}]
        if path.endswith('/client-secret'):
            assert '/bearer/' not in path
            return 200, {'value': 'synthetic-secret'}
        if path.endswith('/service-account-user'):
            return 200, {'id': 'service-user'}
        if path.endswith('/role-mappings'):
            return 200, {'realmMappings': [{'name': 'role'}], 'clientMappings': {}}
        raise AssertionError(path)
    monkeypatch.setattr(identity_demo_adapter, 'fixture_request', request)
    monkeypatch.setattr(identity_demo_keycloak_upstream, 'issuer_request', request)
    for base in ('https://synthetic-original', identity_demo_keycloak_upstream.BASE):
        exported = setup.realm_export(base, {'keycloak_admin': 'synthetic', 'analyst': 'synthetic', 'viewer': 'synthetic'})
        assert exported['clients'][1]['secret'] == 'synthetic-secret'
        assert len(exported['users']) == 3
        assert all(u['realmRoles'] == ['role'] for u in exported['users'])
    assert not any('/clients/bearer/' in path for path in calls)


@pytest.mark.parametrize('unsafe', [None, 'wrong-owner', 'wrong-type', 'other-reference', 'changed-config'])
def test_resume_verifies_generated_pull_secret_additions(monkeypatch: pytest.MonkeyPatch, unsafe: str | None) -> None:
    """Only a registry credential owned by the exact ServiceAccount may differ."""
    desired = obj('ServiceAccount', 'fixture-test', automountServiceAccountToken=False)
    current = deepcopy(desired)
    current['metadata']['uid'] = 'account-uid'
    current['secrets'] = [{'name': 'fixture-test-dockercfg-abcde'}]
    current['imagePullSecrets'] = deepcopy(current['secrets'])
    secret = {'type': 'kubernetes.io/dockercfg', 'metadata': {'ownerReferences': [
        {'kind': 'ServiceAccount', 'name': 'fixture-test', 'uid': 'account-uid'}]}}
    if unsafe == 'wrong-owner':
        secret['metadata']['ownerReferences'][0]['uid'] = 'someone-else'
    elif unsafe == 'wrong-type':
        secret['type'] = 'Opaque'
    elif unsafe == 'other-reference':
        current['secrets'][0]['name'] = 'unrelated-credential'
    elif unsafe == 'changed-config':
        current['automountServiceAccountToken'] = True
    monkeypatch.setattr(setup, 'kube', lambda *a, **kw: secret)
    if unsafe in ('wrong-owner', 'wrong-type', 'other-reference'):
        with pytest.raises(ValueError):
            setup.recorded_configuration_matches(None, current, desired, setup.fingerprint(desired))
    else:
        assert setup.recorded_configuration_matches(None, current, desired, setup.fingerprint(desired)) == (unsafe is None)


@pytest.mark.parametrize('denied', [False, True])
def test_permission_preflight_queries_exact_api_and_namespace(monkeypatch: pytest.MonkeyPatch, denied: bool) -> None:
    """Requester permissions can fail before the first persisted application write."""
    queries = []
    def call(args: object, *words: str, value: dict) -> dict:
        assert words == ('create', '-f', '-', '-o', 'json')
        assert value['kind'] == 'SelfSubjectAccessReview'
        query = value['spec']['resourceAttributes']
        queries.append(query)
        return {'status': {'allowed': not (denied and query['resource'] == 'gateways')}}
    monkeypatch.setattr(setup, 'kube', call)
    result = setup.permissions(None, [obj('Gateway', 'fixture-mcp'),
        obj('Service', 'fixture-one'), obj('Service', 'fixture-two')])
    assert result['ready'] is not denied
    assert result['create_scopes_checked'] == 2
    assert not result['cluster_changed']
    assert queries[0] == {'group': 'gateway.networking.k8s.io', 'resource': 'gateways',
                          'namespace': setup.NAMESPACES[0], 'verb': 'create'}
    assert len(result['missing_create_permissions']) == int(denied)


@pytest.mark.parametrize('unsafe', [None, 'wrong-root', 'extra-data', 'annotation', 'ordinary-map'])
def test_resume_checks_injected_ca_against_platform_authority(monkeypatch: pytest.MonkeyPatch, unsafe: str | None) -> None:
    """Trust injection cannot hide arbitrary data or a replacement trust root."""
    desired = obj('ConfigMap', 'fixture-service-ca', data={})
    desired['metadata']['annotations'] = {'service.beta.openshift.io/inject-cabundle': 'true'}
    current = deepcopy(desired)
    current['data'] = {'service-ca.crt': 'synthetic-authority'}
    if unsafe == 'wrong-root':
        current['data']['service-ca.crt'] = 'attacker'
    elif unsafe == 'extra-data':
        current['data']['other'] = 'unexpected'
    elif unsafe == 'annotation':
        current['metadata']['annotations'] = {}
    elif unsafe == 'ordinary-map':
        desired['metadata']['annotations'] = {}
        current['metadata']['annotations'] = {}
    monkeypatch.setattr(setup, 'kube', lambda *a, **kw: {'data': {'service-ca.crt': 'synthetic-authority'}})
    if unsafe in ('wrong-root', 'extra-data', 'annotation'):
        with pytest.raises(ValueError):
            setup.recorded_configuration_matches(None, current, desired, setup.fingerprint(desired))
    else:
        assert setup.recorded_configuration_matches(None, current, desired, setup.fingerprint(desired)) == (unsafe is None)


@pytest.mark.parametrize("action,module,function", [
    ("diagnostic-build", "diagnostic_build", "diagnostic_build"),
    ("native-build", "native_build", "native_build"),
    ("verify-backup", "deployment_backup", "verify_backup"),
])
@pytest.mark.parametrize("failure", [False, True])
def test_local_setup_cli_never_contacts_cluster(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
        action: str, module: str, function: str, failure: bool) -> None:
    """Offline build/backup entry points retain summaries and sanitized failures."""
    from types import SimpleNamespace
    import sys

    output = tmp_path / "attempt"
    expected = {"synthetic": True, "ready": False}
    imports = []

    def local(options: argparse.Namespace) -> dict:
        assert options.action == action and options.output_dir == output
        assert options.kubeconfig is None and options.expected_server is None
        if failure:
            raise ValueError("synthetic-private-diagnostic-must-not-be-printed")
        return expected

    def load(name: str) -> object:
        imports.append(name)
        return SimpleNamespace(**{function: local})

    def no_cluster(*args: object, **kwargs: object) -> None:
        pytest.fail("Local setup action attempted a cluster operation")

    monkeypatch.setattr(setup, "import_module", load)
    monkeypatch.setattr(setup, "target", no_cluster)
    monkeypatch.setattr(setup, "kube", no_cluster)
    monkeypatch.setattr(sys, "argv", ["identity_demo_setup.py", action, "--output-dir", str(output)])
    if failure:
        with pytest.raises(SystemExit) as stopped:
            setup.main()
        assert stopped.value.code == 1
        assert json.loads(capsys.readouterr().out) == {
            "completed": False, "failure_kind": "ValueError", "details_withheld": True}
        assert not (output / "setup.summary.json").exists()
    else:
        setup.main()
        assert json.loads(capsys.readouterr().out) == expected
        receipt = output / "setup.summary.json"
        assert json.loads(receipt.read_text()) == expected
        assert receipt.stat().st_mode & 0o077 == 0
    assert imports == [module]


def test_private_files_cannot_land_in_source_archive_without_git(tmp_path,monkeypatch):
    repo=tmp_path/'source-archive';repo.mkdir();monkeypatch.setattr(setup,'ROOT',repo)
    key=repo/'input.json';key.write_text('{}');key.chmod(0o600)
    assert setup.in_checkout(key) and not (repo/'.git').exists()
    with pytest.raises(ValueError,match='outside checkout'):setup.private_file(str(key))


def test_administrator_prerequisites_require_original_uid_source_and_configuration(tmp_path,monkeypatch):
    from copy import deepcopy
    from argparse import Namespace
    from deployment_profile import LEGACY
    tmp_path.chmod(0o700)
    desired={'apiVersion':'rbac.authorization.k8s.io/v1','kind':'Role','metadata':{
        'name':'fixture-installer-scope','namespace':LEGACY.core_namespace,'labels':dict(LEGACY.labels)},
        'rules':[{'apiGroups':[''],'resources':['pods'],'verbs':['get']}]}
    current=deepcopy(desired);current['metadata'].update(uid='original-uid',resourceVersion='1')
    record={'object':deepcopy(current),'uid':'original-uid','fingerprint':setup.fingerprint(current),
            'declared_fingerprint':setup.fingerprint(desired)}
    path=tmp_path/'administrator.receipt.json'
    setup.write(path,{'schema_version':1,'installation_profile':LEGACY.to_dict(),
        'expected_server':LEGACY.expected_server,'created':[record]})
    args=Namespace(profile=LEGACY,administrator_receipt=str(path),administrator_receipt_sha256=setup.sha(path))
    assert setup.administrator_prepared(args,desired,current)
    for mutated in (dict(current,metadata=dict(current['metadata'],uid='replacement')),
                    dict(current,rules=[{'apiGroups':[''],'resources':['secrets'],'verbs':['get']}])):
        with pytest.raises(ValueError,match='identity or configuration'):setup.administrator_prepared(args,desired,mutated)
    with pytest.raises(ValueError,match='Application state'):
        setup.administrator_prepared(args,dict(desired,kind='Secret'),current)
    args.administrator_receipt_sha256='0'*64
    with pytest.raises(ValueError,match='receipt hash'):setup.administrator_prepared(args,desired,current)


@pytest.mark.parametrize('drift', [None, 'uid', 'rules'])
def test_install_retains_only_exact_prepared_grants_and_never_recreates_them(tmp_path, monkeypatch, drift):
    from deployment_profile import LEGACY
    tmp_path.chmod(0o700)
    api = API()
    monkeypatch.setattr(setup, 'kube', api.call)
    desired = obj('Role', 'fixture-reviewed', rules=[{
        'apiGroups': [''], 'resources': ['pods'], 'verbs': ['get']}])
    original = api.call(None, 'create', value=desired)
    receipt = tmp_path / 'administrator.json'
    setup.write(receipt, {'schema_version': 1, 'expected_server': LEGACY.expected_server,
        'installation_profile': LEGACY.to_dict(), 'created': [{
            'object': original, 'uid': original['metadata']['uid'],
            'fingerprint': setup.fingerprint(original),
            'declared_fingerprint': setup.fingerprint(desired)}]})
    options = args(tmp_path, profile=LEGACY, administrator_receipt=str(receipt),
                   administrator_receipt_sha256=setup.sha(receipt))
    api.events.clear()
    api.denied_resources.add('roles')
    if drift == 'uid':
        api.objects[('Role', 'fixture-reviewed')]['metadata']['uid'] = 'replacement'
    elif drift == 'rules':
        api.objects[('Role', 'fixture-reviewed')]['rules'][0]['resources'] = ['secrets']
    if drift:
        with pytest.raises(ValueError, match='identity or configuration'):
            setup.install(options, [desired])
        assert not (tmp_path / 'creation-ledger.private.json').exists()
    else:
        assert setup.permissions(options, [desired])['ready']
        assert setup.install(options, [desired])['completed']
        ledger = json.loads((tmp_path / 'creation-ledger.private.json').read_text())
        assert ledger['created'] == [] and len(ledger['retained_prerequisites']) == 1
        assert ledger['retained_prerequisites'][0]['uid'] == original['metadata']['uid']
        options.ledger = str(tmp_path / 'creation-ledger.private.json')
        assert setup.reconcile_creation(options, [desired]) == ledger
        api.objects[('Role', 'fixture-reviewed')]['metadata']['uid'] = 'replacement'
        with pytest.raises(ValueError, match='prerequisite changed'):
            setup.reconcile_creation(options, [desired])
    assert not any(words[0] == 'create' and (body or {}).get('kind') == 'Role'
                   for words, body in api.events)


@pytest.mark.parametrize("fault", [None, "uid", "selector", "receipt", "core"])
def test_workspace_isolation_retention_never_grants_policy_creation(tmp_path, monkeypatch, fault):
    from deployment_profile import LEGACY
    tmp_path.chmod(0o700)
    api = API()
    monkeypatch.setattr(setup, "kube", api.call)
    desired = obj("NetworkPolicy", "identity-demo-default-deny", spec={"podSelector": {}, "policyTypes": ["Ingress", "Egress"]})
    desired["metadata"]["namespace"] = LEGACY.core_namespace if fault == "core" else LEGACY.triage_namespace
    original = api.call(None, "create", value=desired)
    path = tmp_path / "administrator.json"
    setup.write(path, {"schema_version": 1, "expected_server": LEGACY.expected_server, "installation_profile": LEGACY.to_dict(), "created": [{"object": original, "uid": original["metadata"]["uid"], "fingerprint": setup.fingerprint(original), "declared_fingerprint": setup.fingerprint(desired)}]})
    options = args(tmp_path, profile=LEGACY, administrator_receipt=str(path), administrator_receipt_sha256=setup.sha(path))
    api.events.clear()
    api.denied_resources.add("networkpolicies")
    if fault == "uid":
        api.objects[("NetworkPolicy", desired["metadata"]["name"])]["metadata"]["uid"] = "replacement"
    elif fault == "selector":
        api.objects[("NetworkPolicy", desired["metadata"]["name"])]["spec"]["podSelector"] = {"matchLabels": {"other": "true"}}
    elif fault == "receipt":
        options.administrator_receipt = None
        options.administrator_receipt_sha256 = None
    if fault:
        with pytest.raises(ValueError):
            setup.install(options, [desired])
        assert not (tmp_path / "creation-ledger.private.json").exists()
    else:
        assert setup.permissions(options, [desired])["ready"]
        assert setup.install(options, [desired])["completed"]
        ledger = json.loads((tmp_path / "creation-ledger.private.json").read_text())
        assert ledger["created"] == [] and ledger["retained_prerequisites"][0]["uid"] == original["metadata"]["uid"]
        options.ledger = str(tmp_path / "creation-ledger.private.json")
        assert setup.reconcile_creation(options, [desired]) == ledger
    assert not any(words[0] == "create" and (value or {}).get("kind") == "NetworkPolicy" for words, value in api.events)
