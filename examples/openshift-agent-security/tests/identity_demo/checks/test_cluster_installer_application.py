# SPDX-License-Identifier: Apache-2.0
"""Application installation never combines build and credential-mount authority."""

import json

import pytest

from cluster_installer_application import authority
from cluster_installer_resources import bootstrap, build_job
from checks.test_cluster_installer_session import config
from checks.test_installer_prerequisites import source
from deployment_profile import LEGACY


def proposed():
    bundle, artifacts = source()
    value = config()
    return authority(
        LEGACY,
        bundle["objects"],
        [],
        artifacts,
        "registry.example/worker@sha256:" + "a" * 64,
        value,
    )


def test_application_identity_cannot_build_or_write_global_policies():
    objects = proposed()
    bindings = [o for o in objects if o["kind"].endswith("RoleBinding")]
    assert all(
        o["subjects"]
        == [
            {
                "kind": "ServiceAccount",
                "name": "fixture-installer",
                "namespace": LEGACY.core_namespace,
            }
        ]
        for o in bindings
    )
    for obj in objects:
        for rule in obj.get("rules", []):
            assert not set(rule["resources"]) & {
                "builds",
                "buildconfigs",
                "buildconfigs/instantiatebinary",
                "serviceaccounts/token",
            }
            if obj["kind"] == "ClusterRole":
                assert set(rule["verbs"]) <= {"get"}
            if "secrets" in rule["resources"] and "get" in rule["verbs"]:
                assert (
                    rule.get("resourceNames")
                    and "fixture-application-ca" not in rule["resourceNames"]
                )
            assert not (
                set(rule["resources"]) & {"roles", "rolebindings", "serviceaccounts"}
                and set(rule["verbs"]) - {"get"}
            )


def test_application_admission_excludes_signer_mounts_and_installer_state():
    policy = next(o for o in proposed() if o["kind"] == "ValidatingAdmissionPolicy")
    text = json.dumps(policy["spec"])
    assert "variables.secretMounts" in text and "variables.claimMounts" in text
    assert "fixture-installer-state" not in text
    assert "fixture-application-ca" not in text
    assert "has(v.hostPath)" not in text
    assert policy["spec"]["failurePolicy"] == "Fail"
    assert ":fixture-installer" in policy["spec"]["matchConditions"][0]["expression"]
    assert all(
        "fixture-installer-build-operator" not in v["expression"]
        for v in policy["spec"]["variables"]
    )


def test_build_and_application_use_separate_accounts_and_lease_grants():
    value = config()
    objects = bootstrap(value)
    roles = [o for o in objects if o["kind"] == "Role"]
    leases = [r for o in roles for r in o["rules"] if r["resources"] == ["leases"]]
    assert leases[0]["resourceNames"] == ["fixture-installer-build-operator"]
    image = "registry.example/installer@sha256:" + "b" * 64
    assert (
        build_job(value, image)["spec"]["template"]["spec"]["serviceAccountName"]
        == "fixture-installer-build-operator"
    )
    assert (
        build_job(value, image, phase="application")["spec"]["template"]["spec"][
            "serviceAccountName"
        ]
        == "fixture-installer"
    )


def test_signing_key_in_application_contract_is_rejected():
    bundle, artifacts = source()
    value = config()
    bundle["objects"].append(
        {
            "kind": "Secret",
            "metadata": {
                "name": "fixture-application-ca",
                "namespace": LEGACY.core_namespace,
            },
        }
    )
    with pytest.raises(ValueError, match="signing material"):
        authority(
            LEGACY,
            bundle["objects"],
            [],
            artifacts,
            "registry.example/worker@sha256:" + "a" * 64,
            value,
        )


def test_managed_leaf_identity_and_validity_are_part_of_admission():
    from managed_certificates import resources

    bundle, artifacts = source()
    contract = {
        "mode": "managed",
        "issuer_ref": {
            "name": "fixture-application-ca",
            "kind": "Issuer",
            "group": "cert-manager.io",
        },
    }
    bundle["objects"] += resources(LEGACY, contract)
    objects = authority(
        LEGACY,
        bundle["objects"],
        [],
        artifacts,
        "registry.example/worker@sha256:" + "a" * 64,
        config(),
    )
    policy = next(o for o in objects if o["kind"] == "ValidatingAdmissionPolicy")
    validation = policy["spec"]["validations"][-1]["expression"]
    for cert in resources(LEGACY, contract):
        assert json.dumps(cert["spec"]["commonName"]) in validation
        assert json.dumps(cert["spec"]["secretName"]) in validation
    assert "duration(variables.target.spec.duration)" in validation
    assert "variables.target.spec.isCA == false" in validation
    assert "rotationPolicy" in validation


@pytest.mark.parametrize("phase", ["build", "application"])
def test_installer_phase_remount_preserves_private_checkpoint_permissions(phase):
    from checks.test_cluster_installer_session import config

    job = build_job(
        config(), "registry.example/installer@sha256:" + "a" * 64, phase=phase
    )
    pod = job["spec"]["template"]["spec"]
    assert pod["securityContext"]["fsGroupChangePolicy"] == "OnRootMismatch"
    assert pod["securityContext"]["runAsNonRoot"] is True
    assert (
        "runAsUser" not in pod["securityContext"]
    )  # Platform assigns the namespace UID.
    assert next(v for v in pod["volumes"] if v["name"] == "state")[
        "persistentVolumeClaim"
    ] == {"claimName": "fixture-installer-state"}


@pytest.mark.parametrize("kind", ["Issuer", "ClusterIssuer"])
def test_managed_installer_can_observe_exact_leaves_but_never_signing_secret(kind):
    from managed_certificates import SECRETS

    value = config()
    value["certificate_management"] = {
        "mode": "managed",
        "issuer_ref": {
            "name": "approved-issuer",
            "kind": kind,
            "group": "cert-manager.io",
        },
        "issuer_uid": "00000000-0000-4000-8000-000000000001",
        "ca_file_ref": "application-ca.pem",
    }
    bundle, artifacts = source()
    objects = authority(
        LEGACY,
        bundle["objects"],
        [],
        artifacts,
        "registry.example/worker@sha256:" + "a" * 64,
        value,
    )
    issuer_rules = [
        r
        for o in objects
        for r in o.get("rules", [])
        if r["resources"] in (["issuers"], ["clusterissuers"])
    ]
    assert issuer_rules == [
        {
            "apiGroups": ["cert-manager.io"],
            "resources": ["issuers" if kind == "Issuer" else "clusterissuers"],
            "resourceNames": ["approved-issuer"],
            "verbs": ["get"],
        }
    ]
    leaf_rules = [
        r
        for o in objects
        for r in o.get("rules", [])
        if r["resources"] == ["secrets"] and r.get("resourceNames") == list(SECRETS)
    ]
    assert leaf_rules == [
        {
            "apiGroups": [""],
            "resources": ["secrets"],
            "resourceNames": list(SECRETS),
            "verbs": ["get"],
        }
    ]
    assert all(
        "fixture-application-ca" not in r.get("resourceNames", [])
        for o in objects
        for r in o.get("rules", [])
        if "secrets" in r["resources"]
    )



def environment_policy(secret):
    bundle, artifacts = source()
    bundle["objects"].append({
        "apiVersion": "v1", "kind": "Secret",
        "metadata": {"name": "fixture-component-password", "namespace": LEGACY.core_namespace,
                     "labels": dict(LEGACY.labels)}, "data": {"component-password": "c3ludGhldGlj"}})
    bundle["objects"].append({
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": "fixture-component", "namespace": LEGACY.core_namespace,
                     "labels": dict(LEGACY.labels)},
        "spec": {"template": {"spec": {
            "serviceAccountName": "default", "volumes": [],
            "containers": [{"name": "component", "env": [{
                "name": "PASSWORD", "valueFrom": {"secretKeyRef": {
                    "name": secret, "key": "component-password"}}}]}]}}}})
    return next(o for o in authority(
        LEGACY, bundle["objects"], [], artifacts,
        "registry.example/worker@sha256:" + "a" * 64, config())
        if o["kind"] == "ValidatingAdmissionPolicy")


def test_environment_secret_key_does_not_grant_volume_or_bulk_secret_access():
    policy = environment_policy("fixture-component-password")
    variables = {v["name"]: v["expression"] for v in policy["spec"]["variables"]}
    assert json.loads(variables["secretEnv"])["fixture-component"] == {
        "fixture-component-password": ["component-password"]}
    assert json.loads(variables["secretMounts"])["fixture-component"] == []
    assert json.loads(variables["secretEnvFrom"])["fixture-component"] == []


@pytest.mark.parametrize("secret", ["fixture-application-ca", "unrelated-secret"])
def test_unregistered_environment_credentials_fail_before_admission(secret):
    with pytest.raises(ValueError, match="registered application Secrets"):
        environment_policy(secret)



def test_custom_route_host_permission_is_namespaced_and_pinned_to_full_route_spec():
    bundle, artifacts = source()
    route = {"apiVersion": "route.openshift.io/v1", "kind": "Route",
             "metadata": {"name": "fixture-console", "namespace": LEGACY.core_namespace,
                          "labels": dict(LEGACY.labels)},
             "spec": {"host": "console.example.test", "to": {"kind": "Service", "name": "fixture-console", "weight": 100},
                      "port": {"targetPort": "https"}, "tls": {"termination": "reencrypt"},
                      "wildcardPolicy": "None"}}
    bundle["objects"].append(route)
    objects = authority(LEGACY, bundle["objects"], [], artifacts,
                        "registry.example/worker@sha256:" + "a" * 64, config())
    grants = [o for o in objects if any(r["resources"] == ["routes/custom-host"] for r in o.get("rules", []))]
    assert len(grants) == 1 and grants[0]["kind"] == "Role"
    assert grants[0]["metadata"]["namespace"] == LEGACY.core_namespace
    assert next(r for r in grants[0]["rules"] if r["resources"] == ["routes/custom-host"])["verbs"] == ["create"]
    policy = next(o for o in objects if o["kind"] == "ValidatingAdmissionPolicy")
    variables = {v["name"]: v["expression"] for v in policy["spec"]["variables"]}
    assert json.loads(variables["routes"])["fixture-console"] == {
        "host": "console.example.test", "service": "fixture-console", "port": "https",
        "port_kind": "string", "termination": "reencrypt", "insecure": "",
        "destination_ca": "", "path": ""}
    assert any("variables.target.spec.host == variables.routes" in v["expression"] and "!has(variables.target.spec.tls.key)" in v["expression"] for v in policy["spec"]["validations"])


def test_no_custom_host_grant_without_reviewed_routes():
    assert not any(r["resources"] == ["routes/custom-host"] for o in proposed() for r in o.get("rules", []))


@pytest.mark.parametrize("resource,group", [("sandboxes", "agents.x-k8s.io"), ("resourcequotas", "")])
def test_native_context_inventory_is_read_only_and_workspace_scoped(resource, group):
    objects = proposed()
    observations = [(obj, rule) for obj in objects for rule in obj.get("rules", [])
                    if resource in rule["resources"] and "list" in rule["verbs"]]
    assert {obj["metadata"]["namespace"] for obj, _ in observations} == set(
        LEGACY.application_namespaces[1:])
    assert len(observations) == len(LEGACY.application_namespaces[1:])
    for obj, rule in observations:
        assert obj["kind"] == "Role"
        assert rule == {"apiGroups": [group],
                        "resources": [resource], "verbs": ["list"]}
        bindings = [binding for binding in objects if binding["kind"] == "RoleBinding"
                    and binding["metadata"]["namespace"] == obj["metadata"]["namespace"]
                    and binding["roleRef"]["name"] == obj["metadata"]["name"]]
        assert len(bindings) == 1
        assert bindings[0]["subjects"] == [{"kind": "ServiceAccount",
            "name": "fixture-installer", "namespace": LEGACY.core_namespace}]


def test_installer_router_egress_matches_actual_router_pods_not_service_ip():
    from cluster_console_resources import ingress_peer
    bundle, artifacts = source()
    objects = authority(LEGACY, bundle["objects"], [], artifacts,
        "registry.example/worker@sha256:" + "a" * 64, config(),
        ingress_address="172.30.1.2")
    policy, = [o for o in objects if o["kind"] == "NetworkPolicy"]
    assert policy["metadata"]["namespace"] == LEGACY.core_namespace
    assert policy["spec"]["podSelector"]["matchLabels"] == {
        "app": "fixture-installer", "identity-demo-installer-phase": "application",
        "identity-demo-owner": LEGACY.owner}
    assert policy["spec"]["egress"][0] == {
        "to": [ingress_peer()], "ports": [{"protocol": "TCP", "port": 443}]}
    assert ingress_peer() == {
        "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "openshift-ingress"}},
        "podSelector": {"matchLabels": {"ingresscontroller.operator.openshift.io/deployment-ingresscontroller": "default"}}}
    assert policy["spec"]["policyTypes"] == ["Egress"]


def test_gateway_controller_observation_adds_no_replicaset_write_authority():
    grants = [(obj, rule) for obj in proposed() for rule in obj.get("rules", [])
              if "replicasets" in rule["resources"]]
    assert len(grants) == 1
    obj, rule = grants[0]
    assert obj["kind"] == "Role" and obj["metadata"]["namespace"] == LEGACY.core_namespace
    assert rule == {"apiGroups": ["apps"], "resources": ["replicasets"], "verbs": ["get"]}


def test_live_gateway_destinations_are_exact_in_rbac_and_admission():
    from identity_demo_action_policy import owned_frontend
    objects = proposed()
    policy = next(o for o in objects if o["kind"] == "ValidatingAdmissionPolicy")
    names = json.loads(next(v["expression"] for v in policy["spec"]["variables"] if v["name"] == "names"))
    rendered = owned_frontend("-----BEGIN CERTIFICATE-----", "https://issuer.example/realms/identity-demo", "https://"+LEGACY.service_host("fixture-mcp-bound")+"/mcp")
    assert {(v["kind"],v["metadata"]["name"]) for v in rendered} == {
        ("AuthConfig","fixture-step56-live-identity"),("EnvoyFilter","fixture-step56-live-identity")}
    core = next(o for o in objects if o["kind"] == "Role" and o["metadata"]["namespace"] == LEGACY.core_namespace and o["metadata"]["name"].endswith("installer-application"))
    for kind, resource in (("AuthConfig","authconfigs"),("EnvoyFilter","envoyfilters")):
        assert "fixture-step56-live-identity" in names[kind]
        assert "fixture-step56-live-identity-foreign" not in names[kind]
        writes = [rule for rule in core["rules"] if rule["resources"] == [resource] and "patch" in rule["verbs"]]
        assert len(writes) == 1 and "fixture-step56-live-identity" in writes[0]["resourceNames"]
        assert "*" not in writes[0]["resourceNames"]


def test_workers_can_project_only_named_public_leaves_and_no_private_keys():
    policy = next(o for o in proposed() if o["kind"] == "ValidatingAdmissionPolicy")
    rule = next(v["expression"] for v in policy["spec"]["validations"] if "Only reviewed data and credentials" in v["message"])
    assert "s.secret.name in variables.certificateSecrets" in rule
    assert "size(s.secret.items) == 1" in rule
    assert "s.secret.items[0].key == 'tls.crt'" in rule
    assert "s.secret.items[0].path == s.secret.name + '.crt'" in rule
    assert "v.projected.defaultMode == 292" in rule
    assert "v.name == 'application-certificates'" in rule
    assert "['fixture-console-coordinator','fixture-console-preparer']" in rule
    assert "tls.key" not in rule
