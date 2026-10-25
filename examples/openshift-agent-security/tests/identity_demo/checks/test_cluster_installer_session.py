# SPDX-License-Identifier: Apache-2.0
"""Installer restart cannot replay an uncertain mutation or change its inputs."""

import json
from types import SimpleNamespace

import pytest

from cluster_installer_session import CompletedStages, configuration, ownership
import connected_install
import identity_demo_setup as setup
from deployment_profile import LEGACY


def config():
    return {
        "schema_version": 1,
        "profile": LEGACY.to_dict(),
        "artifacts": {
            "schema_version": 1,
            "images": {
                role: "registry.example/" + role + "@sha256:" + "a" * 64
                for role in (
                    "jira_runtime",
                    "keycloak_management",
                    "keycloak_exchange",
                    "openshell_gateway",
                    "openshell_supervisor",
                )
            },
        },
        "application": dict(
            chat_request_url="https://model.example.org/v1/messages",
            chat_model="reviewed-model",
            workload_image="pinned-by-original-validator",
            diagnostic_runtime_image="pinned-by-original-validator",
        ),
        "public_trust": dict(
            service_ca="service-ca.pem",
            spire_ca="spire-ca.pem",
            upstream_ca_bundle="upstream-ca.pem",
            kubernetes_ca="kubernetes-ca.pem",
        ),
        "kubernetes_api_cidrs": ["192.0.2.1/32"],
        "certificate_management": {"mode": "legacy"},
        "credentials": {
            "inference": {
                "secret_name": "fixture-installer-inference",
                "key": "api-key",
            }
        },
    }


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "unknown",
        "raw-credential",
        "alternate-secret",
        "unknown-application",
        "schema-bool",
    ],
)
def test_installer_configuration_accepts_only_versioned_fixed_references(fault):
    value = config()
    if fault == "unknown":
        value["command"] = "arbitrary-script"
    elif fault == "raw-credential":
        value["credentials"]["inference"]["password"] = "must-not-be-accepted"
    elif fault == "alternate-secret":
        value["credentials"]["inference"]["secret_name"] = "fixture-application-ca"
    elif fault == "unknown-application":
        value["application"]["credential_file"] = "/arbitrary/key"
    elif fault == "schema-bool":
        value["schema_version"] = True
    if fault:
        with pytest.raises(ValueError):
            configuration(value)
    else:
        assert configuration(value) == value


def completed(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    calls = []
    fence = []
    args = SimpleNamespace(output_dir=tmp_path, stage_fence=lambda: fence.append(True))

    def run(self, name, script, words, **kwargs):
        calls.append((name, script, words))
        setup.write(tmp_path / (name + ".pending.json"), {"submitted": True})
        out = tmp_path / name
        out.mkdir()
        log = tmp_path / (name + ".private.log")
        log.write_text("bounded stage output")
        log.chmod(0o600)
        setup.write(
            tmp_path / (name + ".receipt.json"),
            {"stage": name, "exit": 0, "log_sha256": setup.sha(log)},
        )
        return {"completed": True}, out

    monkeypatch.setattr(connected_install.Stages, "run", run)
    return CompletedStages(args, {}), calls, fence


def test_verified_completion_can_be_reused_without_repeating_a_mutation(
    tmp_path, monkeypatch
):
    stages, calls, fence = completed(tmp_path, monkeypatch)
    first = stages.run("native", "trusted.py", ["fixed-argument"])
    assert stages.run("native", "trusted.py", ["fixed-argument"]) == first
    assert len(calls) == 1 and len(fence) >= 3


@pytest.mark.parametrize("change", ["pending", "arguments", "log", "receipt"])
def test_interruption_or_changed_completion_requires_recovery(
    tmp_path, monkeypatch, change
):
    stages, calls, fence = completed(tmp_path, monkeypatch)
    if change == "pending":
        setup.write(tmp_path / "native.pending.json", {"submitted": True})
    else:
        stages.run("native", "trusted.py", ["fixed"])
        if change == "log":
            (tmp_path / "native.private.log").write_text("changed")
        if change == "receipt":
            (tmp_path / "native.receipt.json").write_text("{}")
    with pytest.raises(ValueError):
        stages.run(
            "native", "trusted.py", ["changed" if change == "arguments" else "fixed"]
        )
    assert len(calls) == (0 if change == "pending" else 1)


def test_second_process_cannot_take_the_pvc_installation_lock(tmp_path):
    root = tmp_path / "state"
    with ownership(root):
        with pytest.raises(BlockingIOError):
            with ownership(root):
                pytest.fail("A concurrent installer acquired the same state")
    with ownership(root):
        assert root.is_dir()


def test_projected_token_is_not_copied_and_frozen_inputs_survive_rotation(tmp_path):
    from datetime import datetime, timedelta, timezone
    import hashlib
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    from cluster_installer_session import prepare_inputs

    tmp_path.chmod(0o700)
    source = tmp_path / "source"
    source.mkdir()
    original = source / "README.md"
    original.write_text("public reviewed source")
    (source / "export-manifest.json").write_text(
        json.dumps(
            {
                "files": [
                    {
                        "path": "README.md",
                        "sha256": hashlib.sha256(original.read_bytes()).hexdigest(),
                    }
                ]
            }
        )
    )
    credentials = tmp_path / "credentials"
    credentials.mkdir()
    (credentials / "inference.key").write_text("synthetic-test-key")
    tokens = tmp_path / "token"
    tokens.mkdir()
    (tokens / "token").write_text("first-project-token-never-copied")
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic installer test CA")]
    )
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    public = certificate.public_bytes(serialization.Encoding.PEM).decode()
    (tokens / "ca.crt").write_text(public)
    value = config()
    public_root = tmp_path / "public-trust"
    public_root.mkdir()
    for filename in value["public_trust"].values():
        (public_root / filename).write_text(public)
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    inputs = prepare_inputs(
        value,
        root,
        source=source,
        credential_root=credentials,
        token_root=tokens,
        public_trust_root=public_root,
    )
    kube = json.loads((inputs / "kubeconfig.json").read_text())
    assert kube["users"][0]["user"] == {"tokenFile": str(tokens / "token")}
    assert all(
        b"first-project-token-never-copied" not in p.read_bytes()
        for p in root.rglob("*")
        if p.is_file()
    )
    (tokens / "token").write_text("rotated-project-token")
    assert (
        prepare_inputs(
            value,
            root,
            source=source,
            credential_root=credentials,
            token_root=tokens,
            public_trust_root=public_root,
        )
        == inputs
    )
    assert not (root / "source/inference.key").exists()
    (inputs / "service_ca.pem").write_text("substituted trust")
    with pytest.raises(ValueError, match="Frozen installer inputs changed"):
        prepare_inputs(
            value,
            root,
            source=source,
            credential_root=credentials,
            token_root=tokens,
            public_trust_root=public_root,
        )


def test_bootstrap_build_authority_excludes_signing_keys_global_mutation_and_spire_exec():
    from cluster_installer_resources import bootstrap, build_job

    value = config()
    objects = bootstrap(value)
    local = next(o["rules"] for o in objects if o["kind"] == "Role")
    assert not any("secrets" in rule["resources"] for rule in local)
    assert not any(
        "roles" in rule["resources"] or "rolebindings" in rule["resources"]
        for rule in local
    )
    execute = next(rule for rule in local if rule["resources"] == ["pods/exec"])
    assert execute["resourceNames"] == ["fixture-native-export"]
    for obj in objects:
        if obj["kind"] == "ClusterRole":
            assert all(
                rule["verbs"] == ["get"] and rule.get("resourceNames")
                for rule in obj["rules"]
            )
        scope = obj["metadata"].get("namespace")
        if scope == "openshift-ingress":
            assert obj["kind"] in ("Role", "RoleBinding")
            if obj["kind"] == "Role":
                assert obj["rules"] == [
                    {
                        "apiGroups": [""],
                        "resources": ["services"],
                        "verbs": ["get"],
                        "resourceNames": ["router-default"],
                    }
                ]
        else:
            assert scope in (None, LEGACY.core_namespace)
    quota = next(o for o in objects if o["kind"] == "ResourceQuota")
    assert quota["spec"]["hard"]["requests.storage"] == "40Gi"
    policy = next(o for o in objects if o["kind"] == "ValidatingAdmissionPolicy")
    assert policy["spec"]["failurePolicy"] == "Fail"
    conditions = " ".join(v["expression"] for v in policy["spec"]["matchConditions"])
    assert (
        "system:serviceaccount:" + LEGACY.core_namespace + ":fixture-installer"
        in conditions
    )
    assert LEGACY.core_namespace in conditions
    job = build_job(value, "registry.example/installer@sha256:" + "a" * 64)
    pod = job["spec"]["template"]["spec"]
    assert job["spec"]["backoffLimit"] == 0 and pod["restartPolicy"] == "Never"
    assert (
        pod["serviceAccountName"] == "fixture-installer-build-operator"
        and not pod["automountServiceAccountToken"]
    )
    token = next(v for v in pod["volumes"] if v["name"] == "api-token")
    assert token["projected"]["sources"][0]["serviceAccountToken"] == {
        "expirationSeconds": 3600,
        "path": "token",
    }
    assert [v["secret"]["secretName"] for v in pod["volumes"] if "secret" in v] == [
        "fixture-installer-inference"
    ]
    assert pod["containers"][0]["securityContext"]["readOnlyRootFilesystem"]
    assert not any(
        "password" in str(v).lower() or "kubeconfig" in str(v).lower()
        for v in pod["volumes"]
    )


@pytest.mark.parametrize(
    "cidrs", [["0.0.0.0/0"], ["192.0.2.0/24"], [], ["not-a-network"]]
)
def test_bootstrap_never_widens_api_egress(cidrs):
    from cluster_installer_resources import bootstrap

    value = config()
    value["kubernetes_api_cidrs"] = cidrs
    with pytest.raises(ValueError):
        bootstrap(value)


@pytest.mark.parametrize(
    "fault", [None, "digest", "foreign-owned-namespace", "credentials"]
)
def test_builder_mirror_preserves_pinned_bytes_and_owned_registry_scope(fault):
    from native_build import RECIPES

    value = config()
    digest = json.loads((RECIPES / "inputs.lock.json").read_text())[
        "builder_platform_digest"
    ]
    image = (
        "image-registry.openshift-image-registry.svc:5000/"
        + value["profile"]["core_namespace"]
        + "-build/fixture-native-builder-base@"
        + digest
    )
    if fault == "digest":
        image = image.replace(digest, "sha256:" + "0" * 64)
    if fault == "foreign-owned-namespace":
        image = image.replace(
            value["profile"]["core_namespace"] + "-build/", "foreign-build/"
        )
    if fault == "credentials":
        image = "user:password@" + image
    value["native_builder_image"] = image
    if fault:
        with pytest.raises(ValueError):
            configuration(value)
    else:
        assert configuration(value) == value


@pytest.mark.parametrize("mode", ["synthetic", "none", "arbitrary", True, None])
def test_fixture_seed_mode_is_explicit_and_bounded(mode):
    value = config()
    value["fixture_seed_mode"] = mode
    if mode in ("synthetic", "none"):
        assert configuration(value)["fixture_seed_mode"] == mode
    else:
        with pytest.raises(ValueError, match="fixture seed mode"):
            configuration(value)
