# SPDX-License-Identifier: Apache-2.0
"""Administrator handoff excludes private data and unrelated policy authority."""

from copy import deepcopy
import hashlib
from io import BytesIO
from types import SimpleNamespace

import pytest

from deployment_profile import LEGACY
from cluster_installer_prerequisites import objects, run
import installer_tools

from checks.support.installer_prerequisites import source






def test_handoff_uses_the_existing_generators_and_excludes_private_application_state():
    bundle, artifacts = source()
    before = deepcopy(bundle)
    result = objects(LEGACY, bundle, artifacts)
    assert bundle == before
    assert all(
        o["kind"]
        not in {"Secret", "Deployment", "StatefulSet", "PersistentVolumeClaim"}
        for o in result
    )
    assert not any(o["metadata"]["name"] == "identity-demo-"+LEGACY.installation_id+"-public-trust" for o in result)
    assert len([o for o in result if o["kind"] == "ClusterSPIFFEID"]) == 3
    for obj in result:
        namespace = obj["metadata"].get("namespace")
        assert namespace is None or namespace in (
            *LEGACY.application_namespaces,
            LEGACY.identity_namespace,
        )
        for rule in obj.get("rules", []):
            assert not any(
                "*" in rule.get(key, []) for key in ("verbs", "apiGroups", "resources")
            )
            assert not (
                "pods/exec" in rule.get("resources", [])
                and namespace == LEGACY.identity_namespace
            )
            assert not (
                "clusterspiffeids" in rule.get("resources", [])
                and set(rule["verbs"]) - {"get"}
            )


@pytest.mark.parametrize("wrong", ["profile", "native", "unbuilt"])
def test_handoff_rejects_cross_installation_or_unverified_native_contract(wrong):
    bundle, artifacts = source()
    if wrong == "profile":
        bundle["installation_profile"]["owner"] = "someone-else"
    elif wrong == "native":
        artifacts["native_build_contract"]["OPENSHELL_DEMO_TRUST_DOMAIN"] = (
            "foreign.example"
        )
    else:
        bundle["native_build_contract_matches"] = False
    with pytest.raises(ValueError, match="Matching reviewed"):
        objects(LEGACY, bundle, artifacts)


def test_handoff_cannot_apply_privileges(tmp_path):
    with pytest.raises(ValueError, match="review-only"):
        run(SimpleNamespace(apply=True, output_dir=tmp_path))
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("mode", ["ok", "hash", "size", "scheme", "redirect"])
def test_public_archive_fetch_is_bounded_and_verified_before_use(
    tmp_path, monkeypatch, mode
):
    content = b"synthetic public archive"

    class Response(BytesIO):
        def geturl(self):
            return (
                "http://downgrade.example/archive"
                if mode == "redirect"
                else "https://source.example/archive"
            )

    monkeypatch.setattr(installer_tools, "urlopen", lambda *a, **k: Response(content))
    url = (
        "http://source.example/archive"
        if mode == "scheme"
        else "https://source.example/archive"
    )
    expected = "0" * 64 if mode == "hash" else hashlib.sha256(content).hexdigest()
    limit = 1 if mode == "size" else 100
    target = tmp_path / "archive"
    if mode == "ok":
        assert installer_tools.fetch(url, expected, target, limit) == expected
        assert target.read_bytes() == content
    else:
        with pytest.raises(ValueError):
            installer_tools.fetch(url, expected, target, limit)


def test_workspace_isolation_is_administrator_prepared_and_installer_read_only():
    from cluster_installer_application import authority
    from checks.support.cluster_installer_session import config
    bundle, artifacts = source()
    for namespace in LEGACY.application_namespaces:
        bundle["objects"].append({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"namespace": namespace, "name": "identity-demo-default-deny", "labels": dict(LEGACY.labels)}, "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}})
    prerequisites = objects(LEGACY, bundle, artifacts)
    retained = [o for o in prerequisites if o["kind"] == "NetworkPolicy" and o["metadata"].get("namespace") in LEGACY.application_namespaces]
    assert {o["metadata"]["namespace"] for o in retained} == set(LEGACY.application_namespaces[1:])
    grants = authority(LEGACY, bundle["objects"], prerequisites, artifacts, "registry.example/worker@sha256:" + "a" * 64, config())
    for namespace in LEGACY.application_namespaces[1:]:
        rules = [rule for o in grants if o["kind"] == "Role" and o["metadata"].get("namespace") == namespace for rule in o["rules"] if rule["resources"] == ["networkpolicies"]]
        assert rules and all(rule["verbs"] == ["get"] and rule["resourceNames"] == ["identity-demo-default-deny"] for rule in rules)
