# SPDX-License-Identifier: Apache-2.0
"""Original identity/configuration receipts, not labels, authorize retention."""

from copy import deepcopy
from uuid import uuid4

import pytest

from cluster_installer_receipts import normalize
from cluster_installer_resources import namespace_objects
from cluster_console_resources import resource
from deployment_profile import LEGACY


def receipt_inputs():
    plan = {
        "apiVersion": "v1",
        "kind": "List",
        "items": [
            resource(
                LEGACY,
                "rbac.authorization.k8s.io/v1",
                "Role",
                "fixture-reviewed",
                LEGACY.core_namespace,
                rules=[{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}],
            ),
            resource(
                LEGACY,
                "v1",
                "ServiceAccount",
                "fixture-reviewed",
                LEGACY.core_namespace,
                automountServiceAccountToken=False,
            ),
        ],
    }
    namespaces = {"kind": "List", "items": namespace_objects(LEGACY)}
    for o in namespaces["items"]:
        o["metadata"]["uid"] = str(uuid4())
    created = deepcopy(plan["items"])
    for o in created:
        o["metadata"]["uid"] = str(uuid4())
    current = deepcopy([*created, *namespaces["items"]])
    return (
        plan,
        {"created": created, "current": current, "registry_owners": []},
        namespaces,
    )


def test_original_complete_matching_resources_produce_a_retention_receipt():
    plan, evidence, namespaces = receipt_inputs()
    result = normalize(LEGACY, plan, evidence, namespaces, plan_sha256="a" * 64)
    assert len(result["created"]) == 5
    assert all(
        r["object"]["metadata"]["uid"] == r["uid"] and r["declared_fingerprint"]
        for r in result["created"]
    )
    assert result["plan_sha256"] == "a" * 64


@pytest.mark.parametrize(
    "fault",
    ["replaced", "rules", "extra", "missing", "duplicate", "owner", "terminating"],
)
def test_replaced_or_changed_prerequisites_cannot_be_adopted(fault):
    plan, evidence, namespaces = receipt_inputs()
    current = evidence["current"][0]
    if fault == "replaced":
        current["metadata"]["uid"] = str(uuid4())
    elif fault == "rules":
        current["rules"][0]["verbs"].append("create")
    elif fault == "extra":
        evidence["current"].append(
            resource(
                LEGACY, "v1", "Secret", "fixture-unexpected", LEGACY.core_namespace
            )
        )
    elif fault == "missing":
        evidence["current"].pop()
    elif fault == "duplicate":
        evidence["created"].append(deepcopy(evidence["created"][0]))
    elif fault == "owner":
        current["metadata"]["labels"]["identity-demo-owner"] = "someone-else"
    elif fault == "terminating":
        current["metadata"]["deletionTimestamp"] = "2099-01-01T00:00:00Z"
    with pytest.raises(ValueError):
        normalize(LEGACY, plan, evidence, namespaces, plan_sha256="a" * 64)


@pytest.mark.parametrize(
    "fault", [None, "wrong-owner", "private-data", "foreign-reference"]
)
def test_generated_pull_references_require_exact_service_account_owner(fault):
    plan, evidence, namespaces = receipt_inputs()
    account = evidence["current"][1]
    name = account["metadata"]["name"] + "-dockercfg-test"
    account["imagePullSecrets"] = [{"name": name}]
    secret = {
        "apiVersion": "v1",
        "kind": "Secret",
        "type": "kubernetes.io/dockercfg",
        "metadata": {
            "name": name,
            "namespace": LEGACY.core_namespace,
            "ownerReferences": [
                {
                    "kind": "ServiceAccount",
                    "name": account["metadata"]["name"],
                    "uid": account["metadata"]["uid"],
                }
            ],
        },
    }
    evidence["registry_owners"] = [secret]
    if fault == "wrong-owner":
        secret["metadata"]["ownerReferences"][0]["uid"] = str(uuid4())
    elif fault == "private-data":
        secret["data"] = {"unwanted": "not-accepted"}
    elif fault == "foreign-reference":
        account["imagePullSecrets"] = [{"name": "foreign-pull-key"}]
    if fault:
        with pytest.raises(ValueError):
            normalize(LEGACY, plan, evidence, namespaces, plan_sha256="a" * 64)
    else:
        result = normalize(LEGACY, plan, evidence, namespaces, plan_sha256="a" * 64)
        assert (
            next(
                r for r in result["created"] if r["object"]["kind"] == "ServiceAccount"
            )["object"]["imagePullSecrets"]
            == account["imagePullSecrets"]
        )


@pytest.mark.parametrize("fault", [None, "selector", "scope", "extra-rule", "declared-selector"])
def test_only_equivalent_admission_api_defaults_are_normalized(fault):
    plan, evidence, namespaces = receipt_inputs()
    policy = resource(
        LEGACY, "admissionregistration.k8s.io/v1", "ValidatingAdmissionPolicy",
        "fixture-reviewed-admission", None,
        spec={"matchConstraints": {"resourceRules": [{
            "apiGroups": [""], "apiVersions": ["v1"],
            "operations": ["CREATE"], "resources": ["pods"],
        }]}, "validations": [{"expression": "false"}]},
    )
    plan["items"].append(deepcopy(policy))
    policy["metadata"]["uid"] = str(uuid4())
    constraints = policy["spec"]["matchConstraints"]
    constraints.update(matchPolicy="Equivalent", namespaceSelector={}, objectSelector={})
    constraints["resourceRules"][0]["scope"] = "*"
    evidence["created"].append(deepcopy(policy))
    evidence["current"].append(policy)
    if fault == "selector":
        constraints["namespaceSelector"] = {"matchLabels": {"other": "true"}}
    elif fault == "scope":
        constraints["resourceRules"][0]["scope"] = "Namespaced"
    elif fault == "extra-rule":
        constraints["resourceRules"].append(deepcopy(constraints["resourceRules"][0]))
    elif fault == "declared-selector":
        plan["items"][-1]["spec"]["matchConstraints"]["objectSelector"] = {"matchLabels": {"owned": "true"}}
    if fault:
        with pytest.raises(ValueError, match="configuration differs"):
            normalize(LEGACY, plan, evidence, namespaces, plan_sha256="a" * 64)
    else:
        result = normalize(LEGACY, plan, evidence, namespaces, plan_sha256="a" * 64)
        assert len(result["created"]) == 6
