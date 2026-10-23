# SPDX-License-Identifier: Apache-2.0
"""Offline ownership and image-only drift guards for the approved candidate."""

from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts" / "identity_demo"))
from identity_demo_runtime_candidate import NAME, NAMESPACE, allowed_image, image_patch, resume_state  # noqa: E402
from identity_demo_spire_registration import GATEWAY_IMAGE, prepare  # noqa: E402
from identity_demo_lab import LABELS  # noqa: E402

CANDIDATE = ("image-registry.openshift-image-registry.svc:5000/demo-core/"
             "fixture-openshell-subject-fix@sha256:" + "a" * 64)


def fixture() -> dict:
    """Return a synthetic owned template with no cluster access."""
    return {"metadata": {"name": NAME, "namespace": NAMESPACE, "labels": dict(LABELS),
                         "uid": "owned", "resourceVersion": "1"},
            "spec": {"template": {"spec": {"containers": [
                {"name": "openshell-gateway", "image": GATEWAY_IMAGE}]}}}}


def test_patch_changes_only_image_and_checks_uid_revision_and_spec() -> None:
    """Concurrent edits and resource replacement are never overwritten."""
    value = fixture()
    before = deepcopy(value)
    patch = image_patch(value, CANDIDATE)
    assert value == before
    assert [p["path"] for p in patch[:3]] == ["/metadata/uid", "/metadata/resourceVersion", "/spec"]
    assert patch[3] == {"op": "replace", "path": "/spec/template/spec/containers/0/image",
                        "value": CANDIDATE}


@pytest.mark.parametrize("image", ["ghcr.io/other/image:latest", CANDIDATE.replace("@sha256:", ":"),
                                   CANDIDATE.replace("demo-core", "another-team"),
                                   CANDIDATE.replace("subject-fix", "unreviewed-fork")])
def test_other_repositories_tags_and_namespaces_rejected(image: str) -> None:
    """An explicit candidate option cannot expand ownership or trust."""
    assert not allowed_image(image)
    with pytest.raises(ValueError):
        image_patch(fixture(), image)
    with pytest.raises(ValueError):
        prepare("unused", "unused", "unused", gateway_image=image)


@pytest.mark.parametrize("change", ["namespace", "labels", "name"])
def test_unowned_statefulset_rejected(change: str) -> None:
    """The fixture name alone is insufficient evidence of ownership."""
    value = fixture()
    value["metadata"][change] = {} if change == "labels" else "another-team"
    with pytest.raises(ValueError):
        image_patch(value, CANDIDATE)


def test_registration_resumption_accepts_only_recorded_image_change() -> None:
    """A partial rollout can finish without another image mutation."""
    previous = fixture()
    current = deepcopy(previous)
    current["spec"]["template"]["spec"]["containers"][0]["image"] = CANDIDATE
    resume_state(current, previous, CANDIDATE)


@pytest.mark.parametrize("drift", ["uid", "spec", "image"])
def test_registration_resumption_refuses_drift(drift: str) -> None:
    """Resumption cannot overwrite replacement resources or another writer."""
    previous = fixture()
    current = deepcopy(previous)
    current["spec"]["template"]["spec"]["containers"][0]["image"] = CANDIDATE
    if drift == "uid":
        current["metadata"]["uid"] = "replacement"
    elif drift == "spec":
        current["spec"]["replicas"] = 2
    else:
        current["spec"]["template"]["spec"]["containers"][0]["image"] = GATEWAY_IMAGE
    with pytest.raises(ValueError):
        resume_state(current, previous, CANDIDATE)


@pytest.mark.parametrize("image", ["ghcr.io/other/supervisor:latest",
    "image-registry.openshift-image-registry.svc:5000/another-team/fixture-openshell-sender@sha256:" + "a" * 64,
    "image-registry.openshift-image-registry.svc:5000/demo-core/fixture-openshell-sender:latest"])
def test_registration_refuses_unpinned_or_other_supervisor(image: str) -> None:
    """Opt-in transport cannot expand registration to another owner's image."""
    with pytest.raises(ValueError):
        prepare("unused", "unused", "unused", supervisor_image=image)
