#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Roll out the approved owned gateway candidate with exact drift checks.

Default is a server dry-run. The reference release, management issuer and
supervisor image remain unchanged. Refresh only the existing owned gateway's
exact registration after Pod replacement. Every artifact stays outside Git.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
import re
import time
from typing import Callable

from identity_demo_keycloak_recovery import command, write_private
from identity_demo_lab import LABELS
from identity_demo_runtime import guard, NAMESPACE
from identity_demo_spire_registration import GATEWAY_IMAGE, prepare
from identity_demo_spire_network import SERVER
from deployment_profile import active_profile, LEGACY
from deployment_artifacts import configured_native_image
from deployment_profile import in_source_checkout

NAME = "fixture-openshell"
REGISTRATION = active_profile().gateway_registration_name


def allowed_image(image: str) -> bool:
    """Accept only the reference or a digest in our exact private repository."""
    locked = configured_native_image("openshell_gateway")
    if image == locked:
        return True
    return active_profile() == LEGACY and (image == GATEWAY_IMAGE or bool(re.fullmatch(
        r"image-registry\.openshift-image-registry\.svc:5000/demo-core/"
        r"fixture-openshell-subject-fix@sha256:[a-f0-9]{64}", image)))


def image_patch(current: dict, desired: str) -> list[dict]:
    """An image-only change cannot overwrite another writer's configuration."""
    if (current["metadata"]["name"] != NAME
            or current["metadata"].get("namespace") != NAMESPACE
            or any(current["metadata"].get("labels", {}).get(k) != v
                   for k, v in LABELS.items())):
        raise ValueError("Exact owned StatefulSet required")
    containers = current["spec"]["template"]["spec"]["containers"]
    if (len(containers) != 1 or containers[0]["name"] != "openshell-gateway"
            or not allowed_image(containers[0]["image"]) or not allowed_image(desired)):
        raise ValueError("Explicit pinned reference/candidate images required")
    return [{"op": "test", "path": "/metadata/uid", "value": current["metadata"]["uid"]},
            {"op": "test", "path": "/metadata/resourceVersion",
             "value": current["metadata"]["resourceVersion"]},
            {"op": "test", "path": "/spec", "value": current["spec"]},
            {"op": "replace", "path": "/spec/template/spec/containers/0/image", "value": desired}]


def resume_state(current: dict, previous: dict, candidate: str) -> None:
    """Resume only the recorded image change, refusing any intervening drift."""
    image_patch(current, candidate)
    expected = deepcopy(previous["spec"])
    expected["template"]["spec"]["containers"][0]["image"] = candidate
    if (current["metadata"]["uid"] != previous["metadata"]["uid"]
            or current["spec"] != expected):
        raise ValueError("Recorded rollout drift prevents registration resumption")


def run(args: argparse.Namespace) -> dict:
    """Validate packaging, dry-run and optionally roll out the owned candidate."""
    args.namespace = NAMESPACE
    if args.expected_server != SERVER:
        raise ValueError("Exact agreed lab required")
    guard(args)
    output = Path(args.output_dir)
    if (not output.is_dir() or output.is_symlink() or output.stat().st_mode & 0o077
            or in_source_checkout(output)):
        raise ValueError("Private evidence directory outside Git required")

    def read(kind: str, name: str, namespace: str | None = NAMESPACE) -> dict:
        scope = ["-n", namespace] if namespace else []
        return json.loads(command(args, "--request-timeout=20s", "get", kind, name,
                                  *scope, "-o", "json"))

    stream = read("imagestream", "fixture-openshell-subject-fix")
    if any(stream["metadata"].get("labels", {}).get(k) != v for k, v in LABELS.items()):
        raise ValueError("Owned image stream required")
    digest = read("imagestreamtag", "fixture-openshell-subject-fix:candidate")["image"]["metadata"]["name"]
    candidate = ("image-registry.openshift-image-registry.svc:5000/" + NAMESPACE + "/"
                 "fixture-openshell-subject-fix@" + digest)
    if not allowed_image(candidate):
        raise ValueError("Invalid resolved image digest")
    before = read("statefulset", NAME)
    resuming = getattr(args, "resume_registration", False)
    if resuming:
        if not args.deploy:
            raise ValueError("Registration resumption requires explicit --deploy")
        report = json.loads((output / "gateway-deployment-started.private.json").read_text())
        if report.get("deployed") is not True or report.get("candidate_image") != candidate:
            raise ValueError("Recorded candidate rollout required")
        previous = json.loads((output / "gateway-before.private.json").read_text())
        resume_state(before, previous, candidate)
        current = read("clusterstaticentry.spire.spiffe.io", REGISTRATION, None)
        recorded = json.loads((output / "registration-before.private.json").read_text())
        if (current["metadata"]["uid"] != recorded["metadata"]["uid"]
                or current["spec"] != recorded["spec"]):
            raise ValueError("Recorded registration drift prevents resumption")
    else:
        report = start_rollout(args, output, before, candidate, read)
        if not args.deploy:
            return report
        current = json.loads((output / "registration-before.private.json").read_text())
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        pods = json.loads(command(args, "--request-timeout=20s", "get", "pods", "-n", NAMESPACE,
                                  "--field-selector=metadata.name=" + NAME + "-0", "-o", "json"))["items"]
        if len(pods) != 1:
            time.sleep(2)
            continue
        pod = pods[0]
        if (pod["spec"]["containers"][0]["image"] == candidate
                and not pod["metadata"].get("deletionTimestamp")
                and all(v.get("ready") for v in pod.get("status", {}).get("containerStatuses", []))
                and len(pod.get("status", {}).get("containerStatuses", [])) == 1):
            break
        time.sleep(2)
    else:
        raise RuntimeError("Owned candidate rollout did not become Ready")
    registrations = prepare(args.kubeconfig, args.sandbox_id, args.sandbox_name, candidate)
    desired = next(v for v in registrations["items"] if v["metadata"]["name"] == REGISTRATION)
    after_registration = read("clusterstaticentry.spire.spiffe.io", REGISTRATION, None)
    if (after_registration["metadata"]["uid"] != current["metadata"]["uid"]
            or after_registration["spec"] != current["spec"]
            or any(after_registration["metadata"].get("labels", {}).get(k) != v
                   for k, v in LABELS.items())
            or current["spec"]["spiffeID"] != desired["spec"]["spiffeID"]
            or current["spec"]["className"] != desired["spec"]["className"]):
        raise ValueError("Existing owned identity registration required")
    current = after_registration
    patch = [{"op": "test", "path": "/metadata/uid", "value": current["metadata"]["uid"]},
             {"op": "test", "path": "/metadata/resourceVersion", "value": current["metadata"]["resourceVersion"]},
             {"op": "test", "path": "/spec", "value": current["spec"]},
             {"op": "replace", "path": "/spec", "value": desired["spec"]}]
    command(args, "patch", "clusterstaticentry.spire.spiffe.io", REGISTRATION,
            "--type=json", "--dry-run=server", "-p", json.dumps(patch))
    command(args, "patch", "clusterstaticentry.spire.spiffe.io", REGISTRATION,
            "--type=json", "-p", json.dumps(patch))
    report["registration_refreshed"] = True
    write_private(output / "rollout.summary.json", report)
    return report


def start_rollout(args: argparse.Namespace, output: Path, before: dict,
                  candidate: str, read: Callable[[str, str, str | None], dict]) -> dict:
    """Record and start one image change after checking registration custody."""
    patch = image_patch(before, candidate)
    # Establish registration custody before changing a running credential holder.
    current = read("clusterstaticentry.spire.spiffe.io", REGISTRATION, None)
    prior = prepare(args.kubeconfig, args.sandbox_id, args.sandbox_name,
                    before["spec"]["template"]["spec"]["containers"][0]["image"])
    prior_entry = next(v for v in prior["items"] if v["metadata"]["name"] == REGISTRATION)
    if (any(current["metadata"].get("labels", {}).get(k) != v for k, v in LABELS.items())
            or current["spec"] != prior_entry["spec"]):
        raise ValueError("Exact current owned registration required before rollout")
    write_private(output / "registration-before.private.json", current)
    write_private(output / "gateway-before.private.json", before)
    write_private(output / "gateway-image-patch.private.json", patch)
    command(args, "patch", "statefulset", NAME, "-n", NAMESPACE,
            "--type=json", "--dry-run=server", "-p", json.dumps(patch))
    report = {"candidate_image": candidate, "deployed": False,
              "registration_refreshed": False, "step4_complete": False}
    if not args.deploy:
        return report
    command(args, "patch", "statefulset", NAME, "-n", NAMESPACE,
            "--type=json", "-p", json.dumps(patch))
    report["deployed"] = True
    write_private(output / "gateway-deployment-started.private.json", report)
    return report


def main() -> None:
    """Report sanitized results; failed live rollout is never marked successful."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("kubeconfig", "expected-server", "credentials-file", "output-dir",
                 "sandbox-id", "sandbox-name"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--deploy", action="store_true")
    parser.add_argument("--resume-registration", action="store_true",
                        help="Finish only the exact recorded rollout after a transient failure")
    args = parser.parse_args()
    try:
        print(json.dumps(run(args)))
    except Exception as error:
        print(json.dumps({"passed": False, "failure_kind": type(error).__name__,
                          "details_withheld": True, "step4_complete": False}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
