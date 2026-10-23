#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Inventory owned runtime images and handoff sources without exporting Secrets.

This is a read-only preparation artifact. It does not prove mirrored image
availability, cold installation, inference, disconnected operation or provenance
of an externally built image. Actual endpoint configuration stays outside Git.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

from identity_demo_lab import oc
from identity_demo_runtime import guard, NAMESPACE
from identity_demo_runtime_cli import private_path
from deployment_profile import active_profile

ROOT = Path(__file__).resolve().parents[2]
PROFILE = active_profile()
NAMESPACES = (*PROFILE.application_namespaces, PROFILE.identity_namespace)
ENDPOINT_ROLES = {"chat", "issuer", "jwks", "registry", "audit"}
BUILD_INPUTS = (
    "infra/openshell/native-build/inputs.lock.json",
    "infra/openshell/native-build/Builder.Containerfile",
    "infra/openshell/native-build/build-native.sh",
    "infra/openshell/native-build/README.md",
    "tests/identity_demo/tools/inputs.lock.json",
    "tests/identity_demo/tools/read_native_projection.go",
    "tests/identity_demo/tools/read_native_projection_test.go",
    "tests/identity_demo/tools/README.md",
)


def image_inventory(resources: list[dict]) -> list[dict]:
    """Select image references and pull policy from pod specs only, never env/data."""
    references: dict[str, dict] = {}
    for resource in resources:
        kind, metadata = resource["kind"], resource["metadata"]
        if metadata["namespace"] not in NAMESPACES:
            raise ValueError("Only owned pilot namespaces may be inventoried")
        spec = resource["spec"]
        if kind == "Pod":
            pod = spec
        elif kind == "Sandbox":
            pod = spec["podTemplate"]["spec"]
        elif kind in ("Deployment", "DaemonSet", "StatefulSet"):
            pod = spec["template"]["spec"]
        else:
            raise ValueError("Unsupported inventory kind")
        for group in ("containers", "initContainers", "ephemeralContainers"):
            for container in pod.get(group, []):
                image = container["image"]
                if not isinstance(image, str) or len(image) > 1024 or any(c.isspace() for c in image):
                    raise ValueError("Invalid image reference")
                item = references.setdefault(image, {"image": image,
                    "digest_pinned": bool(re.search(r"@sha256:[a-f0-9]{64}$", image)), "used_by": []})
                item["used_by"].append({"kind": kind, "namespace": metadata["namespace"],
                    "name": metadata["name"], "container": container["name"],
                    "pull_policy": container.get("imagePullPolicy", "Kubernetes default")})
    return [references[key] for key in sorted(references)]


def endpoints(value: dict) -> dict:
    """Validate transport descriptions; never accept inline secrets or credentials."""
    if not isinstance(value, dict) or set(value) - ENDPOINT_ROLES:
        raise ValueError("Only documented endpoint roles are accepted")
    safe = {}
    for role, endpoint in value.items():
        if not isinstance(endpoint, str):
            raise ValueError("Endpoint URL required; secrets supplied separately")
        parsed = urlsplit(endpoint)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username
                or parsed.password or parsed.query or parsed.fragment):
            raise ValueError("Fixed HTTPS endpoint without inline credentials/query required")
        safe[role] = endpoint
    return safe


def source_inventory() -> list[dict]:
    """Hash selected delivery sources, including both pinned binary build recipes.

    Source hashes are an inventory, not bundled dependencies, an SBOM or proof
    that a disconnected build works. Missing recipes and symlink escapes fail.
    """
    required = [ROOT / name for name in BUILD_INPUTS]
    if any(not path.is_file() or path.is_symlink() for path in required):
        raise ValueError("Complete checked-in native/diagnostic build inputs required")
    files = [*ROOT.glob("scripts/identity_demo/*.py"),
        *ROOT.glob("tests/identity_demo/**/*.py"), *ROOT.glob("tests/identity_demo/requirements*.txt"),
        *ROOT.glob("infra/openshell/patches/*.patch"),
        *ROOT.glob("infra/identity-demo/*.json"), *ROOT.glob("infra/identity-demo/*.Containerfile"),
        *ROOT.glob("infra/identity-demo/templates/*.json"),
        *ROOT.glob("infra/operators/spiffe-spire/identity-demo/*.yaml"),
        *[p for p in ROOT.glob("workloads/agents/service-request-demo/**/*") if p.is_file()],
        *ROOT.glob("docs/*.md"),
        *ROOT.glob("docs/examples/identity-demo-*"), *required]
    sources = []
    for path in sorted(set(files)):
        if any(part in {"__pycache__", ".pytest_cache", ".ruff_cache"} for part in path.parts) or path.suffix == ".pyc":
            continue
        if path.is_symlink() or not path.resolve().is_relative_to(ROOT.resolve()):
            raise ValueError("Repository source symlinks/escapes refused")
        if path.is_file():
            sources.append({"path": str(path.relative_to(ROOT)),
                            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    return sources


def run(args: argparse.Namespace) -> dict:
    """Read only owned namespaces and retain complete inventory privately."""
    args.namespace = NAMESPACE
    guard(args)
    resources = []
    for namespace in NAMESPACES:
        ns = json.loads(oc(args, "get", "namespace", namespace, "-o", "json"))
        if any(ns["metadata"].get("labels", {}).get(k) != v for k, v in PROFILE.labels.items()):
            raise ValueError("Owned namespace required")
        for kind in ("pods", "deployments", "statefulsets", "daemonsets"):
            resources.extend(json.loads(oc(args, "get", kind, "-n", namespace, "-o", "json"))["items"])
    images = image_inventory(resources)
    supplied = endpoints(json.loads(private_path(args.endpoints_file).read_text())) if args.endpoints_file else {}
    sources = source_inventory()
    inventory = {"images": images, "endpoints": supplied, "repository_sources": sources,
        "required_artifact_kinds": ["digest-addressed images and operator bundles",
            "selected installer/rendering sources, operator manifests and CRDs", "hash-pinned wheels for each target architecture",
            "CLI/helper binaries with source/build provenance", "CVE intelligence and deterministic fixtures",
            "chat inference endpoint and internal service CAs", "UI assets, runbooks and rollback inputs"],
        "missing_endpoint_roles": sorted(ENDPOINT_ROLES - supplied.keys()),
        "external_image_source_provenance": "Requires authoritative image build inputs; repository source hashes alone are insufficient.",
        "mirror_availability_proven": False, "cold_restart_without_public_egress_proven": False,
        "inference_proven": False, "disconnected_operation_proven": False}
    parent = private_path(str(Path(args.output_dir).parent), directory=True)
    directory = parent / Path(args.output_dir).name
    directory.mkdir(mode=0o700)
    with os.fdopen(os.open(directory / "inventory.private.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
        json.dump(inventory, stream, indent=2)
    result = {"inventoried": True, "images": len(images),
        "unpinned_image_references": sum(not i["digest_pinned"] for i in images),
        "repository_source_files": len(sources), "missing_endpoint_roles": inventory["missing_endpoint_roles"],
        "secret_values_exported": False, "cluster_changed": False, "step7_complete": False}
    with os.fdopen(os.open(directory / "inventory.summary.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
        json.dump(result, stream, indent=2)
    return result


def main() -> None:
    """Publish classifications only; endpoints and complete artifact lists stay private."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("kubeconfig", "expected-server", "credentials-file", "output-dir"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--endpoints-file")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        print(json.dumps(run(args)))
    except Exception as error:
        print(json.dumps({"inventoried": False, "kind": type(error).__name__, "details_withheld": True}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
