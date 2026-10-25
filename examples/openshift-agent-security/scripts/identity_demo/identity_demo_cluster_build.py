# SPDX-License-Identifier: Apache-2.0
"""Owned OpenShift build/Job transport for the existing pinned native recipe.

Each mutation has a durable pending record. A missing response is uncertain and
is never retried as a fresh create. No Docker daemon or privileged custom build
is introduced; compilation uses a tokenless, egress-denied ordinary Job.
"""

from __future__ import annotations
from copy import deepcopy
from pathlib import Path
import re
import shutil
import subprocess
import time

from deployment_profile import DeploymentProfile
from native_build import prepare, digest, RECIPES
from source_render import read_json
from identity_demo_private_state import checkpoint


class OwnedOperations:
    def __init__(self, args, profile, directory):
        from identity_demo_setup import write

        self.args, self.profile, self.directory = args, profile, directory
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.records = []
        self.write = write

    def scope(self, obj):
        meta = obj["metadata"]
        allowed = {
            "Namespace",
            "ServiceAccount",
            "RoleBinding",
            "BuildConfig",
            "ImageStream",
            "PersistentVolumeClaim",
            "NetworkPolicy",
            "Job",
            "Pod",
            "Build",
        }
        if (
            obj["kind"] not in allowed
            or not isinstance(meta.get("name"), str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,62}", meta["name"])
            or (
                meta.get("namespace") != self.profile.core_namespace
                if obj["kind"] != "Namespace"
                else meta["name"] != self.profile.core_namespace
                or meta.get("namespace") is not None
            )
            or any(
                meta.get("labels", {}).get(k) != v
                for k, v in self.profile.labels.items()
            )
            or meta.get("labels", {}).get("identity-demo-installation")
            != self.profile.installation_id
        ):
            raise ValueError("Exact owned build resource scope required")

    def read(self, obj):
        self.scope(obj)
        from identity_demo_setup import kube

        meta = obj["metadata"]
        scope = ["-n", meta["namespace"]] if meta.get("namespace") else []
        return kube(
            self.args,
            "get",
            obj["kind"],
            meta["name"],
            *scope,
            "--ignore-not-found",
            "-o",
            "json",
        )

    def create(self, obj):
        from identity_demo_setup import kube, fingerprint, owned

        index = len(self.records)
        if self.read(obj):
            raise ValueError("Creation collision; existing resources cannot be adopted")
        self.write(self.directory / (str(index) + ".plan.private.json"), obj)
        kube(
            self.args, "create", "--dry-run=server", "-f", "-", "-o", "json", value=obj
        )
        self.write(
            self.directory / (str(index) + ".pending.private.json"),
            {"object": obj, "submitted": True},
        )
        value = kube(self.args, "create", "-f", "-", "-o", "json", value=obj)
        owned(value, self.profile)
        record = {
            "object": deepcopy(value),
            "uid": value["metadata"]["uid"],
            "fingerprint": fingerprint(value),
        }
        self.records.append(record)
        self.write(self.directory / (str(index) + ".created.private.json"), record)
        checkpoint(
            self.directory / "creation-ledger.private.json",
            {
                "schema_version": 1,
                "installation_profile": self.profile.to_dict(),
                "created": self.records,
            },
        )
        return value

    def delete(self, record):
        from identity_demo_setup import kube, fingerprint, owned

        obj = record["object"]
        current = self.read(obj)
        if not current:
            return False
        owned(current, self.profile)
        projected = deepcopy(current)
        if obj["kind"] == "Pod" and not obj.get("spec", {}).get("nodeName"):
            # Scheduling assigns this one field after creation. Every execution,
            # image, volume and credential field still has to match the receipt.
            projected.get("spec", {}).pop("nodeName", None)
        if (
            current["metadata"]["uid"] != record["uid"]
            or fingerprint(projected) != record["fingerprint"]
        ):
            raise ValueError(
                "Replacement or configuration drift refused during cleanup"
            )
        meta = current["metadata"]
        api = current["apiVersion"]
        kind = current["kind"]
        resources = {
            "Namespace": "namespaces",
            "ServiceAccount": "serviceaccounts",
            "RoleBinding": "rolebindings",
            "BuildConfig": "buildconfigs",
            "ImageStream": "imagestreams",
            "PersistentVolumeClaim": "persistentvolumeclaims",
            "NetworkPolicy": "networkpolicies",
            "Job": "jobs",
            "Pod": "pods",
            "Build": "builds",
        }
        resource = resources[kind]
        uri = "/apis/" + api if "/" in api else "/api/" + api
        if meta.get("namespace"):
            uri += "/namespaces/" + meta["namespace"]
        uri += "/" + resource + "/" + meta["name"]
        kube(
            self.args,
            "delete",
            "--raw",
            uri,
            "-f",
            "-",
            value={
                "apiVersion": "v1",
                "kind": "DeleteOptions",
                **({"propagationPolicy": "Foreground"} if kind == "Job" else {}),
                "preconditions": {
                    "uid": meta["uid"],
                    "resourceVersion": meta["resourceVersion"],
                },
            },
        )
        return True


def object_for(profile, kind, name, spec=None, *, api="v1", namespaced=True):
    meta = {
        "name": name,
        "labels": dict(
            profile.labels, **{"identity-demo-installation": profile.installation_id}
        ),
    }
    if namespaced:
        meta["namespace"] = profile.core_namespace
    result = {"apiVersion": api, "kind": kind, "metadata": meta}
    if spec is not None:
        result["spec"] = spec
    return result


def compiler_context(args, lock, plan):
    source = Path(plan["source"])
    if digest(source / "Cargo.lock") != lock["cargo_lock_sha256"]:
        raise ValueError("Verified prepared source required")
    directory = args.output_dir / "cluster-compiler-context"
    directory.mkdir(mode=0o700)
    for name in ("Builder.Containerfile", "build-native.sh"):
        shutil.copyfile(RECIPES / name, directory / name)
    shutil.copytree(source, directory / "source", symlinks=True)
    recipe = (directory / "Builder.Containerfile").read_text()
    recipe += (
        "\nENV OPENSHELL_DEMO_CARGO_LOCK_SHA256=" + lock["cargo_lock_sha256"] + "\n"
    )
    recipe += (
        'COPY source/ /work/source/\nRUN echo "'
        + lock["cargo_lock_sha256"]
        + '  Cargo.lock" | sha256sum -c - && build-native fetch && mkdir -p /work/output && chmod -R g=u /work/source /cache /work/output\n'
    )
    (directory / "Containerfile").write_text(recipe)
    return directory


def start(args):
    from identity_demo_setup import kube, write

    args.engine = "cluster"
    lock, plan = prepare(args)
    profile = DeploymentProfile.from_dict(read_json(Path(args.installation_profile)))
    if args.expected_server != profile.expected_server:
        raise ValueError("Exact installation server required")
    args.profile = profile
    configured = subprocess.run(
        [
            args.oc,
            "--kubeconfig",
            args.kubeconfig,
            "config",
            "view",
            "--minify",
            "-o",
            "jsonpath={.clusters[0].cluster.server}",
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    if configured != profile.expected_server:
        raise ValueError("Cluster target mismatch")
    from native_build import verified_builder_image

    builder = (
        verified_builder_image(args.native_builder_image, lock)
        if getattr(args, "native_builder_image", None)
        else lock["builder_base"]
    )
    context = compiler_context(args, lock, plan)
    account = "fixture-installer-build"
    name = "fixture-native-compiler"
    objects = [
        object_for(profile, "Namespace", profile.core_namespace, namespaced=False),
        object_for(profile, "ServiceAccount", account),
        object_for(profile, "ImageStream", name, api="image.openshift.io/v1"),
        object_for(
            profile,
            "BuildConfig",
            name,
            api="build.openshift.io/v1",
            spec={
                "runPolicy": "Serial",
                "nodeSelector": {"kubernetes.io/arch": "amd64"},
                "serviceAccount": "builder",
                "source": {"type": "Binary", "binary": {}},
                "strategy": {
                    "type": "Docker",
                    "dockerStrategy": {
                        "dockerfilePath": "Containerfile",
                        "buildArgs": [
                            {"name": "BUILDER_BASE", "value": builder},
                            {
                                "name": "DEBIAN_SNAPSHOT",
                                "value": lock["debian_snapshot"],
                            },
                            {
                                "name": "CARGO_AUDITABLE_VERSION",
                                "value": lock["cargo_auditable_version"],
                            },
                        ],
                    },
                },
                "output": {
                    "to": {"kind": "ImageStreamTag", "name": name + ":candidate"}
                },
                "resources": {
                    "requests": {"cpu": "1", "memory": "2Gi"},
                    "limits": {"cpu": "2", "memory": "6Gi"},
                },
                "successfulBuildsHistoryLimit": 1,
                "failedBuildsHistoryLimit": 1,
                "triggers": [],
            },
        ),
    ]
    objects[1]["automountServiceAccountToken"] = False
    if getattr(args, "namespace_creation_receipt", None):
        from cluster_console_install import namespaces

        namespaces(args, profile)
        objects = [o for o in objects if o["kind"] != "Namespace"]
    write(
        args.output_dir / "cluster-native.plan.private.json",
        {
            "schema_version": 1,
            "objects": objects,
            "source_commit": lock["source_commit"],
            "offline_compilation_required": True,
            "shared_resources_modified": False,
        },
    )
    if not args.apply:
        return {"native_cluster_build_prepared": True, "applied": False}
    ledger = OwnedOperations(args, profile, args.output_dir / "objects")
    for obj in objects:
        ledger.create(obj)
    write(
        args.output_dir / "compiler-submission.pending.private.json",
        {"build_config": name, "expected_build": name + "-1"},
    )
    response = subprocess.run(
        [
            args.oc,
            "--kubeconfig",
            args.kubeconfig,
            "--request-timeout=240s",
            "start-build",
            name,
            "-n",
            profile.core_namespace,
            "--from-dir",
            str(context),
            "-o",
            "name",
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    write(
        args.output_dir / "compiler-submission.response.private.json",
        {
            "exit_code": response.returncode,
            "stdout": response.stdout,
            "stderr": response.stderr,
        },
    )
    if (
        response.returncode
        or response.stdout.strip() != "build.build.openshift.io/" + name + "-1"
    ):
        raise RuntimeError(
            "Build submission uncertain; inspect exact recorded build and do not resubmit"
        )
    build = kube(
        args, "get", "build", name + "-1", "-n", profile.core_namespace, "-o", "json"
    )
    write(args.output_dir / "compiler-build.created.private.json", build)
    record = {"object": build, "uid": build["metadata"]["uid"]}
    compiled = wait_terminal(lambda: exact(args, profile, record), "Build")
    write(args.output_dir / "compiler-build.complete.private.json", compiled)
    resolved = (
        compiled.get("status", {})
        .get("output", {})
        .get("to", {})
        .get("imageDigest", "")
    )
    if not re.fullmatch("sha256:[a-f0-9]{64}", resolved):
        raise ValueError("Immutable compiler output required")
    image = (
        "image-registry.openshift-image-registry.svc:5000/"
        + profile.core_namespace
        + "/"
        + name
        + "@"
        + resolved
    )
    environment = dict(
        line.split("=", 1)
        for line in (args.output_dir / "native-build.env").read_text().splitlines()
    )
    compile_plan = {
        "image": image,
        "objects": compile_objects(profile, image, environment),
    }
    write(args.output_dir / "offline-compile.plan.private.json", compile_plan)
    for obj in compile_plan["objects"]:
        ledger.create(obj)
    args.native_build_directory = str(args.output_dir)
    return complete(args)


def compile_objects(profile, image, environment):
    from deployment_artifacts import IMAGE_REFERENCE

    if not IMAGE_REFERENCE.fullmatch(image):
        raise ValueError("Pinned compiler image required")
    job_labels = dict(
        profile.labels,
        **{
            "identity-demo-installation": profile.installation_id,
            "identity-demo-offline-compile": "true",
            "identity-demo-installer-child": "true",
        },
    )
    security = {
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]},
        "readOnlyRootFilesystem": True,
    }
    volume = {
        "name": "state",
        "persistentVolumeClaim": {"claimName": "fixture-native-build-state"},
    }
    mounts = [
        {"name": "state", "mountPath": "/state"},
        {"name": "tmp", "mountPath": "/tmp"},
    ]
    env = dict(
        environment, CARGO_HOME="/state/cache", CARGO_TARGET_DIR="/state/output/target"
    )
    container = {
        "name": "compile",
        "image": image,
        "workingDir": "/state/source",
        "command": [
            "/bin/sh",
            "-ec",
            "mkdir /state/compile.claim; build-native compile; sha256sum /state/source/Cargo.lock /state/output/openshell-gateway /state/output/openshell-supervisor",
        ],
        "env": [{"name": k, "value": v} for k, v in sorted(env.items())],
        "securityContext": security,
        "volumeMounts": mounts
        + [{"name": "state", "mountPath": "/work/output", "subPath": "output"}],
        "resources": {
            "requests": {"cpu": "2", "memory": "8Gi"},
            "limits": {"cpu": "2", "memory": "12Gi"},
        },
    }
    init = {
        "name": "seed",
        "image": image,
        "command": [
            "/bin/sh",
            "-ec",
            "mkdir -p /state/cache /state/output; cp -R /cache/. /state/cache/; cp -R /work/source /state/source",
        ],
        "securityContext": security,
        "volumeMounts": mounts,
        "resources": {
            "requests": {"cpu": "100m", "memory": "256Mi"},
            "limits": {"cpu": "1", "memory": "1Gi"},
        },
    }
    spec = {
        "backoffLimit": 0,
        "activeDeadlineSeconds": 2400,
        "template": {
            "metadata": {"labels": job_labels},
            "spec": {
                "serviceAccountName": "fixture-installer-build",
                "automountServiceAccountToken": False,
                "restartPolicy": "Never",
                "nodeSelector": {"kubernetes.io/arch": "amd64"},
                "securityContext": {
                    "runAsNonRoot": True,
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
                "initContainers": [init],
                "containers": [container],
                "volumes": [
                    volume,
                    {"name": "tmp", "emptyDir": {"sizeLimit": "512Mi"}},
                ],
            },
        },
    }
    return [
        object_for(
            profile,
            "NetworkPolicy",
            "fixture-native-offline",
            api="networking.k8s.io/v1",
            spec={
                "podSelector": {
                    "matchLabels": {"identity-demo-offline-compile": "true"}
                },
                "policyTypes": ["Egress"],
                "egress": [],
            },
        ),
        object_for(
            profile,
            "PersistentVolumeClaim",
            "fixture-native-build-state",
            spec={
                "accessModes": ["ReadWriteOnce"],
                "storageClassName": profile.storage_class,
                "resources": {"requests": {"storage": "30Gi"}},
            },
        ),
        object_for(profile, "Job", "fixture-native-compile", api="batch/v1", spec=spec),
    ]


def exact(args, profile, record):
    """Read the recorded identity; a replacement never becomes a resume target."""
    from identity_demo_setup import kube, owned

    obj = record["object"]
    meta = obj["metadata"]
    current = kube(
        args,
        "get",
        obj["kind"],
        meta["name"],
        "-n",
        profile.core_namespace,
        "-o",
        "json",
    )
    owned(current, profile)
    if current["metadata"]["uid"] != record["uid"]:
        raise ValueError("Recorded build identity replaced; recovery required")
    return current


def wait_terminal(read, kind, timeout=2400):
    """Observe only; never resubmit a Job or a build after a lost response."""
    deadline = time.monotonic() + timeout
    while True:
        current = read()
        status = current.get("status", {})
        if kind == "Build":
            phase = status.get("phase")
            if phase == "Complete":
                return current
            if phase in ("Failed", "Error", "Cancelled"):
                raise RuntimeError("Owned build failed; retain its private receipt")
        else:
            conditions = {
                v["type"]
                for v in status.get("conditions", [])
                if v.get("status") == "True"
            }
            if "Failed" in conditions:
                raise RuntimeError("Owned compile/check Job failed; do not replay")
            if "Complete" in conditions:
                return current
        if time.monotonic() >= deadline:
            raise TimeoutError(
                "Owned operation still uncertain; observe its recorded UID"
            )
        time.sleep(5)


def docker_objects(profile, name, recipe=None):
    """Standard namespace build credentials are separate from tokenless execution."""
    spec = {
        "runPolicy": "Serial",
        "nodeSelector": {"kubernetes.io/arch": "amd64"},
        "serviceAccount": "builder",
        "source": {"type": "Dockerfile", "dockerfile": recipe}
        if recipe is not None
        else {"type": "Binary", "binary": {}},
        "strategy": {
            "type": "Docker",
            "dockerStrategy": {
                "dockerfilePath": "Containerfile" if recipe is None else "Dockerfile"
            },
        },
        "output": {"to": {"kind": "ImageStreamTag", "name": name + ":candidate"}},
        "resources": {
            "requests": {"cpu": "100m", "memory": "512Mi"},
            "limits": {"cpu": "1", "memory": "2Gi"},
        },
        "successfulBuildsHistoryLimit": 1,
        "failedBuildsHistoryLimit": 1,
        "triggers": [],
    }
    return [
        object_for(profile, "ImageStream", name, api="image.openshift.io/v1"),
        object_for(
            profile, "BuildConfig", name, api="build.openshift.io/v1", spec=spec
        ),
    ]


def submit_build(args, ops, name, context=None):
    """Journal once, then reconcile only that exact build identity."""
    from identity_demo_setup import kube, write

    path = args.output_dir / (name + ".submission")
    write(
        path.with_suffix(".pending.private.json"),
        {"build_config": name, "expected_build": name + "-1"},
    )
    words = [
        args.oc,
        "--kubeconfig",
        args.kubeconfig,
        "--request-timeout=240s",
        "start-build",
        name,
        "-n",
        ops.profile.core_namespace,
        "-o",
        "name",
    ]
    if context is not None:
        words += ["--from-dir", str(context)]
    result = subprocess.run(words, capture_output=True, text=True, timeout=300)
    write(
        path.with_suffix(".response.private.json"),
        {
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        },
    )
    if (
        result.returncode
        or result.stdout.strip() != "build.build.openshift.io/" + name + "-1"
    ):
        raise RuntimeError(
            "Build submission uncertain; inspect recorded name; no automatic replay"
        )
    current = kube(
        args,
        "get",
        "build",
        name + "-1",
        "-n",
        ops.profile.core_namespace,
        "-o",
        "json",
    )
    config = next(
        r
        for r in ops.records
        if r["object"]["kind"] == "BuildConfig"
        and r["object"]["metadata"]["name"] == name
    )
    if (
        current.get("spec", {}).get("serviceAccount") != "builder"
        or current["metadata"].get("labels", {}).get("buildconfig") != name
    ):
        raise ValueError("Exact namespace build association required")
    record = {
        "object": current,
        "uid": current["metadata"]["uid"],
        "build_config_uid": config["uid"],
    }
    write(path.with_suffix(".build.private.json"), record)
    final = wait_terminal(lambda: exact(args, ops.profile, record), "Build")
    write(path.with_suffix(".complete.private.json"), final)
    digest = (
        final.get("status", {}).get("output", {}).get("to", {}).get("imageDigest", "")
    )
    if not re.fullmatch("sha256:[a-f0-9]{64}", digest):
        raise ValueError("Resolved immutable registry digest required")
    return (
        "image-registry.openshift-image-registry.svc:5000/"
        + ops.profile.core_namespace
        + "/"
        + name
        + "@"
        + digest
    )


def export_object(profile, image):
    """Read-only compiler output access, without tokens or network egress."""
    result = object_for(
        profile,
        "Pod",
        "fixture-native-export",
        spec={
            "serviceAccountName": "fixture-installer-build",
            "automountServiceAccountToken": False,
            "restartPolicy": "Never",
            "nodeSelector": {"kubernetes.io/arch": "amd64"},
            "activeDeadlineSeconds": 1800,
            "securityContext": {
                "runAsNonRoot": True,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "containers": [
                {
                    "name": "export",
                    "image": image,
                    "command": ["/bin/sh", "-ec", "sleep 1750"],
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        "readOnlyRootFilesystem": True,
                        "capabilities": {"drop": ["ALL"]},
                    },
                    "resources": {
                        "requests": {"cpu": "20m", "memory": "64Mi"},
                        "limits": {"cpu": "100m", "memory": "256Mi"},
                    },
                    "volumeMounts": [
                        {"name": "state", "mountPath": "/state", "readOnly": True}
                    ],
                }
            ],
            "volumes": [
                {
                    "name": "state",
                    "persistentVolumeClaim": {
                        "claimName": "fixture-native-build-state",
                        "readOnly": True,
                    },
                }
            ],
        },
    )

    result["metadata"]["labels"]["identity-demo-installer-child"] = "true"
    return result


def packaged_probe(profile, role, image):
    binary = (
        "/usr/local/bin/openshell-gateway"
        if role == "gateway"
        else "/openshell-supervisor"
    )
    container = {
        "name": "help",
        "image": image,
        "command": [binary, "--help"],
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]},
        },
        "resources": {
            "requests": {"cpu": "50m", "memory": "64Mi"},
            "limits": {"cpu": "500m", "memory": "256Mi"},
        },
    }
    spec = {
        "backoffLimit": 0,
        "activeDeadlineSeconds": 120,
        "template": {
            "metadata": {
                "labels": dict(
                    profile.labels,
                    **{
                        "identity-demo-installation": profile.installation_id,
                        "identity-demo-offline-compile": "true",
                        "identity-demo-installer-child": "true",
                    },
                )
            },
            "spec": {
                "serviceAccountName": "fixture-installer-build",
                "automountServiceAccountToken": False,
                "restartPolicy": "Never",
                "nodeSelector": {"kubernetes.io/arch": "amd64"},
                "securityContext": {
                    "runAsNonRoot": True,
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
                "initContainers": [
                    dict(container, name="version", command=[binary, "--version"])
                ],
                "containers": [container],
            },
        },
    }
    return object_for(
        profile, "Job", "fixture-native-" + role + "-check", api="batch/v1", spec=spec
    )


def complete(args):
    """Finish a recorded offline compile and publish/verify both native images.

    Requires the original private output directory. Exclusive receipts prevent
    replay; interrupted mutations require the existing explicit identity review.
    """
    from identity_demo_setup import write
    from native_build import runtime_context

    if not args.apply:
        raise ValueError(
            "Completion requires explicit --apply and original build directory"
        )
    from identity_demo_setup import private_file, in_checkout

    root = Path(args.native_build_directory)
    if (
        not root.is_absolute()
        or root.is_symlink()
        or not root.is_dir()
        or root.stat().st_mode & 0o077
        or in_checkout(root)
    ):
        raise ValueError("Original private native build directory required")
    profile = DeploymentProfile.from_dict(
        read_json(private_file(args.installation_profile))
    )
    configured = subprocess.run(
        [
            args.oc,
            "--kubeconfig",
            args.kubeconfig,
            "config",
            "view",
            "--minify",
            "-o",
            "jsonpath={.clusters[0].cluster.server}",
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    if (
        args.expected_server != profile.expected_server
        or configured != profile.expected_server
    ):
        raise ValueError("Exact installation target required")
    args.profile = profile
    args.output_dir = root
    ops = OwnedOperations(args, profile, root / "objects")
    ledger = read_json(root / "objects/creation-ledger.private.json")
    if ledger["installation_profile"] != profile.to_dict():
        raise ValueError("Original build ledger required")
    ops.records = ledger["created"]
    recorded = next(
        r
        for r in ops.records
        if r["object"]["kind"] == "Job"
        and r["object"]["metadata"]["name"] == "fixture-native-compile"
    )
    job = wait_terminal(lambda: exact(args, profile, recorded), "Job")
    write(root / "offline-compile.complete.private.json", job)
    compile_plan = read_json(root / "offline-compile.plan.private.json")
    exporter = export_object(profile, compile_plan["image"])
    exporter["metadata"]["labels"]["identity-demo-offline-compile"] = "true"
    created = ops.create(exporter)
    export_record = ops.records[-1]
    deadline = time.monotonic() + 120
    while True:
        observed = exact(args, profile, export_record)
        if observed.get("status", {}).get("phase") == "Running":
            break
        if (
            observed.get("status", {}).get("phase") in ("Failed", "Succeeded")
            or time.monotonic() >= deadline
        ):
            raise RuntimeError("Owned output export Pod unavailable")
        time.sleep(2)
    allowed = {
        "/state/output/openshell-gateway",
        "/state/output/openshell-supervisor",
        "/state/output/builder-packages.txt",
        "/usr/lib/x86_64-linux-gnu/libz3.so.4",
        "/usr/lib/x86_64-linux-gnu/libgcc_s.so.1",
        "/usr/share/doc/libz3-4/copyright",
        "/usr/share/doc/libgcc-s1/copyright",
    }

    def export(source, destination):
        if source not in allowed:
            raise ValueError("Fixed native output paths only")
        exact(args, profile, export_record)
        with destination.open("xb") as stream:
            result = subprocess.run(
                [
                    args.oc,
                    "--kubeconfig",
                    args.kubeconfig,
                    "--request-timeout=120s",
                    "exec",
                    created["metadata"]["name"],
                    "-n",
                    profile.core_namespace,
                    "-c",
                    "export",
                    "--",
                    "cat",
                    source,
                ],
                stdout=stream,
                stderr=subprocess.PIPE,
                timeout=150,
            )
        if result.returncode or not 0 < destination.stat().st_size <= 250_000_000:
            raise RuntimeError("Bounded fixed output export failed")
        check = subprocess.run(
            [
                args.oc,
                "--kubeconfig",
                args.kubeconfig,
                "--request-timeout=20s",
                "exec",
                created["metadata"]["name"],
                "-n",
                profile.core_namespace,
                "-c",
                "export",
                "--",
                "sha256sum",
                source,
            ],
            capture_output=True,
            text=True,
            timeout=35,
        )
        if check.returncode or check.stdout.split()[0] != digest(destination):
            raise ValueError("Exported native bytes differ from compiler output")

    (root / "compiled").mkdir(mode=0o700)
    for name in ("openshell-gateway", "openshell-supervisor", "builder-packages.txt"):
        export("/state/output/" + name, root / "compiled" / name)
    lock = read_json(root / "inputs.lock.executed.json")
    plan = read_json(root / "native-build.plan.json")
    results = {}
    for role in ("gateway", "supervisor"):
        context = runtime_context(
            args, lock, plan, role, compile_plan["image"], export_file=export
        )
        name = "fixture-native-" + role
        for obj in docker_objects(profile, name):
            ops.create(obj)
        image = submit_build(args, ops, name, context)
        binary = (
            "/usr/local/bin/openshell-gateway"
            if role == "gateway"
            else "/openshell-supervisor"
        )
        expected = digest(root / "compiled" / ("openshell-" + role))
        recipe = (
            "FROM "
            + image
            + " AS packed\nFROM "
            + compile_plan["image"]
            + "\nCOPY --from=packed "
            + binary
            + ' /verify-binary\nRUN echo "'
            + expected
            + '  /verify-binary" | sha256sum -c -\n'
        )
        for obj in docker_objects(profile, name + "-bytes", recipe):
            ops.create(obj)
        submit_build(args, ops, name + "-bytes")
        probe = ops.create(packaged_probe(profile, role, image))
        wait_terminal(
            lambda: exact(
                args, profile, {"object": probe, "uid": probe["metadata"]["uid"]}
            ),
            "Job",
            180,
        )
        results[role] = {
            "image": image,
            "binary_sha256": expected,
            "packaged_binary_matches": True,
            "offline_help_and_version_passed": True,
        }
    write(
        root / "native-cluster-build.receipt.json",
        {
            "schema_version": 1,
            "applied": True,
            "offline_compilation_passed": True,
            "source_commit": lock["source_commit"],
            "native_build_contract": profile.native_build_contract,
            "native_ca_bundle_sha256": plan["native_ca_bundle_sha256"],
            "runtime_checks": results,
            "production_approved": False,
            "live_acceptance_passed": False,
            "security_and_distribution_approved": False,
        },
    )
    # Export Pod is only needed while collecting outputs; retain compile/cache PVC
    # and exact build receipts until final candidate acceptance and cleanup.
    ops.delete(export_record)
    deletion_deadline = time.monotonic() + 60
    while current := ops.read(export_record["object"]):
        if (
            current["metadata"]["uid"] != export_record["uid"]
            or not current["metadata"].get("deletionTimestamp")
            or time.monotonic() >= deletion_deadline
        ):
            raise RuntimeError(
                "Exporter deletion requires reconciliation; do not repeat the delete"
            )
        time.sleep(2)
    return {
        "native_cluster_build_completed": True,
        "offline_compilation_passed": True,
        "runtime_checks": results,
        "live_acceptance_passed": False,
    }
