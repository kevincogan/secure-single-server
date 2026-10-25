# SPDX-License-Identifier: Apache-2.0
"""Prepare and build target-bound native images without deploying or publishing.

The default only prepares a verified context. Applying builds a documented
compiler image, fetches locked dependencies, compiles offline, packages over
pinned official runtime bases and checks packaged executable hashes/startup.
It does not confer vendor support, scan approval or live acceptance.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
from uuid import uuid4
from urllib.parse import quote

from deployment_profile import DeploymentProfile
from source_render import canonical_hash, certificate_bundle, read_json

ROOT = Path(__file__).resolve().parents[2]
RECIPES = ROOT / "infra/openshell/native-build"
PATCHES = ROOT / "infra/openshell/patches"


def verified_builder_image(image, lock):
    """Permit an approved mirror only for the pinned AMD64 manifest bytes."""
    from deployment_artifacts import IMAGE_REFERENCE
    if (not isinstance(image,str) or not IMAGE_REFERENCE.fullmatch(image)
            or image.rsplit('@',1)[-1] != lock['builder_platform_digest']):
        raise ValueError('Builder mirror must preserve the pinned AMD64 manifest digest')
    return image


def digest(path: Path) -> str:
    """Hash large source/executable files without logging their contents."""
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def command(words: list[str], log: Path, *, cwd: Path | None = None,
            timeout: int = 7200) -> None:
    """Retain build output privately; expose only stage names and error categories."""
    print(json.dumps({"native_build_stage": log.stem}), flush=True)
    fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        result = subprocess.run(words, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
    if result.returncode:
        raise RuntimeError("Native build stage failed; inspect its private log")


def capture(words: list[str]) -> str:
    """Read bounded engine metadata without forwarding arbitrary engine errors."""
    result = subprocess.run(words, capture_output=True, text=True, timeout=60)
    if result.returncode or len(result.stdout) > 65536:
        raise RuntimeError("Native build metadata unavailable; details withheld")
    return result.stdout.strip()


def prepare(args: argparse.Namespace) -> tuple[dict, dict]:
    """Validate archive/patch/lock/trust inputs before executing source tools."""
    from identity_demo_setup import private_file, write

    helper_source = Path(__file__).read_bytes()
    lock = read_json(RECIPES / "inputs.lock.json")
    profile = DeploymentProfile.from_dict(read_json(private_file(args.installation_profile)))
    archive = Path(args.source_archive).expanduser()
    # This archive is public, hash-pinned source, not operator credential state.
    if (not archive.is_absolute() or archive.is_symlink() or not archive.is_file()
            or archive.stat().st_size > 32_000_000 or digest(archive) != lock["source_archive_sha256"]):
        raise ValueError("Exact reviewed source archive required")
    ca_path = private_file(args.native_ca_bundle)
    public = certificate_bundle(ca_path).encode()
    if public != ca_path.read_bytes():
        raise ValueError("Canonical current public CA bundle required; render again after trust changes")
    for patch in lock["patches"]:
        path = PATCHES / patch["file"]
        if path.parent != PATCHES or digest(path) != patch["sha256"]:
            raise ValueError("Exact reviewed patchset required")
    source_parent = args.output_dir / "source"
    source_parent.mkdir(mode=0o700)
    with tarfile.open(archive) as packed:
        members = packed.getmembers()
        roots = {Path(m.name).parts[0] for m in members}
        if len(roots) != 1 or len(members) > 10000 or sum(m.size for m in members) > 100_000_000:
            raise ValueError("Bounded single-root source archive required")
        # The built-in data filter refuses traversal, special files and escaping
        # symlinks. The exact upstream archive includes a safe .claude symlink.
        packed.extractall(source_parent, filter="data")
    source = source_parent / next(iter(roots))
    if digest(source / "Cargo.lock") != lock["upstream_cargo_lock_sha256"]:
        raise ValueError("Reviewed upstream Cargo lockfile required")
    for index, patch in enumerate(lock["patches"]):
        path = PATCHES / patch["file"]
        command(["git", "apply", "--check", str(path)], args.output_dir / f"patch-{index}-check.log", cwd=source)
        command(["git", "apply", str(path)], args.output_dir / f"patch-{index}-apply.log", cwd=source)
    if digest(source / "Cargo.lock") != lock["cargo_lock_sha256"]:
        raise ValueError("Exact reviewed patched Cargo lockfile required")
    builder = args.output_dir / "builder"
    builder.mkdir(mode=0o700)
    for name in ("Builder.Containerfile", "build-native.sh"):
        shutil.copyfile(RECIPES / name, builder / name)
    environment = {**profile.native_build_contract, "CARGO_BUILD_JOBS": "2",
                   "OPENSHELL_DEMO_CARGO_LOCK_SHA256": lock["cargo_lock_sha256"]}
    env_path = args.output_dir / "native-build.env"
    with env_path.open("x") as stream:
        os.chmod(env_path, 0o600)
        stream.write("".join(k + "=" + v + "\n" for k, v in sorted(environment.items())))
    (args.output_dir / "native-public-trust.pem").write_bytes(public)
    unique = "identity-demo-" + profile.installation_id + "-" + uuid4().hex[:10]
    plan = {"schema_version": 1, "build_inputs": lock, "source": str(source), "source_commit": lock["source_commit"],
        "source_archive_sha256": lock["source_archive_sha256"],
        "cargo_lock_sha256": lock["cargo_lock_sha256"], "patches": lock["patches"],
        "native_build_contract": profile.native_build_contract,
        "native_ca_bundle_sha256": hashlib.sha256(public).hexdigest(),
        "recipe_sha256": {**{p.name: digest(p) for p in (RECIPES / "inputs.lock.json",
            RECIPES / "Builder.Containerfile", RECIPES / "build-native.sh")},
            "native_build.py": hashlib.sha256(helper_source).hexdigest()},
        "images": {role: "localhost/" + unique + "-" + role for role in ("builder", "gateway", "supervisor")},
        "target": lock["target"], "engine": args.engine, "applied": False,
        "cluster_contacted": False, "published": False, "live_acceptance_proven": False}
    # Preserve the exact helper and lock with the plan, even if the checkout is
    # edited later. Original receipts and their source hashes are never rewritten.
    for name, data in (("native_build.executed.py", helper_source),
                       ("inputs.lock.executed.json", (RECIPES / "inputs.lock.json").read_bytes())):
        with (args.output_dir / name).open("xb") as stream:
            os.chmod(stream.name, 0o600)
            stream.write(data)
    write(args.output_dir / "native-build.plan.json", plan)
    return lock, plan


def runtime_recipe(lock: dict, plan: dict, role: str) -> str:
    """Render the exact public runtime recipe shared by build and publication."""
    if role not in ("gateway", "supervisor"):
        raise ValueError("Known native runtime role required")
    binary = "openshell-" + role
    library = "libz3.so.4" if role == "gateway" else "libgcc_s.so.1"
    copyright_file = ("libz3-4" if role == "gateway" else "libgcc-s1") + ".copyright"
    destination = "/usr/local/bin/openshell-gateway" if role == "gateway" else "/openshell-supervisor"
    patch_hash = canonical_hash({p["file"]: p["sha256"] for p in lock["patches"]})
    return ("# SPDX-License-Identifier: Apache-2.0\nFROM " + lock["runtime_bases"][role] + "\n"
        + f"COPY --chmod=0555 {binary} {destination}\n"
        + f"COPY --chmod=0444 {library} /usr/lib/x86_64-linux-gnu/{library}\n"
        + f"COPY --chmod=0444 {copyright_file} /usr/share/licenses/identity-demo/{copyright_file}\n"
        + "COPY --chmod=0444 supplied-library.spdx.json /usr/share/identity-demo/supplied-library.spdx.json\n"
        + "COPY --chmod=0444 native-public-trust.pem /etc/ssl/certs/ca-certificates.crt\n"
        + 'LABEL org.opencontainers.image.revision="' + lock["source_commit"] + '" \\\n'
        + ' identity-demo.native-contract-sha256="' + canonical_hash(plan["native_build_contract"]) + '" \\\n'
        + ' identity-demo.native-ca-sha256="' + plan["native_ca_bundle_sha256"] + '" \\\n'
        + ' identity-demo.patchset-sha256="' + patch_hash + '"\nUSER 1000:1000\n')


def runtime_context(args: argparse.Namespace, lock: dict, plan: dict, role: str,
                    builder_id: str, *, export_file=None) -> Path:
    """Create an allowlisted binary/library/public-trust context, never private state."""
    from identity_demo_setup import write

    context = args.output_dir / role
    context.mkdir(mode=0o700)
    binary = "openshell-" + role
    shutil.copyfile(args.output_dir / "compiled" / binary, context / binary)
    header = (context / binary).read_bytes()[:20]
    if not (header[:6] == b"\x7fELF\x02\x01" and header[18:20] == b"\x3e\x00"):
        raise ValueError("Linux AMD64 ELF executable required")
    library = "libz3.so.4" if role == "gateway" else "libgcc_s.so.1"
    def exported(source, target):
        if export_file is not None:
            export_file(source, target)
        else:
            with target.open("xb") as stream:
                result = subprocess.run([args.engine, "run", "--rm", "--network=none", "--read-only",
                    "--cap-drop=ALL", "--security-opt=no-new-privileges", "--entrypoint", "cat", builder_id,
                    source], stdout=stream, stderr=subprocess.PIPE, timeout=60)
            if result.returncode:
                raise RuntimeError("Target runtime export failed; details withheld")
        if not target.is_file() or not target.stat().st_size:
            raise ValueError("Nonempty runtime export required")
    exported("/usr/lib/x86_64-linux-gnu/" + library, context / library)
    package = "libz3-4" if role == "gateway" else "libgcc-s1"
    versions = [line.split()[1] for line in (args.output_dir / "compiled/builder-packages.txt").read_text().splitlines()
                if line.split() and line.split()[0] == package + ":amd64"]
    if len(versions) != 1:
        raise ValueError("Exact copied-library package version required")
    copyright_file = package + ".copyright"
    exported("/usr/share/doc/" + package + "/copyright", context / copyright_file)
    # Copying a shared library does not update the base image's dpkg database.
    # Preserve a separate truthful SPDX package record and its real licence text.
    library_hash = digest(context / library)
    library_sbom = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
        "name": "identity-demo-supplied-library", "documentNamespace": "https://spdx.org/spdxdocs/identity-demo-" + library_hash,
        "creationInfo": {"creators": ["Tool: identity-demo-native-build"],
                         "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
        "packages": [{"SPDXID": "SPDXRef-SuppliedLibrary", "name": package,
            "versionInfo": versions[0], "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION", "copyrightText": "NOASSERTION",
            "sourceInfo": "Copied from recorded builder image " + builder_id + "; shared-library SHA256 " + library_hash,
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                "referenceLocator": "pkg:deb/debian/" + package + "@" + quote(versions[0], safe="") + "?arch=amd64&distro=debian-13"}]}],
        "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                           "relatedSpdxElement": "SPDXRef-SuppliedLibrary"}]}
    write(context / "supplied-library.spdx.json", library_sbom)
    shutil.copyfile(args.output_dir / "native-public-trust.pem", context / "native-public-trust.pem")
    (context / "Containerfile").write_text(runtime_recipe(lock, plan, role))
    write(args.output_dir / (role + "-context.json"), {p.name: digest(p) for p in context.iterdir()})
    return context


def validate_runtime(args: argparse.Namespace, role: str, image_id: str) -> dict:
    """Check architecture, exact installed path/hash, help and version offline."""
    binary = "/usr/local/bin/openshell-gateway" if role == "gateway" else "/openshell-supervisor"
    if capture([args.engine, "image", "inspect", image_id, "--format", "{{.Architecture}} {{.Os}} "]) != "amd64 linux":
        raise ValueError("Linux AMD64 runtime image required")
    container = capture([args.engine, "create", "--platform=linux/amd64", "--entrypoint", binary, image_id, "--version"])
    if not re.fullmatch(r"[a-f0-9]{12,64}", container):
        raise ValueError("Exact newly created validation container ID required")
    packaged = args.output_dir / (role + ".packaged.bin")
    try:
        command([args.engine, "cp", container + ":" + binary, str(packaged)],
                args.output_dir / (role + "-copy.log"), timeout=60)
    finally:
        command([args.engine, "rm", container], args.output_dir / (role + "-container-cleanup.log"), timeout=60)
    expected = digest(args.output_dir / "compiled" / ("openshell-" + role))
    if digest(packaged) != expected:
        raise ValueError("Packaged executable differs from compiled output")
    for option in ("--version", "--help"):
        command([args.engine, "run", "--rm", "--platform=linux/amd64", "--network=none",
            "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--entrypoint", binary, image_id, option],
            args.output_dir / (role + "-" + option[2:] + ".log"), timeout=60)
    return {"image_id": image_id, "binary_sha256": expected, "installed_path": binary,
            "packaged_binary_matches": True, "offline_help_and_version_passed": True}


def compiler_cache(args: argparse.Namespace, lock: dict) -> str | None:
    """Reuse only an immutable compiler image from a hash-pinned private receipt.

    Native binaries and source/patch checks are never reused or bypassed. This
    avoids a registry metadata dependency when the identical compiler is local.
    """
    from identity_demo_setup import private_file
    filename = getattr(args, "compiler_cache_receipt", None)
    expected = getattr(args, "compiler_cache_sha256", None)
    if not filename:
        if expected:
            raise ValueError("Compiler cache receipt required with hash")
        return None
    path = private_file(filename)
    if not expected or digest(path) != expected:
        raise ValueError("Exact prior compiler receipt hash required")
    prior = read_json(path)
    if prior.get("applied") is not True or prior.get("offline_compilation_passed") is not True:
        raise ValueError("Completed previous native build required")
    compiler_fields = ("builder_base", "rust_version", "cargo_auditable_version", "debian_snapshot", "target")
    if any(prior.get("build_inputs", {}).get(k) != lock.get(k) for k in compiler_fields):
        raise ValueError("Compiler build inputs changed")
    if any(prior.get("recipe_sha256", {}).get(name) != digest(RECIPES / name)
           for name in ("Builder.Containerfile", "build-native.sh")):
        raise ValueError("Compiler recipes changed")
    image = prior.get("builder_image_id", "")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
        raise ValueError("Immutable compiler image ID required")
    if capture([args.engine, "image", "inspect", image, "--format", "{{.Id}} "]) != image:
        raise ValueError("Recorded compiler image is not present locally")
    return image


def seed_dependency_cache(args: argparse.Namespace, lock: dict, builder_id: str) -> bool:
    """Reuse private dependencies; discard all workspace binaries/fingerprints.

    A completed hash-pinned build is the cache authority. Cargo still fetches
    with --locked and compiles --frozen without networking. No Cargo credentials
    or host configuration are copied, and no prior sender binary is retained.
    """
    from identity_demo_setup import private_file, in_checkout
    filename = getattr(args, "native_cache_receipt", None)
    expected = getattr(args, "native_cache_sha256", None)
    if not filename:
        if expected:
            raise ValueError("Native cache receipt required with hash")
        return False
    path = private_file(filename)
    if not expected or digest(path) != expected:
        raise ValueError("Exact native dependency cache receipt hash required")
    prior = read_json(path)
    if (prior.get("applied") is not True or prior.get("offline_compilation_passed") is not True
            or prior.get("builder_image_id") != builder_id
            or prior.get("cargo_lock_sha256") != lock["cargo_lock_sha256"]
            or prior.get("target") != lock["target"]):
        raise ValueError("Matching completed compiler/dependency build required")
    for parent in (path.parent, path.parent / "cache", path.parent / "compiled"):
        if (parent.is_symlink() or not parent.is_dir() or parent.stat().st_uid != os.getuid()
                or parent.stat().st_mode & 0o077):
            raise ValueError("Owner-only private cache directories required")
    roots = [path.parent / "cache", path.parent / "compiled/target"]
    for root in roots:
        if (root.is_symlink() or not root.is_dir() or in_checkout(root.resolve())
                or root.stat().st_uid != os.getuid()):
            raise ValueError("Owned private dependency cache required")
    cache = args.output_dir / "cache"
    compiled = args.output_dir / "compiled"
    cache.mkdir(mode=0o700)
    compiled.mkdir(mode=0o700)
    for name in ("registry", "git"):
        source = roots[0] / name
        if source.is_symlink():
            raise ValueError("Dependency cache root symlink refused")
        if source.is_dir():
            shutil.copytree(source, cache / name, symlinks=True)
    target = compiled / "target"
    shutil.copytree(roots[1], target, symlinks=True)
    # Rust target caches also contain workspace binaries. Force every OpenShell
    # crate and build script to compile for the current source and contract.
    for debug in (target / "debug", target / lock["target"] / "debug",
                  target / "release", target / lock["target"] / "release"):
        for directory in (debug, debug / "deps", debug / ".fingerprint", debug / "build"):
            if directory.is_symlink():
                raise ValueError("Workspace cache directory symlink refused")
            for pattern in ("openshell*", "libopenshell*"):
                for item in directory.glob(pattern):
                    if item.is_symlink() or item.is_file():
                        item.unlink()
                    elif item.is_dir():
                        shutil.rmtree(item)
    return True


def native_build(args: argparse.Namespace) -> dict:
    """Run the source build locally only when explicitly applied."""
    from identity_demo_setup import write

    lock, plan = prepare(args)
    if not args.apply:
        return {"native_build_prepared": True, "applied": False, "cluster_contacted": False,
                "source_and_patches_verified": True, "live_acceptance_proven": False}
    engine = args.engine
    if engine == "docker":
        capture([engine, "buildx", "version"])  # Fail before compiling if BuildKit is unavailable.
    builder = args.output_dir / "builder"
    builder_id = compiler_cache(args, lock)
    compiler_reused = builder_id is not None
    if builder_id is None:
        command([engine, "build", "-f", str(builder / "Builder.Containerfile"),
            "--build-arg", "BUILDER_BASE=" + lock["builder_base"],
            "--build-arg", "DEBIAN_SNAPSHOT=" + lock["debian_snapshot"],
            "--build-arg", "CARGO_AUDITABLE_VERSION=" + lock["cargo_auditable_version"],
            "-t", plan["images"]["builder"], str(builder)], args.output_dir / "builder-build.log")
        builder_id = capture([engine, "image", "inspect", plan["images"]["builder"], "--format", "{{.Id}}"])
    write(args.output_dir / "build-environment.json", {
        "engine_version": capture([engine, "--version"]),
        "builder_platform": capture([engine, "image", "inspect", builder_id, "--format", "{{.Os}}/{{.Architecture}}"]),
        "runtime_target": "linux/amd64"})
    cache_seeded = seed_dependency_cache(args, lock, builder_id)
    for name in ("cache", "compiled"):
        if not (args.output_dir / name).exists():
            (args.output_dir / name).mkdir(mode=0o700)
    run = [engine, "run", "--rm", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--pids-limit=512", "--user", str(os.getuid()) + ":" + str(os.getgid()),
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=512m", "--env-file", str(args.output_dir / "native-build.env"),
        "-v", plan["source"] + ":/work/source:rw", "-v", str(args.output_dir / "cache") + ":/cache:rw",
        "-v", str(args.output_dir / "compiled") + ":/work/output:rw"]
    command([*run, builder_id, "fetch"], args.output_dir / "dependency-fetch.log")
    command([*run, "--network=none", builder_id, "compile"], args.output_dir / "native-compile.log")
    if digest(Path(plan["source"]) / "Cargo.lock") != lock["cargo_lock_sha256"]:
        raise ValueError("Build modified the reviewed dependency lock")
    result = {}
    for role in ("gateway", "supervisor"):
        context = runtime_context(args, lock, plan, role, builder_id)
        command([engine, "build", "--platform=linux/amd64", "-f", str(context / "Containerfile"),
            "-t", plan["images"][role], str(context)], args.output_dir / (role + "-image-build.log"))
        image_id = capture([engine, "image", "inspect", plan["images"][role], "--format", "{{.Id}}"])
        result[role] = validate_runtime(args, role, image_id)
    receipt = {**plan, "applied": True, "builder_image_id": builder_id, "outputs": result,
               "offline_compilation_passed": True, "compiler_image_reused": compiler_reused, "dependency_cache_seeded": cache_seeded,
               "workspace_cache_discarded": cache_seeded, "sbom_and_scans_approved": False,
               "vendor_support_established": False}
    write(args.output_dir / "native-build.receipt.json", receipt)
    return {"native_images_built_and_packaging_verified": True, "applied": True,
            "offline_compilation_passed": True, "cluster_contacted": False,
            "published": False, "live_acceptance_proven": False, "sbom_and_scans_approved": False}


def repackage(args: argparse.Namespace) -> dict:
    """Refresh public runtime trust without recompiling unchanged audited binaries.

    A new receipt links to the exact verified compilation. Contract/patch changes
    require native-build; this cannot reuse a binary from another installation.
    """
    from identity_demo_setup import private_file, write
    from source_render import certificate_bundle
    from deployment_profile import read_profile
    original = private_file(args.native_build_receipt)
    if not args.native_build_sha256 or digest(original) != args.native_build_sha256:
        raise ValueError('Exact completed native build receipt required')
    prior = read_json(original)
    profile = read_profile(str(private_file(args.installation_profile)))
    lock = read_json(RECIPES/'inputs.lock.json')
    if (prior.get('applied') is not True or prior.get('offline_compilation_passed') is not True
            or prior.get('native_build_contract') != profile.native_build_contract
            or prior.get('build_inputs') != lock or prior.get('target') != lock['target']):
        raise ValueError('Unchanged target, compiler and complete patch inputs required')
    compiled = args.output_dir/'compiled'
    compiled.mkdir(mode=0o700)
    for name in ('openshell-gateway', 'openshell-supervisor', 'builder-packages.txt'):
        source = original.parent/'compiled'/name
        if source.is_symlink() or not source.is_file():
            raise ValueError('Exact original compiled files required')
        if name != 'builder-packages.txt':
            role = name.removeprefix('openshell-')
            output = prior.get('outputs', {}).get(role, {})
            if output.get('packaged_binary_matches') is not True or digest(source) != output.get('binary_sha256'):
                raise ValueError('Compiled binary differs from verified receipt')
        shutil.copyfile(source, compiled/name)
    pem = certificate_bundle(private_file(args.native_ca_bundle)).encode()
    (args.output_dir/'native-public-trust.pem').write_bytes(pem)
    unique = 'identity-demo-'+profile.installation_id+'-'+uuid4().hex[:10]
    plan = {**prior, 'kind': 'native-runtime-repackage-v1', 'applied': False,
        'binary_source_receipt_sha256': args.native_build_sha256, 'compilation_performed': False,
        'native_ca_bundle_sha256': hashlib.sha256(pem).hexdigest(),
        'images': {role: 'localhost/'+unique+'-'+role for role in ('gateway','supervisor')},
        'outputs': {}, 'cluster_contacted': False, 'published': False, 'live_acceptance_proven': False,
        'repackage_helper_sha256': digest(Path(__file__))}
    write(args.output_dir/'native-repackage.plan.json', plan)
    if not args.apply:
        return {'native_repackage_prepared': True, 'compilation_performed': False, 'cluster_contacted': False}
    outputs = {}
    for role in ('gateway', 'supervisor'):
        context = runtime_context(args, lock, plan, role, prior['builder_image_id'])
        command([args.engine, 'build', '--platform=linux/amd64', '-f', str(context/'Containerfile'),
            '-t', plan['images'][role], str(context)], args.output_dir/(role+'-image-build.log'))
        image_id = capture([args.engine, 'image', 'inspect', plan['images'][role], '--format', '{{.Id}}'])
        outputs[role] = validate_runtime(args, role, image_id)
    write(args.output_dir/'native-build.receipt.json', {**plan, 'applied': True, 'outputs': outputs})
    return {'native_images_repackaged': True, 'compilation_performed': False,
            'packaged_binaries_verified': True, 'cluster_contacted': False}
