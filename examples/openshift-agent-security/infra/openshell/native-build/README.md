<!-- SPDX-License-Identifier: Apache-2.0 -->

# Build the native evaluation images

Use the existing setup entry point's `native-build` action. It never contacts
a cluster, pushes an image or changes an installation. The result is a local
development gateway/supervisor pair for **Linux AMD64**. Do not describe patched
outputs as an official OpenShell release or a supported production component.

## Inputs and pins

- Rendered installation profile and `native-public-trust.pem`, containing public
  CA certificates only. Never supply `installation-state.private.json`, an API
  credential, a kubeconfig or a private key to the build.
- The exact upstream archive identified in `inputs.lock.json`. The source URL is
  recorded there; download or obtain it from an approved artifact mirror, then
  supply the local file. A changed archive is refused even for the same commit.
- Five checked-in patches, in recorded order. Upstream and patched Cargo locks
  have **different pinned hashes**: the sender patch deliberately adds its X.509
  dependencies. No implicit dependency updates are allowed during compilation.
- Rust 1.95.0 official multi-architecture base pinned by digest, signed Debian
  snapshot `20260520T000000Z`, and pinned official AMD64 runtime bases.
- Pinned `cargo-auditable` 0.7.7, installed as a build tool with its dependency
  lock. Its compiler wrapper embeds the actual Rust dependency graph into each
  executable for scanner discovery; it adds no runtime service. See the
  [upstream guidance](https://github.com/rust-secure-code/cargo-auditable/tree/v0.7.7).

The builder uses a dated Debian repository to fix package resolution. Only that
historical repository's Release freshness is exempted; package signatures and
HTTPS certificate verification remain enabled. Snapshot age is not security
approval: scan/review the exact resulting builder and runtime packages before
customer release. Record new reviewed pins to remediate vulnerabilities.

## Prepare, then build

Run from the example root (or its private configured copy) with the pinned
operator dependencies installed.
`DEMO_PACKAGE_OUTPUT` must be an existing owner-only directory outside Git.

```bash
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py native-build \
  --source-archive "$DEMO_OPENSHELL_SOURCE_ARCHIVE" \
  --installation-profile "$DEMO_INSTALLATION_PROFILE" \
  --native-ca-bundle "$DEMO_NATIVE_PUBLIC_TRUST" \
  --engine docker --output-dir "$DEMO_PACKAGE_OUTPUT/native-plan-01"
```

Preparation verifies and safely extracts the source, checks/applies all patches,
checks both dependency locks, validates public trust and records the exact build
contract/recipe hashes. It executes no container engine or network operation.
Review the private plan, then repeat with **a new output directory** and `--apply`.
`--engine podman` selects the same command path; engine-specific acceptance must
be recorded rather than inferred from Docker results.

The apply path:

1. Builds the compiler image from the checked-in recipe and records its image ID.
2. Fetches the locked Cargo dependencies in a separate step.
3. Compiles both executables with `cargo auditable build`, networking disabled
   and `--frozen`, using an
   unprivileged UID, read-only root, dropped capabilities and only source/cache/
   output mounts. No host credential directory or container socket is mounted.
4. Creates small runtime contexts containing only the executable, required AMD64
   library, real package-version provenance, licence text, public CA bundle and
   Containerfile. Supervisor installation is at
   `/openshell-supervisor`; gateway installation is at
   `/usr/local/bin/openshell-gateway`.
5. Checks runtime architecture and packaged executable hashes, then runs help
   and version with networking disabled, a read-only root and dropped capabilities.

The initial compiler-image build and dependency fetch need approved connected
artifact access. Offline compilation alone is **not disconnected installation**.
The checked-in recipe is intended for Linux ARM64/AMD64 builder hosts; other
hosts/targets and engine combinations need explicit validation.

## Outputs and acceptance

`native-build.receipt.json` records source/patch/recipe hashes, native endpoint
and audience contract, public CA hash, builder ID, runtime IDs and executable
hashes. `builder-packages.txt` records installed build-package versions. Logs,
source and cache remain in the protected output directory. Failed attempts are
not overwritten; inspect the specific stage log before starting another attempt.
Changing trust or any sender destination/domain requires a new image contract.

Local image IDs are not published registry manifest digests. After review, export
or publish only to the approved repository, record the actual pullable digests,
generate SBOM/provenance/licence/vulnerability results and update the installation
artifact lock. Never substitute a local ID for a cluster-pullable reference.
Installation/scenario acceptance, running executable validation, independent
handoff and support/security decisions remain separate gates. This utility does
not silently replace the currently accepted images.

## Publish through the owned OpenShift build service

For an internal registry, use the existing setup entry point. Do not expose the
shared registry or disable TLS to make a local push work. Prepare the application
namespace first with the [explicit access step](../../../docs/identity-demo-reference.md#prepare-owned-namespaces-and-installer-routing-access).
The caller needs authorized Binary Build, BuildConfig, ImageStream and
NetworkPolicy creation in that owned namespace; the tool grants none of these.

Supply the completed `native-build.receipt.json` and its independently recorded
SHA-256, matching rendered profile, and a private reviewed network JSON:

```json
{
  "schema_version": 1,
  "api_cidrs": ["192.0.2.1/32"],
  "https_cidrs": ["198.51.100.1/32"]
}
```

These example addresses are placeholders. Use exact API service/endpoint host
routes and approved artifact registry/blob-storage destinations. No default
route is accepted. For the tested OpenShift internal-registry path this includes GitHub's published
package-service prefixes from [the official metadata API](https://docs.github.com/en/rest/meta/meta#get-github-meta)
(`https://api.github.com/meta`, `packages`), cluster-verified exact host routes for
`pkg-containers.githubusercontent.com`, and official AWS S3 regional prefixes:
the internal registry can
redirect layer transfers to its external storage. Retain the inventory URL,
retrieval hash and selected prefixes privately. An internal hostname alone does
not prove disconnected delivery. A customer mirror needs its own approved routes.
Do not rely on DNS answers obtained from the installation workstation: the cluster may
resolve the same registry to different valid addresses. The GitHub `packages`
list alone is insufficient for layer downloads: the blob CDN can use addresses
inside other published GitHub ranges. Have the platform owner verify the actual
cluster-side answers and permit only the reviewed host routes on HTTPS.

If a build exposes an omitted destination, retain its failed/stalled evidence and
review that destination before changing access. Do not delete the restrictive
policy, open a default route, rewrite the original publication receipt, or
resubmit an upload with an uncertain outcome. Any separately approved temporary
policy must select only the exact recorded build names, have its UID recorded,
and be conditionally removed after those builds terminate. Record such input
corrections; a recovered build is not an uninterrupted-install claim.

```bash
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py native-publish \
  --native-build-receipt "$DEMO_NATIVE_BUILD_RECEIPT" \
  --native-build-sha256 "$DEMO_NATIVE_BUILD_SHA256" \
  --installation-profile "$DEMO_INSTALLATION_PROFILE" \
  --publication-network "$DEMO_PUBLICATION_NETWORK" \
  --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --output-dir "$DEMO_PACKAGE_OUTPUT/publication-plan-01"
```

Review the plan, then repeat with a new directory and `--apply`. It refuses any
collision before creation and validates an allowlisted context, exact binary/CA
hashes and the checked-in runtime recipe. It creates two new ImageStreams and
Binary BuildConfigs with no triggers, plus one temporary egress policy selecting
only their first build Pods. DNS and internal registry access are narrowly
scoped; reviewed external destinations allow HTTPS only. No runtime policy or
shared resource is edited. Binary upload occurs once per build. An uncertain
submission stops without retry; inspect the exact pending/response receipts and
Build rather than start another copy. Do not rewrite old receipt hashes.

`native-publish-resume` accepts the same plan/hash/kubeconfig/server options as
status below. It verifies all recorded resources first. A confirmed prior Build
is retained only if its recorded UID/specification matches. An upload may start
only when no previous Build exists and its BuildConfig has never allocated a
version. If a pending intent exists, only the explicitly recognized local CLI
JSON-output parser failure permits automatic continuation: a missing/uncertain
transport response requires investigation. Plan first, then `--apply` in a new
directory. Use the **new resumed plan and hash** for later status; old receipts
are never overwritten or relabelled. Binary upload uses `-o name`, followed by
an exact Build read; some clients reject JSON output for binary uploads.

For a genuinely new attempt after terminal failure/cancellation, select a
distinct `--publication-id` (for example `p2`) in both plan and apply. This uses
new BuildConfigs/ImageStreams and policy names, preserving earlier Build history.
It is not a retry of an uncertain upload. Stop only exact owned stalled builds
with the supported `oc cancel-build` command after checking their recorded UIDs;
wait for terminal status and retire their old temporary policy through status.

Use the apply invocation's `publication.plan.private.json` and its recorded hash
to observe the builds in a new private directory on each invocation:

```bash
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py native-publication-status \
  --publication-plan "$DEMO_PUBLICATION_PLAN" \
  --publication-plan-sha256 "$DEMO_PUBLICATION_PLAN_SHA256" \
  --artifacts-file "$DEMO_ARTIFACTS_FILE" \
  --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --output-dir "$DEMO_PACKAGE_OUTPUT/publication-status-01"
```

Status verifies recorded object/Build UIDs, BuildConfig ownership, submitted Build
specification and network policy. A Complete build must report an immutable
manifest digest in the exact output repository. While any build is active,
retain its policy. Once both builds are terminal, repeat status with `--apply`
and a new directory to remove only the exact temporary policy using UID and
resource-version preconditions. Keep the final `publication.receipt.json` and
creation receipts. ImageStreams, BuildConfigs and build history are retained;
later application rollback does not delete them or the prerequisite namespaces.

With `--artifacts-file`, completed status writes a new `artifacts.private.json`:
the other three image pins are retained, the two native pins use actual output
digests, and the native build contract/CA hash and source receipt hashes are
recorded. The input lock is never edited; obsolete native claims are not copied.
Use this lock in a new private render configuration, then render again with the
original generated state. Re-run permission/admission checks against that final bundle.
Publication alone does not prove scanned artifacts, a successful runtime flow,
or a complete customer installation.

## SBOM and vulnerability checks

Use pinned, verified scanner releases and record their versions and vulnerability
database metadata. The initial validation used Syft 1.54.1 and Grype 0.120.1.
For each built image, export an archive, then run the standard tools:

```bash
docker image save --output "$DEMO_IMAGE_ARCHIVE" "$DEMO_NATIVE_IMAGE_ID"
syft scan "docker-archive:$DEMO_IMAGE_ARCHIVE" \
  --select-catalogers +sbom-cataloger \
  -o "spdx-json=$DEMO_IMAGE_SPDX" -o "syft-json=$DEMO_IMAGE_SYFT"
grype "sbom:$DEMO_IMAGE_SYFT" -o json --file "$DEMO_IMAGE_VULNERABILITIES"
grype db status -o json
```

Require Rust packages from `cargo-auditable-binary-cataloger` and the copied
library (`libz3-4` for gateway, `libgcc-s1` for supervisor) at its recorded version.
The explicit SBOM cataloger imports the supplied-library SPDX provenance because
copying a shared library does not update the runtime base's dpkg database.
Check package coverage before interpreting vulnerability counts. A standalone
Cargo.lock scan is a conservative workspace superset, not exact runtime
dependency attribution. Inspect source-only versus runtime dependencies and
unknown licence assertions explicitly.

Preserve raw reports; classify each material match against authoritative vendor
advisories, actual affected code paths and available fixes. Scanner severity,
distribution `no-dsa`/`wont-fix` status and a successful startup check cannot
approve a risk. Do not suppress findings automatically. Designated security reviewers
must decide any required exception; fixed bases/rebuilt binaries require new
packaging, scan and live acceptance evidence.


## Reusing a verified compiler

An optional `--compiler-cache-receipt` plus `--compiler-cache-sha256` reuses the
exact immutable local compiler image from a completed private native-build
receipt. The helper checks its compiler inputs, recipe hashes and local image ID.
Native sources/patches, generated public trust, compilation, packaged executable
hashes and startup checks still run. It does not reuse the old sender binary.
Without this option the normal pinned compiler-image build remains unchanged.
Keep the prior receipt outside Git; its checksum is not a security approval.

If Docker stalls on public registry metadata while host registry access works,
check the Docker credential helper first. Use a reviewed separate private Docker
client configuration for public-image builds and the same local daemon socket;
do not delete or edit the operator's global login configuration. Never disable
TLS. Preloaded OCI archives must preserve the exact locked upstream digests.


An optional `--native-cache-receipt` with `--native-cache-sha256` seeds dependencies
from a completed private build using the same immutable compiler, Cargo lock and
target. The helper copies registry/Git dependencies and Rust dependency artifacts,
but omits Cargo credentials/configuration and discards all OpenShell workspace
binaries, fingerprints and build scripts. Every workspace crate is compiled for
the current source and target contract. The prior build and receipts are retained.
No dependency cache is required for a first installation.

Docker builds require Buildx; this is checked before compilation. A separate
Docker client configuration must retain the approved Buildx plugin search path
as well as the selected local daemon socket. An empty config without its plugin
path can fall back to the obsolete builder, which cannot use `COPY --chmod`.
No operator global credential configuration needs to be changed.

## Docker Desktop credential-helper recovery

Use this optional workaround only when Docker Desktop's credential helper
blocks **public-image** metadata access. First verify the normal Docker context
and approved registry access. A separate private client configuration preserves
global logins and Buildx. It contains no private-registry authentication; do not
use it for builds that require those credentials. Podman users skip this section.

Inputs: the validated local Docker Desktop daemon and private Python environment.
Save the current shell settings so they can be restored afterward:

```bash
DEMO_SAVED_DOCKER_CONFIG="${DOCKER_CONFIG-}"
DEMO_SAVED_DOCKER_HOST="${DOCKER_HOST-}"
DEMO_SAVED_DOCKER_CONTEXT="${DOCKER_CONTEXT-}"
```

```bash
export DEMO_DOCKER_SOCKET="$(docker context inspect --format '{{.Endpoints.docker.Host}}')"
mkdir -m 700 "$DEMO_PRIVATE_ROOT/docker-public"
"$DEMO_PYTHON" - "$DEMO_PRIVATE_ROOT/docker-public/config.json" <<'PYCONFIG'
import json, pathlib, sys
paths = [pathlib.Path.home() / '.docker/cli-plugins',
         pathlib.Path('/Applications/Docker.app/Contents/Resources/cli-plugins')]
directories = [str(p) for p in paths if (p / 'docker-buildx').is_file()]
if not directories:
    raise SystemExit('Install the approved Docker Buildx plugin before continuing')
with pathlib.Path(sys.argv[1]).open('x') as stream:
    json.dump({'auths': {}, 'cliPluginsExtraDirs': directories}, stream)
PYCONFIG
export DOCKER_HOST="$DEMO_DOCKER_SOCKET"
export DOCKER_CONFIG="$DEMO_PRIVATE_ROOT/docker-public"
unset DOCKER_CONTEXT
docker buildx version
```

Use this only with the validated local Docker Desktop daemon. Do not change a
remote daemon's authentication/TLS setup. If any step fails, stop and inspect;
never replace the existing global Docker configuration or disable TLS.

Expected: `docker buildx version` succeeds and public image metadata resolves.
After the affected builds, restore the shell's original Docker settings:

```bash
if test -n "$DEMO_SAVED_DOCKER_CONFIG"; then export DOCKER_CONFIG="$DEMO_SAVED_DOCKER_CONFIG"; else unset DOCKER_CONFIG; fi
if test -n "$DEMO_SAVED_DOCKER_HOST"; then export DOCKER_HOST="$DEMO_SAVED_DOCKER_HOST"; else unset DOCKER_HOST; fi
if test -n "$DEMO_SAVED_DOCKER_CONTEXT"; then export DOCKER_CONTEXT="$DEMO_SAVED_DOCKER_CONTEXT"; else unset DOCKER_CONTEXT; fi
```
