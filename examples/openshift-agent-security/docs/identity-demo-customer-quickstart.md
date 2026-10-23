<!-- SPDX-License-Identifier: Apache-2.0 -->
# Set up the security infrastructure, then the demo

This is a connected, synthetic-data security evaluation on an existing OpenShift
4.21 cluster with Linux AMD64 workers. A platform administrator prepares the
controllers and identity foundation; the demo installer configures the owned
security/application components. The customer supplies approved external images,
registry access and private credentials. OpenShift/cloud provisioning,
disconnected installation and production certification are outside scope.

**Runtime boundary:** the default path runs the coordinator, preparer and
owner-authenticated Jira view on OpenShift. The installation workstation is
needed for setup and maintenance, not for ongoing browser execution. Local CLI
operation remains a compatibility option. See the
[verified boundaries](identity-demo-reference.md#cluster-runtime-hardening-status).
Never put installer kubeconfigs or human passwords in runtime Pods.

**Read this guide in order.** All commands run from the example root,
`examples/openshift-agent-security/` in the parent checkout. Keep one
installation active at a time on the operator host. The following stage order
separates infrastructure readiness from proof that authorization works.

| Stage | Operator | Required outcome |
|---|---|---|
| Workstation and inputs | Delivery engineer | Private environment, approved images and explicit target |
| Security foundation | Platform administrator | Sandbox, Gateway/MCP/Kuadrant and attested SPIRE/CSI/discovery ready |
| Owned security and demo application | Installer | Fresh identity issuers, approval driver, protected adapter and fixtures installed |
| Functional verification | Presenter | Protected reads, exact approved create, denials and replenishment pass |

## What our security layer does

The browser authenticates the person with Keycloak/OIDC and PKCE. The driver
binds a bounded run to that person, workload and project. OpenShell executes the
workload in an isolated sandbox; SPIRE attests the supervisor. The native path
exchanges the delegated user credential in two stages and binds the final token
to the supervisor certificate presented to the protected gateway.

| Control | Configuration and proof |
|---|---|
| User authentication | Fresh Keycloak realm, clients and Analyst/Viewer roles; verify login and Viewer denial |
| Workload identity | SPIRE PSAT node attestation, exact supervisor Pod/container/image registration and CSI; verify native identity and Reader denial |
| Token exchange and mTLS | Matching issuers, audiences and current trust; verify protected read, certificate binding and unauthorized-request rejection |
| Authorization | User + workload + project + original run deadline/cancellation; verify the permission matrix and outside-project HTTP 403 |
| Exact approval | Approve the displayed fields; compare actual Jira fields and audit to that approval |
| Credential custody | Trusted supervisor/adapter inject scoped credentials; verify model/backend credentials never enter the agent or browser |
| Isolation and audit | OpenShell policy, bounded tool loop, one-use identities, no blind write retry; verify containment, cleanup and correlated outcomes |

Human and workload permissions are independent: Analyst + Triage may create
only after exact approval; Viewer or Reader cannot create. Browser session renewal
does not extend a run's original deadline. Model output is untrusted proposal
content, never authority to choose permissions or approve a write.

The reusable layer is identity, exchange, policy, approval, credential custody and
audit. CVE/Jira and synthetic incident/remediation text are demonstration fixtures.
CVE assessment is frozen, not a live scan. Incident/remediation use a real Messages
model. The protected adapter uses scoped service credentials, not native Jira
human delegation; arbitrary agent-to-agent delegation is not claimed. The model
endpoint is supplied privately; embeddings are not required.

## 0. Prepare the operator workstation

The validated installation workstation is Apple Silicon macOS with Python 3.13
(the code requires at least 3.12),
`oc`, Git, Make and a working Docker or Podman engine. The native builder
cross-compiles Linux AMD64 cluster executables. Install Google Chrome for the
automated browser rehearsal. Other installation host combinations need their own acceptance. The two
continuous worker services run on Linux AMD64 OpenShift workers.

From the example root, create an external private workspace and environment:

```bash
export DEMO_PRIVATE_ROOT="$HOME/.local/share/agent-security-demo"
umask 077
mkdir -p "$DEMO_PRIVATE_ROOT"
chmod 700 "$DEMO_PRIVATE_ROOT"
python3 -m venv "$DEMO_PRIVATE_ROOT/venv"
export DEMO_PYTHON="$DEMO_PRIVATE_ROOT/venv/bin/python"
"$DEMO_PYTHON" -m pip install \
  -r tests/identity_demo/requirements-lock.txt \
  -r tests/identity_demo/requirements-operator.txt
```

For Docker Desktop on this macOS host, use a separate client configuration for
these **public native-image builds**. This avoids an unrelated desktop credential
helper blocking registry discovery and leaves normal registry logins unchanged.
Keep Buildx available; the native helper now checks it before compilation.
Podman users skip this block.

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

Acquire the public OpenShell CLI rather than copying an old lab executable.
These commands are for the validated Apple Silicon macOS host. Other pinned CLI
archives are in `infra/openshell/native-build/cli.lock.json`.

```bash
curl --fail --location --proto '=https' --proto-redir '=https' \
  --output "$DEMO_PRIVATE_ROOT/openshell-cli.tar.gz" \
  https://github.com/NVIDIA/OpenShell/releases/download/v0.1.3/openshell-aarch64-apple-darwin.tar.gz
printf '%s  %s\n' \
  2eda3676aa85ff60551b403847090942e119c89f37c84d1635ac166c6b879826 \
  "$DEMO_PRIVATE_ROOT/openshell-cli.tar.gz" | shasum -a 256 --check -
mkdir -m 700 "$DEMO_PRIVATE_ROOT/cli"
tar -xzf "$DEMO_PRIVATE_ROOT/openshell-cli.tar.gz" -C "$DEMO_PRIVATE_ROOT/cli"
chmod 700 "$DEMO_PRIVATE_ROOT/cli/openshell"
export DEMO_OPENSHELL_CLI="$DEMO_PRIVATE_ROOT/cli/openshell"
"$DEMO_OPENSHELL_CLI" --version
```

Stop if the hash or version does not match. The official archive was checked to
contain the single `openshell` executable. Checksums identify bytes; they do not
replace artifact security/licensing review. Keep the downloaded binary outside Git.
The CLI is distinct from the patched gateway/supervisor images built later.

Direct CLI maintenance uses isolated management profiles and loopback ports.
Never terminate another installation's listener or run duplicate workers against
one installation. Browser operation uses the cluster services installed in stage 3.

## 1. Prepare the platform and delivery inputs once

### 1A. Prepare or verify the security foundation

Use a platform-authorized kubeconfig for this section. Use the application
installer account for the next section. Never fall back automatically to admin.
Set `DEMO_PLATFORM_KUBECONFIG` to the platform account’s protected kubeconfig and
`DEMO_SERVER` to the exact API URL. Copy `docs/examples/identity-demo-installation.example.json` outside Git, fill the
actual namespace/domain/storage values, and set `DEMO_SECURITY_PROFILE` to that
private file. It must match the application profile you use later.

The compatibility baseline is `infra/identity-demo/prerequisites.lock.json`:
OpenShift 4.21; ZTWIM 1.1.1; Agent Sandbox 0.9.0; MCP Gateway 0.7.1;
Connectivity Link 1.4.3 and platform-managed Istio 1.27.8. These identify the tested
API baseline, not a promise that another version works or is supported.

Official installation procedures:
[ZTWIM](https://docs.redhat.com/en/documentation/openshift_container_platform/4.21/html/security_and_compliance/zero-trust-workload-identity-manager),
[OpenShift Gateway API](https://docs.redhat.com/en/documentation/openshift_container_platform/4.21/html-single/ingress_and_load_balancing/index),
[Connectivity Link](https://docs.redhat.com/en/documentation/red_hat_connectivity_link/1.4/html-single/installing_connectivity_link/index),
[Agent Sandbox OLM](https://github.com/kubernetes-sigs/agent-sandbox/blob/main/olm/README.md),
[MCP Gateway](https://github.com/Kuadrant/mcp-gateway).
Use the pinned operator packages; do not run upstream main-branch installers,
replace OpenShift-managed CRDs, install a second mesh or blindly approve OLM dependencies.

#### Existing foundation

Inspect installed subscriptions, cluster-scoped identity CRs and consumers first.
Keep existing controllers if the platform owner approves them and the required
APIs are compatible. Do not relabel someone else's identity foundation to pass
an ownership check. An approved attachment must satisfy this implementation's
owner/trust-domain/cluster-name contract. Run the readiness command below.
A successful check neither changes controllers nor proves a fresh installation.

#### Plan missing components on the actual cluster

This path supports an empty owned identity foundation on a cluster that may
already provide shared Sandbox, Gateway/MCP and Kuadrant controllers. Inventory
comes first. Existing platform components remain prerequisites; they are not
adopted, relabelled, upgraded or included in the create manifests.

Copy `docs/examples/identity-demo-security-network.example.json` outside Git.
Supply platform-reviewed **exact API and worker host CIDRs**. API entries include
the external API DNS addresses, the `default/kubernetes` Service ClusterIPs and
its actual EndpointSlice addresses; in-cluster API traffic can use different
addresses from the public API URL. Worker InternalIPs are needed for kubelet
attestation. Inspect these with `oc get service kubernetes -n default -o json`,
`oc get endpointslices -n default -l kubernetes.io/service-name=kubernetes -o json`
and `oc get nodes -o wide`. Account for API/load-balancer or worker changes. Broad ranges, `0.0.0.0/0` and guessed addresses are refused.

```bash
export PYTHONPATH=scripts/identity_demo:tests/identity_demo
export DEMO_SECURITY_PROFILE="$DEMO_PRIVATE_ROOT/security-profile.json"
export DEMO_SECURITY_NETWORK="$DEMO_PRIVATE_ROOT/security-network.json"
export DEMO_SECURITY_PLAN="$DEMO_PRIVATE_ROOT/security-plan-01"
# Copy/edit the profile and network examples privately; chmod 600 both files.
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py security-plan \
  --installation-profile "$DEMO_SECURITY_PROFILE" \
  --security-network "$DEMO_SECURITY_NETWORK" \
  --kubeconfig "$DEMO_PLATFORM_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --output-dir "$DEMO_SECURITY_PLAN"
```

Expected: `security_plan_ready: true`, `blocked: 0` in the classification counts,
and `cluster_changed: false`. Read `security-review.private.json`: it identifies
create/reuse/blocked objects and the exact UIDs of retained prerequisites. Missing
SPIRE APIs can be listed as pending operator installation; this is not readiness.
A Forbidden/unknown inventory, conflicting target, unhealthy package or unreviewed
version stops setup. Resolve it with the platform owner; never remove guards.

**Use only `create-*.json` from this live plan.** The unprefixed files are the
complete offline reference and can contain existing shared resources. With a
conflict, every create list is empty. Re-running planning over a partial owned
installation is not a recovery mechanism; retain its original receipts.

#### Create only the reviewed, missing resources

The function below skips empty lists and checks the exact server. It performs
server admission before each creation; it does not update existing objects.
Keep the terminal output privately. Stop on any failure or partial creation and
inspect actual UIDs before continuing; do not rerun a started create blindly.

```bash
set -e
create_reviewed() {
  "$DEMO_PYTHON" - "$DEMO_SECURITY_PLAN/security-review.private.json" <<'PYCHECK'
import json, sys
if not json.load(open(sys.argv[1]))['ready']:
    raise SystemExit('Security plan blocked; no creation allowed')
PYCHECK
  if "$DEMO_PYTHON" - "$1" <<'PYCOUNT'
import json, sys
raise SystemExit(0 if json.load(open(sys.argv[1]))['items'] else 1)
PYCOUNT
  then
    oc --kubeconfig "$DEMO_PLATFORM_KUBECONFIG" --server "$DEMO_SERVER" \
      create --dry-run=server -f "$1"
    oc --kubeconfig "$DEMO_PLATFORM_KUBECONFIG" --server "$DEMO_SERVER" \
      create -f "$1"
  else
    echo "No new resources in $1; retained prerequisites stay unchanged."
  fi
}
create_reviewed "$DEMO_SECURITY_PLAN/create-namespaces.json"
create_reviewed "$DEMO_SECURITY_PLAN/create-operators.json"
```

Inspect each **new** manual InstallPlan's exact CSVs, versions, permissions and
dependencies against the baseline before approving that particular plan.
`startingCSV` is not a permanent version lock. Do not approve extra dependencies,
a substitute latest version or an upgrade to a retained shared installation.
Wait for the new approved CSV to report `Succeeded` and required CRDs to be
`Established`. If no new operator was planned, retain the verified existing ones.

Then create the remaining reviewed objects in order. The foundation uses
exact-Pod discovery; do not create the operator's broad OIDC discovery operand
alongside it. Existing GatewayClass/Kuadrant entries have empty create lists.

```bash
create_reviewed "$DEMO_SECURITY_PLAN/create-network.json"
create_reviewed "$DEMO_SECURITY_PLAN/create-gateway.json"
create_reviewed "$DEMO_SECURITY_PLAN/create-identity.json"
create_reviewed "$DEMO_SECURITY_PLAN/create-discovery.json"
```

Wait for the SPIRE server and worker agent/CSI components to be ready. The custom
discovery Pod waits for its identity. Generate its registration using the
existing attestation helper, which verifies its actual Pod, image and PSAT parent:

```bash
export IDENTITY_DEMO_CONFIG="$DEMO_SECURITY_PROFILE"
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_discovery_registration.py \
  --kubeconfig "$DEMO_PLATFORM_KUBECONFIG" \
  --output "$DEMO_PRIVATE_ROOT/discovery-registration.json"
oc --kubeconfig "$DEMO_PLATFORM_KUBECONFIG" create -f "$DEMO_PRIVATE_ROOT/discovery-registration.json"
```

For the new **owned** Kuadrant instance, generate TLS patch plans. The helper
refuses a foreign owner or broken Kuadrant → Authorino → Service ownership chain.
Inspect the two JSON patches; they enable the service-CA certificate and contain
UID/resource-version tests. Apply each once; a conflict requires inspection and
a new plan, never removing the tests.

```bash
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py security-tls-plan \
  --installation-profile "$DEMO_SECURITY_PROFILE" \
  --kubeconfig "$DEMO_PLATFORM_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --output-dir "$DEMO_PRIVATE_ROOT/security-tls-plan-01"
oc --kubeconfig "$DEMO_PLATFORM_KUBECONFIG" patch service authorino-authorino-authorization \
  -n kuadrant-system --type=json --patch-file "$DEMO_PRIVATE_ROOT/security-tls-plan-01/authorization-service.patch.json"
oc --kubeconfig "$DEMO_PLATFORM_KUBECONFIG" patch authorino authorino \
  -n kuadrant-system --type=json --patch-file "$DEMO_PRIVATE_ROOT/security-tls-plan-01/authorino.patch.json"
```

For an existing shared Kuadrant, its owner configures/reviews TLS; do not use
this patch path to take ownership. Preserve that owner's controller settings.

#### Verify the foundation before installing the application

```bash
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py security-check \
  --installation-profile "$DEMO_SECURITY_PROFILE" \
  --kubeconfig "$DEMO_PLATFORM_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --output-dir "$DEMO_PRIVATE_ROOT/security-check-01"
```

Expected: `security_configuration_ready: true`. This checks the exact API/TLS,
required served APIs, owned identity foundation, controller generations,
SPIRE/CSI readiness, live exact-Pod discovery registration, Authorino TLS and
current public CA bundles. It exports `service-ca.pem` and `spire-ca.pem` for the
application source configuration. Supply the approved upstream HTTPS CA bundle
separately. Authorization and certificate-bound tool access still require the
functional tests below. Stage-specific `.pending.json`/`.receipt.json` files identify the failed check
without disclosing credentials; preserve them. A forbidden API or failed check stops setup; ask the
platform owner for the documented access rather than bypassing the check.

The aggregate ZTWIM manager can remain NotReady because its unused operator OIDC
operand is absent. Required operands and our exact-Pod discovery are verified
individually; do not create broad discovery just to turn that aggregate green.

**Evidence boundary:** distinguish a fresh owned identity/application install
from an empty-platform controller bootstrap. A retained shared controller was
not installed by this procedure. The current tested boundaries and outstanding
gates are recorded in [verification](verification.json). Retain failed and
successful stage receipts; readiness alone does not prove authorization.

### 1B. Prepare private application inputs

The delivery engineer prepares:

- The reviewed checkout, Python 3.12+, `oc`, the pinned OpenShell CLI and a
  non-admin installer identity with the documented installation/RBAC privileges.
- A protected kubeconfig, exact API URL, three distinct application namespaces,
  identity namespace, route domain, trust domain, storage class and exact API
  host CIDRs. [Profile example](examples/identity-demo-installation.example.json).
- The private source-render JSON and public CA files described in
  [source rendering](identity-demo-reference.md#source-rendering-for-a-fresh-application-installation).
- An approved digest-pinned artifact lock covering all five image roles.
  Native gateway/supervisor images must match this installation's endpoints,
  trust domain **and application CA hash**. Historical internal lab image addresses
  are not a customer distribution registry.
- A protected Messages configuration matching your approved endpoint/model contract.
  Keep its credential outside Git and out of shell arguments. See the
  [inference example](examples/identity-demo-inference.example.json).

Required artifact delivery is explicit; a registry placeholder is not an image:

| Input | How the customer obtains it |
|---|---|
| Jira emulator and CVE runtime | Delivery owner supplies approved immutable image references, pull access and provenance/licence records; these external applications are not bundled |
| Management and exchange Keycloak | Review the pinned registry references in `infra/identity-demo/artifacts.reference.json`; provide required registry entitlement/access |
| Native gateway/supervisor | Build the patched target-specific binaries from pinned public OpenShell source, then publish to the approved registry |
| Operator/operand images | Platform administrator supplies the vendor entitlements and validates the manual OLM dependency plan |
| Model endpoint | Customer supplies a compatible approved Messages endpoint/model and private key-file reference |

Do not declare customer delivery complete until the customer can obtain all of
these. If an external image's rights or source are unresolved, record that release
gate; do not substitute fabricated digests or imply this repo supplies that source.
For the initial render only, the native roles may use the approved upstream base
references from `infra/openshell/native-build/inputs.lock.json`; they are **not**
installation-ready patched images. The native publication step replaces them with
the newly built target-compatible images. All-zero placeholder digests are refused.

Before rendering, configure the fixed provider/image contract. Copy `config/demo-contract.example.json`
outside Git, set approved values and the private model-key file path, then plan:

Validate the generic delivery before adding private provider settings:

```bash
make test PYTHON="$DEMO_PYTHON"
make check PYTHON="$DEMO_PYTHON"
"$DEMO_PYTHON" - "$DEMO_PRIVATE_ROOT/source" <<'PYCOPY'
from pathlib import Path
import shutil, sys
source = Path.cwd().resolve()
target = Path(sys.argv[1]).resolve()
if target.exists() or target.is_relative_to(source):
    raise SystemExit('Choose an unused private working directory outside this checkout')
shutil.copytree(source, target, ignore=shutil.ignore_patterns(
    '.git', '__pycache__', '.pytest_cache', '.ruff_cache', '.venv', 'venv', '.DS_Store'))
target.chmod(0o700)
PYCOPY
cd "$DEMO_PRIVATE_ROOT/source"
"$DEMO_PYTHON" scripts/configure-demo.py \
  --config "$DEMO_PRIVATE_ROOT/demo-contract.json" \
  --output-dir "$DEMO_PRIVATE_ROOT/configuration-plan-01"
```

Review the plan, then configure this private working copy:

```bash
"$DEMO_PYTHON" scripts/configure-demo.py \
  --config "$DEMO_PRIVATE_ROOT/demo-contract.json" \
  --output-dir "$DEMO_PRIVATE_ROOT/configuration-01" --apply
export DEMO_INFERENCE_CONFIG="$DEMO_PRIVATE_ROOT/configuration-01/inference-config.private.json"
make test PYTHON="$DEMO_PYTHON"
"$DEMO_PYTHON" scripts/verify-source.py
```

Expected: the declared source templates are parameterized, both local checks pass
and a protected inference configuration is written. The configuration helper
never reads the model key. Use this exact working copy for subsequent rendering,
native build receipts and coordinator staging. To change the contract later,
start with a new generic working copy; do not bypass template hash guards.

The public-safety scanner remains a release check on the **generic** source and
archive. A working copy configured for a private provider can correctly trigger
it; do not distribute that copy or weaken the scanner to obtain a pass.
The Messages API must support bounded tool use. Keep the existing Jira emulator;
provide its approved immutable image as the `jira_runtime` artifact. No replacement
backend is introduced. The separately supplied workload
image must provide the CVE handoff libraries; see [external inputs](identity-demo-reference.md#required-external-inputs).
The repository does not contain confidential image credentials or claim ownership
of external images. The delivery owner supplies approved registry access/digests.
Use the [runtime interface check](identity-demo-reference.md#supplied-runtime-images)
to catch incompatible images before installation.

The automated browser rehearsal currently requires macOS with Google Chrome
installed at its standard application path. It launches an isolated Chrome
context with normal certificate verification; installing bundled Chromium alone
does not satisfy this runner. Other operator operating systems have not been
validated. For private video recording, install the Playwright recorder:

```bash
"$DEMO_PYTHON" -m playwright install ffmpeg
```

### 1C. Render fresh keys and build the target-bound native images

#### Select application certificate management

Use a platform-approved cert-manager issuer for managed application TLS. The
tested controller API is `cert-manager.io/v1` (controller 1.20.4). Reuse the
installed platform service; this installer never installs or upgrades it.
The issuer must permit ECDSA P-256 server **and client** certificates, internal
Service DNS names, `localhost`, `127.0.0.1` and `::1`. An ordinary public ACME
issuer or OpenShift service CA alone does not satisfy that contract.

For a fresh target, obtain an approved `ClusterIssuer`; a namespaced `Issuer`
must already exist in the receipt-proven owned core namespace. Use the platform's
PKI procedure to prepare it. Do not borrow another namespace's issuer, import a
signing key into worker Pods, or silently create a new shared authority.

Copy the [certificate configuration example](examples/identity-demo-certificates.example.json)
outside Git. Replace its issuer name, kind, **actual resource UID**, and public
CA-file path. Use the same stanza in `DEMO_INSTALLATION_CONFIG` and set
`DEMO_CERTIFICATE_CONFIG` to that private file. The CA file contains approved
public trust, never a signing key. For example, obtain the UID read-only:

```bash
oc --kubeconfig "$DEMO_KUBECONFIG" get clusterissuer "$DEMO_CERTIFICATE_ISSUER" \
  -o jsonpath='{.metadata.uid}{"\n"}'
```

Inputs: an approved issuer and installer kubeconfig. Expected: the exact UID and
an issuer reporting `Ready=True`. If either is missing or incompatible, stop
managed setup and ask the platform owner; do not substitute a different issuer.
Existing installations default to legacy certificate management until explicitly
migrated. The example source configuration marks that compatibility mode; replace
its stanza with the approved managed configuration before rendering a new managed
installation.

Managed rendering requests three standard Certificates: 720 hours, renewal
168 hours before expiry, and `rotationPolicy: Always`. The approved CA is retained
for ordinary renewal. Issued identities, usages, chain and lifetime are checked
before dependent workloads start. A separate public SPIRE trust Secret protects
MCP client authentication; the server's issuer CA never replaces it.

Prepare the private source config from `docs/examples/identity-demo-source-config.example.json`:
copy the verified profile; set the approved artifact-lock path, exported
`service-ca.pem`/`spire-ca.pem`, approved upstream HTTPS CA bundle and exact API
CIDRs. No private key is a public-trust input. Set `DEMO_INSTALLATION_CONFIG`,
`DEMO_PACKAGE_OUTPUT` (an existing 0700 directory), `DEMO_INSTALLER_USER` and the
application account's `DEMO_KUBECONFIG`. Keep platform credentials separate.

```bash
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py render \
  --installation-config "$DEMO_INSTALLATION_CONFIG" \
  --output-dir "$DEMO_PACKAGE_OUTPUT/render-01"
export DEMO_INSTALLATION_STATE="$DEMO_PACKAGE_OUTPUT/render-01/installation-state.private.json"
export DEMO_INSTALLATION_PROFILE="$DEMO_PACKAGE_OUTPUT/render-01/installation-profile.json"
export DEMO_NATIVE_PUBLIC_TRUST="$DEMO_PACKAGE_OUTPUT/render-01/native-public-trust.pem"
```

Expected: fresh application state and source rendered. In managed mode, the
approved issuer generates TLS leaf keys during installation. A nonmatching native
contract is expected before building; never install those initial native image references.
Retain this exact state file for every later render/install—do not regenerate it.

Acquire the exact source URL/hash from `infra/openshell/native-build/inputs.lock.json`
and save the archive outside Git as `DEMO_OPENSHELL_SOURCE_ARCHIVE`. The helper
refuses changed bytes. Plan the build, inspect its source/patch/target/public-CA
hashes, then build in a new directory:

```bash
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py native-build \
  --source-archive "$DEMO_OPENSHELL_SOURCE_ARCHIVE" \
  --installation-profile "$DEMO_INSTALLATION_PROFILE" \
  --native-ca-bundle "$DEMO_NATIVE_PUBLIC_TRUST" \
  --engine docker --output-dir "$DEMO_PACKAGE_OUTPUT/native-plan-01"
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py native-build \
  --source-archive "$DEMO_OPENSHELL_SOURCE_ARCHIVE" \
  --installation-profile "$DEMO_INSTALLATION_PROFILE" \
  --native-ca-bundle "$DEMO_NATIVE_PUBLIC_TRUST" \
  --engine docker --output-dir "$DEMO_PACKAGE_OUTPUT/native-build-01" --apply
```

Expected: completed native receipt, executable hashes and offline packaged runtime
checks. This is a Linux AMD64 build even on the validated Apple Silicon host.

For the tested OpenShift internal-registry publication path, prepare only the
owned application namespaces/access from this exact rendered bundle. The helper
checks ownership and permissions; it does not install application workloads yet:

```bash
export DEMO_STACK_BUNDLE="$DEMO_PACKAGE_OUTPUT/render-01/stack.private.json"
export DEMO_STACK_SHA256="$(shasum -a 256 "$DEMO_STACK_BUNDLE" | awk '{print $1}')"
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py prepare-access \
  --bundle "$DEMO_STACK_BUNDLE" --bundle-sha256 "$DEMO_STACK_SHA256" \
  --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --installer-user "$DEMO_INSTALLER_USER" --output-dir "$DEMO_PACKAGE_OUTPUT/access-plan-01"
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py prepare-access \
  --bundle "$DEMO_STACK_BUNDLE" --bundle-sha256 "$DEMO_STACK_SHA256" \
  --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --installer-user "$DEMO_INSTALLER_USER" --output-dir "$DEMO_PACKAGE_OUTPUT/access-apply-01" --apply
```

Prepare `DEMO_PUBLICATION_NETWORK` from the approved API and registry/blob-storage
CIDRs (shape and review requirements are in the native build reference). Include
GitHub registry **and blob CDN** destinations when using its public images:
`packages` metadata alone does not cover `pkg-containers.githubusercontent.com`.
The platform administrator must verify its DNS addresses from the cluster and
check them against GitHub’s published ranges; use exact reviewed host routes for
the CDN, not broad internet access or addresses copied from an old lab. Include
the internal registry’s regional blob-storage routes too. Keep the metadata source
URLs/hashes and network review privately. Set `DEMO_ARTIFACTS_FILE` to the approved initial five-role lock. Publish through the
existing helper; the native build receipt and every subsequent plan need their
own recorded SHA-256:

```bash
export DEMO_NATIVE_BUILD_RECEIPT="$DEMO_PACKAGE_OUTPUT/native-build-01/native-build.receipt.json"
export DEMO_NATIVE_BUILD_SHA256="$(shasum -a 256 "$DEMO_NATIVE_BUILD_RECEIPT" | awk '{print $1}')"
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py native-publish \
  --native-build-receipt "$DEMO_NATIVE_BUILD_RECEIPT" --native-build-sha256 "$DEMO_NATIVE_BUILD_SHA256" \
  --installation-profile "$DEMO_INSTALLATION_PROFILE" --publication-network "$DEMO_PUBLICATION_NETWORK" \
  --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --output-dir "$DEMO_PACKAGE_OUTPUT/publication-plan-01"
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py native-publish \
  --native-build-receipt "$DEMO_NATIVE_BUILD_RECEIPT" --native-build-sha256 "$DEMO_NATIVE_BUILD_SHA256" \
  --installation-profile "$DEMO_INSTALLATION_PROFILE" --publication-network "$DEMO_PUBLICATION_NETWORK" \
  --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --output-dir "$DEMO_PACKAGE_OUTPUT/publication-01" --apply
export DEMO_PUBLICATION_PLAN="$DEMO_PACKAGE_OUTPUT/publication-01/publication.plan.private.json"
export DEMO_PUBLICATION_PLAN_SHA256="$(shasum -a 256 "$DEMO_PUBLICATION_PLAN" | awk '{print $1}')"
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py native-publication-status \
  --publication-plan "$DEMO_PUBLICATION_PLAN" --publication-plan-sha256 "$DEMO_PUBLICATION_PLAN_SHA256" \
  --artifacts-file "$DEMO_ARTIFACTS_FILE" \
  --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --output-dir "$DEMO_PACKAGE_OUTPUT/publication-status-01" --apply
```

Inspect each plan before its apply. Continue only when both builds are Complete
and status produced a new artifact lock. If still running, observe status in a
**new** output directory; never resubmit an uncertain upload. Update the private
source config's `artifacts_file` to the status-produced lock and retain the same
installation state. The installer refuses unmatched target/CA/build contracts.
See the native build component reference only for cache, publication recovery or
alternate approved registry details; it is not a separate installation path.

All `DEMO_*` variables below are operator-selected absolute **paths or nonsecret
identifiers**, not credentials. Use a private parent directory outside any Git
checkout (`0700`); input files must be `0600`, and the private CLI executable
must be `0700`. Do not source an unreviewed environment file.

## 2. Run the connected installer

Review the [paths-only environment template](examples/identity-demo-inputs.env.example),
copy it to your private directory, and replace its placeholders. Preserve paths
already set by completed stages; do not source an unedited template over them.
The command uses:

| Variable | Required value |
|---|---|
| `DEMO_PYTHON` | Python from the private environment with both pinned requirements files installed |
| `DEMO_INSTALLATION_CONFIG` | Private source-render JSON with profile, artifact-lock path, public CA paths and exact API CIDRs |
| `DEMO_INSTALLATION_STATE` | Original generated state from the render used to build the matching native images |
| `DEMO_KUBECONFIG`, `DEMO_SERVER`, `DEMO_INSTALLER_USER` | Protected credentials path and exact approved target/user identifiers |
| `DEMO_OPENSHELL_CLI` | Private pinned CLI executable |
| `DEMO_PRIVATE_STORAGE` | Existing mode-0700 external parent; each run's output directory must be new |

Install dependencies using the [developer environment guide](../GETTING-STARTED.md#local-environment).
Keep generated keys and credentials outside the checkout. Do not set
`IDENTITY_DEMO_CONFIG` to a profile that has not been rendered yet. The connected
installer selects its newly generated profile for its own stages. From the example root:

```bash
PYTHONPATH=scripts/identity_demo:tests/identity_demo "$DEMO_PYTHON" \
  scripts/identity_demo/identity_demo_setup.py connected-install \
  --installation-config "$DEMO_INSTALLATION_CONFIG" \
  --state-file "$DEMO_INSTALLATION_STATE" \
  --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --installer-user "$DEMO_INSTALLER_USER" --cli "$DEMO_OPENSHELL_CLI" \
  --inference-config "$DEMO_INFERENCE_CONFIG" \
  --output-dir "$DEMO_PRIVATE_STORAGE/connected-install-01" --apply
```

`DEMO_INSTALLATION_STATE` is the private `installation-state.private.json` from
the initial render used to build the native images. The installation config
points at the final matching artifact lock. Each invocation requires a **new**
output directory. Omit `--apply` for a read-only cluster plan. Admission for
absent namespaces is deferred until explicit access preparation; a successful
plan alone is not permission or runtime acceptance.

The connected installer reads the retained `router-default` Service in
`openshift-ingress` and records its UID and internal address before rendering.
It does not change that Service. No previous lab router IP is reused. The
installer needs read access to this prerequisite; if it is absent, incompatible
or differs from an explicitly supplied `ingress_cluster_ip`, stop and have the
platform owner confirm the ingress setup. Offline native-contract rendering can
omit this optional address; use the connected installer to resolve it before
application creation.

The command reuses existing helpers to:

1. Check the exact API, verified TLS, owned foundation, served APIs and storage.
2. Render source with retained keys and refuse unmatched native artifacts.
3. Prepare only the three owned namespaces and explicit installer routing access.
4. Check permissions, collisions and server admission before application creation.
5. Create the application with its UID/fingerprint recovery ledger.
6. Add exact runtime/image-pull grants and the narrow discovery attachment.
7. Wait for controllers and run strict configuration/readiness verification.
8. Refresh owned SPIRE trust, create native workspace records and the synthetic
   SERVICE and OPS projects, then issue a short-lived catalog credential.
9. Write private driver credentials and `operator-paths.private.json` for rehearsal.

No admin fallback, existing application adoption or automatic destructive
rollback occurs. Native runtime permissions include documented cluster-scoped
reads/token review; this is not an entirely namespace-scoped installation.
No existing shared operator, SCC or registry setting is changed.

`application_installation_completed: true` means setup completed.
`functional_scenarios_proven: false` deliberately remains until rehearsal.
The base MCP catalog policy may report that it has no active route before a
registration exists. The installer retains that failed strict-verifier receipt
and accepts only that exact unchanged dormant policy as a setup limitation;
the active bound/tool routes must pass. Functional acceptance must prove
enforcement after registering the tools. All other verification failures stop.

## 3. Start the OpenShift services and automatic pool

Use the **same configured source copy** as stage 1B. Do not install Mac worker
services or manually seed workflow contexts for this path. The cluster preparer
creates the initial eight contexts. The installation workstation may disconnect
after acceptance; browser runs, preparation and Jira viewing remain on OpenShift.

Inputs: the completed application installer, original Namespace creation receipt,
matching native artifacts, source-configuration receipt, approved publication
network and private inference file. Keep administrator and installer credentials
on the workstation. Runtime Pods receive separate role credentials and rotating
projected ServiceAccount tokens, never the installer kubeconfig or user passwords.

Use Bash, stop on errors, and keep every output directory unique:

```bash
set -euo pipefail
export DEMO_CONNECTED="$DEMO_PRIVATE_STORAGE/connected-install-01"
export IDENTITY_DEMO_CONFIG="$DEMO_CONNECTED/02-render/installation-profile.json"
export IDENTITY_DEMO_ARTIFACTS="$("$DEMO_PYTHON" -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["artifacts"])' \
  "$DEMO_CONNECTED/operator-paths.private.json")"
export IDENTITY_DEMO_REGISTRATION_MODE=controller
export PYTHONPATH=scripts/identity_demo:tests/identity_demo
export DEMO_NAMESPACE_RECEIPT="$DEMO_PACKAGE_OUTPUT/access-apply-01/setup.summary.json"
export DEMO_LEDGER="$DEMO_CONNECTED/07-install/creation-ledger.private.json"
export DEMO_BUNDLE="$DEMO_CONNECTED/02-render/stack.private.json"
export DEMO_FIXTURE_CREDENTIALS="$DEMO_CONNECTED/02-render/fixture-credentials.private.json"
export DEMO_RUNTIME_ROOT="$DEMO_PRIVATE_ROOT/cluster-console-01"
mkdir -m 700 "$DEMO_RUNTIME_ROOT"
sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
console_stage() {
  local stage="$1" output="$2"; shift 2
  "$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py console-runtime-prepare \
    --console-runtime-stage "$stage" --output-dir "$output" \
    --installation-profile "$IDENTITY_DEMO_CONFIG" \
    --namespace-creation-receipt "$DEMO_NAMESPACE_RECEIPT" \
    --namespace-creation-sha256 "$(sha256_file "$DEMO_NAMESPACE_RECEIPT")" \
    --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" "$@"
}
console_change() {
  local stage="$1"; shift
  console_stage "$stage" "$DEMO_RUNTIME_ROOT/$stage-plan" "$@"
  # Read the private plan before continuing. No command auto-adopts collisions.
  read -r -p "Reviewed $stage plan for the exact owned installation? [yes] " reply
  test "$reply" = yes
  console_stage "$stage" "$DEMO_RUNTIME_ROOT/$stage" "$@" --apply
}
ledger_args=(--ledger "$DEMO_LEDGER" \
  --console-ledger-sha256 "$(sha256_file "$DEMO_LEDGER")")
console_change permissions
console_change policies --artifacts-file "$IDENTITY_DEMO_ARTIFACTS"
console_change realm-permissions "${ledger_args[@]}" \
  --credentials-file "$DEMO_FIXTURE_CREDENTIALS"
console_change configure "${ledger_args[@]}" \
  --bundle "$DEMO_BUNDLE" --bundle-sha256 "$(sha256_file "$DEMO_BUNDLE")"
certificate_args=()
# Set DEMO_CERTIFICATE_CONFIG only after the approved managed-issuer gate passes.
if test -n "${DEMO_CERTIFICATE_CONFIG:-}"; then
  certificate_args=(--managed-certificate-config "$DEMO_CERTIFICATE_CONFIG")
fi
console_change trust-observation "${ledger_args[@]}" "${certificate_args[@]}"
```

Expected: separate scoped ServiceAccounts, owned identity policies, exact issuer
service-client grants, private HTTPS operator access and matching public trust.
The policies derive supervisor identity from attested Pods. Runtime services have
no SPIRE-server execution or registration-write grant. Planning may defer a
RoleBinding admission check until its reviewed Role exists; apply then checks it.
If ownership, trust, permissions or identity checks fail, stop at that stage and
retain its receipts. Do not reapply a partially completed stage as a new install.

The Namespace receipt above must be the **original creation** from stage 1C,
not the connected install's later no-op access check. For an updated existing UI,
the installer additionally requires its exact immutable ConfigMap creation
receipt; see the optional technical reference. This fresh path needs no adoption.

Install the stable gateway through the existing execution helper. Inputs are the
fresh application credentials, private CLI profile and current discovery credential
from `operator-paths.private.json`; catalog credentials expire after one hour.
If expired, run the existing catalog-only refresh once (do not restart Jira):

```bash
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_adapter_catalog.py \
  --action rotate --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --catalog-credential-file "$DEMO_PRIVATE_ROOT/catalog-new.private.json" \
  --receipt-file "$DEMO_PRIVATE_ROOT/catalog-new.receipt.json"
export DEMO_CATALOG_CREDENTIAL="$DEMO_PRIVATE_ROOT/catalog-new.private.json"
```

Expected: a new scoped private credential with at least 600 seconds remaining.
Stop if rotation is uncertain; retain the receipt and inspect instead of replaying.
For an unexpired initial credential, use the connected installer path below.

```bash
export DEMO_CATALOG_CREDENTIAL="${DEMO_CATALOG_CREDENTIAL:-$DEMO_CONNECTED/catalog-credential.private.json}"
demo_exec() {
  "$DEMO_PYTHON" scripts/identity_demo/identity_demo_execution_setup.py \
    --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
    --credentials-file "$DEMO_FIXTURE_CREDENTIALS" --cli "$DEMO_OPENSHELL_CLI" \
    --cli-config-dir "$DEMO_CONNECTED/cli-config" "$@"
}
demo_exec --action gateway-install --catalog-credential-file "$DEMO_CATALOG_CREDENTIAL" \
  --output-dir "$DEMO_RUNTIME_ROOT/gateway-plan"
# Inspect the exact gateway/policy plan before applying.
demo_exec --action gateway-install --catalog-credential-file "$DEMO_CATALOG_CREDENTIAL" \
  --output-dir "$DEMO_RUNTIME_ROOT/gateway" --apply
console_stage gateway-observation "$DEMO_RUNTIME_ROOT/gateway-observation" \
  --runtime-gateway-receipt "$DEMO_RUNTIME_ROOT/gateway/persistent-gateway.receipt.private.json"
export DEMO_GATEWAY_RECEIPT="$DEMO_RUNTIME_ROOT/gateway-observation/persistent-gateway.receipt.private.json"
```

Expected: stable routing/filter configuration passes observation. It contains no
previous-run grants; user, workload, project, certificate binding, cancellation,
deadline and exact-approval checks still execute on every protected request.
A missing or changed resource blocks execution. Do not bypass that failure.

Build the thin Linux runtime with the **Linux AMD64** `oc` and OpenShell archives
specified by `infra/identity-demo/console-runtime.lock.json` and its CLI lock.
Download those public archives over verified HTTPS to private files, then set
`DEMO_LINUX_OC_ARCHIVE` and `DEMO_LINUX_CLI_ARCHIVE` to their absolute paths.
The builder rejects changed hashes, platforms or packaged versions. Use the
completed **source configuration** receipt from stage 1B, not the cluster
`configure` receipt, for `--runtime-configuration-receipt`.

```bash
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py console-runtime-build \
  --runtime-configuration-receipt "$DEMO_PRIVATE_ROOT/configuration-01/configuration.receipt.json" \
  --oc-archive "$DEMO_LINUX_OC_ARCHIVE" --cli-archive "$DEMO_LINUX_CLI_ARCHIVE" \
  --engine docker --output-dir "$DEMO_RUNTIME_ROOT/runtime-build" --apply
export DEMO_RUNTIME_BUILD="$DEMO_RUNTIME_ROOT/runtime-build/console-runtime-build.receipt.json"
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py console-runtime-publish \
  --runtime-build-receipt "$DEMO_RUNTIME_BUILD" --runtime-build-sha256 "$(sha256_file "$DEMO_RUNTIME_BUILD")" \
  --installation-profile "$IDENTITY_DEMO_CONFIG" --publication-network "$DEMO_PUBLICATION_NETWORK" \
  --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --output-dir "$DEMO_RUNTIME_ROOT/runtime-publication-plan"
# Review the publication plan, then run the same command with a new output path and --apply:
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py console-runtime-publish \
  --runtime-build-receipt "$DEMO_RUNTIME_BUILD" --runtime-build-sha256 "$(sha256_file "$DEMO_RUNTIME_BUILD")" \
  --installation-profile "$IDENTITY_DEMO_CONFIG" --publication-network "$DEMO_PUBLICATION_NETWORK" \
  --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --output-dir "$DEMO_RUNTIME_ROOT/runtime-publication" --apply
export DEMO_RUNTIME_PLAN="$DEMO_RUNTIME_ROOT/runtime-publication/publication.plan.private.json"
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py native-publication-status \
  --publication-plan "$DEMO_RUNTIME_PLAN" --publication-plan-sha256 "$(sha256_file "$DEMO_RUNTIME_PLAN")" \
  --artifacts-file "$IDENTITY_DEMO_ARTIFACTS" \
  --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --output-dir "$DEMO_RUNTIME_ROOT/runtime-publication-status" --apply
```

Expected: a completed runtime build, exact packaged-tool checks and publication
receipt with `published: true` and `runtime: Complete`. Observe an unfinished
build again in a **new** status directory; never resubmit an uncertain upload.
Use the completed status receipt path below if a later observation was required.
This tested helper publishes to the owned OpenShift internal registry. An
alternate customer distribution registry needs separately verified publication;
internal lab references are not a customer artifact-access entitlement.

```bash
export DEMO_CONSOLE_CONFIG="$DEMO_RUNTIME_ROOT/configure/setup.summary.json"
export DEMO_RUNTIME_PUBLICATION="$DEMO_RUNTIME_ROOT/runtime-publication-status/publication.receipt.json"
console_change workloads \
  "${certificate_args[@]}" \
  --installation-config "$DEMO_INSTALLATION_CONFIG" \
  --artifacts-file "$IDENTITY_DEMO_ARTIFACTS" --credentials-file "$DEMO_FIXTURE_CREDENTIALS" \
  --console-configuration-receipt "$DEMO_CONSOLE_CONFIG" \
  --console-configuration-sha256 "$(sha256_file "$DEMO_CONSOLE_CONFIG")" \
  --runtime-publication-receipt "$DEMO_RUNTIME_PUBLICATION" \
  --runtime-publication-sha256 "$(sha256_file "$DEMO_RUNTIME_PUBLICATION")" \
  --runtime-gateway-receipt "$DEMO_GATEWAY_RECEIPT" \
  --console-management-ca "$DEMO_CONNECTED/02-render/runtime-gateway-ca.pem" \
  --console-catalog-credential "$DEMO_CATALOG_CREDENTIAL" \
  --console-trust-observation-receipt "$DEMO_RUNTIME_ROOT/trust-observation/sender-trust.receipt.json" \
  --inference-config "$DEMO_INFERENCE_CONFIG"
export DEMO_WORKER_RECEIPT="$DEMO_RUNTIME_ROOT/workloads/setup.summary.json"
# Opt in to public CA refresh before enabling the pool. Both workers must be idle.
console_change update-workloads --refresh-sender-trust --enable-public-trust-refresh \
  "${ledger_args[@]}" --credentials-file "$DEMO_FIXTURE_CREDENTIALS" \
  --console-configuration-receipt "$DEMO_CONSOLE_CONFIG" \
  --console-configuration-sha256 "$(sha256_file "$DEMO_CONSOLE_CONFIG")" \
  --console-worker-receipt "$DEMO_WORKER_RECEIPT" \
  --console-worker-sha256 "$(sha256_file "$DEMO_WORKER_RECEIPT")" \
  --runtime-publication-receipt "$DEMO_RUNTIME_PUBLICATION" \
  --runtime-publication-sha256 "$(sha256_file "$DEMO_RUNTIME_PUBLICATION")" \
  --runtime-gateway-receipt "$DEMO_GATEWAY_RECEIPT"
export DEMO_WORKER_RECEIPT="$DEMO_RUNTIME_ROOT/update-workloads/setup.summary.json"
console_change automatic-enable \
  --console-configuration-receipt "$DEMO_CONSOLE_CONFIG" \
  --console-configuration-sha256 "$(sha256_file "$DEMO_CONSOLE_CONFIG")" \
  --console-worker-receipt "$DEMO_WORKER_RECEIPT" \
  --console-worker-sha256 "$(sha256_file "$DEMO_WORKER_RECEIPT")"
```

Expected: one coordinator and one preparer Deployment, separate state PVCs,
role credentials, management profiles and durable leases. The activation helper
waits for health and checks the actual projected API identities and lease owners.
Automatic preparation then targets **eight ready / twelve managed** contexts.
An available workflow may start while another context is prepared; only one demo
executes at a time. Capacity or quarantines may leave preparation waiting.
Do not run a second local worker against the same installation.

The idle `update-workloads` step above enables public CA refresh on this owned
installation. It needs the same creation ledger and completed worker/publication
receipts; no human or installer credential enters a runtime Pod. Expected: two
public-only trust Secrets, a narrowly scoped Role and enforced admission policy,
and issuer HTTPS reload every 60 seconds. The serving-key Secret stays unreadable
to workers. Istio uses its separate `-cacert` Secret through SDS. Routine SPIRE CA
changes then pause admission, update only these public trust copies, wait through
the projection/reload interval (210 seconds, plus readiness checks), and recheck before accepting
another run. Workload identities, permissions and run deadlines do not change.

If this maintenance fails, preserve its pending receipts and stopped-worker
state. Inspect the exact failed step; do not rerun an uncertain operation or
restore an older database. Existing installations keep manual trust behavior
until this guarded opt-in succeeds. See Operations for recovery.

On activation failure, preserve all pending receipts and inspect the reported
stage. Do not force-delete leases, clear quarantines or overwrite databases.
Follow [Operations](identity-demo-console.md) for status, restart and recovery.

## 4. Verify and present the demo

Open the driver HTTPS Route from the rendered profile. Sign in using the fresh
private Analyst/Viewer credentials. Settings should report a healthy coordinator,
automatic preparation and verified workflow availability. The authenticated
**Access Jira** view runs in the console; no laptop preview service is needed.

After enabling automatic mode and opening the UI, run the required acceptance
scenarios below. Consumed slots replenish automatically. The optional
[technical reference](identity-demo-reference.md#operator-cli-reference) contains
CLI provisioning and automated acceptance commands:

| Workflow | User / workload | Required result |
|---|---|---|
| CVE, TEST | analyst / triage | One verified approved create |
| CVE, TEST | viewer / triage | Denied even after approval |
| CVE, TEST | analyst / reader | Denied even after approval |
| Remediation, SERVICE | analyst / triage | Actual inference and one verified approved create |
| Remediation, SERVICE | viewer / triage | Actual inference and denied create |
| Incident triage, OPS | analyst / triage | Actual investigation reads/inference, TEST denied and one verified approved create |

The pool maintains two verified unused contexts for each of the four workflow/role
slots. After consuming a context, confirm its automatic replacement becomes ready
and a subsequent run succeeds. No manual batch refill is required. Incident triage's
controlled TEST request must return HTTP 403 with no TEST data. It demonstrates
project isolation, not an agent independently deciding to attack another project.
The final verification record separates this rebuild from prior installations.

Retain each 14-check native result, correlated audit and backend count evidence.
Automatic mode retires each exact consumed context after verified cleanup. It
preserves existing workspaces, durable history and consumed-identity records; only
newly recorded disposable synthetic scratch is eligible for guarded deletion. Inference failure, renewal/reconnect and preservation
checks remain part of the [acceptance procedure](identity-demo-reference.md).
The CVE presentation uses frozen assessment input; it is not autonomous CVE
analysis. Incident and Remediation perform real inference with the configured model.

Use the [console operations guide](identity-demo-console.md) for the live presentation.
Identify recorded snapshots clearly; do not present them as a live gateway dashboard.

## 5. If setup stops

Keep the entire private output directory. Stage `.pending.json`, `.receipt.json`
and `.private.log` files identify where it stopped without printing raw failure
bodies. A timeout or failed mutation is **not** automatically retried. Inspect
live owned resources and use the existing [resume/recovery procedure](identity-demo-reference.md)
with the exact bundle hash and creation ledger. Do not rerun the whole command
over an occupied application or delete namespaces to bypass collision checks.

For the specific case where stages through `08-runtime-apply` completed and
only the read-only `09-discovery-plan` failed, use the bounded continuation:

```bash
PYTHONPATH=scripts/identity_demo:tests/identity_demo "$DEMO_PYTHON" \
  scripts/identity_demo/identity_demo_setup.py connected-install \
  --installation-config "$DEMO_INSTALLATION_CONFIG" \
  --resume-installation "$DEMO_PRIVATE_STORAGE/connected-install-01" \
  --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --installer-user "$DEMO_INSTALLER_USER" --cli "$DEMO_OPENSHELL_CLI" \
  --inference-config "$DEMO_INFERENCE_CONFIG" \
  --output-dir "$DEMO_PRIVATE_STORAGE/connected-resume-plan-01"
```

Review the plan, then repeat with a new output directory and `--apply`.
Continuation verifies stage/log hashes, unchanged source and configuration,
exact created UIDs/fingerprints, runtime grants and idle durable state. It reuses
the retained keys and never replays completed creation. It refuses any started
later mutation, drift, incomplete creation, active run or uncertain write.
Other checkpoints require the explicit recovery procedure; do not alter receipts
or use this flag to skip a failed mutation.

The application ledger is at `07-install/creation-ledger.private.json`. Namespace
access, runtime grants and discovery attachment have their own receipts;
application cleanup is not a complete platform uninstall. Preserve Secrets,
PVCs, database/history, keys and workspace state. A configuration bundle is
not a full backup. Production backup/restore, image approval, support and
independent customer installation review remain release requirements.
