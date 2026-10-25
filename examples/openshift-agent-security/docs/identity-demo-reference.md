<!-- SPDX-License-Identifier: Apache-2.0 -->
# Technical reference

Start with [Setup](identity-demo-customer-quickstart.md); use
[Operations](identity-demo-console.md) for daily tasks. This optional reference
contains lower-level commands, security boundaries and release evidence.

| Topic | Reference |
|---|---|
| Design and permission model | [Architecture](#architecture-and-permission-boundaries), [permission matrix](#permission-matrix), [custody](#custody-and-lifecycle) |
| Staged installation and backup | [Deployment](#deployment-and-recovery-reference), [recovery](#application-data-backup-and-restart-validation) |
| Direct CLI acceptance | [Operator CLI](#operator-cli-reference), [security probes](#read-only-replay-certificate-renewal-and-containment-acceptance) |
| Safe maintenance | [Context retirement](#retire-used-contexts-safely), [worker updates](#updating-the-isolated-cluster-workers) |
| Delivery and verified scope | [Release gates](#open-release-gates), [verification boundary](#cluster-runtime-hardening-status) |
| Existing workstation workers only | [Legacy local runtime](#legacy-local-runtime-compatibility) |

## Architecture and permission boundaries

The browser authenticates the human with Keycloak using OIDC and PKCE. The driver
registers a bounded run linking that user to one approved workload identity and
project. The coordinator runs in its own OpenShift Deployment and orchestrates
the agent inside the exact registered OpenShell sandbox. SPIRE attests the
sandbox supervisor and supplies its short-lived workload identity.

The native path exchanges the user's delegated credential in two stages. The
final access token is bound to the supervisor certificate presented on the MCP
connection. The protected path checks issuer/signature, audience, certificate
binding, workload, user, project, run expiry/cancellation and exact consent.

The agent can read permitted Jira context and propose content. It cannot choose
its identity, permissions, credential, approval or write authority. The LLM sees
bounded tool feedback; all model output and Jira content are untrusted inputs.
The trusted coordinator performs an approved write once through the gateway and
protected adapter. The adapter uses scoped backend service credentials. These are
not native Jira per-user delegated credentials.

The console's moving diagram projects recorded milestones and tool responses.
It is a logical architecture view, not a packet capture. Agent activity shows
observable model turns and reads; it does not expose private model reasoning.

Relevant design references are [certificate-bound OAuth tokens (RFC 8705)](https://www.rfc-editor.org/rfc/rfc8705.html),
[MCP authorization](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
and [Kubernetes projected ServiceAccount tokens](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/).
Implementation conformance and vendor support still require the recorded release reviews.

## Permission matrix

| Human role | Workload | Approved Jira create |
|---|---|---|
| Analyst | Triage | Allowed only for the run's project and exactly approved fields |
| Analyst | Reader | Denied by workload permission |
| Viewer | Triage | Denied by human permission |
| Viewer | Reader | Denied; verify the earliest enforcing boundary in target acceptance |

Assessment/read access and write access are distinct. The CVE workload dropdown
does not change the signed-in user's Keycloak role. Incident OPS access does not
imply TEST access. Its outside-project request is a deliberate security probe;
it is not autonomous evidence that the model decided to cross a boundary.

## Custody and lifecycle

- Private keys, model keys, backend credentials and operator credentials stay
  outside the browser and unprivileged agent. Native provider header injection
  resolves only the configured endpoint's opaque credential handle.
- Context identities are single-use. The preparer allocates new contexts only
  within registered workflow/project/role slots, under durable reservations.
- The original run deadline does not extend when the browser session refreshes.
  Session activity is bounded by idle, absolute/Keycloak and revocation limits.
- A write with an uncertain outcome stops for review; it is never retried blindly.
- Cleanup restores run-specific routing/provider state, closes authorization and
  retires exact identities. Durable audit, Jira data and retained PVCs are separate
  from temporary execution cleanup.

## Deployment boundary

The setup guide prepares the security foundation before the application.
On the recorded target, the owned SPIRE operator, CSI, identity services and
exact-Pod discovery were installed fresh; compatible shared Sandbox and
Gateway/MCP/Kuadrant/Authorino controllers were retained without changes.
Installing every shared controller on an empty platform remains unproved.
The application installer creates only approved owned resources with collision
checks and per-object recovery ledgers. Some runtime
and registration grants are cluster-scoped and need platform authorization.

The coordinator and preparer run on OpenShift with separate scoped ServiceAccounts,
projected tokens, persistent state and execution leases. Browser runs, automatic
preparation and the authenticated Jira view work with local workers stopped.
Local CLI/worker operation remains an explicit compatibility mode. This is a
connected evaluation with development patches; review the
[release gates](#open-release-gates) before customer delivery.

## Deployment and recovery reference

For the ordered connected setup command, start with the
[customer quickstart](identity-demo-customer-quickstart.md). The staged commands
below remain the recovery and inspection interface.

The connected installer creates owned application components on a prepared
OpenShift platform. OpenShift, RHOAI and shared controllers are platform-team
prerequisites; this installer does not install or upgrade them. Native
images must match the selected endpoints, identity domain and generated public CA;
a new namespace alone does not make a compiled sender portable.
Review [scope and release requirements](identity-demo-reference.md).

## Deployable stack

| Component | Installed/configured by | Boundary |
|---|---|---|
| Owned core and triage/reader namespaces, namespaced RBAC/network policies | New stack bundle installer | Creation-ledger UIDs and ownership checks; shared prerequisites are excluded |
| Original management Keycloak and development exchange Keycloak | Source-rendered deployment/realm definitions and fresh keys | Separate issuers; synthetic users, hydrated client secrets/service-account roles; no old database imported |
| OpenShell gateway, storage and TLS/configuration | Source-rendered runtime definitions and target-bound native images | Pinned development images; encryption/TLS inputs private; shared Sandbox controller prerequisite |
| Strict Jira emulator and protected adapter | Current desired definitions and repository source | Fresh synthetic seed; adapter mediates credentials, not native human delegation |
| Authenticated driver and persistent run/action/audit database | Current source/config and new driver PVC | New installation starts with no execution-context mappings; old database/history is not reset or imported implicitly |
| Gateway, routes and policies | Owner-controlled CRs in bundle; existing controllers reconcile generated resources | Gateway/MCP extensions are exported; controller-generated broker/authorizer workloads are regenerated, not adopted or copied |
| New triage/reader identities and SERVICE/OPS projects | Existing execution setup helper | Native IDs, exact SPIRE registration, additive mappings; safe exact-context retirement |
| Model provider, approval and protected action | Existing rehearsal helpers | Temporary per-run provider, endpoint-scoped key resolution; no extra model service |
| Presentation/evidence | Authenticated console and run-scoped Jira view on OpenShift | Durable owner-scoped history; local preview is optional legacy compatibility |

The supported source path renders new desired definitions and uses create-only
operations with a private recovery ledger. The snapshot path is for a reviewed
existing owned installation; do not replay early bootstrap or migration helpers
over a persistent stack. Current source and native build inputs remain pinned.

## Shared prerequisites and ownership

The tested version baseline is in `infra/identity-demo/prerequisites.lock.json`: OpenShift 4.21, ZTWIM 1.1.1, Sandbox 0.9.0, MCP Gateway 0.7.1, RHCL 1.4.3 and platform-managed Istio 1.27.8. This records compatibility evidence, not vendor support. The setup guide contains the guided platform-administrator procedure; its create/reuse/blocked plan distinguishes fresh owned resources from retained prerequisites.

- Approved OpenShift/RHOAI, ingress/DNS/time, an approved configured storage class and registry access.
- Existing Agent Sandbox controller, Gateway/Authorino/Kuadrant/MCP APIs and controllers, including the approved `openshift-ai-inference` GatewayClass.
- Reviewed ZTWIM/SPIRE/CSI and PSAT node attestation; the foundation includes
  cluster-scoped singletons/CRDs, SCCs and node components. It is not namespace-local.
- OpenShift service-CA controller regenerates the four application TLS Secrets from the rendered Service annotations. Gateway/mesh controllers regenerate their own serving resources and CA ConfigMaps. These are not copied as owned application objects.
- Explicit approved runtime, requester and registration grants. Application
  install never changes shared infrastructure or silently grants its caller
  permissions. In each fresh namespace, check the actual installer's create/get
  privileges for every selected API before creating application objects; the
  reference namespace's Gateway RoleBinding does not carry over. Namespace
  administration alone may omit Gateway create permission. A platform-authorized
  namespace Role/Binding is sufficient for that gap; no admin login is required.
  Preflight requires the foundation
  and required APIs; server dry-run records actual admission/permission results.
- Assign platform/native security and application reviewers before release.
  Helper success does not grant security, support or distribution approval.

## Private inputs

Retain the private evidence, credentials and operator profile in a durable directory
outside Git. Use [the path template](examples/identity-demo-inputs.env.example) and
[Messages template](examples/identity-demo-inference.example.json). Supply explicit
kubeconfig/API, fixture credentials, native CLI/profile, driver credentials,
catalog credential and approved Messages provider key by private file path. Expiring credentials still
need refresh. Native gateway/supervisor patches and exact TLS/realm targets must match
the selected rendered profile and retained state.

Retain original receipts privately and do not overwrite failed attempts. Follow
the [developer environment](../GETTING-STARTED.md#local-environment); virtualenvs must be recreated for the
host using both pinned requirements files. Approved offline wheels configure
operator dependencies only, not disconnected cluster installation. Never source
an unreviewed shell file.

## Preflight → snapshot → plan → install → verify

Fresh installation uses source rendering through the quickstart. Snapshot
commands below are optional recovery tools for an existing owned installation;
no prior deployment snapshot is required for fresh setup.

### Source rendering for a fresh application installation

The `identity_demo_setup.py render` action works offline.
It reads versioned templates and current repository Python sources; it does not
need an export of the running demo. Source rendering is part of the proven
connected application installer. A render alone does not establish installation
or runtime acceptance; follow the quickstart through its verification gates.
Use the snapshot workflow below only for an existing owned installation.

Prepare a private JSON file outside Git with these fields:

```json
{
  "schema_version": 1,
  "profile": { "...": "use every field in the installation-profile example" },
  "artifacts_file": "/absolute/private/path/artifacts.json",
  "public_trust": {
    "service_ca": "/absolute/private/path/service-ca.pem",
    "spire_ca": "/absolute/private/path/spire-ca.pem",
    "upstream_ca_bundle": "/absolute/private/path/approved-upstream-roots.pem"
  },
  "kubernetes_api_cidrs": ["192.0.2.1/32"]
}
```

The example addresses are placeholders. Copy the complete profile from
[the profile example](examples/identity-demo-installation.example.json), select
distinct installation IDs/namespaces, and supply the actual public CA roots and
API endpoint host routes. Never substitute a broad network CIDR. Set the input
file to mode `0600`. Use [the complete source-config example](examples/identity-demo-source-config.example.json).
Image inputs must cover all five roles in `infra/identity-demo/artifacts.reference.json`
with approved actual registry digests; its zero-digest example values are deliberately
nondeployable. The separately supplied CVE workload image is configured in the source
contract before this render step.

```bash
mkdir -m 700 -p "$DEMO_PACKAGE_OUTPUT"
PYTHONPATH=scripts/identity_demo:tests/identity_demo "$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py \
  render --installation-config "$DEMO_INSTALLATION_CONFIG" \
  --output-dir "$DEMO_PACKAGE_OUTPUT/render-01"
```

Rendering creates a private bundle, keys/state, synthetic credentials and a
nonsecret runtime profile. Preserve the state file securely; use `--state-file`
when rendering the same installation again. Fresh rendering without that file
creates different keys/passwords and is not an upgrade. Changed trust roots or
expired/damaged generated TLS state require explicit rotation; rendering refuses
to reuse them silently. The generated evaluation CA/leaf validity is 365/30 days;
this is the legacy compatibility mode. Opt-in managed mode uses an approved
cert-manager issuer for the three application leaves; see the Setup guide's
[certificate prerequisites](identity-demo-customer-quickstart.md#1-approve-the-platform).
Production PKI approval and unattended CA rollover are not implied.

Use the setup entry point's
[`native-build` action](../infra/openshell/native-build/README.md) to prepare and
build the target-bound gateway and supervisor from pinned source and checked-in
recipes. Supply the rendered profile and public native CA bundle, never private
generated state. It builds locally only; published image digests, artifact scans
and live acceptance remain explicit later steps.

Use the same setup entry point's `native-publish` and
`native-publication-status` actions for guarded OpenShift binary-build publication
when the registry is internal. See the
[publication procedure](../infra/openshell/native-build/README.md#publish-through-the-owned-openshift-build-service).
They create new owned build resources, record output manifest digests and remove
their temporary build-only network policy after terminal builds. They never
expose or reconfigure the shared registry. Publication does not approve scans or
prove the deployed executable; retain the later runtime/scenario checks.

For operator commands against a new installation, set `IDENTITY_DEMO_CONFIG` to
the rendered absolute profile path. The new application mounts that profile
read-only. Portability of every historical diagnostic helper is not yet complete;
do not run a legacy command against a new installation without checking its
scope. Native sender images must be rebuilt for the exact host, token endpoint,
audiences and trust domain. The artifact lock must record the matching
`native_build_contract`; installation refuses an unmatched source bundle.

The source templates create a `fixture-jira-data` PVC and independent credentials.
A fresh installation does not import another installation's issue history.
Cluster-wide workspace/token-review grants, SPIRE registrations, shared
controllers and their installation still require their own explicit preparation.

After reviewing the render result, set `DEMO_STACK_BUNDLE` to its
`stack.private.json`, `DEMO_STACK_SHA256` to its recorded `bundle_sha256`, and
`DEMO_INSTALLATION_PROFILE` to its `installation-profile.json`. Require
`native_build_contract_matches: true` before installation. Continue with the
permission, admission, install and runtime-permission commands below; a snapshot
is unnecessary for this source path. Then prepare discovery access and native
workspace records before provisioning execution contexts.

### Attach the fresh issuer to existing owned discovery

A source installation does not inherit discovery ingress from the reference
namespace. The `discovery-access` action checks ownership of both namespaces,
the discovery Deployment and the fresh issuer Deployment. It prepares one new
installation-specific NetworkPolicy in the owned identity namespace, allowing
only the owned upstream Keycloak Pods in the exact fresh core namespace to
reach discovery on TCP 8443. Existing policies, identities and controllers are
never modified. If the foundation is managed by another owner, request that
owner's equivalent narrow attachment; do not remove ownership checks.

```bash
IDENTITY_DEMO_CONFIG="$DEMO_INSTALLATION_PROFILE" \
PYTHONPATH=scripts/identity_demo:tests/identity_demo "$DEMO_PYTHON" \
  scripts/identity_demo/identity_demo_setup.py discovery-access \
  --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --bundle "$DEMO_STACK_BUNDLE" --bundle-sha256 "$DEMO_STACK_SHA256" \
  --output-dir "$DEMO_PACKAGE_OUTPUT/discovery-access-plan-01"
```

Review the private plan, then repeat with a new output directory and `--apply`.
Existing exact attachment is accepted; drift or an ownership collision is
refused. Preserve the separate created UID/resource-version receipt. Application
cleanup does not delete this attachment; retirement requires inspection and
conditional deletion of that exact owned policy. Prove HTTPS discovery and
delegation in the fresh scenario; TCP reachability alone is insufficient.

### Snapshot an existing owned installation

Run from the example root. Commands write private artifacts into new directories
under an existing private parent. They never print Secret values or API error bodies.

```bash
export DEMO_PACKAGE_OUTPUT="$DEMO_PRIVATE_STORAGE/package"
mkdir -m 700 -p "$DEMO_PACKAGE_OUTPUT"
PYTHONPATH=scripts/identity_demo:tests/identity_demo "$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py \
  preflight --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --output-dir "$DEMO_PACKAGE_OUTPUT/preflight-01"

# Read-only capture of the quiescent accepted owned stack, not a data backup.
PYTHONPATH=scripts/identity_demo:tests/identity_demo "$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py \
  snapshot --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --credentials-file "$DEMO_FIXTURE_CREDENTIALS" \
  --output-dir "$DEMO_PACKAGE_OUTPUT/snapshot-01"
export DEMO_STACK_BUNDLE="$DEMO_PACKAGE_OUTPUT/snapshot-01/stack.private.json"
# Set this to bundle_sha256 from snapshot-01/setup.summary.json after reviewing it.
export DEMO_STACK_SHA256="<recorded-and-reviewed-sha256>"

PYTHONPATH=scripts/identity_demo:tests/identity_demo "$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py \
  plan --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --bundle "$DEMO_STACK_BUNDLE" --bundle-sha256 "$DEMO_STACK_SHA256" \
  --server-dry-run --output-dir "$DEMO_PACKAGE_OUTPUT/plan-01"
```

The bundle contains private Secrets and complete synthetic realm configuration;
keep it 0600 and never commit/share it as a public manifest. It records source,
dependency and patch hashes and pinned container images. Namespace UID ranges are
adapted only within the recorded SCC allocation range when recreating a namespace.
A copied configuration does not establish image provenance, an SBOM or customer acceptance.

Bundles retain exact source paths and hashes. Capture a new bundle after source
changes; never rewrite an earlier receipt or remove a hash guard to reuse it.

Planning reports occupied resources. Owned existing namespaces are prerequisites
and are not changed; existing Secrets/PVCs/controllers are never adopted or replaced.
Server dry-run performs create admission checks for absent objects only. Occupied objects are reported as collisions and are not replaced, even in dry-run; their complete fresh admission remains pending an empty target.
Installation refuses collisions and checks every remaining create permission
before writing any resource. Its private `installation-permissions.json`
identifies denied scopes; `resume` checks only the resources still to create.

### Prepare owned namespaces and installer routing access

For a new target, use the existing setup entry point to prepare the three owned
application namespaces and explicit installer access before installing the
application. This is a separate privilege-bearing operation, never an automatic
fallback inside `install`. Use your exact authenticated non-admin username:

```bash
PYTHONPATH=scripts/identity_demo:tests/identity_demo "$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py \
  prepare-access --installer-user "$DEMO_INSTALLER_USER" \
  --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --bundle "$DEMO_STACK_BUNDLE" --bundle-sha256 "$DEMO_STACK_SHA256" \
  --output-dir "$DEMO_PACKAGE_OUTPUT/access-plan-01"
```

Review the plan, then repeat with a new output directory and `--apply` where
authorized. The authenticated username must match. It creates absent owned
namespaces and one core-namespace Role/RoleBinding for that user: create
Gateways/HTTPRoutes, and get/update/patch/delete only the routing object names
in the bundle. Kubernetes cannot restrict `create` by resource name; that
permission applies to those two APIs throughout this dedicated core namespace.
It grants no ServiceAccount, group, cluster-wide or foundation access. RBAC
escalation/binding checks still apply; denial never triggers an admin login.

Existing foreign namespaces or differing grants are refused before creation;
matching owned prerequisites are read without modification. Missing-namespace
and missing-role admission checks are deferred in plan mode and run before each
actual create. Keep the private per-object pending/UID/fingerprint receipts.
An uncertain create stops immediately: inspect the object and receipt before
another invocation. These prerequisite resources have separate receipts and
are retained by application rollback. Do not delete their namespaces to remove
the installer grant. Native runtime grants and discovery access remain separate
explicit steps below.

**Before installing:** verify the preservation and recovery plan. The current
Jira fixture uses a PVC; that still requires a verified database backup. Preserve
issuer configuration, keys, databases and driver history. Retire native contexts
before replacing their gateway. Never delete a working installation or shared
resources merely to bypass a collision check.

On the prepared empty owned application target, with shared prerequisites intact:

```bash
PYTHONPATH=scripts/identity_demo:tests/identity_demo "$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py \
  permissions --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --bundle "$DEMO_STACK_BUNDLE" --bundle-sha256 "$DEMO_STACK_SHA256" \
  --output-dir "$DEMO_PACKAGE_OUTPUT/permissions-01"
PYTHONPATH=scripts/identity_demo:tests/identity_demo "$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py \
  install --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --bundle "$DEMO_STACK_BUNDLE" --bundle-sha256 "$DEMO_STACK_SHA256" \
  --output-dir "$DEMO_PACKAGE_OUTPUT/install-01" --apply
PYTHONPATH=scripts/identity_demo:tests/identity_demo "$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py \
  verify --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --bundle "$DEMO_STACK_BUNDLE" --bundle-sha256 "$DEMO_STACK_SHA256" \
  --output-dir "$DEMO_PACKAGE_OUTPUT/verify-01"
```

Require the permission result to pass before installation. It uses
SelfSubjectAccessReview for each distinct create API/namespace scope and never
grants access. Namespaced grants must already exist to pass; use the authorized
preparation above or have the platform owner supply them. This check does not prove admission, read
access, runtime ServiceAccount privileges or functional behavior; retain the
separate plan/dry-run and runtime checks.

Verification checks ownership, pinned application and init-container templates, observed workload generation and readiness. Controller-generated gateway/authorizer readiness and actual protected calls still require the following acceptance scenarios. Follow
[execution setup](#operator-cli-reference) afterward to reconcile trust and
catalog inputs, provision identities and register mappings. Run the
[workflow acceptance matrix](identity-demo-customer-quickstart.md#6-verify-and-present)
and retain backend/audit outcomes and corrections. Readiness or
server dry-run is not successful cold-installation/scenario acceptance.

Verification also compares the bundle's exact namespaced Role rules,
RoleBinding subjects/role references and NetworkPolicy specifications. An extra
grant or broadened egress fails even when the workloads remain Ready. It reports
drift without changing live resources; investigate intentional changes and render
a new reviewed bundle rather than editing old receipts to make the check pass.

### Native runtime permission preparation

Use the same installation profile and bundle for `runtime-permissions`. It
prepares four exact ClusterRole/Binding objects from the existing runtime and
workspace helpers, separately from namespaced application creation. Plan first
without `--apply`, then use a new output directory with `--apply` only under the
authorized platform account. It refuses an unowned or broader existing grant;
it never edits an existing one. Preserve its UID receipts separately from the
application creation ledger.

```bash
IDENTITY_DEMO_CONFIG="$DEMO_INSTALLATION_PROFILE" \
PYTHONPATH=scripts/identity_demo:tests/identity_demo "$DEMO_PYTHON" \
  scripts/identity_demo/identity_demo_setup.py runtime-permissions \
  --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --bundle "$DEMO_STACK_BUNDLE" --bundle-sha256 "$DEMO_STACK_SHA256" \
  --output-dir "$DEMO_PACKAGE_OUTPUT/runtime-permissions-plan-01"
```

These bind only the configured gateway ServiceAccount: TokenReview creation,
exact configured namespace reads and native Sandbox list/watch. List/watch is
cluster-wide because the native controller watches workspaces; this scope must
be reviewed explicitly. Workload accounts do not gain those permissions. The
dry-run defers binding admission until its absent role actually exists; apply
then performs each exact server check before creating it.

When the supervisor image is published in this installation's internal-registry
repository, the same action also prepares one namespaced Role/RoleBinding in
the owned core namespace. It permits `get` on `imagestreams/layers` for that
**exact supervisor ImageStream name**, bound only to the triage and reader
`fixture-openshell-sandbox` ServiceAccounts. Both accounts, namespaces and source
ImageStream must pass ownership checks. It copies no pull credentials, grants
no Secret reads, changes no registry setting and refuses broader collisions.
Run this before provisioning sandboxes: application Pods starting in the core
namespace do not prove cross-namespace supervisor image pulls. External/private
registries require separately approved pull configuration; this helper does not
invent credentials. See [OpenShift image pull permissions](https://docs.redhat.com/en/documentation/openshift_container_platform/4.21/html/images/managing-images).

## Application data backup and restart validation

Use the private operator environment and original installation receipts. The
application backup covers driver/Jira SQLite data; issuer databases, signing keys,
SPIRE, OpenShell and workspace volumes need separate recovery inputs. Rollback
must preserve newer audit, approvals, consumed identities and quarantine.

### Back up and verify application data

Use the final connected installation's bundle, not an earlier pre-build render.
The generated profile and bundle are in the same render directory. These
commands assume the private paths are loaded and cluster workers are idle.
Fence only this installation's coordinator/preparer before
maintenance; keep the UI closed to new submissions.

```bash
export DEMO_STACK_BUNDLE="$(dirname "$IDENTITY_DEMO_CONFIG")/stack.private.json"
export DEMO_STACK_SHA256="$(shasum -a 256 "$DEMO_STACK_BUNDLE" | awk '{print $1}')"
export DEMO_MAINTENANCE="$DEMO_PRIVATE_ROOT/maintenance-01"
mkdir -m 700 "$DEMO_MAINTENANCE"
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py backup-data \
  --bundle "$DEMO_STACK_BUNDLE" --bundle-sha256 "$DEMO_STACK_SHA256" \
  --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --output-dir "$DEMO_MAINTENANCE/backup-01"
export DEMO_BACKUP_MANIFEST="$DEMO_MAINTENANCE/backup-01/backup.private.json"
export DEMO_BACKUP_SHA256="$("$DEMO_PYTHON" -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["manifest_sha256"])' \
  "$DEMO_MAINTENANCE/backup-01/setup.summary.json")"
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py verify-backup \
  --backup-manifest "$DEMO_BACKUP_MANIFEST" --backup-sha256 "$DEMO_BACKUP_SHA256" \
  --output-dir "$DEMO_MAINTENANCE/restore-check-01"
```

Expected: driver/Jira snapshots and verified restored **local copies**. A failed
quiescence, ownership or content check stops maintenance; preserve the receipt
and inspect before retrying. No live database is overwritten. These backups do
not cover Keycloak, SPIRE, OpenShell or workspace volumes. Preserve generated
keys/configuration separately and use component-specific recovery procedures.
Do not describe these two databases as a complete platform backup.

For a read-only capture with **no active run, preparation or uncertain outcome**,
`backup-data --allow-idle-heartbeat` permits only the coordinator/preparer
`updated` timestamps to advance between captures. Other worker fields, schema,
audit, approvals, pool lifecycle and all Jira data must still match. Restore
verification checks every captured field. This option neither pauses workers nor
makes live database rollback safe. If the check fails, keep the failed receipt,
identify the changed tables and use a new output directory after resolving it.


### Restart the two application databases safely

After successful backup verification, use the same bundle/backup arguments with
`restart-data`. Plan first; inspect the exact owned Deployment changes, then
apply once to a new output directory:

```bash
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py restart-data \
  --bundle "$DEMO_STACK_BUNDLE" --bundle-sha256 "$DEMO_STACK_SHA256" \
  --backup-manifest "$DEMO_BACKUP_MANIFEST" --backup-sha256 "$DEMO_BACKUP_SHA256" \
  --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --output-dir "$DEMO_MAINTENANCE/restart-plan-01"
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py restart-data \
  --bundle "$DEMO_STACK_BUNDLE" --bundle-sha256 "$DEMO_STACK_SHA256" \
  --backup-manifest "$DEMO_BACKUP_MANIFEST" --backup-sha256 "$DEMO_BACKUP_SHA256" \
  --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --output-dir "$DEMO_MAINTENANCE/restart-01" --apply
```

Expected: only driver/Jira restart, with database contents, PVC identities and
images preserved. After success, start the trusted services, sign in again and
verify readiness. On failure, retain state and inspect the exact receipt; never
restore older approval history or repeat an uncertain mutation blindly.


### Verify issuer recovery separately

The application backup above excludes the issuer databases and signing keys.
For the current development-file issuers, use an administrator-approved encrypted
CSI snapshot procedure; realm exports alone do not establish recovery. This is
an idle maintenance operation on this installation, never on shared services.

1. Verify exact issuer Deployment/PVC UIDs against installation receipts. Save
   their configuration and required keys privately, and verify the application
   backup. Stop if a resource was replaced, an action is uncertain or a run is active.
2. Fence coordinator/preparer ownership and wait for their Pods and original
   leases to expire. Stop only the two owned issuers and confirm no Pod still
   mounts either source PVC before taking cold snapshots.
3. Use an approved, non-default CSI snapshot class with `Retain` policy. Record
   snapshot/content UIDs and private storage handles; require both snapshots to
   report `readyToUse`. Preserve failed receipts and inspect the same operation
   after a timeout rather than replaying creation.
4. Restore the original issuer specifications against their original PVCs.
   Verify readiness and unchanged public signing keys before resuming workers.
   Never replace live databases with the test copies.
5. Restore snapshots into **new PVCs in a separate, owned recovery namespace**.
   Verify deny-all ingress/egress and no Service/Route. Use the same pinned issuer
   images and feature settings, a loopback listener, no bootstrap credentials,
   no realm re-import and no Kubernetes token mount. Wait for the actual HTTP
   listener; Pod `Running` alone is insufficient. Through an authenticated
   operator tunnel, verify a freshly signed test token against pre-backup public
   keys and the original issuer. Do not send that token to any live service.
6. Delete only receipt-matched test Pods and restored volumes. Preserve cold
   backups, private recovery configuration and current application history.
   Verify audit, approvals, Jira data and pool readiness afterward.

This procedure passed for both candidate issuers, including actual signing-key
use, with original volumes preserved. Temporary restored volumes were removed;
no extra Jira issue was created. It does not prove full SPIRE/OpenShell recovery,
cross-cluster disaster recovery or a production database backup policy. Arrange
backup retention, encryption/key access and platform restore ownership with the
customer administrator. See the official
[CSI snapshot lifecycle](https://kubernetes.io/docs/concepts/storage/volume-snapshots/)
and [Keycloak export limitations](https://www.keycloak.org/server/importExport).
Network policies are additive: a deny-all policy inside a namespace with broader
allow rules does not by itself isolate a restored issuer.

### Application resource defaults

The owned application namespace uses a standard LimitRange for containers whose
controller supplies no resource budget, including the MCP broker: requests of
100m CPU and 128 MiB, with limits of one CPU and 512 MiB. Explicit application and
build settings take precedence. This keeps generated Pods bounded without
patching the shared controller. These are single-execution evaluation defaults;
production sizing still needs representative load measurements.

### Restore kubelet coverage after worker replacement

Inputs: the loaded private installation profile, its original security-creation
receipts, an approved `DEMO_PLATFORM_KUBECONFIG`, and an idle, certain console.
The administrator’s installation preflight checks current worker InternalIPs
without editing policy. Runtime workers have no node-inventory permission; a
subsequent node change can cause workload attestation to time out during a
protected read. Monitor SPIRE attestation failures and ask the platform owner to
restore exact host coverage before retrying with a fresh run.

1. Use `demo_exec --action inspect-state` with a new private output directory.
   Require no active run, console job, preparation or uncertain action. Match
   `identity-demo-kubelet-egress` to its **original creation UID** and verify the
   identity namespace is exclusively owned. Stop if ownership is uncertain or
   another consumer could be affected; ask the platform owner instead.
2. Use the guarded idle worker maintenance procedure to fence the two exact
   owned workers and verify process exit/lease expiry. Keep their definitions
   and state PVCs; do not uninstall infrastructure or clear leases.
3. Plan the existing helper's change, then inspect the private receipt:

   ```bash
   "$DEMO_PYTHON" scripts/identity_demo/identity_demo_spire_network.py \
     --phase kubelet-reconcile --kubeconfig "$DEMO_PLATFORM_KUBECONFIG" \
     --output "$DEMO_PRIVATE_ROOT/kubelet-plan-01.private.json"
   ```

   Expected: `applied: false`, with only current worker host destinations added
   to the SPIRE-agent rule on TCP 10250. Other selectors, ports and rules must
   remain unchanged. An identity/API/admission failure stops here. Preserve the
   receipt and resolve it; do not substitute a broad CIDR or another account.
4. Recheck the original UID, unchanged rule and reviewed current worker set,
   then apply with a different output filename:

   ```bash
   "$DEMO_PYTHON" scripts/identity_demo/identity_demo_spire_network.py \
     --phase kubelet-reconcile --kubeconfig "$DEMO_PLATFORM_KUBECONFIG" \
     --output "$DEMO_PRIVATE_ROOT/kubelet-apply-01.private.json" --apply
   ```

   Expected: `coverage_current: true`; UID/resource-version/spec tests guard the
   update. On failure, inspect the actual policy and receipt before another
   mutation. Do not overwrite evidence or restore an older database.
5. Restore the same two saved worker specifications. Require current
   readiness, attested contexts and automatic preparation to resume. If coverage
   still fails, compare the new node set and keep the failure blocked for review.

This updates only the existing owned policy's host allowlist. It does not modify
nodes, shared controllers, trust roots, workload identities or run deadlines.

## Cleanup and installation rollback

Use only this installation's exact private creation ledger. Inspect first without
`--apply`; use a new output directory for the explicit apply. The helper checks
UID, configuration drift and its unique installation marker. It checks quiescent
driver state before driver removal and uses UID/version DeleteOptions. It retains
namespaces, Secrets, PVCs and Jira. Retire native contexts with the execution helper
before removing their gateway; shared controllers/identity foundation remain untouched.

```bash
PYTHONPATH=scripts/identity_demo:tests/identity_demo "$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py \
  cleanup --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --credentials-file "$DEMO_FIXTURE_CREDENTIALS" \
  --ledger "$DEMO_PACKAGE_OUTPUT/install-01/creation-ledger.private.json" \
  --output-dir "$DEMO_PACKAGE_OUTPUT/cleanup-plan-01"
```

Interrupted creation leaves a `pending` record and is not automatically retried.
New ledgers record the admission fingerprint and an installation marker. The
`resume` action accepts the original `--ledger`, exact `--bundle` and
`--bundle-sha256`, a new `--output-dir`, and explicit `--apply`. It checks all
recorded objects for ownership, UID and drift, then resolves only that journaled
pending creation. The original ledger remains immutable. A missing, changed or
replaced confirmed object stops resumption; older ledgers without the required
marker/fingerprint need manual investigation. Never edit a ledger to disguise an
unrelated or replaced object. Retained objects
can block another clean install until their separate recovery/disposition is reviewed.
For version rollback of an existing driver, use the proven recipe in execution setup.

Resume recognises only verified OpenShift registry pull-Secret additions and
service-CA injection as controller updates. Registry credentials must have the
exact ServiceAccount owner UID and expected type; injected roots must match the
namespace platform CA. Configuration, UID and ownership drift still stop the
operation. Older generated TLS state lacking certificate key identifiers must
be explicitly repaired or regenerated, repackaged and validated; do not disable
strict TLS checking or rewrite old installation receipts to work around it.

## Acceptance and release

Installation readiness is not functional acceptance. On your exact target, prove
the permission matrix, live model workflows, protected native reads, project
isolation, cleanup/replenishment, renewal and safe failure behavior. Check audit,
backend counts and exact approved fields. Retain all receipts privately.

Use the [console guide](identity-demo-console.md) for presentation and
[known limitations](identity-demo-reference.md) for external images, diagnostic security,
licensing/support, independent handoff and disconnected/empty-platform boundaries.

## Supplied runtime images

Keep the existing Jira emulator. The delivery owner provides its approved
immutable image and the CVE workload image, with provenance/licence records
outside the public source tree. Customer registry credentials belong in the
customer's private registry/cluster configuration. Functional compatibility is
separate from redistribution permission; do not mark the latter approved because
an image ran successfully.

Load or pull the approved images into the selected local engine using its private
credential store. The helper never pulls images implicitly. Check their interfaces
without networking, writable host mounts or credential files:

```bash
export DEMO_CVE_WORKLOAD_IMAGE="registry.example.test/demo/cve-workload@sha256:replace-with-actual-digest"
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py runtime-check \
  --artifacts-file "$DEMO_ARTIFACTS_FILE" --workload-image "$DEMO_CVE_WORKLOAD_IMAGE" \
  --engine podman --output-dir "$DEMO_PRIVATE_ROOT/runtime-check" --apply
```

The Jira image must provide `jira_emulator`, `mcp_servers.atlassian_jira`, FastMCP,
SQLAlchemy and the existing app/database/token interfaces. The CVE image must
provide `exploit_iq_commons`, the reviewed output models and the real
`vuln_analysis.utils.jira_handoff` functions. A vanilla upstream CVE image without
that handoff is incompatible. Import checks catch missing interfaces but do not
prove TLS, persistence, permissions or approved writes; target acceptance does.
No externally authored emulator or CVE source has been silently relicensed here.


### Check the supplied images directly on OpenShift

If the images are not cached on the installation workstation, use the same `runtime-check` action
in a prepared **owned** application namespace instead of downloading large images.
The namespace must already exist with the profile's owner labels. First omit
`--apply` for permission/admission planning, then apply in a new output directory:

```bash
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py runtime-check \
  --runtime-check-target cluster \
  --installation-profile "$DEMO_INSTALLATION_PROFILE" \
  --artifacts-file "$DEMO_ARTIFACTS_FILE" --workload-image "$DEMO_CVE_WORKLOAD_IMAGE" \
  --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --output-dir "$DEMO_PRIVATE_ROOT/runtime-cluster-check" --apply
```

This creates two bounded Jobs and one policy selecting only those probe Pods.
They have no API token, real Jira/model credentials or host mounts. The dedicated
policy requests denied ingress/egress; existing namespace allow rules are additive,
so it does not independently certify isolation. The Jira import receives synthetic initialization
values and makes no tool call. Failed imports report only allowlisted error types,
never exception messages or raw logs. The helper requests conditional deletion
of its exact recorded UIDs after confirmed completion. A timeout or uncertain
creation keeps receipts for operator inspection. Verify deletion completion before
calling the target empty. These checks do not alter the running demo or prove
the end-to-end permission scenarios.

## Operator CLI reference

For application installation start with the [quickstart](identity-demo-customer-quickstart.md).
This reference covers execution contexts, CLI acceptance, optional diagnostics
and exact retirement on the configured owned installation. It does not bootstrap
shared platform controllers. Optional diagnostic binaries have separate release
requirements in [known limitations](identity-demo-reference.md).

For browser operation, use the OpenShift services and automatic pool in the
[quickstart](identity-demo-customer-quickstart.md#5-review-the-application-handoff-and-activate).
The manual context/registration commands below apply to explicit CLI maintenance
or legacy local mode. They do not replace automatic pool preparation. Fence the
browser workers before direct execution; never run both against one installation.

### CLI inputs and ownership

Use Python 3.12+, the pinned test dependencies, `oc`, and the official OpenShell
v0.1.3 CLI. Use an explicit private kubeconfig and expected server on every call.
Use the [private input rules](#private-inputs). The following additional paths
are needed only for the selected CLI acceptance or diagnostic operation; do not
install diagnostic tools for a normal browser workflow.

| Variable | Required input |
|---|---|
| `DEMO_PYTHON` | Interpreter with the repository's pinned test dependencies |
| `DEMO_KUBECONFIG`, `DEMO_SERVER` | Private authenticated kubeconfig and exact expected API URL |
| `DEMO_FIXTURE_CREDENTIALS` | Existing private fixture/runtime credential file |
| `DEMO_OPENSHELL_CLI`, `DEMO_CLI_CONFIG` | v0.1.3 CLI and the prepared private operator profile |
| `DEMO_PRIVATE_ROOT` | Private directory outside this repository, mode 0700 |
| `DEMO_SPIRE_AGENT`, `DEMO_PROJECTION_READER` | Reviewed Linux SPIRE CLI and native compute-projection diagnostic; reproduce with [diagnostic-build](../tests/identity_demo/tools/README.md) |
| `DEMO_DRIVER_CREDENTIALS`, `DEMO_CATALOG_CREDENTIAL` | Existing private operator-driver keys and fresh catalog-only credential |
| `DEMO_INFERENCE_CONFIG` | Private approved Messages provider JSON with an existing protected raw-key file reference |

Install the operator dependencies in a private virtual environment using both
`tests/identity_demo/requirements-lock.txt` and
`tests/identity_demo/requirements-operator.txt`. Browser rehearsal uses installed
Google Chrome; Playwright is not deployed to the cluster.

Before allocating a run, reconcile the current SPIRE public CA bundle with the
owned Keycloak client trust and bound MCP listener using
`scripts/identity_demo/identity_demo_sender_trust.py`. Run in plan mode first with a fresh
private output directory; if the bundle changed, repeat with `--apply` and a
different directory, then wait for `fixture-keycloak-upstream` rollout. This
manual step is required after authority rotation in legacy/direct installations.
Cluster installations using the Setup guide's public-trust opt-in instead refresh
their two public CA copies automatically while idle. Do not restart Jira. Refresh the catalog-only credential with
`scripts/identity_demo/identity_demo_adapter_catalog.py --action rotate`; it must have at least
600 seconds remaining before a rehearsal starts.

```bash
mkdir -m 700 "$DEMO_PRIVATE_ROOT/trust-check-new"
PYTHONPATH=scripts/identity_demo "$DEMO_PYTHON" scripts/identity_demo/identity_demo_sender_trust.py \
  --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --credentials-file "$DEMO_FIXTURE_CREDENTIALS" \
  --output-dir "$DEMO_PRIVATE_ROOT/trust-check-new"
PYTHONPATH=scripts/identity_demo "$DEMO_PYTHON" scripts/identity_demo/identity_demo_adapter_catalog.py \
  --action rotate --kubeconfig "$DEMO_KUBECONFIG" \
  --expected-server "$DEMO_SERVER" \
  --catalog-credential-file "$DEMO_PRIVATE_ROOT/catalog-new.private.json" \
  --receipt-file "$DEMO_PRIVATE_ROOT/catalog-new.receipt.json"
export DEMO_CATALOG_CREDENTIAL="$DEMO_PRIVATE_ROOT/catalog-new.private.json"
```

Use unused output names. If trust needs reconciliation, repeat the first command
with `--apply` and a different output directory before creating a run. Wait for
the owned issuer rollout if reported. Catalog rotation allows at most two live
credentials; if both slots are occupied, use `--action revoke` with the exact old
private credential file and a fresh receipt before issuing another. Revocation
does not remove run/action/audit state. Never print the credential JSON.

The helper verifies the existing owned namespaces, native gateway, reviewed image,
separate tokenless ServiceAccounts, and exact SPIRE registrations. The integration helpers restrict operations to the selected private installation
profile and matching native artifact lock. A different target needs its own
profile, realm/trust inputs and rebuilt native endpoint/CA contract; use the
quickstart rather than disabling these guards. Separate-cluster acceptance is
still required before claiming portability to that target.

Infrastructure/native changes require the designated platform reviewers;
workload changes also require the application owner's review. Keep reviewable changes separate from shared
resources. These development helper calls never count as review approval.

### Register native workspaces after a fresh application install

For a new source installation, export `IDENTITY_DEMO_CONFIG` to the rendered
`installation-profile.json` and `IDENTITY_DEMO_ARTIFACTS` to its matching private
artifact lock **for every operator/helper command**. Do not reuse the reference
CLI profile. Create a new private CLI directory and set `DEMO_RUNTIME_CA` to the
rendered `runtime-gateway-ca.pem`. The triage/reader namespace names must each
fit OpenShell's 19-character workspace limit; rendering rejects longer names.

Kubernetes namespaces and native OpenShell workspace records are distinct.
After the application and exact runtime grants are ready, register the two
workspace records using the supported native API:

```bash
PYTHONPATH=scripts/identity_demo:tests/identity_demo "$DEMO_PYTHON" \
  scripts/identity_demo/identity_demo_execution_setup.py \
  --action prepare-workspaces --ca-file "$DEMO_RUNTIME_CA" \
  --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --credentials-file "$DEMO_FIXTURE_CREDENTIALS" \
  --cli "$DEMO_OPENSHELL_CLI" --cli-config-dir "$DEMO_CLI_CONFIG" \
  --output-dir "$DEMO_PRIVATE_ROOT/native-workspaces-plan-01"
```

Run plan first, then repeat with a new output directory and `--apply`. This
initializes only the private operator CLI profile and creates absent native
workspace records with exact owner/installation labels. It checks the configured
namespace allowlist and refuses different existing native ownership. It neither
adopts nor edits Kubernetes namespaces. On an uncertain create, inspect native
workspace inventory and the pending receipt before repeating. Existing reference
workspaces without the new installation labels must not be silently adopted.
Then run the management probe and the remaining execution steps below.

### Provision a fresh execution identity

Run from the example root. Choose an unused 1–3 character alphanumeric suffix;
for example `n1` if it has never been used. The resulting sandbox name is at most 19 characters. Use a
different private output directory for each invocation. Omit `--apply` first to
check ownership and name collisions without creating a sandbox.

```bash
export DEMO_SUFFIX="n1" # Choose a never-used suffix for every scenario.
PYTHONPATH=scripts/identity_demo:tests/identity_demo "$DEMO_PYTHON" \
  scripts/identity_demo/identity_demo_execution_setup.py \
  --action provision --role triage --suffix "$DEMO_SUFFIX" \
  --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --credentials-file "$DEMO_FIXTURE_CREDENTIALS" \
  --cli "$DEMO_OPENSHELL_CLI" --cli-config-dir "$DEMO_CLI_CONFIG" \
  --output-dir "$DEMO_PRIVATE_ROOT/context-$DEMO_SUFFIX" --apply
export DEMO_FRESH_CONTEXT="$DEMO_PRIVATE_ROOT/context-$DEMO_SUFFIX/context.private.json"
```

The runtime supplies the UUID. The helper then registers the exact supervisor
Pod/container/resolved-image and actual PSAT-attested node. It creates a private
`context.private.json`; no credential or private key belongs in that receipt.
Provisioning alone does not prove identity delivery or a protected tool call.

New native workload containers request and limit **50m CPU / 128Mi memory**.
Existing prepared contexts keep their admitted settings until normal replacement.
Supervisor overhead and storage are separate from the workload reservation. Do not infer whole-cluster cost savings from the workload reservation.

If creation times out, inspect the exact Sandbox/Pod and retained failure receipt.
Do not retry creation blindly. After resolving scheduling, `--action
recover-provision` with the same role/suffix and a new output directory inspects
the existing native identity and completes its registration. It never creates a
replacement. Recovery requires a native Ready sandbox and unused registration.

### Add trusted workflow mappings

The default `--workflow cve --project TEST` keeps the accepted CVE behavior.
For the SERVICE workflow (now **Remediation change request** in the browser), use
`--workflow service-request --project SERVICE`
with a separately provisioned triage context. Provision the dedicated synthetic
project using the same helper with `--action provision-project --project SERVICE`
(plan mode first, then `--apply` in a new output directory). This uses the
supported fixture admin API, verifies the fixed synthetic name on an existing
project, and compares the existing TEST data before/after. It never resets Jira.
The project comes
from this trusted configuration, never from the browser.

```bash
PYTHONPATH=scripts/identity_demo:tests/identity_demo "$DEMO_PYTHON" \
  scripts/identity_demo/identity_demo_execution_setup.py \
  --action register-driver --workflow service-request --project SERVICE \
  --context-file "$DEMO_FRESH_CONTEXT" \
  --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --credentials-file "$DEMO_FIXTURE_CREDENTIALS" \
  --cli "$DEMO_OPENSHELL_CLI" --cli-config-dir "$DEMO_CLI_CONFIG" \
  --output-dir "$DEMO_PRIVATE_ROOT/driver-service-$DEMO_SUFFIX" --apply
```

Repeat `--context-file` to add several freshly validated mappings in one update.
The helper preserves every old mapping, Secret reference and PVC; it versions
the code/config ConfigMap and saves the prior Deployment privately. No identity
can be reassigned. Dry-run mode renders private desired artifacts and performs
server validation before an apply. After driver rollout, sign in again if the
browser session expired. Durable run/action/audit records and verified Jira
references remain available; temporary in-memory state is not recovery evidence.

This step does not prove the service-request matrix. The actual native client,
approval, backend verification and denial tests must follow.

### Run the CVE and Messages workflows

Use a fresh registered service context for **each** scenario. The runner refuses
retired identities. The following runs actual approved Messages provider inference, real browser
consent and a protected create attempt. It also tests unavailable inference before
attaching the model provider, actual agent socket denials, and a protected read
after the configured 30-second final-token lifetime. It never sends the real
model key into the agent. Native provider header injection is limited to
`inference.example.test:443`, POST `/v1/messages`, and the reviewed Python binary.
It removes the temporary model/MCP provider and route on exit.

Static native credentials use an opaque placeholder environment value. The
client validates that format and supplies it in `x-api-key`; the supervisor
rewrites it after endpoint admission. Do not substitute the real key, and do not
assume a missing static header is automatically synthesized. This uses the
v0.1.3 `openshell-core/src/secrets.rs` provider mechanism, with no OpenShell change.

```bash
export DEMO_FRESH_OUTPUT="$DEMO_PRIVATE_ROOT/walkthrough-$DEMO_SUFFIX"
PYTHONPATH=scripts/identity_demo:tests/identity_demo "$DEMO_PYTHON" \
  tests/identity_demo/rehearse_walkthrough.py \
  --workflow service-request --inference-config "$DEMO_INFERENCE_CONFIG" \
  --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --credentials-file "$DEMO_FIXTURE_CREDENTIALS" \
  --cli "$DEMO_OPENSHELL_CLI" --cli-config-dir "$DEMO_CLI_CONFIG" \
  --context-file "$DEMO_FRESH_CONTEXT" \
  --catalog-credential-file "$DEMO_CATALOG_CREDENTIAL" \
  --driver-credentials-file "$DEMO_DRIVER_CREDENTIALS" \
  --output-dir "$DEMO_FRESH_OUTPUT" --label "walkthrough-model-$DEMO_SUFFIX" \
  --username analyst --enable-create --headed --record-video
```

Omit `--inference-config` for the deterministic non-CVE producer. For the viewer
denial, prepare a new triage context and use `--username viewer` with a fresh
output directory/label; retain `--enable-create`. Use the CVE walkthrough for the
separate reader denial. Run `"$DEMO_PYTHON" -m playwright install ffmpeg` once
before recording. Video starts only after login; state moves in memory to the
recording browser context, with no saved cookie export. Private recordings and
screenshots still require inspection before sharing.

The direct acceptance matrix below covers five combinations; the quickstart also
requires Incident triage acceptance. Provision and
register a never-used context for each row; retain `--enable-create` so a denial
tests authorization rather than a disabled write path. For CVE rows, use
`--workflow cve --project TEST` when registering, `--workflow cve` when rehearsing,
and omit `--inference-config`. Choose `--role reader` only for the reader row.

| Workflow | Role | User | Inference | Expected write |
|---|---|---|---|---|
| CVE / TEST | triage | analyst | No | One verified create |
| CVE / TEST | triage | viewer | No | User-permission denial |
| CVE / TEST | reader | analyst | No | Workload-permission denial |
| Remediation request / SERVICE | triage | analyst | Messages agent | One verified create |
| Remediation request / SERVICE | triage | viewer | Messages agent | User-permission denial |

The native proxy verifies upstream HTTPS; the workload verifies the supervisor's
TLS interception using runtime-supplied CA settings. No redirect, alternate
provider, raw-key agent environment or model-selected authority field is permitted.
Model output is untrusted summary/description text and requires the same exact
action approval as the deterministic case. The approved Messages endpoint is an external dependency.
These controls constrain the actual agent; trusted supervisor/operator egress,
DNS and image pulls are explicit exceptions, not disconnected-install evidence.
API-key rotation at approved Messages provider requires its owner's separately issued credential;
successful final-token renewal does not prove that external rotation or SVID
certificate rollover.

## Read-only replay, certificate renewal and containment acceptance

Run these optional direct probes before enabling/registering the browser
coordinator: the direct probe is not a coordinator and cannot satisfy its
heartbeat gate. Do not run a direct probe alongside console execution. After
console mode is enabled, use the documented browser acceptance path unless an
explicitly reviewed idle maintenance procedure changes that mode.

After source installation, use a never-used triage context, its exact SPIRE
registration and trusted driver mapping. Stage the reviewed diagnostics above
and refresh the scoped catalog credential. Create a new private empty output
directory first; the native probe requires that directory to exist.

For an installation with the **private operator listener**, run the probe only
in a reviewed idle CLI maintenance window: stop and fence both workers, pause
automatic preparation and use direct console mode. Preserve the before-state
and restore browser/automatic mode only after the exact run and credential
cleanup are verified. Never run a direct probe alongside browser execution.

Verify the `fixture-identity-operator` Service UID against the completed private
configuration receipt. Set the following in the probe terminal, using the same
installation profile and freshly observed public service CA:

```bash
export DEMO_CORE_NAMESPACE="$("$DEMO_PYTHON" -c 'from deployment_profile import active_profile; print(active_profile().core_namespace)')"
export DEMO_OPERATOR_SERVICE="$("$DEMO_PYTHON" -c 'from deployment_profile import active_profile; print(active_profile().service_host("fixture-identity-operator"))')"
export IDENTITY_DEMO_OPERATOR_ORIGIN="https://$DEMO_OPERATOR_SERVICE:8444"
export IDENTITY_DEMO_OPERATOR_CA="$DEMO_PRIVATE_ROOT/operator-service-ca.pem"
oc --kubeconfig "$DEMO_KUBECONFIG" -n "$DEMO_CORE_NAMESPACE" \
  get configmap fixture-service-ca -o 'jsonpath={.data.service-ca\.crt}' \
  > "$IDENTITY_DEMO_OPERATOR_CA"
chmod 600 "$IDENTITY_DEMO_OPERATOR_CA"
export IDENTITY_DEMO_OPERATOR_LOOPBACK_PORT=18447
```

In a separate operator terminal, start the fixed loopback-only tunnel, using the
same namespace and kubeconfig values:

```bash
oc --kubeconfig "$DEMO_KUBECONFIG" -n "$DEMO_CORE_NAMESPACE" \
  port-forward --address 127.0.0.1 service/fixture-identity-operator 18447:8444
```

Expected: forwarding is active, with no occupied-port error. Then run the probe
below in the first terminal. TLS still verifies the **service hostname**, not
the loopback address. A missing/incorrect CA, service or reply stops the call;
there is no fallback to public operator routes and no mutation retry. On failure,
retain receipts and review the outcome before restoring execution. Close only
this tunnel with Ctrl-C after the probe and cleanup finish. Legacy installations
without the private listener leave these three `IDENTITY_DEMO_OPERATOR_*`
variables unset and retain their existing transport.

Private-listener direct mode requires the installer-held operator credential.
Cluster mode accepts only the separate coordinator credential for execution
coordination; a failed authentication never falls back to another credential.
Changing execution mode requires the guarded installer update while idle.

```bash
mkdir -m 700 "$DEMO_SECURITY_OUTPUT"
PYTHONPATH=scripts/identity_demo:tests/identity_demo "$DEMO_PYTHON" \
  tests/identity_demo/probe_native_exchange.py \
  --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --credentials-file "$DEMO_FIXTURE_CREDENTIALS" \
  --cli "$DEMO_OPENSHELL_CLI" --cli-config-dir "$DEMO_CLI_CONFIG" \
  --context-file "$DEMO_FRESH_CONTEXT" \
  --driver-credentials-file "$DEMO_DRIVER_CREDENTIALS" \
  --driver-check read-security --demo-user analyst \
  --gateway-mode persistent --gateway-receipt "$DEMO_GATEWAY_RECEIPT" \
  --upstream-development-issuer --bound-sender-listener --check-run-binding \
  --protected-backend-catalog-credential-file "$DEMO_CATALOG_CREDENTIAL" \
  --label fresh-read-security --output-dir "$DEMO_SECURITY_OUTPUT"
```

For a separate source installation, export its exact `IDENTITY_DEMO_CONFIG`
and `IDENTITY_DEMO_ARTIFACTS` first, as in section 0. This selects the existing
`ReadSecurityFlow`; it does not run the browser/create scenario. The command
refuses `--enable-create` and users other than analyst. It proves real native
leaf rotation and same-identity/different-leaf copied-token denial, forged peer
header rejection, invalid/expired tokens, strict body/parser controls, private
report isolation and operator revocation of a still-valid bound token. Require
all native and read-security assertions, unchanged backend counts and successful
cleanup. The suite intentionally cancels its run and retains history; never
reuse that execution identity.

`DEMO_GATEWAY_RECEIPT` is the private completed persistent-gateway receipt for
this installation. The probe verifies its resource identities, configuration and
current trust; it does not replace the stable gateway. A legacy temporary-mode
installation omits both gateway flags. After verified direct-test cleanup, use
the existing installer retirement helper before resuming automatic preparation;
preserve the consumed identity and workspace/history. Cluster preparers still
require the private retirement check and receive no installer Pod-exec access.

Replay credentials are obtained administratively in the supervisor and kept
in private operator receipts. The other-identity certificate is an explicitly
minted negative control, not evidence of workload attestation. These tests do
not establish that an unprivileged agent can obtain either credential, nor do
they prove complete platform recovery, model-key rotation or disconnected use.

### Native connection after SVID expiry

Use the same native probe command above with `--driver-check native-renewal`
and a **new unused execution context**, label and existing empty private output
directory. Stage the diagnostic tools first. This read-only gate requires the
analyst and refuses create mode. It reads through the actual sandbox proxy,
waits for the original real SVID leaf to expire, then opens a fresh native MCP
session and repeats the protected project read without restarting the supervisor
or injecting credentials into the agent. The existing short SVID lifetime must
permit the bounded test; the helper never changes registration TTLs.

Require the native summary and `.native-renewal.summary.json` to pass, with
successful cleanup and unchanged backend counts. The proof requires new gateway
request IDs, the exact broker-normalized read-body hash and the same authenticated user/workload/run;
the signed token fingerprint must match the actual TLS peer and differ from the
expired leaf. Operator replay requests and old log entries cannot satisfy it.
This checks fresh sessions through the persistent native proxy after expiry;
it does not test uninterrupted long-lived streams or full platform recovery.
Require actual before/after certificate and native-read receipts on the target cluster.
A local test or recorded source result does not prove real SVID renewal.

## Retire used contexts safely

When capacity is needed, use `--action retire --context-file <used-receipt>` with
the same private inputs and a new output directory. Omit `--apply` to check first.
The helper requires exactly one closed durable run, no executing/unknown action,
and positive cleanup evidence for an associated console job. A still-present
sandbox must pass the full native ownership/identity checks and have no attached
provider. It preserves run/action/audit/tombstones and retains referenced workspace
PVCs by removing only exact Sandbox owner references with UID/version guards.
After both native Pods are gone, it deletes only the exact owned supervisor
`ClusterStaticEntry`, also with UID/version guards, and verifies absence. Jira and
the shared SPIRE foundation remain unchanged. Existing issued SVIDs are not
revoked by registration deletion: run closure, detachment and the existing
certificate/token lifetime controls remain required.

Generated workspace claims appear on the materialized worker Pod, not the
Sandbox template's volume list. The helper accounts for claim templates before
deletion and verifies retained PVC UIDs and Bound state afterward. Automatic
retirement uses the same guarded function. No uncertain mutation is replayed
automatically, and an uncertain write or incomplete cleanup makes a run ineligible.

If an attempt fails, inspect its private failure, retirement-state and registration
receipts. A manual retry uses the same immutable context receipt and a **new
sibling private output directory under the same parent**. If the Sandbox is
already absent, the helper can finish missing registration cleanup without
replaying native deletion. If a still-live Sandbox already has detached workspace
ownership, exact prior private PVC UID/Sandbox-owner evidence is required before
continuing. Foreign/replaced objects or remaining Pods stop cleanup. Older console
records without an explicit cleanup result require independent operator review;
do not fabricate a cleanup flag, remove a tombstone or clear a recovery checkpoint.

Do not restart Jira as a capacity-cleanup shortcut. Its current PVC preserves
storage across Pod replacement, but safe maintenance still requires quiescence,
a verified database backup and the guarded restart procedure.

## Recovery and rollback

An inference `output_schema` failure means the model response was rejected before
proposal submission. Model output is variable; a successful connection does not
guarantee acceptable content. Keep the strict parser and inspect the sanitized
receipt/backend outcome. After cleanup and cancellation, use a fresh execution
identity for a new attempt. Do not retry a pending write or reuse a retired run.
The separately selected deterministic workflow remains available for presentation;
it is never an automatic fallback or a substitute for inference acceptance.

Do not repeat a timed-out mutation before inspecting its exact resource/UID and
private receipt. A still-running test must finish or be observed terminal before
starting another: native helpers reserve one loopback management tunnel and
temporarily configure the same owned gateway route. Failed runs are cancelled;
their execution identities remain retired even when no issue was created.

The walkthrough verifies restoration of temporary profiles/providers, gateway
configuration and issuer inventories. On an interrupted cleanup, use its saved
ledger to identify the exact created object ID; never remove an object merely
because its name looks similar. Retain audit/action/tombstone state and workspace
PVCs. No cleanup operation should restart/reset Jira or restore obsolete SPIRE
trust after CA rotation.

For a driver source/config rollback, first ensure no active run or uncertain
dispatch remains and identify the recorded previous revision from the saved
deployment receipt and rollout history. Set `DEMO_CORE_NAMESPACE` to the
profile's exact `core_namespace`.
Verify the namespace/deployment still have the configured owner label, then use
only the selected revision:

Use the setup helper with `--action inspect-state` and the common private
arguments above (no `--apply`) before/after rollback. Its `setup.summary.json`
contains only row counts/hashes and lifecycle counts; require
`rollback_quiescent: true` before changing the deployment, and identical table
hashes afterward. It never exports database rows or credentials.

```bash
oc --kubeconfig "$DEMO_KUBECONFIG" -n "$DEMO_CORE_NAMESPACE" \
  rollout history deployment/fixture-identity-driver
oc --kubeconfig "$DEMO_KUBECONFIG" -n "$DEMO_CORE_NAMESPACE" \
  rollout undo deployment/fixture-identity-driver --to-revision "$DEMO_ROLLBACK_REVISION"
oc --kubeconfig "$DEMO_KUBECONFIG" -n "$DEMO_CORE_NAMESPACE" \
  rollout status deployment/fixture-identity-driver --timeout=90s
```

This restores the versioned code/config reference while retaining its database
PVC and separate credential references. Browser sessions and in-memory decision
references require reauthentication; they are not recovery evidence. Verify
durable run/action/audit contents and backend data afterward. An old source
version is not approved for writes merely because its Pod is Ready. The official
OpenShell baseline is a reference/rollback artifact; reverting the development
sender patches does not establish a successful identity demo or authorize a
client-secret bypass.

## Required external inputs

- An installed and reviewed OpenShift cluster, ingress, storage, time,
  approved registry/network routes and explicit platform/application permissions.
  The platform team must install or approve the documented controllers and
  identity foundation before application installation.
- Digest-pinned Jira fixture, management Keycloak, exchange Keycloak, native
  gateway and supervisor images. Native images must match the generated target
  endpoint/identity/public-CA contract.
- A separately approved CVE workload image with Python and the real
  `exploit_iq_commons`, `vuln_analysis` and `jira_handoff` code used by the frozen
  fixture. Source/build provenance and distribution rights are required. This
  repository does not provide that external application's source or binary.
- An approved Messages API implementing `/v1/messages`, tool use, `x-api-key`
  and the configured model. Other API dialects, custom provider CA files and
  automatic model/provider switching are not implemented here. System-trusted
  HTTPS is mandatory; redirects remain disabled.
- Private protected kubeconfig, operator/fixture/driver/catalog credentials and
  model key. No credentials or private platform state are included.

## Open release gates

[Recorded verification](verification.json) describes the tested target. It is
not independent customer acceptance or production certification. Resolve the
applicable gates below before the corresponding customer handoff.

| Area | Required before the relevant customer handoff |
|---|---|
| Artifact security | Scan exact delivered images, CLI and dependency versions; remediate or obtain explicit security disposition for findings |
| Diagnostic CLI | The pinned SPIRE CLI has recorded unresolved Critical/High dependency matches; it is optional and no binary is bundled here |
| Provenance and licences | Establish Jira emulator/CVE image and management/native build provenance, applicable licences, notices and distribution rights |
| Supported operation | Review the preview/development identity-exchange components and native patches; vendor support is not implied |
| Installation handoff | Have an independent engineer follow the quickstart on the approved target and retain passing target-specific receipts |
| Recovery | Verify data backups and recovery for all retained databases, keys and workspaces; application bundle cleanup is not a complete uninstall |

The root Apache-2.0 licence covers source under its applicable notices. External
images, compiled upstream code and dependencies have their own licences; their
approval is not granted by copying this repository. No compiled binaries are
included. Supply approved artifacts separately. Checksums establish identity,
not security approval.

## Scope limits

- Frozen CVE assessment is synthetic; no live scanner or autonomous vulnerability
  analysis is claimed. Model-based incident/remediation flows propose Jira tasks;
  they do not implement production changes.
- The protected adapter mediates scoped service credentials. It does not establish
  native Jira human delegation or arbitrary agent-to-agent authorization.
- The owned SPIRE operator, CSI, identity/discovery foundation and application
  were installed fresh on the recorded target. Compatible shared platform
  controllers were retained. Installing every controller on an empty platform,
  full disconnected installation/operation and separate-cluster acceptance remain
  unproved. No embeddings are required for the selected workflows.
- Repeatable scripts still need reviewed private inputs, target-compatible images,
  platform permissions and scenario acceptance. The exact target-bound sender
  must be rebuilt when its CA/endpoints/trust contract changes.
- OpenShift mode does not require local background services after installation.
  The automated browser rehearsal was validated on macOS with Chrome; other
  workstation combinations need their own validation.

## Acceptance boundary

Require an empty, collision-free owned application target, an approved preservation/
recovery plan, readiness and all permission scenarios before presenting. Exercise
approved create, Viewer denial, Reader denial, live model inference/denial,
project isolation, cleanup/replenishment, renewal/reconnect and safe provider failure.
Check backend counts, exact approved issue fields and correlated audit; a Ready Pod,
mock, model-only smoke test or successful source render is insufficient.
Retain failed as well as successful receipts. Original authorization deadlines and
uncertain-write stops must remain enforced. Do not bypass guards to obtain a pass.


## Cluster-runtime hardening status

The verified presentation deployment runs its coordinator, preparer, private
operator HTTPS listener and authenticated Jira issue view on OpenShift. Acceptance
with local background workers stopped verified a protected Reader denial, cleanup,
automatic replacement to eight ready contexts, and owner-authorized historical
issue access (HTTP 200 for the owner, HTTP 403 for a Viewer). The current console
uses its authenticated issue view; no operator-host preview service is required.

| Area | Verified boundary | Remaining gate |
|---|---|---|
| Identity and authorization | Attested native exchange, exact subject/certificate binding, protected reads, Analyst create, Viewer/Reader denial and project isolation | Independent security review and supported-version/preview decisions |
| Application TLS | Opt-in cert-manager leaves, 30-day requests/seven-day renewal, new keys, native reload/SDS and strict live TLS checks; owned-authority overlap tested | Platform-approved issuer; full application CA rollover remains reviewed maintenance, and HA peer RPC is untested in one replica |
| Cluster operation | Separate scoped workers/profiles/Leases, natural projected-token rotation and local-worker-off browser-path acceptance | Independent walkthrough from another customer's workstation |
| Automatic preparation | Eight-ready/twelve-managed limits, concurrent preparation, subsequent run and retained history | Demand beyond the bounded pool can still wait |
| Recovery | Local restored driver/Jira copies, cold issuer snapshot/signing-key proof, actual service replacement and unused-context quarantine/retirement | Full SPIRE/OpenShell disaster recovery is not claimed |
| Interruption faults | Offline native-effect fixtures exercise actual preparer process exit/replacement and durable checkpoint/SQLite recovery; ambiguous preparation/retirement cannot replay | These fault injections do not deliberately break the live native/CSI control plane |
| Artifacts | Pinned release builds, packaged-binary checks, exact registry payload hashes and recorded scans | Findings dispositions, provenance/signatures, rights and customer pull access |
| Documentation and delivery | OpenShift runtime is the required-guide default; local operation is optional compatibility mode | Independent engineer and security/licensing release clearance |

History from a previous installation is not imported automatically. Before
replacing an installation, back up any records that must be retained and verify
the restore procedure. Shared platform controllers may have other consumers; keep
them unless ownership and dependencies are independently confirmed.

Raw receipts, logs, screenshots and database backups are private evidence, not
part of the customer package. No evaluation result constitutes production
certification.

### Preserve an existing UI during runtime configuration

The `console-runtime-prepare --console-runtime-stage configure` path normally
requires every application object in the original creation ledger. If an owned
installation later created an immutable UI ConfigMap, supply that exact
`configmap-created` JSON receipt and its independently recorded SHA256 using
`--console-web-code-receipt` and `--console-web-code-sha256`. Keep both outside Git.
The helper verifies namespace, owner, UID, immutable content and owner references;
a familiar name or owner label is insufficient. Other objects still require the
bootstrap ledger. A missing/mismatched receipt stops configuration before changes;
inspect the original UI update records rather than editing the bootstrap ledger.
Current context/permission configuration and state/credential mounts are retained.
This adds receipt verification, not permission to activate a busy installation.

Legacy drivers need the reviewed native artifact lock in
`IDENTITY_DEMO_ARTIFACTS` before enabling profiles. The existing `update-console`
action adds its read-only public projection, preserving state and credential
mounts. Existing projections retain their exact path and contract. Do not widen
the image allowlist to bypass a rejected profile configuration.

### Retire unused contexts for maintenance

This is a human-installer operation for a planned image upgrade, not normal pool
replenishment. Deploy the reviewed console guards first. Preserve a current
application backup, then stop the exact workers, observe process exit/lease
expiry and disable automatic scheduling. Never create a business run merely to
make an unused identity eligible for deletion.

Copy [the private review template](examples/identity-demo-unused-retirement.example.json)
outside Git. Replace its profile with the exact installed profile; use one fresh
`uuid4().hex` reservation and the exact minimal context from its provisioning
receipt. Record current driver/code/Sandbox/workload/supervisor UIDs. For static
identity mode, `registration` is the recorded ClusterStaticEntry UID; for
controller mode it must be `null`. Do not switch identity modes to make a review
pass. `pool_context_sha256` hashes the exact stored `console_pool_items.context`
text for that workload, obtained by a read-only operator inventory. Names and
owner labels alone are insufficient.

The three required evidence files are owner-only files outside Git:

| Evidence | Required content |
|---|---|
| Namespace creation | The original three Namespace creation identities, not a later no-op access check |
| Backup | Same-installation `backup-data` manifest; the helper verifies restored local copies |
| Worker fencing | `schema_version: 1`, exact `profile` and `runtime`. For `cluster`, two `workers` records with `name`, Deployment `uid`, `lease_uid`, `holder`; actual zero replicas/Pods and expired matching leases are rechecked. For `local`, two `services` records with the installed launchd `label` and previous `pid`; both must be unloaded and absent on the same Mac |

An optional `disposable_workspace` evidence entry may name an existing
receipt-proven synthetic scratch file. Without it, workspace storage is retained.
Disposable scratch binds to the original pool item, not the new maintenance
reservation. Apply and reconciliation both verify its exact PVCs are absent before
completing.

The helper does not remove historical volumes. Each evidence entry has the
absolute `path` and separately recorded `sha256` shown in the template. Keep the
review file itself private and record its SHA256. A changed file stops the action.

Load the same configured source/private environment used by the installation.
Inputs below are the existing installer credentials, context and completed
review; no human password or installer kubeconfig enters a runtime Pod.

```bash
export DEMO_UNUSED_REVIEW="$DEMO_PRIVATE_ROOT/unused-retirement-review.json"
export DEMO_UNUSED_REVIEW_SHA256="$(shasum -a 256 "$DEMO_UNUSED_REVIEW" | awk '{print $1}')"
unused_retirement_args=(
  --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER"
  --credentials-file "$DEMO_FIXTURE_CREDENTIALS" --cli "$DEMO_OPENSHELL_CLI"
  --cli-config-dir "$DEMO_CLI_CONFIG" --context-file "$DEMO_FRESH_CONTEXT"
  --review-receipt "$DEMO_UNUSED_REVIEW" --review-sha256 "$DEMO_UNUSED_REVIEW_SHA256"
)
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_execution_setup.py \
  --action retire-unused "${unused_retirement_args[@]}" \
  --output-dir "$DEMO_PRIVATE_ROOT/unused-plan-01"
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_execution_setup.py \
  --action retire-unused "${unused_retirement_args[@]}" \
  --output-dir "$DEMO_PRIVATE_ROOT/unused-apply-01" --apply
```

Expected: the plan changes no durable state. Apply atomically quarantines the
unused identity, uses the existing guarded retirement once, verifies resource
absence and marks the context retired. Context/permission mappings and business
runs/actions remain retained. Operator events use `maintenance:<reservation>`;
they are not synthetic business runs. There is no runtime HTTP action for this.

On a failure, preserve receipts and the quarantine. Inspect the same resources;
never clear a reservation or replay an uncertain delete automatically. Once exact
Sandbox/Pod absence and registration absence (or verified controller
inactivation) are established, this explicit reconciliation
only finalizes durable state:

```bash
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_execution_setup.py \
  --action retire-unused "${unused_retirement_args[@]}" --resume-unused-retirement \
  --output-dir "$DEMO_PRIVATE_ROOT/unused-reconcile-01" --apply
```

If a resource remains, reconciliation stops and performs no native mutation.
An operator must review that exact object before any separate guarded cleanup.
After all old contexts are retired, the existing cluster `automatic-enable`
stage accepts `--resume-retired-pool`: it requires an empty native target, only
retired durable inventory and verified scoped workers. It preserves history and
creates fresh identities; it never treats an old database as an initial empty
installation. Fresh installations continue to use the original activation path.

### Review failed context creation

A failed preparation remains quarantined even if its command returned an error.
Stop scheduling, fence both workers and verify a current application backup
before reviewing its original reservation, native identity and resource receipts.
Pair authenticated native inventory with exact Kubernetes identity/dependency
checks; an empty search or a masked NotFound response alone proves nothing.

If creation is independently confirmed absent, the installer may retire only its
capacity entry through the shared guarded transaction. The original quarantined
preparation, target and failure receipt remain unchanged, with an additional
correlated absence confirmation. It never repeats creation or native deletion.
If a native object exists, keep it quarantined for reviewed retirement or recovery;
do not clear the reservation to make capacity available.

### Reviewing a proved dispatch rejection

This is an explicit installer decision, not automatic reconciliation or a runtime
API. Use it only after reviewing the original terminal response, the exact pinned
backend's no-commit contract, a consistent independent backend snapshot, and
credential/authorization cleanup evidence. Missing project metadata or an empty
search alone is insufficient. Unknown transport outcomes remain blocked.

Keep the review and all evidence in private files outside Git. The review schema
is version 1 and binds `decision: rejected_without_commit`, `installation_id`,
`owner`, `expected_server`, the exact human `reviewed_by`, `run_id`, `action_id`,
`execution_id`, `action_digest`, `driver_uid`, `jira_uid`, and the digest-pinned
`jira_image`. Its `evidence` object contains exactly `terminal_rejection`,
`no_commit_contract`, `backend_snapshot`, and `credential_cleanup`; each is an
object with the private file `path` and its exact `sha256`. The receipt records
an operator-reviewed conclusion; the command does not derive that conclusion
from hashes or claim that a scanner approved it.

Inputs: the existing `demo_exec` function, the installation's private environment,
and the reviewed receipt/hash. Plan first with a new output directory:

```bash
demo_exec --action review-dispatch-rejection \
  --review-receipt "$DEMO_REJECTION_REVIEW" --review-sha256 "$DEMO_REJECTION_SHA256" \
  --output-dir "$DEMO_PRIVATE_ROOT/rejection-review-plan-01"
```

Expected: a read-only review plan with the original action still `unknown`.
Inspect the plan and retained evidence, then record that exact decision:

```bash
demo_exec --action review-dispatch-rejection \
  --review-receipt "$DEMO_REJECTION_REVIEW" --review-sha256 "$DEMO_REJECTION_SHA256" \
  --confirm-rejected-without-commit \
  --output-dir "$DEMO_PRIVATE_ROOT/rejection-review-apply-01" --apply
```

Expected: only that closed run's exact unknown action becomes `failed`, with one
new audit event linking the review hash. Payload, approval, execution identifier,
original deadline, previous audit and single-use identity remain preserved.
The command does not replay dispatch or clear console cleanup recovery. Finish
the existing trusted cleanup review only after verifying cleanup independently.
On any mismatch or lost reply, stop and inspect durable state; never repeat the
review or edit the database to force a pass. Runtime ServiceAccounts receive no
new authority. Verify the resulting audit event and cleanup state before closing
operator recovery.

### Updating the isolated cluster workers

Use the existing `console-runtime-prepare --console-runtime-stage
update-workloads` stage with the original namespace/configuration receipts, the
**latest** worker receipt and its hash, a completed runtime publication receipt
and its hash, and the verified private gateway receipt. Plan first; use a new
private output directory and `--apply` only when the candidate is idle and no
write is uncertain. The stage refuses changed UIDs or unrecorded worker edits.

It dry-runs the patches, stops the two workers, observes Pod exit and expiry of
their exact leases, and then updates only the recorded image and gateway
observation input. Worker state volumes remain intact. Its output becomes the
next worker receipt; retain all earlier receipts and rollback definitions.
Verify readiness and a fresh protected workflow afterward. A failed/uncertain
update requires inspection of the saved pending receipts before any recovery;
never restart the operation blindly or restore an older database over newer
history. This stage does not hand over the existing presentation installation.

If the approved SPIRE bundle changes, workers stop admission rather than gaining
access to serving keys or silently accepting different trust. An installer can
add `--refresh-sender-trust` to this idle update, supplying the original
`--ledger` and `--console-ledger-sha256`. This uses the existing owned trust
refresh helper, preserves the issuer PVC, waits for its rollout, and replaces
only the exact recorded immutable public observation using UID/version
preconditions. The new worker input and receipt bind that observation. Shared
SPIRE is read, never changed. An interrupted maintenance stays stopped for
operator reconciliation; retain its pending receipts and private before-state.
This is guarded installer maintenance. To opt in to automatic public CA refresh,
add `--enable-public-trust-refresh` to that same update with
`--refresh-sender-trust`. The stage creates a public-only Istio `-cacert` Secret,
name-scoped coordinator permissions and a fail-closed admission policy, enables
Keycloak's native 60-second HTTPS reload, and pins the approved source/target
identities in the immutable observation. No serving-key or SPIRE-write access is
granted. Future normal bundle changes reconcile while the execution lane is
closed, followed by a 210-second projection/reload wait and a fresh comparison.
A source/target substitution or uncertain update remains blocked for review.

Retain exact before-state and created-object receipts for rollback. Keep the
separate listener CA Secret until its current roots have been copied back to the
original listener and the effective gateway trust has been inspected; deleting
it prematurely can restore stale fallback trust. Disable automatic refresh only
during a guarded idle worker update, preserving pending decisions and history.

Parallel installations also need distinct Authorino lookup keys: its host index
is shared across namespaces. New native-route rendering keeps the broker's
private HTTP host stable but sets a namespace-specific policy host through
Envoy's trusted `check_settings.context_extensions`. User headers cannot select
this key. Host linkage is now a readiness gate; `HostsNotLinked` is not ready
even when discovery or a static gateway inspection passed. See
[Authorino host lookup](https://docs.kuadrant.io/dev/authorino/docs/architecture/).
Envoy marks this map sensitive and redacts its values in admin dumps
([upstream definition](https://github.com/envoyproxy/envoy/blob/v1.35.0/api/envoy/extensions/filters/http/ext_authz/v3/ext_authz.proto#L449)).
Inspection therefore requires the exact receipt-backed, unchanged filter source,
the expected map on both effective listeners, and no more-specific route override.
A redacted value alone never passes. The complete filter inventory and gateway
process are checked before/after inspection; real protected requests and denials
remain required acceptance evidence. This relies on the trusted platform applying
the recorded configuration, not on recovering sensitive values from its dump.

For an existing, receipt-proven legacy host collision, the installer can add
`--isolate-private-authorizer` to the idle worker update. It reviews and patches
only the owned AuthConfig host and the two matching Envoy mediation settings,
waits for host linkage, and captures fresh effective TLS/filter/context evidence
before updating the private worker receipt. Authentication, exact approval,
HTTP routing and other installations remain unchanged. Failed or interrupted
repair leaves workers stopped for reconciliation; it never falls back to the
colliding shared host. The current status table above lists the verified boundary and remaining release gates.

If both host patches completed but worker activation did not begin, the same
stage supports `--resume-worker-update "$DEMO_RECOVERY_MANIFEST"` and
`--resume-worker-update-sha256 "$DEMO_RECOVERY_SHA256"`. An installer first reviews
the saved evidence and pins it in a private JSON object with
`kind: private-host-update-recovery-v1`, the exact installation `profile`, and a
`files` mapping. Its keys are `before`, `plan`, `idle`, `proofs`, `stop0`, `stop1`,
`AuthConfig` and `EnvoyFilter`; each value contains an absolute private `path`
and its `sha256`. These refer to the original worker before-state/plan, idle
history, prior lease proofs, and completed stop/host-patch receipts. Keep them
outside Git. This is an installer recovery input, never a runtime permission.

Plan into a new private output directory before applying. Recovery checks the
original worker receipt, reviewed image, unchanged inputs/history, exact stopped
workers and expired leases. It observes the completed gateway patches and full
effective TLS/filter configuration without repeating them. It refuses recovery
if an input-update or worker-start operation may already have begun. On any
mismatch, keep the candidate stopped and inspect the retained evidence; do not
edit receipts, replay an uncertain patch, or restore an older database. Successful
activation still requires fresh worker readiness and protected-flow acceptance.

An idle worker update may also use `--refresh-adapter-code`, with the exact
original application `--ledger`/`--console-ledger-sha256` and completed private
configuration receipt. It changes only the fixed catalog guard and Jira action modules in a new
immutable ConfigMap and the receipt-proven adapter's code reference. The old map,
application settings, keys and data remain intact. Plan first; both workers must
be fenced before activation. A collision, drift or incomplete adapter rollout
leaves workers stopped for inspection. Pending changes are never blindly replayed.

The staged catalog correction authenticates an SSE GET before returning HTTP 405
with `Allow: POST`; it does not open an SSE session or permit tool execution.
This follows the [MCP transport specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#listening-for-messages-from-the-server).
At the start of native execution, a discovery-only reconciliation race may be
observed for up to 30 seconds. Each observation revalidates the exact gateway
and security configuration. Policy, trust or process drift still fails immediately;
no tool call, claim or mutation is repeated, and the original run deadline is
unchanged. Protected-read and permission-denial acceptance passed after these corrections; see the current status table above for remaining gates.

Restricted binary-build publication needs the approved registry, RPM and Python
download destinations. Resolve their addresses from the cluster network before
preparing build-only CIDRs; workstation DNS can select a different CDN edge.
Static IP allowlists can become stale. Prefer an existing platform-approved
egress proxy or mirror where available. On a denied download, retain the failed
Build, revalidate the exact approved destinations and use a separately recorded
publication attempt. Never open unrestricted egress or silently retry a submission
whose result is unknown. The publication status stage removes only the recorded
temporary build policy after a confirmed terminal Build; failed evidence remains.

## Legacy local runtime compatibility

The required Setup guide runs both workers on OpenShift. This section is only
for existing macOS/launchd worker installations. It is not needed for a fresh
cluster runtime, requires an awake workstation and has separate credentials.
Never run both runtimes against the same execution lane.

### Prepare the workflows once

The connected installer prepares both synthetic projects before console activation.
A missing project is a setup failure, not a valid empty search result. If an older
installation lacks OPS or SERVICE, use `provision-project --project OPS` (or
`SERVICE`) through `demo_exec` below, with a new private output directory: plan
first, inspect, then apply only while the driver is quiescent. This helper can
create synthetic seed issues; include them in any authorized issue budget.
Use `--project-only` when the reviewed recovery calls for an empty synthetic
project and no seed issues. It preserves other project data and does not change
permissions. Default installation still includes the supplied synthetic seeds.
If a dispatch is unknown, reconcile it first; project creation cannot clear an
uncertain write and the helper must not bypass that stop.

Use Bash for the command blocks below, which use Bash arrays. Inspect the
generated private `operator-inputs.env` before sourcing it. Keep
`IDENTITY_DEMO_CONFIG` set to the rendered installation profile and
`IDENTITY_DEMO_ARTIFACTS` set to the matching artifact lock on every command.
Pass `--inference-config` to the connected installer so the generated environment
retains the validated inference-file path; otherwise add its private path before
installing the user services. Shell exports alone are not inherited by launchd.

Seed the four workflow/role slots once before starting the services. Automatic
preparation later maintains two ready contexts per slot. Native workspaces
and SERVICE/OPS already exist after the connected installer; do not repeat those
completed stages. These commands use the generated private environment. Choose
four never-used suffixes, at most three alphanumeric characters; the example
suffixes must not be reused after a failed or consumed provision.

```bash
export PYTHONPATH=scripts/identity_demo:tests/identity_demo
set -e
export DEMO_BATCH_DIR="$DEMO_PRIVATE_ROOT/console-initial-01"
mkdir -m 700 "$DEMO_BATCH_DIR"
# Helpers pass file paths, not secret values. Every invocation has a new output directory.
demo_exec() {
  "$DEMO_PYTHON" scripts/identity_demo/identity_demo_execution_setup.py \
    --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
    --credentials-file "$DEMO_FIXTURE_CREDENTIALS" \
    --cli "$DEMO_OPENSHELL_CLI" --cli-config-dir "$DEMO_CLI_CONFIG" "$@"
}
demo_context() {
  demo_exec --action provision --role "$1" --suffix "$2" \
    --output-dir "$DEMO_BATCH_DIR/context-$2-$DEMO_BATCH_PHASE" ${DEMO_APPLY[@]+"${DEMO_APPLY[@]}"}
}
demo_register() {
  demo_exec --action register-driver --workflow "$1" --project "$2" \
    --console-enabled --presenter-subject "$DEMO_PRESENTER_SUBJECT" \
    --output-dir "$DEMO_BATCH_DIR/register-$1-$DEMO_BATCH_PHASE" \
    "${DEMO_CONTEXT_FLAGS[@]}" ${DEMO_APPLY[@]+"${DEMO_APPLY[@]}"}
}
DEMO_BATCH_PHASE=plan
DEMO_APPLY=()
demo_context triage z1
demo_context reader zr
demo_context triage zs
demo_context triage zi
```

Stop on any failure. Inspect the private plans for exact target, owner, role and
unused names. Then create only those contexts:

```bash
DEMO_BATCH_PHASE=apply
DEMO_APPLY=(--apply)
demo_context triage z1
demo_context reader zr
demo_context triage zs
demo_context triage zi
```

Expected: four successful provisions with distinct `context.private.json` files.
On an uncertain create, stop and inspect; do not choose a new suffix to hide the
failed attempt. The technical reference describes exact-context recovery.

Register the fixed workflow mappings. Run the next block first with `plan`,
inspect results, then repeat it with `apply` and `DEMO_APPLY=(--apply)`:

```bash
DEMO_BATCH_PHASE=plan
DEMO_APPLY=()
DEMO_CONTEXT_FLAGS=(--context-file "$DEMO_BATCH_DIR/context-z1-apply/context.private.json" \
  --context-file "$DEMO_BATCH_DIR/context-zr-apply/context.private.json")
demo_register cve TEST
DEMO_CONTEXT_FLAGS=(--context-file "$DEMO_BATCH_DIR/context-zs-apply/context.private.json")
demo_register service-request SERVICE
DEMO_CONTEXT_FLAGS=(--context-file "$DEMO_BATCH_DIR/context-zi-apply/context.private.json")
demo_register incident-triage OPS
```

`DEMO_PRESENTER_SUBJECT` is the fresh Analyst's exact subject from the generated
private operator environment, not a username. It explicitly permits Settings
preparation; Viewer membership never grants this action. The old
`service-request` identifier is the Remediation change request workflow. Registration
must complete while idle, before presentation; it rolls the web driver and
requires a new browser login. Never share credentials from that environment.

Registration and UI code updates roll the driver while idle and require fresh
browser login. Register all initial mappings before presentation. Do not execute
a legacy browser rehearsal and the coordinator against the same installation
at the same time.

#### Install persistent gateway configuration

Inputs: the configured source copy, generated private environment, current catalog
credential and an idle installation. Use the existing helper defined above:

```bash
demo_exec --action gateway-install \
  --catalog-credential-file "$DEMO_CATALOG_CREDENTIAL" \
  --output-dir "$DEMO_PRIVATE_ROOT/gateway-plan-01"
# Review the exact owned resources and policy changes in the private plan.
demo_exec --action gateway-install \
  --catalog-credential-file "$DEMO_CATALOG_CREDENTIAL" \
  --output-dir "$DEMO_PRIVATE_ROOT/gateway-install-01" --apply
```

Expected: admission/readiness checks pass and
`gateway-install-01/persistent-gateway.receipt.private.json` is created. The
existing gateway now keeps stable configuration; user/workload/run/project,
certificate binding, expiry/cancellation and exact approval remain live checks.
A partial or uncertain installation stops here: retain its receipts, do not
repeat creation or bypass a collision. Review before resuming or rolling back.

Add these **path/settings values** to the private operator environment before
staging the services. Keep the environment mode 0600; do not store it in Git:

```bash
export DEMO_GATEWAY_MODE=persistent
export DEMO_GATEWAY_RECEIPT="$DEMO_PRIVATE_ROOT/gateway-install-01/persistent-gateway.receipt.private.json"
export DEMO_POOL_MODE=automatic
export DEMO_PREPARER_CLI_CONFIG="$DEMO_PRIVATE_ROOT/cli-config-preparer"
export DEMO_PREPARER_MANAGEMENT_PORT=18444
```

The coordinator keeps its own profile and loopback port 18443. The preparer
initializes a separate verified-TLS profile on 18444, using `DEMO_RUNTIME_CA`.
Keep both directories private and distinct. Never disable TLS to resolve a
profile, trust or port mismatch.

### Start the trusted services

Save the reviewed paths-only environment outside Git, mode 0600; private root
mode 0700. Set `DEMO_OPERATOR_ENV_FILE` to its absolute path and source it.
Credentials stay in the referenced private files. From the private configured example directory:

```bash
export DEMO_OPERATOR_ENV_FILE=/absolute/private/demo/operator-inputs.env
source "$DEMO_OPERATOR_ENV_FILE"
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_console_launchd.py \
  --action plan --environment-file "$DEMO_OPERATOR_ENV_FILE" \
  --private-root "$DEMO_PRIVATE_ROOT"
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_console_launchd.py \
  --action install --environment-file "$DEMO_OPERATOR_ENV_FILE" \
  --private-root "$DEMO_PRIVATE_ROOT"
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_console_launchd.py \
  --service preparer --action plan --environment-file "$DEMO_OPERATOR_ENV_FILE" \
  --private-root "$DEMO_PRIVATE_ROOT"
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_console_launchd.py \
  --service preparer --action install --environment-file "$DEMO_OPERATOR_ENV_FILE" \
  --private-root "$DEMO_PRIVATE_ROOT"
```

Plans precede each service installation. These are user services, with new source
snapshots under protected private storage. They do not install a new cluster
operator. The source labels are `org.example.agent-security-console` and its
`-preparer` service. Do not also run duplicate foreground workers. Source changes
need explicit idle service restaging; changing this checkout does not update a
previous immutable snapshot. To activate changed source while idle, first verify
both existing service definitions refer to this installation's private environment
and root. Retain their rollback paths, uninstall only those exact owned services,
then repeat plan/install from the updated configured source. Stop/start alone
continues to use the previous immutable bundle; never overwrite a different agent.

Check service status with the same flags and `--action status`, adding
`--service preparer` for that service. `--action stop`, `start` and `uninstall`
control that exact local user service. Stop only while idle and preserve recovery
receipts. A sleeping host or expired operator credential can make the UI offline.
`loaded` confirms only service registration, not a healthy worker. Require the
coordinator and preparer to be online, then enable the verified automatic pool
below. Filling a slot does not require waiting for the entire pool. If a
loaded service stays offline, inspect its private `console-worker.launchd.*.log`
or `console-preparer.launchd.*.log` before restarting; preserve the failure logs.
A private operator-login file is optional. Without one, renew the selected
kubeconfig interactively with your approved `oc login` procedure before it
expires; never add passwords to this repository or a command history.

#### Enable the automatic warm pool

Run after the two services are healthy and the preparer profile exists. This
explicit preflight verifies gateway configuration, profile separation, known
native contexts and capacity before changing scheduling mode:

```bash
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_presentation.py \
  --action automatic-enable --kubeconfig "$DEMO_KUBECONFIG" \
  --expected-server "$DEMO_SERVER" --credentials-file "$DEMO_FIXTURE_CREDENTIALS" \
  --driver-credentials-file "$DEMO_DRIVER_CREDENTIALS" \
  --cli "$DEMO_OPENSHELL_CLI" --cli-config-dir "$DEMO_PREPARER_CLI_CONFIG" \
  --coordinator-cli-config-dir "$DEMO_CLI_CONFIG" \
  --management-port "$DEMO_PREPARER_MANAGEMENT_PORT" \
  --gateway-receipt "$DEMO_GATEWAY_RECEIPT" \
  --output-dir "$DEMO_PRIVATE_ROOT/automatic-enable-01"
```

Expected: `automatic_pool_enabled: true`. Settings reports a target of **eight
ready contexts**, two each for CVE Triage, CVE Reader, Incident and Remediation.
The total managed cap is **12**, including preparation, allocated, consumed,
retiring and quarantined contexts. Capacity shortages pause preparation; they do
not discard evidence or exceed the cap. A failed preflight changes no scheduling
mode. Inspect the exact failed prerequisite rather than repeating installation.

When migrating an existing installation, retire only independently verified closed
identities first. Supply their original private context files using repeated
`--retired-context-file` arguments. The helper checks exact sandbox, Pod and
registration absence; the driver checks closed runs and records the receipt.
Never declare a live or uncertain identity retired just to free capacity.


## Onboard another use case

Jira remains the supported cluster integration. The synthetic document connector
is an automated proof of the shared controls, not a delivered document service
or evidence of a complete non-Jira installation.

| Shared mechanism | Integration responsibility |
|---|---|
| User/workload binding, ownership, deadline and cancellation | Trusted mapping from the actual tool request to its resource/action |
| Exact consent and atomic execution claim | Strict schema, normalized effectful payload and fixed backend |
| Credential-release ordering and uncertain-write stop | Scoped backend credential handling and independently verified outcome |
| Correlated audit and durable recovery | Connector-specific result references and reconciliation evidence |

1. **Define the effect.** Specify permitted reads and writes, resource identifiers,
   strict tool inputs, a fixed destination and independently observable results.
2. **Register the connector.** Add a reviewed `ConnectorContract` to
   `supported_connectors()` in `identity_demo_connector.py`. The registry cannot
   load modules or destinations from model output or requests. Unknown integration
   identifiers and tools fail closed. Change the schema/contract version when its
   authorization semantics change.
3. **Map authority.** Define user/workload roles and resource scope. Consent never
   supplies missing authority. Bind approvals to connector, backend, tool, schema,
   resource and normalized payload. Existing Jira digests retain compatibility;
   immutable run-contract records prevent their reuse under another connector.
4. **Define compatible capacity.** Approve the workload/supervisor images,
   namespace, ServiceAccount, sandbox policy and identity/issuer contract. Map each
   workflow to that profile and its allowed resource scope. A ready sandbox has
   no user grant; allocation freezes its run-specific binding and original deadline.
5. **Prove the boundary.** Exercise actual shared persistence/authorization code:
   allowed read, exact approval, denied user/workload/resource, changed payload,
   wrong connector/schema, competing claims, cancellation, expiry and uncertain
   outcome recovery. Verify the real backend independently before enabling it.

Do not build a universal credential proxy. A new backend still needs its connector,
policy mappings and acceptance tests. No model-selected credentials, arbitrary URL
routing or approval reuse across backends is supported.

### Profile pool compatibility

Profile mode is additive and opt-in. It does not reinterpret legacy contexts.
The prepared contract fingerprints images, namespace, ServiceAccount, isolation
policy, workload permissions and identity/issuer inputs. A context must match
that fingerprint and pass fresh native-identity/policy checks before allocation.

Compatible workflows can share Triage capacity; Reader capacity remains separate.
The defaults are six Triage and two Reader contexts, with at most 12 non-retired
entries including preparing, allocated, retiring and quarantined states.
Qualify profile compatibility on an owned candidate before migrating another installation.
Pool availability cannot grant user, workload or resource permission.

Profile `tools` and `write_actions` must match the registered connector's reviewed
action labels for that workload role. They do not create permissions. Unsupported
action lists, resource scopes and role/connector combinations fail configuration
before activation. New connectors declare these labels before using profile pools.

An authenticated operator may revise targets and trusted workflow/resource mappings
only while execution, preparation and recovery are idle. Each revision is retained;
existing runs keep their original binding and deadline. A profile's security
fingerprint cannot change while any non-retired context still uses it, including
an ambiguous or quarantined reservation. Retire those contexts through the guarded
path before approving a replacement profile. Do not edit SQLite records directly.

The compatibility field `project` holds one trusted resource scope per workflow
mapping. Jira interprets it as a project key; another connector must validate its
own resource identifier. Multiple-resource authorization is not implemented by
placing comma-separated values in this field: it needs a reviewed connector
contract and corresponding scope/approval tests.

Keep historical mappings immutable. Disable scheduling and establish an idle,
certain execution state before changing modes. Retire obsolete unused contexts
through the receipt/UID-guarded path; never relabel them as a different profile.
Rollback must use a compatible image and preserve history, consumed identities
and quarantine decisions. Never restore an older database over newer records.

### Permission changes

Protected calls check live run closure and cancellation as well as token validity.
User role claims can remain valid until their bounded authorization expires;
changing a Keycloak role is not a promise of immediate revocation of issued tokens.
Use explicit run cancellation for urgent revocation. Cancellation stops future
authorization and cannot undo a backend operation already dispatched. Establish
an uncertain write outcome before another execution; do not replay it blindly.

## Platform administrator preparation

The coordinated installer does not install or upgrade shared controllers. These
optional commands require the developer/operator Python environment described in
[Development](../GETTING-STARTED.md#local-environment). They produce the approved
identity foundation and public inputs for Setup stage 1; they are not extra
application installation stages. Keep all private profiles and receipts outside Git.

### 1A. Prepare or verify the security foundation

Before cluster commands, copy the [paths-only environment template](examples/identity-demo-inputs.env.example)
outside Git, replace its placeholders and review it before sourcing. Set these
inputs from the approved target; keep existing values as later stages add paths.

| Input | Required value |
|---|---|
| `DEMO_SERVER` | Exact approved Kubernetes API URL |
| `DEMO_PLATFORM_KUBECONFIG` | Protected platform-administrator kubeconfig |
| `DEMO_KUBECONFIG`, `DEMO_INSTALLER_USER` | Separate non-admin installer kubeconfig and its authenticated username |
| `DEMO_PRIVATE_STORAGE` | Existing mode-0700 parent for connected-install outputs; may equal `DEMO_PRIVATE_ROOT` |
| `DEMO_PACKAGE_OUTPUT` | Existing mode-0700 parent for renders, builds and access receipts |

Set the directories explicitly in your private environment. Credentials stay in
mode-0600 files; environment variables contain paths or nonsecret identifiers.
Do not source an unedited template over values already created in stage 0.


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

<details>
<summary><strong>Platform administrator: plan and create a missing owned foundation</strong></summary>

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

</details>

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


## Installation checkpoint recovery

The launcher is create-only. `status` and `observe` read the original recorded
Build/Job UID. They never infer ownership from a name or label and do not submit
another attempt. Keep every original response, pending marker, private stage log
and source/image hash. A terminal rejection may be reconciled explicitly only
after checking the exact API object and proving that no mutation remains uncertain.

An existing bootstrap namespace requires `install.sh build --namespace-receipt
/absolute/private/original-namespace.json --namespace-receipt-sha256 <sha256>`.
That receipt must be the original creation response, not a newly captured object.
For an approved new attempt, choose a new private output directory and
`--attempt-id <short-id>` only after reconciling the preceding submission. These
flags do not authorize overwriting an existing BuildConfig or adopting a namespace.

A failed tokenless planning Job can be replaced only after its terminal state,
original UID and absence of API credentials are established. Preserve its logs
and receipt, use UID/resourceVersion deletion preconditions, and record the new
creation response. Do not delete a running parent Job, claim, Lease or PVC to make
an uncertain installation appear fresh. The build/application parent owns its
lease and fences child process groups if ownership is lost.

Installation rollback disables scheduling first, waits for a certain idle state,
then selects a compatible retained image/configuration. It preserves new history,
approvals, consumed identities and quarantine. Never restore an older database
over current records or install expired certificates. A candidate must pass the
functional gates before the presentation URL is switched.

## Managed certificate maintenance commands

These optional commands use the private operator/developer environment. Daily
browser use needs none of these workstation services.

### Renewal, loading and CA rollover

Legacy installations use the original evaluation certificates until explicitly
migrated. Managed mode delegates three leaves to the approved cert-manager issuer:

| Certificate | Purpose | Replacement loading |
|---|---|---|
| `fixture-openshell-server-tls` | TLS for native management and sandbox connections | OpenShell's existing file watcher |
| `fixture-openshell-client-tls` | OpenShell peer-client TLS | Projected file; each new peer channel reads current credentials |
| `fixture-mcp-bound-mutual` | Protected MCP listener's server identity | Envoy SDS |

The requested validity is 30 days with renewal seven days before expiry and a
new ECDSA key each time. Issuers can impose different limits; the helper checks
actual issuance. Renewal under the approved CA needs no native rebuild or routine
operator approval. It does not extend user sessions, run deadlines or approvals.
SPIRE's SVID lifecycle remains separate.

`fixture-openshell-client-ca` holds public application trust separately from the
leaf Secret, permitting a reviewed CA-overlap window. MCP workload authentication
uses the separate `fixture-mcp-bound-mutual-cacert` SPIRE bundle. Never replace that
bundle with the MCP server's issuer CA.

Inputs: the approved private certificate config from Setup, current profile,
installer kubeconfig and a new external output directory. Observe status and the
**actual served certificates**, without starting a demo:

```bash
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py certificate-status \
  --installation-profile "$IDENTITY_DEMO_CONFIG" \
  --managed-certificate-config "$DEMO_CERTIFICATE_CONFIG" \
  --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --verify-certificate-loading \
  --output-dir "$DEMO_PRIVATE_ROOT/certificate-status-01"
```

Expected: `ready: true`, verified Certificate revisions and expiry/renewal times.
The approved issuer UID is checked against your private configuration.
The loading receipt matches actual OpenShell/MCP server fingerprints to issued
leaves. A new native mTLS connection checks the renewed client credential; the
consumer Secret reference is pinned. A single-replica installation does not
exercise a peer-to-peer RPC. The minimal native image needs no diagnostic tools. A Secret update or Ready Pod alone is not
proof of loading. `mutual_tls_verified` describes that diagnostic handshake only;
the MCP listener observation checks server TLS, while a real protected workload
request proves its separate SPIRE-bound client authentication. Root expiry within
45 days is reported for rollover planning.
If verification fails, retain the receipt, inspect issuer/Certificate events and
consumer logs, and keep execution stopped. Never bypass hostname/chain checks.

Workers mount only the three **public** leaf PEMs. They gain no serving-key,
signing-key or deployment-mutation permissions. A healthy leaf in its renewal
window does not stop a ready workflow. Insufficient validity for the maximum
session/run bound plus five minutes, an invalid chain or unexpected identity
stops admission with an application-certificate diagnostic in the coordinator log.

#### Migrate an existing installation

1. Complete the approved-issuer gate in Setup. First enable the existing
   [public SPIRE trust isolation](identity-demo-reference.md#updating-the-isolated-cluster-workers)
   in its own guarded idle update if not already enabled; retain that completed
   worker receipt. Certificate migration requires its recorded separate public
   listener trust. Ordinary migration keeps the application CA byte-for-byte;
   a CA change is a separate operation.
2. The migration installer needs `get` and `patch` on `certificates/status`,
   restricted to the three names in the table above and the owned core namespace.
   Ask the platform owner for that named permission; no runtime ServiceAccount
   needs it. Preflight checks this before downtime and never falls back to admin.
3. Verify private database/configuration/key backups and exact rollback receipts.
   Confirm no execution, uncertain write or preparation remains.
4. Plan the existing [idle worker update](identity-demo-reference.md#updating-the-isolated-cluster-workers)
   with `--managed-certificate-config "$DEMO_CERTIFICATE_CONFIG"`, the original
   application `--ledger`/`--console-ledger-sha256`, and current worker/publication
   receipts. Use the new runtime image containing managed monitoring.
5. Review the plan, then apply that same maintenance stage in a new private output
   directory. It fences both workers, creates only the reviewed resources, verifies
   issuance and isolates OpenShell's public client trust. That initial trust-volume
   change causes one guarded OpenShell rollout. Ordinary leaf renewals do not.
6. Require live loading checks, fresh worker Leases, protected access and the
   permission/workflow checks before presenting. Existing unused identities and
   historical data remain retained; root-stable migration needs no native rebuild.

A valid legacy leaf can initially report Ready without a new issuance. Migration
therefore requests one explicit renewal through cert-manager's public `Issuing`
condition, the same operation used by [cmctl renew](https://cert-manager.io/docs/reference/cmctl/#renew).
It keeps the Secret and its UID, waits for verified issuance and key loading, and
journals the request once. Normal scheduled renewals need no operator request.

An interrupted creation, ambiguous patch or failed rollout stays stopped for
operator reconciliation. Do not replay the maintenance command over collisions.
Use the exact before-state, created UIDs and pending receipts to complete only
the remaining reviewed steps. Rollback fences scheduling first and restores
recorded worker/consumer specifications while retaining valid current leaves.
Never restore expired certificates or an older database over newer history.

#### CA rollover is separate

The CA issuer does **not** automatically rotate its signing CA. Follow the
approved PKI's lifecycle. In an idle owned candidate, distribute overlapping old
and new public roots to OpenShell client/peer trust, management profiles and all
native outbound trust stores **before** switching issuance. Keep SPIRE trust
separate. Use `native-repackage` when only public roots change and verified native
binaries remain compatible; no recompile is required for unchanged build contracts.

To repackage unchanged verified binaries, supply the original completed native
build receipt/hash, the same installation profile, and the reviewed **combined**
public outbound trust bundle (all required platform roots plus both application
roots). Build privately before following Setup's publication/admission stages:

```bash
"$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py native-repackage \
  --native-build-receipt "$DEMO_NATIVE_BUILD" --native-build-sha256 "$DEMO_NATIVE_BUILD_SHA256" \
  --installation-profile "$IDENTITY_DEMO_CONFIG" \
  --native-ca-bundle "$DEMO_OVERLAP_PUBLIC_TRUST" --engine docker \
  --output-dir "$DEMO_PRIVATE_ROOT/native-overlap-plan"
# Review, then use a new output directory and --apply to build the two images.
```

Expected: `compilation_performed: false`, followed after apply by verified
packaged binaries and a new receipt. A contract/hash mismatch stops this path;
do not reuse binaries compiled for a different installation. No cluster change
is made by repackaging. Publish and admit the reviewed images before switching
issuance; a file on the operator workstation does not update running consumers.

Then issue/verify new leaves, prove new management and protected connections, and
retire/replace only affected unused contexts under the existing guarded path.
Update pinned issuer/public-trust observations and worker inputs through reviewed
maintenance. Remove the old root only after all consumers use the new chain and
the overlap has ended. Verify both the accepted new path and rejection of retired
trust. Preserve the old CA's private recovery inputs until the PKI retention policy
allows removal. Unattended CA rollover and full production PKI acceptance are not
claimed by ordinary certificate-renewal acceptance.

OpenShift-issued Service certificates are a separate lifecycle. Keycloak can
reload its configured HTTPS files; the Python console, adapter and Jira launchers
load TLS at startup. Their replacement requires guarded idle restart and a fresh
served-certificate check. Updating those Secrets alone is insufficient.


## Pinned builder mirror

A registry mirror is an optional artifact-delivery input, not a different compiler.
The platform owner copies the exact Linux AMD64 Rust manifest recorded as
`builder_platform_digest` in `infra/openshell/native-build/inputs.lock.json` and
retains source/destination digest evidence. The upstream multi-platform index
remains pinned as `builder_base`. Never replace the image with a mutable tag or
an independently rebuilt lookalike.

Add `native_builder_image` to the versioned installer configuration only after
verification. Its canonical `registry/repository@sha256:...` must use that exact
AMD64 manifest digest. An internal mirror must be in this installation's bootstrap
namespace as `fixture-native-builder-base`; the planner grants only named image
layer reads to the required owned ServiceAccounts. External approved mirrors need
their platform-reviewed pull access. The installer does not export a human login,
copy the workstation Docker configuration into Pods, change a shared pull Secret
or install a cluster-wide mirror rule.

Customer installations can use their existing approved registry process. A
one-time public-image copy from an authorized workstation is also an artifact
preparation option; it is not an ongoing runtime dependency. Private registry
credentials stay outside the source package and must not appear in logs or receipts.

### Updating a worker image through OpenShift Builds

The existing `console-runtime-cluster-build` helper accepts the same optional
`--publication-id r2` convention as the publication helpers. Use a new private,
configured source copy and its completed provider-configuration receipt. The
suffix selects a distinct owned BuildConfig/ImageStream, preserving the active
image and prior build evidence. The default installer still uses its fixed build
name; its scoped admission does not gain permission to choose arbitrary build
repositories. This optional maintenance action needs an authorized operator.

For a maintenance build after application isolation is active, supply the
existing `--publication-network /absolute/private/build-network.json` input.
Its version-1 `api_cidrs` and `https_cidrs` contain reviewed, bounded destinations;
include actual API endpoints after Service translation. The helper reuses the
publication policy validator and selects only the exact first Build Pod. DNS and
the internal registry remain separately scoped. It deletes this temporary policy
by UID after a verified terminal build; uncertain submissions retain it for
reconciliation. Runtime network permissions do not change. Do not disable the
application's default-deny policies to build an update.

Packaged tool/import verification must pass before using the resulting
`publication.receipt.json` with the existing guarded worker-update procedure.
A published image alone does not prove workflow acceptance. Native binaries need
no rebuild when only compatible Python or documentation changes are made.

### Public trust during a long installation

SPIRE may add or remove overlapping CA roots while native builds run. Before
recording trust and activating workers, setup reconciles only this installation's
public issuer/listener trust copies from the approved operator-managed bundle.
The existing helper verifies idle state, reviews all changes and applies exact
UID/version/data preconditions. It preserves managed serving certificates and
TLS verification, then waits for the owned issuer rollout. It requires no SPIRE
server execution or registration write permission. Unexpected ownership, an
uncertain update or failed verification stops setup for reconciliation.
