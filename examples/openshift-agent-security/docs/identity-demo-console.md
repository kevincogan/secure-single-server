<!-- SPDX-License-Identifier: Apache-2.0 -->
# Browser console operations

Install with the [quickstart](identity-demo-customer-quickstart.md) first. The
browser is the presenter interface. A coordinator and separate preparer run on
OpenShift with isolated profiles, scoped ServiceAccounts and durable state.
The authenticated Jira view also runs in the console. The install workstation
and local background services are not required for ongoing browser demos.
Local CLI operation remains an explicit compatibility/maintenance option.

## Recovery rule for an uncertain write

Do not repeat an action whose outcome is unknown. A trusted operator first checks
its original dispatch and independent backend state. An empty search alone does
not establish failure. A positively verified issue uses the existing exact-marker
and exact-field reconciliation path. A proved terminal rejection requires the
installer-only review procedure in the
[technical reference](identity-demo-reference.md#reviewing-a-proved-dispatch-rejection).
That procedure closes the original action as failed; it grants no new execution
and leaves cleanup review separate. Never restore an older database over current
history to remove a recovery stop.

## 1. Check the installed services

The [Setup guide, stage 3](identity-demo-customer-quickstart.md#3-start-the-openshift-services-and-automatic-pool)
installs both workers and activates the initial pool. Do not provision another
manual batch or run a local worker against this installation.

Inputs: the same private profile, installer kubeconfig, original Namespace receipt
and private-listener configuration receipt retained during setup. Load only your
reviewed paths-only environment; passwords remain in private files. From the
configured source root, define these existing-helper arguments:

```bash
export PYTHONPATH=scripts/identity_demo:tests/identity_demo
sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
cluster_console() {
  local stage="$1" output="$2"; shift 2
  "$DEMO_PYTHON" scripts/identity_demo/identity_demo_setup.py console-runtime-prepare \
    --console-runtime-stage "$stage" --output-dir "$output" \
    --installation-profile "$IDENTITY_DEMO_CONFIG" \
    --namespace-creation-receipt "$DEMO_NAMESPACE_RECEIPT" \
    --namespace-creation-sha256 "$(sha256_file "$DEMO_NAMESPACE_RECEIPT")" \
    --console-configuration-receipt "$DEMO_CONSOLE_CONFIG" \
    --console-configuration-sha256 "$(sha256_file "$DEMO_CONSOLE_CONFIG")" \
    --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" "$@"
}
cluster_console status "$DEMO_PRIVATE_ROOT/status-01"
```

Expected: `online: true`, a ready/preparing phase, automatic mode and per-slot
availability. A ready slot does not wait for all eight. On a failed observation,
keep the private output and inspect the worker's recorded UID, Pod events,
role-specific logs, projected-token access and Lease. Do not start a second worker
or delete a Lease to remove an error. A normal installer credential expiry affects
maintenance commands; runtime Pods use their own rotating tokens.

The setup helper already records requests/limits and owned quotas for the workers
and complete sandbox/supervisor budget. Do not reduce memory or increase the
managed cap from an idle sample. A full-capacity acceptance measured a transient
peak, not an exhaustive production sizing benchmark.

## 2. Maintenance and restart

Start only when Settings and the private status receipt show no running job,
preparation, uncertain write or shared recovery condition. Preserve a recent
verified backup and current worker/image/configuration receipts.

For worker restart or source/image/trust updates, use the existing
[guarded worker update](identity-demo-reference.md#updating-the-isolated-cluster-workers).
It verifies creation identities, stops the preparer before the coordinator,
fences both workers,
records rollback and preserves their state PVCs. Restore the recorded worker
specifications through that procedure; it leaves the recorded pool mode intact. Wait for the
replacement ready Pods and matching fresh Leases before accepting another demo.
A failed startup retains its checkpoint and quarantine for review.

`automatic-enable` is the **initial empty-pool** acceptance command; do not rerun
it over retained ready contexts after maintenance. Do not clear inventory, delete
a Lease or overwrite a database to make activation pass. The explicit
`--resume-retired-pool` path is only for an independently reviewed empty target
whose entire old inventory is durably retired.

Discovery credentials renew automatically while idle. Renewal retains at most two
valid credentials for overlap. If both slots are occupied, the coordinator waits
for a slot to expire and checks again; this read-only refusal does not require
operator review. Existing lifetime checks still stop new starts when too little
validity remains. An unknown result after a credential mutation continues to
require review and is never retried blindly.

Projected API tokens rotate automatically while Pods remain running. Native
management reconnection does not replay claims or mutations. With the Setup
guide's explicit public-trust opt-in, the coordinator also follows the recorded
operator-managed SPIRE bundle while idle. It can read/update only two public CA
copies; it cannot read the gateway's serving key or change SPIRE. Keycloak reloads
its truststore and Istio reloads its separate `-cacert` Secret using native TLS/SDS
mechanisms. No extra controller is installed.

During a normal CA update, admission pauses while those copies propagate and
reload (210 seconds, plus readiness checks). Wait for **Ready to start**. Discovery credentials can
still renew while trust admission is stopped. A replaced source/target identity,
changed policy, failed reload or uncertain mutation still requires operator
review. Preserve the pending receipt; never clear it to force readiness. Legacy
installations without the opt-in need the guarded installer trust refresh.

For an interrupted update, first inspect the private before-state, pending
operations and live identities. If the issuer is merely slow to become ready,
verify its rollout and the applied trust copies before completing only the
remaining recorded steps; never replay the whole update. A protected native read
is still required after maintenance. No worker can execute in the SPIRE server.

Direct CLI operation remains supported for reviewed maintenance and security
acceptance. Its management connections must have isolated profiles/ports, and
browser execution must be fenced when switching to direct-test mode. The
[optional CLI reference](identity-demo-reference.md#operator-cli-reference)
contains those commands and the legacy local-runtime procedure. Cluster browser
operation and historical Jira viewing do not require that local compatibility mode.

### Managed application certificates

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
  --installation-profile "$DEMO_INSTALLATION_PROFILE" \
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
  --installation-profile "$DEMO_INSTALLATION_PROFILE" \
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

## 3. Present the demo

Open `https://fixture-identity-driver-<core_namespace>.<route_domain>/` using the
values from the rendered profile. Sign in with the private synthetic Analyst or
Viewer credentials. In Settings, check coordinator readiness and prepared counts.
Only start when the relevant workload context is ready.

1. Select the workflow and, for CVE, Triage or Reader. The human Keycloak role
   and workload selection are separate.
2. Start one run. Watch identity verification, protected reads and assessment.
   Agent activity shows observed model/read events; the frozen CVE case has no
   live model activity. Security trace and decision audit show enforcement.
3. For live workflows, inspect model-informed content and bounded Jira findings.
   Incident triage includes a controlled TEST request denied with HTTP 403 from
   the OPS context. This is an expected project-isolation result.
   Access Jira opens an authenticated, run-scoped read-only view in this console
   and enforces the original run owner's access. It needs no local preview
   service. Existing legacy local installations use the optional compatibility
   procedure in the technical reference. Both modes admit only independently
   verified issue references.
4. Review the exact proposed fields. Approve only those fields. Analyst + Triage
   may create within the authorized project; Viewer or Reader must be denied.
5. Check the independently verified Jira outcome and audit. Access Jira opens the
   read-only issue view. A model proposal alone does not establish a successful write.
6. Wait for authorization/credential cleanup verification before another run.
   Subsequent sandbox retirement and replenishment can continue in the background. An uncertain
   write or cleanup stops for operator review; never resubmit it blindly.

Browser sessions renew within configured idle/absolute and Keycloak session
limits. Logout/revocation remain effective. Session renewal never changes the
original authorization deadline of a run. Cancellation closes driver authorization
and protected tool access immediately. Native delegated-token exchange may finish
during cleanup; the next execution waits for verified provider/credential
detachment. Do not describe this as instant removal of every credential.

## 4. Automatic replenishment and completed evidence

No presenter action is needed to refill the pool. Each run consumes a fresh
identity; the preparer replaces missing contexts automatically. Used identities
are never returned to the ready pool.

| Situation | What the presenter can do |
|---|---|
| Selected workflow has a verified context; execution lane and security gates are clear | Start while background replenishment or resource retirement continues |
| Selected workflow is depleted | Wait for **Preparing your next run** to become **Ready to start**; other ready workflows remain available |
| Another demo is executing or closing its authorization/credentials | Wait; only one demo executes at a time |
| Uncertain write or shared-security recovery | Operator review is required; no automatic write replay |
| A new context fails preparation | It is quarantined and counted toward capacity; other verified contexts remain usable unless a shared safety gate blocks them |

Settings shows ready/target counts by workflow, preparation progress, the managed
capacity limit and quarantines. Routine observations can retain a recent
successful readiness result while the coordinator finishes fresh checks before
execution. Startup, stale results, security failures and credential/trust
maintenance still pause starts. Preparing all eight ahead of a presentation reduces waiting; it does
not guarantee supply under unlimited demand or remove model/network latency.
This follows the [warm-pool pattern](https://agent-sandbox.sigs.k8s.io/docs/use-cases/examples/warmpool-quickstart/)
through the existing OpenShell helpers, without another pool controller.

After a run, open **Runs** or **Evidence**, select the completed run and inspect
its audit and exact outcome. **Access Jira** opens only the original owner's independently verified issue in
the authenticated console. Keep the console, protected adapter and Jira fixture
available; no local loopback preview is required for the cluster runtime. A new authorized sign-in can still
view its retained history; execution expiry does not erase records.

| Data | Retention |
|---|---|
| Newly created automatic-pool synthetic scratch | Removed only after verified retirement, exact ownership and Pod/controller/PVC-clone reference checks |
| Existing historical workspace volumes | Preserved |
| Driver/Jira databases, audit, approvals and issue references | Preserved outside sandboxes |
| Ambiguous operations and failed acceptance receipts | Preserved privately for review |

Legacy/manual batch preparation remains an operator fallback. To switch modes,
use the same presentation helper with `--action automatic-disable` during an idle
window, preserving its receipt. Do not change gateway mode until background work
has finished and the automatic scheduler is disabled. The original manual batch
plan remains available through `--action prepare --plan-file`; its full-batch
verification gates apply only in legacy mode.

## 5. Recovery and data preservation

An installer can retire a **verified unused** context for an image upgrade without
creating an artificial demo run. Use the
[reviewed maintenance procedure](identity-demo-reference.md#retire-unused-contexts-for-maintenance).
Workers must be fenced and scheduling disabled. The installer first creates a
durable quarantine; a failure or restart leaves execution blocked until exact
resource absence is reviewed. Reconciliation never repeats native deletion.
Retired identities remain unavailable even in legacy mode; history is preserved.
This operation is unavailable to browser users and runtime ServiceAccounts.

Direct CLI security probes use the same private operator transport as cluster
workers. Follow the [read-only probe procedure](identity-demo-reference.md#read-only-replay-certificate-renewal-and-containment-acceptance)
in a reviewed idle maintenance window; fence workers and pause automatic
preparation first. Restore browser operation only after verified cleanup. A
private API failure must not be worked around by reopening public operator routes.

Use a fresh release copy configured for the same provider using
[Setup stage 1B](identity-demo-customer-quickstart.md#1b-prepare-private-application-inputs)
when updating console code or services. Do not copy pristine template modules
over a configured installation: worker model evidence and console validation must
match. The console updater checks that contract before admission or mutation.
A mismatch requires the correctly configured source, not relaxed validation.
Preserve existing keys, application databases and private inputs; a code update
is not a fresh installation or a model-provider migration.

Keep private coordinator/preparer logs and exact stage receipts. Check run,
action, preparation and recovery state before any update. Never clear a lease,
used identity or safety reservation just to re-enable starts. Inspect the exact
owned resource and ambiguous outcome first. The execution helper's
`--action inspect-state` is read-only; its quiescent result is a prerequisite,
not authorization to delete data. Rollback must retain the driver and Jira PVCs,
keys, audit and identity tombstones. See [deployment recovery](identity-demo-reference.md).

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

### Common setup and presentation stops

| Symptom | Check and next action |
|---|---|
| Security plan blocked | Read its create/reuse/blocked review; have the platform owner resolve compatibility or access. Do not apply the full offline manifests. |
| SPIRE agents starting, discovery not ready | Wait for the fresh bundle and parent attestation, then generate the exact discovery entry. Do not copy an old bundle or broaden selectors. |
| Registry image pull denied | Confirm the exact digest, entitlement and pull access. Do not replace it with an arbitrary tag. |
| Coordinator offline | Check the recorded cluster Deployment/Pod, role Secret references, readiness and Lease. Inspect its private log; do not start a duplicate local worker. |
| No prepared context | In automatic mode, follow the affected slot in Settings; other ready workflows remain usable. If preparation is offline or quarantined, inspect its private receipt. Manual batches require explicit legacy mode. A consumed identity is never reused. |
| Identity-network stop after worker replacement | Follow the exact kubelet-host reconciliation below during idle maintenance; do not broaden subnets or bypass readiness. |
| Inference unavailable | Check approved endpoint/model and private key reference. Retain the failed run; no weaker provider or write retry is allowed. |
| Query rejected before execution | Local validation sent no backend request. The agent receives bounded grammar feedback within the same four model turns and original deadline. An empty successful search is usable evidence. Foreign-project permissions and the independent gateway query check remain unchanged; no fallback draft or write retry is introduced. |
| Cleanup/write uncertain | Stop submissions and inspect correlated audit and backend outcome before operator recovery. |

Target acceptance must include approved create, user/workload denial, live
model behavior, project isolation, replenishment and safe failures. Review the release requirements in the [technical reference](identity-demo-reference.md)
before customer installation or release.

### Restore kubelet coverage after worker replacement

Inputs: the loaded private installation profile, its original security-creation
receipts, an approved `DEMO_PLATFORM_KUBECONFIG`, and an idle, certain console.
The readiness check observes current worker InternalIPs; it never edits policy.
If a new worker is missing from the owned SPIRE kubelet rule, starts and refill
pause until the dependency is repaired.

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

### Roll back gateway persistence

Disable automatic scheduling first and wait for an idle, certain installation.
Preserve exact service definitions, environment and gateway installation receipt.
Use `demo_exec --action gateway-remove --gateway-receipt "$DEMO_GATEWAY_RECEIPT"`
with a new private output directory to inspect the rollback plan, then repeat in
another new directory with `--apply` only after review. This removes only
receipt-matched resources and restores recorded policies/listener configuration.
The supplied cluster runtime requires persistent gateway mode. Returning to
temporary mode requires the explicit legacy local compatibility procedure; do not
change cluster worker inputs to unsupported temporary mode. Do not run temporary gateway setup
while persistent resources remain. Never restore an older authorization database
over new audit records, consumed identities or quarantine decisions.
