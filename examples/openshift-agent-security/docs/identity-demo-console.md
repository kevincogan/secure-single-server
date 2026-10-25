<!-- SPDX-License-Identifier: Apache-2.0 -->
# Operations guide

Install with the [quickstart](identity-demo-customer-quickstart.md) first. The
browser is the presenter interface. A coordinator and separate preparer run on
OpenShift with isolated profiles, scoped ServiceAccounts and durable state.
The authenticated Jira view also runs in the console. The install workstation
and local background services are not required for ongoing browser demos.
Local CLI operation remains an explicit compatibility/maintenance option.

## Choose a task

| Task | Section |
|---|---|
| Run and present a workflow | [1. Present the demo](#1-present-the-demo) |
| Check availability or review completed evidence | [2. Automatic replenishment and completed evidence](#2-automatic-replenishment-and-completed-evidence) |
| Inspect worker health | [3. Check the installed services](#3-check-the-installed-services) |
| Renew trust, inspect certificates or update workers | [4. Maintenance and restart](#4-maintenance-and-restart) |
| Back up, restart or investigate a failure | [5. Recovery and data preservation](#5-recovery-and-data-preservation) |

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

## 1. Present the demo

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
   the OPS context. This is a deliberate test-harness probe, not a model-selected action.
4. Review the exact proposed fields. Approve only those fields. Analyst + Triage
   may create within the authorized project; Viewer or Reader must be denied.
5. Check the independently verified outcome. Open **Access Jira** to view this
   run's verified issue, then inspect **Agent activity** and the decision audit.
   The view is read-only and restricted to the original run owner. A proposal
   alone does not establish a successful write.
6. Wait for authorization/credential cleanup verification before another run.
   Subsequent sandbox retirement and replenishment can continue in the background. An uncertain
   write or cleanup stops for operator review; never resubmit it blindly.

Browser sessions renew within configured idle/absolute and Keycloak session
limits. Logout/revocation remain effective. Session renewal never changes the
original authorization deadline of a run. Cancellation closes driver authorization
and protected tool access immediately. Native delegated-token exchange may finish
during cleanup; the next execution waits for verified provider/credential
detachment. Do not describe this as instant removal of every credential.

## 2. Automatic replenishment and completed evidence

A **context** is an unused, verified sandbox and its exact native identity,
isolation policy and approved execution profile. It has no human grant. Allocation
atomically reserves it, binds the authenticated user, trusted workflow/connector
and permitted resource scope, and records the original run deadline.

| Installation mode | Ready targets | Compatibility |
|---|---|---|
| Profile mode, new installer | Six Triage + two Reader | Compatible CVE, Incident and Remediation workflows share Triage capacity; Reader remains separate |
| Legacy, existing installations | Two per workflow/role, eight total | Original immutable workflow/project mappings remain valid until explicit idle migration |

The maximum is **12 non-retired contexts**, including pending preparation,
allocated/consumed, retiring and quarantined entries. One execution and one
preparation/retirement operation may run concurrently with separate management
profiles. Used identities never return to the ready pool.

| What Settings shows | What to do |
|---|---|
| Ready to start | Start when the execution lane and security gates are clear, even while another context is prepared |
| Preparing your next run | Wait for that compatible profile; other ready profiles remain available |
| Run executing or closing access | Wait for authorization closure and verified credential/provider detachment |
| Quarantined context | Operator reviews its exact identity and receipt; it still counts toward the cap |
| Uncertain write or shared-security recovery | Stop starts until the outcome is established; never replay the mutation |

Routine observations do not disable an otherwise eligible workflow. Fresh identity,
policy, certificate-validity and shared-security checks still apply before
allocation. Pool availability is capacity, **never authority**. Compatibility
fingerprints include images, namespace, ServiceAccount, policy, workload permission
and identity/issuer contracts. Never relabel an old context to bypass a mismatch.
Change targets or workflow mappings only through authenticated idle maintenance.
Existing runs retain their original scope. Changing a profile's security contract
requires guarded retirement of every non-retired context using the old contract,
including quarantined reservations; never change state just to bypass this check.

After cleanup, open the completed run's **Agent activity**, **Decision and outcome
audit**, and **Access Jira**. The issue view is authenticated, read-only and limited
to the original owner's independently verified issue. It needs the cluster console,
adapter and Jira fixture; it does not need a local preview service. A new authorized
sign-in can review retained history without reopening execution authorization.

| Data | Retention |
|---|---|
| New receipt-proven disposable synthetic scratch | Delete only after guarded retirement and exact ownership/reference checks |
| Historical volumes, application databases, audit and approvals | Preserve |
| Consumed-identity tombstones and quarantine decisions | Preserve across restart, cleanup and rollback |
| Failed/successful acceptance receipts | Retain privately outside Git |

Manual preparation remains an operator fallback. Profile migration requires an
idle installation and guarded retirement of obsolete unused contexts. Existing
installations keep legacy behaviour until explicitly migrated. See
[profile compatibility](identity-demo-reference.md#profile-pool-compatibility).

## 3. Check the installed services

Use the original private Setup configuration and authorized kubeconfig. Set the
actual application namespace; these commands are read-only:

```bash
export DEMO_CORE="your-owned-core-namespace"
oc --kubeconfig "$DEMO_KUBECONFIG" get deployments,statefulsets,pods \
  -n "$DEMO_CORE"
oc --kubeconfig "$DEMO_KUBECONFIG" get certificates -n "$DEMO_CORE"
```

Expected: desired replicas are ready; managed Certificates report Ready. Check
Settings for worker health, compatible context availability and recovery needs.
A Ready Pod or updated Secret alone does not prove authorization or that a service
has loaded its replacement certificate. Detailed operator verification uses the
[maintenance commands](identity-demo-reference.md#managed-certificate-maintenance-commands).

For an installation in progress, use `install.sh status` / `observe` with its
original private output directory. Once accepted, `install.sh finalize` retires
only the original installer bindings. Runtime roles and retained recovery data
remain; ongoing maintenance uses separately authorized operator access. Do not submit another Build/Job or delete its
Lease to clear an error. Keep private logs; share sanitized failure categories
and receipt hashes, not credentials or full configuration dumps.

## 4. Maintenance and restart

### Managed application certificates

| Certificate | Purpose | Loading |
|---|---|---|
| `fixture-openshell-server-tls` | Native server TLS | OpenShell file watcher |
| `fixture-openshell-client-tls` | Native client/peer TLS | New channels read projected credentials |
| `fixture-mcp-bound-mutual` | Protected MCP server TLS | Envoy SDS |

Managed mode requests 30-day leaves, renewal seven days before expiry and a new
ECDSA key. Actual issuer limits and **served** fingerprints must be checked.
Routine renewal under the approved CA does not need a native rebuild or extend
run deadlines, approvals or user sessions. SPIRE SVID renewal is separate.

CA rollover is explicit: distribute overlapping approved public roots before
switching leaves, verify new connections/loading, then retire old trust after the
reviewed overlap. Keep the MCP listener's SPIRE client-trust bundle separate from
its serving-certificate issuer. Do not claim unattended CA rollover.

Unexpected identity/issuer drift, insufficient safe validity, ambiguous updates
or failed verification stop starts for review. Healthy certificates merely
approaching their renewal window do not disable eligible workflows. Follow the
[certificate procedure](identity-demo-reference.md#managed-certificate-maintenance-commands).

Trust or code maintenance starts with a database-consistent backup and a verified
idle, certain state. Stop scheduling, fence the exact workers and preserve their
original definitions/UIDs before a disruptive change. Console code updates must
use the provider-configured source and preserve its approved model contract; the
existing update-console guard checks this before changes. Use the existing guarded
[worker update](identity-demo-reference.md#updating-the-isolated-cluster-workers)
and [retirement](identity-demo-reference.md#retire-unused-contexts-for-maintenance)
procedures. Do not start local workers alongside the cluster workers.

## 5. Recovery and data preservation

| Symptom | Action |
|---|---|
| Registry denied/rate-limited | Verify the pinned image and approved pull authentication/mirror; do not substitute a tag or change shared credentials |
| Coordinator offline | Inspect its exact Pod, projected-token access, private log, state volume and Lease; do not start a duplicate |
| Context preparation failed | Retain its checkpoint/quarantine; inspect scheduler, capacity and identity evidence |
| Trust or certificate review required | Compare the recorded approved authority and actual loaded certificate; use guarded idle maintenance, never insecure TLS |
| Kubelet coverage missing after node replacement | Ask the platform owner for [exact-host reconciliation](identity-demo-reference.md#restore-kubelet-coverage-after-worker-replacement); do not widen subnets |
| Model unavailable | Check the approved endpoint/model/key reference; preserve the failed run without a fabricated draft or write retry |
| Write or cleanup uncertain | Establish the original dispatch/backend outcome before another execution; preserve all safety state |

A locally rejected query can receive bounded grammar feedback within the original
model-turn/run limits. An out-of-project protected request is still denied; the
Incident TEST probe is deliberate test input. Do not describe it as autonomous
model behaviour or a universal promise to continue after every denial.

Follow the existing [backup/restore reference](identity-demo-reference.md#application-data-backup-and-restart-validation)
for application databases and configuration. Verify restored copies, issuer keys
and private recovery inputs separately. Never overwrite newer history with an
older snapshot. Preserve audit, approvals, consumed identities and quarantine.

Rollback disables automatic scheduling first and waits for a certain idle state.
Use a compatible retained image and exact receipts. Retired identities remain
retired; replacements require fresh contexts. An older image that cannot read the
added state is not a valid rollback. The cluster workers require
persistent gateway mode; temporary mode is legacy local compatibility only.
Cleanup uses exact ownership, native identity, dependencies and UID preconditions;
never use namespace/prefix deletion. See
[checkpoint recovery](identity-demo-reference.md#installation-checkpoint-recovery)
and [cleanup](identity-demo-reference.md#cleanup-and-installation-rollback).
