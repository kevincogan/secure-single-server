<!-- SPDX-License-Identifier: Apache-2.0 -->
# Reusing the security runtime

The security mechanism owns durable user/workload/run binding, authorization,
exact approval, atomic dispatch and outcome reconciliation. CVE triage, Incident
triage, Remediation, Jira and the browser are consumers and integrations around
that mechanism. This refactor keeps the supported OpenShell identity contract;
it does not claim to authenticate every agent platform.

## Small public boundary

Install the local distribution with `python -m pip install .` from the example
root, or install its reviewed wheel. It needs Python 3.12 or newer and no runtime
packages outside the standard library. Consumers import only the supported
`agent_security_runtime` namespace:

```python
from agent_security_runtime import (
    RunStore, ConnectorContract, BackendPort, SecurityService, VerifiedActor,
)
```

The historical flat imports remain compatible during migration. The wheel
contains only the security contracts, state and services, plus the public exports;
it does not contain the UI, OpenShift tooling, examples or automated tests.
The implementation is divided into:

- `agent_security_contracts.py` defines a reviewed `ConnectorContract`, strict MCP
  request parsing and canonical effect digests. The host supplies fixed schema,
  resource, permission-role and backend-reference functions. A request cannot
  choose a connector, import, destination or credential.
- `agent_security.py` provides `RunStore`: private durable SQLite state, original
  deadlines, one-use workload binding, permission decisions, exact approval,
  atomic claims, terminal outcomes and correlated audit. It retains historical
  database columns and the original Jira digest format for compatible history.
- `agent_security_service.py` provides `RunService` for proposals/consent and
  `SecurityService` for protected reads/writes. `VerifiedActor` is supplied by a
  trusted authentication adapter. Constructing it does not authenticate anyone.
  `BackendPort` contains fixed trusted callbacks, never model-selected routing.

`SecurityService.execute` parses the actual tool-call body, canonicalizes its
effects and atomically claims the approved action before calling the backend.
It verifies the backend reference and independently observed effects before
recording success. Missing authority, scope, identity or approval stops dispatch.
A lost response or mismatched observation becomes `unknown` and cannot be
replayed. Cancellation prevents future claims; it cannot undo a mutation already
in flight. Recovery requires independent positive evidence.

The agent does not receive an `ALLOW` token it can use elsewhere. Its host performs
the protected operation through this boundary. A real integration must also
prevent direct agent access to protected credentials or alternate backend routes.
These Python APIs do not provide network isolation by themselves.

## Component ownership

The driver composes application operations with separate browser, protected-adapter
and operator HTTP modules. Console rendering and fixed CSS/JavaScript consume
projected display state. The backend can start with `with_ui=False` without
loading rendering. Shared admission timing is independent of presentation;
allocation, fencing and queue reservation retain their original transactions.
The trusted OpenShift package under `scripts/identity_demo/openshift_security/`
owns PKCE/session handling and verified delegation-to-run binding. Both the
Jira driver and document host supply their own explicit issuer-to-connector role
map. Issuer verification, original deadlines and backend authorization still
have separate responsibilities. The same package is used in the projected
driver code map and the separately built document proof image. Private
operator artifact writers also live outside the installer and execution
entrypoints.

The native exchange engine has a separate pure provider-policy renderer and
context preflight. The historical `probe_native_exchange.py` entry point remains
compatible. Test setup lives in domain support modules, outside runtime delivery.

For a minimal independent integration, start with the [BYOA quickstart](byoa-quickstart.md).

## Existing OpenShift integration

The existing browser and trusted operator paths use `RunService` for proposal and
approval, backed by the same `RunStore` used by request authorization and the
protected Jira adapter. OIDC authentication, server-side token custody, workload
attestation, short-lived delegation and actual MCP request checks stay at their
existing trusted edges. No browser-provided actor or model-provided consent is
accepted. The Jira adapter continues to inspect and verify the actual request
and backend response at its execution boundary.

`scripts/identity_demo/identity_demo_run_store.py` is the platform wrapper. It
keeps the installed console call signature, legacy Jira default and atomic
pool/job admission. Allocation, fencing and job reservation remain in the same
transaction as run creation. Coordinator and preparer privileges remain separate.

`runtime/identity_demo/` owns OpenShell execution, native MCP transport and the
sample workflows. The cluster coordinator supplies an attached run session to the workflow.
It reads the original authenticated association and waits for durable consent.
Browser qualification supplies a separate session to the same workflow. `scripts/identity_demo/` owns the OIDC/UI,
Keycloak/SPIRE/OpenShift integrations and installation/maintenance entrypoints.

Runtime services do not import `tests/identity_demo/`. That directory contains
automated checks and optional browser/qualification tools. The runtime build uses
`config/runtime-sources.json` and `config/requirements-runtime.txt`; it excludes
the Python test suite, pytest and browser tooling. The explicit allowlist also
retains shared setup modules and the native diagnostic compiler fixture they
consume. It is not a minimal service-only image. These platform tools are
separate from the three-module reusable core. The worker image excludes the six optional boundary/concurrency/dependency/key-rotation/
lifecycle/recovery qualification flows. The installer retains their full source
and tooling, including the boundary rehearsal; their tests remain in the suite.

## Prove reuse without Jira or the browser

The [document agent](../examples/document-agent/agent.py) only creates content.
Its [trusted host](../examples/document-agent/host.py) registers a document
connector, holds the private file-backed service and uses the public modules.
Neither imports CVE/Jira code, browser helpers or `identity_demo` modules.

Install the local package first. From the example root, with that interpreter:

```bash
"$DEMO_PYTHON" examples/document-agent/host.py
"$DEMO_PYTHON" examples/document-agent/host.py --approve
"$DEMO_PYTHON" examples/document-agent/host.py --approve --user-role viewer
"$DEMO_PYTHON" examples/document-agent/host.py --approve --workload-role reader
```

The first command produces an awaiting-approval proposal. The second records
synthetic consent and verifies one publication. The last two deny dispatch even
after consent. Each run uses a private temporary directory and removes it on exit.
There are no cluster, live-model or external backend calls.

These four commands are offline examples with explicitly synthetic identities.
The optional [deployed document proof](../examples/document-agent/README.md)
adds real PKCE authentication, attested native transport, separate HTTPS backend
and bounded security acceptance. The independent
[artifact consumer](../examples/artifact-metadata-agent/README.md) exercises
onboarding through the installed public package without core changes.
Neither result is production certification. To integrate a real agent, the host must derive identities
and role/resource bindings from verified authentication and attestation, register
a reviewed schema/backend adapter, retain the fixed execution boundary and add
adapter acceptance tests. Do not expose `VerifiedActor` or `BackendPort` as agent
input fields.

## One reviewed configuration

`runtime/provider-contract.json` is the single public model/endpoint/image
contract. Its sibling loader validates exact fields, duplicate keys, canonical
HTTPS DNS `/v1/messages`, bounded model IDs and digest-pinned images. There is no
environment-selected contract path. The checked-in contract contains placeholders
and must be configured before installation or an agent image build.

The existing installer invokes `scripts/configure-demo.py` using private reviewed
inputs. The tool verifies the fixed source pins and changes only the public JSON.
It records the before/after hashes and backup privately; the inference key remains
in an external credential file and is never read by configuration. Application
source, tests and Containerfiles remain unchanged. The native provider profile,
client, evidence filter, sandbox delivery and identity image checks read the same
contract. Installed console updates reject a different configured contract.

The optional workload `make build` uses `scripts/build-agent.py` to construct a
closed temporary context containing only the four agent files, loader, public
JSON and Dockerfile. It passes the validated digest base explicitly. It neither
pushes nor deploys. Native source/build locks and downstream patch pins remain
separate reviewed infrastructure contracts.

## Compatibility and validation

Historical run/action/audit data and unknown-write reconciliation remain
compatible. The old `service-request` identifier still means Remediation in the
UI. Source moves require rebuilt runtime images and freshly rendered immutable
code maps; changing this checkout does not update a running deployment. Retain
the previous image, immutable maps, private receipts and database backup for a
guarded idle update or rollback. Never restore an old database over newer history
or retry an uncertain build, installation or backend mutation.

Legacy local Mac workers/installers and superseded standalone gateway/OAuth
setup commands are retired from the current delivery path. Existing MCP listener
configuration remains because credential-route and diagnostic consumers still
use it. OpenShift workers, the HTTPS MCP adapter, protected backend service,
platform prerequisites, scoped maintenance, historical issue viewing and recovery
remain. Existing installations require a reviewed migration and isolated
candidate acceptance before replacing their images/resources.

Focused evidence is in `tests/identity_demo/checks/test_security_service.py`,
`test_connector_contract.py`, `test_run_store.py`, `test_console_atomic_admission.py`,
`test_reduction_security_boundaries.py`, `test_runtime_boundary.py` and the
existing identity/session/adapter/pool/recovery suites. Export tests verify the
single-data-file configuration and closed build context. Distinct negative,
concurrency and recovery cases are retained; line coverage is not a deletion rule.

Run `make test PYTHON="$DEMO_PYTHON"` and `make check PYTHON="$DEMO_PYTHON"`.
Offline checks cannot prove live inference, attestation, certificate renewal or
cluster cleanup. Those require an owned isolated candidate with independent
backend observations and UID-bound cleanup receipts before a live update.

## Adapter onboarding contract

A trusted host authenticates the person and attested native workload, verifies
issuer/audience/signature/expiry and a maximum 30-second delegation lifetime, then constructs
`VerifiedActor(user, workload)`. Never accept that object or its fields as
authority from the agent. Persist the verified roles, permitted resource scope
and original deadline with `RunStore.create_run`. Human credentials remain on
the trusted side. The canonical workload identifier remains
`spiffe://<trust-domain>/openshell/sandbox/<canonical-UUID>`.

Register one fixed `ConnectorContract` in trusted code. `normalize` rejects unknown
fields, wrong types and unbounded input. `resource` derives scope from the actual
effects. `proposal` adds a reserved operation marker; reject agent-supplied markers.
`check_reference` restricts returned backend references to that scope. `has_marker`
checks independently observed operation ownership. Choose explicit read/write
user and workload roles. The connector fingerprint binds persisted runs; schema
or semantic changes need a version and a reviewed migration.

Bind fixed `BackendPort` callbacks for dispatch, independent observation and
optional reads. Dispatch receives canonical approved effects and returns a
backend reference. Observation returns those effects including the operation
marker. Callbacks own destination/credential selection, verified TLS, bounded
responses and redirect policy. Never retry a protected write after a timeout.
The backend itself needs authenticated host access, isolated storage and restrictive
network policy. Prevent agent access by service, IP and alternate route; keep
backend credentials and host state out of its mounts. These are deployment
responsibilities, not protections supplied by the Python library.

Use `SecurityService.propose` for the proposal, and its action ID and canonical
digest for separately authenticated human consent through `approve`. The agent
sends a strict JSON-RPC `tools/call` envelope with the fixed tool name and
`run_id`, `action_id` and the exact proposed arguments. Only
`SecurityService.execute(actor, body_bytes)` performs protected dispatch.
Consent supplies no missing role. Use `read` for scoped reads.

A `Denied` result stops the operation. An unknown outcome stays unreplayable;
reconcile only after independent positive backend observation, using
`store.reconciliation` and `store.reconcile_result`. Cancellation and credential
renewal must not extend the original run deadline. Retain history through restart
and upgrades; never restore an older database over newer actions.

The public offline harness is `examples/adapter_conformance.py`. Import `verify`
from that supplied file and pass your connector, `effects(scope)`,
`backend_factory(private_directory)`, allowed scope and another valid scope.
Your backend supplies `dispatch`, `observe` and `read`; each case starts with
empty private state. Use different roles/resource/action semantics from the
document example. Run with the installed wheel, not a repository `PYTHONPATH`.
The harness checks authorization, exact consent, user/workload/scope binding,
replay and committed lost-response reconciliation. Integration-specific concurrency,
schema, recovery, observation mismatch and authentication tests remain required.
It does not certify real authentication, network isolation or production readiness.

On OpenShift PVC mounts, the host calls `prepare_storage(database_path)` from the
public namespace before constructing `RunStore`. It restores private modes only
on owned directories and regular SQLite files, rejects symlinks/foreign owners,
and preserves contents. The driver compatibility import remains supported. This
handles platform `fsGroup` mode changes without weakening `RunStore`'s private
file checks. Keep the configured state path outside agent control.

A repeated successful `execute` returns `dispatched: false` and its retained
reference; callers must not assume that replay responses repeat the first
response's `verified` field. Unknown outcomes still raise `Denied` until
independently reconciled. A duplicate workload passed to `create_run` fails the
database's single-use constraint with `sqlite3.IntegrityError`; it does not
return a reusable run. The trusted host translates that configuration/allocation
error safely, obtains a genuinely fresh attested context and never retries it
as the same workload. Policy and lifecycle denials use `Denied`.

## Public call shapes and results

The minimal host wiring uses these call shapes (all identities, roles, callbacks
and configuration are supplied by the trusted host):

```python
store = RunStore(database_path, connector=contract, trust_domain=trust_domain)
run = store.create_run(issuer=issuer, user=user, user_role=user_role,
    workload=workload, workload_role=workload_role, project=scope,
    expires=original_deadline, assessment=assessment)
port = BackendPort(contract.fingerprint, dispatch, observe, read)
service = SecurityService(store, port)
actor = VerifiedActor(user, workload)
action = service.propose(actor, run, effects)
service.approve(actor, run, action['action_id'], action['digest'], approval_deadline)
result = service.execute(actor, actual_mcp_body_bytes)
```

`ConnectorContract` requires `identifier`, `backend`, `schema`, `tool`, `normalize`,
`resource`, `valid_scope`, `proposal`, `check_reference` and `has_marker`.
Pass immutable `user_roles`, `workload_roles`, `write_user_roles` and
`write_workload_roles` explicitly when the integration uses different roles.
`normalize(effects)` returns a JSON-serializable canonical effect mapping;
`resource(effects)` returns its scope; `valid_scope(value)` returns a boolean.
`proposal(effects, action_id)` adds the reserved marker and returns effects.
`check_reference(scope, reference)` raises on an invalid or out-of-scope reference.
`has_marker(observed_effects, action_id)` returns whether the independently
observed effect belongs to that operation. Version the identifier/schema when
these semantics change; do not infer semantic equivalence from a fingerprint.

A proposal returns `action_id`, `digest` and `arguments`. Execute consumes those
exact arguments in the strict MCP envelope described above. First success returns
`state: succeeded`, `dispatched: true`, `verified: true` and `result_ref`.
The existing historical Jira contract uses `issue_key` instead of `result_ref`.
Replay returns the retained state/reference and `dispatched: false`, without a
new dispatch or a guaranteed `verified` field. `read(actor, run, scope)` returns
the backend's read projection after permission checks; it does not wrap that
projection in an authorization token.

`store.describe(run, user)` returns owner-scoped `run`, `actions` and `audit`.
The run includes identity/roles, scope (`project`), original `expires`, `active`
and assessment. Actions include `id`, `run_id`, JSON `payload`, `digest`, `state`,
`approval_expires`, `approver`, `execution_id`, historical `issue_key`, `outcome`
and the generic `result_ref` where applicable. Audit rows contain `sequence`,
`at`, `run_id`, `action_id`, `event` and JSON-string `detail`. These are historical
observations, not fresh authorization. Consumers should select documented fields
and tolerate additional observation fields.

For unknown outcomes, `store.reconciliation(run, action_id)` yields the retained
`execution_id`; a trusted host independently observes the backend, then calls
`store.reconcile_result(run, action_id, execution_id, reference, observed_effects)`.
It never retries dispatch to discover whether the first write committed.
`store.recover_dispatched()` runs once on coordinated single-instance startup;
interrupted claims become unknown. `store.cancel(run, user)` or the trusted
`store.revoke(selector, value)` closes future authority while preserving history.

A connector may set `scope_denial` and `read_reason` to fixed diagnostic reason
strings for its resource vocabulary; they grant no authority. Its public
`canonical(effects)` returns `(canonical_json_string, digest_hex)`. Use the digest
for exact consent and independent-effect comparison; it is not a bearer grant.
