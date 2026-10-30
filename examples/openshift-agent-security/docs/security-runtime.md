<!-- SPDX-License-Identifier: Apache-2.0 -->
# Reusing the security runtime

The security mechanism owns durable user/workload/run binding, authorization,
exact approval, atomic dispatch and outcome reconciliation. CVE triage, Incident
triage, Remediation, Jira and the browser are consumers and integrations around
that mechanism. This refactor keeps the supported OpenShell identity contract;
it does not claim to authenticate every agent platform.

## Small public boundary

The public Python modules in `runtime/` use the standard library:

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

## Existing OpenShift integration

The existing browser and trusted operator paths use `RunService` for proposal and
approval, backed by the same `RunStore` used by request authorization and the
protected Jira adapter. OIDC authentication, server-side token custody, workload
attestation, certificate binding and actual MCP request checks stay at their
existing trusted edges. No browser-provided actor or model-provided consent is
accepted. The Jira adapter continues to inspect and verify the actual request
and backend response at its execution boundary.

`scripts/identity_demo/identity_demo_run_store.py` is the platform wrapper. It
keeps the installed console call signature, legacy Jira default and atomic
pool/job admission. Allocation, fencing and job reservation remain in the same
transaction as run creation. Coordinator and preparer privileges remain separate.

`runtime/identity_demo/` owns OpenShell execution, native MCP transport and the
sample workflows. Cluster model flows share an explicit execution lifecycle and
do not inherit browser automation. `scripts/identity_demo/` owns the OIDC/UI,
Keycloak/SPIRE/OpenShift integrations and installation/maintenance entrypoints.

Runtime services do not import `tests/identity_demo/`. That directory contains
automated checks and optional browser/qualification tools. The runtime build uses
`config/runtime-sources.json` and `config/requirements-runtime.txt`; it excludes
the Python test suite, pytest and browser tooling. The explicit allowlist also
retains shared setup modules and the native diagnostic compiler fixture they
consume. It is not a minimal service-only image. These platform tools are
separate from the three-module reusable core. The installer retains the full
source verification and qualification tooling.

## Prove reuse without Jira or the browser

The [document agent](../examples/document-agent/agent.py) only creates content.
Its [trusted host](../examples/document-agent/host.py) registers a document
connector, holds the private file-backed service and uses the public modules.
Neither imports CVE/Jira code, browser helpers or `identity_demo` modules.

From the example root, with the developer interpreter:

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

This is an offline integration proof with explicitly synthetic identities. It
does not demonstrate a new production authentication service or a non-Jira
OpenShift installation. To integrate a real agent, the host must derive identities
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
