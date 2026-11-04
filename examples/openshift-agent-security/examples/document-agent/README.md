<!-- SPDX-License-Identifier: Apache-2.0 -->
# Document agent: unrelated-agent integration proof

`agent.py` creates content only. `host.py` supplies a reviewed document connector,
synthetic identities, private file-backed backend and the shared security service.
No CVE, Jira, browser or `identity_demo` import is required.

Install the runtime package first with `python3 -m pip install .` from the
example root. Then run:

```bash
python3 examples/document-agent/host.py
python3 examples/document-agent/host.py --approve
python3 examples/document-agent/host.py --approve --user-role viewer
python3 examples/document-agent/host.py --approve --workload-role reader
```

Expect awaiting approval, verified publication, user denial and workload denial,
respectively. Temporary private state is removed on exit. `--approve` records
explicitly synthetic consent; identities in this fixture are not authenticated.

For trust boundaries and real integration requirements, see
[the reuse guide](../../docs/security-runtime.md).

## Optional deployed proof

`service.py` is the trusted host. It derives user/workload associations from
verified Keycloak tokens, signed workload claims and its persisted runs.
Its human control listener and MCP execution listener are separate. The agent
cannot use the control listener to forge an identity or approve its own action.

`backend.py` is a separate HTTPS SQLite fixture with immutable revisions. Only
the host holds its write credential; a distinct observer can independently read
committed effects. The backend, host state and credentials are never mounted in
the agent. `live_agent.py` sends tool requests without credentials; OpenShell's
native transport obtains and injects short-lived bearer delegation. Credential
custody and exact live authorization remain required; a copied grant is replayable
before expiry and its residual risk requires explicit review.

`proof.py` defaults to `plan` and provides explicit `install`, `run` and `cleanup`
actions. Its reviewed private configuration identifies the candidate namespace
by its original creation receipt, three attested contexts and an immutable image.
The plan includes a separate public PKCE client and only the existing Analyst/Viewer
role scopes. Installation records its exact realm client ID before scope changes;
cleanup removes only that recorded client. The existing driver client is preserved.
Resource creation is collision-intolerant. Cleanup checks original UID, current
resource version, ownership and configuration; uncertain operations stop.
The runner does not create or delete namespaces or alter shared prerequisites.

The fixture permits at most three approved successful publications: normal,
concurrent single dispatch and a committed third revision with an intentionally
incomplete HTTP response. Negative tests must leave the backend unchanged.
Reconciliation requires positive matching backend evidence; it never enables
replay. This fault is private fixture configuration, never a tool parameter.

The deployed proof and broader candidate readiness are separate acceptance
outcomes. Unit tests and resource readiness do not demonstrate real authentication,
attestation, bypass prevention or an unassisted installation. Consult the private
acceptance receipts before presenting those capabilities as verified.

The existing `fixture-isolation` rule is additive. The optional installation
therefore also needs its original API creation response as
`namespace_policy_receipt`. The runner excludes exactly the two document service
labels from that broad allow, using UID, resource-version and exact-spec tests.
Cleanup restores the recorded rule only after all document Pods have stopped.
It never updates the corresponding policy in another installation.

The private proof configuration contains the complete installation `profile`,
`namespace_receipt`, `namespace_policy_receipt`, immutable `image`, the three
verified `contexts`, issuer URLs, public CA PEMs and these operator-only inputs:

- `browser_users`: owner-only file containing the candidate Analyst/Viewer test
  passwords. Authentication uses the normal browser login and PKCE callback.
- `browser_executable`: the approved local Chrome executable.
- `native_inputs`: owner-only JSON with `arguments` for the existing native
  operator client and `contexts` keyed by `publisher`, `viewer` and `reader`.
  Each context supplies its `context_file` and reviewed execution `contract`.
- `control_origin`, `audience` and `endpoint`: the fixed candidate HTTPS control
  origin, compiled MCP audience and `/_document_proof/mcp` resource respectively.
- `disposable_synthetic_data`: explicit confirmation that this candidate's three
  document revisions and private state may be removed.

If the document image is stored in another namespace, authorize only the exact
sandbox ServiceAccounts to pull image layers from that namespace. Kubernetes
image-pull access does not require application Secret-read permissions.

Set `IDENTITY_DEMO_CONFIG`, `IDENTITY_DEMO_ARTIFACTS` and the installation's
registration mode before importing the existing operator tools. The native
credentials, CLI profile, public management CA and context receipts belong in
private directories outside the checkout. The optional delegation controls also
require the reviewed diagnostic binaries staged in the two actual supervisors;
they never run inside the agent. See the existing diagnostic reproduction and
staging instructions in the technical reference.

Run from an operator environment with the normally installed runtime package,
Playwright and the existing operator-tool import paths:

```bash
python3 examples/document-agent/proof.py plan \
  --config "$DOCUMENT_PROOF_CONFIG" --kubeconfig "$DEMO_ADMIN_KUBECONFIG" \
  --output-dir "$DOCUMENT_PROOF_OUTPUT"
```

Review the private plan before repeating the command with `install`. Use `run`
once installation and the exact native contexts are ready. Use `cleanup` with
the same immutable configuration and output directory. A pending operation
requires inspection of its original response and backend state. Do not delete
checkpoints to force another run.

The resource renderer uses service-serving certificates and the existing native
server-authenticated TLS listener. It leaves the human control listener without an MCP route. The
runner observes the effective Envoy route name before applying three route-local
filter overrides: the Jira identity lookup, Jira credential mediation and MCP
broker processing. The document host supplies its own complete JWT, workload,
run, role, scope, approval and dispatch checks. Existing `/mcp` route and virtual
host filter configuration must remain identical; a real original-route denial
is also required. A route override or a healthy Pod alone proves none of these
security properties.

The native v0.1.3 proxy can return HTTP 502 when the issuer rejects a revoked
subject token. The qualification runner accepts this only alongside an independently
observed revoked, unexpired run, a correlated issuer validation failure and a
healthy authorized Publisher read. A generic transport failure is insufficient.
Run deadlines are never extended to recover an interrupted qualification attempt.
Keep prior receipts and use fresh identities for any separately reviewed continuation.
