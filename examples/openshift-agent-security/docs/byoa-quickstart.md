<!-- SPDX-License-Identifier: Apache-2.0 -->
# Bring your own agent

The security runtime is an in-process boundary for a **trusted host**. Your agent
supplies a proposal; the host authenticates identity, records consent and performs
the protected operation. The library does not create network isolation or verify
an arbitrary platform's identity for you.

## Try an independent consumer

From the example root, create an isolated interpreter outside the checkout:

```bash
python3 -m venv /absolute/private/byoa-venv
/absolute/private/byoa-venv/bin/python -m pip install --no-deps .
unset PYTHONPATH
/absolute/private/byoa-venv/bin/python examples/artifact-metadata-agent/host.py --approve
/absolute/private/byoa-venv/bin/python examples/artifact-metadata-agent/host.py --approve --user-role catalog-observer
/absolute/private/byoa-venv/bin/python examples/artifact-metadata-agent/host.py --approve --workload-role catalog-reader
```

Use your approved package source for the build backend if it is not already
available. These commands use synthetic identity and a temporary local backend:
one permitted write succeeds; either missing permission denies it. For the fully
isolated installed-wheel conformance and integration checks, follow the
[artifact example](../examples/artifact-metadata-agent/README.md).

## Integrate your agent

1. Keep your agent's domain logic outside the security core. It returns bounded
   proposed effects and cannot supply trusted identity, credentials or approval.
2. Register a fixed `ConnectorContract`: exact schema/tool, permitted roles,
   resource scopes, canonical effects and result/operation-marker checks.
3. Supply a trusted host that verifies the user and attested workload before
   constructing `VerifiedActor`. Store their roles, permitted scope and original
   deadline with `RunStore`; never accept these from model output.
4. Bind a fixed `BackendPort` that holds credentials privately, dispatches only
   after the atomic claim and independently observes the actual result. Prevent
   direct agent access to the backend and credentials.
5. Use `SecurityService.propose`, `approve` and `execute`. Obtain real separate
   consent for the displayed digest. An unknown result requires reconciliation;
   never retry an uncertain write automatically.
6. Run the public conformance harness and integration checks for your adapter.
   Prove wrong identity/scope, altered payload, replay, racing callers, response
   loss and backend mismatch denials. Qualify real identity/isolation separately.

The installed `agent_security_runtime` package contains no UI, OpenShift CLI,
example application or test framework. The existing demo driver also supports
`Driver(config, verifier, with_ui=False)` for protected HTTP operations without
loading console rendering; it still needs its trusted platform configuration.
Use the public package for a backend-independent integration.

See the [exact public contract](security-runtime.md#adapter-onboarding-contract)
and [deployed document proof](../examples/document-agent/README.md) for real
PKCE login, attested OpenShell transport and a separately protected backend.
