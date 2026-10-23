<!-- SPDX-License-Identifier: Apache-2.0 -->
# Runtime and operator entry points

Start with the [customer quickstart](../../docs/identity-demo-customer-quickstart.md).
Run from the repository root with
`PYTHONPATH=scripts/identity_demo:tests/identity_demo`.

| Entry point | Responsibility | Guide |
|---|---|---|
| `identity_demo_setup.py` | Render, connected install, build/publication, admission, verification, backup and guarded cleanup | [Deployment](../../docs/identity-demo-reference.md) |
| `identity_demo_execution_setup.py` | Exact context provision/registration/retirement and UI code snapshots | [Execution](../../docs/identity-demo-reference.md) |
| `identity_demo_cluster_bootstrap.py` | OpenShift coordinator/preparer entry point; scoped projected tokens and durable leases | [Setup](../../docs/identity-demo-customer-quickstart.md#3-start-the-openshift-services-and-automatic-pool) |
| `identity_demo_console_launchd.py` | Optional legacy local worker lifecycle | [Compatibility](../../docs/identity-demo-reference.md#legacy-local-runtime-compatibility) |
| `identity_demo_presentation.py` | Automatic pool configuration and legacy manual preparation | [Console](../../docs/identity-demo-console.md) |
| `identity_demo_sender_trust.py` | Guarded owned trust-copy reconciliation | [Execution](../../docs/identity-demo-reference.md) |

The remaining modules implement the driver, server-rendered UI, OIDC/exchange,
run/action/approval store, scoped backend adapter, native runtime and installer.
Use [the developer guide](../../GETTING-STARTED.md) for checks. Credentials stay
outside Git and generated output stays in protected operator storage.
