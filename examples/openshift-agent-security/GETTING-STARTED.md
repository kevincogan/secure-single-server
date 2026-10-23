<!-- SPDX-License-Identifier: Apache-2.0 -->
# Developer guide

Run example commands from `examples/openshift-agent-security/` in the parent checkout.
For installation start with the [quickstart](docs/identity-demo-customer-quickstart.md).
For a file map use [the source hash inventory](export-manifest.json).

## Local environment

Use the [workstation setup in the quickstart](docs/identity-demo-customer-quickstart.md#0-prepare-the-operator-workstation)
to create the private Python environment and acquire the pinned CLI. Keep
credentials and generated output outside Git. Python 3.12+ is required.
Use approved package sources or wheels. Local Python dependencies do not
install shared cluster controllers.

## Local checks

```bash
make test PYTHON="$DEMO_PYTHON"
make check PYTHON="$DEMO_PYTHON"
PYTHONPATH=scripts/identity_demo:tests/identity_demo "$DEMO_PYTHON"   scripts/identity_demo/identity_demo_setup.py --help
```

Unit tests use synthetic fixtures. Explicit live/integration tests are skipped
without private inputs. A passing local suite is not live acceptance. Automated
browser acceptance currently uses Google Chrome on macOS. Optional recording uses
Playwright ffmpeg. No browser install is required for unit checks.

## Source map

| Directory | Responsibility |
|---|---|
| `scripts/identity_demo/` | Installer, identity, policies, UI, durable run state and trusted operator services |
| `tests/identity_demo/` | Both operator runtime helpers and automated checks; keep this directory in deployment packages |
| `workloads/agents/service-request-demo/src/` | Bounded agent loop, Messages client and synthetic remediation input |
| `infra/identity-demo/` | Application/realm templates and native runtime recipes |
| `infra/openshell/` | Pinned upstream build inputs and evaluation patches |
| `docs/examples/` | Public templates; copy to protected private storage before editing |
| `config/` | Nonsecret source configuration template and exact parameterization targets |

Module names and the legacy `service-request` workflow identifier remain stable;
the UI calls that workflow **Remediation change request**.

Change one responsibility at a time. Retain ownership, exact TLS/identity checks,
original run deadlines, exact-field approval, single-use identities, uncertain-write
stops and data-preserving rollback. Run checks before staging any code snapshot.
A source change requires an explicitly reviewed idle application/service update;
editing this checkout alone does not change an existing deployment.

## Review the security path

| Concern | Start here |
|---|---|
| Login, session limits and request authorization | `identity_demo_driver.py`, `identity_demo_run_store.py` |
| Exact approval, one-time dispatch and backend verification | `identity_demo_action_policy.py`, `identity_demo_jira_action_adapter.py`, `identity_demo_backend_observation.py` |
| Atomic allocation, quarantine and restart recovery | `identity_demo_console_store.py`, `identity_demo_warm_pool.py`, `identity_demo_worker_lease.py` |
| Cluster permissions, private endpoints and public trust | `cluster_console_resources.py`, `identity_demo_controller_identity.py`, `identity_demo_public_trust.py` |
| Native changes and build pins | `infra/openshell/patches/README.md`, `infra/openshell/native-build/inputs.lock.json` |

Python modules above are in `scripts/identity_demo/`. Focused regressions are in
`tests/identity_demo/checks/`; export/setup tests are in `tests/export/`. Helpers
at the root of `tests/identity_demo/` are also runtime dependencies, not test-only
code. That inherited layout is deliberate compatibility, pending a separate
reviewed refactor.

`make check` checks syntax, links, templates, native patch pins, the complete
source inventory and common private-data patterns. Its report contains file paths
and categories, not matching credential bytes. It is a sharing gate, not a full
secret detector or an independent security assessment. After an intentional
generic source change, regenerate `export-manifest.json` from the reviewed source;
never regenerate it just to hide unexplained drift. Configured private working
copies use `scripts/verify-source.py` without `--inventory` as shown in Setup.

## Git and refresh

This example is imported without private development history and uses the
parent repository's Git checkout. Keep private inputs outside that entire
checkout. Never copy another repository's `.git` file or directory into
the example. Review refreshed source and avoid divergent runtime fixes.
