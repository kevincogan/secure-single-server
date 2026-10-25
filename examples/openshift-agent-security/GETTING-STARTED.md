<!-- SPDX-License-Identifier: Apache-2.0 -->
# Developer guide

Run example commands from `examples/openshift-agent-security/` in the parent checkout.
For installation start with the [quickstart](docs/identity-demo-customer-quickstart.md).
For a file map use [the source hash inventory](export-manifest.json).

## Local environment

Development and optional administrator helpers require Python 3.12 or newer.
This is separate from the normal `oc` launcher path. Create a private environment
outside every Git checkout:

```bash
umask 077
export DEMO_PRIVATE_ROOT="$HOME/.local/share/agent-security-development"
mkdir -p "$DEMO_PRIVATE_ROOT"
chmod 700 "$DEMO_PRIVATE_ROOT"
python3 -m venv "$DEMO_PRIVATE_ROOT/venv"
export DEMO_PYTHON="$DEMO_PRIVATE_ROOT/venv/bin/python"
"$DEMO_PYTHON" -m pip install \
  -r tests/identity_demo/requirements-lock.txt \
  -r tests/identity_demo/requirements-operator.txt
make test PYTHON="$DEMO_PYTHON"
make check PYTHON="$DEMO_PYTHON"
```

Expected: the required checks pass. Keep private runtime inputs outside source.
CLI/native maintenance also needs the checksum-verified tools in the existing
[CLI lock](infra/openshell/native-build/cli.lock.json) and the
[native build reference](infra/openshell/native-build/README.md).

## Local checks

```bash
make test PYTHON="$DEMO_PYTHON"
make check PYTHON="$DEMO_PYTHON"
PYTHONPATH=scripts/identity_demo:tests/identity_demo "$DEMO_PYTHON" \
  scripts/identity_demo/identity_demo_setup.py --help
```

Unit tests use synthetic fixtures. Explicit live/integration tests are skipped
without private inputs. A passing local suite is not live acceptance. Automated
browser acceptance has separate prerequisites below. No browser install or
cluster access is required for unit checks.

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
| Connector contracts and backend-specific validation | `identity_demo_connector.py`, `identity_demo_jira_contract.py` |
| Atomic allocation, profile compatibility, quarantine and restart recovery | `identity_demo_console_store.py`, `identity_demo_pool_profiles.py`, `identity_demo_warm_pool.py`, `identity_demo_worker_lease.py` |
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
copies use `scripts/verify-source.py` without `--inventory`; their configuration
receipt records the reviewed parameter changes.

## Git and refresh

This example is imported without private development history and uses the
parent repository's Git checkout. Keep private inputs outside that entire
checkout. Never copy another repository's `.git` file or directory into
the example. Review refreshed source and avoid divergent runtime fixes.

## Optional browser rehearsal

For automated acceptance, use the current profile-based walkthrough in the
[CLI reference](docs/identity-demo-reference.md#run-the-cve-and-messages-workflows).
It starts actual workflows and can create synthetic issues: use only an approved
owned target and the stated write budget. Unit checks do not grant that approval.

| Activity | Workstation requirement |
|---|---|
| Manual browser presentation | Approved browser and access to the console Route |
| Automated browser rehearsal | Validated on macOS with Google Chrome installed at its standard application path |
| Private video capture | The same rehearsal environment plus Playwright ffmpeg |

Bundled Chromium alone does not satisfy the current automated runner. Other
workstation combinations need validation. For optional private recording only:

```bash
"$DEMO_PYTHON" -m playwright install ffmpeg
```

Expected: the recorder installs into the operator environment. On a failed
download, fix approved artifact access; do not bypass TLS. Browser tooling is
not deployed to the cluster and is not required to keep the demo running.


For reviewed reuse, follow [onboarding another use case](docs/identity-demo-reference.md#onboard-another-use-case).
The automated document fixture exercises shared run, approval, permission, audit
and recovery code without Jira fields or JQL. It does not certify a new backend.
