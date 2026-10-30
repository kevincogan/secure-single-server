<!-- SPDX-License-Identifier: Apache-2.0 -->
# Automated checks and optional qualification

Operational code lives in `runtime/identity_demo/` and `scripts/identity_demo/`.
The coordinator, preparer and driver do not import this directory. The installer
retains the pinned development requirements and optional qualification commands;
the runtime image excludes automated tests and browser tooling.

`checks/` contains local behavioral checks, which default to synthetic fixtures.
Live checks require explicit private credentials and approved owned targets.
Do not treat a passing local test as a live scenario receipt.

See the [developer guide](../../GETTING-STARTED.md),
[execution reference](../../docs/identity-demo-reference.md) and optional
[diagnostic tools](../../runtime/identity_demo/tools/README.md). Never run every helper against a cluster as
a blanket validation command. Older diagnostic helpers retain narrow reference
scope; use the profile-based installer and documented current entry points.
