<!-- SPDX-License-Identifier: Apache-2.0 -->
# Native helpers and automated checks

This directory is required at runtime. The coordinator imports these native MCP,
browser, inference and audit helpers; the installer also uses the policy and
pinned requirements. Keep it with scripts/identity_demo in delivery packages.

`checks/` contains local behavioral checks, which default to synthetic fixtures.
Live checks require explicit private credentials and approved owned targets.
Do not treat a passing local test as a live scenario receipt.

See the [developer guide](../../GETTING-STARTED.md),
[execution reference](../../docs/identity-demo-reference.md) and optional
[diagnostic tools](tools/README.md). Never run every helper against a cluster as
a blanket validation command. Older diagnostic helpers retain narrow reference
scope; use the profile-based installer and documented current entry points.
