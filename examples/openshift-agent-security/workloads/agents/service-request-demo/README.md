<!-- SPDX-License-Identifier: Apache-2.0 -->
# Bounded agent workflows

`src/agent_loop.py` and `src/inference.py` implement the live Messages agent used
for Incident triage (OPS) and Remediation change request (SERVICE).
`src/client.py` is the deterministic fixture; running it alone is not live agent
or security acceptance. `src/remediation.json` supplies synthetic change input.

Only permitted project-scoped reads and draft content are available to the
model. The trusted coordinator and protected gateway own approval and mutation.
The runtime uses the approved CVE workload image supplied separately; the image
source, licences and provenance must be reviewed before distribution.

Use the example [Setup guide](../../../docs/identity-demo-customer-quickstart.md) and
[console guide](../../../docs/identity-demo-console.md). Configure the approved
fixed Messages endpoint/model/image contract before rendering. No embeddings,
model key or backend credential belongs in the agent environment.
