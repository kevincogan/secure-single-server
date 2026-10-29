# Example scenarios

These examples begin after a reviewed deployment is already running. Each one
opens with the outcome and the shortest safe path, then points to the exact
policy and runtime files needed for review.

## What this deployment is for

The fitting tasks share one shape, found in the [use-case
analysis](../development/sandbox-use-case-analysis.md): **input arrives
read-only, output departs as an artifact, and verification happens inside the
sandbox when the project is Node-based.** Everything the sandbox denies —
pushing, commenting, exfiltrating to non-allowlisted hosts — is a property the
enterprise reader is asking for, not friction to engineer around.

| Scenario | Use | Boundary it relies on |
| --- | --- | --- |
| [OpenCode PR-candidate queue](opencode-pr-queue/README.md) | Turn public GitHub issues or operator prompts into reviewable patch bundles | No GitHub token in the sandbox; output stops at a patch artifact, publication stays on the workstation |
| [Review as a service](review-service/README.md) | Delegate pull-request review: clone public repositories, emit one Markdown report per PR | L7 read-only GitHub REST, per-binary `git` transport allowlist, landlock filesystem policy |
| [Praxis token quotas](praxis-quotas/README.md) | Inspect providers, preview, apply, and verify shared rolling-day model-token allowances | Gateway-side quota ledger — the only model egress, holding all provider credentials |

### Planned use cases

Ranked fits from the same analysis, not yet packaged as examples:

| Use case | Why it fits |
| --- | --- |
| Issue digest automation | Needs only `api.github.com` GET, already allowed in the `automation` profile; a human applies labels |
| Codemod patch loop | Clone, apply a Node-based transform, verify with `npm test`, emit a patch; the write boundary stays at the patch file |
| Dependency and supply-chain analysis for Node | The open npm registry makes `npm audit`, SBOM generation, and license scanning native; bounded lockfile input, bounded report output |
| Test generation for Node | Full red-green loop (`npm install` + `npm test`) while contained |
| Onboarding/Q&A assistant over private code | Clone, answer, never write — "chat with our codebase" without the data-residency objection |
| Release-notes drafting | Needs only local git history after clone |

## How the boundary protects these tasks

Each of these replays a reported or plausible attack and shows where it dies:
at `connect()` for non-allowlisted hosts, at the L7 policy for unauthorized
methods, or at the gateway catalog before credentials are ever spent.

| Scenario | Use |
| --- | --- |
| [Streamlit before and after OpenShell](streamlit-security/README.md) | Show credential-free managed inference and a confined filesystem in one short demo |
| [API key theft](api-key-theft/README.md) | Replay the reported key-stealing agent: the key is findable, and every path to spend it at another provider dies at `connect()` |
| [Document exfiltration](document-exfiltration/README.md) | A malicious downloaded skill tries five legitimate-looking ways to ship a raw document to an attacker bucket; the boundary stops each |
| [Model escalation](model-escalation/README.md) | The same agent image with and without the boundary: one flag spends the key on a premium model in the open; behind the gateway the catalog refuses it before credentials |

Each example names its prerequisites and the evidence it does not claim. Treat
a successful demo as a workflow result, not a substitute for the deployment's
separate qualification tests.
