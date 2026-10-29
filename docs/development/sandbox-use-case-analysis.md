# Sandbox use-case analysis: what the restricted environment is for

This analysis grew out of empirical exploration of an OpenCode sandbox on the
bootc-deployed RHEL host (`sandbox-opencode-dev`, 2026-10-13). The exploration
documented the sandbox's actual capability envelope — which toolchains run,
which network paths each binary may take, and where the allowlist proxy blocks
at L7 — and asked which tasks that envelope supports.

The core finding is a framing shift: the sandbox's restrictions are not
friction to engineer around but the product itself. The environment is a
**read-by-default, evidence-producing, non-exfiltrating execution boundary**,
and that is exactly the property set enterprises ask for before letting agents
near their code.

## Capability envelope

Observed inside the `dev` profile sandbox:

| Capability | Status | Detail |
|---|---|---|
| Read GitHub repos (clone/ls-remote) | yes | `git` → `github.com:443` |
| Read issues/PRs/metadata via REST | yes | `node` GET `api.github.com` (L7 read-only) |
| Full Node.js toolchain + npm registry | yes | `node`/`npm` → `registry.npmjs.org` (all methods) |
| Write files inside sandbox | yes | `/sandbox`, `/home`, `/tmp` |
| Write to GitHub (issues, PRs, comments, push) | no | L7 policy denies POST/PATCH/PUT/DELETE before GitHub; pushes lack credentials |
| Non-Node toolchains | limited | only what can be acquired through allowed registries (the agent installed Go by extracting an npm package that vendors the toolchain) |
| Arbitrary network (docs, pypi, proxy.golang.org) | no | connect() denied with EACCES |

## Use cases that fit, ranked

The pattern across all fitting use cases: **input arrives read-only, output
departs as an artifact, verification happens inside when the project is
Node-based.** Any task describable in that sentence fits; any task that needs
unpredictable dependency graphs, write access to external systems, or
interactive debugging does not.

1. **PR/code review as a service** — the strongest fit. The repo arrives
   read-only (clone), findings depart as report files. The agent physically
   cannot push, comment, merge, or exfiltrate the code to a non-allowlisted
   host. For "let a cloud-model agent review proprietary code", these denials
   are the selling point, and the OpenShell audit log records what the agent
   attempted.
2. **Issue triage and digest automation** — needs only `api.github.com` GET,
   already allowed in the `automation` profile. Read issues across a repo set,
   classify, emit a daily report; a human applies labels.
3. **Dependency and supply-chain analysis for Node projects** — the fully open
   npm registry makes `npm audit`, SBOM generation, and license scanning work
   natively. Bounded input (lockfile), bounded output (report).
4. **Bounded code transformation (codemod) farms** — clone, apply a
   node-based transform, verify with `npm test`, emit a patch file; the
   operator applies and pushes. Write boundary stays at the patch file.
5. **Test generation for Node code** — maximal-capability variant: the agent
   gets a full red-green loop (`npm install` + `npm test` work) while staying
   contained.
6. **Onboarding/Q&A assistant over private code** — clone, answer, never
   write. Answers the "chat with our codebase" ask without the usual
   data-residency objection.
7. **Release-notes/changelog drafting** — needs only local git history after
   clone.

## What deliberately stays out of scope

- General feature development — unpredictable dependency graphs (a Go build
  fails transitively on `gopkg.in/yaml.v3` because `proxy.golang.org` is
  blocked), missing toolchains, no docs access.
- Anything requiring the agent-side write loop — until (and unless) the
  `github_api` L7 policy is relaxed to read-write for a scoped set of repos,
  all outputs exit as artifacts. "Agent opens a PR, human merges" remains the
  right trust boundary for a reference architecture.
- Interactive debugging — the least predictable activity; needs arbitrary
  search and iterative tool acquisition.

## Governance observations

- **An open registry is a tool-provisioning channel.** The Go-via-npm-module
  install shows a fully open `registry.npmjs.org` dissolves the "no package
  manager in the workload image" design intent, because npm tarballs can carry
  binaries. For delegated-analysis use cases that is acceptable, even useful;
  for a hostile-agent threat model it deserves an explicit line in
  [the OpenShell Overview](../../openshell/docs/README.md): registry egress
  equals tool provisioning, planned or not.
- **Profiles are task-shaped, not user-shaped.** The profile directory
  (`review`, `dev`, `automation`, `interactive`) is a capability envelope per
  class of work. New use cases should add narrow profiles rather than widen
  existing ones, so audit records keep meaning and the two-factor design
  (binary presence plus allowlist) holds.
- **The boundary files are the real review gate.** Every shipped policy is
  checked against a per-family maximum-access boundary
  (`tests/policy-boundary/`); a new profile must stay within the existing
  boundary or the boundary itself must be consciously widened.

## Next steps

Prototype the top use cases as workload templates plus host-side drivers,
turning "restrictions we documented" into "delegated task patterns we
validated":

1. Review as a service — `pr-review` profile, task driver, report
   collector ([review service design](../examples/review-service/README.md)).
2. Issue digest automation on the `automation` profile.
3. Codemod patch loop on the `dev` profile.
