# Review as a service

Delegated pull-request review inside a restricted OpenCode sandbox. The agent
clones the repository, reads PR metadata, and writes one Markdown report per
PR; it has no credentials and no write access to GitHub. Reports are
collected to the operator's machine over the same SSH channel that installed
the harness configuration — no `podman cp` or host login required.

Design rationale: [sandbox use-case analysis](../../development/sandbox-use-case-analysis.md).

## Security model

The `pr-review` profile grants exactly three network capabilities, each
scoped per binary:

| Binary | May reach | Access |
|---|---|---|
| `opencode`, `node` | model API (or the Praxis gateway on the bootc/Praxis shape) | read-write |
| `node`, `git` | `api.github.com` | REST, read-only (L7-enforced) |
| `git` | `github.com:443` | git transport (clone/fetch) |

The agent cannot push, comment, open or close issues or PRs (denied by the
L7 policy before reaching GitHub, regardless of credentials), cannot reach
any other host, and works inside landlock-enforced filesystem policy with a
read-only `/usr`. The profile stays within the reviewed
[opencode boundary](https://github.com/redhat-et/secure-single-server/blob/main/tests/policy-boundary/opencode.yaml); OpenShell's
audit log records every denied attempt.

Unlike the `review` profile (whose read-only workdir expects code pushed in
from outside), `pr-review` clones the repository itself, so its workspace —
`/sandbox`, which is the sandbox user's home in the workload image — is
writable like `dev`. Reports live under `~/reports` (that is,
`/sandbox/reports`).

OpenShell 0.1.3 caps sandbox names at 19 characters; the profile is named
`pr-review` so the derived default name `opencode-pr-review` (18 characters)
fits without an explicit `--name`.

Output is deliberately artifact-based. Reports land in `~/reports` inside the
sandbox and leave only through `review-collect.sh` run by the operator. Posting
reports as PR comments is a planned phase-2 host-side step so the GitHub
token never enters the sandbox.

## Setup

Create the sandbox once (administrator action, on the host that runs the
OpenShell CLI):

```bash
openshell/harnesses/opencode/create.sh --profile pr-review
```

### Running on the bootc host

Two bootc-specific rules catch every direct-script attempt:

- The OpenShell CLI lives at `/usr/bin/openshell`, not the generic scripts'
  default `/usr/local/bin/openshell` — set `OPENSHELL_BIN=/usr/bin/openshell`.
- All harness scripts must run as the `openshell-svc` service account (with
  its `HOME`, `XDG_RUNTIME_DIR`, and `DBUS_SESSION_BUS_ADDRESS`), because the
  gateway — and the template inventory `create.sh` reads — belongs to that
  user's session. Running as `cloud-user` fails at
  `workload templates: template list failed (exit 1)`.

After the harness image is rebuilt with this branch, the wrapped commands
work directly:

```bash
sudo sss-bootc harness create --profile pr-review
sudo sss-bootc harness review --repo OWNER/REPO --pr 74 --pr 78
sudo sss-bootc harness review-collect --name opencode-pr-review
```

To pilot from a checkout that predates the running image, sync the branch to
the host with
[`scripts/dev/sync-branch.sh`](https://github.com/redhat-et/secure-single-server/blob/main/scripts/dev/sync-branch.sh)
(per-file `scp -p` with add/modify/delete handling — the bootc host ships no
rsync), stage the checkout where `openshell-svc` can read it
(`sudo chmod -R a+rX` on a copy under `/var/tmp`, following the
controlled-policy-qualification convention), and use the same `runuser`
wrapper the quickstart documents:

```bash
# The integrated create path rejects an empty model ID. List what the gateway
# serves: curl --fail --silent --show-error http://127.0.0.1:8080/v1/models
model_id="qwen3-8b"
uid="$(id -u openshell-svc)"
sudo runuser -u openshell-svc -- env HOME=/var/lib/openshell-svc \
  XDG_RUNTIME_DIR=/run/user/"$uid" \
  DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/"$uid"/bus \
  OPENSHELL_BIN=/usr/bin/openshell OPENSHELL_MODEL_ID="$model_id" \
  /var/tmp/secure-single-server/openshell/harnesses/opencode/create.sh \
  --profile pr-review \
  --config /var/tmp/secure-single-server/configs/openshell-praxis
```

`review.sh` and `review-collect.sh` take the same `runuser` wrapper (without
`OPENSHELL_MODEL_ID`). On the bootc/Praxis shape the sandbox reaches the
Praxis gateway, not provider APIs directly, so always pass the
`--config .../configs/openshell-praxis` recipe and the administrator-approved
model ID when creating.

The instructions the agent follows
([review-agents.md](../../../openshell/harnesses/opencode/review-agents.md))
are pushed into the sandbox on every review turn, so updating them in the
repository is enough — no sandbox recreation.

## Usage

End-of-day batch:

```bash
openshell/harnesses/opencode/review.sh \
  --repo redhat-et/secure-single-server --pr 74 --pr 78 --pr 88 \
  [--message "focus on the upgrade cleanup"] [--timeout 7200]
```

The driver pushes the task and agent instructions over SSH stdin, runs one
bounded non-interactive `opencode run` turn (default timeout 1 h, maximum
4 h), and prints the agent's final JSON response. Next morning:

```bash
openshell/harnesses/opencode/review-collect.sh            # into ./opencode-review-github-reports/
openshell/harnesses/opencode/review-collect.sh --dest ~/reviews-2026-10-14/
```

`review-collect.sh` copies every file under the sandbox's `~/reports` to the local
directory and fails if no reports exist (a review turn that produced nothing
is a failure, not an empty success).

## Known startup noise

Two lines always appear in the sandbox's
`~/.local/share/opencode/log/opencode.log` at startup and are **not**
failures — both endpoints are denied by policy in every profile, OpenCode
logs them and continues:

- `ERROR ... "Failed to fetch models.dev"` (the `models.opencode.ai` catalog)
- `WARN ... "background dependency install failed"` (the npm plugin
  self-check, ~70 s after start)

The log records only startup and errors, not agent activity — a quiet log
after these lines is normal. Watch `~/review/` and `~/reports/` for progress.

## Report contract

One file per PR, `~/reports/pr-N.md`, always written — including a failure
report when a step (clone, rate limit, unfetchable ref) goes wrong. Verdict
is one of `approve`, `comment`, `request-changes`; every finding carries
file, line, severity, and a suggested fix. The full contract lives in
[review-agents.md](../../../openshell/harnesses/opencode/review-agents.md).

## Limitations

- Stopping `review.sh` (Ctrl-C) kills only the local ssh connection — the
  in-sandbox `opencode` process keeps running and will continue consuming
  quota on retry backoffs. The `--timeout` bound is the reliable way to end
  a turn; to stop one manually, open `connect_bash.sh` and `kill` the
  opencode process. Zombie turns from interrupted runs hold gateway
  reservations and rate-limit slots, which can starve subsequent runs.
- Gateway quota: review turns are token-heavy (each model turn carries the
  instruction file, PR metadata, and repo context), and the shared gateway
  enforces a 24h sliding-window token quota (10M tokens on the bootc
  memory-backend shape) plus per-request reservations of 10,000 tokens held
  for up to 300 s. A retry storm can exhaust capacity through reservations
  alone; that condition self-heals roughly five minutes after requests
  stop, while exhaustion through settled usage does not. Sustained 429s
  present as a silent hang: `opencode run --format json` retries without
  terminal output. Check `sudo journalctl _SYSTEMD_USER_UNIT=praxis.service`
  for `status=429` access-log lines before assuming the agent is slow. On
  the memory backend, restarting the `praxis.service` user unit clears the
  ledger (test environments only); the container healthcheck
  (`sudo -u praxis-svc podman inspect praxis-shared-gateway
  --format '{{.State.Health.Status}}'`) reports container health but says
  nothing about quota — and probing `/v1/models` costs a reservation, so
  prefer the healthcheck.

- Model compatibility: the rendered config uses the native `@ai-sdk/openai`
  adapter with `forceReasoning` so current OpenAI model families (gpt-5/6),
  which reject the classic `max_tokens` parameter, work through Praxis. A
  model that fails with `Unsupported parameter: 'max_tokens'` in a sandbox
  predating this fix can be switched in place by editing
  `~/.config/opencode/opencode.json` (no sandbox recreation).

- Public repositories only: `git` and `api.github.com` run unauthenticated,
  and introducing a GitHub token into the sandbox would be a new credential
  surface (see phase 2 below).
- Unauthenticated `api.github.com` is rate-limited (60 requests/hour per
  IP); the instructions tell the agent to fetch each PR's metadata once.
- One `review.sh` invocation runs sequentially in one sandbox; a large batch
  may exceed the 4 h timeout — split it into multiple invocations.

## Phase 2 (not built yet)

A host-side poster that takes the collected reports and adds them as PR
comments using a host-held `GH_TOKEN` (scoped to the target repositories).
The token stays outside the sandbox; the agent remains read-only. This gives
the "human leaves comments in the PRs" experience without extending the
sandbox's write boundary.
