# OpenCode PR-candidate queue

Turn a public GitHub issue or an operator prompt into a reviewable patch bundle.
This is issue-or-prompt-to-patch work, not pull-request review. OpenCode makes a
local branch and proposes a diff; a human decides whether to apply it and open a
pull request from a workstation.

```text
issue or prompt
  → bounded OpenCode turn in the pr-queue sandbox
  → task, patch, metadata, and report artifacts
  → human review
  → workstation Git/gh publication
```

The sandbox has no GitHub token and cannot push, create a pull request, comment,
or close an issue. The EC2 or bootc host also never receives the credentials used
to publish code.

## What you get

- One task directory per queued issue or prompt.
- `changes.patch` containing the only proposed code change.
- `metadata.json` recording the repository, base, branch, title, summary, test
  results, risks, and `success` or `failed` status.
- `report.md` written for the human reviewer.
- A clear separation between generation inside the sandbox and publication from
  the workstation.

This example is for one trusted operator and a public repository. It is not
multi-user authorization or proof that generated code is safe.

Known limits found in validation:

- The sandbox has no Git identity. A model that commits must set one in the
  clone (`git config user.name`/`user.email`); otherwise the commit fails and
  only the working tree changes.
- `base`, `title`, `tests` and `risks` in `metadata.json` come from the model.
  Check them against `changes.patch`; a `success` status does not prove the
  fields are complete.
- Multi-turn local Qwen needs the Responses history adapter; without it the
  return turn is rejected. Use an approved cloud model for a full tool loop, or
  follow the [history adapter](../../testing/gateway-features.md#model-switching-and-reasoning)
  setup.
- The OpenShell service account must be able to read the checkout. On a manual
  or AWS host, use a service-readable path such as `/opt/secure-single-server`
  rather than another user's home directory.

## Try it

### 1. Check prerequisites

- A reviewed OpenShell + Praxis deployment is already running.
- Praxis has an administrator-approved model and valid provider credentials.
- The target repository is public.
- The operator has enough shared Praxis token quota for the batch.
- The workstation has Git and, for the optional publication step, the GitHub CLI.

Model credentials stay in the host-side Praxis deployment. There is deliberately
no GitHub PAT loading step for the sandbox or queue. For model credential setup,
use the [bootc credential guide](../../quickstarts/bootc/README.md) or the
all-in-one [memory](../../quickstarts/all-in-one/in-memory.md#4-create-provider-secrets)
or [Valkey](../../quickstarts/all-in-one/valkey.md#3-create-provider-secrets)
provider-secret procedures.

### 2. Create the sandbox

On a bootc host:

```console
sudo sss-bootc harness create \
  --profile pr-queue --name opencode-pr-queue \
  --config /usr/share/secure-single-server/configs/openshell-praxis \
  --model administrator-approved-model
```

The explicit `--config` is required. `pr-queue` is integrated with Praxis and
has no standalone direct-provider catalog entry.

On a manual or AWS all-in-one deployment, use the service-owner helper from the
[manual guide](../../quickstarts/openshell-single-server/manual.md#2-set-up-the-service-owner-shell-helper):

```console
os_run "$repo/openshell/harnesses/opencode/create.sh" \
  --profile pr-queue --name opencode-pr-queue \
  --config "$repo/configs/openshell-praxis" \
  --model administrator-approved-model
```

### 3. Queue work

On a bootc host, queue one or more public issues:

```console
sudo sss-bootc harness queue \
  --name opencode-pr-queue \
  --repo OWNER/REPOSITORY \
  --issue 123 --issue 124 \
  --message "Keep the change focused and include documentation" \
  --timeout 7200
```

On a manual or AWS all-in-one deployment, use the queue runner directly:

```console
os_run "$repo/openshell/harnesses/opencode/pr-queue/queue.sh" \
  --name opencode-pr-queue \
  --repo OWNER/REPOSITORY \
  --issue 123 --issue 124 \
  --message "Keep the change focused and include documentation" \
  --timeout 7200
```

To queue the included prompt on a bootc host, first create a readable task file
outside the image:

```console
sudo tee /var/tmp/opencode-pr-queue-demo-task.md >/dev/null <<'EOF'
Create a new file named OPENCODE_DEMO.md at the repository root.

The file must contain exactly this line:
OpenCode PR-candidate queue demo succeeded.

Do not modify any other file. If the repository has no tests, record that no
tests are applicable.
EOF
sudo sss-bootc harness queue \
  --name opencode-pr-queue \
  --repo octocat/Hello-World \
  --prompt-file /var/tmp/opencode-pr-queue-demo-task.md \
  --timeout 900
```

On a manual or AWS deployment, use the prompt checked out with the repository:

```console
os_run "$repo/openshell/harnesses/opencode/pr-queue/queue.sh" \
  --name opencode-pr-queue \
  --repo octocat/Hello-World \
  --prompt-file "$repo/docs/examples/opencode-pr-queue/demo-task.md" \
  --timeout 900
```

Tasks run sequentially in the named sandbox. Each turn, including SSH setup and
artifact checks, is bounded from 60 seconds through four hours; the default is
one hour.

For a live demonstration, run the command directly and let the JSON events
stream. For a longer batch that must survive an SSH disconnect, start it in
tmux:

```console
tmux new-session -s opencode-pr-queue
# run the queue command above
```

Detach with `Ctrl-b` and then `d`. Reconnect with:

```console
tmux attach-session -t opencode-pr-queue
```

tmux is optional. The queue itself does not require it.

### 4. Optional: `bot`-label issue factory

This scenario turns the queue into a small factory for selected GitHub issues:

1. **Intake:** add the `bot` label to an open issue in a public repository.
2. **Scheduling:** a host-side watcher polls GitHub on a timer and selects
   issues that have not completed a queue turn.
3. **Production:** the existing `pr-queue` sandbox gives each issue one bounded
   OpenCode turn to clone the repository and produce a branch, patch, report,
   and metadata.
4. **Inspection:** a human collects and reviews the artifacts, runs tests, and
   checks the complete diff.
5. **Shipping:** the human applies the accepted patch and opens a draft pull
   request from a workstation.

The watcher uses unauthenticated, read-only GitHub API access and never receives
GitHub write credentials. It also never publishes: every patch stops at the
human inspection gate.

Choose one persistent state file per repository and label:

```console
sudo install -d -o openshell-svc -g "$(id -gn openshell-svc)" -m 0700 \
  /var/lib/openshell-svc/opencode-pr-queue
state=/var/lib/openshell-svc/opencode-pr-queue/owner-repo-bot-state.json
```

The private parent directory is required. Both entry points execute the watcher
as `openshell-svc`; placing the state file directly in root-owned `/var/tmp`
would be rejected by the watcher's ownership checks.

Run one watcher when possible. If duplicate watchers start accidentally, they
must share this state file so issue leases prevent duplicate active turns.

`--repo` is compared without regard to case, so an operator may pass any
spelling of `OWNER/REPOSITORY` while GitHub still reports its canonical
`owner/repository` casing in the API responses.

Preview the current intake without spending model tokens:

```console
sudo sss-bootc harness watch \
  --name opencode-pr-queue \
  --repo OWNER/REPOSITORY \
  --label bot \
  --state "$state" \
  --once --dry-run
```

The preview initializes or migrates the state file, reports issues already
attempted or active, and does not reserve new issues or run OpenCode.

Start the factory in `tmux`:

```console
tmux new-session -s opencode-bot-watcher
sudo sss-bootc harness watch \
  --name opencode-pr-queue \
  --repo OWNER/REPOSITORY \
  --label bot \
  --state "$state" \
  --interval 300 \
  --timeout 3600 \
  --max-pages 10 \
  --max-issues-per-poll 1 \
  --message "Keep the change focused and include documentation"
```

Detach with `Ctrl-b` and then `d`; reconnect with:

```console
tmux attach-session -t opencode-bot-watcher
```

On a manual or AWS all-in-one deployment, replace the `sss-bootc harness watch`
command with the direct runner:

```console
os_run "$repo/openshell/harnesses/opencode/pr-queue/watch.sh" \
  --name opencode-pr-queue \
  --repo OWNER/REPOSITORY \
  --label bot \
  --state "$state" \
  --interval 300 \
  --timeout 3600 \
  --max-pages 10 \
  --max-issues-per-poll 1 \
  --message "Keep the change focused and include documentation"
```

Before a turn, the watcher reserves the issue with a lease lasting the task
timeout plus ten minutes. The queue process is hard-stopped five minutes before
that lease expires, preventing a hung turn from overlapping another watcher. A
failed turn retains its reservation because stopping the local queue process
does not prove that remote sandbox work has stopped. One-shot mode exits
nonzero, and the long-running watcher retries only after the lease expires. If
a watcher crashes, its lease eventually expires and a later poll retries the
issue.

The state file must stay owned by the watcher account with mode `0600`;
malformed, duplicate, or permanently leased entries are rejected, and the file
is capped at 10,000 successful issues. State replacements are flushed to
durable storage before publication. Keep the adjacent `.lock` file persistent;
do not delete or replace it while a watcher is running.

OpenCode must produce non-empty `changes.patch`, `report.md`, and successful
metadata before the queue writes a per-issue completion token through a
no-follow, owner-and-mode-checked helper. The watcher creates that marker empty
immediately after reserving the issue, so an empty marker means the turn is
still pending: a duplicate watcher that sees one skips the issue instead of
stopping. Once the queue writes the token the watcher records the issue as
attempted and removes the marker. If the watcher cannot update state after
OpenCode succeeds, it stops with both the lease and completion marker retained;
a restart reconciles the marker while the lease is still valid. If the lease
expires first, the next poll discards the stale marker and queues the issue
again instead of blocking it permanently. Inspect the artifacts before manually
repairing state.

The watcher reads GitHub pages of 100 matching issues, rejects duplicate issue
IDs within one poll, and follows page numbers through the `--max-pages` limit.
The default is 10 pages, or 1,000 issues, and the maximum is 100 pages. Every
page consumes unauthenticated GitHub API capacity. Keep the interval at five
minutes or longer unless the API response explicitly permits a shorter
interval, and reduce `--max-pages` when rate limits are reached.

`--max-issues-per-poll` bounds how many new model turns start in one polling
cycle. Its default is one; already attempted or active issues do not consume
that budget.

If a full page is returned at the `--max-pages` limit, the watcher logs a
pagination warning because later matching issues may remain pending.
With the default work limit, a poll starts at most one new turn before
sleeping. The interval is therefore a minimum delay after that turn finishes,
not a maximum end-to-end latency for every labeled issue.

GitHub poll failures are logged and retried by the long-running watcher;
`--once` exits nonzero so schedulers and health checks can detect them.

Collect, inspect, and publish artifacts exactly as described below. The factory
does not change the credential-free sandbox or the human review gate.

### 5. Collect the artifacts

On the deployed host:

```console
sudo sss-bootc harness collect \
  --name opencode-pr-queue \
  --dest /var/tmp/opencode-pr-queue-artifacts
```

The collector uses the existing OpenShell SSH channel. Its safe extractor accepts
only regular files and directories, so malformed sandbox output cannot traverse
outside the destination. A missing or empty required artifact is a failed task,
not an empty success. A failed task may omit `changes.patch` when `report.md`
explains the failure.

Copy the bundle to the workstation when ready:

```console
scp -r ec2-user@SERVER:/var/tmp/opencode-pr-queue-artifacts ./
```

### 6. Review and publish

Read `report.md`, inspect `changes.patch`, and check `metadata.json`. Then apply
exactly one accepted patch in a clean target checkout:

```console
base_ref="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["base_ref"])' \
  ../opencode-pr-queue-artifacts/issue-123-*/metadata.json)"
base_commit="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["base_commit"])' \
  ../opencode-pr-queue-artifacts/issue-123-*/metadata.json)"
git fetch origin "$base_ref"
if [[ "$(git rev-parse FETCH_HEAD)" == "$base_commit" ]]; then
  git switch -c agent/issue-123 "$base_commit"
else
  echo "Collected base no longer matches ${base_ref}" >&2
  false
fi
git apply --3way ../opencode-pr-queue-artifacts/issue-123-*/changes.patch
git diff --check
```

Run the repository's tests and inspect the complete diff. If the result is
acceptable, commit it with an appropriate message and attribution, then publish:

```console
git push -u origin agent/issue-123
gh pr create --draft \
  --title "Proposed fix for issue 123" \
  --body-file ../opencode-pr-queue-artifacts/issue-123-*/report.md
```

With an SSH remote, `git push` uses the workstation SSH key; with HTTPS, it can
use the workstation credential manager. `gh pr create` uses the GitHub CLI's
workstation authentication. If `gh` is absent, install it on the workstation or
push the branch and open the draft PR in the GitHub web UI. Do not move a
write-capable PAT to the server to work around a missing local CLI.

The proposed title and summary in `metadata.json` are suggestions, not approved
content. Nothing is published until the human reviewer takes these workstation
actions.

## Check token capacity

Praxis token quotas count input, output, cached, and repeated prompt/history
tokens. A 30-task batch at roughly 30,000 total tokens per turn is already near
the shipped 1,000,000-token rolling-day safety default before overhead, retries,
or additional operators are considered.

From the deployed checkout:

```console
sudo scripts/common/quota-status
sudo scripts/common/quota-set --list
```

Preview and apply a larger OpenAI rolling-day capacity:

```console
sudo scripts/common/quota-set --provider openai --capacity 10000000
sudo scripts/common/quota-set --provider openai --capacity 10000000 --apply
```

Stop active tasks before applying a changed capacity. Apply restarts Praxis:
memory-quota usage resets, while Valkey ledger usage survives. On a managed
Valkey gateway, an administrator can also clear selected provider usage for
testing:

```console
sudo scripts/common/quota-reset --list
sudo scripts/common/quota-reset --provider openai --apply
```

These are shared allowances, not per-user budgets or USD spend caps. See the
[token quota guide](../../quickstarts/common/token-quotas.md) for backend
persistence, metrics, and reset limitations.

## Security boundary

| Binary | Destination | Access |
| --- | --- | --- |
| `opencode`, `node-26` | Praxis gateway | Model calls only |
| `node-26`, `git` | `api.github.com` | REST, read-only |
| `git` | `github.com:443` | Git Smart HTTP clone/fetch only |

The `pr-queue` profile allows no npm, documentation, cloud-provider, or other
network destination. Git push uses `git-receive-pack`, which is denied by the
Layer 7 rules. OpenShell records allowed and denied attempts in its audit log.

When the optional watcher is enabled, its `curl` process runs on the deployed
host and makes one read-only, unauthenticated GitHub issue-list request per
poll. For an issue task, the queue runner makes one additional host-side,
read-only issue-metadata request and passes that metadata to OpenCode. Neither
process loads a GitHub token or receives repository write access.

Queue turns run OpenCode with `--pure --auto` and a closed stdin channel.
`--pure` avoids external plugin discovery, `--auto` prevents a non-interactive
turn from waiting for OpenCode's own tool prompt, and closing stdin prevents
`opencode run` from waiting for terminal input. These choices do not expand the
boundary: OpenShell still enforces the filesystem, process, and network policy.

### GitHub CLI credential decision (issue #57)

Keep authenticated `gh` on the operator's workstation, after human review. Do
not add it to the sandbox image or inject a GitHub token into the sandbox for
this workflow. The alternatives considered are:

| Option | Benefit | Credential and policy tradeoff | Decision |
| --- | --- | --- | --- |
| Ship unauthenticated `gh` in the sandbox | Some CLI convenience for public data | Adds an image dependency; many PR commands require authentication. It does not remove unauthenticated API rate limits, and `gh` is not an allowed network binary in the current policy. | Defer; public HTTPS Git and unauthenticated REST already cover intake. |
| Inject a scoped read-only token | Authenticated metadata access and higher API rate limits | Repository content and agent tools could read or disclose the token. Read-only scope limits writes, not disclosure or private-data access; a token does not itself grant OpenShell network access. | Reject for this workflow; requires a separate credential-boundary and policy review. |
| Keep authenticated `gh` outside the sandbox | Natural PR metadata and publication commands | The trusted operator retains credentials and chooses what to publish. | Use the workstation workflow in step 5. |

Do not forward `GH_TOKEN`, `GITHUB_TOKEN`, `gh` authentication configuration, Git
credential helpers, or SSH credentials into the sandbox. Issue intake remains
public and unauthenticated; API rate limits are an accepted limitation rather
than a reason to load a token into the worker.

Issue #57's original `pr-review` proposal now lives in the tree as the
[review-service example](../review-service/README.md); its host-side report
poster is an unbuilt phase 2. This queue generates patch candidates, and its
boundary is stricter than the proposed host-side report poster: publication
credentials
belong on the workstation, not the EC2 or bootc host. A future host-side poster
would need its own reviewed design for token scope, storage, repository and
operation restrictions, and explicit human approval before posting. Sandbox
reports and metadata must remain untrusted proposals, never instructions to run
authenticated commands or automatic authorization to publish.

## Where this example lives

| Purpose | Path |
| --- | --- |
| This user-facing runbook | `docs/examples/opencode-pr-queue/README.md` |
| Ready-to-run demo prompt | [demo-task.md](demo-task.md) |
| Sandbox policy | [`configs/openshell-praxis/profiles/pr-queue/policy.yaml`](https://github.com/redhat-et/secure-single-server/blob/main/configs/openshell-praxis/profiles/pr-queue/policy.yaml) |
| OpenCode model/provider template | [`configs/openshell-praxis/pr-queue/harness-provider.json.in`](../../../configs/openshell-praxis/pr-queue/harness-provider.json.in) |
| Queue runner | [`openshell/harnesses/opencode/pr-queue/queue.sh`](https://github.com/redhat-et/secure-single-server/blob/main/openshell/harnesses/opencode/pr-queue/queue.sh) |
| Optional labeled-issue watcher | [`openshell/harnesses/opencode/pr-queue/watch.sh`](https://github.com/redhat-et/secure-single-server/blob/main/openshell/harnesses/opencode/pr-queue/watch.sh) |
| Artifact collector | [`openshell/harnesses/opencode/pr-queue/collect.sh`](https://github.com/redhat-et/secure-single-server/blob/main/openshell/harnesses/opencode/pr-queue/collect.sh) |
| Shared metadata validation | [`openshell/harnesses/opencode/pr-queue/lib.sh`](https://github.com/redhat-et/secure-single-server/blob/main/openshell/harnesses/opencode/pr-queue/lib.sh) |
| Agent instructions and artifact contract | [`openshell/harnesses/opencode/pr-queue/instructions.md`](../../../openshell/harnesses/opencode/pr-queue/instructions.md) |
| Contracts and tests | [`openshell/tests/pr-queue.py`](https://github.com/redhat-et/secure-single-server/blob/main/openshell/tests/pr-queue.py) |

Executable runtime code stays under `openshell/` and deployment configuration
stays under `configs/`. This page is the single entry point; the source map
above exists for review and audit, not as required reading before the first run.

## Limits and factory evolution

- Public repositories only. A GitHub token in the sandbox would create a new
  credential surface and is outside this example.
- Unauthenticated GitHub API access is rate-limited; the host fetches issue
  metadata once and passes it to OpenCode.
- The optional watcher makes one unauthenticated GitHub API request per page,
  up to `--max-pages`, during each poll.
- One invocation runs sequentially in one sandbox. Split large batches into
  multiple invocations.
- A patch, passing test output, or model completion is not proof that a change is
  correct or secure. Human review remains mandatory.

The optional label watcher is intentionally simple intake. A “dark factory”
could preserve this boundary while replacing tmux with a `systemd --user`
worker, using a SQLite or PostgreSQL job store, adding concurrency and retry
controls, and retaining audit logs and artifacts for every accepted or rejected
job. Webhooks or a token-backed intake service could improve responsiveness
without granting the sandbox write access.
