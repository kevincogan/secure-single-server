# Postmortem: the review turn that waited for EOF

Date: 2026-10-14. Branch: `feature/review-service`. Scope: the first
end-to-end `pr-55` review run on the AWS bootc host. Workflow context:
[review as a service](../examples/review-service/README.md).

## Summary

The first full review run (`review.sh --pr 55`) sat silent for half an hour —
no clone, no gateway traffic, no report. When the operator finally killed the
stuck job, the review secretly started running headless: it cloned the
repository, fetched the PR metadata, and ended without writing a report.

The root cause is one behavior of the OpenCode CLI: `opencode run` drains
piped stdin to EOF before submitting its prompt. Over `harness_ssh` (no PTY)
the turn's stdin is the SSH channel, and that channel never EOFs while the
operator's terminal holds it open. The turn parked in the event loop before
creating a session and waited for an EOF that could only arrive by accident.

## Timeline

| Time (UTC) | Event |
| ---------- | ----- |
| 17:32 | First `review.sh --pr 55` attempt starts; OpenCode parks on stdin |
| 18:02 | Operator kills the stuck job (Ctrl-Z, `kill %1`); the parked turn wakes and runs headless, cloning the repository |
| 19:51 | Praxis gateway restarted; the memory ledger is cleared |
| 21:15 | Second attempt starts; parks the same way |
| 21:16 | OpenCode startup completes (known noise only); no session created |
| 21:22 | Operator's manual test via `connect_bash` (PTY) succeeds — misleading |
| 21:43 | A/B stdin experiment via `harness_ssh`: EOF finishes in 6 s, held-open pipe hangs |
| 22:15 | Timeout expires and review.sh exits — but this turn never wakes: no session, no gateway traffic |

## What the hang looked like

Three observations, each pointing away from the obvious suspects:

- The OpenCode log showed a complete startup (the `models.dev` ERROR and the
  npm WARN ~70 s in — both known noise) and then nothing: no
  `created id=ses_...` session line, no `loop`, no `stream`.
- The Praxis gateway journal had no entries at all — not 429s, nothing. No
  request had ever been attempted, which ruled out quota exhaustion.
- The process was alive with seven threads, all idle: `epoll_wait` and
  futexes, zero open sockets, no lock contention. Something was waiting for
  an event that never came.

## Diagnosis

The sandbox's own `/proc` is policy-locked — even same-uid reads of
`/proc/<pid>/syscall` are denied, good hardening but inconvenient forensics —
so the evidence came from the host side as root, using the container's
host-side PID:

- `sudo cat /proc/<pid>/syscall` — `epoll_pwait2`: the event loop, idle
- `sudo ls -l /proc/<pid>/fd` — fd 0 a pipe; no sockets anywhere; SQLite
  storage open but idle
- Pipe ownership — the write end of fd 0 held by `openshell-sandbox`, the
  supervisor forwarding the SSH channel
- `sudo cat /proc/<pid>/fdinfo/<epoll>` — fd 0 registered with `EPOLLIN`:
  the process was kernel-level waiting on stdin

The confirmation was an A/B experiment through `harness_ssh` itself — same
command, same directory, one variable:

```bash
# B: stdin closed — completed in 6 seconds
harness_ssh "$name" 'cd ~/review && opencode run --format json "respond with OK"' </dev/null

# A: stdin an open pipe with no data — hung until killed
sleep 150 | harness_ssh "$name" 'cd ~/review && opencode run --format json "respond with OK"'
```

Control B answered "OK" in six seconds. Repro A hung until its timeout.

## Root cause

`opencode run` supports piped prompts (`echo message | opencode run`) and
drains stdin to EOF before submitting — even when the prompt is already in
argv. When stdin is a TTY it skips the read, which is why every interactive
test passed: `connect_bash` allocates a PTY, so the operator's manual
"respond with OK" worked and pointed away from the transport. `review.sh`
launches the turn over SSH without a PTY, so the CLI saw a pipe, read it,
and waited.

## The twist: some disconnects wake the turn, some do not

The operational lore said "Ctrl-C on `review.sh` leaves a zombie opencode
that keeps consuming quota." The session log splits that into two different
events:

- At 18:02 the operator stopped the parked 17:32 run. Ctrl-C alone did
  nothing; Ctrl-Z plus `kill %1` killed the whole job — and the moment the
  tree died, the turn woke: a session was created at 18:02:44 and the review
  ran headless, cloning the repository, before ending without a report.
- At 22:15 the `--timeout 3600` on the 21:15 run expired. That turn never
  woke at all: no session was ever created for it, and the gateway saw no
  traffic from it.

The difference is which processes the signal reaches (inferred from the
session log; the signal tree was not traced directly). A job-control kill
takes down the entire tree including the ssh client, and the kernel's socket
cleanup closes the channel, which the sandbox supervisor translates into the
stdin EOF the parked turn is waiting for. The `timeout` expiry signals only
its direct child; the ssh client survives as an orphan and the channel — and
with it the pipe's write end — stays open. A parked turn is therefore neither
guaranteed to stay parked after `review.sh` exits nor guaranteed to wake; the
sure way to end one is to kill the remote opencode process itself.

Why the 18:02 zombie ended without a report is unknown. Its stdout channel
was gone with the ssh connection, and the report contract in
`openshell/harnesses/opencode/review-agents.md` says even a failed turn
writes `~/reports/pr-N.md` — none appeared. That question stays open.

## The fix

One redirect inside the remote command, so both execution branches (with and
without `timeout`) are covered and the file-push calls keep their stdin:

```bash
review_cmd='cd ~/review && opencode run --format json "$(cat task.md)" </dev/null'
```

The regression test (`test_review_turn_stdin_reaches_eof` in
`tests/openshell-praxis/offline.py`) closes the blind spot that let this
ship: the existing fake ssh recorded command lines but never forwarded
stdin. The new fake executes the remote command with stdin passed through,
like real ssh, and the fake `opencode` drains stdin to EOF — the unfixed
script hangs the test; the fixed one passes in under a second.

## Lessons

- A test shim must be faithful on the axis the bug lives on. Recording
  arguments is not enough when the failure is about data flow.
- An empty gateway journal is evidence: no 429 lines means no requests,
  which excludes quota before anyone restarts anything.
- Hardened sandboxes block same-uid `/proc` forensics, but the host side of
  the container PID still answers everything as root.
- Whether a disconnected turn keeps running or finally starts depends on how
  the connection dies: a whole-tree kill closes the channel, a timeout orphan
  leaves it open. Neither Ctrl-C nor `--timeout` reliably ends a turn — only
  killing the remote opencode process does.
