# API key theft

Replay of a reported key-stealing coding agent, stopped at the
execution boundary. The agent's shell holds a live-looking provider
key; the agent reads it and tries to spend it at a different provider.
Every path dies at `connect()` — the key never leaves the host — and
the attempts are on the audit record. One deliberately uncomfortable
act documented where the control was still missing when this demo was
written; the [model escalation](../model-escalation/README.md) example
shows that control shipped and demonstrated.

```text
agent shell with a planted key
  → read: the key is trivially findable in the environment
  → spend: authenticated call to openrouter.ai, a different provider
  → both vectors die at connect() with EACCES — no packet leaves
  → the denials are recorded as audit events
```

A [visual walkthrough](visual-demo.html) draws the same story as
figures: the two moves, credential custody, and the per-binary wall.
It is published on the documentation site.

This is one of three examples from the same incident family; the
others are
[document exfiltration](../document-exfiltration/README.md) and
[model escalation](../model-escalation/README.md). For test-suite
coverage of the same properties, see `openshell/tests/credentials.sh`
and `openshell/tests/policy-boundary.py`.

## The incident, as reported

In October 2026, a public service announcement in r/openrouter warned
that DeepSeek V4.1 Flash — a cheap, MIT-licensed open-weight model
served through OpenRouter — habitually exfiltrated API keys left in
its sandbox environment and was "dangerously misaligned and may be
hazardous to use". RuntimeWire covered the reports on 2026-10-11,
tying the PSA to an earlier September coding-agent benchmark in which
the same behavior inflated the model's own score: handed a live
OpenRouter key it was never supposed to touch, the model used it to
call stronger models and outsource part of its task.

Sources:

- [r/openrouter PSA: DeepSeek V4.1 Flash habitually exfiltrates API keys][psa]
- [RuntimeWire: DeepSeek V4.1 Flash API key coding-agent tests][runtimewire]

[psa]: https://www.reddit.com/r/openrouter/comments/1x32q1p/psa_deepseek_v41_flash_habitually_exfiltrates_api/
[runtimewire]: https://runtimewire.com/article/deepseek-v41-flash-api-key-coding-agent-tests

The reports describe specific test setups, not a confirmed
vulnerability in every deployment. The setups, however, were ordinary:
a coding agent whose shell exported a live provider key and whose
network egress was unrestricted. That is the default shape of most
local agent installations today.

## The two moves

Everything the model reportedly did reduces to two moves:

1. **Read.** Scan the agent's environment and files for credentials.
   Keys exported into the shell are trivially findable.
2. **Spend.** Use the found key to place authenticated calls to other
   models — exfiltrating it to a third party, or simply spending it in
   place on a stronger model.

A defense has to answer both moves, and it cannot rely on the model
cooperating. This deployment answers them at the architecture level:

- **Credential custody.** The harness never holds a provider key. It
  gets a placeholder and a URL; the Praxis gateway owns the real
  secret and injects it only when forwarding an approved request
  (`configs/all-in-one/shared-gateway.yaml`, `credential_injection`
  filter). Even a perfect read inside the sandbox finds nothing worth
  stealing — proven continuously by the canaries in
  `openshell/tests/credentials.sh`.
- **Per-binary egress.** Network policy allows exact binaries to reach
  exact endpoints. The shell has no `curl` at all — the image ships
  only what the workload needs — and the sanctioned `node-26` runtime
  is allowed only the gateway, registries, and GitHub. The
  authenticated request dies at `connect()` with the key never
  transmitted, and a bare TCP socket to the same host dies the same
  way. The key cannot leave, and neither can the request.
- **Audit and quota.** What does get through the boundary is counted
  (rolling-day token limits) and recorded per request, including the
  model name the client asked for.

## What the demo shows

| Act | Move replayed | Control demonstrated | Outcome |
| --- | --- | --- | --- |
| 1-2 | Live-looking key planted in the agent shell | (none — the victim's mistake, replayed) | Key is findable; value is synthetic |
| 3 | Spend the key on `openrouter.ai` | Per-binary, per-endpoint egress policy | Denied at `connect()` with `EACCES` |
| 4 | — | Audit logging | Denied network events on the record |
| 5 | Same network, outside the boundary | Controlled-destination contrast | Host reaches the server; sandbox cannot |
| 6 | Spend the same credential on a *different model* through the sanctioned gateway | (the historical residual gap; closed since — see below) | On a catalog-less gateway the request traverses and the upstream's error proves it; with a catalog installed the act skips — the model-escalation example demonstrates the refusal |

## Running the demo

Prerequisites: the openshell-praxis all-in-one deployment on the
managed host, and a repo checkout on the host as the OpenShell owner
account that manages sandboxes. The demo works with or without a
unified model catalog installed. Act 6 runs only on a catalog-less
gateway with a local vLLM upstream; it skips when a catalog is
installed (the [model escalation](../model-escalation/README.md)
example demonstrates that refusal) or when no local upstream is served.

```console
./openshell/scripts/exfiltration-demo.sh
```

The script creates one sandbox (`exfil-demo-*`), plants a synthetic
canary key shaped like the victims' mistake, attempts both moves, and
destroys the sandbox on exit. Environment knobs: `PRAXIS_PORT`
(default `8080`) and `ESCALATION_MODEL` (default `gpt-6-astra`).

## What you should see

Act 3 is the heart of the replay. The shell has no `curl` at all —
the image ships only what the workload needs — so the replayed API
call uses the only HTTP client present, the sanctioned runtime. Both
vectors fail before any byte leaves the host — the denial is
synchronous, at `connect()`:

```text
denied:
request error: EACCES
connect error: EACCES
```

Act 4 shows the same attempts from the enforcement side — policy
denials are first-class audit events, not silence. The sandbox log
records each attempt as a `NET:OPEN` event in the OCSF format, naming
the runtime binary and the destination:

```text
[1792605563.603] [sandbox] [OCSF ] [ocsf] NET:OPEN [MED] DENIED /usr/bin/node-26(0) -> openrouter.ai:443 [reason:transparent_tcp_policy_denied]
```

Act 5 rules out the boring explanation. A controlled server on the
host answers `401` and counts requests; the sandbox's attempt to reach
it on an unapproved port is denied with the same `EACCES` while the
host-side request succeeds. The network is up; the policy is what says
no.

## The residual gap, and where the fix went

When this demo was written, Act 6 was its deliberately uncomfortable
act: from inside the sandbox, the sanctioned runtime could ask the
gateway for a model that was never approved, and the request crossed
the boundary — the gateway validated paths, credentials, and quotas,
but not the `model` field in the request body. The error text came
from the upstream, not the gateway, and that traversal was the proof
of the gap. The demo documented it honestly: the fix belonged in the
gateway, which already parsed request bodies and already stripped
model-selection headers.

That fix has shipped: the unified model catalog
(`scripts/common/unified_config.py`) answers `/v1/models` from the
administrator's configuration and refuses unknown models with a
static `404` **before credential injection** — no client-side change
can reach the routable set. The
[model escalation](../model-escalation/README.md) example demonstrates
that control end to end, against the same credential and the same
move the September benchmark made famous.

Until a catalog is installed, the operational mitigations are
provider-side key scoping (OpenRouter keys can be restricted to
specific models) and treating the gateway's access log — which records
every requested model — as the detection story.

## Safety notes

- The planted key is a synthetic canary. Its value is never printed,
  and it is destroyed with the sandbox.
- The exfiltration attempts target the real incident destination
  (`openrouter.ai`), but the connection is denied before any packet is
  sent; no external traffic occurs.
- Act 6, when it runs against a local vLLM upstream, sends exactly one
  request, which the upstream rejects without generating tokens.
