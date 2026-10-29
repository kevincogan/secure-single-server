# Model escalation

The same agent image, run twice. In a plain container, one `-m` flag
redirects the agent to a premium model it was never approved to use,
the provider key travels with the request, and nothing anywhere
refuses or records a violation. Behind the OpenShell boundary, every
path to a model runs through the Praxis gateway, whose administrator
catalog lists exactly the approved models: the same pick is refused
with `404 Unknown model` **before credentials are injected**, forged
routing headers are stripped, and the direct provider path dies at
`connect()`.

```text
plain container (no boundary)
  → provider key exported in the environment
  → -m gpt-6-sol honored end to end
  → key attached to every request; no refusal, no audit

OpenShell + Praxis (behind the boundary)
  → no provider key in the sandbox (placeholder only)
  → every model path routes through the gateway
  → catalog lists gpt-4.1-mini only
  → gpt-6-sol: 404 Unknown model, before credentials, before upstream
  → forged X-Gateway-Model stripped; the body's model decides
  → direct api.openai.com: EACCES at connect()
```

The rule the catalog enforces, in one line: **agents may use only the
models the administrator has approved.** The demo's sanctioned pick is
a budget model (`gpt-4.1-mini`) and its misuse target is a premium one
(`gpt-6-sol`) — the budget-versus-premium tiering an administrator
would actually configure, with per-agent tiers (local-only models for
some agents, approved external models for others) as the deployment
pattern this control enables.

A [visual walkthrough](visual-demo.html) draws the same story as
figures: both sides, the catalog lookup, and the three refused
fallbacks. It is published on the documentation site.

This is one of three examples from the same incident family. The
[API key theft](../api-key-theft/README.md) example documented the gap
this control closes; this example is the demonstration that it is
closed.

## Background

The September 2026 coding-agent benchmark (see the
[incident report](../api-key-theft/README.md#the-incident-as-reported))
made this move famous: handed a live key it was never supposed to
touch, the model spent it on stronger models and outscored itself.
Spending the key on a *different provider* is key theft; spending it
on a *stronger model at the legitimate provider* is model escalation —
same credential, same endpoint, only the `model` field changes. A
boundary that validates paths, credentials, and quotas but not the
model field does not stop it; that was the residual gap the
API-key-theft demo recorded when it was written, and the unified model
catalog is the fix that shipped for it.

## What the demo shows

| Act | Move replayed | Control demonstrated | Outcome |
| --- | --- | --- | --- |
| 1 | — | The catalog itself | `/v1/models` lists exactly the approved model |
| 2 | Escalation, no boundary | (none — the default shape of local installs) | Wrong model served with the canary attached; no refusal, no audit |
| 3 | Same image, behind the boundary | Credential custody; single model path | Sandbox's only model path is the gateway |
| 4 | The sanctioned flow | Catalog routing + credential injection | The approved model answers |
| 5 | The same pick, three fallbacks | Catalog lookup before credentials; header sanitization; per-binary egress | `404 Unknown model`; forged header stripped; direct provider `EACCES` |
| 6 | — | Audit logging | The direct-provider denial on the record |

Side A runs the agent image as a plain container: a provider key in
the environment, unrestricted network, and a stand-in provider on the
host playing the real provider's role. The client-side model list is
the user's own config file — and the user who owns the config owns the
list. Side B runs the same image in an OpenShell sandbox whose only
model path is the gateway, configured exactly as the deployed harness
configures it.

## Running the demo

Prerequisites:

- The openshell-praxis all-in-one deployment on the managed host, with
  a real provider credential enabled (the demo makes exactly one real
  completion request, a few tokens on the sanctioned model).
- The unified model catalog installed. A fresh deployment lists the
  upstream's raw catalog (every model the provider serves); install
  the shipped single-model catalog with:

```console
sudo python3 scripts/common/provider_manage.py unified \
  --models openshell/scripts/model-misuse-catalog.json
```

- `ripgrep` on the host (the demo copies it into the sandbox for
  OpenCode's tools).

Then, as the OpenShell owner account:

```console
./openshell/scripts/model-misuse-demo.sh
```

The script creates one sandbox (`model-demo-*`), runs both sides, and
destroys the sandbox on exit. Environment knobs: `PRAXIS_PORT`
(default `8080`), `WRONG_MODEL` (default `gpt-6-sol`), and
`FIXTURE_PORT`/`CONTROL_PORT` for the side-A stand-in.

## What the transcript shows

Side A's record, from the stand-in provider's own request log:

```text
the agent ran its bash tool, wrote the proof file, and confirmed completion on gpt-6-sol
stand-in provider records: 3 completion request(s) for gpt-6-sol, canary credential attached to each
```

The client's model choice was honored verbatim, the key traveled with
it, and nothing refused or logged a violation. A real provider would
bill for this and tell no one.

Side B's sanctioned flow, through the catalog:

```text
the approved model answered: I am the GPT-4.1-mini language model.
```

The same pick, through the boundary — first as the user experiences it
(opencode's generic `UnknownError` wrapper, which cannot attribute the
refusal), then as the raw request the sandbox's sanctioned runtime can
make:

```text
HTTP 404
Unknown model
```

That is the gateway's own answer, produced **before credentials and
before the upstream**: the model field is a catalog lookup key, not a
command. Forging the routing header (`X-Gateway-Model`) changes
nothing — caller copies are stripped during body pre-read, and the
body's model decides. Skipping the gateway entirely is Story 1's
vector one layer down, and it dies the same way:

```text
connect error: EACCES
```

The audit record holds the one network denial side B produces — every
other failure happens inside the client or inside an allowed
connection:

```text
[1792602895.804] [sandbox] [OCSF ] [ocsf] NET:OPEN [MED] DENIED /usr/bin/node-26(0) -> api.openai.com:443 [reason:transparent_tcp_policy_denied]
```

## What this demo does not claim

- **The catalog is per-gateway.** Every sandbox behind one gateway
  shares the routable set; per-agent tiers (a different catalog per
  agent class) are a deployment pattern — multiple gateways, or future
  per-caller catalogs — not something this demo demonstrates.
- **The client contract constrains the catalog.** The deployed client
  path (OpenCode through the openai-compatible provider package)
  sends the legacy `max_tokens` parameter, which current premium
  model families reject; the sanctioned model must come from the
  intersection of what the administrator approves and what the
  qualified client can actually call. That coupling is a property of
  the client SDK, fetched at sandbox creation, and outside this
  deployment's control.
- **Quota and audit are the spend controls, not the catalog.** The
  catalog decides *which* models are routable; rolling-day token
  limits and per-request access logs decide and record *how much*.

## Safety notes

- The side-A provider is a host-side stand-in
  (`tests/openshell-praxis/opencode-provider.py`); the planted key is
  a synthetic canary whose value is never printed.
- Side B makes exactly one real completion request — the sanctioned
  model, a few tokens. The wrong-model requests are refused by the
  gateway before credentials, and the direct provider path is denied
  at `connect()` before any packet; no key ever exists inside the
  sandbox to transmit.
