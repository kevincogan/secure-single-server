# Scope and roadmap

> **Where this fits:** The planning stop. Use it to distinguish current
> acceptance from future goals.

The goal is a single-server AI agent environment on administrator-managed RHEL,
combining controlled execution, model access, and shared inference usage.
Users run useful coding tasks with approved models; administrators retain
provider credentials, control inference usage, and protect host capacity and
workspaces. The repository turns that goal into deployable configurations,
harness recipes and repeatable acceptance tests.

This roadmap distills the user-supplied *Secure single-server Standalone AI
Gateway* design, whose requirements and topology sections are dated September
23, 2026. It is a statement of direction, not a claim that every requirement is
implemented. The document contains earlier design snapshots and illustrative
commands; the repository's current recipes and validation records govern what
can be run today. Upstream issue status alone does not qualify a deployment.

## Phased outcomes

| Phase | Intended user or operator outcome | Repository position today |
| --- | --- | --- |
| 1. Shared gateway and durable quotas | Run Claude Code, OpenCode or OpenClaw on RHEL without provider keys. Apply ordered model-specific and catch-all token rules; preserve allowances through restarts with private Valkey. | All-in-one profiles and harness recipes exist. Shipped quotas are shared catch-all allowances per API chain; model rules and full native RHEL/real-provider acceptance remain incomplete. Memory profiles are development-only. |
| 2. Routing and continuity | Choose approved models automatically, fail over safely, and switch when a model allowance is exhausted. | Switchyard has an experimental Weak/Strong Chat Completions profile. Cross-API behavior, judge accounting, selected-model quotas and failover need further work. |
| 3. Inference guardrails | Screen requests without changing harnesses, preserving screening across every route. | NeMo/Lakera deployment and end-to-end allow/block/modify acceptance are roadmap work. |
| 4. Self-managed inference | Use a private vLLM model through the same gateway controls. | The optional bootc deployment serves Qwen3-8B on CPU or a single NVIDIA L4. OpenCode → Praxis → vLLM passed real inference, tool, isolation and lifecycle checks on AWS; see the [local validation](../bootc/VLLM-VALIDATION.md). Other harness adapters and hardware remain unqualified. |
| 5. Individual access and quotas | Authenticate callers and enforce user, model and organisation/team allowances together. | Remote HTTPS with administrator-issued JWTs exists. Personal/hierarchical quotas, identity-provider integration and renewal/revocation workflows are not qualified by that profile. |
| 6. Retained sandboxed work | Start a harness, disconnect, reconnect or hand off work, with defined workspace retention and access/resource controls. | OpenShell creation and OpenCode/OpenClaw CLI execution have AWS evidence. Retained processes, reboot recovery, collaboration, individual authorization and aggregate resource/storage enforcement remain qualification targets. |
| 7. Usage visibility | Monitor consumption across gateway servers. | External usage export and its delivery contract are roadmap work. |
| Later: monetary budgets | Cap paid inference while keeping explicitly exempt models available. | Token quotas do not enforce USD spending or provide billing/chargeback. |

For phase 1, ordered first-match rules mean a request charges its matching model
rule **or** the catch-all, not both. Simultaneous user/model/parent limits are a
separate phase 5 requirement. Persistent Valkey state also does not itself
provide a usage dashboard.

## Upstream 0.1.x capabilities we do not use yet

These mechanisms are documented in upstream v0.1.5. Their presence upstream
is not evidence that the pinned ODH deployment or our harness paths qualify them.
Standalone recipes already expose explicit provider attachment at creation;
the remaining work includes integrating and testing that model across Praxis
paths. Managed inference routes and `openshell inference` were removed upstream
in the 0.1 series, not omitted only by the fork.

| Mechanism and upstream reference | Relevant phases and remaining integration |
| --- | --- |
| [Provider profiles and sandbox attachments](https://github.com/NVIDIA/OpenShell/blob/v0.1.5/docs/how-it-works/inference.mdx): import a reviewed profile, create a provider, then grant access with `--provider` or `sandbox provider attach/detach --wait`. | Phases 1, 2, 4: qualify explicit Praxis endpoint profiles, effective policy and credential lifecycle. Harness creation uses `--no-auto-providers` to disable automatic provider discovery/attachment; explicit `--provider` remains possible in standalone mode. Local vLLM currently uses OpenCode configuration plus endpoint policy. Attachments grant endpoint access; model selection, failover and durable quotas still need Praxis/client work. |
| [Sandbox templates](https://github.com/NVIDIA/OpenShell/blob/v0.1.5/docs/how-it-works/sandboxes/templates.mdx): `sandbox template create` and `sandbox create --template`. | Phase 6: move repeated image, environment and resource settings into reviewed workspace templates; qualify admission and aggregate capacity limits separately. |
| [Sandbox stop/start](https://github.com/NVIDIA/OpenShell/blob/v0.1.5/docs/how-it-works/sandboxes/overview.mdx#stop-and-start-sandboxes): `sandbox stop` and `sandbox start`. | Phase 6: qualify retained storage and restart behavior on the pinned Podman driver. Restarting compute is not proof of live-process continuation or reboot recovery. |
| [Workspaces](https://github.com/NVIDIA/OpenShell/blob/v0.1.5/docs/how-it-works/workspaces.mdx) and [OIDC authentication/RBAC](https://github.com/NVIDIA/OpenShell/blob/v0.1.5/docs/how-it-works/gateways/authentication.mdx): workspace membership, roles and optional token scopes. | Phases 5, 6: replace the shared operator identity with tested individual/team boundaries. Map caller identity to Praxis separately; workspace membership does not implement hierarchical token quotas. |
| [Gateway interceptors](https://github.com/NVIDIA/OpenShell/blob/v0.1.5/docs/extensibility/gateway-interceptors.mdx): gRPC extensions validate or modify allowed control-plane RPCs. | Phases 5, 6: evaluate admission rules for policy and resource changes across every relevant RPC. These hooks do not screen model request bodies. |
| [Supervisor middleware](https://github.com/NVIDIA/OpenShell/blob/v0.1.5/docs/extensibility/supervisor-middleware/index.mdx): inspect, deny or modify supported network requests and responses. | Phase 3: evaluate a guardrail service on sandbox traffic, including failure behavior, streaming and inspection limits. T2/T3 traffic outside OpenShell still requires gateway screening. |
| [OCSF JSON export](https://github.com/NVIDIA/OpenShell/blob/v0.1.5/docs/observability/ocsf-json-export.mdx): enable `ocs_json_enabled` and ship sandbox JSONL logs. [Gateway metrics configuration](https://github.com/NVIDIA/OpenShell/blob/v0.1.5/docs/how-it-works/gateways/configuration.mdx): `metrics_bind_address`. | Phase 7: qualify collection, retention, access control and delivery across servers. Security events and operational metrics do not establish a durable token-usage ledger or the later monetary-budget requirement. |

Use the [OpenShell upgrade runbook](../openshell/docs/upgrade.md) when changing
release pins; retained sandboxes must not carry old runtime state across upgrades.

## Where harnesses run

| Design | Harness and tools | Access boundary and current guide |
| --- | --- | --- |
| T2: shared RHEL host | Personal OS accounts on the server | SSH/SSM admission, loopback Praxis; [all-in-one](quickstarts/all-in-one/README.md). OS accounts are not hostile-agent sandboxes. |
| T3: remote gateway | Approved client machines | HTTPS and administrator-issued caller JWTs; [remote gateway](quickstarts/remote-gateway/README.md). Client tools remain outside server containment. |
| T4: shared sandbox environment | OpenShell sandboxes on RHEL | [OpenShell + Praxis](quickstarts/openshell-praxis/README.md) is experimental. The current single-operator setup does not yet establish the proposed shared-collaborator lifecycle. |

Per-user containers (T2a), identity-provider-issued tokens (T3a), and individual
OpenShell identities with personal/team workspaces (T4a) require separate
qualification. A shared login/control identity provides no personal workspace
privacy. An OpenShell identity does not automatically become a Praxis quota
identity; host-login limits do not automatically constrain service-owned sandboxes.

## How bootc helps

[bootc](../bootc/README.md) is a deployment mechanism across this work, rather
than another inference feature. One common Praxis/OpenShell base and one OS
image per harness make host configuration reviewable and repeatable. Pinned
workloads are pulled on first boot and cached; secrets and persistent data stay
outside the OS image. Updates and OS rollback can then be tested against the
same service setup.

The current RHEL 9 x86_64 implementation has AWS build, boot and lifecycle
evidence. It uses in-memory Praxis quotas and does not yet fulfill the durable
Valkey baseline. OS rollback does not restore application data, prove retained
harness sessions, or complete sandbox-to-Praxis routing.

## What counts as acceptance

A healthy gateway or successful image build is one checkpoint. An advertised
combination also needs a real coding/tool task with streaming and continuation,
correct usage settlement, restart/outage recovery, and evidence that credentials,
network paths and resource boundaries behave as intended. Qualify the exact
harness, provider/model, API, image and native architecture used.

Use the [testing guide](testing/README.md), [quota semantics](quickstarts/common/token-quotas.md),
[OpenShell integration matrix](quickstarts/openshell-praxis/users.md) and
[AWS bootc validation](../bootc/VALIDATION.md) for current evidence and gaps.

## Next step

Return to the [documentation map](README.md) to choose the next route, then use
the [testing guide](testing/README.md) to qualify it.
