# Single-server qualification and policy reference

[Deployment choices](README.md) · [Manual deployment](manual.md) · [Bootc deployment](bootc.md)

## Current qualification status

| Harness | Qualified in the single-server OpenShell path | Explicitly not qualified |
| --- | --- | --- |
| OpenCode | Sandbox lifecycle and policy controls; [historical 0.1.3 Praxis fixture model, write and bash tools](../../testing/upgrade-0.1.3.md) | Fresh paid-provider and real-GPU inference on the 0.1.5 pins; the narrower `review` profile |
| OpenClaw | Sandbox lifecycle and policy controls; [historical 0.1.3 bounded Praxis fixture model and write tool](../../testing/upgrade-0.1.3.md) | Automatic `exec`, browser/gateway authentication, retained sessions, `--backend`, and untested providers |

## AWS verification

The active [0.1.5 pin review](../../testing/upgrade-0.1.5.md) records release
compatibility and offline validation. The [0.1.3 upgrade qualification](../../testing/upgrade-0.1.3.md)
remains historical evidence for both harnesses' controlled model/tool tests and
rebuilt bootc container checks. Neither record qualifies a fresh booted OS
rollout or real inference on the 0.1.5 pins. The following published-image
results predate both upgrades.

On 2026-10-02, the manual path was exercised on a disposable RHEL 9 x86_64 EC2
host in `us-east-1`. It created Ready OpenCode and OpenClaw sandboxes, passed
the controlled allow/deny policy test, verified two-CPU, 4 GiB, 2048-PID
limits, confirmed SELinux Enforcing and lingering, and showed ports 8090/8091
bound only to loopback.

The bootc path was then qualified in the same region from the published Quay
`v0.1` images, not from a locally rebuilt image. Both published variants
started the reconciliation
service, rendered the pinned `sandbox_runtime_image`, created Ready sandboxes,
passed file-write and controlled allow/deny tests, and reported the same
runtime, SELinux, lingering, and loopback-only results as the manual path.
Model routing was not active during this OpenShell qualification; follow the
Praxis guide for that separate model-path test. See the
[bootc validation record](../../../bootc/VALIDATION.md) for the full AWS
evidence.

## Why OpenShell

OpenShell surrounds the harness with a locked service account, rootless
Podman, filesystem and network policy, runtime ceilings, and auditable
allow/deny decisions. The bootc image packages the pinned control plane,
harness, and policies into one repeatable deployment.

The current deployment is for a **trusted single operator**. It is not
multi-tenant authorization, and it does not inspect prompts or guarantee that
code produced by a model is trustworthy. Read the
[OpenShell Overview](../../../openshell/docs/README.md) before exposure to
valuable data or shared use.

## What the policy protects

OpenShell profiles are applied when a sandbox is created. You do not install a
policy afterward and hope the harness uses it.

| Control | What the profile declares | Default `dev` behavior |
| --- | --- | --- |
| Filesystem | Read-only and read-write path sets, plus optional workspace inclusion. | Inside the sandbox, `/usr`, `/lib`, `/lib64`, `/etc`, `/proc`, `/dev/urandom`, and `/opt` are read-only. OpenCode permits writes under `/sandbox`, `/home`, `/tmp`, and `/dev/null`. OpenClaw keeps `/app` read-only, disables automatic working-directory grants, and uses `/home/node/.openclaw/workspace` under writable `/home`; `/tmp` and `/dev/null` are also writable. |
| Network | Named endpoint allowlists scoped to exact harness/tool binary paths. | OpenCode permits selected model, OpenCode registry, GitHub, and npm endpoints. OpenClaw permits selected model, GitHub, and npm endpoints. Other destinations are denied. |
| Runtime | Rootless Podman execution with per-sandbox CPU, memory, and PID limits. | Two CPUs, 4 GiB of memory, and 2048 PIDs by default; these are per-sandbox limits, not a host-wide budget. |
| Credentials | No provider key is forwarded by the SSH helper. | Standalone credentials must be explicitly registered and attached. Integrated model-routing mode rejects direct provider attachment. |

The default development endpoints are:

| Harness | Permitted on TCP 443 |
| --- | --- |
| OpenCode | `api.anthropic.com`, `api.openai.com`, `opencode.ai`, read-only `api.github.com`, `github.com`, and `registry.npmjs.org`. |
| OpenClaw | `api.anthropic.com`, `api.openai.com`, read-only `api.github.com`, `github.com`, and `registry.npmjs.org`. |

The exact endpoint and filesystem rules differ by profile. Review the policy
before deployment rather than inferring it from the profile name:

- [OpenCode policies](https://github.com/redhat-et/secure-single-server/blob/main/openshell/harnesses/opencode/profiles/dev/policy.yaml)
- [OpenClaw policies](https://github.com/redhat-et/secure-single-server/blob/main/openshell/harnesses/openclaw/profiles/dev/policy.yaml)
- [Full policy qualification contract](../../../openshell/docs/README.md#policy-enforcement-and-qualification)

Start with the `dev` profile for the first smoke test. It is intentionally wide
enough for the CLI to operate; the manual section records current harness
limitations. Treat a move to `automation`, `interactive`, or a custom profile as
a reviewed policy change with fresh positive and negative network tests.

Important limits:

- The installer rejects a host without Landlock ABI 3 or newer, but
  `landlock.compatibility` remains `best_effort`; record actual runtime
  filesystem enforcement.
- GitHub API access is method-restricted. Git Smart HTTP permits clone and
  fetch operations on `github.com`, while push remains denied. An allowed
  endpoint can still receive data from a malicious harness or tool.
- A policy parsing or sandbox Ready result does not prove enforcement. Use a
  successful positive control plus an explicit denial when qualifying a host.
- Deleting a sandbox can destroy work. Export anything you need first.

## Custom runtime limits

Each sandbox defaults to two CPUs, 4 GiB, and 2048 PIDs. These are per-sandbox
ceilings, not aggregate host reservations. In the [manual guide](manual.md),
pass overrides through the service-owner helper when creating a sandbox:

```bash
os_run env OPENSHELL_SANDBOX_CPU=1 OPENSHELL_SANDBOX_MEMORY=512Mi \
  "$repo/openshell/harnesses/$harness/create.sh" --profile dev --name limited-dev
```

OpenCode's `review` profile currently denies its CLI runtime-state directory;
a Ready sandbox does not prove the CLI can run. OpenClaw's `--backend` option
is unsupported. Its browser workflow and retained service sessions are not
qualified. Keep management and browser ports private.

See [workload templates](../../development/workload-templates.md) for catalog profiles, idempotent sync, and labelled inventory.
