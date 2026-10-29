# OpenClaw model access through Praxis

Run a bounded model task with OpenClaw inside OpenShell using read/write tools. Praxis holds the
upstream credentials; OpenClaw receives only a local placeholder. This path
uses the `dev` profile and `openclaw agent exec`, not a browser or gateway service.

Use a checkout containing this integration, or a bootc image built from it.
Previously published `v0.1` images do not gain the new scripts automatically.
See the [0.1.5 pin review](../../testing/upgrade-0.1.5.md) for the active pins
and release compatibility. The [0.1.3 fixture qualification](../../testing/upgrade-0.1.3.md)
and [earlier real-model evidence](../../testing/openclaw-praxis.md) are
historical records; rerun an opt-in real-model task before promotion.

## Prepare model access

First install [OpenShell manually](../openshell-single-server/manual.md) and
[Praxis](install.md), or deploy your rebuilt [bootc image](../openshell-single-server/bootc.md).
Keep provider credentials at Praxis; do not attach an OpenShell `--provider`
or enter a real key in OpenClaw's config.

Choose one route:

- **OpenAI:** follow the [Praxis credential setup](../all-in-one/in-memory.md). On bootc, use
  the [hidden-prompt secret and activation commands](../bootc/README.md).
  Set `OPENSHELL_MODEL_ID` to an exact model ID available to your account.
- **An existing local OpenAI-compatible API with a key:** configure the
  [administrator-owned custom provider](../common/providers.md#another-compatible-provider).
  `sudo scripts/common/providers enable team --openai-url https://inference.example.com/v1`
  prompts for the real key and stores a Podman secret. With a non-unified
  mutable gateway, set `PRAXIS_API_PREFIX=/providers/team` and use the cloud
  OpenClaw config. For private IP upstreams, Praxis must also explicitly permit
  private upstreams in its reviewed configuration. Custom HTTP upstreams and
  bootc custom-provider management require a separately reviewed configuration. The API must support streaming chat completions and tool calls.
  Keep the key in a Praxis service-account Podman secret, not in the sandbox.
- **Private vLLM without a key:** use the [separate inference server guide](../common/vllm.md).
  The mutable installer serves `qwen3-8b`; the bootc recipe serves `Qwen/Qwen3-8B`.
  Use the ID actually returned by your server's model listing. The dedicated
  vLLM template disables Qwen thinking per request for bounded coding tasks.

## Manual container deployment

Run these commands as the configured OpenShell service owner, using its HOME,
XDG runtime directory, and user session bus as shown in the installation guide.
Assume Praxis is already ready on host loopback port 8080:

```bash
export OPENSHELL_MODEL_ID='YOUR_SERVED_MODEL_ID'
export PRAXIS_PORT=8080
# Cloud or keyed private provider managed by Praxis:
config="$PWD/configs/openshell-praxis/openclaw"
# For the dedicated credentialless vLLM route instead:
# config="$PWD/configs/vllm/openclaw"
openshell/harnesses/openclaw/create.sh --profile dev \
  --name openclaw-dev --config "$config"
openshell/harnesses/openclaw/run.sh --name openclaw-dev --timeout 600 \
  --message 'Write /home/node/.openclaw/workspace/greeting.txt containing a short greeting, then read it and report its contents.'
```

The command returns JSON. Require `ok: true`, a useful `final` response, and
check the file independently through `connect.sh --name openclaw-dev`.
The runner sends the task through stdin and directs SQLite temporary files to
policy-permitted `/tmp`. It creates disposable per-call agent state; it does
not retain a conversation between invocations.

The cloud development policy also permits selected GitHub/npm traffic. The vLLM
policy permits only `GET /vllm/v1/models` and
`POST /vllm/v1/chat/completions` on the Praxis model endpoint. Neither permits
direct cloud model access. Do not combine this mode with automatic provider
injection.

## Bootc deployment

On an OpenClaw bootc host built from this checkout, first activate Praxis
credentials and choose cloud, local vLLM, or remote-vLLM inference using the
[bootc guide](../openshell-single-server/bootc.md). For cloud routing:

```bash
IFS= read -r -p 'Model ID: ' model_id
uid="$(id -u openshell-svc)"
cd /
sudo runuser -u openshell-svc -- env HOME=/var/lib/openshell-svc \
  XDG_RUNTIME_DIR=/run/user/"$uid" \
  DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/"$uid"/bus \
  OPENSHELL_BIN=/usr/bin/openshell OPENSHELL_MODEL_ID="$model_id" \
  /usr/share/secure-single-server/openshell/harnesses/openclaw/create.sh \
  --profile dev --name openclaw-dev \
  --config /usr/share/secure-single-server/configs/openshell-praxis/openclaw
sudo sss-bootc harness run --name openclaw-dev --timeout 600 \
  --message 'Write /home/node/.openclaw/workspace/greeting.txt containing a short greeting, then read it and report its contents.'
```

For the bootc-managed vLLM modes, `sudo sss-bootc harness create --profile dev
--name openclaw-dev` selects the local model configuration automatically; use
that instead of the cloud creation command. `harness connect` still opens a
shell for inspecting the workspace.

## Validation limits

The pinned OpenShell sandbox denies process-group signals with `EPERM`.
OpenClaw's `exec` tool requires those signals to certify process-tree cleanup,
so it returns a cleanup error even after a command finishes. This integration
exposes only `read` and `write` tools. Run generated code manually through
`connect.sh`, or use OpenCode when the model must execute commands itself.
The real-model acceptance test independently tests generated code through
sandbox SSH. Do not enable `exec` until that cleanup contract is qualified.


Automated tests cover authenticated and credentialless synthetic upstreams,
streamed tool execution, continuation, invalid upstream credentials, and
OpenShell allow/deny enforcement. AWS also exercises the pinned workload and
bootc container build. These [0.1.3 upgrade checks](../../testing/upgrade-0.1.3.md)
used a controlled model fixture, and the same pins passed
[real OpenAI model tasks on manual and booted bootc deployments](../../testing/upgrade-0.1.3-e2e.md).
The earlier Qwen GPU results and both records predate the active 0.1.5 pins;
real-model and GPU acceptance still require separate opt-in qualification.
A synthetic credential test does not qualify a paid OpenAI account or every
OpenAI-compatible service. Browser login, gateway service deployment, retained
sessions, and `--backend` remain outside this tested path.
