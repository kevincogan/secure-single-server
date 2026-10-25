# llm-d-sc semantic-routing quickstart

This quickstart runs the [llm-d-sc semantic-routing demo](https://github.com/RMalone8/llm-d-sc-demo)
with explicit Podman networking. It does **not** use OpenShift, RHOAI, KServe, Routes, or `podman compose`.

Deterministic tests use synthetic OpenAI-compatible backends. GitHub CI checks
image pins, container hardening, classifier readiness, routing and failover,
WebUI, and trace API without Qwen weights or a GPU. A manual AWS scenario
validates real vLLM.

## Architecture

The optional browser path adds Open WebUI and a repository-owned trace relay:

```text
Open WebUI
  -> trace-ui :8080
  -> Praxis :8080
  -> llm-d-sc classifier :50051
  -> trace-ui backend relay :8081 or :8082
  -> synthetic vllm-cpu or vllm-gpu backend
```

The front relay records requests in SQLite and forwards them to Praxis. Backend
relays add `X-Demo-Route` and `X-Demo-Classification` and record attempts,
including failovers. The dashboard is at `/`; traces are at `/_trace/api/traces`.

The validated AWS topology splits CPU and GPU work across two hosts:

```text
CPU host (m7i.4xlarge)
  Open WebUI + trace-ui + Praxis + llm-d-sc + vllm-cpu
        |
        | private VPC TCP/8000
        v
GPU host (g6.8xlarge)
  vllm-gpu only
```

This split is required because the selected G6 shape lacks the AVX-512 or AMX
instructions required by the pinned CPU vLLM image. Both hosts serve
`RedHatAI/Qwen3.8-27B-INT4`; llm-d-sc routes by prompt complexity.

## Run the deterministic test

From an amd64 Linux host with Podman running:

```bash
python3 -B tests/llm-d-sc/unit.py
CONTAINER_ENGINE=podman python3 tests/llm-d-sc/integration.py
```

The integration test pulls pinned images, creates a temporary network and
model volume, waits for classifier readiness, sends simple and reasoning
prompts through WebUI, checks traces, then cleans up. Pass `--keep` to leave the
stack running for [OpenCode](#run-opencode-through-the-routed-backend). Synthetic
backends also return OpenAI-compatible events for streaming clients.

A successful run reports:

- `SIMPLE` with `x-llm-d-sc-status: OK`, routed to `vllm-cpu`.
- `REASONING` with `x-llm-d-sc-status: OK`, routed to `vllm-gpu`.
- A synthetic CPU 503 fails over to the alternate backend and records both hops.
- Open WebUI health, model discovery, chat, and trace API checks passed.

GitHub CI runs this path with Docker; it does not test real generation, GPU
scheduling, model quality, throughput, or latency.

## Run the AWS split-host scenario

This manual, billable scenario uses two amd64 RHEL 9 hosts in one VPC with
rootless Podman, 200 GiB disk on CPU and 300 GiB on GPU. CPU needs AVX-512 or
AMX; the validated `g6.8xlarge` GPU host had an NVIDIA L4, driver, and CDI
device (`nvidia.com/gpu=0`).

The sizing presets are:

- `configs/aws/llm-d-sc-webui-cpu.json`: `m7i.4xlarge`, 64 GiB RAM.
- `configs/aws/llm-d-sc-webui.json`: `g6.8xlarge`, one L4 GPU, 128 GiB RAM.

Allow only the CPU security group to reach GPU TCP/8000; do not expose it
publicly. Enable user lingering on both hosts before starting containers over SSH:

```bash
sudo loginctl enable-linger "$USER"
```

On the GPU host, start only the backend on its private address; replace
`GPU_PRIVATE_IP` with that host's private IPv4 address:

```bash
CONTAINER_ENGINE=podman \
LLM_D_SC_BACKEND_TIMEOUT=720 \
python3 tests/llm-d-sc/integration.py \
  --real --gpu-only --gpu-publish-host GPU_PRIVATE_IP --keep
```

On the CPU host, run the complete stack against that endpoint:

```bash
CONTAINER_ENGINE=podman \
LLM_D_SC_BACKEND_TIMEOUT=720 \
python3 tests/llm-d-sc/integration.py \
  --real --remote-gpu GPU_PRIVATE_IP --keep
```

Tunnel to the loopback WebUI URL printed by the test, replacing the port:

```bash
ssh -L 8080:127.0.0.1:PRINTED_WEBUI_PORT USER@CPU_PUBLIC_IP
```

Open `http://127.0.0.1:8080`; reach the trace dashboard using its printed port.

Add `--cache-volume NAME` to reuse a named Podman cache and avoid downloading
the 18 GiB model again. The test does not remove named caches.

## Run OpenCode through the routed backend

Run this with an integration stack still up (`--keep`), either mocked or
split-host. OpenShell must run on the stack host so its sandbox can reach
`host.openshell.internal`. Set `PRINTED_TRACE_PORT` to the port in the printed
`trace_ui.url`, then create an OpenCode workload using this relay as its model gateway:

```bash
os_run env PRAXIS_PORT=PRINTED_TRACE_PORT \
  openshell/harnesses/opencode/create.sh \
  --profile dev \
  --name opencode-llm-d-sc \
  --config "$PWD/configs/llm-d-sc"
```

The template supplies model ID `Semantic-Qwen`. The strict policy permits only
model discovery and chat completion through the trace relay to Praxis. The
provider marks the model as reasoning but does not replay interleaved reasoning,
which can confuse Qwen's parser after tool calls.

## AWS validation record

The split-host scenario was validated on 2026-10-20 in `us-east-1`:

| Check | Result |
| --- | --- |
| CPU host | `m7i.4xlarge`, AVX-512 available, 64 GiB RAM |
| GPU host | `g6.8xlarge`, NVIDIA L4, driver 580.178.04 |
| Model | `RedHatAI/Qwen3.8-27B-INT4`, 18.12 GiB weights |
| Simple prompt | `SIMPLE` -> `vllm-cpu`, HTTP 200, 19.342 s |
| Reasoning prompt | `REASONING` -> `vllm-gpu`, HTTP 200, 10.086 s |
| Open WebUI | health, model list, and chat passed |
| Trace API | CPU and GPU routes both recorded |

These are single-request measurements, not a benchmark. GPU load used 16.84 GiB
VRAM and steady serving about 20.5 GiB. Real-mode prompts disable Qwen thinking
so validation receives final content within the token budget.

OpenCode was also validated on disposable AWS `m7i.2xlarge` RHEL 9.6 with
OpenShell v0.1.4 and mocked backends; simple and reasoning prompts each routed
to the expected CPU or GPU backend in one turn.

## Security boundary

Host-published listeners stay on loopback. Praxis and backends use a private
container network; split-host GPU traffic uses private VPC addressing and a
source security-group rule.

`insecure_options.allow_private_upstreams: true` disables upstream SSRF
protection for private backends. Do not expose the listener publicly without a
reviewed network and authorization boundary.

`WEBUI_AUTH=false` is only for a disposable loopback demo. Shared deployments
need authentication and HTTPS. The trace relay stores prompts and responses
(up to 16,000 characters) in temporary SQLite; treat this data as sensitive.

## Temporary image

The integration uses the filter-enabled Praxis image pinned in
[`images.env`](../../../configs/llm-d-sc/images.env):

```text
quay.io/rmalone/praxis-ai-llm-d-sc@sha256:1db1eb2a115273836a186018f20df32197336a14ed2026cede8e0946385893dc
```

This linux/amd64 image's registry metadata identifies
[`praxis-proxy/ai`](https://github.com/praxis-proxy/ai) as its source but does
not include a source revision. It is the temporary digest-pinned input approved
for this integration in [issue #73](https://github.com/redhat-et/secure-single-server/issues/73);
[issue #74](https://github.com/redhat-et/secure-single-server/issues/74) tracks
consolidating `llm_d_sc` into the reviewed Praxis image. Keep the digest pin;
do not use the mutable `latest` tag.
