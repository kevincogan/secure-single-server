# Optional Qwen3-8B inference

This guide covers private Qwen inference deployment. For an informational
overview of the components and model access paths, see the
[Architecture overview](../docs/quickstarts/architecture-walkthrough/README.md).

The supported topology runs `Qwen/Qwen3-8B` in vLLM on a separate server. The
bootc single server keeps only OpenShell, Praxis, and the harness, preserving
the **OpenCode → Praxis → vLLM** boundary without coupling inference resources
to the single-server host. The older co-located bootc profile remains available
for compatibility but is deprecated for new deployments.

The configured request path is **OpenCode → Praxis → vLLM**. Local vLLM
serving and the host Praxis route can be checked independently. The sandbox
path uses the trusted host mapping in OpenShell v0.1.5. Rebuilt OpenClaw images also support [bounded local model/tool tasks](../docs/quickstarts/openshell-praxis/openclaw.md); previously published images require a rebuild.

## Host requirements

- Published OS images: `quay.io/redhat-et/secure-single-server-vllm-cpu:v0.1`
  and `quay.io/redhat-et/secure-single-server-vllm-gpu:v0.1`.
- Separate CPU vLLM server: x86_64 with AVX-512, at least 32 GB RAM, and 64
  GiB recommended. This is a starting resource budget, not a throughput
  guarantee. The CPU profile uses BF16, a 4 GiB KV cache, and no explicit CPU
  affinity/NUMA binding. Boot `vllm-cpu`; it omits NVIDIA drivers and the
  Container Toolkit.
- GPU: exactly one NVIDIA L4, a compatible NVIDIA host driver, and
  `nvidia-ctk` installed in the bootc OS image. The reconciler regenerates CDI
  at boot. `vllm-gpu` includes the NVIDIA 580 open driver and Container
  Toolkit, compiled for the kernel in the published image. Secure Boot with a
  custom signing key is not configured.
- Persistent disk on the vLLM server: allow space for roughly 16 GB of model
  weights, workload images, and caches. Budget at least 100 GiB for CPU or
  200 GiB for GPU demonstrations and check free space first.
- First startup needs access to Docker Hub and Hugging Face download endpoints.
  No Hugging Face token is required for this public model.

Both profiles use BF16, a 16,384-token context, one concurrent sequence, eager
execution, and tensor parallel size 1. GPU memory utilization is limited to
90%. OpenCode reserves at most 2,048 output tokens within that context. Thinking is
disabled by default for predictable demo latency; callers can explicitly
set `chat_template_kwargs.enable_thinking` to true.

## Separate AWS server and endpoint discovery

Use the [AWS deployment guide](../docs/testing/aws.md#separate-vllm-server)
to launch a dedicated tagged vLLM VM, grant TCP 8000 only to the single
server's security group, and discover its private address. After both VMs are
in the same VPC, the administrator-side helper prints an `RFC1918_IP:PORT` endpoint;
no AWS credential or instance profile is placed on the single server.

```console
source scripts/aws/session.sh
VLLM_INFO="$(aws_test_vllm_endpoint vllm-server-gpu)" \
  || printf 'Endpoint discovery failed; inspect the vLLM VM.\n'
VLLM_ENDPOINT="$(printf '%s' "${VLLM_INFO:-}" | jq -er '.VllmEndpoint')" \
  || printf 'Endpoint JSON was invalid.\n'
printf 'Private vLLM endpoint: %s\n' "${VLLM_ENDPOINT:-unknown}"
```

On the dedicated server, deploy `vllm-cpu:v0.1` on a CPU instance or
`vllm-gpu:v0.1` on the L4 instance. Do not substitute the mutable RHEL vLLM
installer or a locally built image. On the booted single server, configure
Praxis without changing the OpenShell harness policy:

```console
sudo sss-bootc inference remote-vllm "$VLLM_ENDPOINT"
sudo sss-bootc inference status
sudo sss-bootc inference check
```

Praxis continues listening only on `127.0.0.1:8080`; the sandbox still reaches
`host.openshell.internal:8080` and has no direct vLLM or cloud-provider egress.
If the remote server stops, Praxis returns an upstream error rather than
falling back to a cloud provider.

## Deploy a dedicated vLLM image

Use the published `v0.1` image that matches the server hardware. The dedicated
`vllm-cpu` and `vllm-gpu` images exclude Praxis and OpenShell. The CPU image
omits NVIDIA components; the GPU image includes the NVIDIA 580 open driver and
Container Toolkit:

```console
sudo bootc switch quay.io/redhat-et/secure-single-server-vllm-gpu:v0.1
sudo bootc status
sudo systemctl reboot
```

Use `secure-single-server-vllm-cpu:v0.1` on a CPU server. For a fresh single
server or bare-metal host, use a standard bootc deployment workflow with the
published reference; do not create or substitute a locally built image.

Deployment changes the host's SSH host keys. Compare the new fingerprint
through a trusted AWS or console channel before accepting it and reconnecting
as `cloud-user@BOOTC_HOST`. Do not bypass host-key verification in production.

GPU drivers are OS components; vLLM and model weights remain separate workload
containers and persistent data. On the booted host, select the mode matching
the image. Mismatched selections are rejected before starting a container:

```console
sudo sss-vllm select cpu
# On the vllm-gpu image booted on the prepared single-L4 host:
sudo sss-vllm select gpu
sudo sss-vllm status
sudo journalctl -u secure-single-server-vllm.service -b
sudo journalctl _SYSTEMD_USER_UNIT=vllm.service -f
```

The first command pulls the selected pinned image. Model download/loading
continues after systemd starts the container; an active unit alone does not
prove inference readiness. Retry the health request while loading, inspecting
logs if startup fails:

```console
curl --fail --max-time 30 "http://${VLLM_ENDPOINT:-127.0.0.1:8000}/health"
curl --fail --max-time 30 "http://${VLLM_ENDPOINT:-127.0.0.1:8000}/v1/models"
curl --fail --max-time 600 "http://${VLLM_ENDPOINT:-127.0.0.1:8000}/v1/chat/completions" \
  -H 'Content-Type: application/json' \
  -d '{"model":"Qwen/Qwen3-8B","messages":[{"role":"user","content":"Reply with a short greeting."}],"max_tokens":64,"temperature":0.7,"chat_template_kwargs":{"enable_thinking":false}}'
```

Confirm a nonempty assistant response. CPU latency can be substantial. The
API is unauthenticated and listens on all host interfaces; restrict TCP 8000
to the single-server security group and do not expose it to the Internet.
Use the Praxis route below for harness configuration; sandbox bypass denial
remains a required qualification test.

```console
sudo sss-vllm select disabled
```

Disabling stops the service and removes its generated Quadlet while retaining
images and model caches. It does not delete downloaded data. Mode selection
persists in `/etc/secure-single-server/vllm-mode`; caches live under
`/var/lib/vllm-svc/cache`. A separate boot service ensures a failed vLLM pull
or preflight does not block Praxis/OpenShell startup. Failed reconciliation
retries every 30 seconds. Inspect failures with the journal commands above.

## Image pins and validation

[Image and model pins](https://github.com/redhat-et/secure-single-server/blob/main/configs/vllm/images.env) belong to the OS deployment.
The CPU image is vLLM `v0.19.0-x86_64`; the GPU image is `v0.19.0`.
Both use the same pinned Hugging Face model revision. This guide intentionally
refers to the published OS images by their `v0.1` tags.

GPU mode disables SELinux container labeling for this container to allow CDI
access, following the reference lab. SELinux remains enforcing on the host.
The service is rootless, runs as container UID 1001, drops capabilities, and
uses private shared memory. The L4 runtime check exercises driver/CDI access with these restrictions. CPU mode keeps normal container labeling.

See [image publication](README.md#image-publication) and the automated checks
that run without model weights or provider credentials.
See the runtime report for boot, inference, sandbox and lifecycle results.
Registry-failure recovery, offline operation, sustained load, and additional
hardware remain separate qualification work. Static rendering tests alone do
not establish model readiness or policy enforcement.

References: [vLLM CPU installation](https://docs.vllm.ai/en/v0.19.0/getting_started/installation/cpu/),
[Qwen3-8B model card](https://huggingface.co/Qwen/Qwen3-8B),
and [reference GPU launcher](https://github.com/cooktheryan/openshell-lab/blob/9b35d982bc8fea3f36a4069b1eaa0098fb9fbabd/labs/lab5/configure-vllm.sh).

## Route Praxis to the deprecated local backend

After local vLLM answers the direct health/model/chat requests, select the local
backend on the booted host:

```console
sudo sss-bootc inference vllm
sudo sss-bootc inference status
sudo sss-bootc inference check
```

`check` generates a short completion through vLLM and then through Praxis;
HTTP errors, missing models, and empty completions fail the check. It does not
qualify streaming, tool calling, the harness, or policy enforcement. Praxis
continues applying its request rate and shared in-memory token limits. A slow
CPU request can still hit runtime timeouts; this path needs load testing.

The local Praxis container uses host networking to reach vLLM's loopback port
across their separate rootless accounts. Its listeners bind only to
`127.0.0.1:8080` and admin `127.0.0.1:9901`. Port 8081 is not used. The local
configuration neither reads cloud-provider secrets nor routes to a cloud API.
An unavailable vLLM produces an upstream failure instead of a cloud fallback.
Disabling vLLM leaves the Praxis backend selection unchanged.

Selection persists in `/etc/secure-single-server/inference-backend`. To return
to the existing cloud profile, provision the usual OpenAI/Anthropic secrets and
run `sudo sss-bootc inference cloud`. Selecting cloud without secrets stops
Praxis until they are provisioned. Existing sandboxes are not reconfigured by
backend changes; avoid changing it while a sandbox is in use.

## OpenCode configuration

Use the **OpenCode** bootc variant. Once either vLLM backend is selected, this
command automatically selects the Qwen3-8B Praxis provider and dedicated dev
policy, rejecting a direct `--provider` or custom `--config` override:

```console
sudo sss-bootc harness create --profile dev --name qwen-dev
sudo sss-bootc harness connect --name qwen-dev
# From the host, run the repository smoke test against that sandbox:
sudo bootc/test-inference qwen-dev
```

Only the writable dev profile is provided for this path. Its network policy
allows the Praxis endpoint at `host.openshell.internal:8080`, with no direct
vLLM or cloud-provider endpoint. It intentionally omits package and GitHub
network access. The pinned image must supply its OpenCode provider adapter;
a missing dependency must be packaged into the image before qualification.
Both vLLM profiles enable Hermes tool-call parsing and Qwen3 reasoning parsing.
The configured context and output limits are carried through provider rendering.
Existing sandboxes retain their installed configuration and policy; recreate them
after changing these defaults.

Upstream OpenShell removed workspace-global managed inference routes and the
`openshell inference` commands in the 0.1 series; this is not an ODH-only omission.
The supported replacement is [provider profiles and per-sandbox attachments](https://github.com/NVIDIA/OpenShell/blob/v0.1.5/docs/how-it-works/inference.mdx#migrate-from-managed-inference-routes).
This example uses an explicit **OpenCode** Praxis provider configuration plus a
sandbox policy permitting only the Praxis endpoint. It does not yet import an
OpenShell provider profile or attach a provider; that integration is tracked in
[the roadmap](../docs/roadmap.md#upstream-01x-capabilities-we-do-not-use-yet).
OpenCode's canonical binary path is `/usr/local/bin/opencode`; its
`/usr/local/sbin` launcher is a symlink.

See [runtime validation](VLLM-VALIDATION.md) for the tested hardware, image revisions,
actual inference results, and remaining limits. Use the dedicated local policy;
the general development profiles intentionally permit additional network access.

CPU/GPU selection queues preparation asynchronously so a later disable command
can cancel a slow image pull. Check status and `/health` for readiness. Status
does not wait for the reconciliation lock; disabling waits for the service to stop.

## Follow the validated co-located path

This compatibility path is **OpenCode → Praxis → vLLM** on one bootc host. The
preferred deployment places vLLM on a separate private server; use the earlier
sections in this guide for that topology. The co-located path uses no
cloud-provider credential or fallback.

### 1. Start local inference

After deploying the OpenCode bootc image, select CPU or single-L4 GPU mode:

```console
sudo sss-bootc vllm cpu
sudo sss-bootc vllm status
```

Wait for the model to load, then confirm vLLM is answering:

```console
curl --fail http://127.0.0.1:8000/health
curl --fail http://127.0.0.1:8000/v1/models
```

This direct request is a diagnostic. It shows that the model is running; it
does not show that the sandbox uses the intended route. vLLM is loopback-only
and is not the endpoint given to the harness.

### 2. Route requests through Praxis

```console
sudo sss-bootc inference vllm
sudo sss-bootc inference status
sudo sss-bootc inference check
```

The check calls vLLM and then Praxis. The
[Praxis configuration](https://github.com/redhat-et/secure-single-server/blob/main/configs/vllm/praxis.yaml) binds to `127.0.0.1`,
strips caller authorization headers, applies two requests per second, and
enforces a shared one-million-token rolling day with a 4,096-token reservation
per request. These are shared allowances, not per-user or USD budgets; see
[quota semantics](../docs/quickstarts/common/token-quotas.md).

### 3. Connect the OpenCode sandbox to Praxis

```console
sudo sss-bootc harness create --profile dev --name qwen-dev
sudo sss-bootc harness connect --name qwen-dev
```

The [OpenCode provider configuration](../configs/vllm/harness/harness-provider.json.in)
uses the Praxis URL and a placeholder local API key. It contains no provider
secret. The [sandbox network policy](https://github.com/redhat-et/secure-single-server/blob/main/configs/vllm/harness/profiles/dev/policy.yaml)
allows OpenCode and Node to use only the listed Praxis model endpoints. The
sandbox has no direct vLLM or cloud-provider endpoint.

### 4. Run the validation suite

From the host, run the end-to-end test against the sandbox:

```console
sudo bootc/test-inference qwen-dev
```

The test checks model listing through Praxis, denies direct connections to
vLLM and `api.openai.com`, confirms the denials in OpenShell audit records,
checks a streamed completion and bash tool call, and independently reads back
a file written in `/sandbox`. It also checks for errors in OpenCode's JSON
events. The [runtime validation record](VLLM-VALIDATION.md) documents the
tested images, hardware, and remaining limits.

Optionally stop vLLM and call the gateway:

```console
sudo sss-bootc vllm disabled
curl --max-time 30 -i http://127.0.0.1:8080/v1/models
```

Praxis should return an upstream error instead of sending the request to a
cloud provider. Re-enable local inference with `sudo sss-bootc vllm cpu` or
`sudo sss-bootc vllm gpu`.

### 5. Remove the sandbox

Deleting a sandbox destroys its work. Export anything you need first:

```console
sudo sss-bootc openshell sandbox delete qwen-dev
sudo sss-bootc vllm disabled
```
