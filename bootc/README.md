# RHEL 9.8+ bootc images

> **Where this fits:** The operations stop. Use it after selecting a deployment
> route, not as a substitute for understanding its boundaries.

bootc turns the reviewed OpenShell setup and selected harness into a repeatable
RHEL host deployment. For the curated OpenCode/OpenClaw manual and quickstart
paths, start with the
[OpenShell single-server guide](../docs/quickstarts/openshell-single-server/README.md).
Praxis is optional model routing and shared-quota tooling; its integration
remains [experimental](../docs/quickstarts/openshell-praxis/users.md).

Deploy one of the project's published x86_64 OS images:

```text
secure-single-server:opencode
secure-single-server:openclaw
secure-single-server:praxis
secure-single-server:vllm-cpu
secure-single-server:vllm-gpu
```

The target must already be a bootc host. `bootc switch` refuses a package-based
RHEL installation (`System not booted via bootc`), so provision bootc first, for
example by installing the RHEL bootc image with `bootc install to-disk`, or use
a bootc cloud image. A standard RHEL 9 cloud AMI is package-based and cannot
switch.

The harness images include Podman, the native
OpenShell CLI, deployment configuration, and a boot service for OpenShell and
the optional, separately activated Praxis path. The standalone `praxis` image is
a slimmer direct RHEL
bootc image for gateway-only deployments; it excludes OpenShell, harnesses, and
NVIDIA components. The standalone `vllm-cpu` and `vllm-gpu` images are also
direct RHEL bootc images; they exclude Praxis and OpenShell. The CPU image
omits NVIDIA components, while the GPU image includes the NVIDIA 580 open
driver and Container Toolkit. Each harness image adds one harness's selection
and scripts/policies. Harness binaries run in the pinned workload containers,
not directly on the host. When Praxis is activated, this path uses its
in-memory quota profile; OpenShell is administrator-operated. It does not yet
provide Valkey, remote-gateway TLS/JWT, or ordinary-user access to OpenShell.
It is a deployment
foundation for the [phased gateway goals](../docs/roadmap.md), not completion of
the durable-quota or retained-session requirements.

## Published images

The bootc workflow publishes deployable images to `quay.io/redhat-et` with the
release-facing `v0.1` tag. This informational path intentionally uses that
mutable tag directly; do not substitute locally built images. The internal
`base` image is not published.

```text
quay.io/redhat-et/secure-single-server-praxis:v0.1
quay.io/redhat-et/secure-single-server-vllm-cpu:v0.1
quay.io/redhat-et/secure-single-server-vllm-gpu:v0.1
quay.io/redhat-et/secure-single-server-opencode:v0.1
quay.io/redhat-et/secure-single-server-openclaw:v0.1
```

## Pull on first boot

Application containers are **not embedded** in the OS image. First boot pulls
the repository's pinned Praxis and OpenShell control-plane images,
plus only the selected harness image. This keeps OS distribution smaller;
the installed host still needs disk space for the OS, container cache and
workspace data. The native OpenShell CLI is included in the OS image so boot
never writes into `/usr`.
The Praxis image is present for the optional route; without secrets and
activation it does not provide model access, while OpenShell remains usable.

Pulls use persistent, separate rootless stores for `praxis-svc` and
`openshell-svc`. Each boot checks for the exact pinned images locally before
pulling. A cached reboot needs no registry access. Failed pulls leave the boot
service failed/retrying every 30 seconds, rather than starting with different
tags. The OS remains accessible for diagnosis.

Initial startup requires DNS and HTTPS access to Quay and its blob storage
endpoints. Private workload registries need authentication in the relevant
service account's Podman authfile; credentials are never baked into the image.

## Deploy a published image

Use only the published references listed above. For this informational path,
deploy the mutable `v0.1` tag directly:

```console
sudo bootc switch quay.io/redhat-et/secure-single-server-opencode:v0.1
sudo bootc status
sudo systemctl reboot
```

Substitute the selected variant's published reference. For a fresh single
server or bare-metal host, use a standard bootc deployment workflow and supply
one of those published references as the image source; do not create or
substitute a locally built image. For EC2, preserve the administrator SSH-key
provisioning and required AWS boot/network configuration.

After the reboot, verify the deployment on the booted host:

```console
ssh cloud-user@BOOTC_HOST
sudo journalctl -u secure-single-server.service -b
sudo sss-bootc openshell --version
sudo sss-bootc openshell sandbox list
```

## Optional Praxis secrets

Wait for the initial boot service to finish. It reports that Praxis awaits
secrets; OpenShell can already be inspected. Provider keys go through stdin to
the Praxis account's Podman secret store. Example in Bash, with tracing off:

```bash
set +x
read -r -s -p 'OpenAI key: ' key; printf '\n'
printf '%s' "$key" | sudo sss-bootc secret openai v1
unset key
read -r -s -p 'Anthropic key: ' key; printf '\n'
printf '%s' "$key" | sudo sss-bootc secret anthropic v1
unset key
sudo sss-bootc activate praxis-openai-api-key-v1 praxis-anthropic-api-key-v1
sudo sss-bootc status
```

Both names are required by the default two-provider Praxis configuration.
The optional `sss-bootc inference vllm` profile requires no cloud secrets. For
no-provider smoke tests use explicit dummy values; this verifies service health,
not inference. Rotation uses new secret versions and another `activate` call.
Only names are stored in `/etc/secure-single-server/secret-names`.

## Deploy standalone Praxis

The `praxis` image is independent of the OpenShell base. On its booted host,
use `sss-praxis` instead of `sss-bootc` for secrets, activation, status, and
Praxis upstream selection. It supports cloud providers or a private
`remote-vllm` endpoint; local vLLM belongs on the separate vLLM image:

```console
printf '%s' "$key" | sudo sss-praxis secret openai v1
sudo sss-praxis activate praxis-openai-api-key-v1 praxis-anthropic-api-key-v1
sudo sss-praxis inference remote-vllm 10.0.0.10:8000
sudo sss-praxis status
```

On the booted host, deploy the selected image directly:

```console
sudo bootc switch quay.io/redhat-et/secure-single-server-opencode:v0.1
```

Use the corresponding published Quay reference; locally built image tags are
not deployment artifacts.

## Use the selected harness

```console
sudo sss-bootc harness create --profile dev --name demo-dev
sudo sss-bootc harness connect --name demo-dev
```

These commands run as `openshell-svc` and automatically ensure the selected
[workload template](../docs/development/workload-templates.md). To preload its
catalog, run `sudo sss-bootc harness template sync`. Template settings include
image and resources; policy, provider bindings, and policy-advisor settings stay
per sandbox.

Standalone policies permit provider endpoints. Attach direct providers explicitly
with `--provider NAME`; no SSH helper forwards keys. OpenCode and OpenClaw `dev`
also support the dedicated [Praxis integration workflow](../docs/quickstarts/openshell-praxis/README.md)
using `--config`, which rejects direct provider bindings. Local and remote vLLM
backend selection chooses the catalog's integrated configuration automatically.
OpenClaw's qualified model tools are read/write; automatic command execution
remains disabled. See the [0.1.5 pin review](../docs/testing/upgrade-0.1.5.md)
and the historical [0.1.3 real-model qualification](../docs/testing/upgrade-0.1.3-e2e.md).
A boot check alone does not prove a model task or its access policy works; the
0.1.5 pin review records the validated scenarios and remaining qualification.

Start with `dev` for the CLI smoke test. OpenCode currently attempts to write
runtime state under `/sandbox/.local/share`, which the shipped read-only
`review` profile denies; sandbox creation can succeed while the CLI fails.
That profile needs a separate runtime-state policy design before it is usable
with OpenCode. Do not broaden the whole review workspace to work around it.

## Optional inference

Run [Qwen3-8B with vLLM on a separate server](VLLM.md). The single server keeps
the OpenCode → Praxis boundary and receives only a private `RFC1918_IP:PORT` upstream.
The older co-located CPU/single-L4 mode remains available for compatibility but
is deprecated for new deployments. Use the [AWS helper](../docs/testing/aws.md#separate-vllm-server)
to grant and discover the private endpoint.

## Image publication

[Validation CI](https://github.com/redhat-et/secure-single-server/blob/main/.github/workflows/validate.yml) runs static checks and
synthetic OpenAI contracts on native amd64 and arm64 Linux runners. It does not
use provider credentials, download model weights, exercise GPUs, or replace RHEL
runtime qualification.

[Bootc image CI](https://github.com/redhat-et/secure-single-server/blob/main/.github/workflows/bootc-images.yml) is the publisher for
these images. Repository maintainers use it to review and publish releases;
deployment guides intentionally use the mutable `v0.1` tag for simplicity and
do not include image-build instructions.

## Validation

See the [dated AWS boot results](VALIDATION.md) for tested image releases,
checks, and remaining qualification.

## Next step

Review the [validation record](VALIDATION.md), then reproduce the relevant
checks with the [testing guide](../docs/testing/README.md).
