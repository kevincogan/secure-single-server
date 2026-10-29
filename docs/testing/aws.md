# Deploy AWS RHEL test VMs

Start here. Deploy any of the VMs below; each has its own plan, launch
and journal. They can run at the same time. AWS deployment prepares the host;
[smoke tests](rhel-smoke.md) install and test the services afterward.

For the PriceTag metering pilot, see the
[pilot overview](pricetag.md) and its [AWS deployment runbook](aws-pricetag.md).
The gateway, metering service, dashboard and PostgreSQL run as independent
containers; the metering service does not require a GPU.

## PriceTag on an existing VM

Resume the existing run's AWS credentials, region, account, SSH key and launch
journal using [resume settings](aws-operations.md#resume-a-terminal-or-inspect-an-earlier-vm).
Run these commands from this checkout. `RHEL_STATE_FILE` must be the existing
VM's launch journal, even if that file lives in an earlier worktree.

```console
if [ -n "${RHEL_STATE_FILE:-}" ] && CLIENT_IP="$(curl -4 -fsS https://checkip.amazonaws.com)"; then
  CLIENT_CIDR="$CLIENT_IP/32"
  scripts/aws/https-access --state-file "$RHEL_STATE_FILE" \
    --account-id "$ACCOUNT" --region "$REGION" --allowed-cidr "$CLIENT_CIDR" \
    || printf 'HTTPS plan failed; correct the error before applying.\n'
else
  printf 'Resume the launch settings and check your public IP before continuing.\n'
fi
```

Review the instance, security group and single client `/32`. Then apply:

```console
if [ -n "${RHEL_STATE_FILE:-}" ] && [ -n "${CLIENT_CIDR:-}" ]; then
  scripts/aws/https-access --state-file "$RHEL_STATE_FILE" \
    --account-id "$ACCOUNT" --region "$REGION" --allowed-cidr "$CLIENT_CIDR" --apply \
    || printf 'HTTPS update stopped; inspect the security group and journal before retrying.\n'
else
  printf 'Resume the launch settings and run the HTTPS plan first.\n'
fi
```

This adds **TCP 8443 from your workstation IP only**, preserves SSH rules,
and updates the existing journal so subsequent verification recognizes the
change. It checks account, ownership tags, instance and security-group state;
unexpected existing ingress is rejected. It does not launch a VM or install
services. If you use an AWS named profile, add `--profile NAME` to both commands.

Your browser and local OpenCode use the public HTTPS address. Harnesses on the
VM use `https://localhost:8443` with the same JWT authentication and CA checks.
The VM's public IP does **not** need a separate ingress rule for those tests.
Continue with the [PriceTag deployment runbook](aws-pricetag.md) for the pinned
images, service setup, key provisioning and dashboard workflow.

For a separate gateway host, use the **all-in-one without vLLM** recipe below
to prepare the private provider configuration this pilot consumes. Complete
provider/catalog setup, add the workstation-only HTTPS rule above, then deploy
PriceTag's remote endpoint. Reusing the GPU VM is sufficient for the initial
local vLLM pilot; keep the memory/context sizing below for inference decisions.

| VM name | Scenario | Inference preset |
| --- | --- | --- |
| `all-in-one-gpu` | Local users, optional OpenShell | GPU: `g6.2xlarge`, L4, 32 GiB RAM, 200 GiB disk |
| `all-in-one-cpu` | Local users, optional OpenShell | CPU: `m7i.4xlarge`, 64 GiB RAM, 100 GiB disk |
| `remote-gateway-gpu` | Remote HTTPS/JWT clients | GPU: `g6.2xlarge`, L4, 32 GiB RAM, 200 GiB disk |
| `remote-gateway-cpu` | Remote HTTPS/JWT clients | CPU: `m7i.4xlarge`, 64 GiB RAM, 100 GiB disk |
| `all-in-one-cloud` | Local users, external providers only | No vLLM: `m7i.2xlarge`, 32 GiB RAM, 50 GiB disk |
| `remote-gateway-cloud` | Remote clients, external providers only | No vLLM: `m7i.2xlarge`, 32 GiB RAM, 50 GiB disk |
| `vllm-server-gpu` | Separate Qwen inference server | GPU: `g6.2xlarge`, L4, 32 GiB RAM, 200 GiB disk |
| `vllm-server-cpu` | Separate Qwen inference server | CPU: `m7i.4xlarge`, 64 GiB RAM, 100 GiB disk |

## Model and context sizing

Choose a model, total context, output allowance and concurrency before choosing
hardware. The table below assumes **one text-only request at a time**. Context
contains input, thinking and the final answer; output is not extra space beyond
that total. The 27B preset now uses 32,768 context / 8,192 output tokens. Its
recorded RHEL passes used 16,384 / 4,096; a fresh run is required for the increase.

The larger rows are **planning candidates, not tested deployment presets or
proven minimum instance sizes**. GPU memory is AWS's advertised GB; host RAM is
GiB. Region/AZ availability, runtime kernels and measured peak memory still
need verification before deployment.

| Model and target | Instance candidate | Host RAM / GPU memory | Status and required changes |
| --- | --- | --- | --- |
| 27B INT4, 32,768 context / 8,192 output | `g6.2xlarge` | 32 GiB / 1 × L4, 24 GB | Current GPU host; increased budgets need rerun. 200 GiB EBS |
| 27B INT4, 32,768 context / 8,192 output | `m7i.4xlarge` | 64 GiB / CPU | Current CPU host; increased budgets need rerun. 100 GiB EBS |
| 27B INT4, full native 262,144 context / 32,768 output trial | `g6e.2xlarge` | 64 GiB / 1 × L40S, 48 GB | First GPU sizing candidate; larger cache and matching client limits. 200 GiB EBS |
| 27B INT4, full native 262,144 context / 32,768 output trial | `m7i.8xlarge` | 128 GiB / CPU, 32 vCPU | CPU capacity candidate, not a latency recommendation; raise the explicit 4 GiB cache allocation. 200 GiB EBS |
| 27B INT4, extended 1,000,000 context and large reasoning/output allowances | `g7e.12xlarge` | 512 GiB / 2 × RTX PRO 6000 Blackwell, 192 GB total | Conservative GPU headroom candidate; YaRN, multiple GPUs, cache and client changes required. 300 GiB EBS |
| 27B INT4, extended 1,000,000 context and large reasoning/output allowances | `r7i.8xlarge` | 256 GiB / CPU, 32 vCPU | CPU memory candidate only; much larger cache and unqualified long-request latency. 300 GiB EBS |
| Flash-Next official FP8, native 262,144 context / 32,768 output trial | `g7e.24xlarge` | 1,024 GiB / 4 × RTX PRO 6000 Blackwell, 384 GB total | Planning headroom for the much larger model; new model/runtime and multiple-GPU preset required. Start with 1 TiB EBS |
| Flash-Next NVIDIA NVFP4, native 262,144 context / 32,768 output trial | `g7e.12xlarge` | 512 GiB / 2 × RTX PRO 6000 Blackwell, 192 GB total | Memory candidate only; this GPU/runtime combination is not established by NVIDIA's B200/B300 reference. Start with 1 TiB EBS |

Hardware sources: [G6](https://aws.amazon.com/ec2/instance-types/g6/),
[G6e](https://aws.amazon.com/ec2/instance-types/g6e/),
[G7e](https://aws.amazon.com/ec2/instance-types/g7e/),
[M7i](https://aws.amazon.com/ec2/instance-types/m7i/) and
[R7i](https://aws.amazon.com/ec2/instance-types/r7i/).
EBS sizes and candidate selections are project planning estimates.

The current AWS helper accepts **one full NVIDIA L4 only**, and the mutable
installer uses tensor parallelism one. A larger `g6.4xlarge` increases CPU/RAM
but retains the same 24 GB L4. G6e/G7e and multiple-GPU rows need a separately
qualified hardware/runtime profile; they cannot be enabled by changing just
`--instance-type`. A larger CPU VM alone also leaves the present cache and
context settings unchanged.

<details>
<summary>Why cache capacity depends on RAM or VRAM, and what “full context” means</summary>

Linux `buff/cache` includes file cache that can be reclaimed. Judge host memory
headroom using `MemAvailable` (`free -h`'s `available` column), not just `free`
or a graph that counts file cache as used. This differs from vLLM's allocated
inference KV cache. The earlier 16K runs recorded 24 GiB available on the GPU
host and 28 GiB on the CPU host, despite 22 GiB and 27 GiB of `buff/cache`.
These are snapshots, not current readings or peak-load measurements.
[Linux memory accounting](https://docs.kernel.org/filesystems/proc.html#meminfo).

The existing vLLM startup pools held 50,115 tokens on GPU and 79,872 on CPU.
Both exceed the proposed 32,768-token total window, supporting a trial on the
current machines without raising memory allocations. vLLM reserves cache at
startup, so doubling the permitted sequence length need not double its reserved
memory. Recheck capacity after restarting and exercise a near-limit request;
the old pool sizes do not qualify the new limits. CPU keeps its explicit
`VLLM_CPU_KVCACHE_SPACE=4`; GPU keeps its 90% memory target.

On CPU, model weights, cache and working buffers consume host RAM. On GPU,
weights and the normal inference cache primarily consume GPU VRAM; more host
RAM does not automatically increase it. Capacity also depends on cache dtype,
attention layout, recurrent state, sequence count, prefill buffers and the
memory reserved by the runtime. Weight INT4 does not mean cache INT4.

For the pinned 27B architecture, the full-attention portion has 16 layers,
four KV heads and head dimension 256. A conservative BF16 KV estimate is:

```text
2 (K and V) × 16 layers × 4 heads × 256 × 2 bytes = 65,536 bytes/token
262,144 tokens → 16 GiB of full-attention KV
1,000,000 tokens → about 61 GiB of full-attention KV
```

Add recurrent state, allocation overhead, weights and working buffers. FP8 KV
can reduce that component, but requires its own support/quality qualification;
the estimate does not assume it. The observed 27B model-loading memory was
16.84 GiB on GPU and 24.34 GiB on CPU. This explains why the current 24 GB L4
is a bounded-context host, and why 48 GB is a reasonable first full-native-context
GPU candidate. These calculations are not an end-to-end memory benchmark.
[Pinned architecture](https://huggingface.co/RedHatAI/Qwen3.8-27B-INT4/blob/91bd022d5b49442a868bc35008f6c21e1860edfa/config.json),
[measured baseline](compatibility.md#cpugpu-limits-and-measured-performance).

The current 64 GiB CPU host is not ruled out for a single full-native-context
request: its measured available RAM could accommodate a larger cache. That
requires changing the explicit cache allocation and testing peak memory,
reclaim pressure and latency. The 128 GiB row provides conservative headroom;
it is not a demonstrated minimum. The current L4's spare host RAM cannot
extend its VRAM cache without a separately qualified offload strategy.

The native window is 262,144 tokens. A 32,768-token output trial leaves at most
229,376 tokens for all input, including instructions/tools, before allowing
for client overhead. That output allowance is a proposed coding-test budget,
not a model maximum. Qwen describes extending to 1,000,000 with YaRN and, for
frameworks with separate budgets, up to 262,144 reasoning plus 131,072 final
tokens. Those combined allowances leave at most 606,784 input tokens inside
1,000,000. Our current launcher does not expose those separate budgets;
harness/API output ceilings must also be qualified. A larger instance cannot
remove a client's output cap.
[Qwen context and output guidance](https://huggingface.co/Qwen/Qwen3.8-27B#best-practices).

Before recommending a larger profile, record the engine's cache capacity,
peak RAM/VRAM, a request near the chosen total window, thinking/final usage,
tool continuation and compaction recovery. Test each additional simultaneous
sequence separately. Larger memory does not establish acceptable CPU latency.

</details>

<details>
<summary>Qwen3.8 Flash: downloadable quantizations versus the hosted service</summary>

The self-hosted model is **Qwen3.8-Flash-Next**. Its language model has 125B
parameters with 6B active per token, plus a 51B n-gram embedding and 4B MTP.
Low active-parameter count reduces computation, not the need to store the
other weights. Its native window is 262,144; 1M is an extension.
[Qwen model card](https://huggingface.co/Qwen/Qwen3.8-Flash-Next).

Quantizations exist: Qwen publishes
[Flash-Next-FP8](https://huggingface.co/Qwen/Qwen3.8-Flash-Next-FP8), and NVIDIA
publishes [Flash-Next-NVFP4](https://huggingface.co/nvidia/Qwen3.8-Flash-Next-NVFP4).
NVIDIA's artifact mixes NVFP4 experts, BF16 layers and FP8 MTP/embedding data;
it is not uniformly four-bit. Neither artifact fits the current L4 as a normal
all-GPU deployment. The G7e rows above are estimates for a new qualification.

NVIDIA's published reference uses eight B200/B300 GPUs and a specific minimum
vLLM source revision. An AWS counterpart is `p6-b200.48xlarge` (eight B200,
2,048 GiB host RAM), not a claim that eight GPUs are the minimum. Two RTX PRO
GPUs may have sufficient memory for the NVFP4 candidate, but the reference
does not prove its kernels, tensor parallelism or performance there.
[AWS P6 hardware](https://aws.amazon.com/ec2/instance-types/p6/).

The hosted **Qwen3.8-Flash** service is based on Flash-Next and supplies its own
production features and 1M window. Calling that service needs gateway capacity,
not local model GPU memory, but its provider integration is not implemented by
these vLLM presets. The FP8 card distinguishes the hosted and downloadable
versions. Flash installation, pins and acceptance remain future work; this PR
only adds sizing guidance.

</details>

Run these commands from the repository root on your workstation, in Bash or
zsh. Install AWS CLI v2, Python 3.9+, `jq`, `curl` and OpenSSH first.

## 1. Prepare a fresh run

```console
source scripts/aws/session.sh || printf 'Load failed; check your working directory.\n'
aws_test_credentials || printf 'Credentials failed; retry before continuing.\n'
```

Enter AWS credentials at the hidden prompts. Then set up this run:

```console
REGION=eu-central-1
SUBNET=''
CLIENT_CIDR=''
RUN_PREFIX="rhel-$(date -u +%y%m%d-%H%M%S)"
SSH_KEY="$HOME/.secure-single-server-tests/ssh/$RUN_PREFIX"
aws_test_discover || printf 'Discovery failed; correct the error before continuing.\n'
```

Empty `SUBNET` selects an existing default public subnet. Empty `CLIENT_CIDR`
detects your public IPv4 `/32`. Check the printed account, region and subnet.
Create the SSH key with a passphrase, then unlock it:

```console
aws_test_key || printf 'Key creation failed; correct the error before planning.\n'
ssh-add "$SSH_KEY" || printf 'Key not unlocked; retry before SSH testing.\n'
```

Keep `REGION`, `ACCOUNT`, `RUN_PREFIX` and `SSH_KEY` for this run. Only the public
key goes to AWS. For an existing run, use [resume settings](aws-operations.md#resume-a-terminal-or-inspect-an-earlier-vm)
instead of generating a new prefix/key.

## 2. Choose access

Default: restrict SSH and gateway HTTPS to your detected IP:

```console
ALL_IN_ONE_ACCESS=(--ssh-access restricted)
REMOTE_GATEWAY_ACCESS=(--ssh-access restricted --https-access restricted)
```

Optional: keep SSH restricted but allow HTTPS/JWT clients from any IP:

```console
REMOTE_GATEWAY_ACCESS=(--ssh-access restricted --https-access public)
```

Choose access **before** configuring a VM below. [More access examples](aws-operations.md#access-and-changed-ips)
cover public SSH and explicit IPs. Only SSH (22) and remote-gateway HTTPS
(8443) can be opened; vLLM and management ports stay private.

## 3. Deploy the VMs you need

For each chosen VM, run its **plan**, review the one-VM output, then run its
separate **deploy** command. Deployment revalidates the plan and asks for
`launch ACCOUNT REGION PREFIX`. Stop on errors; [inspect a failed launch](aws-operations.md#if-apply-failed)
before retrying. For `InsufficientInstanceCapacity`, use the
[placement check and recovery steps](aws-operations.md#capacity-errors).
Nothing is cleaned up automatically.

The config chooses hardware; `--scenario` chooses the gateway role. Select
Qwen3-8B or quantized Qwen3.8-27B later during [vLLM setup](rhel-real.md#1-install-real-qwen);
AWS deployment itself does not install a model. To change
hardware or disk size, see [configuration examples](aws-operations.md#direct-cli-and-custom-vm-configurations).

### All-in-one GPU

```console
ALL_IN_ONE_GPU_VM=(configs/aws/vllm-gpu.json --scenario all-in-one "${ALL_IN_ONE_ACCESS[@]}")
aws_test_plan all-in-one-gpu "${ALL_IN_ONE_GPU_VM[@]}" \
  || printf 'Plan failed; correct the error before deploying.\n'
```

```console
aws_test_deploy all-in-one-gpu "${ALL_IN_ONE_GPU_VM[@]}" \
  || printf 'Deploy stopped; inspect its journal before retrying.\n'
```

### All-in-one CPU

```console
ALL_IN_ONE_CPU_VM=(configs/aws/vllm-cpu.json --scenario all-in-one "${ALL_IN_ONE_ACCESS[@]}")
aws_test_plan all-in-one-cpu "${ALL_IN_ONE_CPU_VM[@]}" \
  || printf 'Plan failed; correct the error before deploying.\n'
```

```console
aws_test_deploy all-in-one-cpu "${ALL_IN_ONE_CPU_VM[@]}" \
  || printf 'Deploy stopped; inspect its journal before retrying.\n'
```

### Remote-gateway GPU

```console
REMOTE_GATEWAY_GPU_VM=(configs/aws/vllm-gpu.json --scenario remote-gateway "${REMOTE_GATEWAY_ACCESS[@]}")
aws_test_plan remote-gateway-gpu "${REMOTE_GATEWAY_GPU_VM[@]}" \
  || printf 'Plan failed; correct the error before deploying.\n'
```

```console
aws_test_deploy remote-gateway-gpu "${REMOTE_GATEWAY_GPU_VM[@]}" \
  || printf 'Deploy stopped; inspect its journal before retrying.\n'
```

### Remote-gateway CPU

```console
REMOTE_GATEWAY_CPU_VM=(configs/aws/vllm-cpu.json --scenario remote-gateway "${REMOTE_GATEWAY_ACCESS[@]}")
aws_test_plan remote-gateway-cpu "${REMOTE_GATEWAY_CPU_VM[@]}" \
  || printf 'Plan failed; correct the error before deploying.\n'
```

```console
aws_test_deploy remote-gateway-cpu "${REMOTE_GATEWAY_CPU_VM[@]}" \
  || printf 'Deploy stopped; inspect its journal before retrying.\n'
```

### All-in-one without vLLM

Uses external providers such as OpenAI and Anthropic; no model download or GPU.

```console
ALL_IN_ONE_CLOUD_VM=(configs/aws/no-vllm.json --scenario all-in-one "${ALL_IN_ONE_ACCESS[@]}")
aws_test_plan all-in-one-cloud "${ALL_IN_ONE_CLOUD_VM[@]}" \
  || printf 'Plan failed; correct the error before deploying.\n'
```

```console
aws_test_deploy all-in-one-cloud "${ALL_IN_ONE_CLOUD_VM[@]}" \
  || printf 'Deploy stopped; inspect its journal before retrying.\n'
```

### Remote-gateway without vLLM

Uses HTTPS/JWT to reach external providers; no model download or GPU.
For the PriceTag dashboard/metering deployment and its larger disk preset,
follow [AWS remote gateway with PriceTag](../quickstarts/remote-gateway-pricetag/README.md).

```console
REMOTE_GATEWAY_CLOUD_VM=(configs/aws/no-vllm.json --scenario remote-gateway "${REMOTE_GATEWAY_ACCESS[@]}")
aws_test_plan remote-gateway-cloud "${REMOTE_GATEWAY_CLOUD_VM[@]}" \
  || printf 'Plan failed; correct the error before deploying.\n'
```

```console
aws_test_deploy remote-gateway-cloud "${REMOTE_GATEWAY_CLOUD_VM[@]}" \
  || printf 'Deploy stopped; inspect its journal before retrying.\n'
```

### Separate vLLM server

Deploy a no-vLLM gateway VM first, then one dedicated inference VM. The
gateway and inference VM must use the same subnet/VPC. The grant helper adds
only a TCP 8000 security-group rule whose source is the gateway VM's security
group; it does not expose vLLM to the Internet.

```console
VLLM_SERVER_GPU_VM=(configs/aws/vllm-gpu.json --scenario vllm-server "${ALL_IN_ONE_ACCESS[@]}")
aws_test_plan vllm-server-gpu "${VLLM_SERVER_GPU_VM[@]}" \
  || printf 'Plan failed; correct the error before deploying.\n'
```

```console
aws_test_deploy vllm-server-gpu "${VLLM_SERVER_GPU_VM[@]}" \
  || printf 'Deploy stopped; inspect its journal before retrying.\n'
```

After both VMs are running, select the gateway VM, review the read-only grant
plan, and apply it with typed confirmation:

```console
aws_test_verify all-in-one-cloud \
  || printf 'Gateway verification failed; do not grant vLLM access.\n'
aws_test_vllm_grant all-in-one-cloud vllm-server-gpu \
  || printf 'Grant plan failed; inspect both journals.\n'
aws_test_vllm_grant_apply all-in-one-cloud vllm-server-gpu \
  || printf 'Grant failed; no endpoint was configured.\n'
VLLM_INFO="$(aws_test_vllm_endpoint vllm-server-gpu)" \
  || printf 'Endpoint discovery failed; inspect the vLLM VM.\n'
VLLM_ENDPOINT="$(printf '%s' "${VLLM_INFO:-}" | jq -er '.VllmEndpoint')" \
  || printf 'Endpoint JSON was invalid.\n'
printf 'Private vLLM endpoint: %s\n' "${VLLM_ENDPOINT:-unknown}"
```

The endpoint command prints the tagged instance's private IPv4 address as
`VllmEndpoint`. It refuses ambiguous matches and rejects any vLLM security
group with public IPv4/IPv6 ingress on port 8000. Configure the dedicated VM
with [the vLLM administration guide](../quickstarts/common/vllm.md), using
`--remote` and the printed private IP. Configure the gateway with
`--vllm-endpoint "$VLLM_ENDPOINT"`. For the bootc/OpenShell path, run
`sudo sss-bootc inference remote-vllm "$VLLM_ENDPOINT"` instead.

## Share deployed VM details

To hand testing over, copy this block into the same workstation terminal and
paste its output. It lists only this run's deployed VMs and does not print
credentials or private key contents. Keep your SSH key unlocked with `ssh-add`.

```console
(
  printf 'AWS account: %s\nRegion: %s\nRun prefix: %s\n' "$ACCOUNT" "$REGION" "$RUN_PREFIX"
  found=no
  for VM_NAME in all-in-one-gpu all-in-one-cpu remote-gateway-gpu remote-gateway-cpu \
    all-in-one-cloud remote-gateway-cloud vllm-server-gpu vllm-server-cpu; do
    if [ -f "$AWS_TEST_REPO/.state/$RUN_PREFIX-$VM_NAME.json" ]; then
      found=yes
      aws_test_verify "$VM_NAME" || printf 'UNVERIFIED: %s; inspect before testing.\n' "$VM_NAME"
    fi
  done
  if [ "$found" = no ]; then printf 'No deployed VM journals found for this run.\n'; fi
)
```

This leaves your current selection unchanged. Keep the private journals for
recovery. The tester also needs SSH access from the allowed source IP.

## 4. Select one VM for testing

Run **one** of these commands. Repeat this selection whenever you switch VMs:

```console
aws_test_verify all-in-one-gpu || printf 'Verify failed; do not continue to testing.\n'
```

```console
aws_test_verify all-in-one-cpu || printf 'Verify failed; do not continue to testing.\n'
```

```console
aws_test_verify remote-gateway-gpu || printf 'Verify failed; do not continue to testing.\n'
```

```console
aws_test_verify remote-gateway-cpu || printf 'Verify failed; do not continue to testing.\n'
```

```console
aws_test_verify all-in-one-cloud || printf 'Verify failed; do not continue to testing.\n'
```

```console
aws_test_verify remote-gateway-cloud || printf 'Verify failed; do not continue to testing.\n'
```

A successful verify sets `RHEL_HOST`, `RHEL_SCENARIO`, `RHEL_INFERENCE` and
`RHEL_VPC_ID` from that VM's launch record. All following guides use those
variables and `SSH_KEY`. No per-host variables or edits to the test commands
are needed.
If the VM is still pending, wait and rerun verify. Do not continue after a failure.

Verify the host fingerprint through a trusted channel and connect once:

```console
ssh -o ForwardAgent=no -i "$SSH_KEY" "$RHEL_HOST" || printf 'SSH failed; resolve it before testing.\n'
```

Exit the remote shell and continue from your workstation.

## 5. Create the all-in-one user login

Select **one** all-in-one VM in your workstation terminal. Verification sets
`RHEL_HOST` for that VM. Run one block, then the creation block below:

```console
aws_test_verify all-in-one-gpu || printf 'Verify failed; do not create the account.\n'
```

```console
aws_test_verify all-in-one-cpu || printf 'Verify failed; do not create the account.\n'
```

For external providers only:

```console
aws_test_verify all-in-one-cloud || printf 'Verify failed; do not create the account.\n'
```

Repeat selection and creation for each all-in-one VM you deployed. This creates
`praxis-user` before installing Praxis or vLLM, using only this run's public
SSH key. The account has no sudo or service-group membership. Remote-gateway
users run clients on their own machines; skip this step for gateway VMs.

```console
tar --no-xattrs -czf - scripts/common/harness-user scripts/common/harness_user.py \
  scripts/common/harness.py scripts/common/harness_config.py configs/common/harness-versions.json | \
  ssh -o IdentitiesOnly=yes -o ForwardAgent=no -i "$SSH_KEY" "$RHEL_HOST" \
    'install -d -m 0700 ~/secure-single-server-deploy && tar -xzf - -C ~/secure-single-server-deploy' &&
scp -o IdentitiesOnly=yes -o ForwardAgent=no -i "$SSH_KEY" \
  "${SSH_KEY}.pub" "$RHEL_HOST:~/praxis-user.pub" &&
ssh -o IdentitiesOnly=yes -o ForwardAgent=no -i "$SSH_KEY" "$RHEL_HOST" \
  'cd ~/secure-single-server-deploy &&
   sudo dnf module switch-to -y nodejs:22 &&
   sudo dnf install -y nodejs npm git python3 openssh-clients policycoreutils &&
   sudo scripts/common/harness-user --user praxis-user --ssh-public-key "$HOME/praxis-user.pub"' \
  || printf 'User setup failed; inspect the error before continuing.\n'
```

The helper refuses an existing account. If you already created `praxis-user`,
skip creation and log in:

```console
ssh -o IdentitiesOnly=yes -o ForwardAgent=no -i "$SSH_KEY" "praxis-user@${RHEL_HOST#*@}" \
  || printf 'User login failed; check account creation and SSH access.\n'
```

Follow [user setup](../quickstarts/all-in-one/users.md#2-install-the-approved-harnesses)
to install the pinned CLIs in that account. Model requests will work after the
administrator completes service setup below. Exit back to your workstation
before running the test runner; keep `RHEL_HOST` as the administrator login.

## 6. Install services and test

For **manual installation on a fresh VM**, follow the official guides in order:

1. Administrator: [install Qwen and Praxis](../quickstarts/common/vllm.md), choosing
   the intended inference topology and a Valkey gateway for persistent quotas.
2. Administrator: [configure providers and the unified model catalog](../quickstarts/common/providers.md).
   Cloud credentials are optional; begin with Qwen alone.
3. Ordinary user: [generate native configurations and launch harnesses](../quickstarts/all-in-one/users.md).
   The account above is already created. Remote clients instead use
   [HTTPS/JWT client setup](../quickstarts/remote-gateway/users.md); unified catalogs
   currently support the all-in-one gateway only.
4. Test [model selection, switching and quotas](gateway-features.md).
   The Responses history adapter is an explicit experiment in that guide.

For **automated installation and regression tests**, choose:

- **CPU/GPU vLLM variants:** [mock smoke tests](rhel-smoke.md), then
  [real Qwen and manual testing](rhel-real.md). OpenShell is optional on all-in-one.
- **External providers only:** on the fresh VM follow the
  [all-in-one installation](../quickstarts/all-in-one/in-memory.md) or
  [remote-gateway installation](../quickstarts/remote-gateway/install.md).
  These guides configure provider credentials without installing vLLM.
  The mock runner can also use this hardware, but its real-Qwen transition
  requires a CPU/GPU inference preset.

When finished, [clean up each VM](aws-operations.md#cleanup).
