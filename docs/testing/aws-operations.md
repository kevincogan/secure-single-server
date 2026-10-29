# AWS VM operations and recovery

**To deploy gateway or separate vLLM VMs, follow [aws.md](aws.md).**
This page is the reference for custom configuration, recovery and cleanup.
Use [model/context sizing](aws.md#model-and-context-sizing) to distinguish the
current L4/CPU presets from estimated full-context and Flash-Next hardware.
Increasing the instance size does not change the model's configured context,
cache allocation or harness output limits.

## Resource boundary and permissions

`scripts/aws/rhel-vm` uses AWS CLI v2's credential chain. It creates one
on-demand official Red Hat RHEL 9 PAYG VM, one encrypted gp3 root disk, one
security group and one imported **public** SSH key. The primary interface and
root EBS disk have `DeleteOnTermination=true`. IMDSv2 is required. Resources
carry `ManagedBy`, `ResourcePrefix`, `Scenario` and `Name` tags.
The `vllm-grant` mode can add one TCP 8000 source-security-group rule.

No IAM roles, VPCs, subnets, routes, DNS, SSM access or applications are created.
No AWS/provider credentials enter the VM. There is no user-data bootstrap.
G6's included instance-store NVMe is not formatted or used; model caches and
Podman data belong on the encrypted EBS root disk in the planned installation.

| Mode | Behavior |
| --- | --- |
| `plan` | Read-only validation and resource plan; no state-file writes |
| `apply` | Fresh validation and printed plan, then typed account/region/prefix confirmation before creation |
| `verify` | Read-only comparison against the recorded launch, including ownership, image/type, ingress, IMDSv2 and disk/interface deletion settings |
| `capacity` | Read-only offered zones and public subnet candidates; spare instance capacity remains unknown |
| `vllm-endpoint` | Read-only discovery of one running tagged `vllm-server`; rejects ambiguity and public port-8000 ingress |
| `vllm-grant` | Read-only source-group plan; with `--apply`, typed confirmation adds the private TCP 8000 rule |

Credentials need `sts:GetCallerIdentity`, EC2 describe access for instance
types, instance-type offerings, images, subnets, route tables, instances,
security groups, volumes and key pairs. Deployment also needs
`ec2:CreateSecurityGroup`, `ec2:AuthorizeSecurityGroupIngress`,
`ec2:ImportKeyPair`, `ec2:RunInstances` and `ec2:CreateTags` for tagging on
creation. Account policy, RHEL entitlement and service quotas still apply;
planning cannot prove mutation permissions or reserve capacity. No
`iam:PassRole` is needed. Root-account credentials are refused.

## Direct CLI and custom VM configurations

The [session helper](https://github.com/redhat-et/secure-single-server/blob/main/scripts/aws/session.sh) manages hidden credential
entry and common workstation settings. The [VM helper](../../scripts/aws/rhel-vm)
plans/applies/verifies exactly one VM. It also works directly with your normal
AWS CLI credential chain; do not mix exported keys and an AWS profile.

```console
python3 scripts/aws/rhel-vm plan --config configs/aws/vllm-gpu.json --scenario all-in-one \
  --region "$REGION" --account-id "$ACCOUNT" --prefix "$RUN_PREFIX-all-in-one-gpu" \
  --subnet-id "$SUBNET" --allowed-cidr "$CLIENT_CIDR" \
  --public-key "$SSH_KEY.pub" --state-file ".state/$RUN_PREFIX-all-in-one-gpu.json" \
  || printf 'Plan failed; no resources launched.\n'
```

Replace `plan` with `apply` when ready; confirmation remains mandatory. A
separate earlier plan is optional because apply always validates current
inputs. A recorded failed instance launch is reconciled and retried using its existing
security group/key pair. Completed VMs and unrelated name collisions are refused.

Plan/apply require `--config`. The hardware presets omit `scenario`; pass it with
`--scenario all-in-one`, `--scenario remote-gateway`, `--scenario openshell-praxis`
or `--scenario vllm-server`. The session helper
requires that flag, including for a custom file. JSON accepts `scenario`,
`inference`, `arch`, `instance_type`, `volume_gib`, optional `ami_id` and
`ssh_access` / `https_access` (`restricted` or `public`, both default to
`restricted`). Public HTTPS applies only to `remote-gateway`. Explicit flags
override file values.
Omitted type/disk defaults depend on inference: `none` uses `m7i.2xlarge`
(`m7g.2xlarge` on arm64) / 50 GiB; `cpu` uses `m7i.4xlarge` / 100 GiB;
`gpu` uses `g6.2xlarge` / 200 GiB. Editing inference alone in a complete preset
retains its explicit type/disk, so edit all three or choose the matching preset.
Unknown keys, wrong types, small disks and incompatible architectures fail.

For OpenShell deployment or runtime qualification, use an official RHEL 9.8+
AMI. Pass its ID with `--ami-id`: automatic AMI selection has chosen an older
RHEL 9 minor version in this region. See the
[v0.1.5 validation record](upgrade-0.1.5.md) for the tested image and Podman
version.

To edit reusable settings without changing a tracked preset, copy a file to
an ignored `*.local` path:

```console
cp -n configs/aws/vllm-gpu.json configs/aws/custom-gpu.local \
  || printf 'Config not copied; inspect the existing file before editing.\n'
```

Edit `instance_type` and `volume_gib` in that file, then use it in the array:

```console
ALL_IN_ONE_GPU_VM=(configs/aws/custom-gpu.local --scenario all-in-one)
```

Or append explicit overrides after choosing hardware. These are independent
examples; use only the ones matching your run.

**Larger all-in-one GPU VM:** keep a `vllm-gpu.json` hardware selection.

```console
ALL_IN_ONE_GPU_VM+=(--instance-type g6.4xlarge --volume-gib 300)
```

**Larger remote-gateway CPU inference VM:** keep a `vllm-cpu.json` selection.

```console
REMOTE_GATEWAY_CPU_VM+=(--instance-type m7i.8xlarge --volume-gib 150)
```

**Another approved subnet for one VM:** replace the example subnet ID.

```console
ALL_IN_ONE_GPU_VM+=(--subnet-id subnet-REPLACE_ME)
```

**Pin one official RHEL AMI:** replace the example ID; architecture/owner checks remain.

```console
REMOTE_GATEWAY_CPU_VM+=(--ami-id ami-REPLACE_ME)
```

The minimum is 32 GiB RAM for all profiles; CPU inference recommends 64 GiB.
CPU/GPU vLLM profiles require amd64. The current GPU path accepts one full
NVIDIA L4 only, including compatible larger single-L4 instance sizes. It
rejects fractional L4, A10G and multi-GPU types. `none` remains suitable for
arm64 gateway smoke testing when paired with an arm64 instance type.

Planning confirms the instance type is offered in the subnet's Availability
Zone; this does not guarantee spare capacity or sufficient On-Demand GPU quota.
If it fails, select another approved public subnet using `--subnet-id` on that
VM's plan/deploy command. No region, hardware or network fallback is automatic.
AWS metadata does not establish AVX-512 support on the running guest; CPU host
preflight is still required. GPU driver and NVIDIA Container Toolkit readiness
must likewise be checked on the guest before installing vLLM.

## Capacity errors

`InsufficientInstanceCapacity` means AWS could not place the requested instance
in that Availability Zone at launch time. Earlier success and termination of an
old VM do not reserve capacity for a replacement. This differs from a quota or
credentials error. AWS recommends waiting or choosing another zone/type:
[launch troubleshooting](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/troubleshooting-launch.html#troubleshooting-launch-capacity).

In the prepared workstation terminal, reload the helper and inspect alternatives:

```console
source scripts/aws/session.sh || printf 'Load failed; check your working directory.\n'
aws_test_capacity g6.2xlarge || printf 'Placement check failed; inspect the error.\n'
```

The report lists zones offering that type and public subnet candidates in the
current VPC. `SpareInstanceCapacity: unknown` is intentional: instance-type
[offerings](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-instance-type-offerings.html)
are supported locations, not free-instance counts. Subnet IP counts measure
address space only. A launch `--dry-run` checks permissions, not availability.
This command creates nothing and writes no journal.

### Retry the failed GPU launch

Keep its journal and resources. After waiting a few minutes, rerun the same
plan and deploy commands. No new run prefix, key pair or security group is needed:

```console
aws_test_plan all-in-one-gpu "${ALL_IN_ONE_GPU_VM[@]}" \
  || printf 'Plan stopped; inspect the reported recovery condition.\n'
```

```console
aws_test_deploy all-in-one-gpu "${ALL_IN_ONE_GPU_VM[@]}" \
  || printf 'Retry stopped; the journal is retained for another attempt.\n'
```

The plan checks resource ownership, ingress, public key, subnet and recorded
launch tokens. Deploy asks for confirmation. An uncertain prior outcome is
retried in the original subnet with the same token and parameters. If AWS
already has the instance, the helper recovers its ID without launching another.
Concurrent deploys using the same journal are refused.

If the updated helper records another `InsufficientInstanceCapacity`, you can
explicitly select a public subnet in another zone **in the same VPC**. Replace
the placeholder with a candidate from `aws_test_capacity`:

```console
ALL_IN_ONE_GPU_VM+=(--subnet-id subnet-REPLACE_ME)
```

Repeat the two plan/deploy blocks above. The failed attempt remains in the
journal; the new subnet is used only after confirmation. Hardware, AMI, disk,
access rules and SSH key stay fixed. An older journal without a recorded
capacity rejection must first retry its original subnet to resolve its outcome.

There is no automatic launch, zone fallback or instance-size substitution.
Planning checks that the type is offered; only an actual launch establishes
placement. Failures before instance launch and resource drift still require
[inspection](#if-apply-failed); no resources are deleted automatically.

## Deploy additional variants of a scenario

Choose another [named VM block](aws.md#3-deploy-the-vms-you-need). Keep the run
settings/key, and plan/launch that VM independently. Names accept 1–20 lowercase
letters, digits and hyphens, starting with a letter; the full prefix/name must
fit 40 characters. Each name has its own journal.

For external providers without local inference, use the
[all-in-one without vLLM](aws.md#all-in-one-without-vllm) or
[remote-gateway without vLLM](aws.md#remote-gateway-without-vllm) blocks.
Both use the smaller `no-vllm.json` preset. The helper currently requires
at least 32 GiB RAM; smaller instance types are rejected.

For a separate inference host, use the
[separate vLLM server block](aws.md#separate-vllm-server) and a CPU/GPU preset.
The gateway may use `no-vllm.json`; the dedicated server must use `cpu` or `gpu`.

## Access and changed IPs

Choose a block **before** configuring the VM array in [aws.md](aws.md#2-choose-access).
Access flags affect new launches; they do not update existing security groups.

### All-in-one access

Restrict SSH to the IP detected by discovery:

```console
ALL_IN_ONE_ACCESS=(--ssh-access restricted)
```

Or restrict SSH to a specific source (replace the example):

```console
ALL_IN_ONE_ACCESS=(--ssh-access restricted --allowed-cidr 203.0.113.10/32)
```

Or allow SSH from any IPv4 address:

```console
ALL_IN_ONE_ACCESS=(--ssh-access public)
```

### Remote-gateway access

Restrict both SSH and HTTPS to the detected IP:

```console
REMOTE_GATEWAY_ACCESS=(--ssh-access restricted --https-access restricted)
```

Or restrict SSH while allowing HTTPS/JWT clients from any IP:

```console
REMOTE_GATEWAY_ACCESS=(--ssh-access restricted --https-access public)
```

Or restrict SSH to a specific IP and allow public HTTPS:

```console
REMOTE_GATEWAY_ACCESS=(--ssh-access restricted --allowed-cidr 203.0.113.10/32 --https-access public)
```

Or allow both SSH and HTTPS from any IPv4 address:

```console
REMOTE_GATEWAY_ACCESS=(--ssh-access public --https-access public)
```

Public SSH still requires authentication. Check that the guest enables public-key
authentication and disables password/keyboard-interactive authentication:

```console
sudo sshd -T | grep -E '^(pubkeyauthentication|passwordauthentication|kbdinteractiveauthentication) '
```

The helper does not change `sshd` configuration. HTTPS requires TLS/JWT after
service installation. vLLM and management ports remain private. AWS recommends
[restricting SSH sources](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/changing-security-group.html).

Changing `CLIENT_CIDR` affects new plans only. Manual ingress edits cause
`verify` to report drift; there is no security-group update operation here.
Use the original/VPN source or provision with the desired access.

### SSM Session Manager

SSM is not implemented by this workflow. It requires an SSM Agent, managed-instance
IAM permissions, operator session permissions and access to SSM HTTPS endpoints;
CLI use also needs the Session Manager plugin. See the
[AWS prerequisites](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-prerequisites.html).

SSM shells use IAM authorization; [SSH over SSM](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-getting-started-enable-ssh-connections.html)
also uses the SSH key. This runner requires direct SSH and HTTPS. Adding an IAM
instance profile manually causes the current AWS verifier to report drift.

## Resume a terminal or inspect an earlier VM

Keep the original `REGION`, `ACCOUNT`, `RUN_PREFIX` and `SSH_KEY` with your
non-secret test notes. Reload `source scripts/aws/session.sh` after a checkout
update; this preserves your existing credentials/settings. In a new terminal,
load credentials again and restore those values from the recorded run. Verify
uses the journal, not the current config file or current instance defaults:

```console
aws_test_verify all-in-one-gpu || printf 'Verification failed; inspect the recorded deployment.\n'
```

Select another deployed VM by its exact name, for example `aws_test_verify remote-gateway-cpu`.
For any earlier run, use its recorded journal suffix. To inspect one directly:

```console
python3 scripts/aws/rhel-vm verify --region "$REGION" --account-id "$ACCOUNT" \
  --state-file ".state/$RUN_PREFIX-all-in-one-gpu.json" \
  || printf 'Verification failed; inspect the journal and tagged resources.\n'
```

After confirmation, apply creates and fsyncs a private recovery journal before
its first mutation. It records the security group, key-pair name, launch client
token and returned instance ID. Failed updates retain the previous record.
Keep these files; never source them as shell code or delete them to bypass a
retry refusal.

## Cleanup

### What costs money, and what termination removes

For this helper's unchanged deployment, **terminate each VM** in the EC2
console to remove its ongoing billable resources. Do not merely stop it:
stopped instances retain billable EBS storage.

| Resource per VM | Charge | On instance termination |
| --- | --- | --- |
| On-demand EC2 instance with RHEL PAYG | Compute and RHEL usage | Instance usage ends |
| One encrypted gp3 root disk, configured size | EBS storage | Deleted (`DeleteOnTermination=true`), including Praxis/Valkey data |
| Auto-assigned public IPv4 | Public IPv4 usage | Released; not an Elastic IP |
| Primary network interface | No separate interface-hour charge | Deleted (`DeleteOnTermination=true`) |
| Security group and imported public SSH key | No ongoing charge | Remain; optional manual housekeeping |

The helper creates **no** NAT gateway, load balancer, Elastic IP, snapshot,
extra data disk or customer-managed KMS key. Internet data transfer and
provider API calls may incur usage charges while testing; termination does
not erase accrued charges. Existing account-level backup/logging policies or
resources you add yourself are outside this helper's cleanup boundary.

The installer keeps its Podman volumes on the VM's root disk; Valkey does not
create another AWS EBS volume. Deleting that disk permanently deletes its data.

AWS documents [instance termination and disk deletion](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/terminating-instances.html),
[public IPv4 release](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html#eni-basics),
[IPv4 charges](https://aws.amazon.com/vpc/pricing/) and
[security groups without an additional charge](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html).

### Terminate and check

1. Run `verify` before cleanup; it rejects extra disks and retained interfaces.
2. In the EC2 console, select the recorded instance ID and choose
   **Instance state → Terminate (delete) instance**. Repeat for every launched VM.
3. Confirm the instances are terminated, their root volumes and primary
   interfaces are deleted, and their auto-assigned public addresses released.
4. Optionally delete the tagged security groups and imported key pairs.
   Leave shared VPC/subnet resources alone. Revoke provider keys separately.

### If apply failed

Do not delete its journal or immediately launch under a fresh prefix. Inspect
the JSON file and matching resource-prefix tags in the selected account/region.
If `InstanceId` is present, terminate that instance when no longer needed.
If status is `launch-requested` but no instance ID was returned, the launch
may still have succeeded: search EC2 by the resource-prefix tag or the recorded
`ClientToken` before retrying. Inspect tagged EBS volumes too after an
interrupted launch; a volume without a live VM needs separate cleanup.
Earlier failures normally leave only the
non-billable security group/key pair; confirm actual resources in the console.
`verify` refuses an incomplete journal instead of treating it as a successful
deployment. For a recorded instance-launch failure, [repeat plan/deploy](#retry-the-failed-gpu-launch)
to reconcile it. Earlier failures or resource drift require inspection.
No automatic deletion or unconfirmed launch retry occurs.

```console
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_TEST_CREDENTIALS \
  AWS_TEST_READY RHEL_HOST RHEL_SCENARIO RHEL_INFERENCE || printf 'Could not clear credentials; check your shell settings.\n'
```

The helper contains no termination/deletion command. Keep non-secret state
files for audit; never source them as shell code.
