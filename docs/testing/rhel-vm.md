# Test in a local RHEL 9.8+ VM

Use this path to exercise the complete installer, rootless Podman, SELinux,
systemd user services, logout, and reboot behavior before testing in AWS.

## Create the VM

On a Mac M4, use a native **RHEL 9.8+ aarch64** guest. Suggested allocation:
4 vCPUs, 8 GiB RAM and 50 GiB disk for hosted-model tests; no GPU is needed.

1. Download the RHEL **9.8 or later** aarch64 installation ISO from
   [Red Hat Developer](https://developers.redhat.com/products/rhel/download).
   Verify its supplied checksum. Use x86_64 on an Intel/AMD machine instead.
2. In UTM or an equivalent native macOS virtualizer, choose **Virtualize →
   Linux**, attach that ISO, and install a minimal server with an administrator
   account. Use UEFI and a private/shared VM network reachable from the Mac.
3. Enable SSH in the guest console, obtain its IP with `ip -brief address`, and
   authorize your dedicated public SSH key. Keep the private key on the Mac.

The [RHEL VMs extension for Podman Desktop](https://developers.redhat.com/articles/2025/06/11/how-manage-rhel-virtual-machines-podman-desktop)
is another option if it offers a RHEL 9.8+ image for your architecture. A RHEL 10
guest does not qualify this RHEL 9 installer. This local VM is a test target,
not a claim that every Mac hypervisor is a Red Hat-supported production host.

Use the native guest architecture:

| Mac | RHEL VM | Notes |
| --- | --- | --- |
| Apple Silicon, including M4 | `aarch64` | Preferred; do not emulate `x86_64` for normal testing |
| Intel | `x86_64` | Native architecture |

Both architectures are targets, not yet qualified RHEL deployments. The
commands are the same, and the installer checks the selected images against
the guest architecture. Complete and record the checks on each architecture
separately. GPU drivers and local vLLM require separate hardware tests.

## Register the local guest

For an ISO-installed guest using your Developer Subscription, register
**inside the VM**. The interactive command prompts for your Red Hat account
credentials; do not put a password in arguments or scripts:

```console
sudo subscription-manager register
sudo subscription-manager identity
sudo dnf repolist
sudo dnf update -y
sudo systemctl enable --now sshd
getenforce
```

If already registered, inspect its identity instead of registering again.
With Simple Content Access, do not add an `attach --auto` step. Follow the
[RHEL registration guide](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/configuring_basic_system_settings/assembly_registering-the-system-and-managing-subscriptions_configuring-basic-system-settings)
if repositories are unavailable. AWS PAYG guests use RHUI instead.

## Put the repository in the VM

A clone inside this non-production VM preserves the tested Git revision.
Production quickstarts instead transfer only an administrator deployment
bundle. On your Mac, start Bash:

```console
bash
```

Enter the VM administrator login and an optional absolute SSH private-key
path (no surrounding quotes; blank uses your SSH defaults):

```console
{
  read -r -p 'RHEL VM administrator login: ' RHEL_VM
  read -r -p 'SSH private-key path (Enter for SSH defaults): ' SSH_KEY
}
```

Copy and run unchanged:

```console
SSH_OPTIONS=()
if [[ -n "$SSH_KEY" ]]; then
  SSH_OPTIONS=(-i "$SSH_KEY" -o IdentitiesOnly=yes)
fi
ssh -t "${SSH_OPTIONS[@]}" "$RHEL_VM" 'bash -l'
```

Inside the VM, enter the repository URL and branch containing the change.
For an open PR, use its head fork/branch; `main` may not contain it yet:

```console
{
  read -r -p 'Repository HTTPS URL: ' REPOSITORY_URL
  read -r -p 'Branch to test: ' BRANCH
}
```

Copy and run unchanged. The last command records the revision for test
evidence; it does not configure the deployment:

```console
sudo dnf install -y git
git clone --branch "$BRANCH" "$REPOSITORY_URL" ~/secure-single-server
cd ~/secure-single-server
git rev-parse HEAD
```

For unpushed changes, use the bundle-transfer step of the [in-memory
quickstart](../quickstarts/all-in-one/in-memory.md) instead, and record the local revision
plus the uncommitted diff. In that case use `~/secure-single-server-deploy`
as the working directory below.

## Install and verify

Use one guest per scenario, or uninstall/reset between them. For the
**all-in-one** scenario, inside the RHEL VM:

```console
sudo dnf install -y git podman openssl policycoreutils-python-utils tmux curl jq tar gzip python3
sudo scripts/all-in-one/install --prepare
printf '%s' local-openai-test \
  | sudo scripts/common/secret-set openai vm1
printf '%s' local-anthropic-test \
  | sudo scripts/common/secret-set anthropic vm1
sudo scripts/all-in-one/install \
  --profile memory \
  --openai-secret praxis-openai-api-key-vm1 \
  --anthropic-secret praxis-anthropic-api-key-vm1
sudo scripts/common/status
sudo scripts/common/verify --host
```

Dummy credentials are enough for lifecycle checks. Use real versioned
secrets only when testing provider protocols, streaming, tools, accounting,
and coding harnesses.

For the **remote gateway** guest, follow [private-CA preparation and external
TLS/JWT tests](remote-gateway.md) and the [remote installer](../quickstarts/remote-gateway/install.md).
Run the harnesses on your Mac, not in the gateway's service account. No Fedora
override is used on RHEL.

## Test reboot and user separation

```console
sudo reboot
```

Reconnect from the same Mac shell when the VM returns:

```console
ssh -t "${SSH_OPTIONS[@]}" "$RHEL_VM" 'bash -l'
```

Inside the VM (use `~/secure-single-server-deploy` for a transferred bundle):

```console
cd ~/secure-single-server
sudo scripts/common/status
sudo scripts/common/verify --host
```

Create two ordinary VM accounts and test the [user
workflow](../quickstarts/all-in-one/users.md) from each. Both accounts should reach the
loopback inference ports. Neither should be able to read `/etc/praxis`, enter
`/var/lib/praxis-svc`, inspect the service account Podman store, or control
its systemd user services.

Restore a clean VM snapshot before separately testing the Valkey and
Switchyard profiles. Local VM success is the pre-AWS gate; it does not replace
final acceptance on the target AWS RHEL instance.

Next, run [in-memory and Valkey harness acceptance](harnesses.md) with real
provider keys stored by the administrator. Switchyard provider testing is a
later phase. Do not capture snapshots containing real keys for distribution.
