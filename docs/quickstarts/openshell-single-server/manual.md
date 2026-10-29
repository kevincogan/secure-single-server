# Manual single-server container deployment

Install OpenShell and a harness sandbox on a dedicated RHEL 9.8+ x86_64 VM or
bare-metal host. Run every shell block in Bash on that host, logged in as the
administrator, unless a command uses `sudo` or `os_run`. Keep one shell session
open from the repository checkout through the setup so `repo` and `os_run`
remain available. For the OS-image route, use the separate [bootc guide](bootc.md).

OpenShell runs under a locked service account with rootless Podman. Praxis is
an optional, separately installed model gateway. Review the
[qualification and policy limits](reference.md) before extending this deployment.

## 1. Install OpenShell

Use a dedicated RHEL 9.8+ x86_64 host. The full scenario was validated on
RHEL 9.8 with Podman 5.8.2; see the
[validation record](../../testing/upgrade-0.1.5.md). For first qualification,
use a disposable instance before changing a long-lived server. Install Git,
Podman, Python 3,
OpenSSH clients, curl, and the SELinux management tools. RHEL 9 does not
package `ripgrep`, so install the pinned static binary used by the image:

```bash
sudo dnf install -y git podman python3 policycoreutils openssh-clients curl
rg_version=14.1.1
rg_sha256=4cf9f2741e6c465ffdb7c26f38056a59e2a2544b51f7cc128ef28337eeae4d8e
curl -fsSL "https://github.com/BurntSushi/ripgrep/releases/download/${rg_version}/ripgrep-${rg_version}-x86_64-unknown-linux-musl.tar.gz" -o /tmp/rg.tar.gz
printf '%s  /tmp/rg.tar.gz\n' "${rg_sha256}" | sha256sum -c - &&
  tar -xzf /tmp/rg.tar.gz -C /tmp &&
  sudo install -m 0755 "/tmp/ripgrep-${rg_version}-x86_64-unknown-linux-musl/rg" /usr/local/bin/rg
```

In the same host shell, create a checkout under `/opt` and review the commit
before installing. The checkout and its parent directory are readable by
`openshell-svc`, so service-owner commands can use the scripts there:

```bash
sudo install -d -o "$(id -un)" -m 0755 /opt/secure-single-server
git clone https://github.com/redhat-et/secure-single-server /opt/secure-single-server
cd /opt/secure-single-server
repo="$PWD"
git log -1 --oneline
```

```bash
sudo ./openshell/scripts/install.sh --owner openshell-svc
```

The installer creates the locked `openshell-svc` account, enables lingering so
the gateway remains available after logout, and starts the loopback-only
OpenShell gateway with TLS/mTLS for the service operator.
It first verifies Landlock ABI 3 or newer, then pre-pulls every pinned supported
harness image; the selected harness is chosen when its sandbox is created. If
Landlock is unavailable or too old, installation stops with that kernel
diagnostic instead of a later `ContainerExited` sandbox failure. If it reports
that cgroup delegation needs a host reboot, reboot and rerun the same installer.

## 2. Set up the service-owner shell helper

Run the remaining commands in the same Bash session. The helper runs commands
as the locked OpenShell service account with its home and user bus configured.
Keep the checkout and its parent directories readable by `openshell-svc`.

```bash
repo="$PWD"
uid="$(id -u openshell-svc)"
os_run() {
  sudo runuser -u openshell-svc -- env HOME=/var/lib/openshell-svc \
    PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin \
    XDG_RUNTIME_DIR=/run/user/"$uid" \
    DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/"$uid"/bus \
    OPENSHELL_BIN="${OPENSHELL_BIN:-/usr/local/bin/openshell}" \
    "$@"
}
```

The harness scripts look for the OpenShell CLI at `/usr/local/bin/openshell`
by default. Export `OPENSHELL_BIN` before using `os_run` when the CLI lives
elsewhere — on bootc hosts, for example, it is `/usr/bin/openshell`.

## 3. Create and connect the harness

Create the selected harness with its `dev` policy. The profile is part of the
create operation:

```bash
harness=opencode  # opencode or openclaw
os_run "$repo/openshell/harnesses/$harness/create.sh" \
  --profile dev --name "$harness"-dev
```

Connect from the same owner environment:

```bash
os_run "$repo/openshell/harnesses/$harness/connect.sh" --name "$harness"-dev
```

OpenCode launches its CLI. OpenClaw opens a shell for inspecting the sandbox.
For OpenClaw model tasks, configure Praxis and use the
[bounded model and tool workflow](../openshell-praxis/openclaw.md).

To inspect any harness sandbox with a Bash session, pass `bash` as the remote
command instead of modifying the harness script:

```bash
os_run "$repo/openshell/harnesses/$harness/connect.sh" --name "$harness"-dev bash
```

Use `dev` for the initial deployment. Each sandbox defaults to two CPUs, 4 GiB
of memory, and 2048 PIDs. See the [qualification reference](reference.md) for
profile and harness limitations.

## 4. Choose model access

### OpenAI API key

The following example uses OpenCode. Run in Bash on the server after OpenShell
is ready. Create and review this non-secret profile; a fresh gateway has no
pre-imported provider profiles:

```bash
cat > /var/tmp/openai-model.yaml <<'YAML'
id: openai-model
display_name: OpenAI model access
category: inference
credentials:
  - name: api_key
    env_vars: [OPENAI_API_KEY]
    required: true
    auth_style: bearer
    header_name: authorization
endpoints:
  - {host: api.openai.com, port: 443, protocol: rest, access: read-write, enforcement: enforce}
binaries: [/usr/local/bin/opencode, /usr/bin/node-26]
YAML
os_run openshell profile lint -f /var/tmp/openai-model.yaml
os_run openshell profile import -f /var/tmp/openai-model.yaml
```

Register your actual OpenAI API key at the hidden prompt. The key is read inside
the service-account process, so it survives the administrator-to-service-account
boundary without appearing in command arguments:

```bash
os_run bash -c '
cd /
set -eu
set +x
IFS= read -r -s -p "OpenAI API key: " OPENAI_API_KEY; printf "\n"
export OPENAI_API_KEY
openshell provider create --name openai-key --type openai-model \
  --credential OPENAI_API_KEY
unset OPENAI_API_KEY
'
```

Attach the provider when creating a new sandbox, then connect:

```bash
os_run "$repo/openshell/harnesses/opencode/create.sh" --profile dev --name opencode-openai --provider openai-key
os_run "$repo/openshell/harnesses/opencode/connect.sh" --name opencode-openai
```

In OpenCode, use `/models` to select an OpenAI model available to your account.
The attached provider supplies an opaque `OPENAI_API_KEY` placeholder; OpenShell
substitutes the real key only for the profile's authorized endpoint. Do not paste
the real key into OpenCode's `/connect` prompt or store it in harness config.
Follow the [model verification steps](verification.md#1-prove-model-interaction).
Verify model access on your host. The
[real-model deployment qualification](../../testing/upgrade-0.1.3-e2e.md) is
historical 0.1.3 evidence and does not replace a current-host check.

### Local OpenAI-compatible endpoint and key

For an existing authenticated local endpoint, use the same import, hidden-prompt,
and sandbox creation flow above with these substitutions:

| Setting | Local endpoint example |
| --- | --- |
| Profile file and `id` | `/var/tmp/local-model.yaml`, `local-model` |
| Profile endpoint | `host: inference.internal`, `port: 443` |
| Provider creation | `--name local-key --type local-model --credential OPENAI_API_KEY` |
| Prompt value | The key issued by your local inference server, not an OpenAI cloud key |
| Sandbox | `--name opencode-local --provider local-key` |
| Client base URL | `https://inference.internal/v1` |
| Model | The exact model ID served by that endpoint |

See the [complete local profile and OpenCode configuration](model-access.md#local-openai-compatible-service)
for copyable examples. Use the endpoint's actual host and port in both the
profile and client configuration. Changing only the base URL does not authorize
credential delivery to a new host. For inference on the OpenShell host, use
`host.openshell.internal`, rather than sandbox `localhost`.

A server that enforces bearer authentication needs its real key. A server that
does not authenticate requests needs a credentialless profile; an SDK may still
require a non-empty placeholder such as `unused`. The placeholder does not grant
access to an authenticated server.

## 5. Verify the deployment

Set `sandbox` to the name you created, then verify its runtime ceilings from
the host:

```bash
sandbox=opencode-openai  # use opencode-dev or opencode-local for those examples
cd /
container_id="$(
os_run podman ps --filter name=openshell-default--"$sandbox" -q)"
os_run podman inspect "$container_id" \
  --format 'cpus={{.HostConfig.NanoCpus}} memory={{.HostConfig.Memory}} pids={{.HostConfig.PidsLimit}}'
```

The expected default is `cpus=2000000000` (two CPUs), `memory=4294967296`
(4 GiB), and `pids=2048`.

Run the controlled policy qualification as the service owner from the reviewed
repository checkout:

```bash
cd /
os_run bash "$repo/openshell/tests/openshell-policy.sh"
```

The test starts a local HTTP fixture, creates temporary allow and deny
sandboxes, proves the allowed request reaches the fixture, and proves the denied
request returns `EACCES` without reaching the server. A `401` from the fixture
is a successful positive control; an external website error is not.

Follow the [harness checks](verification.md) to test workspace writes and,
when model access is configured, inference and tool execution.

## Optional Praxis routing

Install the [Praxis gateway and OpenShell add-on](../openshell-praxis/install.md),
then follow the [OpenCode integration configuration](../openshell-praxis/users.md).
The gateway installation is a prerequisite for the add-on. Use an integrated
sandbox without a direct `--provider` binding. For OpenClaw, follow the
[bounded model and tool workflow](../openshell-praxis/openclaw.md).

## Sandbox operations

For a one-off network requirement, add `--policy-advisor` when creating the
sandbox. After the harness reports a denial and proposal, review and approve it
as the same service owner:

```bash
os_run "$repo/openshell/scripts/policy-approve.sh" list HARNESS-dev
os_run "$repo/openshell/scripts/policy-approve.sh" approve HARNESS-dev --chunk-id PROPOSAL-ID
```

The grant applies only to that sandbox instance and disappears when the sandbox
is recreated. Successful approvals are recorded in a local JSONL audit file.

Inspect the sandbox and remove it only after exporting needed work:

```bash
os_run openshell sandbox list
os_run openshell sandbox delete HARNESS-dev
```

