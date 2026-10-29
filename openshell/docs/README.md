# OpenShell Overview

OpenShell provides a policy-controlled execution boundary around a coding
harness and its tools. It governs sandbox lifecycle, filesystem access, network
egress, and runtime limits.

The [Architecture overview](../../docs/quickstarts/architecture-walkthrough/README.md)
describes how OpenShell fits with the harness, model gateway, and inference
options. This page covers OpenShell's deployment assumptions, security
boundaries, and policy qualification evidence.

## Deployment role

The gateway controls its owner's Podman service. Its local management API is
restricted to loopback and requires TLS/mTLS for the registered service
operator. This is a **trusted single-operator deployment**, not a shared-host
multi-tenant boundary. Sandbox JWTs do not authenticate ordinary local
operators.

Provider credentials follow the selected deployment path. Standalone mode can
attach an explicit OpenShell provider binding. Integrated mode rejects direct
provider bindings and lets Praxis hold upstream credentials. SSH helpers do
not forward provider keys. Use synthetic credentials during initial checks;
never put real credentials in images, logs, command arguments, Git, or test
artifacts.

## Manual gateway setup on RHEL

Run these commands in Bash on the dedicated RHEL 9.8+ x86_64 host, logged in as
the administrator. Keep the same shell open so `repo`, `uid`, and `os_run`
remain defined. The checkout under `/opt` is readable by the service account
without placing it in an administrator's home directory.

Install the host packages and clone the repository's `main` branch:

```bash
sudo dnf install -y git podman python3 policycoreutils openssh-clients curl
sudo install -d -o "$(id -un)" -m 0755 /opt/secure-single-server
git clone --branch main \
  https://github.com/redhat-et/secure-single-server \
  /opt/secure-single-server
cd /opt/secure-single-server
repo="$PWD"
git log -1 --oneline
```

Review the checked-out revision before installing. Verify the host supports
Landlock ABI 3 or newer, then install OpenShell. The installer repeats the
Landlock check, creates the locked service account, and starts and registers
the loopback gateway:

```bash
python3 "$repo/openshell/scripts/check-landlock.py" --minimum-abi 3
sudo "$repo/openshell/scripts/install.sh" --owner openshell-svc
```

Define `os_run` in the same Bash session to run commands as the service owner,
then check the gateway service and health endpoint:

```bash
uid="$(id -u openshell-svc)"
os_run() {
  sudo runuser -u openshell-svc -- env HOME=/var/lib/openshell-svc \
    PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin \
    XDG_RUNTIME_DIR=/run/user/"$uid" \
    DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/"$uid"/bus \
    OPENSHELL_BIN="${OPENSHELL_BIN:-/usr/local/bin/openshell}" \
    "$@"
}
os_run systemctl --user status openshell-gateway.service --no-pager
curl --fail http://127.0.0.1:8091/healthz
```

Continue with the [manual harness and model setup](../../docs/quickstarts/openshell-single-server/manual.md).

## Trust boundaries and assumptions

OpenShell applies a profile when it creates a sandbox. Policies are scoped to
actual executable paths and declare filesystem permissions, network endpoints,
and runtime limits. This deployment does not make model output trustworthy,
inspect prompts, or authorize multiple users. An allowed endpoint can still
receive data from a malicious harness. Development profiles permit selected
GitHub and package-registry traffic, so registry access remains a tool
provisioning channel.

Filesystem permissions do not create a host checkout or guarantee retention.
`include_workdir` grants policy permissions; it does not mount a host directory
or prove persistence. Removing a sandbox can remove its work. Export data
before deletion and separately qualify any session-retention requirement.
Detached creation retains the sandbox's main process, not necessarily a
harness started later through an SSH session. Admission control and host-wide
resource ceilings require additional deployment work.

`landlock.compatibility: best_effort` can weaken filesystem protection. Record
the actual kernel and supervisor enforcement result; SELinux Enforcing on the
host alone does not prove sandbox enforcement. The gateway Quadlet disables
SELinux labeling to access its Podman socket, so rootless execution,
loopback-only management, a locked service account, and
`NoNewPrivileges=true` are compensating controls. Do not claim blanket
enforcement for kernel and profile combinations that have not been qualified.

## Example policy review: local Qwen access

The [OpenCode local-inference dev policy](https://github.com/redhat-et/secure-single-server/blob/main/configs/vllm/harness/profiles/dev/policy.yaml)
shows how one sandbox profile describes filesystem access and a narrow model
route. It is a template: deployment replaces the Praxis port and API prefix
placeholders before the policy is applied.

| Policy element | What it permits or describes | What to keep in mind |
| --- | --- | --- |
| `include_workdir: true` | Applies the policy's work-directory permissions to the sandbox work directory. | It does not mount a host checkout or guarantee that work survives sandbox removal. |
| `read_only` | Lists system and runtime paths that the sandbox may read. | Read access can still expose information present inside the sandbox at those paths. |
| `read_write` | Grants writes under `/sandbox`, `/home`, `/tmp`, and `/dev/null`. | This is broader than a single project directory within the sandbox. |
| `landlock.compatibility: best_effort` | Requests Landlock compatibility behavior where available. | The actual kernel and supervisor enforcement result must be qualified; the setting alone is not proof. |
| `praxis_gateway` endpoint rules | Allows `GET` for the model list and `POST` for chat completions at the configured Praxis endpoint. | The chat request can carry prompts and responses. This policy contains no direct OpenAI or Anthropic endpoint. |
| `binaries` | Associates the Praxis endpoint permission with the listed Node and OpenCode executable paths. | This is executable-path policy, not per-user identity. |

This policy limits where the sandbox can send model requests; it does not set
the gateway's upstream. The paired [Praxis configuration](https://github.com/redhat-et/secure-single-server/blob/main/configs/vllm/praxis.yaml)
routes to loopback vLLM for local Qwen. A different Praxis configuration can
send requests to an external provider. The standalone
[OpenCode dev policy](https://github.com/redhat-et/secure-single-server/blob/main/openshell/harnesses/opencode/profiles/dev/policy.yaml), for
example, lists direct OpenAI and Anthropic API endpoints. Review the sandbox
policy and gateway configuration together to understand where model traffic
goes.

Images are digest-pinned for repeatability, not as a claim that their contents
have been independently audited. Harness CLIs are preinstalled, while profiles
that allow package registries can still download packages during later work.
Review the exact profile and endpoint list before deployment; see the
[single-server policy reference](../../docs/quickstarts/openshell-single-server/reference.md).

## Policy enforcement and qualification

Policy files describe intended boundaries; their presence or successful schema
parsing does not prove runtime enforcement. The tests use a controlled local
HTTP fixture to distinguish reachability from denial:

- A permitted request must reach the fixture, increment its request counter,
  and return its known HTTP 401 response. An HTTP error still proves the
  destination was reachable.
- A denied request must produce explicit proxy policy-denial evidence without
  incrementing the destination counter.
- A failed positive control, unreachable destination, SSH error, or timeout is
  inconclusive and fails the test; none is accepted as proof of enforcement.

The runtime contract is implemented by
[`openshell/tests/openshell-policy.sh`](https://github.com/redhat-et/secure-single-server/blob/main/openshell/tests/openshell-policy.sh). The
separate [`policy-advisor.sh`](https://github.com/redhat-et/secure-single-server/blob/main/openshell/tests/policy-advisor.sh) checks the approval
flow: a proposed endpoint is pending, approval permits a retry, and recreating
the sandbox removes the temporary grant. These tests do not qualify Praxis
inference; use the [Praxis smoke test](https://github.com/redhat-et/secure-single-server/blob/main/tests/openshell-praxis/smoke.sh)
with a configured test provider and model for that path.

The [policy boundary check](https://github.com/redhat-et/secure-single-server/blob/main/openshell/tests/policy-boundary.py) compares shipped
profiles with the operator-reviewed maximum in
[`tests/policy-boundary/`](../../tests/policy-boundary/). It requires complete
coverage of the modeled filesystem, network, process, and Landlock domains and
uses mutation controls to reject extra grants. The pinned prover cannot model
the npm `allow_encoded_slash` extension, so that extension is allowed only in
the reviewed enforced, rule-less, read-only REST rules. Other unmodeled
extensions fail closed. Update a profile and its reviewed maximum together;
do not regenerate the boundary from the candidate policy.

Run the boundary check with:

```bash
python3 openshell/tests/policy-boundary.py
```

Set `OPENSHELL_PROVER_BIN` if the prover is outside `PATH`. For CI coverage,
native runtime checks, and other deployment combinations, see the
[testing guide](../../docs/testing/README.md). For the AWS host validation
record, see [bootc validation](../../bootc/VALIDATION.md).

## Next steps

- [Deploy the bootc image](../../docs/quickstarts/openshell-single-server/bootc.md)
- [Configure OpenShell with Praxis](../../docs/quickstarts/openshell-praxis/README.md)
