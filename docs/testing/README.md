# Testing

> **Where this fits:** The evidence stop. Return here after every deployment or
> configuration change.

## MaaS and PriceTag benchmarks

[Set up a mock host and run benchmarks](pricetag-perf.md) with configurable
concurrency and request counts, accounting verification and resource sampling.
For real-provider installation and administration, use the official
[MaaS and PriceTag guide](../quickstarts/remote-gateway-pricetag/README.md).

## AWS RHEL workflow

For a fresh VM and manual use, follow the [official installation sequence](aws.md#6-install-services-and-test)
after AWS deployment. It does not require running smoke tests first.

For automated qualification, select a VM once and follow these in order:

1. [Deploy VMs](aws.md) — separate plan/launch blocks, an ordinary user login
   for all-in-one and a copyable VM inventory.
   CPU/GPU variants follow the test sequence below; external-provider-only
   variants link to their standard installation guides.
2. [Run mock smoke tests](rhel-smoke.md) — install services and exercise all
   supported direct harness/provider paths without real keys.
3. [Install and test real Qwen](rhel-real.md) — remove mocks, install vLLM,
   optionally add OpenAI/Anthropic, then start manual testing.

For all-in-one users, use the login created during AWS setup
→ [install and use harnesses](../quickstarts/all-in-one/users.md)
→ [run the acceptance task](harnesses.md#acceptance-task).
Remote clients use [the HTTPS/JWT harness guide](harnesses.md#remote-gateway-client).
For automated tasks from a separate machine, use [external-client acceptance](external-clients.md).
[OpenShell testing](openshell-manual.md) is optional after the all-in-one baseline.

References, as needed:

- [Compatibility matrix](compatibility.md): direct and OpenShell results by scenario/backend.
- [Gateway feature testing](gateway-features.md): model selection, limits, quotas and recovery by harness.
- [AWS operations](aws-operations.md): access choices, custom hardware, recovery and cleanup.
- [vLLM administration](../quickstarts/common/vllm.md): installation without the smoke runner and maintenance.
- [vLLM debugging](vllm-debugging.md): known failures, upstream leads and fix qualification.
- [MaaS + PriceTag pilot](pricetag.md): finite MaaS API keys, USD budgets,
  deployment, and metering. The linked [AWS runbook](aws-pricetag.md) and
  [performance procedure](pricetag-perf.md) retain the pilot's operational and
  measured quota details.

## OpenShell harness model and tool checks

The active OpenShell pins and release compatibility are reviewed in
[OpenShell 0.1.5](upgrade-0.1.5.md). The
[OpenShell 0.1.3 upgrade qualification](upgrade-0.1.3.md) remains historical
AWS OpenCode and OpenClaw evidence with controlled model fixtures and its
coverage limits.

The [earlier OpenClaw Praxis qualification](openclaw-praxis.md) records the
previous pins and real-Qwen acceptance. Those results are historical and do
not qualify real inference on the upgraded pins.

## Local development checks

Run the offline regression suite from the repository root:

```console
python3 -B tests/mocked-provider.py --suite offline
```

It requires Python 3.9+ with PyYAML and Jinja2, Bash, Git, OpenSSL, `jq`, `rg`, Ruby with Psych and
ShellCheck. Install zsh to check both supported workstation shells.

With Podman running, execute the container regressions and mock API contracts:

```console
python3 tests/mocked-provider.py --engine podman
```

On an SELinux-enforcing host (RHEL/Fedora) the container tests stage their
config inputs and request a shared `container_file_t` label (`:ro,z`) on every
bind mount, because rootless Podman cannot read the `user_home_t`/`user_tmp_t`
labels of a checkout or temporary directory. The installer applies the same
label to `/etc/praxis` files with `semanage` and `restorecon`; no extra host
setup is required to run the tests.

The [mocked-provider guide](mocked-provider.md) describes suite selection and
coverage. Container tests check startup, credentials, quotas and API contracts;
RHEL tests additionally check packages, SELinux, rootless user services and
reboot behavior. Neither replaces real model/tool acceptance.

Other environments:

- [Fedora CoreOS Podman machine](fedora-coreos.md): the macOS image test loop.
- [Disposable Podman container](podman.md): manual provider calls.
- [Local RHEL VM](rhel-vm.md): the full host test without AWS.
- [Full Fedora VM](fedora-vm.md): development with the explicit Fedora override.

## Architecture and CI

The pinned Praxis and Valkey images include amd64 and arm64. Container tests
compare the image architecture with the engine host; emulation does not qualify
native deployment. The mutable vLLM workflow requires RHEL 9 x86_64. OpenShell
runtime checks and deployment qualification require RHEL 9.8+; the tested
baseline is Podman 5.8.2.

[CI](https://github.com/redhat-et/secure-single-server/blob/main/.github/workflows/validate.yml) runs static checks and container
contracts on native amd64 and arm64 Linux runners with synthetic credentials.
It does not run the RHEL installer or paid provider calls. Qualify each intended
RHEL architecture, profile and harness/model combination separately.

## OpenShell and bootc

These workflows target RHEL 9 x86_64. OpenShell runtime qualification requires
RHEL 9.8+ with Podman 5.8.2. Run offline checks on Linux with
Bash 4+ (the macOS system Bash 3.2 cannot run all bootc/static checks):

```console
bash openshell/tests/openshell-static.sh
python3 openshell/tests/probe-test.py
python3 bootc/tests/build.py
shellcheck -x bootc/build bootc/test-images bootc/test-host bootc/scripts/*
```

The OpenShell runtime CI job requires manual dispatch, `OPENSHELL_SELF_HOSTED=true`
and a disposable runner labeled `self-hosted/Linux/X64/rhel9/openshell-disposable`.
A skipped job provides no runtime evidence. For combined Praxis inference, use
[the optional OpenShell smoke step](rhel-smoke.md#optional-openshell).

Follow the [bootc guide](../../bootc/README.md) for published-image deployment
and booted-host checks. [Bootc service hardening](bootc-hardening.md) explains
why the reconciler units are not sandboxed, why the container units still are,
and what was validated on a booted host. Bootc and OpenShell
lifecycle tests do not qualify all provider/harness combinations.

## Next step

Review the [compatibility matrix](compatibility.md),
[bootc validation record](../../bootc/VALIDATION.md), and
[vLLM validation record](../../bootc/VLLM-VALIDATION.md) before promoting a
combination.
