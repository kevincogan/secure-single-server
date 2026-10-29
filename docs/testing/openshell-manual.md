# OpenShell engineering acceptance on all-in-one

This is an engineering acceptance page, not a customer deployment guide. For
the OpenCode or OpenClaw manual and bootc paths, start with the
[single-server guide](../quickstarts/openshell-single-server/README.md). Run
these all-in-one checks on RHEL 9.8+ with Podman 5.8.2, after
[direct harness acceptance](harnesses.md) and
keep real Qwen installed.
The [matrix](compatibility.md#openshell) separates CPU/GPU, service-operator
checks and ordinary-user access. Bootc results do not qualify mutable RHEL.

## 1. Run installation, inference and policy probes

On the workstation, [select the VM](aws.md#4-select-one-vm-for-testing), then:

```console
python3 tests/rhel/run.py --host "$RHEL_HOST" --ssh-key "$SSH_KEY" \
  --scenario all-in-one --phase openshell
```

The runner installs the addon under `openshell-svc`, uses its authenticated
TLS/mTLS management connection and selects the installed mock or real Qwen
route. It checks that Praxis files are preserved, requires a final inference
answer and separately exercises controlled network allow/deny cases.
It also approves a policy-advisor proposal for a controlled private endpoint,
requires the retry to reach that endpoint, recreates the sandbox, and requires
the grant to disappear. Use `--profile valkey` if that is the installed profile.

These are **service-operator probes**, not a full harness task or personal-user
acceptance. Do not copy the operator's client certificate/key to `praxis-user`.
Individual access remains blocked by [#12](https://github.com/redhat-et/secure-single-server/issues/12).

The equivalent standalone runtime check is:

```console
sudo runuser -u openshell-svc -- env HOME=/var/lib/openshell-svc \
  XDG_RUNTIME_DIR=/run/user/$(id -u openshell-svc) \
  DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u openshell-svc)/bus \
  bash openshell/tests/policy-advisor.sh
```

## 2. Qualify actual sandboxed harnesses

OpenCode's recipe is the first available Praxis integration. A full result
requires its CLI to perform the [file/test task](harnesses.md#acceptance-task)
inside the sandbox, followed by independent execution of the generated tests.
The pinned OpenCode image has Node.js but no Python. Use equivalent `add.mjs`
and `node:test` cases for `add(2, 3)`, `add(-2, -3)` and `add(0, 0)`; require
`node --test --test-reporter=tap test_add.mjs` to pass with nonzero test count.
Record this as a Node task, separately from the direct-host Python task.
Record the sandbox CLI version separately from the direct-host CLI version.

Require generated files, nonempty tests, streamed inference and continuation
after tool results through Praxis. Do not attach a direct-provider binding.
For OpenClaw, run the [bounded-agent checks](openclaw-praxis.md).
Claude's image/recipe and Anthropic translation remain missing.
A Ready sandbox or API probe cannot qualify a model/tool workflow.

## 3. Record security and lifecycle separately

Check actual sandbox CPU/memory limits, successful Praxis access and explicit
denials of direct backend/provider access. The dev profile permits selected
package/documentation traffic; inference routing alone does not prove confinement.

Record management TLS/mTLS, telemetry settings, kernel enforcement and
restart/reconnect results separately. See [open blockers and follow-up issues](compatibility.md#openshell-blockers-and-open-issues).
Export needed files before deleting a sandbox. Never count a connection failure
as evidence of a policy denial without a successful positive control.
