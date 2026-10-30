# Mock gateway demo checks

The [demo deployment workflow](../../.github/workflows/pricetag-demo.yml) runs on
a disposable GitHub-hosted Linux runner. It builds the pinned MaaS and PriceTag
demo sources, starts PostgreSQL and Praxis, and runs the API/browser/quota suite
against synthetic inference. No provider keys, SSH credentials or publishing
secrets are required.

The [management demo #91](https://github.com/redhat-et/secure-single-server/pull/91)
and [image publication #92](https://github.com/redhat-et/secure-single-server/pull/92)
are merged. Source builds use the same reviewed revisions as publication;
replacing them with qualified registry digests is a later optimization.

The build also runs PriceTag’s Go tests against a disposable PostgreSQL instance
with the full migration chain, plus all PriceTag UI JavaScript unit tests.

## Coverage

| Area | Assertions |
| --- | --- |
| Public boundary | Private management endpoints remain unavailable; forwarded identity headers do not grant privileges. |
| Users and teams | UI onboarding and reassignment; rendered personal Usage for members, managers and impersonation; direct API checks for own-user scope, mixed/cross-user filters, forged headers, and cross-team chart denial; 20-user fixture. |
| Keys | Duplicate submission prevention, hidden copy/download, multiple working keys, cross-key usage, expiry countdowns, active/history pagination, owner-only revocation, admin revoke-all and demotion regression. |
| Offboarding and sessions | Existing-session chart denial after suspension, anonymous API denial, same-origin view-as/logout confirmation, impersonation restrictions. |
| Pricing | Catalog reads, discount save/refresh, custom rates, unchanged historical charges and explicit repricing confirmation. |
| Budgets | Searchable per-user overrides, removal/inheritance, manager monthly totals, configured-model selection, paid-model denial, global exceptions and independent legacy token gate. |

Provider/model editing through a host adapter is excluded. It belongs to the
optional follow-up image and is not required by this suite. Browser tests verify
the actual mock configuration before performing mutations.

## Run on the benchmark RHEL deployment

Install the [mock demo](pricetag-management-demo.md), then install the pinned
browser dependency once from the repository:

```sh
npm ci --prefix tests/pricetag/browser --ignore-scripts
sudo tests/pricetag/browser/node_modules/.bin/playwright install chromium
```

Playwright also needs its OS browser libraries; use a prepared benchmark host.
Then run the suite, using a new private output directory each time:

```sh
sudo python3 tests/pricetag/demo-suite \
  --node-modules "$PWD/tests/pricetag/browser/node_modules" \
  --output /root/pricetag-admin/demo-acceptance
```

If the host cannot reach its own configured public IPv4, append
`--loopback-public-ip`. This temporarily adds a local route for that address and
removes it afterward; it does not change the AWS security group or skip TLS.

## Run the disposable container deployment

Use a disposable Linux host with rootful Podman, Python/PyYAML, OpenSSL, Node and
Playwright. This runner refuses an existing deployment. Pull/build application
images first and set the three image variables to reviewed references:

```sh
sudo python3 tests/pricetag/container-demo.py \
  --maas-image "$MAAS_IMAGE" --metering-image "$METERING_IMAGE" \
  --praxis-image "$PRAXIS_IMAGE" \
  --node-modules "$PWD/tests/pricetag/browser/node_modules" \
  --output /var/tmp/pricetag-demo-acceptance
```

The disposable PostgreSQL container starts directly as the pinned image’s
non-root `postgres` account with all capabilities dropped and
`no-new-privileges`. It creates a private `0700` data directory below a bounded
1 GiB tmpfs, independent of host defaults. This avoids the image’s root-to-user
`gosu` step, where the hosted runner stalled before PostgreSQL initialization.
Application database bootstrap follows the installer: wait for PostgreSQL, pass
SQL through stdin with `ON_ERROR_STOP=1`, then verify the application database.
The generated SQL stays private on the host and is not bind-mounted into the
container. Storage/bootstrap failures produce fixed diagnostic codes and startup milestones
(configuration, data sync and final listener). Raw database logs
remain private. A readiness timeout alone does not establish a storage failure.

Containers and generated deployment credentials are removed afterward. Ports
are bound to loopback. Private diagnostic logs stay in the output directory;
CI uploads **only structured pass/fail results**, never keys, browser traces or
raw service logs.

Container CI validates application behavior and generated gateway configuration.
It does **not** validate RHEL Quadlets, SELinux or fresh-host installation. Keep
[benchmark RHEL qualification](pricetag-management-demo.md) as a separate check.

### Database preflight and environment parity

CI first starts the pinned PostgreSQL image alone, without host mounts,
application data or published ports, on a network with no external connectivity.
It verifies initialization and an authenticated TCP query before building the
application images. On failure, only this disposable container's startup log is
printed, with its generated test password redacted. Application logs remain private.

Run the same preflight on a disposable Linux test host with:

```bash
sudo python3 tests/pricetag/database-smoke.py
```

The preflight records Podman version, CPU architecture, OCI runtime and
AppArmor/SELinux status. GitHub uses an AMD64 Ubuntu 24.04 VM; a Mac Podman VM
may use ARM64 Fedora CoreOS. Running Ubuntu inside that VM does not reproduce
the hosted kernel or security policy. Local passes are regression evidence;
the hosted job must pass before CI qualification is complete.

The Ubuntu CI job loads `tests/pricetag/ci.apparmor` as its container profile.
It preserves the Podman default filesystem, mount and kernel-interface denials,
adding signal permission for the same profile stacked with `crun`. This targets
[container-libs #805](https://github.com/podman-container-tools/container-libs/issues/805):
`no-new-privileges` can otherwise prevent `pg_ctl` from stopping its own temporary
PostgreSQL server. Hosted audit records identified `pricetag-demo-ci` denying signals to
`crun//&pricetag-demo-ci`. The profile permits this exact peer and the reverse
ordering used by other runtime versions; hosted qualification must confirm the
updated rule. AppArmor, seccomp, dropped capabilities and
`no-new-privileges` remain enabled. The profile and configuration are installed
only on the disposable CI host; the RHEL installer retains its SELinux setup.
The database preflight reports the selected profile and exercises PostgreSQL's
bootstrap start/stop sequence before accepting readiness.

On a preflight failure, the job also extracts recent kernel AppArmor signal
denials for PostgreSQL/runtime processes. It prints only profile, peer, process
name, signal and permission masks. Raw audit records, file paths from denied
file operations and command arguments are not published. These records identify
which layer of a stacked profile rejected the signal; a selected container
profile alone does not establish that the host runtime profile allows it.
