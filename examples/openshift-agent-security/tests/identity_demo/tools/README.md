<!-- SPDX-License-Identifier: Apache-2.0 -->

# Reproduce the operator diagnostics

These tools support controlled security tests in the **supervisor**, outside
the unprivileged agent. They are optional for normal native/browser workflows.
They are not customer application services or alternative authentication paths.

**Release gate:** the pinned SPIRE CLI has unresolved Critical/High dependency
matches in the recorded evaluation scan. These optional diagnostics require
remediation or an explicit security disposition before redistribution. See the
[release gates](../../../docs/identity-demo-reference.md#open-release-gates) and
[recorded verification](../../../docs/verification.json); a new release needs a
current scan of its exact artifacts.

- `spire-agent`: the exact upstream SPIRE 1.14.7 Linux AMD64 musl release binary.
  Its archive and executable hashes are pinned in `inputs.lock.json`. The
  release API's archive digest and local executable were checked independently;
  the executable matches the recorded diagnostic build.
- `read-native-projection`: the checked-in small Go diagnostic. It accepts no
  arguments or configurable path and reads only the supervisor's projected
  Kubernetes compute credential. It rejects empty/oversized input before output.
  **Its successful stdout is a credential.** Use only through the private test
  harness; never run it interactively, collect its output in ordinary logs or
  give it to the agent. SVID test responses also contain private key material.

The existing installer provides the build action. Obtain the exact pinned SPIRE
archive from its official URL in the lock or an approved mirror. Set
`DEMO_SPIRE_ARCHIVE` to that local public file and use a new output directory
inside an existing owner-only directory outside Git:

```bash
PYTHONPATH=scripts/identity_demo:tests/identity_demo "$DEMO_PYTHON" \
  scripts/identity_demo/identity_demo_setup.py diagnostic-build \
  --spire-archive "$DEMO_SPIRE_ARCHIVE" --engine docker \
  --output-dir "$DEMO_PRIVATE_ROOT/diagnostic-plan-01"
```

Preparation checks the archive/executable, selects only the expected regular
archive members and retains source/lock/helper hashes and upstream licence text.
It executes no container engine or network operation. Review the result and
repeat in a **new** directory with `--apply` to compile. Outputs are
`binaries/spire-agent`, `binaries/read-native-projection` and the private
`diagnostic-build.receipt.json`. No kubeconfig or credential input is needed.

Apply pulls digest-pinned Go 1.27.2 and runtime validation images, then runs
synthetic Go tests and compiles with networking disabled, no module downloads,
a read-only root, unprivileged UID and dropped capabilities. Compilation targets
Linux AMD64 and records executable hashes. Both tools run in the pinned AMD64
supervisor base: SPIRE must report its exact version; the reader must refuse
a missing projection and any extra argument without writing stdout. The only
host mounts contain source, public binaries and temporary build/cache files.
Docker has actual execution evidence; Podman acceptance is separate.

Supply these outputs to the existing staging command in
[the execution guide](../../../docs/identity-demo-reference.md). Staging still needs
operator update permission on the exact owned Pod's ephemeral-container
subresource. It grants no privileges itself. The staging container mounts only
the shared run volume; the supervisor performs the actual diagnostic calls.
Never grant an agent permission to read API tokens or the Workload API socket.

These are evaluation diagnostics. Release checksum verification, a successful
build and matching binary do not establish licence/security approval,
customer acceptance or vendor support. Preserve source/build/scan receipts and apply
the package's release review to these artifacts as well.

Sources: [SPIRE release](https://github.com/spiffe/spire/releases/tag/v1.14.7),
[Go command documentation](https://pkg.go.dev/cmd/go),
[official Go container](https://hub.docker.com/_/golang).
