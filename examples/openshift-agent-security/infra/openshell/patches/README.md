<!-- SPDX-License-Identifier: Apache-2.0 -->
# Native evaluation patches

Apply the patches in the order pinned by
[the native build lock](../native-build/inputs.lock.json), using the
[guarded native build procedure](../native-build/README.md).
Upstream source/dependency pins are retained. Patch hashes describe the neutral
export bytes; they are not historical deployment receipts.

1. `v0.1.3-sandbox-subject-comparison.patch`: compare signed JWT-SVID subject with
   the authenticated sandbox before intermediate credential release.
2. `v0.1.3-pilot-sender-transport.patch`: share the same immutable X.509 SVID for
   the final exchange and MCP TLS connection; reject binding mismatch/expiry.
3. `v0.1.3-sender-installation-domain.patch`: require the configured compile-time
   trust domain rather than the sender patch's example domain.
4. `v0.1.3-sender-x509-feature.patch`: enable the required X.509 Workload API
   feature with its recorded dependency lock.
5. `v0.1.3-bounded-oauth-response.patch`: bound token responses to 128 KiB and
   report only allowlisted OAuth categories; never reflect issuer descriptions.

The build recipe selects optimized auditable release binaries. The response
bounds passed 16 offline native OAuth tests, and target-specific release images
were built and exercised within the recorded evaluation. Each new installation
still needs its own matching images. Designated platform/native security review,
a named maintenance owner and release approval remain distribution gates.
The build records exact MCP host, token endpoint, issuer/MCP audiences, trust
domain and public CA bundle. A target contract change requires a new build.
The gateway must independently enforce signature, audience, certificate peer,
SPIFFE identity, user/workload/run binding and exact approval.

Install the supervisor binary at `/openshell-supervisor` and gateway at
`/usr/local/bin/openshell-gateway`. Verify packaged and running executables.
These development patches do not establish vendor support or production
approval; review [release limits](../../../docs/identity-demo-reference.md).
