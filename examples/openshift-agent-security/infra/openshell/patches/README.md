<!-- SPDX-License-Identifier: Apache-2.0 -->
# Native evaluation patches

Apply the two patches in the order pinned by [inputs.lock.json](../native-build/inputs.lock.json).
The source commit and upstream Cargo.lock are unchanged. Use the [guarded build procedure](../native-build/README.md).

1. `v0.1.3-sandbox-subject-comparison.patch` compares the signed JWT-SVID subject
   with the authenticated sandbox before releasing intermediate credentials.
   A later gateway denial cannot repair a credential released to another workload.
2. `v0.1.3-bounded-oauth-response.patch` bounds token responses to 128 KiB and
   emits allowlisted OAuth categories without reflecting issuer descriptions.

The sender transport, installation-domain and X.509 feature patches are retired
in this candidate. No request certificate, thumbprint comparison or additional
X.509 dependency is used for delegated MCP requests. Native management mTLS,
ordinary HTTPS and SPIRE attestation remain independently required.

Final grants are bearer tokens with a maximum 30-second lifetime. The protected
host checks their signature, issuer, audience and lifetime, then exact current
user/workload/run/project authority and approval. A copied token can be replayed
within those limits; acceptance must measure credential custody and bypasses.
This candidate is not approved for adoption until deployed checks and explicit
residual-risk review pass. Offline tests alone do not select its token model.

The generic native identity-exchange contract allows unchanged verified binaries
to be repackaged with approved public TLS roots. Images and their trust hashes
remain pinned; endpoint and permission configuration remain installation-specific.
Install the supervisor at `/openshell-supervisor` and gateway at
`/usr/local/bin/openshell-gateway`. Verify packaged and running binaries.
Platform-owner review, maintenance ownership and distribution approval remain
separate gates; development patches do not imply vendor support.
