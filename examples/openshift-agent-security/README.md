<!-- SPDX-License-Identifier: Apache-2.0 -->
# Agent Security Demo

This OpenShift example has its own prerequisites and installation path.
From the parent `secure-single-server` checkout, enter the example before
running its commands:

```bash
cd examples/openshift-agent-security
```

A connected evaluation of authenticated users, attested workloads, certificate-bound
token exchange, protected MCP access, exact approval and scoped Jira credentials.

**Verified evaluation boundary:** protected execution, permission denials, real
inference, automatic preparation, token rotation and selected recovery checks have
recorded evidence. Browser execution, replenishment and authenticated issue viewing
were verified with local background workers stopped. The tested target uses
OpenShift 4.21 and compatible shared platform controllers; bootstrapping every
controller on an empty cluster is not verified. See the [verified boundaries and
remaining release gates](docs/identity-demo-reference.md#cluster-runtime-hardening-status).

**Start with [Setup](docs/identity-demo-customer-quickstart.md).** It explains the
security layer, prepares its infrastructure, then installs and verifies the demo.
Use [Operations](docs/identity-demo-console.md) for automatic preparation, presenting,
retained audit/Jira access and recovery. A bounded warm pool keeps unused contexts
ready; stable gateway configuration still checks every protected request.

Managed certificate mode uses an approved cert-manager issuer to renew the three
application TLS certificates and rotate their keys. Legacy installations opt in
through guarded idle maintenance; CA rollover remains an explicit PKI procedure.
See [certificate operations](docs/identity-demo-console.md#managed-application-certificates).

The reusable security controls constrain three synthetic demonstrations:
Incident triage and Remediation change request use real Messages inference;
CVE triage uses frozen assessment input. Analyst + Triage can create only after
exact approval; Viewer or Reader cannot. Backend credentials stay outside the agent.

An existing OpenShift 4.21 cluster with Linux AMD64 workers, platform-admin
assistance, approved external images and private inputs is required. The installer
workstation was validated on Apple Silicon macOS with Python 3.13; it can be
disconnected after setup. Other workstation platforms need validation. This is an
evaluation package, not production certification or disconnected delivery. See the
verification record for passing scenarios and outstanding acceptance gates.

Architecture review: start with the [request and trust boundaries](docs/identity-demo-reference.md#architecture-and-permission-boundaries),
then the [source review map and local checks](GETTING-STARTED.md). Customer evaluation
delivery still needs approved external artifacts, finding dispositions, support/licensing
clearance and an independent walkthrough; passing tests do not close those gates.

Optional: [technical reference and release requirements](docs/identity-demo-reference.md),
[sanitized verification](docs/verification.json), and [source hash inventory](export-manifest.json).

The customer source package excludes credentials, private configuration, generated
state, binaries and inherited Git history.
