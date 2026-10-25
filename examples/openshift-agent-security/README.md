<!-- SPDX-License-Identifier: Apache-2.0 -->
# Agent Security Demo

**Useful agent workflows. Enforceable security controls.**

Reusable identity, authorization, isolation and approval controls on OpenShift,
demonstrated through synthetic workflows with Jira as the example backend.

## Start here

Follow these two customer guides in order:

| Guide | What it covers |
|---|---|
| **[1. Setup](docs/identity-demo-customer-quickstart.md)** | Six stages: approved platform → inputs → cluster builds → scoped installation → first run |
| **[2. Operations](docs/identity-demo-console.md)** | Presenting, automatic preparation, audit/Jira history, restart and recovery |

In a `secure-single-server` checkout, enter this example:

```bash
cd examples/openshift-agent-security
```

For the standalone archive, run `cd openshift-agent-security` instead.

## Security at a glance

| Control | What the system enforces |
|---|---|
| **Identity and isolation** | Keycloak authenticates the person. SPIRE attests the OpenShell supervisor; the agent runs in an isolated sandbox. |
| **Protected tool access** | Certificate-bound token exchange protects MCP calls. Trusted components keep backend credentials outside the agent. |
| **Permission and consent** | User, workload, project and run checks apply to protected requests. A create must match the exact approved Jira fields. |
| **Lifecycle and evidence** | Single-use identities, original run deadlines, correlated audit and independently verified Jira outcomes. |

**Analyst + Triage** may create after exact approval. **Viewer or Reader** cannot;
approval never supplies missing authority.

- **Automatic preparation:** a bounded warm pool keeps fresh contexts ready.
  Approved execution profiles let compatible workflows share capacity; pool
  availability grants no authority. Persistent gateway configuration checks every
  protected request.
- **Managed TLS:** an approved cert-manager issuer renews three application
  certificates and rotates their keys. Existing installations opt in through
  guarded maintenance; CA rollover is explicit. See
  [certificate operations](docs/identity-demo-console.md#managed-application-certificates).

## Included workflows

| Workflow | Assessment | Example task |
|---|---|---|
| **CVE triage** | Frozen assessment input | Repeatable user/workload permission comparisons |
| **Incident triage** | Real Messages model inference | Investigate an incident and propose a task |
| **Remediation change request** | Real Messages model inference | Draft a change request with tests and rollback |

## Prerequisites

- **Cluster:** OpenShift 4.21, Linux AMD64 workers and compatible platform controllers.
- **Access and artifacts:** platform-admin assistance, approved external images,
  registry access and private inputs.
- **Launcher workstation:** Bash, matching `oc`, `tar` and a SHA-256 utility.
  The coordinated path builds on OpenShift; local Python, Rust and an engine
  are not required. Qualification includes reviewed checkpoint recovery.

The workstation can disconnect after setup: browser workflows, replenishment
and authenticated issue viewing run on OpenShift.

## Verified scope and review

Recorded evidence covers protected execution, permission denials, live inference,
automatic preparation, token rotation and selected recovery checks. Browser
operation was verified with local workers stopped. Shared controllers were
retained; full empty-cluster bootstrap remains unverified.

This is a connected synthetic evaluation, not production certification or
disconnected delivery. Review [external inputs and release gates](docs/identity-demo-reference.md#open-release-gates)
before customer distribution.

Optional: [developer guide](GETTING-STARTED.md) ·
[technical reference](docs/identity-demo-reference.md) ·
[verification record](docs/verification.json).
