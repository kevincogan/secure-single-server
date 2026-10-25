# Secure single-server AI harness

[![Documentation](https://img.shields.io/badge/docs-GitHub%20Pages-blue)](https://redhat-et.github.io/secure-single-server/)
[![Deploy documentation](https://github.com/redhat-et/secure-single-server/actions/workflows/pages.yml/badge.svg)](https://github.com/redhat-et/secure-single-server/actions/workflows/pages.yml)

> **Published documentation.** The rendered guides are available at
> [redhat-et.github.io/secure-single-server](https://redhat-et.github.io/secure-single-server/).

Secure single-server AI harness runs [OpenCode](https://github.com/anomalyco/opencode)
and [OpenClaw](https://github.com/openclaw/openclaw) on one dedicated RHEL 9
x86_64 host. [OpenShell](https://github.com/NVIDIA/OpenShell/tree/v0.1.4/docs)
enforces the execution boundary. For the integrated harness paths,
[Praxis](https://github.com/praxis/praxis) routes model traffic, while
the optional [Red Hat bootc deployment](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_image_mode_for_rhel_to_build_deploy_and_manage_operating_systems/index)
provides a repeatable OS environment managed by a container image.

The simplest way to understand what OpenShell can add to your environment is
the [Streamlit before-and-after demo](docs/examples/streamlit-security/README.md).
It runs the same app in an ordinary container and an OpenShell sandbox to show
credential substitution and filesystem confinement.

> [!IMPORTANT]
> This is an experimental demonstration, not a production-ready platform. Use
> a disposable host for first evaluation and review the linked qualification
> evidence before extending a deployment.

## How It Works

The integrated request path is:

```text
OpenCode / OpenClaw → OpenShell sandbox → Praxis → approved model
```

OpenClaw supports bounded coding tasks through Praxis; see the
[OpenClaw walkthrough](docs/quickstarts/openshell-praxis/openclaw.md) and its test evidence.

- **Dedicated always-on execution.** Long-running agents continue on the
  server while your laptop disconnects. Workspaces, audit records, and cached
  model artifacts remain on the host.
- **Policy-enforced harnesses.** OpenShell confines each harness and its tools
  with declared filesystem, network, process, runtime, and service-account
  policies. The gateway records policy decisions for later review.
- **Centralized model access.** On the integrated paths, Praxis owns provider
  credentials and selects the approved upstream. The harness and sandbox do
  not hold provider keys.
- **Repeatable deployment.** Published bootc images carry the OpenShell CLI,
  service configuration, and pinned workload references. First boot pulls the
  selected control-plane and harness images into rootless Podman storage.

## Deployment methods

Deploy the stack as a bootc image or install it manually with Podman. Both
methods support the [post-deployment scenarios](docs/examples/README.md). See
[Deployment methods](docs/deployment-methods.md) for the guides.

For an alternative OpenShift deployment, see the
[OpenShift agent security example](examples/openshift-agent-security/README.md).
It demonstrates attested workload identity, certificate-bound delegation,
protected MCP tools, exact-action approval and audit using synthetic workflows,
with separate prerequisites and setup instructions.

## What can I do with this setup?

For a post-deployment workflow, try the
[OpenCode PR-candidate queue](docs/examples/opencode-pr-queue/README.md):

- Queue public GitHub issues or operator prompt files for a public repository.
- Optionally keep a longer batch alive in `tmux` after disconnecting from SSH.
- Collect one reviewable bundle per task containing the task, proposed patch,
  metadata, and report.
- Review the bundle on your workstation, then apply it and open a draft PR with
  your local Git and GitHub CLI credentials.

This scenario is issue/prompt-to-patch only. It does not perform pull-request
reviews, and the sandbox receives no GitHub token or GitHub write access.

For risk-focused security demos, explore these scenarios:

- [API key theft](docs/examples/api-key-theft/README.md): a planted key is
  discoverable, but attempts to spend it outside the approved gateway are
  blocked and audited.
- [Document exfiltration](docs/examples/document-exfiltration/README.md): a
  malicious skill tries several ways to send a document to an attacker
  destination; the boundary blocks each attempt.
- [Model escalation](docs/examples/model-escalation/README.md): compare an
  unrestricted model choice with the approved gateway catalog, which refuses
  an unapproved model before credentials are used.

For quota administration, see the [Praxis token quotas scenario](docs/examples/praxis-quotas/README.md). All post-deployment scenarios are indexed in
[Example scenarios](docs/examples/README.md). Run them from the deployed
repository checkout: on a bootc image, use
`/usr/share/secure-single-server`; on a manual deployment, use
`/opt/secure-single-server`. Published image tags contain only the reviewed
revision from their build time, so use a rebuilt image or an updated manual
checkout when trying newer examples.

## Explore Further

- [Architecture overview](docs/quickstarts/architecture-walkthrough/README.md):
  component roles, model access paths, and system boundaries.
- [Manual single-server guide](docs/quickstarts/openshell-single-server/manual.md):
  OpenShell installation from a service-readable checkout, harness setup, Bash
  sandbox access, verification, and policy tests.
- [OpenShell Overview](openshell/docs/README.md): deployment assumptions,
  trust boundaries, and policy qualification evidence.
- [Praxis integration](docs/quickstarts/openshell-praxis/README.md): model
  routing, quota semantics, and the experimental harness paths.
- [llm-d-sc semantic routing](docs/quickstarts/llm-d-sc/README.md):
  experimental content-aware CPU/GPU routing, an optional Web UI, and a
  split-host AWS validation scenario without OpenShift or Compose.
- [Private vLLM inference](bootc/VLLM.md): the separate CPU or GPU server used
  by the strongest validated local-model path.
- [Published bootc images](bootc/README.md): available OpenCode and OpenClaw
  variants and their deployment commands.
- [Testing and compatibility](docs/testing/README.md): how to reproduce the
  recorded checks and review the compatibility matrix.
- [MaaS + PriceTag pilot](docs/testing/pricetag.md): the experimental
  single-server metering deployment, with its [AWS runbook](docs/testing/aws-pricetag.md)
  and [performance procedure](docs/testing/pricetag-perf.md).
- [Documentation map](docs/README.md): alternate deployment shapes and
  configuration guides, including [how to preview the docs locally](docs/README.md#preview-the-documentation-locally).
