# OpenShell 0.1.5 pin and compatibility review

OpenShell deployment and runtime qualification in this repository require
RHEL 9.8+ x86_64. The full Streamlit scenario was validated on RHEL 9.8 with
Podman 5.8.2; RHEL 9.6 is retained below only as a failed historical test.

This update coordinates the OpenShell gateway, supervisor, sandbox, CLI, and
policy prover at v0.1.5. Release asset checksums and GHCR digests are recorded
in [`openshell/configs/releases/v0.1.5.json`](../../openshell/configs/releases/v0.1.5.json)
and enforced by the static check and workflow.

## Release changes that affect this repository

- **Push configuration delivery:** v0.1.5 can stream policy and configuration
  changes to supported supervisors. Compatible supervisors apply changes in
  about 100 ms, while older supervisors continue polling. This deployment keeps
  the default polling mode until live sandbox updates pass AWS runtime
  qualification.
- **OCSF file naming and gateway events:** OCSF log files use the `.jsonl`
  extension; v0.1.5 does not migrate existing `.log` files. The gateway can
  write its own OCSF records, including rejected-authentication events, to an
  optional `[openshell.gateway.ocsf_log]` file sink. This sink is not enabled
  by default. Gateway authentication failures and sandbox network-policy
  denials are different events; the API-key and document scenarios continue
  to verify their sandbox denial records.
- **Private CA support:** Podman supervisors can trust an operator-provided
  `additional_ca_bundle`, which is also trusted inside the workload. It applies
  to every destination, so it is useful for a controlled private CA but is not
  needed for the public provider endpoints in these scenarios.
- **Environment imports:** `sandbox create --env-from` is available, but it
  places imported values in the workload environment. The demos keep provider
  credentials in the gateway and do not use this option.
- **Other changes:** DNS now fails closed in additional cases, OCSF records
  follow OCSF 1.8 requirements, and rejected dynamic-grant requests have
  bounded recovery. Kubernetes allowlists, snap service changes, VM-driver
  bind mounts, and Docker bridge networking do not apply to this repository's
  rootless Podman deployment.

## Scenario impact

The v0.1.5 release did not require new scenario policies. The full Streamlit
comparison did expose two integration details that needed correction for a
real GPT-5.5 request: Chat Completions uses `max_completion_tokens`, and the
provider profile must name the canonical `/usr/local/bin/python3.12` executable
used by the container. Both provider profiles and the Streamlit contract test
now cover those requirements. The API-key theft, document-exfiltration, and
model-escalation scenarios retain their existing behavior.

## AWS validation

Two disposable AWS RHEL 9 x86_64 `m7i.2xlarge` hosts were used. The RHEL 9.6
run used Podman 5.4.0 and Landlock ABI 5; the RHEL 9.8 run used Podman 5.8.2
and Landlock ABI 6.

On RHEL 9.6, the gateway became healthy, pinned images pulled, policy and
template checks passed, and the complete `openshell/tests/openshell-static.sh`
suite passed. Live sandbox creation timed out during Podman's API archive PUT
that copies the workspace into its named volume. A standalone request to the
same Podman API operation reproduced the hang, while a direct rootless Podman
run of the pinned workload image succeeded. This records a provisioning
failure on that host; it does not establish a confirmed upstream root cause.

On RHEL 9.8, sandbox provisioning and runtime checks passed:

- Two credential-isolation sandboxes reached `Ready`; the synthetic key was
  absent from the workload.
- All seven shipped Praxis REST profiles passed: review, dev, automation,
  interactive, OpenClaw, vLLM OpenCode, and vLLM OpenClaw.
- Gateway template synchronization/readback and controlled allow/deny policy
  checks passed.
- OpenClaw and OpenCode tool-use checks passed with synthetic, credentialless
  model configuration, including route denials and credential isolation.
- The document-exfiltration demo passed using a local REST readiness stub and
  its controlled results and attacker endpoints. The permitted results path
  was reached; sandbox attempts to reach the attacker endpoint were denied,
  and the Git denial appeared in sandbox logs. No external destination was
  contacted.

The complete Streamlit before/after scenario was then run through the browser
on the RHEL 9.8 host using the same GPT-5.5 model and synthetic support ticket
in both modes. In the ordinary container, the model summary and follow-up chat
returned successfully, and the write and file-read diagnostics succeeded. In
the OpenShell sandbox, the summary and follow-up chat also returned
successfully through the attached provider, while both diagnostics were
blocked. The workload displayed only an opaque credential placeholder; the
provider credential remained managed by OpenShell. The provider request and
policy logs confirmed the allowed `POST /v1/chat/completions` path.

The first protected request was denied because the profile named the
`python3` symlink while the kernel reported the process executable as
`python3.12`. Updating the provider profile to the canonical path resolved the
denial. The first model request also revealed that GPT-5.5 rejects the legacy
`max_tokens` parameter; the client now sends `max_completion_tokens`.

The Streamlit contract suite and complete OpenShell static suite passed locally
after these fixes. The live model and filesystem scenario was validated on the
RHEL 9.8 AWS host.

The AWS helper selects the matching RHEL 9 image with the newest AMI creation
date. In this region that selected RHEL 9.6, so the RHEL 9.8 run explicitly
specified the official RHEL 9.8 AMI. Use an explicit AMI when reproducing the
RHEL 9.8 results.

## Upgrade procedure

Follow the [upgrade runbook](../../openshell/docs/upgrade.md): export needed
work, delete old sandboxes, upgrade all pinned components together, recreate
sandboxes, and verify the effective policy and a controlled allow/deny pair.
The `.log` to `.jsonl` change does not migrate or rename existing files; retain
or archive old files according to the site's log-collection policy.
