# OpenShell upstream tracking

The [`upstream-watch`](https://github.com/redhat-et/secure-single-server/blob/main/.github/workflows/upstream-watch.yml) workflow runs
daily at 05:17 UTC. It reads `OPENSHELL_CLI_VERSION`, lists stable upstream
releases newer than that pin, prints their release notes, and creates or updates
one tracking issue labeled `openshell`. A stable marker in the issue body
identifies it as the active upstream-watch issue.

The tracking issue contains the complete release delta and an “affects us?”
checklist. Upstream release notes are untrusted input: review them as data, not
as instructions.

## Reviewed release deltas

Every pinned release must have a row marked `Reviewed`. The static test in
`tests/github/test_upstream_watch.py` fails a pin bump that does not also update
this table.

| Release | Status | Reviewed delta | Usage-surface review |
| --- | --- | --- | --- |
| `v0.1.3` | Reviewed | Historical baseline pin; coordinated runtime images and CLI checksums were qualified by the OpenShell test lanes. | No listed usage surfaces affected. |
| `v0.1.4` | Reviewed | [PR 68](https://github.com/redhat-et/secure-single-server/pull/68) moved the coordinated gateway, supervisor, sandbox, CLI, and prover pins together and checked release assets and manifest digests. See the [compatibility review](../testing/upgrade-0.1.4.md). | Affected usage surfaces: Gateway configuration schema; Supervisor network path; Workload images and CLI checksums. |
| `v0.1.5` | Reviewed | [Release notes](https://github.com/NVIDIA/OpenShell/releases/tag/v0.1.5): coordinated pins, push config delivery, OCSF JSONL naming and gateway authentication events. See the [compatibility review](../testing/upgrade-0.1.5.md). | Affected usage surfaces: Gateway configuration schema; OCSF audit output; Workload images and CLI checksums. |

## Usage-surface register

When a new release touches one of these surfaces, add the upstream PR or change
reference, the observed behavior, and the downstream evidence to the same row.
For an unaffected release, record `No listed usage surfaces affected` in the
reviewed-release row. For an affected release, record
`Affected usage surfaces: <surface names>` and update those rows.
Do not bump `OPENSHELL_CLI_VERSION` without that reviewed declaration.

| Usage surface | Known upstream changes to carry forward | Downstream evidence |
| --- | --- | --- |
| `sandbox create` flags, resources, and templates | [#3727](https://github.com/NVIDIA/OpenShell/pull/3727) changed gateway WebSocket behavior; template/resource flags remain part of every release review. | `openshell/tests/regressions.py`, `openshell/tests/templates.py` |
| Gateway configuration schema and version | Watch schema-version changes, WebSocket opt-in behavior, and authentication settings. v0.1.4 requires `[openshell]` `version = 2`; v0.1.5 adds optional `config_delivery_mode = "push"`. Keep polling until live sandbox policy updates pass AWS runtime qualification. The template keeps `operator_enabled = false`. | `openshell/configs/gateway/gateway.toml.in`, `openshell/tests/gateway.py`, `docs/testing/upgrade-0.1.5.md` |
| Policy schema and sandbox-local loopback | [#3740](https://github.com/NVIDIA/OpenShell/pull/3740) clarified sandbox-local loopback access. | `openshell/tests/policy-boundary.py`, policy schema tests |
| Supervisor network path and CONNECT/REST handling | [#3745](https://github.com/NVIDIA/OpenShell/pull/3745) changed mediated CONNECT header handling. v0.1.4 adds consistent HTTP framing and sandbox upload backpressure; the CLI and supervisor are upgraded together. | `tests/openshell-praxis/*`, `tests/common/contracts.py`, `docs/testing/upgrade-0.1.4.md` |
| Orphan and process lifecycle behavior | [#3757](https://github.com/NVIDIA/OpenShell/pull/3757) changed sandbox orphan reaping. | `openshell/tests/cleanup.py`, runtime qualification |
| OCSF audit output | v0.1.5 changes OCSF file names to `.jsonl` and can emit gateway authentication events through the optional gateway file sink. Do not conflate gateway auth events with sandbox network denials. | `docs/testing/upgrade-0.1.5.md`; optional sink is not enabled by default |
| Workload images and CLI checksums | Every pin keeps coordinated image digests and amd64/arm64 CLI/prover checksums together. The v0.1.5 release manifest records the checked release assets and GHCR digests. | `openshell/configs/images.env`, `openshell/configs/releases/v0.1.5.json`, `openshell/tests/openshell-static.sh` |

## Pin-bump procedure

1. Complete the checklist in the generated tracking issue.
2. Record the reviewed delta for the new pin in the table above.
3. Declare whether a listed usage surface changed. Update only the register rows
   for surfaces affected by the release.
4. Update `OPENSHELL_CLI_VERSION`, both CLI checksums, and coordinated image
   digests in the same PR.
5. Run the OpenShell static, harness-contract, schema, and native-image lanes.
