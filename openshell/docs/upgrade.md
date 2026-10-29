# OpenShell upgrade runbook

Use this procedure when changing the pinned OpenShell release, including a
bootc OS switch or rollback that changes OpenShell. Upstream's [0.1 migration
guide](https://github.com/NVIDIA/OpenShell/blob/v0.1.5/docs/upgrade/0-1-0.mdx)
requires coordinated component upgrades and recreation of 0.0.x sandboxes.
This repository applies the recreation rule to every OpenShell upgrade.

**Delete and recreate every pre-upgrade sandbox so no old supervisor, DNS
entry, trust material or cached route survives.** Stop/start alone does not
satisfy this rule. OS rollback does not restore application data or make a
migrated database compatible with an older release.

1. Schedule downtime and stop new sandbox creation. Inventory sandboxes in
   every workspace, including stopped sandboxes, and record their image,
   policy, resource settings and explicit provider attachments. Export needed
   work and verify the export before deletion; recreation does not promise
   workspace retention.
2. As the gateway's service owner, delete each sandbox with
   `openshell sandbox delete NAME` in its workspace. Inspect `sandbox list`
   until each disappears: acceptance of deletion is not completed cleanup.
   Resolve failed cleanup before proceeding.
3. Stop the gateway and back up its persistent database, configuration and
   credential encryption material. Review the target release's migration
   notes. Upgrade the gateway, supervisor, CLI and any drivers, middleware or
   SDK clients together; do not run incompatible peers against the same state.
   On bootc, rebuild with coordinated pins and follow the [OS update
   procedure](../../bootc/README.md); do not use mutable-host installers there.
4. Start the upgraded gateway and review its health and logs. The 0.1 series
   removes stored managed inference routes; they cannot be automatically
   translated into per-sandbox grants. Import reviewed profiles for preserved
   providers before creating sandboxes, then explicitly attach only intended
   providers. Follow the [upstream inference migration](https://github.com/NVIDIA/OpenShell/blob/v0.1.5/docs/how-it-works/inference.mdx#migrate-from-managed-inference-routes).
   The current Praxis paths continue using their dedicated endpoint policies
   and harness provider configuration; do not add direct cloud-provider access.
5. Recreate sandboxes from the new pinned deployment and restore only exported
   user work, not old supervisor state or trust material. Verify effective
   policy, intended endpoint access, bypass denial and a real harness/tool task
   before reopening access. Use the [integration matrix](../../docs/quickstarts/openshell-praxis/users.md)
   and, for local vLLM, the [inference checks](../../bootc/VLLM.md).

For rollback, repeat export, deletion and recreation against the rollback
release. Restore a compatible database backup when its migration requires it;
reverting the OS alone is insufficient.

The v0.1.5 deployment uses pinned upstream gateway, supervisor, and sandbox
images. The CLI comes from an architecture-matched release archive verified
against the committed SHA-256 before installation or copying into bootc.
OpenClaw uses the upstream v2026.9.9 image. Its application directory `/app`
is read-only; agent files live in `/home/node/.openclaw/workspace`. Follow the
[0.1.5 pin review](../../docs/testing/upgrade-0.1.5.md) before promotion.

Repository test cleanup uses `destroy-sandbox.py` to confirm absence through
successful paginated listings. Failed deletion, failed listing, malformed output
and incomplete cleanup fail the check; an already-absent sandbox is safe to
remove again. The deadline defaults to 420 seconds (seven minutes) to allow the pinned
gateway’s orphan grace and reconciliation interval, and can be changed with
`OPENSHELL_CLEANUP_TIMEOUT` when a disposable test needs more time.
