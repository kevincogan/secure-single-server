# Sandbox workload templates

Harness creation uses OpenShell 0.1.5 workspace templates. The catalogs in
[`configs/templates`](../../configs/templates) select the pinned workload image,
CPU, memory, and nonsecret environment for each harness/profile/backend.
Policy, provider credentials, and policy-advisor approval remain attached to each
sandbox. A template does not grant network or filesystem access.

Existing `create.sh --profile ...`, `--name`, `--config`, `--provider`, and
`--policy-advisor` options continue to work. On bootc, `sss-bootc harness create`
uses the selected harness and inference backend. Cloud mode keeps the existing
standalone behavior unless `--config` explicitly requests Praxis. Local and
remote vLLM modes own the catalog model and Praxis port 8080, matching the
existing bootc behavior even if the caller has cloud model/port variables set. They reject
`--provider` and `--config` overrides.

## Synchronize and inspect

Creation automatically ensures its selected template. To preload the catalog on
a bootc harness host:

```bash
sudo sss-bootc harness template sync
sudo sss-bootc openshell sandbox template list \
  --label-selector managed-by=secure-single-server --output json
sudo sss-bootc openshell sandbox list \
  --selector managed-by=secure-single-server,harness=opencode --output json
```

For a manual installation, run `openshell/scripts/template.sh sync` as the same
service account that owns the gateway, with its `HOME`, `XDG_RUNTIME_DIR`, and
`DBUS_SESSION_BUS_ADDRESS` set as in the
[manual guide](../quickstarts/openshell-single-server/manual.md). Set
`OPENSHELL_BIN` when the CLI is outside `/usr/local/bin`. Template operations
require workspace administrator access.

Both list commands return `next_page_token`. Pass a nonempty token as
`--page-token` until it is empty. Templates use `--label-selector`; sandboxes use
`--selector`. Labels identify the managed harness, profile, and backend; they are
inventory metadata, not an authorization boundary.

Sync has a 120-second deadline (`OPENSHELL_TEMPLATE_TIMEOUT` can override it).
It reads every inventory page, validates effective settings before mutations,
and verifies the gateway's stored workload. Repeating sync reuses identical
settings. An unavailable gateway, malformed listing, or conflicting stored
settings fails the command. Sync never deletes a sandbox or overwrites a template.

## Add a profile

Add a policy file and a catalog entry; no shell profile allowlist needs changing.
For example, add this object to `templates` in `configs/templates/opencode.json`:

```json
{
  "harness": "opencode",
  "profile": "audit",
  "backend": "standalone",
  "image_variable": "ODH_OPENCODE_IMAGE",
  "cpu": "1",
  "memory": "2Gi",
  "environment": {},
  "policy": "openshell/harnesses/opencode/profiles/audit/policy.yaml"
}
```

Then run the existing entry point with `--profile audit`, or
`sudo sss-bootc harness create --profile audit` on the corresponding rebuilt
harness image. Bootc images include only their harness's catalog and policy files.
Adding a new client still requires qualifying its client configuration and tools.

The top-level JSON object has `version: 1` and a `templates` array. Entries are
unique by `(harness, profile, backend)`. Image variables refer to the central
[`images.env`](https://github.com/redhat-et/secure-single-server/blob/main/openshell/configs/images.env) digest pins. Set either `policy`
for a standalone sandbox or `config_dir` for an integrated policy/provider recipe.
Paths are relative to the installed repository root, including when a reviewed
catalog is supplied through `OPENSHELL_TEMPLATE_DIR`; they are not relative to
the catalog file. An optional `model_id` supplies a local recipe's default model. Model and provider
configuration is installed per sandbox after creation; it is not stored in the
workload template. Existing qualified custom `--config` directories remain
supported for OpenCode profiles and OpenClaw `dev`.

`OPENSHELL_SANDBOX_CPU` and `OPENSHELL_SANDBOX_MEMORY` override catalog defaults.
CPU accepts positive cores or millicores (`2`, `0.5`, `500m`). Memory accepts the
pinned CLI's positive integer quantities (`512Mi`, `4Gi`, `8G`, or plain bytes
`1024`); `1024B` is not accepted by OpenShell 0.1.5.

Changing the image, resources, environment, or identifying labels produces a new
content-derived template name (`sss-` plus 15 hex digits, within 0.1.5's
19-character limit). Use labels for the readable harness/profile/backend identity. Existing templates remain available for review;
prune old ones explicitly with `openshell sandbox template delete NAME` after
checking the complete sandbox inventory. Never put keys, tokens, or passwords in
catalogs or template environment. Use the [credential setup](../quickstarts/openshell-single-server/manual.md)
for direct provider bindings or protected Praxis secrets instead.

## Validation

`openshell/tests/templates.py` exercises sync, pagination, conflict rejection,
concurrent creation, resource overrides, catalog-only profiles, and credential
field rejection. `openshell/tests/openshell-static.sh` runs it in normal CI.
The existing harness contract tests verify per-sandbox policy/provider attachment,
labels, client configuration, and absence of inline workload flags when a template
is selected. `openshell/tests/templates-runtime.sh` verifies real gateway sync and readback
twice. The opt-in RHEL runtime suite runs it and exercises actual template-based
OpenCode and OpenClaw creation through the existing entry points.

The verified sandbox deletion helper has a separate seven-minute default
(`OPENSHELL_CLEANUP_TIMEOUT` overrides it). On bootc/Podman, 0.1.5 can retain
`Deleting` metadata after the container is removed until its five-minute orphan
grace and one-minute reconciliation sweep complete. The helper still requires
successful complete listings proving absence; it never treats container removal,
a failed listing, or an expired deadline as success.
