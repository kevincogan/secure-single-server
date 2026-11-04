# OpenCode: manual configuration and desktop

Use the [dynamic launch](README.md#6-run-opencode) for a fresh catalog on every
start. Expand an option below to save a configuration, configure OpenCode
manually, or use the desktop app with the remote gateway.
First complete [local connection setup](README.md#5-prepare-the-local-connection);
these examples use its workstation shell variables.

<details markdown="1">
<summary>Save native configuration and a launcher — no exports needed on later runs</summary>

Run in the **workstation setup shell** after connection setup. Requires `jq`.
Choose a user key below. This saves all advertised models and a launcher;
only the key's absolute path is written to the config.

```console
KEY_FILE="$CLIENT_DIR/alice.key"  # Choose your user's local key file.
umask 077
chmod 600 "$KEY_FILE"
curl --fail --cacert "$CLIENT_DIR/ca.pem" "$GATEWAY_URL/v1/models" \
  -o "$CLIENT_DIR/models.json"
jq --arg base "$GATEWAY_URL/v1" --arg key "{file:$KEY_FILE}" \
  --arg model "$MODEL" '
  {provider: (reduce .data[] as $m ({};
    reduce $m.praxis.apis[] as $api (. ;
      if ($api == "openai" or $api == "anthropic") then
        ("praxis-" + $api) as $id |
        .[$id] //= {name: $id,
          npm: (if $api == "anthropic" then "@ai-sdk/anthropic" else "@ai-sdk/openai-compatible" end),
          options: {baseURL: $base, apiKey: $key}, models: {}} |
        .[$id].models[$m.id] = {name: $m.id,
          limit: {context: $m.praxis.context, output: $m.praxis.output}} |
        ($m.praxis.upstream_model | ascii_downcase) as $upstream |
        if $api == "openai" and
          (($upstream | test("^(gpt-5|gpt-6|o1|o3|o4)")) or
           ($m.praxis.provider == "vllm" and ($upstream | contains("qwen")))) then
          .[$id].models[$m.id] += {provider: {npm: "@ai-sdk/openai"}, reasoning: true,
            options: {store: false, reasoningEffort: "medium", include: ["reasoning.encrypted_content"]}}
        elif $api == "openai" and ($upstream | contains("qwen")) then
          .[$id].models[$m.id] += {reasoning: true, interleaved: {field: "reasoning"}}
        elif $api == "anthropic" and
          ($upstream | test("^claude-((opus|sonnet)-(4-[678]|5)(-|$)|haiku-5(-|$))")) then
          .[$id].models[$m.id].options = {thinking: {type: "adaptive", blockBinding: false}}
        else . end
      else . end))), disabled_providers: []} |
  .enabled_providers = (.provider | keys) |
  .model = ((first(["praxis-openai", "praxis-anthropic"][] as $id | select(.provider[$id].models[$model]) | $id)
    // error("Selected model is missing")) + "/" + $model)
' "$CLIENT_DIR/models.json" > "$CLIENT_DIR/opencode.json"
python3 -c '
import pathlib, shlex, sys
directory = pathlib.Path(sys.argv[1]).resolve()
launcher = directory / "opencode"
command = ["env", "NODE_EXTRA_CA_CERTS=" + str(directory / "ca.pem"),
           "OPENCODE_CONFIG=" + str(directory / "opencode.json"), "opencode"]
launcher.write_text("#!/bin/sh\nunset OPENCODE_CONFIG_CONTENT\nexec " + shlex.join(command) + " \"$@\"\n")
launcher.chmod(0o700)
print("\nRun this from any project directory, without exporting variables:\n")
print(shlex.quote(str(launcher)))
' "$CLIENT_DIR"
```

Run the printed launcher path from any project directory:

```console
/absolute/path/to/client-directory/opencode
```

It loads the saved config and CA without exports. Regenerate after model changes.
To switch users, regenerate with another `KEY_FILE`; after rotation, replace the
referenced key file and restart OpenCode. Keep keys outside project repositories.

</details>

<details markdown="1">
<summary>Manual config — direct OpenAI and external OpenAI/Messages</summary>

Inspect your generated file with `jq . "$CLIENT_DIR/opencode.json"` in the setup
shell, or save the example below as your private `opencode.json` without using
our helper. Replace the gateway URL and key path. Include only aliases advertised
by your gateway and copy their `praxis.context` / `praxis.output` values from
`/v1/models`; these example limits are not discovery from the upstream provider.

`praxis-openai` groups both direct `openai/` and external `external/` aliases by
API dialect. `praxis-anthropic` handles external Messages aliases. These are
connections to Praxis, not direct connections to the upstream services.

```json
{
  "provider": {
    "praxis-openai": {
      "name": "praxis-openai",
      "npm": "@ai-sdk/openai-compatible",
      "options": {
        "baseURL": "https://gateway.example:8443/v1",
        "apiKey": "{file:/absolute/path/to/alice.key}"
      },
      "models": {
        "openai/gpt-5.4-mini": {
          "name": "openai/gpt-5.4-mini",
          "limit": {"context": 400000, "output": 128000},
          "provider": {"npm": "@ai-sdk/openai"},
          "reasoning": true,
          "options": {
            "store": false,
            "reasoningEffort": "medium",
            "include": ["reasoning.encrypted_content"]
          }
        },
        "external/gpt-5.4-mini": {
          "name": "external/gpt-5.4-mini",
          "limit": {"context": 400000, "output": 128000},
          "provider": {"npm": "@ai-sdk/openai"},
          "reasoning": true,
          "options": {
            "store": false,
            "reasoningEffort": "medium",
            "include": ["reasoning.encrypted_content"]
          }
        }
      }
    },
    "praxis-anthropic": {
      "name": "praxis-anthropic",
      "npm": "@ai-sdk/anthropic",
      "options": {
        "baseURL": "https://gateway.example:8443/v1",
        "apiKey": "{file:/absolute/path/to/alice.key}"
      },
      "models": {
        "external/claude-sonnet-5-5": {
          "name": "external/claude-sonnet-5-5",
          "limit": {"context": 1000000, "output": 128000},
          "options": {"thinking": {"type": "adaptive", "blockBinding": false}}
        }
      }
    }
  },
  "disabled_providers": [],
  "enabled_providers": ["praxis-anthropic", "praxis-openai"],
  "model": "praxis-openai/openai/gpt-5.4-mini"
}
```

Save this file outside your project repository and protect it and the key with
`chmod 600`. To run directly from a project shell:

```console
NODE_EXTRA_CA_CERTS=/absolute/path/to/ca.pem \
OPENCODE_CONFIG=/absolute/path/to/opencode.json opencode
```

Both providers reference the same private user-key file. GPT uses the Responses
SDK; Messages uses the Anthropic SDK. The launcher supplies the CA separately.

</details>

<details markdown="1">
<summary>Use the standard config directory and run just opencode</summary>

First generate the config using the **Save native configuration** block above.
Then run in the **workstation setup shell**. If a global JSON/JSONC config exists,
merge the generated settings into it instead; this block refuses to overwrite it.

```console
(
  set -e
  CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/opencode"
  mkdir -p "$CONFIG_DIR"
  if [ -e "$CONFIG_DIR/opencode.json" ] || [ -e "$CONFIG_DIR/opencode.jsonc" ]; then
    printf 'Existing OpenCode config: merge the generated settings instead.\n'
    exit 1
  fi
  cp "$CLIENT_DIR/opencode.json" "$CONFIG_DIR/opencode.json"
  chmod 600 "$CONFIG_DIR/opencode.json"
)
```

For the default private certificate, configure its CA once (**zsh on macOS**):

```console
printf '\nexport NODE_EXTRA_CA_CERTS=%q\n' "$CLIENT_DIR/ca.pem" >> "$HOME/.zshrc"
export NODE_EXTRA_CA_CERTS="$CLIENT_DIR/ca.pem"
unset OPENCODE_CONFIG OPENCODE_CONFIG_CONTENT
```

For Bash, use `~/.bashrc`. Preserve any existing CA bundle you need. Skip this
CA setting for a publicly trusted certificate; never disable TLS verification.

Then, in this shell or a newly opened project shell:

```console
cd /path/to/your/project
opencode
```

To switch users, change `options.apiKey` in both Praxis providers to the other
user's `{file:/absolute/path/to/key}`, then restart. Refresh the global config
when models change. Project settings can override global settings.

[Config locations and precedence](https://opencode.ai/docs/config/#precedence-order) ·
[Custom certificates](https://opencode.ai/docs/network/#custom-certificates)

</details>

<details markdown="1">
<summary>External Claude rejects thinking.adaptive.block_binding</summary>

OpenCode may inject a thinking extension that an Anthropic-compatible gateway
rejects. The helper sets this compatibility option for recognized adaptive-thinking
Claude models, using upstream model metadata rather than the public alias:

```json
"options": {
  "thinking": { "type": "adaptive", "blockBinding": false }
}
```

This retains adaptive thinking and omits the unsupported binding field. It does
not change authentication, routing or model limits. Verified with OpenCode 1.19.5;
[upstream opt-out](https://github.com/anomalyco/opencode/pull/46820).
Restart the helper for a session config, or regenerate a saved native config
before restarting OpenCode. This is a workstation change; no gateway rebuild is
needed. OpenCode 2 requires separate qualification because its compatibility
configuration differs ([tracked issue](https://github.com/anomalyco/opencode/issues/52325)).

</details>

## OpenCode Desktop

Desktop manages its own background process. **No separate CLI server or running
terminal is needed.** It sends inference to the remote gateway over HTTPS.

Use the global configuration file:

| Platform | Default config path |
| --- | --- |
| macOS / Linux | `~/.config/opencode/opencode.json` |
| Windows | `%USERPROFILE%\.config\opencode\opencode.json` |

If `XDG_CONFIG_HOME` is set, use its `opencode` directory instead.

1. Save or merge the provider configuration from **Save native configuration** or
   **Manual config** above. Preserve existing JSON/JSONC settings and keep each
   provider's `apiKey` as a reference to your private user-key file.
2. Configure the gateway CA **once**, using your platform's instructions below.
   This setting applies to the backend process, not to an individual provider.
   Skip it for a publicly trusted gateway certificate.
3. Fully quit Desktop and reopen it normally from Applications, Start or your
   application menu. Keep the default **local/built-in server**, open a project,
   select a `praxis-openai` or `praxis-anthropic` model and send a short request.
   Check that request in PriceTag.

On Windows, forward slashes avoid JSON escaping in the key reference, for example
`{file:C:/Users/YOUR_USER/.config/praxis-pricetag/alice.key}`.

The gateway URL belongs in provider `baseURL`, **not** the Desktop server picker.
Remove any previous custom `http://127.0.0.1:4096` selection. Keep your CA and key
files at their configured paths; no private CA key is needed.

<details markdown="1">
<summary>macOS — one-time CA setup, then launch from Applications or the Dock</summary>

For the default **zsh** shell, add this line to `~/.zshrc` (or
`$ZDOTDIR/.zshrc` if you configured `ZDOTDIR`), using your CA's absolute path:

```sh
export NODE_EXTRA_CA_CERTS="/absolute/path/to/ca.pem"
```

Alternatively, append it from the quickstart's **workstation setup shell**:

```console
printf '\nexport NODE_EXTRA_CA_CERTS=%q\n' "$CLIENT_DIR/ca.pem" >> "${ZDOTDIR:-$HOME}/.zshrc"
```

Add it only once; edit the existing line when changing the CA. If Bash is your
login shell, use `~/.bash_profile` instead. Fully quit Desktop, then reopen it
from Applications or the Dock. Desktop loads the login-shell environment when
starting its backend; you do not need to launch it from Terminal.

</details>

<details markdown="1">
<summary>Windows — one-time user environment variable, then launch from Start</summary>

Open **Edit environment variables for your account** from Start. Under **User
variables**, create or edit:

- **Name:** `NODE_EXTRA_CA_CERTS`
- **Value:** the full path to your CA PEM file, such as
  `C:\Users\YOUR_USER\.config\praxis-pricetag\ca.pem` (without surrounding quotes).

Or run this once in **PowerShell**, replacing the path:

```powershell
$ca = (Resolve-Path -LiteralPath 'C:\Users\YOUR_USER\.config\praxis-pricetag\ca.pem' -ErrorAction Stop).Path
[Environment]::SetEnvironmentVariable('NODE_EXTRA_CA_CERTS', $ca, 'User')
```

Fully quit Desktop and reopen it from Start. If it still has the old environment,
sign out of Windows and sign back in. No administrator rights, open PowerShell
window or WSL configuration are required for the native Windows app. Keep the
user-key file in your private Windows profile.

</details>

<details markdown="1">
<summary>Linux — one-time shell setup, then launch from the application menu</summary>

For a native Desktop installation, add this line to your shell's startup file,
using the absolute path to your CA:

```sh
export NODE_EXTRA_CA_CERTS="/absolute/path/to/ca.pem"
```

- **Bash:** `~/.bashrc`.
- **Zsh:** `~/.zshrc` (or `$ZDOTDIR/.zshrc`).
- **Fish:** run `set -Ux NODE_EXTRA_CA_CERTS /absolute/path/to/ca.pem` once.

Edit an existing setting instead of adding conflicting entries. Fully quit
Desktop, then reopen it from the application menu. Desktop reads the shell
environment for its backend; no terminal needs to remain open. Sandboxed packages
also need access to the config, CA and key files inside their sandbox.

</details>

These steps are based on **OpenCode Desktop 1.19.5** startup code and platform
environment-variable documentation. Desktop GUI smoke tests on each platform
remain pending. The provider examples use OpenCode 1.x syntax. OpenCode 2
[normalizes supported V1 settings](https://opencode.ai/v2/docs/migrate-v1/),
including provider definitions and the provider allowlist; Desktop 2 end-to-end
inference qualification remains pending.

<details markdown="1">
<summary>Switch users, refresh models or troubleshoot certificates</summary>

- **Switch user:** change both providers' `options.apiKey` to the other user's
  `{file:/absolute/path/to/user.key}` and fully restart Desktop. Keep key files
  private (`chmod 600` on macOS/Linux); never paste the key into the configuration.
- **Refresh models:** regenerate the saved config, merge it into the global config
  and restart Desktop. Project config can override global settings.
- **CA changes:** update the platform setting above and restart. The file must be
  readable PEM. If other services require additional private CAs, use one PEM
  bundle containing all required certificates.
- **Certificate error:** check the CA path and gateway hostname. On macOS/Linux,
  Desktop's shell probe has a five-second timeout; a slow or failing shell startup
  can prevent loading the setting. Review Desktop logs. Never disable TLS checks.

</details>

[OpenCode custom CA documentation](https://opencode.ai/docs/network/#custom-certificates) ·
[Desktop server selection](https://opencode.ai/docs/troubleshooting/#fix-server-connection-issues) ·
[Desktop 1.19.5 environment loading](https://github.com/anomalyco/opencode/blob/v1.19.5/packages/desktop/src/main/server.ts) ·
[Desktop 1.19.5 shell probe](https://github.com/anomalyco/opencode/blob/v1.19.5/packages/desktop/src/main/shell-env.ts) ·
[Windows user environment variables](https://learn.microsoft.com/en-us/dotnet/api/system.environment.setenvironmentvariable?view=netcore-3.0)
