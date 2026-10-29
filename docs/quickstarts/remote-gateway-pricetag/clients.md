# Saved OpenCode configuration

Optional alternatives to the [dynamic launch](README.md#6-run-opencode).
First complete [local connection setup](README.md#5-prepare-the-local-connection);
these examples use its workstation shell variables.

<details>
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

<details>
<summary>Resulting OpenCode config — two-model example</summary>

Inspect your generated file with `jq . "$CLIENT_DIR/opencode.json"` in the setup
shell. It uses your URL, key path and model limits; for example:

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

Both providers reference the same private user-key file. GPT uses the Responses
SDK; Messages uses the Anthropic SDK. The launcher supplies the CA separately.

</details>

<details>
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

<details>
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
