# Model endpoint configuration

Both [manual deployment](manual.md#4-choose-model-access) and
[bootc deployment](bootc.md#configure-model-access) show how to register your
OpenAI key and attach a provider. Base URL and model selection are separate
from the credential; the following examples use OpenCode.

## Local OpenAI-compatible service

On the host, create this non-secret profile. Replace the host and port with the
endpoint you administer. This example assumes HTTPS on port 443:

```bash
cat > /var/tmp/local-model.yaml <<'YAML'
id: local-model
display_name: Private OpenAI-compatible inference
category: inference
credentials:
  - name: api_key
    env_vars: [OPENAI_API_KEY]
    required: true
    auth_style: bearer
    header_name: authorization
endpoints:
  - {host: inference.internal, port: 443, protocol: rest, access: read-write, enforcement: enforce}
binaries: [/usr/local/bin/opencode, /usr/bin/node-26]
YAML
```

Use the import and hidden-prompt commands in your deployment guide with this
file, `--type local-model`, and provider name `local-key`. Enter your inference
server's real API key at that prompt. Then create `opencode-local` with
`--provider local-key`. The profile's `id` must match `provider create --type`.
Review the effective policy and actual caller binary when qualifying a host.

For a service on the OpenShell host, substitute `host.openshell.internal` and
its listening port in the profile and client URL. For another machine, use a
reachable private hostname or IP. Sandbox `127.0.0.1` refers to the sandbox.
If the server uses private HTTP, use its `http://` URL and actual port; HTTP
provides no transport encryption for the bearer key.

### Configure OpenCode

Inside the new sandbox, save this as `~/.config/opencode/opencode.json` before
restarting OpenCode. Replace `SERVED_MODEL_ID` in both places and the base URL.
The config refers to the attached credential placeholder, not the real key:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "provider": {
    "local": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "Private inference",
      "options": {
        "baseURL": "https://inference.internal/v1",
        "apiKey": "{env:OPENAI_API_KEY}"
      },
      "models": {
        "SERVED_MODEL_ID": {"name": "Private model"}
      }
    }
  },
  "model": "local/SERVED_MODEL_ID"
}
```

The client SDK must be present in the pinned image, and the endpoint must
support the API and tool calls required by the harness. A model listing alone
does not prove that support. Run the [harness checks](verification.md).

### Service without API-key authentication

Replace the profile's entire `credentials` block with `credentials: []` before
importing. Create `local-key` with `--type local-model` and omit `--credential`;
there is no hidden key prompt. Keep the endpoint and binary restrictions.
In OpenCode's config, set `"apiKey": "unused"` instead of the environment lookup.
That value only satisfies the client SDK; it is not a secret or an authentication
mechanism. The project's private [vLLM setup](../common/vllm.md) follows this
credentialless upstream pattern through Praxis.

## Sources and qualification

The pinned [OpenShell provider contract](https://github.com/NVIDIA/OpenShell/blob/v0.1.5/docs/how-it-works/inference.mdx)
defines profile-bound credential substitution and custom endpoints. OpenCode's
[provider configuration](https://opencode.ai/docs/providers/#custom-provider) and
[environment substitution](https://opencode.ai/docs/config/#env-vars) define
client configuration. These examples describe setup; real inference and tool
execution must be qualified on the deployed host. For OpenClaw, use the [bounded Praxis workflow](../openshell-praxis/openclaw.md)
and review its recorded test evidence.
