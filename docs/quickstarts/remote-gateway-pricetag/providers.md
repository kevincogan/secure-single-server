# Providers and models

Provider keys stay on RHEL; clients use their own MaaS user keys.

| Profile | Upstream API | Client-visible model name |
| --- | --- | --- |
| `openai` | OpenAI directly | `openai/MODEL_ID` |
| `external` | OpenAI-compatible Chat/Responses, Anthropic Messages, or both | `external/MODEL_ID` |

An external provider is a hosted service or another gateway. Both APIs can share
an endpoint or use separate endpoints, but must accept the same key. GPT models
using Responses need `/v1/responses`, not just Chat compatibility.

The installer supports these two fixed profiles. Choose them during installation;
the helper cannot add arbitrary profile names. Older `pricetag/` deployments use
the legacy `pricetag` command.

Provider and model routing is configured through the host CLI below. User,
budget, key and pricing management is available in the browser.

## Update the external provider’s models

The numbered steps below update an installed external provider. For a fresh
installation, use the [installer](README.md#3-install) or
[manual provider setup](manual.md#2-configure-providers) instead.

### Open the management session

From the **workstation installation shell**:

```console
ssh -t "${SSH_OPTS[@]}" "$RHEL_HOST" \
  'cd ~/secure-single-server && exec bash'
```

Run the following steps **on RHEL**. New workstation shell? Restore the
[connection variables](README.md#1-set-the-connection) first.

## 1. Inspect configured and available models

List the saved profiles, model aliases and limits without revealing credentials:

```console
sudo python3 scripts/pricetag/providers list
```

Discover model IDs from the external service (enter its credentials again):

```console
sudo python3 scripts/pricetag/providers external --api both --list-models
```

Enter the endpoint(s) and key at the hidden prompt. The helper prints advertised
IDs grouped by API and the preset-file path. It saves nothing and does not
provide limits, prices or generated JSON. Listing does not verify inference access.

<details markdown="1">
<summary>Search, pagination and direct OpenAI</summary>

```console
sudo python3 scripts/pricetag/providers external --api both --list-models --search claude
sudo python3 scripts/pricetag/providers openai --list-models --search gpt --all
```

Use `--api openai` or `--api anthropic` for a single external API. By default,
Enter advances through 20-model pages; `q` stops. Use `--page 2 --page-size 20`
for one page or `--all` for every match. Search is a case-insensitive ID substring.
Filtering is local after fetching the catalog; it is not an upstream search query.

</details>

## 2. Edit the model selection and limits

```console
cd ~/secure-single-server
cp -p configs/pricetag/provider-models.json configs/pricetag/provider-models.json.bak
vi configs/pricetag/provider-models.json
python3 -m json.tool configs/pricetag/provider-models.json >/dev/null
```

The file is `~/secure-single-server/configs/pricetag/provider-models.json`.
Keep the desired rows under each **API**, using upstream IDs without gateway
prefixes. Each row is `["MODEL_ID", context_tokens, max_output_tokens]`:

```json
{
  "openai": [
    ["gpt-6-luna", 1050000, 128000]
  ],
  "anthropic": [
    ["claude-sonnet-5-5", 1000000, 128000]
  ]
}
```

Add/remove rows manually; retain other models you need. The `openai` array is
shared by direct OpenAI and external OpenAI-compatible setup. JSON validation
checks syntax only. Limits are administrator-selected presets; explicit lower
`praxis` limits advertised by a gateway cap them during setup.

Use your hosted provider's documented limits when they differ from the original
model's limits. References: [OpenAI models](https://developers.openai.com/api/docs/models),
[Anthropic models](https://platform.claude.com/docs/en/models/overview),
[DeepSeek models](https://api-docs.deepseek.com/quick_start/pricing/),
[GLM documentation](https://docs.z.ai/guides/llm/glm-5.3).

## 3. Check pricing in PriceTag

PriceTag ships a bundled price catalog and built-in hosted-model prices. At
startup it tries current LiteLLM prices, falls back to its bundled catalog,
and seeds PostgreSQL. **Prices do not come from `/models` or the preset JSON.**
Check the administrator dashboard's pricing view before enabling new models;
public catalog prices may differ from your upstream contract. Some built-in
hosted-model entries are intentionally $0: a present price row does not mean
usage will consume a USD budget. Decide whether free access is intended before
enabling those models.
[PriceTag price loading](https://github.com/redhat-et/pricetag-metering/blob/6d9c1c6e1fc6f8b38f15cc17783dc4758237aa1f/internal/pricing/pricing.go).

Zero-price models do not add USD spend. They still count toward the configured
10-billion-token monthly per-user safety quota. The public listener also has a
shared 30-request/second limit with burst 120; this is not a per-user or concurrent
stream limit. Upstream rate/capacity limits apply separately. With the default
empty post-budget exception list, exhausting the USD budget on paid models also
blocks free models.

| Data | Authoritative location |
| --- | --- |
| Selected models and configured limits | `~/secure-single-server/configs/pricetag/provider-models.json` |
| Active USD rates | PostgreSQL `metering.model_pricing` |
| Generated alias-to-price-source mapping | `/etc/praxis-pricetag/price-sources.json` |

`configs/pricetag/price-seeds.json` is not consumed by this installation path;
editing it does not change active prices. Usage is priced by the exact upstream model ID recorded by PriceTag. Existing custom
rates are preserved; imported rates follow PriceTag refresh and discount policy. Missing rates use the configured PriceTag fallback until
an administrator adds explicit rates; publishing an alias does not add a price.

The gateway `/v1/models` lists configured models. The usage dashboard lists
models with recorded usage in the selected scope and period. Pricing can contain
both an upstream ID and its gateway alias; these are separate rate records,
not duplicate charges.

Use the [pricing UI and APIs](pricing.md) to inspect rates and manage source-catalog
discounts. Add missing rates through **Administration → Model pricing**. Price the
upstream ID recorded in usage; catalog refresh does not synchronize copied aliases.

## 4. Apply the external models to Praxis

```console
sudo python3 scripts/pricetag/providers external --api both --replace --refresh-models
sudo python3 scripts/pricetag/providers list
```

Enter the intended endpoint(s) and key again. Use the same single-API choice as
setup if only one API is supported. The command:

- Selects presets advertised by the upstream, plus explicit pins.
- Updates `/etc/praxis-pricetag/gateway/gateway.json`: model catalog, access
  rules, routing entries and request model rewrites.
- Updates `/etc/praxis-pricetag/models.json`, price-source mappings and saved inputs.
- Preserves existing upstream rates, restarts Praxis and checks readiness.
  Failed activation attempts rollback; existing users, usage and prices remain.

Models removed from selection stop being routed; their historical usage stays.
Do not edit generated gateway files or rerun `prepare.py` for this operation.

<details markdown="1">
<summary>How model aliases and routing work</summary>

For a preset `gpt-6-luna`, the external profile exposes `external/gpt-6-luna`.
Praxis routes that alias to the external OpenAI endpoint and rewrites the request's
`model` to `gpt-6-luna`. The catalog exposes the alias and configured limits;
PriceTag records and prices usage under the rewritten upstream model ID.

The aliases select different connections, but the shared upstream model ID has
one PriceTag price record; aliases alone cannot assign separate supplier rates. The underlying gateway renderer supports
separate `id` (alias) and `model` (upstream ID) fields, but this helper generates
`PROFILE/MODEL_ID` automatically. Arbitrary names such as `fast-coder` require
additional configuration support; the three-field preset format cannot set them.

</details>

<details markdown="1">
<summary>Models omitted from discovery and direct OpenAI limits</summary>

A provider may serve a model without advertising it. For a verified preset:

```console
sudo python3 scripts/pricetag/providers external --api both --replace --refresh-models \
  --pin-model anthropic:MODEL_ID
```

A pin does not verify entitlement. Use `--check-inference anthropic:MODEL_ID`
instead of replacement options for a diagnostic request of up to 16 output
tokens; it may incur charges.

Direct OpenAI live model refresh is not implemented: configure its presets
before installation. `openai --replace` retains the current model selection.

</details>

## 5. Refresh local OpenCode

Return to your **workstation** with `exit`. Restart the
[dynamic helper](README.md#6-run-opencode) to fetch the new catalog, or regenerate
saved configuration. If the default model was removed, choose another alias.
Keep the intended user-key path; upstream changes do not require new user keys.

## Replace credentials without changing models

On **RHEL**, run only the relevant command. Both use hidden credential prompts:

```console
sudo python3 scripts/pricetag/providers openai --replace
sudo python3 scripts/pricetag/providers external --api both --replace
```

Omitting `--refresh-models` preserves model selection, budgets and usage.

<details markdown="1">
<summary>Endpoint and discovery options</summary>

HTTPS and `/v1` normalization are automatic. Enter API origins, not request paths.
For separate endpoints:

```console
sudo python3 scripts/pricetag/providers external --api both --replace \
  --anthropic-url MESSAGES_HOST --openai-url OPENAI_COMPATIBLE_HOST
```

For diagnostics, use `--check-auth --debug` without replacement options.
`--catalog-auth` controls discovery headers; `--messages-auth` controls the
Messages credential header. Authentication/TLS failures stop setup.
`--allow-unverified-models` allows presets after discovery HTTP 404/405/501 only;
it does not verify credentials or model access.

</details>

<details markdown="1">
<summary>Unattended credentials</summary>

For automation, provision one-line credentials in root-owned regular files,
mode `0400` or `0600`, inside a root-owned `0700` directory. Pass paths, never
values. The helper imports keys into Podman through stdin.

```console
sudo scripts/pricetag/install --hostname GATEWAY_IP_OR_DNS \
  --provider openai --provider external --external-api both \
  --openai-key-file /root/provider-keys/openai.key \
  --external-key-file /root/provider-keys/external.key \
  --external-messages-url MESSAGES_HOST --external-openai-url OPENAI_COMPATIBLE_HOST \
  --no-sample-users --monthly-usd 5 --yes
```

Use the same hostname for both external options if appropriate. Remove unused
provider options for a single-provider install. Provider commands also accept
`--key-file /root/provider-keys/NAME.key`. Staged files are not automatically
deleted; remove them through your secret-delivery process after verification.

</details>

Provider configuration uses the host helper above. The [management API client](management-api.md)
handles identities, budgets, keys and prices, not provider credentials or routing.
