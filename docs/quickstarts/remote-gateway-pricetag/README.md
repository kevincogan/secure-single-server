# Remote gateway with PriceTag

Run Praxis, MaaS, PriceTag and PostgreSQL on one RHEL host. Connect local
OpenCode with a user key and a monthly USD budget.

**Needs:** a fresh RHEL 9.6 x86_64 host with sudo, outbound HTTPS, and inbound
SSH/8443 from your IP; Git, Python 3 and OpenCode on your workstation.
The tested VM has 8 vCPUs, 32 GiB RAM and 150 GiB disk. No GPU is needed.

> The installer uses digest-pinned published MaaS and PriceTag demo images.
> [Source builds](images.md) remain available for testing another branch or commit.
> The optional provider editor is not included.

## 1. Set the connection

Run from your checked-out `secure-single-server` repository on your workstation:

```console
RHEL_HOST=ec2-user@YOUR_SERVER_IP
SSH_KEY="$HOME/.ssh/YOUR_KEY"
GATEWAY_HOST="${RHEL_HOST#*@}"
REPO="$PWD"
SSH_OPTS=(-o IdentitiesOnly=yes -o ForwardAgent=no -i "$SSH_KEY")
```

<details>
<summary>Need a test VM? Create one with the AWS helper</summary>

Follow the [AWS test-VM example](../../testing/aws-pricetag.md), then continue
below in the same shell. It sets `RHEL_HOST` and `SSH_KEY` for you; the final
block derives `GATEWAY_HOST` and `REPO`. Skip the connection block above.

</details>

## 2. Copy the checkout

Copy the checked-out **commit** from your workstation. This does not install services:

```console
SSH_OPTS=(-o IdentitiesOnly=yes -o ForwardAgent=no -i "$SSH_KEY")
(
  set -o pipefail
  git -C "$REPO" archive HEAD | ssh "${SSH_OPTS[@]}" "$RHEL_HOST" \
    'mkdir -p ~/secure-single-server && tar -xf - -C ~/secure-single-server'
)
```

For [manual installation](manual.md) or [mock benchmarks](../../testing/pricetag-perf.md),
stop here and follow that guide.
Otherwise continue below.

## 3. Install

In the same workstation shell:

```console
ssh -t "${SSH_OPTS[@]}" "$RHEL_HOST" \
  "cd ~/secure-single-server && sudo scripts/pricetag/install --hostname '$GATEWAY_HOST'"
```

Choose providers, enter their keys at hidden prompts, then confirm with `install`.

- **Providers:** OpenAI, an external OpenAI-compatible/Messages service, or both.
- **Users:** admin is required; Alice/Bob are optional. Choose **Admin only** to
  [create your own user](users.md#create-a-user) afterward.
- **Defaults:** real providers, published images, $5/month per ordinary user.

<details>
<summary>Installer options and logs</summary>

| Option | Purpose |
| --- | --- |
| `--no-sample-users` | Create admin only; onboard users in Administration → Users. |
| `--monthly-usd 10` | Set the default per-user monthly allowance. |
| `--image-mode source` | Build application images; see [image options](images.md). |
| `--mode mock` | Use synthetic providers for [benchmarks](../../testing/pricetag-perf.md). |

External setup accepts one or both APIs; one key must cover the selected APIs.
Credentials and model presets are checked before installation. Prices are loaded
at service startup. Missing prices use [PriceTag fallback rates](pricing.md#missing-price-fallback)
and do not block installation. Review rates before using real providers.
For a DNS certificate, set `GATEWAY_HOST` to that name before running the installer.
Existing deployments are refused.

The installer prints progress and a private log path under `/var/log/`, plus a
`sudo tail -f` command. On failure, inspect that log before retrying; do not share
it without reviewing its contents.

[Manual installation](manual.md) · [Unattended provider setup](providers.md)

</details>

## 4. Open the dashboards

In the installation shell on macOS, print the login URL and copy the admin key to the clipboard without displaying it:

```console
printf 'https://%s:8443/login\n' "$GATEWAY_HOST"
ssh "${SSH_OPTS[@]}" "$RHEL_HOST" \
  'sudo cat /root/pricetag-admin/admin.key' | pbcopy
```

Open the URL, accept the deployment certificate and paste the admin key.
Clear the clipboard after login with `pbcopy < /dev/null`. Clipboard managers may retain copied keys.
Open **Administration** at `/admin`: **Users** handles onboarding and managers;
**Safety Net** handles budgets. **My keys** at `/management` handles personal keys.
Follow the [UI demo walkthrough](demo.md) for the
onboarding, personal/team views, read-only impersonation, budgets, pricing and
key replacement/offboarding.

## 5. Prepare the local connection

In the **workstation installation shell**, choose your user on the first line.
For installer/CLI-created users, this copies the CA/key and prints a launch command
for any project shell. Browser-issued keys are shown once: save yours privately to
`$CLIENT_DIR/$INFERENCE_USER.key` instead of the key-copy SSH command below.

```console
INFERENCE_USER=alice  # Change to a user you created; do not use admin.
cd "$REPO"
CLIENT_DIR="$HOME/.config/praxis-pricetag/$GATEWAY_HOST"
umask 077
mkdir -p "$CLIENT_DIR"
chmod 700 "$CLIENT_DIR"
ssh "${SSH_OPTS[@]}" "$RHEL_HOST" 'sudo cat /etc/praxis-pricetag/ca.pem' > "$CLIENT_DIR/ca.pem"
KEY_FILE="$CLIENT_DIR/$INFERENCE_USER.key"
ssh "${SSH_OPTS[@]}" "$RHEL_HOST" "sudo cat /root/pricetag-admin/$INFERENCE_USER.key" > "$KEY_FILE"
chmod 600 "$CLIENT_DIR/ca.pem" "$KEY_FILE"
GATEWAY_URL="https://$GATEWAY_HOST:8443"
curl --fail --silent --show-error --cacert "$CLIENT_DIR/ca.pem" "$GATEWAY_URL/v1/models" \
  -o "$CLIENT_DIR/models.json"
MODEL=$(python3 -c 'import json,sys; rows=json.load(open(sys.argv[1]))["data"]; assert rows, "Gateway has no models"; print(rows[0]["id"])' "$CLIENT_DIR/models.json")
printf 'Initial model: %s\n' "$MODEL"
printf '\nCopy into any workstation shell opened in your project directory:\n\n'
printf 'export REPO=%q\nexport CLIENT_DIR=%q\nexport GATEWAY_URL=%q\nexport MODEL=%q\nexport KEY_FILE=%q\n' \
  "$REPO" "$CLIENT_DIR" "$GATEWAY_URL" "$MODEL" "$KEY_FILE"
printf '%s\n' \
  'python3 "$REPO/scripts/pricetag/harness" opencode \' \
  '  --url "$GATEWAY_URL" --key-file "$KEY_FILE" \' \
  '  --ca-file "$CLIENT_DIR/ca.pem" --model "$MODEL"'
```

The first model is selected automatically; all models remain in the picker.
The printed command contains file paths, never key contents.

## 6. Run OpenCode

In a **project shell**, paste the printed block. Each launch refreshes the catalog;
the helper passes gateway settings for that process without writing a config file.
OpenCode merges these with existing settings. Sessions for one user share their budget.

Send: **“Reply with just: gateway works.”** In the admin dashboard, select Alice
(or your chosen user) and confirm the request, model alias and recorded spend.
Accounting may take a few seconds; free models record zero USD. The default
allowance is per user. With the management candidate, view and change overrides
in **Administration → Safety Net**; the [user helper](users.md) uses the same service API.
The pinned published demo image includes these controls. Older images may not.
For budget-denial testing, use the separate [mock quota probe](../../testing/pricetag-perf.md#usd-quota-probe).

[Save a native config or switch to the standard OpenCode config directory](clients.md).

<details>
<summary>Switch users</summary>

Copy the other user's key with step 5, then launch with its path:

```console
KEY_FILE="$CLIENT_DIR/carol.key"  # Or the absolute path to another private user key.
python3 "$REPO/scripts/pricetag/harness" opencode --url "$GATEWAY_URL" \
  --key-file "$KEY_FILE" --ca-file "$CLIENT_DIR/ca.pem" --model "$MODEL"
```

</details>

## Operations

With the **management candidate**, use Administration for users, team
relationships, budgets, onboarding keys and prices; use My keys for personal keys. Provider/model configuration stays in the host CLI
for the reduced demo image. Personal
and manager dashboards show scoped usage. For automation, use
[`scripts/pricetag/api`](management-api.md#remote-https-client) from your workstation
or [`scripts/pricetag/manage`](management-api.md#host-management-over-ssh) on RHEL.
Both call service APIs; neither writes business tables. Use the
[mock demo setup](../../testing/pricetag-management-demo.md) for synthetic
quota-exhaustion and team-fixture tests.

Installation and approval of new provider origins remain host operations.
Quota exceptions permit explicit client model selection; they do not reroute
a denied request automatically.


[Providers](providers.md) · [Users, keys and budgets](users.md) ·
[Management CLI and API](management-api.md) ·
[Manual installation](manual.md) · [Mock benchmarks](../../testing/pricetag-perf.md)

**Pilot limits:** keep this host restricted to trusted administrators. MaaS
management stays private. Keys expire within 90 days; revoking a key does not
end an existing dashboard session. Retention, upgrades and recovery still need
qualification. [Details](users.md#limits)
