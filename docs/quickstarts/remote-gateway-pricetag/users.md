# Users, budgets and keys

Admin is always created; Alice/Bob are optional. Ordinary users inherit $5/month
unless configured otherwise. Keys expire within 90 days. Use ordinary-user keys
for inference: admin is quota-exempt.

With the management candidate installed, **Administration** provides user/manager controls and onboarding keys;
**Safety Net** includes per-user USD overrides. **My keys** manages personal keys. The commands below use the same
service APIs; they do not write business tables directly. Published images without
those APIs are not compatible with this branch's helpers.

## Open the management session

From the **workstation shell used for installation**:

```console
ssh -t "${SSH_OPTS[@]}" "$RHEL_HOST" \
  'cd ~/secure-single-server && exec bash'
```

Run operations below in **this SSH session**; `exit` returns to your workstation.
New shell? Restore [connection variables](README.md#1-set-the-connection) first.

## Create a user

```console
sudo python3 scripts/pricetag/user --subject carol --name Carol \
  --monthly-usd 5 --key-lifetime 30d --output /root/pricetag-admin/carol.key
sudo cat /root/pricetag-admin/carol.key
```

Omit `--monthly-usd` to inherit the default; omit `--key-lifetime` for 90 days.
On your workstation, follow [client setup](README.md#5-prepare-the-local-connection)
with `INFERENCE_USER=carol`. That key charges Carol's budget.

## Change a budget

```console
sudo python3 scripts/pricetag/user --subject carol --monthly-usd 10 --no-key
```

Existing keys and usage are preserved. Allow up to 15 seconds for cached
admission decisions to expire.

## List users and keys

The administrator dashboard's **Users** page lists local identities. To list
one user's keys and expiry/status metadata (not the key values):

```console
sudo python3 scripts/pricetag/maas-key list --subject carol
```

To read a saved key for login or secure copying:

```console
sudo cat /root/pricetag-admin/carol.key
```

## Manage keys in the dashboard

**Administration → Users** creates an identity without a key. **Issue onboarding key**
adds a key; it does not replace existing keys. Choose **Copy key** or **Download .key**,
then **Dismiss key**. The secret is never displayed or saved in browser storage.

Users manage their own keys under **My keys**. Active keys appear first, with expiry
and remaining lifetime. **Revoke** stops a key; revoked/expired records remain in
expandable history. Permanent deletion is not supported. The deployed MaaS cleanup
API targets expired ephemeral keys, not ordinary revoked key records.

Administrators can **Check active keys** and **Revoke all keys** for the selected
user. These actions cover all linked logins. Revocation does not disable the user
or end an existing browser session; suspend the account to block both. A new key
can be created later. Do not share administrator keys with ordinary users.

Downloaded files contain only the credential. Keep the file private and use its
path in the [OpenCode setup](clients.md):

```sh
chmod 600 /path/to/pricetag.key
```

## Inspect a user's view

As superadmin, select the user in **Administration → Users → Issue onboarding key**
and choose **View selected user’s usage** or **View selected user’s team**.
Confirm **Continue**; no key needs to be issued or copied. The **Viewing as** banner
identifies the target. Use **Back to admin view** and confirm to restore your view.

Impersonation is read-only and follows the target's current identity/team scope.
It does not allow administrative changes or key issuance. To demonstrate the
user's actual login and key management, sign in with their key in a separate
browser profile. See the [demo walkthrough](demo.md#3-inspect-a-users-view-through-impersonation).

## Rotate or revoke a key

```console
sudo python3 scripts/pricetag/user --subject carol --rotate \
  --key-lifetime 30d --output /root/pricetag-admin/carol-next.key
```

Copy the new file to your workstation, then use its path as `KEY_FILE` and
restart OpenCode. Rotation saves the replacement before
revoking previous keys named `inference`; use a new output filename each time.
To revoke a specific key, copy its ID from `list`:

```console
sudo python3 scripts/pricetag/maas-key revoke --subject carol --key-id OLD_KEY_ID
```

<details>
<summary>Copy a rotated key and switch OpenCode</summary>

Run in the **workstation installation shell**, after exiting SSH:

```console
umask 077
KEY_FILE="$CLIENT_DIR/carol-next.key"
ssh "${SSH_OPTS[@]}" "$RHEL_HOST" 'sudo cat /root/pricetag-admin/carol-next.key' > "$KEY_FILE"
chmod 600 "$KEY_FILE"
printf 'User key saved at: %s\n' "$KEY_FILE"
```

In your project shell, set `KEY_FILE` to that printed path and rerun the
[OpenCode command](README.md#6-run-opencode). For a saved native configuration,
regenerate it with this key path. Alternatively, securely replace the contents
of the key file it already references and restart OpenCode.

</details>

<details>
<summary>Rotate with an overlap while clients switch</summary>

```console
sudo python3 scripts/pricetag/maas-key create --subject carol \
  --name laptop-next --expires-in 30d --output /root/pricetag-admin/carol-laptop.key
```

Switch the client, verify inference, then revoke the old key by ID.

</details>

<details>
<summary>Find saved keys or recover access</summary>

```console
sudo find /root/pricetag-admin -maxdepth 1 -type f -name '*.key' -print
```

Saved files may contain revoked keys; `maas-key list` is authoritative. Use
`--admin` for key operations on the configured administrator identity.
An SSH administrator can issue a replacement after all a user's keys expire.
If rotation reports a revocation failure, retain the new file and revoke the
reported old IDs after checking their status.

</details>

<details>
<summary>Dashboard versus CLI: supported operations</summary>

| Task | Available interface |
| --- | --- |
| View aggregate and user spending | Administrator dashboard |
| View local users and change administrator roles or manager relationships | Administrator **Users** |
| Set the default monthly allowance and post-limit model exceptions | Administrator **Safety Net** (`/api/v1/admin/safety-net`) |
| Create users or change an individual allowance | Administration → Users / Safety Net → Per-user monthly overrides; SSH `scripts/pricetag/user` uses the same PriceTag APIs |
| Issue onboarding keys | Administration → Users → Issue onboarding key |
| Create/list/revoke your own keys | My keys (`/management`); SSH `scripts/pricetag/maas-key` remains available |
| Configure providers, credentials and advertised models | SSH [provider helper](providers.md) |
| View personal/team spending | Usage is personal for users/managers; My team follows manager relationships |
| Inspect a user’s scoped view without their key | Superadmin View / Team links; read-only impersonation with confirmed return |

The default monthly allowance applies separately to each user. An individual
allowance overrides that default. This deployment starts with an empty
post-limit exception list, so no model bypasses the USD limit.

</details>

<details>
<summary>Administration boundaries and upstream API gaps</summary>

- The matching PriceTag demo image is required.
  Published upstream images do not yet provide this complete contract.
- MaaS owns keys; PriceTag owns identities, usage and budgets. Public browser
  management is authenticated by PriceTag; MaaS lifecycle endpoints stay private.
- User and budget writes use PriceTag APIs; deployment scripts do not write
  business tables. See [pricing management](pricing.md) for price changes.
- Deactivation suspends sessions and inference through the gateway. It is not
  permanent key deletion. Reactivation can make unrevoked finite keys usable again.
- Key expiry/revocation stops inference but does not end an existing browser session;
  suspend the profile to deny both. Sessions have their own seven-day lifetime.
- The `super_admin` role bypasses quotas. Grant it only to administrators;
  ordinary inference users keep the `user` role.

</details>

## Limits

- Monthly admission decisions are cached for about 15 seconds; concurrent or
  delayed requests can overshoot a USD allowance.
- Key revocation stops new key validation, but does **not** end an existing
  dashboard session. It is not complete account offboarding.
- MaaS administration stays on host loopback over SSH. Host administrators and
  configured service peers are privileged.
- Raw-event retention, upgrades and backup/recovery are not qualified by this
  fresh-install guide. Use the [mock benchmark](../../testing/pricetag-perf.md)
  to measure resource and storage growth.

For candidate automation over SSH, use the [private management API client](management-api.md).
