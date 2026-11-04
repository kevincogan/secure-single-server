# Management CLI and API

Use **Administration** for admin operations and **My keys** for personal key operations.
For automation, `scripts/pricetag/manage` calls the private loopback API with the
host's protected service credential. It does not print credentials or response
bodies, and it refuses to overwrite response files.

## Prepare workstation administrator access

After [local connection setup](README.md#5-prepare-the-local-connection), run in
that workstation shell. This copies an administrator key into a private file;
keep it separate from the ordinary-user key used for inference.

```console
umask 077
ssh "${SSH_OPTS[@]}" "$RHEL_HOST" 'sudo cat /root/pricetag-admin/admin.key' > "$CLIENT_DIR/admin.key"
chmod 600 "$CLIENT_DIR/admin.key"
cd "$REPO"
```

For a browser-issued administrator key, use its downloaded private file instead.
Do not commit keys or management response files to the repository. Use a private
working directory for the examples below:

```console
mkdir -p "$CLIENT_DIR/management"
chmod 700 "$CLIENT_DIR/management"
cd "$CLIENT_DIR/management"
```

## Remote HTTPS client

From a checkout on your workstation, use the same key and CA as browser/harness
access. The helper creates an **in-memory session**, applies normal server-side
role checks, and writes the response to a new private file:

```sh
python3 "$REPO/scripts/pricetag/api" GET /api/v1/management/users \
  --url "$GATEWAY_URL" --key-file "$CLIENT_DIR/admin.key" \
  --ca-file "$CLIENT_DIR/ca.pem" --output users.json
```

Use an ordinary user's key with `/me/keys` or scoped dashboard APIs. Personal key
operations cannot manage another user's keys, including when called by an admin.
Supported methods: GET, POST, PUT, PATCH and DELETE. The helper also accepts `/api/v1/pricing?used=0` to list the complete catalog.
Other query strings are rejected; use a direct authenticated API client for filtered reporting.

<details markdown="1">
<summary>Change a user's budget over HTTPS</summary>

```sh
umask 077
printf '%s\n' '{"subject":"carol","monthly_usd":5}' > budget-input.json
python3 "$REPO/scripts/pricetag/api" PUT /api/v1/management/budgets \
  --url "$GATEWAY_URL" --key-file "$CLIENT_DIR/admin.key" \
  --ca-file "$CLIENT_DIR/ca.pem" --input budget-input.json \
  --output budget-result.json
```

Input files must be owned by the caller with mode 0600. Pass provider credentials
only in such a file, never as command arguments. Inspect key-issuance responses
privately; delete credential input files when finished. A transport failure does
not prove that a mutation failed; the helper does not retry it.

</details>

## Host management over SSH

Run from the installed repository **on RHEL**:

```sh
sudo install -d -m 0700 /root/gateway-management
sudo python3 scripts/pricetag/manage GET users \
  --output /root/gateway-management/users.json
```

Choose a new output filename for each call. Inspect files privately with
`sudo less`; key-issuance responses contain a one-time key.

## Change a budget

Create a private request file and edit it:

```sh
sudo install -m 0600 /dev/null /root/gateway-management/budget-input.json
sudoedit /root/gateway-management/budget-input.json
```

Enter:

```json
{"subject": "carol", "monthly_usd": 5}
```

Then apply it:

```sh
sudo python3 scripts/pricetag/manage PUT budgets \
  --input /root/gateway-management/budget-input.json \
  --output /root/gateway-management/budget-result.json
```

The same resource names are available for `users`, `prices`, `policy`, `keys` and `key-revocations`. They use the deployed PriceTag management API schemas. The server validates allowed methods and fields;
this client does not bypass authorization or manipulate database tables.



**On errors:** inspect server state before repeating a mutation. A transport or
output error does not prove that key issuance failed server-side.
The client retains its private response file for inspection and does not retry.
Remove private request files when no longer needed.

## Count or revoke all keys for a user

`POST /api/v1/management/key-revocations` requires administrator access. Use
`{"subject":"carol","dry_run":true}` to count active keys without changing them.
Change `dry_run` to `false` only when ready to revoke every active key across that
user’s linked logins. Other users are unaffected; new keys issued afterward remain
valid. Existing browser sessions are not terminated; suspend the user for full
offboarding.

Use the HTTPS helper above, or save the request in a root-private JSON file and
run on RHEL:

```sh
sudo python3 scripts/pricetag/manage POST key-revocations \
  --input /root/gateway-management/key-revocations-input.json \
  --output /root/gateway-management/key-revocations-result.json
```

A partial upstream failure is reported explicitly. Retrying revocation is safe;
never automatically retry key issuance.
