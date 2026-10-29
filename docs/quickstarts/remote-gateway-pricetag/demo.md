# Walk through the gateway demo

Start with the [quickstart](README.md). Use synthetic providers on a dedicated
host for budget-exhaustion tests; real-provider requests incur charges.
Use the [default published demo images](images.md) for the complete flow below.
Provider/model routing is configured through the CLI; the optional provider editor
is not included.

**Demo story:** observe spending → onboard a team → inspect personal/team usage →
apply budgets → continue on an approved model → explain prices and key lifecycle.
On a populated deployment, begin at **Usage** (`/dashboard`) as superadmin to show
aggregate requests, models and USD spend. A fresh deployment needs requests first;
the steps below create the people and activity to inspect.

## 1. Onboard users and a manager

Sign in at `https://<gateway-host>:8443/login` with the administrator key.
Open **Administration → Users** (`/admin`):

1. In **Create or update a login**, create an ordinary user and a second ordinary user to be their
   manager. Keep their login names stable: usage belongs to that identity.
2. In the existing user table, choose the manager in the user’s **Manager**
   dropdown and retain the `user` role. Changes save immediately. A manager does not need administrator privileges.
3. In **Administration → Safety Net → Per-user monthly overrides**, choose the user and set their monthly USD limit.
   **Use global default** removes an override; it does not reset spending.
4. Return to **Users → Issue onboarding key**, select each user and choose a name and finite
   lifetime. This creates an additional key, not a rotation. Use **Copy key** or
   **Download .key**; the secret is never displayed. Keep the downloaded file private
   (`chmod 600 /path/to/pricetag.key`) and pass its path to the client helper. Do not include keys in screenshots or recordings.

Repeat for more users. The UI supports individual creation; the automated
[20-user mock fixture](../../testing/pricetag-management-demo.md) prepares a
larger demonstration through the same APIs, not through a bulk-import UI.

## 2. Generate and observe usage

Follow [Connect OpenCode](README.md#5-prepare-the-local-connection) using the
ordinary user's key. Send requests to the preconfigured expensive and cheaper
model aliases. Provider routes are prepared with the [provider helper](providers.md);
creating a price entry alone does not expose a model.

| Signed-in role | View | What to show |
| --- | --- | --- |
| Superadmin | **Usage** (`/dashboard`) | Aggregate requests, models, tokens and USD spending; filter to a user or model. **Administration** (`/admin`) contains management controls. |
| User | **Usage** (`/dashboard`) | Their own charts and recent activity, plus monthly spend/allowance. Usage belongs to the identity, not the particular key used to sign in. |
| Manager | **Usage** (`/dashboard`) | Their personal usage only. |
| Manager | **My team** (`/manager`) | Their reporting subtree, team charts and member budgets. Drill into a member; unrelated teams remain inaccessible. |

Choose a time range containing the requests and use **Refresh**. Monthly budget
figures remain month-to-date even when a chart uses a different range. Charts show
recorded activity, not the entire configured model catalog. A load error is shown
with a retry instruction; it must not be mistaken for zero usage. Managers do not
gain administrator budget-override permissions.

Allow time for accounting to arrive. Distinguish discount savings shown by the
UI from measured savings achieved by switching models. Synthetic data does not
prove model quality or a fixed cost reduction.

## 3. Inspect a user's view through impersonation

As superadmin, open **Administration → Users**:

1. Select the user under **Issue onboarding key**; you do not need to issue a key.
2. Choose **View selected user’s usage** or **View selected user’s team**.
   Confirm with **Continue**.
3. Show the **Viewing as** banner. Personal Usage must contain only the selected
   identity; the team view must contain only that identity's authorized subtree.
4. Choose **Back to admin view** in the banner and confirm. Aggregate Usage and
   administrator controls are available again.

Impersonation is read-only: it does not grant the target your administrator
privileges or allow key issuance or other business changes. Inactive or missing
identities are rejected. For a full end-user login demonstration, use their key
in a separate browser profile instead.

## 4. Apply controls and continue on an allowed model

1. In **Administration → Safety Net → Per-user monthly overrides**, lower the test user's
   allowance below their recorded spend. Use an ordinary user: superadmin
   accounts are exempt from this spending gate.
2. Send another paid-model request and observe denial after policy caches refresh
   (allow about 15 seconds). Refresh the user dashboard to show their allowance.
3. In **Administration → Safety Net → Models allowed after the limit**, select
   an approved model from the configured-model picker. Labels identify gateway
   aliases; the saved value is the **billed upstream ID**.
4. Select the corresponding alias explicitly in OpenCode and retry. Confirm the
   exception works and a different paid model remains blocked.
5. Expand **Existing user overrides** to search/page through overrides.
   **Remove override** restores the global allowance without resetting spending.
   Restore the intended allowance and exception list after the demonstration.

Exceptions are **global**, not per-user automatic fallback routing. A cheap model
can still cost money. The legacy token gate remains independent. Concurrent and
in-flight requests can overshoot the USD allowance; this is not a reserved-funds
hard cap. Use the [mock quota tests](../../testing/pricetag-management-demo.md)
to verify behavior without spending real money.

Gateway aliases sharing a billed model ID share the exception. This is not a
per-user model allowlist.

## 5. Review prices and discounts

- **Pricing:** open the rate-card view and enable unused models when you want
  the full price catalog, rather than just models with recorded usage.
- **Administration → Pricing Discounts:** save a scoped discount policy and
  verify its effective rates. Saving the policy refreshes prices.
- **Administration → Pricing Discounts → Model pricing:** the demo image also provides the
  optional custom-rate API/UI. Set input, output, cache-read and cache-write
  rates explicitly in USD per million tokens. Search **Current model rates**,
  choose **Edit rates**, review all four values and save. Use the billed model ID.
  Alternatively, copy a source model’s rates as a snapshot.

PriceTag stores current rates in PostgreSQL. New custom saves are marked
**Managed override**; imported-price and discount refreshes leave those rates
unchanged. Deliberately setting every rate to zero makes a model free.

New rates apply to future events. Historical repricing is a separate, deliberate
API operation with a preview and confirmation hash; it is not a UI action.
See [pricing operations](pricing.md) for refresh, catalog and repricing examples.

## 6. Replace keys and offboard

1. Sign in as the user and open **My keys** (`/management`). Create another key
   with a distinct name and allowed finite lifetime. Deliberate additional keys
   are supported; repeated submissions while creation is pending are ignored.
2. **Copy key** or **Download .key**, then **Dismiss key**. The secret is not
   displayed and cannot be retrieved later. Update OpenCode's key-file path,
   restart it and verify inference. Both keys work until one expires or is revoked.
3. **Revoke** the old key. Active keys appear first; expandable history lists
   revoked/expired records with status, expiry dates and remaining lifetime.
   This is revocation, not permanent record deletion.
4. As superadmin, use **Administration → Users → Revoke a user's keys** to
   **Check active keys** or **Revoke all keys** for a selected identity. New keys
   can still be issued afterward; this action does not disable the account.
5. To offboard, save the login as **Inactive** under **Create or update a login**.
   Verify that its existing browser session cannot read usage and its inference
   access is denied. Revoke its keys as well when permanent offboarding is intended.

Key revocation does not itself end an existing dashboard session. Suspension
blocks access; reactivation can make unrevoked, unexpired keys usable again.
See [users and keys](users.md) for CLI equivalents and overlap rotation.

<details>
<summary>Automated verification of these boundaries</summary>

The [mock demo suite](../../testing/pricetag-management-demo.md) exercises the
management flow with synthetic providers. The deployment CI suite additionally
checks rendered personal charts, manager team charts, impersonation/return,
chart-error retry and direct API boundaries: anonymous access, spoofed identity
headers, mixed/cross-user filters, cross-team requests and suspended identities
with existing sessions. These checks validate authorization independently of
which controls the UI displays.

</details>

## What remains a slide or a separate integration

Installation and provider configuration use the documented CLI. A new hosted
inference service needs its own deployment and a configured gateway route;
changing that provider is not part of the reduced browser UI. RHOAI growth,
SSO onboarding, managed databases and Side-Eye are future integrations. No
automatic cheaper-model routing or guaranteed 10× saving is demonstrated here.
