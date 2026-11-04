# Management demo on RHEL

**Mock demo:** use a dedicated benchmark VM and the pinned published management
images. All inference is synthetic; no real provider credentials are needed.

## Install on a fresh benchmark host

Run from the copied checkout on RHEL. The installer pulls the pinned published
images, imports them and starts the Quadlet services with two synthetic
model aliases. No real provider credentials are accepted.

```sh
read -r -p 'Gateway IP or DNS: ' GATEWAY_HOST
sudo scripts/pricetag/install --hostname "$GATEWAY_HOST" \
  --mode mock --demo-fixture --yes
```

Keep TCP 8443 restricted to the testing IPs. Existing deployments are refused.
For already-built images, use [image overrides](../quickstarts/remote-gateway-pricetag/images.md)
or `scripts/pricetag/install-demo --help`. Database and key-management ports stay
private.

## Prepare the live UI demo

1. Sign in at `https://<gateway-host>:8443/login` using the administrator key at
   `/root/pricetag-admin/admin.key`. Transfer/display keys only in a private terminal.
2. Open **Administration → Model pricing**. Configure illustrative rates for
   upstream IDs `fixture` and `fixture-cheap`; label them synthetic. For example,
   USD/MTok input/output rates of 1,000/2,000 and 100/200 make the mock differences
   visible. Set both cache rates explicitly. These are demo rates, not vendor prices.
3. Create the 20-user, two-team fixture. The script creates finite keys through
   APIs and generates mock usage; it does not write business tables directly.

```sh
cd ~/secure-single-server
sudo python3 tests/pricetag/rhel-demo-fixture.py \
  --output /root/pricetag-admin/demo-team-fixture
```

Use `--resume` with the same arguments after an interrupted fixture run. Private
keys and its progress manifest remain in the output directory. Resume skips
recorded successful traffic; it is not an exactly-once workload after a crash.

Perform live user/team, key, budget and pricing changes in the UI. Prepare provider/model routes before the demo using the host workflow.
Fixture generation and automated assertions may use APIs. Do not use terminal
management as a substitute for a missing demo UI.

Follow the [browser walkthrough](../quickstarts/remote-gateway-pricetag/demo.md)
before running the quota test below. The quota test retains a 10B-token
synthetic event that distorts aggregate usage and savings charts. Use a
separate host if you need to keep the presentation dashboard available.

## API qualification

After the presentation, run on an idle mock deployment. The fixture and tests
verify the generated mock configuration before mutations. They do not require
a provider-management adapter.

```sh
sudo python3 tests/pricetag/rhel-pricing.py \
  --output /root/pricetag-admin/demo-pricing-checks
sudo python3 tests/pricetag/rhel-quota-matrix.py \
  --output /root/pricetag-admin/demo-quota-checks
```

Use a new output directory each run. Tests restore policy and suspend their
test identities, but retain synthetic accounting history. A global
post-budget exception bypasses the USD gate, not the legacy token gate.

Clean up the presentation fixture when finished (accounting history is retained):

```sh
sudo python3 tests/pricetag/rhel-demo-fixture.py --cleanup \
  --output /root/pricetag-admin/demo-team-fixture
```

## Run the complete API and browser suite

The [demo CI workflow](../../.github/workflows/pricetag-demo.yml) runs the
mock deployment suite, including browser authorization and lifecycle tests.
Follow [the suite instructions](pricetag-demo-ci.md#run-on-the-benchmark-rhel-deployment)
for browser prerequisites and the complete run command. RHEL benchmark validation remains separate from hosted CI; a passing
mock suite does not qualify real-provider behavior.
