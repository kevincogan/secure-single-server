# Benchmark the MaaS and PriceTag gateway

Use a dedicated mock-only RHEL VM. This measures HTTPS, Praxis, MaaS, PriceTag
accounting and PostgreSQL with a synthetic LLM, not model quality, GPU capacity
or real-provider latency. Never configure real provider keys on this host.

## Set up the benchmark host

Follow the [RHEL requirements and AWS setup](../quickstarts/remote-gateway-pricetag/README.md#1-set-the-connection)
and [copy the reviewed checkout](../quickstarts/remote-gateway-pricetag/README.md#2-copy-the-checkout).
Choose a separate VM name such as `pricetag-perf` in the AWS commands. Then run
over SSH, substituting that VM's public IP or DNS name:

```console
cd ~/secure-single-server
sudo scripts/pricetag/install --mode mock --demo-fixture --hostname PERFORMANCE_VM_PUBLIC_IP_OR_DNS --yes
```

This is a fresh installation, not an update command. It pulls the pinned
MaaS, metering and Praxis images, configures the fixture and starts the
Quadlet services. It needs no upstream provider credentials. For manual image
preparation, follow [the image steps](../quickstarts/remote-gateway-pricetag/manual.md#1-prepare-rhel-and-images),
then prepare the mock configuration using the image variables from those steps:

```console
GATEWAY_HOST='PERFORMANCE_VM_PUBLIC_IP_OR_DNS'
sudo python3 scripts/pricetag/prepare.py --mock-provider \
  --hostname "$GATEWAY_HOST" --praxis-image "$PRAXIS_IMAGE" \
  --maas-image "$MAAS_IMAGE" --metering-image "$METERING_IMAGE" \
  --price-sources configs/pricetag/perf-price-sources.json --monthly-usd 5
sudo scripts/pricetag/start
```

Do not run manual preparation after a successful guided install. The fixture
price source is synthetic test configuration; do not reuse it for real models.
Manual preparation above supports the benchmark. The acceptance script below
also checks model aliases and requires the guided install with `--demo-fixture`.

## One-command benchmark

After a mock installation, run:

```console
cd ~/secure-single-server
sudo python3 scripts/pricetag/benchmark
```

This creates 20 distinct test users, runs 3,600 streamed requests at concurrency
1/5/10/20, verifies exact per-user accounting, and samples host/container/database
resources during the load. It stops on load failures, sampler errors, service
restarts or less than 30% disk available. The roughly 20-minute default workload
uses a three-second mock stream. For a short installation check:

```console
sudo python3 scripts/pricetag/benchmark --requests 20
```

To change load, set concurrency phases and requests per user **per phase**:

```console
sudo python3 scripts/pricetag/benchmark --concurrency 1 5 10 --requests 50
sudo python3 scripts/pricetag/benchmark --concurrency 20 --requests 500
```

| Parameter | Default | Allowed values / meaning |
| --- | --- | --- |
| `--concurrency` | `1 5 10 20` | One or more sequential phases, each with 1–20 simultaneous users |
| `--requests` | `100` | 1–1000 requests per user in each phase |

Total load requests are `sum(concurrency) × requests`: the examples above send
800 and 10,000 requests. Each worker sends one streamed request at a time using
a distinct non-admin MaaS key; the fixture records two input and three output
tokens per request. The wrapper uses no think time. Use the individual steps
below for pacing (`perf run --think SECONDS`) or separate resource sampling.

It prints a private result directory containing `summary.json`, `requests.json`,
`observe.jsonl` and a private `keys/` directory. Do not publish `keys/`. Reports
are retained on failure; `summary.json` is written only after all checks pass.
The command refuses non-fixture models and real-provider credential mounts.
It does not delete usage history, tune quotas, rotate production keys, or prove
long-term retention safety.

<details markdown="1">
<summary>Using OpenCode against the mock host</summary>

The fixture emits a fixed `add(2,3)` call whenever tools are advertised. OpenCode
has no such tool and can repeatedly retry it. For a text-only client smoke test,
add `"tools": {"*": false}` and `"permission": {"*": "deny"}` to the temporary
OpenCode configuration. Both Chat and Messages paths were checked this way.
This does not qualify real-model tool behavior; keep these overrides out of
your real-provider configuration.

</details>

## Individual benchmark steps

On the performance RHEL host:

```console
cd ~/secure-single-server
PERF_RUN="perf-$(python3 -c 'import uuid; print(uuid.uuid4().hex[:8])')"
sudo python3 scripts/pricetag/perf users \
  --tokens "/root/pricetag-admin/$PERF_RUN" --prefix "$PERF_RUN" --count 20 \
  --maas-url http://127.0.0.1:18086
sudo python3 scripts/pricetag/perf run --url https://localhost:8443 \
  --ca /etc/praxis-pricetag/ca.pem --tokens "/root/pricetag-admin/$PERF_RUN" \
  --concurrency 1 5 10 20 --requests 100 --think 0 \
  --output "/root/pricetag-admin/$PERF_RUN.json"
sudo python3 scripts/pricetag/perf verify \
  --report "/root/pricetag-admin/$PERF_RUN.json" \
  --database pricetag-db --service-user praxis-svc
```

Each test identity receives a $100 monthly USD override, so the normal
spending enforcement remains active without stopping the synthetic run. The
edge rate limit remains enabled. This profile sends 3,600 requests across the
four concurrency levels and checks that the ledger records exactly the
expected per-user requests and token counts. Include the single smoke request
when comparing the final ledger total.

## Record resource and storage growth

In a second SSH session, sample the containers while the run is active. Define
`svc` once in that shell:

```console
PRICETAG_UID=$(id -u praxis-svc)
svc() {
  (cd /tmp && sudo -u praxis-svc env \
    XDG_RUNTIME_DIR="/run/user/$PRICETAG_UID" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$PRICETAG_UID/bus" "$@")
}
svc podman stats --no-stream --format json \
  pricetag-gateway pricetag-maas pricetag-metering pricetag-db pricetag-provider
svc podman exec pricetag-db psql -U metering -d metering -At -c \
  "SELECT count(*), pg_total_relation_size('usage_events') FROM usage_events;"
svc podman exec pricetag-db psql -U metering -d metering -At -c \
  'SELECT pg_database_size(current_database());'
free -h
df -h / /var/lib/containers
```

For repeated machine-readable samples, start this while the load command runs
in the first session. Reuse the same value printed in the first session:

```console
PERF_RUN='perf-REPLACE_WITH_RUN_ID'
sudo python3 scripts/pricetag/observe \
  --samples 160 --interval 10 \
  --output "/root/pricetag-admin/$PERF_RUN-observe.jsonl"
```

This collects a little over the expected load duration. Capture repeated
samples and before/after disk use for longer soaks. Include host CPU, memory,
disk, service restarts, PostgreSQL/WAL size and report contents. A single
snapshot does not establish peak usage or sustained capacity. Local laptop runs
are not substitutes for RHEL measurements.

## Pricing administration check

```console
sudo python3 tests/pricetag/rhel-pricing.py --output /root/pricetag-admin/pricing-check
```

Use a new output directory. This mock-only test verifies administrator, ordinary
user and anonymous access; saves the unchanged discount policy; and refreshes
source prices. It previews and confirms repricing for one uniquely named
synthetic event, including an idempotent repeat. A discount-save failure now
fails the test; it is not accepted as a known bug. Catalog refresh requires
outbound access and can update imported rates; managed overrides remain intact.

## Missing-price fallback check

On the mock-only host:

```console
sudo python3 tests/pricetag/rhel-price-fallback.py
```

This checks through service APIs that missing prices permit setup with a warning
and that copying a source rate prices the billed upstream ID, not an unused
alias. It creates unique, unrouted synthetic price records and retains them for
audit; existing model rates, users and usage are unchanged.
See [fallback rates](../quickstarts/remote-gateway-pricetag/pricing.md#missing-price-fallback).

## USD quota probe

Run after the load test on the mock-only host:

```console
sudo python3 tests/pricetag/rhel-quota.py --output /root/pricetag-admin/quota-check
```

Use a new output directory for each run. The test creates a dedicated user with
a $0.01 monthly allowance and sends paced mock requests using the configured
fixture price. It verifies recorded spend reached the allowance, subsequent
inference returns HTTP 429, another user remains permitted, and increasing the
allowance restores the same key. It does not alter model prices.

Requests stay below the gateway's transport rate limit so a transport rejection
cannot be mistaken for USD enforcement. Admission decisions are cached for up to
15 seconds; concurrent requests and delayed events can exceed the allowance.
This is admission control, not an exact billing ceiling.

For role isolation, user/key lifecycle and model-alias checks:

```console
sudo python3 tests/pricetag/rhel-acceptance.py --output /root/pricetag-admin/acceptance-check
```

This test briefly restarts the mock gateway to check distinct client/upstream
model names and spoofed headers. Run it separately from performance measurements.
The original configuration is restored afterward. Test credentials stay private
in the output directory; `checks.json` contains sanitized results.

## Acceptance and cleanup

Require all requests to complete without unexpected 4xx/5xx responses, complete
streams, exact ledger reconciliation, no service restart or out-of-memory kill,
and no unexpected disk growth. Inspect the dashboard and user isolation
separately; this benchmark does not prove dashboard authorization or long-term
retention behavior.

The metering image currently has no configured raw-event retention deletion.
Do not delete rows manually on a test database. Record its growth rate and keep
the test host isolated; define a reviewed retention and backup policy before
using this deployment for long-lived users. The tested rootless Podman units use
the `k8s-file` log driver with no per-container size cap (`-1B`); the short run
showed stable journald usage, but it does not establish a long-term log bound.
Set and verify a log rotation limit before running a long-lived service.
