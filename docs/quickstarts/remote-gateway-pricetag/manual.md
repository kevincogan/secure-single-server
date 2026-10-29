# Manual installation

Use these steps **instead of** the installer, on a fresh RHEL host after
[copying the checkout](README.md#2-copy-the-checkout). Run all blocks in the same
SSH session. From the workstation installation shell, connect first.
Stop at any failed command.

```console
ssh -t "${SSH_OPTS[@]}" "$RHEL_HOST" \
  'cd ~/secure-single-server && exec bash'
```

## 1. Prepare RHEL and images

Run on each RHEL host after copying the source:

```console
sudo dnf install -y podman git python3 python3-pyyaml openssl curl sudo \
  policycoreutils-python-utils shadow-utils
cd ~/secure-single-server
sudo scripts/common/install --prepare
```

Pull the same digest-pinned images as the installer:

```console
PRAXIS_REF=quay.io/opendatahub/praxis-experimental@sha256:502f120fed7b8e516ce1d78396045c8f72673672351432b9dc2e61baf5c13ac8
MAAS_REF=quay.io/redhat-et/secure-single-server-maas-standalone@sha256:0bec6ef57fa5b10a7bef8f4df8d98f932c9d7fc96798f7bfc0cd77b504790fa8
METERING_REF=quay.io/redhat-et/secure-single-server-pricetag-metering@sha256:02494463ca905e8342c39f707310e4aa2c8a14670625da5c9fdd750e7622220a
(
  for image in "$PRAXIS_REF" "$MAAS_REF" "$METERING_REF"; do
    sudo podman pull "$image" || exit 1
  done
)
```

Import into the service account and capture immutable local IDs:

```console
set -o pipefail
PRICETAG_UID=$(id -u praxis-svc)
svc() {
  (cd /tmp && sudo -u praxis-svc env \
    XDG_RUNTIME_DIR="/run/user/$PRICETAG_UID" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$PRICETAG_UID/bus" "$@")
}
(
  for image in "$PRAXIS_REF" "$MAAS_REF" "$METERING_REF"; do
    sudo podman save "$image" | svc podman load || exit 1
  done
)
```

After a successful import, capture the IDs in the same SSH session:

```console
PRAXIS_ID=$(sudo podman image inspect "$PRAXIS_REF" --format '{{.Id}}')
MAAS_ID=$(sudo podman image inspect "$MAAS_REF" --format '{{.Id}}')
METERING_ID=$(sudo podman image inspect "$METERING_REF" --format '{{.Id}}')
PRAXIS_IMAGE=$(svc podman image inspect "$PRAXIS_ID" --format '{{.Id}}')
MAAS_IMAGE=$(svc podman image inspect "$MAAS_ID" --format '{{.Id}}')
METERING_IMAGE=$(svc podman image inspect "$METERING_ID" --format '{{.Id}}')
PRAXIS_IMAGE="sha256:${PRAXIS_IMAGE#sha256:}"
MAAS_IMAGE="sha256:${MAAS_IMAGE#sha256:}"
METERING_IMAGE="sha256:${METERING_IMAGE#sha256:}"
```

Stop on any import failure. [Image options](images.md) explains source builds for
another branch or commit; they are optional, not required for this deployment.

## 2. Configure providers

Run on the real-provider host. The helper asks for credentials using hidden
prompts, performs HTTPS model discovery, and stores provider secrets separately
from the MaaS user keys. Choose one or both provider types:

**Direct OpenAI** (optional if using only an external provider):

```console
sudo python3 scripts/pricetag/providers openai
```

**External provider** (optional if using only direct OpenAI):

```console
sudo python3 scripts/pricetag/providers external --api both
```

After configuring your chosen provider(s):

```console
sudo python3 scripts/pricetag/providers export
```

For the external provider, use `--api openai`, `--api anthropic`, or `--api both`.
Enter only the selected API endpoint(s), then the credential. HTTPS and `/v1`
normalization are automatic. At least one provider and a matching model preset
are required. Review the printed aliases, limits and price mappings.

See [provider setup and replacement](providers.md) for separate API
endpoints, discovery diagnostics, protected-file automation and replacement.


## 3. Start services

On the real host, export the provider configuration. Set `GATEWAY_HOST` to the
DNS name clients will use, or the VM public IP for the initial IP-bound test.
The TLS certificate includes that name and localhost.

```console
GATEWAY_HOST='gateway.example.invalid'
sudo python3 scripts/pricetag/prepare.py \
  --hostname "$GATEWAY_HOST" --praxis-image "$PRAXIS_IMAGE" \
  --maas-image "$MAAS_IMAGE" --metering-image "$METERING_IMAGE" \
  --providers /root/pricetag-provider-inputs/providers.json \
  --models /root/pricetag-provider-inputs/models.json \
  --provider-unit /root/pricetag-provider-inputs/provider-secrets.container \
  --price-sources /root/pricetag-provider-inputs/prices.json \
  --monthly-usd 5 --no-sample-users
sudo scripts/pricetag/start
```

This creates the administrator only. [Create an inference user](users.md#create-a-user)
next, or omit `--no-sample-users` during preparation to create Alice and Bob.

Missing prices do not block startup; PriceTag uses [fallback estimates](pricing.md#missing-price-fallback).
Inspect the rates before real-provider inference.

Preparation refuses existing directories. Startup installs persistent systemd
Quadlets for PostgreSQL, MaaS, PriceTag and Praxis. Do not rerun preparation over
an existing deployment; upgrades require separate qualification.

<details>
<summary>Private network and trusted services</summary>

MaaS trusts host loopback and the three `/32` service addresses assigned to MaaS,
Praxis and PriceTag on `pricetag-private`. Unrelated containers are excluded.
Host administrators and these service peers remain privileged.

</details>

## 4. Verify services

```console
svc systemctl --user status pricetag-db.service pricetag-maas.service \
  pricetag-metering.service pricetag-gateway.service --no-pager
loginctl show-user praxis-svc -p Linger
sudo curl --fail --cacert /etc/praxis-pricetag/ca.pem https://localhost:8443/login >/dev/null
```

Return to [dashboard and client setup](README.md#4-open-the-dashboards).
