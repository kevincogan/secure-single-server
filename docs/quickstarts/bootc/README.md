# Bootc quickstart

Run this walkthrough in Bash on a disposable, already bootc-managed RHEL 9.8+
x86_64 host. Have an OpenAI API key and an exact model ID available to your
account ready. This published-image example uses OpenCode with Praxis.
For OpenClaw, use the [bounded model/tool guide](../openshell-praxis/openclaw.md)
with a rebuilt image containing the integration.

Target a first model response in under five minutes after the host is prepared
and images are cached. Initial downloads and the OS reboot add time.
For other deployment and credential options, see the
[full bootc guide](../openshell-single-server/bootc.md).

On an existing bootc-managed host, select the image and reboot:

```bash
image=quay.io/redhat-et/secure-single-server-opencode:v0.1
sudo bootc switch "$image"
sudo bootc status
sudo systemctl reboot
```

Reconnect after reboot and wait for the deployment service to finish:

```bash
sudo systemctl start secure-single-server.service
sudo sss-bootc openshell --version
```

Enter your OpenAI key at the hidden prompt. Praxis stores it in a Podman secret;
it is not put in the image or harness. The default cloud configuration requires
an Anthropic secret too; the unused value below allows OpenAI-only evaluation
and cannot authenticate Anthropic requests. Use fresh secret versions if `v1`
already exists.

```bash
(
  set +x
  set -euo pipefail
  sudo -v
  IFS= read -r -s -p 'OpenAI API key: ' key; printf '\n'
  printf '%s' "$key" | sudo sss-bootc secret openai v1
  unset key
  printf '%s' 'unused-anthropic-key' | sudo sss-bootc secret anthropic v1
  sudo sss-bootc activate praxis-openai-api-key-v1 praxis-anthropic-api-key-v1
  sudo sss-bootc inference cloud
)
```

Select your model, create the OpenCode sandbox configured for Praxis, and connect:

```bash
IFS= read -r -p 'OpenAI model ID: ' model_id
uid="$(id -u openshell-svc)"
cd /
sudo runuser -u openshell-svc -- env HOME=/var/lib/openshell-svc \
  XDG_RUNTIME_DIR=/run/user/"$uid" \
  DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/"$uid"/bus \
  OPENSHELL_BIN=/usr/bin/openshell OPENSHELL_MODEL_ID="$model_id" \
  /usr/share/secure-single-server/openshell/harnesses/opencode/create.sh \
  --profile dev --name opencode-dev \
  --config /usr/share/secure-single-server/configs/openshell-praxis
sudo sss-bootc harness connect --name opencode-dev
```

Ask `Reply with a short greeting.` A nonempty response verifies model access;
use the [harness checks](../openshell-single-server/verification.md)
to verify tools and policy. For an existing local API and key, use the
[local endpoint recipe](../openshell-single-server/bootc.md#local-openai-compatible-endpoint-and-key).
For the bundled private vLLM route, use
[Praxis/vLLM setup](../openshell-single-server/bootc.md#praxis-cloud-secrets-or-private-vllm).

