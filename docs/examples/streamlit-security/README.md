# Streamlit before and after OpenShell

This scenario is a simple way to show the benefits of the same application
with and without OpenShell. It runs first in an ordinary container with the
real model key in the application process, then in OpenShell with an attached
provider, a read-only application directory, and a hard-required Landlock
policy. The provider profile authorizes the credential only for
`POST /v1/chat/completions`.

```text
ordinary container
  → real model key inside the app
  → app can write to its own directory
  → app can read a synthetic marker outside its application directory

OpenShell sandbox
  → app receives an opaque credential placeholder
  → OpenShell substitutes the real key at the authorized endpoint
  → app directory is read-only
  → synthetic marker outside the allowed paths is unreadable
```

## Before you start

### Where to run it

Run the commands on a dedicated RHEL 9 x86_64 Linux host, such as a local or
cloud VM or bare-metal machine; an ordinary nested container is not a supported
OpenShell host. Before running the demo, complete the
[manual gateway setup in OpenShell Overview](../../../openshell/docs/README.md#manual-gateway-setup-on-rhel):
install OpenShell, verify Landlock ABI 3 or newer, start the gateway, and define
the `repo` and `os_run` shell helper. The manual checkout is
`/opt/secure-single-server`; keep `repo` pointed at that checkout. Stop before
creating a harness: this demo runs a Streamlit container directly and does not
need a harness or Praxis. Run all commands below in the same Bash session so
the `repo` variable and `os_run` helper remain available.

The unsafe half uses your login account's rootless Podman. The OpenShell half
uses the `openshell-svc` account's OpenShell CLI and rootless Podman, so use the
OpenShell setup's `os_run` helper for its profile, provider, sandbox, service,
and verify commands. If you use a different OpenShell deployment, it must
provide the same service-account CLI and rootless Podman context for
`run-safe.sh`.

If the host is remote, open the matching SSH tunnel before starting each
version, then open Streamlit in your local browser. The unsafe container uses
local port `8501`; the OpenShell service uses local port `8090`.

For the unsafe version, keep this tunnel open:

```console
ssh -N -L 8501:127.0.0.1:8501 user@open-shell-host
```

Replace `user@open-shell-host` in either tunnel command with your SSH username
and OpenShell host.

Use a dedicated model API key and endpoint for the demo. The ordinary run
exposes the key to app code, so use HTTPS. In OpenShell, the app receives an
opaque placeholder and the provider supplies the key only for an authorized
request.

### OpenAI

First export the provider and model values in the Bash session you will use for
both runs. The ordinary run requires the endpoint and model; the OpenShell run
also requires the provider name:

```console
export STREAMLIT_DEMO_PROVIDER=streamlit-demo-openai
export MODEL_BASE_URL=https://api.openai.com/v1
export OPENAI_MODEL=gpt-5.5
```

Import the demo provider profile from the repository root with `os_run`:

```console
os_run openshell profile lint -f "$repo/openshell/demos/streamlit-security/providers/openai.yaml"
os_run openshell profile import -f "$repo/openshell/demos/streamlit-security/providers/openai.yaml"
```

Register the provider by reusing the manual guide's
[hidden-prompt procedure](../../quickstarts/openshell-single-server/manual.md#4-choose-model-access),
with these Streamlit-specific values: `--name streamlit-demo-openai`,
`--type streamlit-openai`, and `--credential OPENAI_API_KEY`. Keep the command
in the service-owner shell so the real key is entered at a hidden prompt.

### OpenAI-compatible endpoint

For endpoint setup details, see the
[OpenAI-compatible model guide](../../quickstarts/openshell-single-server/model-access.md#local-openai-compatible-service).
Edit the host and port in
`openshell/demos/streamlit-security/providers/openai-compatible.yaml`. The
profile host and port must match the HTTPS host and port in `MODEL_BASE_URL`.
Export the provider and model values before importing the profile or running
either app:

```console
export STREAMLIT_DEMO_PROVIDER=streamlit-demo-compatible
export MODEL_BASE_URL=https://inference.internal/v1
export OPENAI_MODEL=your-model-id
```

Lint and import the profile with `os_run`:

```console
os_run openshell profile lint -f "$repo/openshell/demos/streamlit-security/providers/openai-compatible.yaml"
os_run openshell profile import -f "$repo/openshell/demos/streamlit-security/providers/openai-compatible.yaml"
```

Register the provider by reusing the hidden-prompt procedure linked above, with
`--name streamlit-demo-compatible`,
`--type streamlit-openai-compatible`, and `--credential OPENAI_API_KEY`.

## Run the unsafe version

From the repository root, in your login account's rootless Podman context (not
through `os_run`):

```console
read -r -s -p "Model API key: " OPENAI_API_KEY; printf '\n'
export OPENAI_API_KEY

openshell/demos/streamlit-security/run-unsafe.sh
unset OPENAI_API_KEY
```

Use the key, endpoint, and model from the selected provider section above.
Keep the exported endpoint and model values set; the unsafe script inherits
them from this shell.

Open `http://localhost:8501`. Choose **Summarize with model**, then choose both
diagnostics. The model call succeeds, the app writes a fake marker to
`/opt/openshell-demo/leaked-marker`, and it reads the synthetic marker at
`/opt/openshell-demo-secret`.

Both versions include the same follow-up chat. It sends questions to the model;
the diagnostics remain the only local actions.

## Run the OpenShell version

After completing one of the provider sections above and the unsafe run, keep
its exported variables set. The safe run requires all three and passes them
into the service-owner environment. If the host is remote, open the tunnel
below in a second terminal and keep it open while the demo runs:

```console
ssh -N -L 8090:127.0.0.1:8090 user@open-shell-host
```

Start the sandbox through the service-owner helper:

```console
os_run env \
  STREAMLIT_DEMO_PROVIDER="$STREAMLIT_DEMO_PROVIDER" \
  MODEL_BASE_URL="$MODEL_BASE_URL" \
  OPENAI_MODEL="$OPENAI_MODEL" \
  bash "$repo/openshell/demos/streamlit-security/run-safe.sh"
```

Open the URL printed by `run-safe.sh`. The same model summary works, but both
diagnostics are denied: `/opt/openshell-demo` is read-only and
`/opt/openshell-demo-secret` is outside the policy's allowed read paths.

OpenShell's gateway routes exposed services by hostname. Use the exact URL
printed by `run-safe.sh`; `http://localhost:8090` reaches the gateway's default
route and returns `404`, not the Streamlit app.

Optionally verify the boundary as the service owner:

```console
os_run bash "$repo/openshell/demos/streamlit-security/verify.sh"
```

## Cleanup

Stop the unsafe container with `Ctrl-C`. Remove the OpenShell sandbox and its
exposed service through the service-owner CLI with:

```console
os_run openshell service delete streamlit-demo streamlit
os_run openshell sandbox delete streamlit-demo
```

## What this proves

- The unsafe app holds the real model key and can modify its own application
  directory and read the synthetic marker outside it.
- The OpenShell app holds only an opaque placeholder; OpenShell substitutes the
  real key at the endpoint authorized by the provider profile.
- OpenShell makes the application directory read-only, makes the synthetic
  marker unreadable, and requires Landlock.
- The demo uses synthetic markers, never real credentials or real host files.

## What this does not prove

This focused demo shows credential substitution and two filesystem boundaries
for one application; it does not test every syscall, network route, container
escape, or supply-chain boundary. Keep the read target synthetic; do not point
the diagnostic at real host files.
