# Podman quickstart

Use Bash on a RHEL 9.8+ x86_64 host with **Podman already started and running**.
For the model-call example, run from a reviewed repository checkout and have
an OpenAI key and an accessible model ID ready. Target a first model response
in under five minutes with cached images; initial image downloads add time.

Choose image inspection or a direct Praxis model call below. For the complete
OpenShell deployment, use the [bootc guide](../openshell-single-server/bootc.md)
or [manual container guide](../openshell-single-server/manual.md).

## Run the bootc image in Podman

No model credentials or container environment variables are needed to inspect
the bootc image. Set `harness` to `opencode` or `openclaw`:

```bash
harness=opencode
image="quay.io/redhat-et/secure-single-server-${harness}:v0.1"
podman run --rm -it --entrypoint /bin/bash "$image"
```

Inside the container, run `openshell --version` or `sss-bootc help`; use `exit`
to leave. This command starts Bash, not the boot services. Running the complete
nested OpenShell deployment inside this container is not a qualified deployment path.
Use the bootc host or [manual container guide](../openshell-single-server/manual.md)
for sandboxed harness execution.

## Podman-only model call

For a quick inference check without installing an OS image, run the Praxis
workload directly. From a reviewed repository checkout with the Podman engine
already running, set `OPENAI_API_KEY` at the hidden prompt and `MODEL_ID` to an accessible model.
`ANTHROPIC_API_KEY` must also exist for the two-provider config; leave it empty
when only calling OpenAI. `PRAXIS_IMAGE` pins the workload image.

```bash
set +x
IFS= read -r -s -p 'OpenAI API key: ' OPENAI_API_KEY; printf '\n'
export OPENAI_API_KEY
export ANTHROPIC_API_KEY=''
IFS= read -r -p 'OpenAI model ID: ' MODEL_ID
export PRAXIS_IMAGE='quay.io/opendatahub/praxis-experimental@sha256:a3006352106c2264427faa79b57cf7b49287f3f9bfffe9b2eef869d3429988e8'
podman run --rm --detach --name praxis-demo \
  --user 1001:1001 --userns keep-id:uid=1001,gid=1001 \
  --read-only --security-opt no-new-privileges --cap-drop all \
  --publish 127.0.0.1:8080:8080 --publish 127.0.0.1:8081:8081 \
  --env OPENAI_API_KEY --env ANTHROPIC_API_KEY \
  --volume "$PWD/configs/all-in-one/shared-gateway.yaml:/etc/praxis/shared-gateway.yaml:ro,Z" \
  "$PRAXIS_IMAGE" -c /etc/praxis/shared-gateway.yaml
unset OPENAI_API_KEY ANTHROPIC_API_KEY
python3 -c 'import json,sys; print(json.dumps({"model":sys.argv[1],"messages":[{"role":"user","content":"Reply with a short greeting."}]}))' "$MODEL_ID" | \
  curl --fail-with-body --retry 10 --retry-connrefused --retry-delay 1 \
  http://127.0.0.1:8080/v1/chat/completions \
  -H 'Content-Type: application/json' -H 'Authorization: Bearer local-placeholder' -d @-
# When finished:
podman stop praxis-demo
```

This verifies the Praxis model route; it does not run an OpenShell sandbox.
The demo container receives the provider key through its environment. For
protected service-account secrets and startup at boot, use the deployment
guides. See [Podman details](../../testing/podman.md).

