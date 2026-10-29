#!/usr/bin/env bash
set -euo pipefail

DEMO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX="${OPENSHELL_SANDBOX_NAME:-streamlit-demo}"
IMAGE="openshell-streamlit-demo:safe"
PROVIDER="${STREAMLIT_DEMO_PROVIDER:?export STREAMLIT_DEMO_PROVIDER, for example streamlit-demo-openai}"
MODEL_BASE_URL="${MODEL_BASE_URL:?export MODEL_BASE_URL, for example https://api.openai.com/v1}"
OPENAI_MODEL="${OPENAI_MODEL:?export OPENAI_MODEL, for example gpt-5.5}"

python3 - "${SANDBOX}" "${PROVIDER}" "${MODEL_BASE_URL}" "${OPENAI_MODEL}" <<'PY'
import re
import sys
from urllib.parse import urlsplit

sandbox, provider, base_url, model = sys.argv[1:]
name_pattern = r"[a-z][a-z0-9-]{0,62}"
if not re.fullmatch(name_pattern, sandbox):
    raise SystemExit("error: sandbox name must be a lowercase DNS-style name")
if not re.fullmatch(name_pattern, provider):
    raise SystemExit("error: provider name must be a lowercase DNS-style name")
if not re.fullmatch(r"[A-Za-z0-9._:/-]+", model):
    raise SystemExit("error: model name contains unsupported characters")
url = urlsplit(base_url)
if (
    url.scheme not in {"http", "https"}
    or not url.hostname
    or url.username is not None
    or url.password is not None
    or url.query
    or url.fragment
    or any(character.isspace() for character in base_url)
):
    raise SystemExit(
        "error: MODEL_BASE_URL must be an HTTP(S) URL without userinfo, query, or fragment"
    )
try:
    port = url.port
except ValueError as error:
    raise SystemExit("error: MODEL_BASE_URL has an invalid port") from error
if url.scheme == "http" and (
    url.hostname not in {"host.openshell.internal", "host.containers.internal"}
    or port != 18080
):
    raise SystemExit(
        "error: MODEL_BASE_URL must use HTTPS outside the OpenShell proxy on port 18080"
    )
PY

cd "${DEMO_DIR}"
podman build -t "${IMAGE}" .

SERVICES="$(openshell service list --output json)" || {
  printf 'error: could not list OpenShell services\n' >&2
  exit 1
}
SERVICE_NAMES="$(python3 -c '
import json
import sys
document = json.load(sys.stdin)
if not isinstance(document, dict) or not isinstance(document.get("services"), list):
    raise ValueError("service list must contain a services array")
if document.get("next_page_token"):
    raise ValueError("service list is paginated; refusing incomplete cleanup")
for service in document["services"]:
    if not isinstance(service, dict):
        raise ValueError("service entry must be an object")
    sandbox, name = service.get("sandbox"), service.get("service")
    if not isinstance(sandbox, str) or not isinstance(name, str):
        raise ValueError("service entry has invalid sandbox or service name")
    print(sandbox + "/" + name)
' <<<"${SERVICES}")" || {
  printf 'error: OpenShell returned an invalid service list\n' >&2
  exit 1
}
if grep -Fxq "${SANDBOX}/streamlit" <<<"${SERVICE_NAMES}"; then
  openshell service delete "${SANDBOX}" streamlit >/dev/null || {
    printf 'error: could not remove the existing Streamlit service\n' >&2
    exit 1
  }
fi

SANDBOX_NAMES="$(openshell sandbox list --names)" || {
  printf 'error: could not list OpenShell sandboxes\n' >&2
  exit 1
}
if grep -Fxq "${SANDBOX}" <<<"${SANDBOX_NAMES}"; then
  openshell sandbox delete "${SANDBOX}" >/dev/null || {
    printf 'error: could not delete the existing sandbox %s\n' "${SANDBOX}" >&2
    exit 1
  }
fi
for _ in $(seq 1 30); do
  SANDBOX_NAMES="$(openshell sandbox list --names)" || {
    printf 'error: could not check whether sandbox %s was deleted\n' "${SANDBOX}" >&2
    exit 1
  }
  if ! grep -Fxq "${SANDBOX}" <<<"${SANDBOX_NAMES}"; then
    break
  fi
  sleep 1
done
if grep -Fxq "${SANDBOX}" <<<"${SANDBOX_NAMES}"; then
  printf 'error: sandbox %s did not finish deleting\n' "${SANDBOX}" >&2
  exit 1
fi
openshell sandbox create \
  --name "${SANDBOX}" \
  --from "${IMAGE}" \
  --policy policy.yaml \
  --provider "${PROVIDER}" \
  --detach \
  --no-tty \
  --env DEMO_MODE=safe \
  --env STREAMLIT_DEMO_PROVIDER="${PROVIDER}" \
  --env MODEL_BASE_URL="${MODEL_BASE_URL}" \
  --env OPENAI_MODEL="${OPENAI_MODEL}" \
  --env DEMO_MARKER=demo-not-a-real-secret \
  --env HOME=/tmp \
  --env STREAMLIT_SERVER_FILE_WATCHER_TYPE=none \
  --env STREAMLIT_BROWSER_GATHER_USAGE_STATS=false \
  -- /usr/local/bin/python3.12 -m streamlit run /opt/openshell-demo/app.py \
    --server.port=8501 \
    --server.address=0.0.0.0 \
    --server.corsAllowedOrigins "http://default--${SANDBOX}--streamlit.openshell.localhost:8090" \
    --server.headless=true

openshell service expose "${SANDBOX}" 8501 streamlit
