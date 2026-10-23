#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# shellcheck source=/dev/null
set -euo pipefail
umask 077

: "${DEMO_OPERATOR_ENV_FILE:?LaunchAgent must point to the private operator environment file}"
[[ -r "$DEMO_OPERATOR_ENV_FILE" ]] || { printf '%s\n' 'Private operator environment file is not readable' >&2; exit 2; }
source "$DEMO_OPERATOR_ENV_FILE"

for name in DEMO_PYTHON DEMO_KUBECONFIG DEMO_SERVER DEMO_FIXTURE_CREDENTIALS \
  DEMO_OPENSHELL_CLI DEMO_CLI_CONFIG DEMO_DRIVER_CREDENTIALS \
  DEMO_CATALOG_CREDENTIAL DEMO_INFERENCE_CONFIG DEMO_PRIVATE_ROOT; do
  if [[ -z "${!name:-}" ]]; then
    printf '%s\n' "Required private setting is missing: $name" >&2
    exit 2
  fi
done

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
worker="$repo_root/scripts/identity_demo/identity_demo_console_worker.py"
[[ -x "$DEMO_PYTHON" && -r "$worker" ]] || { printf '%s\n' 'Configured interpreter or worker is unavailable' >&2; exit 2; }
[[ -d "$DEMO_PRIVATE_ROOT" && ! -L "$DEMO_PRIVATE_ROOT" ]] || { printf '%s\n' 'Private output root is unavailable' >&2; exit 2; }

export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export PYTHONPATH="$repo_root/scripts/identity_demo:$repo_root/tests/identity_demo"
run_id="$("$DEMO_PYTHON" -c 'import uuid; print(uuid.uuid4().hex)')"
run_dir="$DEMO_PRIVATE_ROOT/console-worker-launch-$run_id"
[[ ! -e "$run_dir" && ! -L "$run_dir" ]] || { printf '%s\n' 'Private worker output path collision' >&2; exit 2; }

set --
if [[ -n "${DEMO_OPERATOR_LOGIN_FILE:-}" ]]; then
  set -- --operator-login-file "$DEMO_OPERATOR_LOGIN_FILE"
fi

if [[ "${DEMO_SERVICE_MODE:-coordinator}" == "preparer" ]]; then
  preparer_config="$DEMO_CLI_CONFIG"
  preparer_port=18443
  if [[ "${DEMO_POOL_MODE:-legacy}" == "automatic" ]]; then
    : "${DEMO_RUNTIME_CA:?Automatic preparation requires the verified runtime CA}"
    preparer_config="${DEMO_PREPARER_CLI_CONFIG:-$DEMO_PRIVATE_ROOT/cli-config-preparer}"
    preparer_port="${DEMO_PREPARER_MANAGEMENT_PORT:-18444}"
    [[ "$preparer_config" != "$DEMO_CLI_CONFIG" && "$preparer_port" != "${DEMO_MANAGEMENT_PORT:-18443}" ]] || { printf '%s\n' 'Separate preparer management profile and port required' >&2; exit 2; }
    mkdir -p "$preparer_config"
    chmod 700 "$preparer_config"
    set -- "$@" --ca-file "$DEMO_RUNTIME_CA" --initialize-management-profile
  fi
  exec "$DEMO_PYTHON" "$repo_root/scripts/identity_demo/identity_demo_console_preparer.py" \
    --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
    --credentials-file "$DEMO_FIXTURE_CREDENTIALS" \
    --cli "$DEMO_OPENSHELL_CLI" --cli-config-dir "$preparer_config" --management-port "$preparer_port" \
    --driver-credentials-file "$DEMO_DRIVER_CREDENTIALS" \
    --output-dir "$DEMO_PRIVATE_ROOT/console-preparer" "$@"
fi

if [[ "${DEMO_GATEWAY_MODE:-temporary}" == "persistent" ]]; then
  : "${DEMO_GATEWAY_RECEIPT:?Persistent mode requires the verified installation receipt}"
  set -- "$@" --gateway-mode persistent --gateway-receipt "$DEMO_GATEWAY_RECEIPT"
fi
exec "$DEMO_PYTHON" "$worker" \
  --kubeconfig "$DEMO_KUBECONFIG" --expected-server "$DEMO_SERVER" \
  --credentials-file "$DEMO_FIXTURE_CREDENTIALS" \
  --cli "$DEMO_OPENSHELL_CLI" --cli-config-dir "$DEMO_CLI_CONFIG" \
  --catalog-credential-file "$DEMO_CATALOG_CREDENTIAL" \
  --driver-credentials-file "$DEMO_DRIVER_CREDENTIALS" \
  --inference-config "$DEMO_INFERENCE_CONFIG" \
  --output-dir "$run_dir" --management-port "${DEMO_MANAGEMENT_PORT:-18443}" "$@" --auto-refresh-catalog --auto-refresh-sender-trust
