#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
OS_DIR="${ROOT}/openshell"
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
# shellcheck source=../scripts/lib.sh
# shellcheck disable=SC1091
source "${OS_DIR}/scripts/lib.sh"

# 1a. Coordinated upstream control-plane images must be pinned by digest.
# (images.env already sourced by lib.sh)
for var in ODH_GATEWAY_IMAGE ODH_SUPERVISOR_IMAGE ODH_SANDBOX_IMAGE; do
  val="${!var:-}"
  [[ -n "${val}" ]] || fail "${var} unset"
  [[ "${val}" =~ ^ghcr\.io/nvidia/openshell/[^@]+@sha256:[a-f0-9]{64}$ ]] \
    || fail "${var} not a digest-pinned upstream image: ${val}"
done

# 1b. images.env must define three @sha256-pinned public aipcc harness images.
for var in ODH_OPENCODE_IMAGE ODH_CODEX_IMAGE; do
  val="${!var:-}"
  [[ -n "${val}" ]] || fail "${var} unset"
  [[ "${val}" =~ ^quay\.io/aipcc/base-images/agentic/[^@]+@sha256:[a-f0-9]{64}$ ]] \
    || fail "${var} not a digest-pinned aipcc image: ${val}"
done
[[ "${ODH_OPENCLAW_IMAGE}" =~ ^ghcr\.io/openclaw/openclaw@sha256:[a-f0-9]{64}$ ]] \
  || fail 'OpenClaw must use a valid digest-pinned upstream image'
[[ "${OPENSHELL_CLI_VERSION}" == v0.1.4 ]] || fail 'CLI release must match the control plane'
for digest in "${OPENSHELL_CLI_SHA256_AMD64}" "${OPENSHELL_CLI_SHA256_ARM64}"; do
  [[ "${digest}" =~ ^[a-f0-9]{64}$ ]] || fail 'CLI checksum missing or malformed'
done
[[ "${OPENSHELL_PROVER_VERSION}" == v0.1.4 ]] || fail 'prover release must match the control plane'
[[ "${OPENSHELL_PROVER_SHA256_AMD64}" =~ ^[a-f0-9]{64}$ ]] \
  || fail 'prover checksum missing or malformed'
arm64_prover_variable=OPENSHELL_PROVER_SHA256_ARM64
[[ -z "${!arm64_prover_variable:-}" ]] \
  || fail 'the reviewed v0.1.4 prover is AMD64-only; remove the ARM64 checksum'
python3 - "${OS_DIR}/configs/releases/v0.1.4.json" \
  "${ODH_GATEWAY_IMAGE}" "${ODH_SUPERVISOR_IMAGE}" "${ODH_SANDBOX_IMAGE}" \
  "${OPENSHELL_CLI_SHA256_AMD64}" "${OPENSHELL_CLI_SHA256_ARM64}" \
  "${OPENSHELL_PROVER_SHA256_AMD64}" <<'PY' || fail 'pins do not match the reviewed v0.1.4 release manifest'
import json
import sys

with open(sys.argv[1]) as manifest_file:
    manifest = json.load(manifest_file)
if manifest.get("prover_architectures") != ["amd64"]:
    raise SystemExit("the reviewed prover manifest must be AMD64-only")
# Compare the reviewed manifest against the values sourced from images.env.
# They are passed as arguments because sourced-but-unexported variables are
# invisible to os.environ in this subprocess.
expected = {
    "ODH_GATEWAY_IMAGE": (manifest["images"]["gateway"], sys.argv[2]),
    "ODH_SUPERVISOR_IMAGE": (manifest["images"]["supervisor"], sys.argv[3]),
    "ODH_SANDBOX_IMAGE": (manifest["images"]["sandbox"], sys.argv[4]),
    "OPENSHELL_CLI_SHA256_AMD64": (manifest["cli_sha256"]["amd64"], sys.argv[5]),
    "OPENSHELL_CLI_SHA256_ARM64": (manifest["cli_sha256"]["arm64"], sys.argv[6]),
    "OPENSHELL_PROVER_SHA256_AMD64": (manifest["prover_sha256"]["amd64"], sys.argv[7]),
}
mismatched = [name for name, (want, got) in expected.items() if got != want]
if mismatched:
    raise SystemExit("mismatched pins: " + ", ".join(mismatched))
PY

# 2. All shell scripts under openshell/ pass shellcheck.
command -v shellcheck >/dev/null 2>&1 || fail "shellcheck is required"
mapfile -t scripts < <(find "${OS_DIR}" -name '*.sh' -type f)
shellcheck -S style "${scripts[@]}" || fail "shellcheck failed"

# 3. Gateway quadlet template renders with no leftover placeholders.
tmp="$(mktemp)"
trap 'rm -f -- "${tmp}"' EXIT
render_openshell_template "${OS_DIR}/configs/quadlet/openshell-gateway.container.in" "${tmp}"
grep -q '@@' "${tmp}" && fail "unrendered placeholder in gateway quadlet"
grep -q "Image=${ODH_GATEWAY_IMAGE}" "${tmp}" || fail "gateway image not pinned in unit"
grep -q 'Pull=never' "${tmp}" || fail "gateway unit must set Pull=never"
grep -q 'Environment=OPENSHELL_TELEMETRY_ENABLED=false' "${tmp}" \
  || fail "gateway unit must disable OpenShell telemetry"
# 4. gateway.toml.in uses the podman driver, JWT auth, and pins workload/supervisor images.
gt="${OS_DIR}/configs/gateway/gateway.toml.in"
grep -q 'compute_driver *= *"podman"' "${gt}" || fail "gateway.toml not podman driver"
grep -q '\[openshell.gateway.gateway_jwt\]' "${gt}" || fail "gateway.toml missing JWT auth block"
grep -q '\[openshell.gateway.tls\]' "${gt}" || fail "gateway.toml missing TLS block"
grep -q 'operator_enabled *= *false' "${gt}" \
  || fail "gateway operator credential retrieval must remain disabled"
grep -q 'cert_path *= *"/var/lib/openshell/tls/server/tls.crt"' "${gt}" || fail "gateway TLS cert path missing"
grep -q 'key_path *= *"/var/lib/openshell/tls/server/tls.key"' "${gt}" || fail "gateway TLS key path missing"
grep -q 'client_ca_path *= *"/var/lib/openshell/tls/ca.crt"' "${gt}" || fail "gateway client CA path missing"
grep -q 'allow_unauthenticated_users = false' "${gt}" || fail "gateway must reject unauthenticated users"
grep -q '\[openshell.gateway.mtls_auth\]' "${gt}" || fail "gateway missing mTLS auth block"
awk '
  /^\[openshell\.gateway\.mtls_auth\]$/ { in_mtls=1; next }
  /^\[/ { in_mtls=0 }
  in_mtls && $0 ~ /^[[:space:]]*enabled[[:space:]]*=[[:space:]]*true[[:space:]]*$/ { found=1 }
  END { exit found ? 0 : 1 }
' "${gt}" || fail "gateway mTLS auth must be enabled"
grep -q 'disable_tls' "${gt}" && fail "gateway must not disable TLS"
grep -q 'grpc_endpoint' "${gt}" && fail "gateway must let the Podman driver derive the https endpoint"
grep -q 'supervisor_image *= *"@@ODH_SUPERVISOR_IMAGE@@"' "${gt}" || fail "supervisor image placeholder missing"
grep -q 'sandbox_runtime_image *= *"@@ODH_SANDBOX_IMAGE@@"' "${gt}" \
  || fail "sandbox runtime image placeholder missing"
grep -q 'default_image *= *"@@ODH_OPENCODE_IMAGE@@"' "${gt}" || fail "default_image must be an aipcc workload image (@@ODH_OPENCODE_IMAGE@@)"

# 4b. Harness creation applies bounded per-sandbox CPU and memory limits.
hl="${OS_DIR}/scripts/harness-lib.sh"
validate_with_resources() {  # <cpu> <memory>
  OPENSHELL_SANDBOX_CPU="$1" OPENSHELL_SANDBOX_MEMORY="$2" \
    bash -c 'source "$1"; validate_sandbox_resources' _ "${hl}"
}
# shellcheck disable=SC2016
grep -q ': "${OPENSHELL_SANDBOX_CPU:=2}"' "${hl}" || fail "harness CPU default missing"
# shellcheck disable=SC2016
grep -q ': "${OPENSHELL_SANDBOX_MEMORY:=4Gi}"' "${hl}" || fail "harness memory default missing"
# shellcheck disable=SC2016
grep -q -- '--cpu "${OPENSHELL_SANDBOX_CPU}"' "${hl}" || fail "explicit workload must pass --cpu"
# shellcheck disable=SC2016
grep -q -- '--memory "${OPENSHELL_SANDBOX_MEMORY}"' "${hl}" || fail "explicit workload must pass --memory"

# 4c. Zero and malformed resource values are rejected before sandbox create.
for bad_cpu in 0 0.0 0m -1 2x .5; do
  if validate_with_resources "${bad_cpu}" 4Gi >/dev/null 2>&1; then
    fail "invalid OPENSHELL_SANDBOX_CPU accepted: ${bad_cpu}"
  fi
done
for bad_memory in 0 0Gi -4Gi 4Xi Gi 1024B; do
  if validate_with_resources 2 "${bad_memory}" >/dev/null 2>&1; then
    fail "invalid OPENSHELL_SANDBOX_MEMORY accepted: ${bad_memory}"
  fi
done
for good_cpu in 1 2 0.5 500m; do
  validate_with_resources "${good_cpu}" 4Gi >/dev/null 2>&1 \
    || fail "valid OPENSHELL_SANDBOX_CPU rejected: ${good_cpu}"
done
for good_memory in 512Mi 4Gi 8G 1024; do
  validate_with_resources 2 "${good_memory}" >/dev/null 2>&1 \
    || fail "valid OPENSHELL_SANDBOX_MEMORY rejected: ${good_memory}"
done

# 5. Structural checks only; schema.py validates with the pinned native CLI.
policy_roots=(
  "${OS_DIR}"
  "${ROOT}/configs/openshell-praxis"
  "${ROOT}/configs/vllm/harness"
  "${ROOT}/configs/vllm/openclaw"
  "${ROOT}/configs/llm-d-sc"
)
for policy_root in "${policy_roots[@]}"; do
  [[ -d "${policy_root}" ]] || fail "policy root missing: ${policy_root}"
done
policy_files="$(find "${policy_roots[@]}" -path '*/profiles/*/policy.yaml' -type f -print)" \
  || fail "could not discover policy files"
[[ -n "${policy_files}" ]] || fail "no policy files found"
if command -v python3 >/dev/null 2>&1; then
  while IFS= read -r p; do
    python3 - "$p" <<'PY' || fail "invalid policy: $p"
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]).read()
                  .replace("@@PRAXIS_PORT@@", "8080")
                  .replace("@@PRAXIS_API_PREFIX@@", ""))
assert d.get("version") == 1, "version"
assert "network_policies" in d, "network_policies"
assert "filesystem_policy" in d, "filesystem_policy"
for name, policy in d["network_policies"].items():
    for endpoint in policy.get("endpoints", []):
        assert type(endpoint["port"]) is int and 1 <= endpoint["port"] <= 65535
        if name == "praxis_gateway" and endpoint.get("protocol") == "rest":
          chat = [{"method": "GET", "path": "/v1/models"},
                  {"method": "POST", "path": "/v1/chat/completions"}]
          responses = chat + [{"method": "POST", "path": "/v1/responses"}]
          assert [rule.get("allow") for rule in endpoint.get("rules", [])] in (chat, responses), \
                f"{name}: REST endpoint requires exact Praxis method/path rules"
        if name == "github_git":
            expected = [{"method": "GET", "path": "/**"},
                        {"method": "HEAD", "path": "/**"},
                        {"method": "OPTIONS", "path": "/**"},
                        {"method": "POST", "path": "/**/git-upload-pack"}]
            assert [rule.get("allow") for rule in endpoint.get("rules", [])] == expected, \
                f"{name}: Git endpoint must permit clone/fetch and deny push"
PY
  done <<<"${policy_files}"
fi

python3 "${OS_DIR}/tests/regressions.py"
python3 "${OS_DIR}/tests/cleanup.py"
python3 "${OS_DIR}/tests/templates.py"
python3 "${OS_DIR}/tests/pr-queue.py"
python3 "${OS_DIR}/tests/streamlit-security.py"
python3 "${OS_DIR}/tests/gateway.py"
python3 "${OS_DIR}/tests/policy-boundary.py"
printf 'openshell-static: OK\n'
