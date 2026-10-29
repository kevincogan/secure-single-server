#!/usr/bin/env bash
# Source from the repository root in Bash or zsh. No cloud calls on load.
# Call functions in `if` or `||` guards, including when the caller has errexit.

if [ ! -f scripts/aws/rhel-vm ]; then
  printf 'Run from the reviewed secure-single-server repository root.\n' >&2
  return 1
fi
AWS_TEST_REPO="$PWD"

_aws_test_error() {
  printf 'error: %s\n' "$*" >&2
  return 1
}

_aws_test_prompt() {
  if [ ! -t 0 ]; then
    _aws_test_error 'Credential prompts require an interactive terminal; do not pipe input.'
    return 1
  fi
  printf '%s: ' "$2" >&2
  if IFS= read -r -s "$1"; then
    printf '\n' >&2
  else
    printf '\n' >&2
    _aws_test_error 'Input cancelled; no credentials loaded.'
    return 1
  fi
}

aws_test_credentials() {
  set +x
  set +a
  local test_access='' test_secret='' test_token=''
  unset AWS_TEST_CREDENTIALS AWS_TEST_READY AWS_TEST_PLAN_INPUTS RHEL_HOST RHEL_SCENARIO RHEL_INFERENCE RHEL_VPC_ID RHEL_STATE_FILE ALL_IN_ONE_HOST REMOTE_GATEWAY_HOST REMOTE_HOST OPENSHELL_HOST
  unset AWS_PROFILE AWS_DEFAULT_PROFILE AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
  _aws_test_prompt test_access 'AWS access key ID' || return 1
  if [ -z "$test_access" ]; then
    _aws_test_error 'Access key ID is required; rerun the credential step.'
    return 1
  fi
  _aws_test_prompt test_secret 'AWS secret access key' || return 1
  if [ -z "$test_secret" ]; then
    _aws_test_error 'Secret access key is required; rerun the credential step.'
    return 1
  fi
  _aws_test_prompt test_token 'AWS session token (Enter for long-lived IAM keys)' || return 1
  export AWS_ACCESS_KEY_ID="$test_access" AWS_SECRET_ACCESS_KEY="$test_secret"
  if [ -n "$test_token" ]; then export AWS_SESSION_TOKEN="$test_token"; fi
  export AWS_PAGER=''
  AWS_TEST_CREDENTIALS=ready
  printf 'Credentials loaded in this terminal only; not yet validated against AWS.\n'
}

_aws_test_identity_ready() {
  if [ "${AWS_TEST_CREDENTIALS:-}" != ready ] || [ -z "${AWS_ACCESS_KEY_ID:-}" ] ||
      [ -z "${AWS_SECRET_ACCESS_KEY:-}" ]; then
    _aws_test_error 'Load credentials first.'
    return 1
  fi
  if [ -z "${REGION:-}" ] || [ -z "${RUN_PREFIX:-}" ]; then
    _aws_test_error 'Run the settings block first.'
    return 1
  fi
}

aws_test_discover() {
  local test_tool test_identity test_principal test_subnets test_ip test_subnet test_cidr
  unset AWS_TEST_READY AWS_TEST_PLAN_INPUTS ACCOUNT RHEL_HOST RHEL_SCENARIO RHEL_INFERENCE RHEL_VPC_ID RHEL_STATE_FILE ALL_IN_ONE_HOST REMOTE_GATEWAY_HOST REMOTE_HOST OPENSHELL_HOST
  _aws_test_identity_ready || return 1
  for test_tool in aws python3 jq curl ssh ssh-keygen; do
    command -v "$test_tool" >/dev/null 2>&1 || {
      _aws_test_error "Install missing prerequisite: $test_tool"
      return 1
    }
  done
  python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' || {
    _aws_test_error 'Python 3.9 or newer is required.'
    return 1
  }
  test_identity=$(aws --region "$REGION" sts get-caller-identity --output json) || return 1
  ACCOUNT=$(printf '%s' "$test_identity" | jq -er '.Account | select(test("^[0-9]{12}$"))') || return 1
  test_principal=$(printf '%s' "$test_identity" | jq -er '.Arn') || return 1
  case "$test_principal" in
    *:root) _aws_test_error 'Root-account credentials are refused.'; return 1 ;;
  esac
  printf 'AWS account: %s\nPrincipal: %s\n' "$ACCOUNT" "$test_principal"
  test_subnet=${SUBNET:-}
  if [ -z "$test_subnet" ]; then
    test_subnets=$(aws --region "$REGION" ec2 describe-subnets \
      --filters Name=default-for-az,Values=true Name=state,Values=available \
        "Name=owner-id,Values=$ACCOUNT" --output json) || return 1
    test_subnet=$(printf '%s' "$test_subnets" | jq -er '
      .Subnets | map(select(.AvailableIpAddressCount > 0)) |
      sort_by(.AvailabilityZone, .SubnetId) | .[0].SubnetId //
      error("No available default subnet. Set SUBNET to an approved public subnet.")') || return 1
  fi
  test_cidr=${CLIENT_CIDR:-}
  if [ -z "$test_cidr" ]; then
    test_ip=$(curl -4 -fsS --connect-timeout 5 --max-time 10 https://checkip.amazonaws.com) || return 1
    test_cidr="$test_ip/32"
  fi
  test_cidr=$(python3 -c '
import ipaddress, sys
try:
    network = ipaddress.ip_network(sys.argv[1], strict=True)
    if network.version != 4 or network.prefixlen != 32:
        raise ValueError("not an IPv4 host")
except ValueError:
    sys.exit("Allowed source must be one IPv4 /32; check CLIENT_CIDR or IP detection.")
print(network)' "$test_cidr") || return 1
  SUBNET="$test_subnet"
  CLIENT_CIDR="$test_cidr"
  AWS_TEST_READY=ready
  printf 'Region: %s\nSubnet: %s\nAllowed source: %s\nSSH key: %s\nRun prefix: %s\n' \
    "$REGION" "$SUBNET" "$CLIENT_CIDR" "${SSH_KEY:-not set}" "$RUN_PREFIX"
  if [ ! -r "${SSH_KEY:-}.pub" ]; then
    printf 'Next: run aws_test_key, then aws_test_plan NAME CONFIG --scenario ROLE.\n'
  else
    printf 'Public key exists. Next: aws_test_plan NAME CONFIG --scenario ROLE.\n'
  fi
}

aws_test_key() {
  local test_key_dir
  case "${SSH_KEY:-}" in
    /*) ;;
    *) _aws_test_error 'Set SSH_KEY to an absolute path in a dedicated private directory.'; return 1 ;;
  esac
  if [ -e "$SSH_KEY" ] || [ -L "$SSH_KEY" ] || [ -e "$SSH_KEY.pub" ] || [ -L "$SSH_KEY.pub" ]; then
    _aws_test_error 'Key path already exists; nothing overwritten. Choose a new SSH_KEY, or reuse your existing test key at the plan step.'
    return 1
  fi
  test_key_dir=$(dirname "$SSH_KEY") || return 1
  case "$test_key_dir" in
    /|"${HOME:-}"|"$AWS_TEST_REPO")
      _aws_test_error 'Use a dedicated key directory, not a filesystem, home or repository root.'
      return 1 ;;
  esac
  install -d -m 0700 "$test_key_dir" || return 1
  ssh-keygen -q -t ed25519 -f "$SSH_KEY" -C "${RUN_PREFIX:-secure-single-server-test}" || return 1
  chmod 0600 "$SSH_KEY" || return 1
  printf 'Private test key: %s\nOnly %s.pub will be imported.\n' "$SSH_KEY" "$SSH_KEY"
}

# One named VM per call. Settings belong to that call, never a global scenario list.
_aws_test_name() {
  local test_name=${1:-} test_valid=yes
  case "$test_name" in ''|[!a-z]*|*[!a-z0-9-]*) test_valid=no ;; esac
  if [ "$test_valid" != yes ] || [ "${#test_name}" -gt 20 ]; then
    _aws_test_error 'Supply one VM name: 1-20 lowercase letters/digits/hyphens, starting with a letter.'
    return 1
  fi
}

_aws_test_vm() {
  python3 "$AWS_TEST_REPO/scripts/aws/rhel-vm" "$@"
}

_aws_test_launch() {
  local test_mode=$1 test_name=${2:-} test_config=${3:-} test_scenario=''
  _aws_test_identity_ready || return 1
  _aws_test_name "$test_name" || return 1
  if [ "${AWS_TEST_READY:-}" != ready ] || [ -z "${ACCOUNT:-}" ] ||
      [ -z "${SUBNET:-}" ] || [ -z "${CLIENT_CIDR:-}" ] || [ -z "${SSH_KEY:-}" ]; then
    _aws_test_error 'Complete settings and successful discovery before deploying.'
    return 1
  fi
  if [ ! -r "$SSH_KEY.pub" ]; then
    _aws_test_error "Missing or unreadable public key: $SSH_KEY.pub. Run aws_test_key before aws_test_plan. If the private key already exists, recover its public key; do not overwrite the private key."
    return 1
  fi
  if [ -z "$test_config" ] || [ ! -r "$test_config" ]; then
    _aws_test_error 'Supply a readable VM configuration, for example configs/aws/vllm-gpu.json.'
    return 1
  fi
  shift 3
  # Only resource overrides; account, prefix, journal and confirmation stay bounded.
  local test_overrides=(--subnet-id "$SUBNET")
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --scenario|--inference|--arch|--instance-type|--volume-gib|--ami-id|--subnet-id|--ssh-access|--https-access|--allowed-cidr)
        if [ "$#" -lt 2 ]; then _aws_test_error "Missing value for $1"; return 1; fi
        if [ "$1" = --scenario ]; then test_scenario=$2; fi
        test_overrides+=("$1" "$2")
        shift 2 ;;
      *) _aws_test_error "Unsupported override: $1"; return 1 ;;
    esac
  done
  case "$test_scenario" in
    all-in-one|remote-gateway|openshell-praxis|vllm-server) ;;
    *) _aws_test_error 'Supply --scenario all-in-one, remote-gateway, openshell-praxis or vllm-server; hardware presets do not choose the role.'; return 1 ;;
  esac
  case "$test_name" in
    all-in-one|remote-gateway|openshell-praxis|vllm-server)
      if [ "$test_name" != "$test_scenario" ]; then
        _aws_test_error "VM name $test_name must use --scenario $test_name."
        return 1
      fi ;;
  esac
  _aws_test_vm "$test_mode" --config "$test_config" --region "$REGION" --account-id "$ACCOUNT" \
    --public-key "$SSH_KEY.pub" --allowed-cidr "$CLIENT_CIDR" \
    --prefix "$RUN_PREFIX-$test_name" --state-file "$AWS_TEST_REPO/.state/$RUN_PREFIX-$test_name.json" \
    "${test_overrides[@]}" || return 1
}

aws_test_plan() {
  _aws_test_launch plan "$@"
}

aws_test_capacity() {
  _aws_test_identity_ready || return 1
  if [ "$#" -ne 1 ] || [ -z "${ACCOUNT:-}" ] || [ -z "${SUBNET:-}" ]; then
    _aws_test_error 'Run discovery, then aws_test_capacity INSTANCE_TYPE (for example g6.2xlarge).'
    return 1
  fi
  _aws_test_vm capacity --region "$REGION" --account-id "$ACCOUNT" \
    --instance-type "$1" --subnet-id "$SUBNET" || return 1
}

aws_test_deploy() {
  # apply re-plans the current inputs and requires typed confirmation itself.
  # rhel-vm reconciles retryable launch journals; completed/unrelated launches are refused.
  _aws_test_launch apply "$@"
}

aws_test_apply() {
  # Replace a previously sourced batch implementation too; never leave it callable.
  _aws_test_error 'Batch aws_test_apply was removed. Use aws_test_deploy NAME CONFIG --scenario ROLE for one VM.'
}

aws_test_verify() {
  local test_name=${1:-} test_info test_ip test_scenario test_inference test_vpc
  unset RHEL_HOST RHEL_SCENARIO RHEL_INFERENCE RHEL_VPC_ID RHEL_STATE_FILE
  _aws_test_identity_ready || return 1
  _aws_test_name "$test_name" || return 1
  if [ "$#" -ne 1 ]; then _aws_test_error 'Verify takes exactly one VM name.'; return 1; fi
  if [ -z "${ACCOUNT:-}" ]; then _aws_test_error 'Discover or set the recorded account first.'; return 1; fi
  test_info=$(_aws_test_vm verify --region "$REGION" --account-id "$ACCOUNT" \
    --state-file "$AWS_TEST_REPO/.state/$RUN_PREFIX-$test_name.json") || return 1
  printf '%s\n' "$test_info"
  test_ip=$(printf '%s' "$test_info" | jq -er 'select(.State == "running") | .PublicIpAddress // empty') || {
    _aws_test_error "$test_name must be running with a public IP; wait and rerun verify."
    return 1
  }
  test_scenario=$(printf '%s' "$test_info" | jq -er '.Scenario | select(. == "all-in-one" or . == "remote-gateway" or . == "openshell-praxis" or . == "vllm-server")') || return 1
  test_inference=$(printf '%s' "$test_info" | jq -er '.Inference | select(. == "cpu" or . == "gpu" or . == "none")') || return 1
  test_vpc=$(printf '%s' "$test_info" | jq -er '.VpcId | select(. != null)') || return 1
  RHEL_HOST="ec2-user@$test_ip"
  RHEL_SCENARIO="$test_scenario"
  RHEL_INFERENCE="$test_inference"
  RHEL_VPC_ID="$test_vpc"
  RHEL_STATE_FILE="$AWS_TEST_REPO/.state/$RUN_PREFIX-$test_name.json"
  printf '%s login: %s\nJournal: %s/.state/%s-%s.json\nSSH key: %s\n' \
    "$test_name" "$RHEL_HOST" "$AWS_TEST_REPO" "$RUN_PREFIX" "$test_name" "${SSH_KEY:-not set}"
  printf 'Selected for testing: %s / %s inference (RHEL_HOST, RHEL_SCENARIO, RHEL_INFERENCE, RHEL_VPC_ID).\n' "$RHEL_SCENARIO" "$RHEL_INFERENCE"
}

_aws_test_vllm_grant() {
  local test_mode=$1 test_client=${2:-} test_vllm=${3:-vllm-server}
  if [ "$#" -gt 3 ]; then _aws_test_error 'vLLM grant takes CLIENT [VLLM_SERVER].'; return 1; fi
  _aws_test_identity_ready || return 1
  if [ -z "${ACCOUNT:-}" ]; then _aws_test_error 'Discover or set the recorded account first.'; return 1; fi
  _aws_test_name "$test_client" || return 1
  _aws_test_name "$test_vllm" || return 1
  if [ "$test_client" = "$test_vllm" ]; then
    _aws_test_error 'Client and vLLM VM names must differ.'
    return 1
  fi
  local test_args=(vllm-grant --region "$REGION" --account-id "$ACCOUNT"
    --client-state-file "$AWS_TEST_REPO/.state/$RUN_PREFIX-$test_client.json"
    --vllm-state-file "$AWS_TEST_REPO/.state/$RUN_PREFIX-$test_vllm.json")
  if [ "$test_mode" = apply ]; then test_args+=(--apply); fi
  _aws_test_vm "${test_args[@]}"
}

aws_test_vllm_grant() {
  _aws_test_vllm_grant plan "$@"
}

aws_test_vllm_grant_apply() {
  _aws_test_vllm_grant apply "$@"
}

aws_test_vllm_endpoint() {
  local test_vllm=${1:-vllm-server}
  if [ "$#" -gt 1 ]; then _aws_test_error 'vLLM endpoint takes [VLLM_SERVER].'; return 1; fi
  _aws_test_identity_ready || return 1
  if [ -z "${ACCOUNT:-}" ]; then _aws_test_error 'Discover or set the recorded account first.'; return 1; fi
  _aws_test_name "$test_vllm" || return 1
  local test_args=(vllm-endpoint --region "$REGION" --account-id "$ACCOUNT"
    --vllm-prefix "$RUN_PREFIX-$test_vllm")
  if [ -z "${RHEL_VPC_ID:-}" ] || [ -z "${RHEL_SCENARIO:-}" ] || [ -z "${RHEL_STATE_FILE:-}" ]; then
    _aws_test_error 'Verify the single server first so vLLM endpoint discovery can check the VPC.'
    return 1
  fi
  case "$RHEL_SCENARIO" in
    all-in-one|remote-gateway|openshell-praxis) ;;
    *)
      _aws_test_error 'Verify the single server first so vLLM endpoint discovery can check the VPC.'
      return 1
      ;;
  esac
  test_args+=(--client-state-file "$RHEL_STATE_FILE" --client-vpc-id "$RHEL_VPC_ID")
  _aws_test_vm "${test_args[@]}"
}

aws_test_ssh() {
  if [ ! -f "${SSH_KEY:-}" ]; then
    _aws_test_error 'Set SSH_KEY to the matching private test key.'
    return 1
  fi
  aws_test_verify "$@" || return 1
  ssh -o IdentitiesOnly=yes -o ForwardAgent=no -i "$SSH_KEY" "$RHEL_HOST"
}

printf 'Loaded AWS helpers: one named VM per plan/deploy. Existing credentials and run settings preserved.\n'
