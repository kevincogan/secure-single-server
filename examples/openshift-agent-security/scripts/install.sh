#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build the reviewed installer on OpenShift. No local Python, Rust or engine.
set -euo pipefail
umask 077
usage() { echo 'Usage: scripts/install.sh build|status|prepare|bootstrap|install|observe|finalize --config FILE --kubeconfig FILE --output-dir PRIVATE_DIR' >&2; exit 2; }
[[ $# -ge 1 ]] || usage
action=$1; shift
case $action in
  prepare|bootstrap|install|observe|finalize)
    exec bash "$(dirname "$0")/identity_demo/cluster_install_launch.sh" "$action" "$@";;
esac
config='' kubeconfig='' out='' namespace_receipt='' namespace_receipt_sha='' attempt='' expected_server=''
while [[ $# -gt 0 ]]; do
  [[ $# -ge 2 ]] || usage
  case $1 in
    --config) config=$2;; --kubeconfig) kubeconfig=$2;; --output-dir) out=$2;;
    --namespace-receipt) namespace_receipt=$2;; --namespace-receipt-sha256) namespace_receipt_sha=$2;;
    --attempt-id) attempt=$2;; --expected-server) expected_server=$2;; *) usage;;
  esac
  shift 2
done
[[ $action == build || $action == status ]] || usage
[[ -f $config && ! -L $config && -f $kubeconfig && ! -L $kubeconfig && $out == /* && ! -L $out ]] || usage
command -v oc >/dev/null
root=$(cd "$(dirname "$0")/.." && pwd -P)
# oc supplies a YAML/JSON parser; shell values are validated before rendering.
api=(oc --kubeconfig "$kubeconfig" --request-timeout=30s)
namespace=$("${api[@]}" create --dry-run=client --validate=false -f "$config" -o jsonpath='{.metadata.namespace}')
owner=$("${api[@]}" create --dry-run=client --validate=false -f "$config" -o jsonpath='{.metadata.labels.identity-demo-owner}')
installation=$("${api[@]}" create --dry-run=client --validate=false -f "$config" -o jsonpath='{.metadata.labels.identity-demo-installation}')
kind=$("${api[@]}" create --dry-run=client --validate=false -f "$config" -o jsonpath='{.kind}')
[[ $kind == ConfigMap && $namespace =~ ^[a-z0-9][a-z0-9-]{0,62}$ && $owner =~ ^[a-z0-9][a-z0-9-]{0,62}$ && $installation =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] || { echo 'Invalid installation metadata' >&2; exit 1; }
# Match a declared API target before any cluster write. Legacy image-build
# metadata can supply the same target explicitly; status remains read-only.
if [[ $action == build ]]; then
  parser_dir=$(mktemp -d "${TMPDIR:-/tmp}/identity-installer-target.XXXXXX")
  trap 'rm -rf "$parser_dir"' EXIT
  "${api[@]}" create --dry-run=client --validate=false -f "$config" -o jsonpath='{.data.installation\.json}' > "$parser_dir/body.json"
  if [[ -s $parser_dir/body.json ]]; then
    printf '{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"fixture-local-target"},"configuration":' > "$parser_dir/parser.json"
    cat "$parser_dir/body.json" >> "$parser_dir/parser.json"
    printf '}\n' >> "$parser_dir/parser.json"
    declared=$("${api[@]}" create --dry-run=client --validate=false -f "$parser_dir/parser.json" -o jsonpath='{.configuration.profile.expected_server}')
    [[ -z $expected_server || $expected_server == "$declared" ]] || { echo 'Conflicting API targets' >&2; exit 1; }
    expected_server=$declared
  fi
  selected=$("${api[@]}" config view --minify --raw -o jsonpath='{.clusters[0].cluster.server}')
  [[ $expected_server == https://* && ${selected%/} == "${expected_server%/}" ]] || { echo 'Exact declared TLS API target required before building; use the versioned configuration or --expected-server.' >&2; exit 1; }
fi
core_namespace=$namespace
namespace=$core_namespace-build
[[ ${#namespace} -le 63 ]] || { echo 'Bootstrap namespace name too long' >&2; exit 1; }
[[ -z $attempt || $attempt =~ ^[a-z0-9]{1,8}$ ]] || usage
if [[ $action == build ]]; then
  [[ ! -e $out ]] || { echo 'Output exists; inspect its receipts and use status, never repeat a submission.' >&2; exit 1; }
  mkdir -m 700 "$out"
  mkdir -m 700 "$out/context" "$out/context/source"
  cd "$root"
  # Read only inventory-listed source, never a checkout-wide tar or .git.
  awk -F'"' '/"path":/ {p=$4} /"sha256":/ {if(p=="") exit 1; print $4 "  " p; p=""}' export-manifest.json > "$out/source.sha256"
  [[ -s $out/source.sha256 ]] || { echo 'Reviewed source inventory required' >&2; exit 1; }
  if command -v sha256sum >/dev/null; then hash=(sha256sum); else hash=(shasum -a 256); fi
  : > "$out/source-files.txt"
  while read -r digest path; do
    [[ $digest =~ ^[a-f0-9]{64}$ && $path =~ ^[A-Za-z0-9_.:/-]+$ && $path != /* && $path != *..* && $path != *.private.* ]] || { echo 'Unsafe inventory entry' >&2; exit 1; }
    case $path in
      .gitignore|AGENTS.md|LICENSE|README.md|GETTING-STARTED.md|Makefile|pytest.ini|config/*|docs/*|examples/*|infra/*|runtime/*|scripts/*|tests/*|workloads/*) ;;
      *) echo 'Unapproved source root' >&2; exit 1;;
    esac
    [[ -f $path && ! -L $path ]] || { echo 'Regular inventoried source required' >&2; exit 1; }
    case $path in
      */.git/*|*/.env|*/.env.*|*.key|*.pem|*.crt|*.p12|*.kubeconfig|*.db|*.sqlite|*.sqlite3) echo 'Private/generated file refused' >&2; exit 1;;
    esac
    printf '%s\n' "$path" >> "$out/source-files.txt"
  done < "$out/source.sha256"
  [[ $(sort "$out/source-files.txt" | uniq -d | wc -l | tr -d ' ') == 0 ]] || { echo 'Duplicate source path' >&2; exit 1; }
  [[ -z $(find config docs examples infra runtime scripts tests workloads -type l -print) ]] || { echo 'Source symlink refused' >&2; exit 1; }
  "${hash[@]}" -c "$out/source.sha256" > "$out/source-check.private.log"
  # A second, complete Python scan runs in the credential-free image build.
  # This pre-upload check emits paths only and catches common private literals.
  : > "$out/private-patterns.private.log"
  while IFS= read -r path; do
    if grep -El '(openshiftapps\.com|devshift\.net|/(Users|home)/[A-Za-z0-9_.-]+/|sha256~[A-Za-z0-9_-]{30,}|github_pat_[A-Za-z0-9_]{30,}|gh[pousr]_[A-Za-z0-9]{30,})' "$path" >> "$out/private-patterns.private.log"; then
      echo 'Private-data pattern found; inspect the private report before uploading.' >&2; exit 1
    else
      result=$?
      [[ $result == 1 ]] || { echo 'Source scan failed; no upload permitted.' >&2; exit 1; }
    fi
  done < "$out/source-files.txt"
  printf '%s\n' export-manifest.json >> "$out/source-files.txt"
  tar -cf - -T "$out/source-files.txt" | tar -xf - -C "$out/context/source"
  cp infra/identity-demo/installer.Containerfile "$out/context/Containerfile"
  source_hash=$("${hash[@]}" export-manifest.json | awk '{print $1}')
  name=fixture-agent-installer-${source_hash:0:12}${attempt:+-$attempt}
  printf '%s\n' "$name" > "$out/build-config-name.txt"
  base=$(sed -n 's/.*"python_base": "\([^"]*\)".*/\1/p' infra/identity-demo/console-runtime.lock.json)
  rpms=$(sed -n '/"python_rpms": \[/,/\]/p' infra/identity-demo/console-runtime.lock.json | sed -n 's/^[[:space:]]*"\([A-Za-z0-9_.-]*\)"[,]*$/\1/p' | tr '\n' ' ')
  extras=$(sed -n '/"extra_rpms": \[/,/\]/p' infra/identity-demo/installer.lock.json | sed -n 's/^[[:space:]]*"\([A-Za-z0-9_.-]*\)"[,]*$/\1/p' | tr '\n' ' ')
  rpms="$rpms $extras"
  rpm_hash=$(sed -n 's/.*"rpm_manifest_sha256": "\([a-f0-9]*\)".*/\1/p' infra/identity-demo/installer.lock.json)
  [[ $source_hash =~ ^[a-f0-9]{64}$ && $base =~ ^[a-z0-9./:@-]+$ && $base == *@sha256:* && -n $rpms && $rpm_hash =~ ^[a-f0-9]{64}$ ]] || { echo 'Pinned build inputs required' >&2; exit 1; }
  "${api[@]}" get namespace "$namespace" --ignore-not-found -o json > "$out/namespace-before.private.json"
  if [[ -s $out/namespace-before.private.json ]]; then
    [[ -n $namespace_receipt && -f $namespace_receipt && ! -L $namespace_receipt && -O $namespace_receipt && $namespace_receipt_sha =~ ^[a-f0-9]{64}$ ]] || { echo 'Existing bootstrap namespace requires its original private creation receipt and hash.' >&2; exit 1; }
    [[ $("${hash[@]}" "$namespace_receipt" | awk '{print $1}') == "$namespace_receipt_sha" ]] || { echo 'Namespace receipt hash mismatch' >&2; exit 1; }
    recorded_uid=$("${api[@]}" create --dry-run=client --validate=false -f "$namespace_receipt" -o jsonpath='{.metadata.uid}')
    recorded_name=$("${api[@]}" create --dry-run=client --validate=false -f "$namespace_receipt" -o jsonpath='{.metadata.name}')
    live_uid=$("${api[@]}" get namespace "$namespace" -o jsonpath='{.metadata.uid}')
    live_owner=$("${api[@]}" get namespace "$namespace" -o jsonpath='{.metadata.labels.identity-demo-owner}')
    live_installation=$("${api[@]}" get namespace "$namespace" -o jsonpath='{.metadata.labels.identity-demo-installation}')
    [[ -n $recorded_uid && $recorded_name == "$namespace" && $recorded_uid == "$live_uid" && $live_owner == "$owner" && $live_installation == "$installation" ]] || { echo 'Namespace identity or ownership mismatch' >&2; exit 1; }
    cp "$namespace_receipt" "$out/namespace.retained.private.json"
  else
    [[ -z $namespace_receipt && -z $namespace_receipt_sha ]] || { echo 'Namespace receipt cannot authorize a replacement namespace.' >&2; exit 1; }
  cat > "$out/namespace.plan.json" <<EOF
{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"$namespace","labels":{"identity-demo-owner":"$owner","identity-demo-installation":"$installation","app.kubernetes.io/part-of":"identity-demo-preflight"}}}
EOF
  "${api[@]}" create --dry-run=server -f "$out/namespace.plan.json" > "$out/namespace.admission.private.log"
  cp "$out/namespace.plan.json" "$out/namespace.pending.json"
  "${api[@]}" create -f "$out/namespace.plan.json" -o json > "$out/namespace.created.private.json"
  fi
  cat > "$out/imagestream.plan.json" <<EOF
{"apiVersion":"image.openshift.io/v1","kind":"ImageStream","metadata":{"name":"$name","namespace":"$namespace","labels":{"identity-demo-owner":"$owner","identity-demo-installation":"$installation","app.kubernetes.io/part-of":"identity-demo-preflight"}}}
EOF
  cat > "$out/buildconfig.plan.json" <<EOF
{"apiVersion":"build.openshift.io/v1","kind":"BuildConfig","metadata":{"name":"$name","namespace":"$namespace","labels":{"identity-demo-owner":"$owner","identity-demo-installation":"$installation","app.kubernetes.io/part-of":"identity-demo-preflight"}},"spec":{"runPolicy":"Serial","nodeSelector":{"kubernetes.io/arch":"amd64"},"serviceAccount":"builder","source":{"type":"Binary","binary":{}},"strategy":{"type":"Docker","dockerStrategy":{"dockerfilePath":"Containerfile","buildArgs":[{"name":"PYTHON_BASE","value":"$base"},{"name":"PYTHON_RPMS","value":"$rpms"},{"name":"RPM_MANIFEST_SHA256","value":"$rpm_hash"},{"name":"SOURCE_MANIFEST_SHA256","value":"$source_hash"}]}},"output":{"to":{"kind":"ImageStreamTag","name":"$name:candidate"}},"resources":{"requests":{"cpu":"100m","memory":"512Mi"},"limits":{"cpu":"1","memory":"2Gi"}},"successfulBuildsHistoryLimit":1,"failedBuildsHistoryLimit":1,"triggers":[]}}
EOF
  for kind_name in imagestream buildconfig; do
    "${api[@]}" create --dry-run=server -f "$out/$kind_name.plan.json" > "$out/$kind_name.admission.private.log"
    cp "$out/$kind_name.plan.json" "$out/$kind_name.pending.json"
    "${api[@]}" create -f "$out/$kind_name.plan.json" -o json > "$out/$kind_name.created.private.json"
  done
  printf '%s\n' "$namespace/$name-1" > "$out/build-submission.pending"
  if ! "${api[@]}" --request-timeout=240s start-build "$name" -n "$namespace" --from-dir "$out/context" -o name > "$out/build.name.private.txt" 2> "$out/build-submission.private.log"; then
    echo 'Submission uncertain; retain receipts and inspect the exact build. Do not repeat build.' >&2; exit 1
  fi
  [[ $(cat "$out/build.name.private.txt") == "build.build.openshift.io/$name-1" ]] || { echo 'Unexpected build identity; inspect receipts.' >&2; exit 1; }
  "${api[@]}" get build "$name-1" -n "$namespace" -o json > "$out/build.created.private.json"
fi
[[ -f $out/build-config-name.txt ]] || { echo 'Original build name checkpoint required' >&2; exit 1; }
name=$(cat "$out/build-config-name.txt")
[[ $name =~ ^fixture-agent-installer-[a-f0-9]{12}(-[a-z0-9]{1,8})?$ ]] || { echo 'Invalid build checkpoint name' >&2; exit 1; }
[[ -s $out/build.created.private.json ]] || { echo 'Exact build creation receipt required; reconcile the pending submission.' >&2; exit 1; }
uid=$("${api[@]}" create --dry-run=client --validate=false -f "$out/build.created.private.json" -o jsonpath='{.metadata.uid}')
live_uid=$("${api[@]}" get build "$name-1" -n "$namespace" -o jsonpath='{.metadata.uid}')
[[ -n $uid && $uid == "$live_uid" ]] || { echo 'Build identity changed' >&2; exit 1; }
"${api[@]}" get build "$name-1" -n "$namespace" -o json > "$out/build-status.private.json"
phase=$("${api[@]}" get build "$name-1" -n "$namespace" -o jsonpath='{.status.phase}')
printf 'Installer build: %s\n' "$phase"
if [[ $phase == Complete ]]; then
  digest=$("${api[@]}" get build "$name-1" -n "$namespace" -o jsonpath='{.status.output.to.imageDigest}')
  [[ $digest =~ ^sha256:[a-f0-9]{64}$ ]] || { echo 'Immutable image digest required' >&2; exit 1; }
  printf 'image-registry.openshift-image-registry.svc:5000/%s/%s@%s\n' "$namespace" "$name" "$digest" | tee "$out/installer-image.txt"
fi
