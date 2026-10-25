#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Private launcher stages around the existing, immutable OpenShift installer.
set -euo pipefail
umask 077
usage() {
  echo 'Usage: scripts/install.sh prepare|bootstrap|install|observe|finalize --config FILE --kubeconfig FILE --image-build-dir PRIVATE_DIR --output-dir PRIVATE_DIR [--public-trust-dir DIR --inference-key FILE]' >&2
  exit 2
}
[[ $# -gt 0 ]] || usage
action=$1; shift
config='' kubeconfig='' image_build='' out='' trust='' inference='' namespace_receipts=''
while [[ $# -gt 0 ]]; do
  [[ $# -ge 2 ]] || usage
  case $1 in
    --config) config=$2;; --kubeconfig) kubeconfig=$2;; --image-build-dir) image_build=$2;;
    --output-dir) out=$2;; --public-trust-dir) trust=$2;; --inference-key) inference=$2;; --namespace-receipts) namespace_receipts=$2;; *) usage;;
  esac
  shift 2
done
[[ $action == prepare || $action == bootstrap || $action == install || $action == observe || $action == finalize ]] || usage
root=$(cd "$(dirname "$0")/../.." && pwd -P)
[[ -f $config && ! -L $config && -f $kubeconfig && ! -L $kubeconfig && -d $image_build && ! -L $image_build && $out == /* && ! -L $out ]] || usage
case $out/ in "$root/"*) echo 'Private output must be outside the checkout' >&2; exit 1;; esac
command -v oc >/dev/null
if command -v sha256sum >/dev/null; then hash=(sha256sum); else hash=(shasum -a 256); fi
if printf '' | base64 --decode >/dev/null 2>&1; then decode=(base64 --decode); else decode=(base64 -D); fi
api=(oc --kubeconfig "$kubeconfig" --request-timeout=30s)
field() { "${api[@]}" create --dry-run=client --validate=false -f "$1" -o "jsonpath=$2"; }
for file in "$image_build/installer-image.txt" "$image_build/build.created.private.json" "$image_build/build-config-name.txt"; do
  [[ -f $file && ! -L $file && -O $file ]] || { echo 'Original completed image-build receipts required' >&2; exit 1; }
done
image=$(cat "$image_build/installer-image.txt")
core=$(field "$config" '{.metadata.namespace}')
owner=$(field "$config" '{.metadata.labels.identity-demo-owner}')
installation=$(field "$config" '{.metadata.labels.identity-demo-installation}')
[[ $core =~ ^[a-z0-9][a-z0-9-]{0,56}$ && $owner =~ ^[a-z0-9][a-z0-9-]{0,62}$ && $installation =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] || usage
build_ns=$core-build
[[ $image =~ ^image-registry.openshift-image-registry.svc:5000/([a-z0-9-]+)/fixture-agent-installer-[a-f0-9]{12}(-[a-z0-9]{1,8})?@sha256:[a-f0-9]{64}$ && ${BASH_REMATCH[1]} == "$build_ns" ]] || { echo 'Exact owned immutable installer image required' >&2; exit 1; }
name=$(cat "$image_build/build-config-name.txt")
original_uid=$(field "$image_build/build.created.private.json" '{.metadata.uid}')
current_uid=$("${api[@]}" get build "$name-1" -n "$build_ns" -o jsonpath='{.metadata.uid}')
phase=$("${api[@]}" get build "$name-1" -n "$build_ns" -o jsonpath='{.status.phase}')
[[ -n $original_uid && $original_uid == "$current_uid" && $phase == Complete ]] || { echo 'Original verified image build must remain complete' >&2; exit 1; }
digest=$("${api[@]}" get build "$name-1" -n "$build_ns" -o jsonpath='{.status.output.to.imageDigest}')
[[ $image == *"@$digest" && $digest =~ ^sha256:[a-f0-9]{64}$ ]] || { echo 'Image digest differs from its original build' >&2; exit 1; }
if [[ $action == prepare ]]; then
  [[ ! -e $out ]] || { echo 'Output exists; use observe and preserve pending receipts, never repeat prepare.' >&2; exit 1; }
  # Validate public and in-cluster API routes before creating output or resources.
  # The native gateway uses Kubernetes' Service endpoint, unlike workstation oc.
  planning_tmp=$(mktemp -d "${TMPDIR:-/tmp}/identity-api-preflight.XXXXXX")
  trap 'rm -rf "$planning_tmp"' EXIT
  field "$config" '{.data.installation\.json}' > "$planning_tmp/installation.json"
  [[ -s $planning_tmp/installation.json ]] || { echo 'ConfigMap data.installation.json is required' >&2; exit 1; }
  # oc parses the versioned public body; it is never evaluated as shell code.
  printf '{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"fixture-local-parser"},"configuration":' > "$planning_tmp/parser.json"
  cat "$planning_tmp/installation.json" >> "$planning_tmp/parser.json"
  printf '}\n' >> "$planning_tmp/parser.json"
  expected=$(field "$planning_tmp/parser.json" '{.configuration.profile.expected_server}')
  target=$("${api[@]}" config view --minify --raw -o jsonpath='{.clusters[0].cluster.server}')
  [[ ${target%/} == "${expected%/}" && $expected == https://* && $(field "$planning_tmp/parser.json" '{.configuration.profile.core_namespace}') == "$core" && $(field "$planning_tmp/parser.json" '{.configuration.profile.owner}') == "$owner" && $(field "$planning_tmp/parser.json" '{.configuration.profile.installation_id}') == "$installation" ]] || { echo 'Configuration and authenticated cluster target differ' >&2; exit 1; }
  "${api[@]}" get service kubernetes -n default -o json > "$planning_tmp/api-service.readonly.json"
  "${api[@]}" get endpointslices.discovery.k8s.io -n default \
    -l kubernetes.io/service-name=kubernetes -o json > "$planning_tmp/api-endpointslices.readonly.json"
  [[ $(field "$planning_tmp/api-service.readonly.json" '{.spec.type}') == ClusterIP && -n $(field "$planning_tmp/api-service.readonly.json" '{.metadata.uid}') ]] || { echo 'Verified Kubernetes API Service required.' >&2; exit 1; }
  declared_api=$(field "$planning_tmp/parser.json" '{.configuration.kubernetes_api_cidrs[*]}')
  service_addresses=$(field "$planning_tmp/api-service.readonly.json" '{.spec.clusterIPs[*]}')
  # oc create processes List items individually; wrap the snapshot for local parsing.
  printf '{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"fixture-api-parser"},"observation":' > "$planning_tmp/api-parser.json"
  cat "$planning_tmp/api-endpointslices.readonly.json" >> "$planning_tmp/api-parser.json"
  printf '}\n' >> "$planning_tmp/api-parser.json"
  endpoint_addresses=$(field "$planning_tmp/api-parser.json" '{range .observation.items[*].endpoints[*]}{.addresses[*]}{" "}{end}')
  [[ -n $service_addresses && -n $endpoint_addresses ]] || { echo 'Kubernetes API Service and endpoint addresses required.' >&2; exit 1; }
  missing_api=''
  for api_address in $service_addresses $endpoint_addresses; do
    if [[ $api_address =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then api_route=$api_address/32
    elif [[ $api_address == *:* && $api_address =~ ^[0-9a-fA-F:]+$ ]]; then api_route=$api_address/128
    else echo 'Unexpected API endpoint address; inspect the public observations.' >&2; exit 1; fi
    case " $declared_api " in *" $api_route "*) ;;
      *) case " $missing_api " in *" $api_route "*) ;; *) missing_api="$missing_api $api_route";; esac;;
    esac
  done
  [[ -z $missing_api ]] || { echo "Add these verified in-cluster API host routes to kubernetes_api_cidrs, then repeat prepare:$missing_api" >&2; exit 1; }
  # Administrator-only observation; runtime workers receive no node/network rights.
  identity_ns=$(field "$planning_tmp/parser.json" '{.configuration.profile.identity_namespace}')
  [[ $identity_ns =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] || { echo 'Approved SPIRE namespace required.' >&2; exit 1; }
  "${api[@]}" get networkpolicy identity-demo-kubelet-egress -n "$identity_ns" -o json > "$planning_tmp/kubelet-policy.readonly.json"
  "${api[@]}" get nodes -l node-role.kubernetes.io/worker -o json > "$planning_tmp/worker-nodes.readonly.json"
  printf '{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"fixture-node-parser"},"observation":' > "$planning_tmp/node-parser.json"
  cat "$planning_tmp/worker-nodes.readonly.json" >> "$planning_tmp/node-parser.json"
  printf '}\n' >> "$planning_tmp/node-parser.json"
  worker_addresses=$(field "$planning_tmp/node-parser.json" '{range .observation.items[*].status.addresses[?(@.type=="InternalIP")]}{.address}{" "}{end}')
  kubelet_routes=$(field "$planning_tmp/kubelet-policy.readonly.json" '{.spec.egress[*].to[*].ipBlock.cidr}')
  [[ -n $worker_addresses && -n $(field "$planning_tmp/kubelet-policy.readonly.json" '{.metadata.uid}') && $(field "$planning_tmp/kubelet-policy.readonly.json" '{.spec.podSelector.matchLabels.app\.kubernetes\.io/name}') == spire-agent && $(field "$planning_tmp/kubelet-policy.readonly.json" '{.spec.egress[*].ports[*].port}') == 10250 ]] || { echo 'Platform owner must verify the SPIRE kubelet policy contract.' >&2; exit 1; }
  missing_kubelets=''
  for worker_address in $worker_addresses; do
    if [[ $worker_address =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then worker_route=$worker_address/32
    elif [[ $worker_address == *:* && $worker_address =~ ^[0-9a-fA-F:]+$ ]]; then worker_route=$worker_address/128
    else echo 'Unexpected worker address; platform review required.' >&2; exit 1; fi
    case " $kubelet_routes " in *" $worker_route "*) ;; *) missing_kubelets="$missing_kubelets $worker_route";; esac
  done
  [[ -z $missing_kubelets ]] || { echo "SPIRE kubelet coverage is missing these exact worker hosts:$missing_kubelets. Ask the platform owner to review guarded reconciliation; prepare has changed no resources." >&2; exit 1; }
  mkdir -m 700 "$out" "$out/plan" "$out/created"
  cp "$config" "$out/configuration.original.private.json"
  printf '%s\n' "$image" > "$out/installer-image.txt"
  cp "$planning_tmp/installation.json" "$planning_tmp/parser.json" \
    "$planning_tmp/api-service.readonly.json" "$planning_tmp/api-endpointslices.readonly.json" \
    "$planning_tmp/kubelet-policy.readonly.json" "$planning_tmp/worker-nodes.readonly.json" "$out/"
  "${api[@]}" create configmap fixture-installer-bootstrap-configuration -n "$build_ns" --from-file=installation.json="$out/installation.json" --dry-run=client -o json > "$out/planning-inputs.json"
  # The owned bootstrap namespace already holds this image. The planning Job
  # needs neither a cross-namespace pull grant nor an API token/model key.
  cat > "$out/planning-isolation.json" <<EOF
{"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"fixture-installer-public-planning","namespace":"$build_ns","labels":{"identity-demo-owner":"$owner","app.kubernetes.io/part-of":"identity-demo-preflight"}},"spec":{"podSelector":{"matchLabels":{"app":"fixture-installer-public-planning"}},"policyTypes":["Ingress","Egress"],"ingress":[],"egress":[]}}
EOF
  cat > "$out/planning-job.json" <<EOF
{"apiVersion":"batch/v1","kind":"Job","metadata":{"name":"fixture-installer-bootstrap-plan","namespace":"$build_ns","labels":{"identity-demo-owner":"$owner","app.kubernetes.io/part-of":"identity-demo-preflight"}},"spec":{"backoffLimit":0,"activeDeadlineSeconds":120,"template":{"metadata":{"labels":{"app":"fixture-installer-public-planning","identity-demo-owner":"$owner"}},"spec":{"automountServiceAccountToken":false,"restartPolicy":"Never","nodeSelector":{"kubernetes.io/arch":"amd64"},"securityContext":{"runAsNonRoot":true,"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"plan","image":"$image","command":["/bin/sh","-ec"],"args":["umask 077; mkdir -m 700 /tmp/private; exec python3.12 /app/scripts/identity_demo/identity_demo_setup.py installer-bootstrap-plan --installer-image $image --output-dir /tmp/private/result"],"resources":{"requests":{"cpu":"100m","memory":"256Mi"},"limits":{"cpu":"1","memory":"512Mi"}},"securityContext":{"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}},"volumeMounts":[{"name":"inputs","mountPath":"/inputs","readOnly":true},{"name":"tmp","mountPath":"/tmp"}]}],"volumes":[{"name":"inputs","configMap":{"name":"fixture-installer-bootstrap-configuration"}},{"name":"tmp","emptyDir":{"sizeLimit":"32Mi"}}]}}}}
EOF
fi
[[ -d $out && -f $out/configuration.original.private.json && -f $out/installer-image.txt && $(cat "$out/installer-image.txt") == "$image" ]] || { echo 'Original private preparation directory required' >&2; exit 1; }
cmp -s "$config" "$out/configuration.original.private.json" || { echo 'Installation configuration changed; review the original checkpoint.' >&2; exit 1; }
expected=$(field "$out/parser.json" '{.configuration.profile.expected_server}')
selected=$("${api[@]}" config view --minify --raw -o jsonpath='{.clusters[0].cluster.server}')
[[ $expected == https://* && ${selected%/} == "${expected%/}" ]] || { echo 'Installation checkpoint and API target differ.' >&2; exit 1; }
create_one() {
  local manifest=$1 receipt=$2 occupied recorded live kind fields original_fields live_fields identity_field
  if [[ -e $receipt ]]; then
    [[ -s $receipt && ! -L $receipt ]] || { echo 'Incomplete original creation response; reconcile without replay.' >&2; exit 1; }
    # An intact receipt must belong to this plan item, not another owned object.
    for identity_field in '{.kind}' '{.metadata.name}' '{.metadata.namespace}'; do
      [[ $(field "$manifest" "$identity_field") == $(field "$receipt" "$identity_field") ]] || { echo 'Creation receipt does not match the reviewed resource identity.' >&2; exit 1; }
    done
    recorded=$(field "$receipt" '{.metadata.uid}')
    live=$("${api[@]}" get -f "$receipt" -o jsonpath='{.metadata.uid}')
    [[ -n $recorded && $recorded == "$live" ]] || { echo 'Original resource was replaced; no operation permitted.' >&2; exit 1; }
    [[ $("${api[@]}" get -f "$receipt" -o jsonpath='{.metadata.labels.identity-demo-owner}') == "$owner" ]] || { echo 'Resource ownership changed' >&2; exit 1; }
    kind=$(field "$receipt" '{.kind}')
    case $kind in
      Role|ClusterRole) fields='{.rules}{.aggregationRule}';;
      RoleBinding|ClusterRoleBinding) fields='{.roleRef}{.subjects}';;
      Lease|Namespace) fields='{.metadata.labels.identity-demo-owner}';;
      ServiceAccount) fields='{.automountServiceAccountToken}{.metadata.labels.identity-demo-owner}';;
      PersistentVolumeClaim) fields='{.spec.accessModes}{.spec.resources.requests}{.spec.storageClassName}';;
      Secret|ConfigMap) fields='{.data}{.binaryData}{.type}{.immutable}';;
      *) fields='{.spec}';;
    esac
    original_fields=$("${api[@]}" create --dry-run=client --validate=false -f "$receipt" -o "jsonpath-as-json=$fields")
    live_fields=$("${api[@]}" get -f "$receipt" -o "jsonpath-as-json=$fields")
    [[ $original_fields == "$live_fields" ]] || { echo 'Recorded resource configuration changed; explicit recovery required.' >&2; exit 1; }
    return
  fi
  [[ ! -e $receipt.pending ]] || { echo 'Operation outcome uncertain; inspect the pending receipt instead of replaying.' >&2; exit 1; }
  occupied=$("${api[@]}" get -f "$manifest" --ignore-not-found -o name)
  [[ -z $occupied ]] || { echo 'Resource collision; no adoption by name or label.' >&2; exit 1; }
  "${api[@]}" create --dry-run=server -f "$manifest" -o name > "$receipt.admission"
  cp "$manifest" "$receipt.pending"
  if ! "${api[@]}" create -f "$manifest" -o json > "$receipt"; then
    echo 'Creation outcome uncertain; retain the pending receipt and do not replay.' >&2; exit 1
  fi
}
json_list() {
  local destination=$1 first=true item; shift
  [[ ! -e $destination ]] || return
  printf '{"apiVersion":"v1","kind":"List","items":[' > "$destination"
  for item in "$@"; do
    if $first; then first=false; else printf ',' >> "$destination"; fi
    cat "$item" >> "$destination"
  done
  printf ']}\n' >> "$destination"
}
label_manifest() {
  "${api[@]}" label --local -f "$1" "identity-demo-owner=$owner" 'app.kubernetes.io/part-of=identity-demo-preflight' -o json > "$2"
}

observe_planning() {
  local original current line index payload
  original=$(field "$out/created/planning-job.json" '{.metadata.uid}')
  current=$("${api[@]}" get job fixture-installer-bootstrap-plan -n "$build_ns" -o jsonpath='{.metadata.uid}')
  [[ -n $original && $original == "$current" ]] || { echo 'Planning Job identity changed' >&2; exit 1; }
  if ! "${api[@]}" wait job/fixture-installer-bootstrap-plan -n "$build_ns" --for=condition=complete --timeout=60s > "$out/planning-wait.private.log" 2>&1; then
    echo 'Planning is pending or failed. Inspect this exact Job; do not resubmit prepare.' >&2; return 1
  fi
  [[ ! -e $out/planning.completed ]] || { echo "Bootstrap plan is ready: $out/plan"; return; }
  "${api[@]}" logs job/fixture-installer-bootstrap-plan -n "$build_ns" --limit-bytes=2000000 > "$out/planning.private.log"
  while IFS= read -r line; do
    index=${line%%:*}; payload=${line#*:}
    [[ $index =~ ^[0-9]{1,3}$ && $payload =~ ^[A-Za-z0-9+/]+=*$ ]] || { echo 'Invalid public planner result' >&2; exit 1; }
    printf '%s' "$payload" | "${decode[@]}" > "$out/plan/$(printf '%03d' "$index").json"
  done < <(sed -n 's/^BOOTSTRAP_RESOURCE=//p' "$out/planning.private.log")
  sed -n 's/^BUILD_JOB=//p' "$out/planning.private.log" | "${decode[@]}" > "$out/build-session.job.json"
  [[ -s $out/plan/000.json && -s $out/build-session.job.json ]] || { echo 'Incomplete bootstrap plan; do not apply.' >&2; exit 1; }
  (cd "$out" && "${hash[@]}" plan/*.json build-session.job.json configuration.original.private.json installation.json installer-image.txt api-service.readonly.json api-endpointslices.readonly.json kubelet-policy.readonly.json worker-nodes.readonly.json > plan.sha256)
  touch "$out/planning.completed"
  printf 'Public bootstrap plan ready: %s/plan\nReview it before running bootstrap. No application has been installed.\n' "$out"
}
observe_build() {
  local original current line index payload completed
  original=$(field "$out/created/build-session.json" '{.metadata.uid}')
  current=$("${api[@]}" get job fixture-installer-build-session -n "$core" -o jsonpath='{.metadata.uid}')
  [[ -n $original && $original == "$current" ]] || { echo 'Build-session Job identity changed' >&2; exit 1; }
  completed=$("${api[@]}" get job fixture-installer-build-session -n "$core" -o jsonpath='{.status.conditions[?(@.type=="Complete")].status}')
  if [[ $completed != True ]]; then
    "${api[@]}" get job fixture-installer-build-session -n "$core" -o custom-columns=NAME:.metadata.name,ACTIVE:.status.active,FAILED:.status.failed,SUCCEEDED:.status.succeeded
    echo 'Build session has not completed. Inspect its private logs; do not submit another Job.'
    return
  fi
  [[ ! -e $out/build.completed ]] || { echo "Administrator handoff ready: $out/administrator-plan"; return; }
  mkdir -m 700 "$out/administrator-plan"
  "${api[@]}" logs job/fixture-installer-build-session -n "$core" --limit-bytes=2000000 > "$out/build-session.private.log"
  sed -n 's/^ADMIN_PLAN=//p' "$out/build-session.private.log" | "${decode[@]}" > "$out/administrator-prerequisites.json"
  sed -n 's/^APPLICATION_JOB=//p' "$out/build-session.private.log" | "${decode[@]}" > "$out/application-session.job.json"
  while IFS= read -r line; do
    index=${line%%:*}; payload=${line#*:}
    [[ $index =~ ^[0-9]{1,3}$ && $payload =~ ^[A-Za-z0-9+/]+=*$ ]] || { echo 'Invalid administrator handoff' >&2; exit 1; }
    printf '%s' "$payload" | "${decode[@]}" > "$out/administrator-plan/$(printf '%03d' "$index").json"
  done < <(sed -n 's/^ADMIN_RESOURCE=//p' "$out/build-session.private.log")
  [[ -s $out/administrator-prerequisites.json && -s $out/application-session.job.json && -s $out/administrator-plan/000.json ]] || { echo 'Incomplete handoff; do not install.' >&2; exit 1; }
  printf '{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"fixture-local-result"},"result":' > "$out/build-result.wrapper.json"
  tail -1 "$out/build-session.private.log" >> "$out/build-result.wrapper.json"
  printf '}\n' >> "$out/build-result.wrapper.json"
  expected=$(field "$out/build-result.wrapper.json" '{.result.administrator_plan_sha256}')
  [[ $expected =~ ^[a-f0-9]{64}$ && $("${hash[@]}" "$out/administrator-prerequisites.json" | awk '{print $1}') == "$expected" ]] || { echo 'Administrator plan hash does not match the completed build receipt.' >&2; exit 1; }
  (cd "$out" && "${hash[@]}" administrator-plan/*.json administrator-prerequisites.json application-session.job.json > administrator-plan.sha256)
  touch "$out/build.completed"
  printf 'Native and worker builds completed. Review %s/administrator-plan before application activation.\n' "$out"
}
json_array() {
  local destination=$1 first=true item; shift
  printf '[' > "$destination"
  for item in "$@"; do
    if $first; then first=false; else printf ',' >> "$destination"; fi
    cat "$item" >> "$destination"
  done
  printf ']\n' >> "$destination"
}
delete_recorded() {
  local receipt=$1 uri=$2 remaining uid rv response observed kind fields original_fields current_fields
  if [[ -e $receipt.deleted.json ]]; then
    remaining=$("${api[@]}" get -f "$receipt" --ignore-not-found -o name)
    [[ -z $remaining ]] || { echo 'Retired installer resource reappeared; stop for review.' >&2; exit 1; }
    return
  fi
  [[ ! -e $receipt.delete-pending.json ]] || { echo 'Retirement outcome uncertain; inspect the original UID without replay.' >&2; exit 1; }
  observed=$(mktemp "$receipt.delete-observed.XXXXXX")
  "${api[@]}" get -f "$receipt" -o json > "$observed"
  uid=$(field "$receipt" '{.metadata.uid}')
  kind=$(field "$receipt" '{.kind}')
  [[ -n $uid && $(field "$observed" '{.metadata.uid}') == "$uid" && $(field "$observed" '{.kind}') == "$kind" && $(field "$observed" '{.metadata.labels.identity-demo-owner}') == "$owner" ]] || { echo 'Original owned installer resource identity required.' >&2; exit 1; }
  case $kind in
    RoleBinding|ClusterRoleBinding) fields='{.metadata.ownerReferences}{.roleRef}{.subjects}';;
    ResourceQuota) fields='{.metadata.ownerReferences}{.spec}';;
    *) echo 'Only reviewed installer bindings and the temporary quota may be retired.' >&2; exit 1;;
  esac
  original_fields=$("${api[@]}" create --dry-run=client --validate=false -f "$receipt" -o "jsonpath-as-json=$fields")
  current_fields=$("${api[@]}" create --dry-run=client --validate=false -f "$observed" -o "jsonpath-as-json=$fields")
  [[ $original_fields == "$current_fields" ]] || { echo 'Installer resource changed; retirement requires review.' >&2; exit 1; }
  # The version comes from the same snapshot as the compared identity/spec.
  # Any subsequent change makes the server reject this deletion.
  rv=$(field "$observed" '{.metadata.resourceVersion}')
  [[ $uid =~ ^[a-f0-9-]{36}$ && $rv =~ ^[0-9]+$ ]] || { echo 'Exact deletion preconditions required' >&2; exit 1; }
  printf '{"apiVersion":"v1","kind":"DeleteOptions","preconditions":{"uid":"%s","resourceVersion":"%s"}}\n' "$uid" "$rv" > "$receipt.delete-pending.json"
  response="$receipt.deleted.json"
  "${api[@]}" delete --raw "$uri" -f "$receipt.delete-pending.json" > "$response.pending"
  mv "$response.pending" "$response"
}
retire_build_authority() {
  local receipt kind name uri found_binding=false found_quota=false
  active=$("${api[@]}" get builds -n "$core" -o jsonpath='{range .items[*]}{.status.phase}{"\n"}{end}')
  while IFS= read -r phase; do
    [[ -z $phase || $phase == Complete || $phase == Failed || $phase == Error || $phase == Cancelled ]] || { echo 'Wait for every candidate build to stop before application authority.' >&2; exit 1; }
  done <<< "$active"
  for receipt in "$out"/created/[0-9][0-9][0-9].json; do
    kind=$(field "$receipt" '{.kind}'); name=$(field "$receipt" '{.metadata.name}')
    if [[ $kind == RoleBinding && $name == "identity-demo-$installation-installer-build" ]]; then
      uri="/apis/rbac.authorization.k8s.io/v1/namespaces/$core/rolebindings/$name"; found_binding=true
    elif [[ $kind == ResourceQuota && $name == fixture-installer-build-budget ]]; then
      uri="/api/v1/namespaces/$core/resourcequotas/$name"; found_quota=true
    else continue
    fi
    delete_recorded "$receipt" "$uri"
  done
  if ! $found_binding || ! $found_quota; then echo 'Both original build-authority receipts are required' >&2; exit 1; fi
}
finalize_installer() {
  local manifest receipt kind name namespace uri expected_sa original live completed planned_fields receipt_fields found=false
  [[ -f $out/created/application-session.json && -d $out/administrator-created ]] || { echo 'Completed application handoff required before finalization.' >&2; exit 1; }
  (cd "$out" && "${hash[@]}" -c plan.sha256 > finalization-plan-check.private.log && "${hash[@]}" -c administrator-plan.sha256 > finalization-administrator-check.private.log)
  original=$(field "$out/created/application-session.json" '{.metadata.uid}')
  live=$("${api[@]}" get job fixture-installer-application-session -n "$core" -o jsonpath='{.metadata.uid}')
  completed=$("${api[@]}" get job fixture-installer-application-session -n "$core" -o jsonpath='{.status.conditions[?(@.type=="Complete")].status}')
  [[ -n $original && $original == "$live" && $completed == True ]] || { echo 'Original application Job must complete before removing installer access.' >&2; exit 1; }
  for manifest in "$out"/plan/[0-9][0-9][0-9].json "$out"/administrator-plan/[0-9][0-9][0-9].json; do
    [[ -f $manifest ]] || continue
    kind=$(field "$manifest" '{.kind}')
    [[ $kind == RoleBinding || $kind == ClusterRoleBinding ]] || continue
    name=$(field "$manifest" '{.metadata.name}'); namespace=$(field "$manifest" '{.metadata.namespace}')
    case $name in
      "identity-demo-$installation-installer-build"|"identity-demo-$installation-installer-build-ingress-read") expected_sa=fixture-installer-build-operator;;
      "identity-demo-$installation-installer-application") expected_sa=fixture-installer;;
      fixture-installer-gateway-access)
        [[ $kind == RoleBinding && $namespace == "$core" ]] || { echo 'Gateway installer binding must remain in its application namespace.' >&2; exit 1; }
        expected_sa=fixture-installer;;
      *) continue;;
    esac
    if [[ $manifest == "$out/plan/"* ]]; then receipt="$out/created/$(basename "$manifest")"; else receipt="$out/administrator-created/$(basename "$manifest")"; fi
    [[ -s $receipt && ! -L $receipt && $(field "$receipt" '{.kind}') == "$kind" && $(field "$receipt" '{.metadata.name}') == "$name" && $(field "$receipt" '{.metadata.namespace}') == "$namespace" ]] || { echo 'Every planned installer binding needs its original creation response.' >&2; exit 1; }
    planned_fields=$("${api[@]}" create --dry-run=client --validate=false -f "$manifest" -o 'jsonpath-as-json={.roleRef}{.subjects}')
    receipt_fields=$("${api[@]}" create --dry-run=client --validate=false -f "$receipt" -o 'jsonpath-as-json={.roleRef}{.subjects}')
    [[ $planned_fields == "$receipt_fields" ]] || { echo 'Installer grant differs from its reviewed plan.' >&2; exit 1; }
    [[ $(field "$receipt" '{.subjects[*].kind}') == ServiceAccount && $(field "$receipt" '{.subjects[*].name}') == "$expected_sa" && $(field "$receipt" '{.subjects[*].namespace}') == "$core" ]] || { echo 'Installer-only principal required; runtime grants cannot be retired.' >&2; exit 1; }
    if [[ $kind == ClusterRoleBinding ]]; then
      [[ -z $namespace ]] || { echo 'Unexpected cluster binding namespace' >&2; exit 1; }
      uri="/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/$name"
    else
      triage=$(field "$out/parser.json" '{.configuration.profile.triage_namespace}')
      reader=$(field "$out/parser.json" '{.configuration.profile.reader_namespace}')
      identity=$(field "$out/parser.json" '{.configuration.profile.identity_namespace}')
      [[ $namespace == "$core" || $namespace == "$triage" || $namespace == "$reader" || $namespace == "$identity" || $namespace == openshift-ingress ]] || { echo 'Unexpected installer grant namespace' >&2; exit 1; }
      uri="/apis/rbac.authorization.k8s.io/v1/namespaces/$namespace/rolebindings/$name"
    fi
    delete_recorded "$receipt" "$uri"
    found=true
  done
  $found || { echo 'Original installer binding receipts required' >&2; exit 1; }
  echo 'Installer grants retired. Runtime permissions, state, history and rollback artifacts retained.'
}
observe_application() {
  local original current completed
  original=$(field "$out/created/application-session.json" '{.metadata.uid}')
  current=$("${api[@]}" get job fixture-installer-application-session -n "$core" -o jsonpath='{.metadata.uid}')
  [[ -n $original && $original == "$current" ]] || { echo 'Application-session Job identity changed' >&2; exit 1; }
  completed=$("${api[@]}" get job fixture-installer-application-session -n "$core" -o jsonpath='{.status.conditions[?(@.type=="Complete")].status}')
  if [[ $completed != True ]]; then
    "${api[@]}" get job fixture-installer-application-session -n "$core" -o custom-columns=NAME:.metadata.name,ACTIVE:.status.active,FAILED:.status.failed,SUCCEEDED:.status.succeeded
    echo 'Application installation has not completed. Inspect its original private checkpoint; never replay an uncertain stage.'
    return
  fi
  "${api[@]}" logs job/fixture-installer-application-session -n "$core" --limit-bytes=2000000 > "$out/application-session.private.log"
  echo 'Application services installed. Verify protected workflows, replenishment and history before accepting or migrating.'
}
install_application() {
  local manifest namespace kind name receipt desired_kind entry meta sa_secret sa_ns selected plan_hash
  [[ -f $out/build.completed && -f $out/administrator-plan.sha256 ]] || { echo 'Completed verified build handoff required' >&2; exit 1; }
  (cd "$out" && "${hash[@]}" -c administrator-plan.sha256 > administrator-plan-check.private.log)
  triage=$(field "$out/parser.json" '{.configuration.profile.triage_namespace}')
  reader=$(field "$out/parser.json" '{.configuration.profile.reader_namespace}')
  identity=$(field "$out/parser.json" '{.configuration.profile.identity_namespace}')
  for manifest in "$out"/administrator-plan/*.json; do
    namespace=$(field "$manifest" '{.metadata.namespace}'); kind=$(field "$manifest" '{.kind}'); name=$(field "$manifest" '{.metadata.name}')
    case $kind in
      ServiceAccount|Role|RoleBinding|ClusterRole|ClusterRoleBinding|Lease|ResourceQuota|LimitRange|NetworkPolicy|ClusterSPIFFEID|ValidatingAdmissionPolicy|ValidatingAdmissionPolicyBinding) ;;
      *) echo 'Administrator plan contains non-public application state' >&2; exit 1;;
    esac
    if [[ -n $namespace && $namespace != "$core" && $namespace != "$triage" && $namespace != "$reader" ]]; then
      if [[ $namespace == openshift-ingress ]]; then
        [[ ( $kind == Role || $kind == RoleBinding ) && $name == "identity-demo-$installation-installer-application" ]] || { echo 'Unexpected shared ingress grant' >&2; exit 1; }
      elif [[ $namespace == "$identity" ]]; then
        [[ ( ( $kind == Role || $kind == RoleBinding ) && ( $name == "identity-demo-$installation-installer-application" || $name == "fixture-console-coordinator-public-trust-$installation" ) ) || ( $kind == NetworkPolicy && $name == "identity-demo-$installation-discovery-access" ) ]] || { echo 'Unexpected shared identity grant' >&2; exit 1; }
      else echo 'Unexpected administrator resource namespace' >&2; exit 1
      fi
    fi
  done
  "${api[@]}" get networkpolicy identity-demo-default-deny -n "$identity" -o json > "$out/discovery-existing-isolation.private.json"
  "${api[@]}" get deployment identity-demo-oidc-discovery -n "$identity" -o json > "$out/discovery-existing-target.private.json"
  [[ $(field "$out/discovery-existing-isolation.private.json" '{.metadata.labels.identity-demo-owner}') == "$owner" && -z $(field "$out/discovery-existing-isolation.private.json" '{.spec.podSelector.matchLabels}{.spec.podSelector.matchExpressions}') && -z $(field "$out/discovery-existing-isolation.private.json" '{.spec.ingress[*]}') && $(field "$out/discovery-existing-isolation.private.json" '{.spec.policyTypes}') == *Ingress* ]] || { echo 'Administrator must verify existing discovery isolation before an additive attachment.' >&2; exit 1; }
  [[ $(field "$out/discovery-existing-target.private.json" '{.metadata.labels.identity-demo-owner}') == "$owner" && $(field "$out/discovery-existing-target.private.json" '{.spec.template.metadata.labels.app}') == identity-demo-oidc-discovery && $(field "$out/discovery-existing-target.private.json" '{.status.readyReplicas}') == 1 ]] || { echo 'Verified existing discovery target required' >&2; exit 1; }
  retire_build_authority
  [[ -d $out/administrator-created ]] || mkdir -m 700 "$out/administrator-created"
  for desired_kind in ServiceAccount Lease LimitRange ResourceQuota NetworkPolicy ValidatingAdmissionPolicy ValidatingAdmissionPolicyBinding ClusterSPIFFEID Role ClusterRole RoleBinding ClusterRoleBinding; do
    for manifest in "$out"/administrator-plan/*.json; do
      [[ $(field "$manifest" '{.kind}') == "$desired_kind" ]] || continue
      create_one "$manifest" "$out/administrator-created/$(basename "$manifest")"
    done
  done
  if [[ ! -f $out/administrator-evidence.json ]]; then
    mkdir -m 700 "$out/current-observations" "$out/registry-owners"
    for receipt in "$out"/administrator-created/*.json "$out/namespaces/$core.json" "$out/namespaces/$triage.json" "$out/namespaces/$reader.json"; do
      kind=$(field "$receipt" '{.kind}'); name=$(field "$receipt" '{.metadata.name}'); namespace=$(field "$receipt" '{.metadata.namespace}')
      entry="$out/current-observations/$kind-$namespace-$name.json"
      "${api[@]}" get -f "$receipt" -o json > "$entry"
      if [[ $kind == ServiceAccount ]]; then
        sa_ns=$namespace
        selected=$("${api[@]}" get -f "$receipt" -o jsonpath='{range .imagePullSecrets[*]}{.name}{"\n"}{end}{range .secrets[*]}{.name}{"\n"}{end}')
        while IFS= read -r sa_secret; do
          [[ -n $sa_secret ]] || continue
          [[ $sa_secret =~ ^[a-z0-9][a-z0-9-]{0,252}$ && $sa_secret == "$name-dockercfg-"* ]] || { echo 'Unrecognized generated registry credential reference' >&2; exit 1; }
          [[ $("${api[@]}" get secret "$sa_secret" -n "$sa_ns" -o jsonpath='{.type}') == kubernetes.io/dockercfg ]] || { echo 'Unexpected registry credential type' >&2; exit 1; }
          meta="$out/registry-owners/$sa_ns-$sa_secret.json"
          printf '{"apiVersion":"v1","kind":"Secret","type":"kubernetes.io/dockercfg","metadata":' > "$meta"
          "${api[@]}" get secret "$sa_secret" -n "$sa_ns" -o jsonpath-as-json='{.metadata}' | sed '1d;$d' >> "$meta"
          printf '}\n' >> "$meta"
        done <<< "$selected"
      fi
    done
    json_array "$out/administrator-created.array.json" "$out"/administrator-created/*.json
    json_array "$out/administrator-current.array.json" "$out"/current-observations/*.json
    files=(); for entry in "$out"/registry-owners/*.json; do [[ -f $entry ]] && files+=("$entry"); done
    json_array "$out/administrator-registry.array.json" "${files[@]}"
    {
      printf '{"created":'
      cat "$out/administrator-created.array.json"
      printf ',"current":'
      cat "$out/administrator-current.array.json"
      printf ',"registry_owners":'
      cat "$out/administrator-registry.array.json"
      printf '}\n'
    } > "$out/administrator-evidence.json"
    "${api[@]}" create configmap fixture-installer-administrator-evidence -n "$build_ns" --from-file=configuration.json="$out/installation.json" --from-file=plan.json="$out/administrator-prerequisites.json" --from-file=evidence.json="$out/administrator-evidence.json" --from-file=namespaces.json="$out/namespaces.json" --dry-run=client -o json > "$out/administrator-evidence.raw.json"
    label_manifest "$out/administrator-evidence.raw.json" "$out/administrator-evidence.plan.json"
  fi
  create_one "$out/administrator-evidence.plan.json" "$out/created/administrator-evidence.json"
  plan_hash=$("${hash[@]}" "$out/administrator-prerequisites.json" | awk '{print $1}')
  if [[ ! -f $out/administrator-normalize.job.json ]]; then
    cat > "$out/administrator-normalize.job.json" <<EOF
{"apiVersion":"batch/v1","kind":"Job","metadata":{"name":"fixture-installer-administrator-receipt","namespace":"$build_ns","labels":{"identity-demo-owner":"$owner","app.kubernetes.io/part-of":"identity-demo-preflight"}},"spec":{"backoffLimit":0,"activeDeadlineSeconds":120,"template":{"metadata":{"labels":{"app":"fixture-installer-public-planning","identity-demo-owner":"$owner"}},"spec":{"automountServiceAccountToken":false,"restartPolicy":"Never","nodeSelector":{"kubernetes.io/arch":"amd64"},"securityContext":{"runAsNonRoot":true,"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"receipt","image":"$image","command":["/bin/sh","-ec"],"args":["umask 077; mkdir -m 700 /tmp/private; exec python3.12 /app/scripts/identity_demo/identity_demo_setup.py installer-administrator-receipt --administrator-plan-sha256 $plan_hash --output-dir /tmp/private/result"],"resources":{"requests":{"cpu":"100m","memory":"256Mi"},"limits":{"cpu":"1","memory":"512Mi"}},"securityContext":{"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}},"volumeMounts":[{"name":"receipts","mountPath":"/receipts","readOnly":true},{"name":"tmp","mountPath":"/tmp"}]}],"volumes":[{"name":"receipts","configMap":{"name":"fixture-installer-administrator-evidence"}},{"name":"tmp","emptyDir":{"sizeLimit":"32Mi"}}]}}}}
EOF
  fi
  create_one "$out/administrator-normalize.job.json" "$out/created/administrator-normalize.json"
  "${api[@]}" wait job/fixture-installer-administrator-receipt -n "$build_ns" --for=condition=complete --timeout=60s > "$out/administrator-normalize.wait.private.log" 2>&1 || { echo 'Administrator receipt verification pending or failed; inspect this exact Job.' >&2; exit 1; }
  if [[ ! -f $out/administrator.receipt.json ]]; then
    "${api[@]}" logs job/fixture-installer-administrator-receipt -n "$build_ns" --limit-bytes=2000000 > "$out/administrator-normalize.private.log"
    sed -n 's/^ADMIN_RECEIPT=//p' "$out/administrator-normalize.private.log" | "${decode[@]}" > "$out/administrator.receipt.json"
    [[ -s $out/administrator.receipt.json ]] || { echo 'No verified administrator receipt; do not activate.' >&2; exit 1; }
    "${api[@]}" create configmap fixture-installer-application-receipts -n "$core" --from-file=administrator.receipt.json="$out/administrator.receipt.json" --from-file=namespaces.json="$out/namespaces.json" --dry-run=client -o json > "$out/application-receipts.raw.json"
    label_manifest "$out/application-receipts.raw.json" "$out/application-receipts.plan.json"
  fi
  create_one "$out/application-receipts.plan.json" "$out/created/application-receipts.json"
  create_one "$out/application-session.job.json" "$out/created/application-session.json"
  observe_application
}
if [[ $action == prepare ]]; then
  for part in planning-inputs planning-isolation planning-job; do
    create_one "$out/$part.json" "$out/created/$part.json"
  done
  observe_planning
elif [[ $action == observe ]]; then
  if [[ -f $out/created/application-session.json ]]; then observe_application
  elif [[ -f $out/created/build-session.json ]]; then observe_build
  else observe_planning; fi
elif [[ $action == install ]]; then
  install_application
elif [[ $action == finalize ]]; then
  finalize_installer
else
  [[ -f $out/planning.completed && -f $out/plan.sha256 && -d $trust && ! -L $trust && -f $inference && ! -L $inference ]] || usage
  (cd "$out" && "${hash[@]}" -c plan.sha256 > plan-check.private.log)
  triage=$(field "$out/parser.json" '{.configuration.profile.triage_namespace}')
  reader=$(field "$out/parser.json" '{.configuration.profile.reader_namespace}')
  [[ $triage =~ ^[a-z0-9][a-z0-9-]{0,18}$ && $reader =~ ^[a-z0-9][a-z0-9-]{0,18}$ && $triage != "$reader" && $triage != "$core" && $reader != "$core" ]] || usage
  for manifest in "$out"/plan/*.json; do
    namespace=$(field "$manifest" '{.metadata.namespace}')
    kind=$(field "$manifest" '{.kind}')
    name=$(field "$manifest" '{.metadata.name}')
    case $namespace in
      ''|"$core"|"$triage"|"$reader"|"$build_ns") ;;
      openshift-ingress)
        [[ ( $kind == Role || $kind == RoleBinding ) && $name == "identity-demo-$installation-installer-build-ingress-read" ]] || { echo 'Unapproved shared namespace resource' >&2; exit 1; };;
      *) echo 'Unapproved resource namespace' >&2; exit 1;;
    esac
    [[ $kind != Secret ]] || { echo 'Public bootstrap cannot contain Secret values' >&2; exit 1; }
  done
  [[ -d $out/namespaces ]] || mkdir -m 700 "$out/namespaces"
  if [[ -n $namespace_receipts ]]; then
    [[ -d $namespace_receipts && ! -L $namespace_receipts ]] || usage
    for name in "$core" "$triage" "$reader"; do
      original_receipt=$namespace_receipts/$name.json
      [[ -f $original_receipt && ! -L $original_receipt && -O $original_receipt ]] || { echo 'Three original namespace creation receipts required.' >&2; exit 1; }
      cp "$original_receipt" "$out/namespaces/received-$name.json"
      [[ $(field "$out/namespaces/received-$name.json" '{.metadata.name}') == "$name" ]] || { echo 'Original namespace receipt mismatch' >&2; exit 1; }
      [[ $name == "$core" || $name == "$triage" || $name == "$reader" ]] || { echo 'Original namespace receipt mismatch' >&2; exit 1; }
      [[ $(field "$out/namespaces/received-$name.json" '{.kind}') == Namespace && -n $(field "$out/namespaces/received-$name.json" '{.metadata.uid}') ]] || { echo 'Original namespace creation response required' >&2; exit 1; }
      if [[ -e $out/namespaces/$name.json ]]; then
        cmp -s "$out/namespaces/received-$name.json" "$out/namespaces/$name.json" || { echo 'Original namespace receipt changed' >&2; exit 1; }
      else
        cp "$out/namespaces/received-$name.json" "$out/namespaces/$name.json"
      fi
    done
  fi
  for desired_kind in Namespace ServiceAccount PersistentVolumeClaim ResourceQuota NetworkPolicy ValidatingAdmissionPolicy ValidatingAdmissionPolicyBinding Role ClusterRole RoleBinding ClusterRoleBinding Lease; do
    for manifest in "$out"/plan/*.json; do
      kind=$(field "$manifest" '{.kind}')
      [[ $kind == "$desired_kind" ]] || continue
      name=$(field "$manifest" '{.metadata.name}')
      receipt="$out/created/$(basename "$manifest")"
      if [[ $kind == Namespace && -f $out/namespaces/$name.json && ! -e $receipt ]]; then cp "$out/namespaces/$name.json" "$receipt"; fi
      create_one "$manifest" "$receipt"
      if [[ $kind == Namespace && ! -e $out/namespaces/$name.json ]]; then cp "$receipt" "$out/namespaces/$name.json"; fi
    done
  done
  json_list "$out/namespaces.json" "$out/namespaces/$core.json" "$out/namespaces/$triage.json" "$out/namespaces/$reader.json"
  if [[ ! -e $out/input-configuration.plan.json ]]; then
    "${api[@]}" create configmap fixture-installer-configuration -n "$core" --from-file=installation.json="$out/installation.json" --dry-run=client -o json > "$out/input-configuration.raw.json"
    label_manifest "$out/input-configuration.raw.json" "$out/input-configuration.plan.json"
    files=()
    for filename in service-ca.pem spire-ca.pem upstream-ca.pem kubernetes-ca.pem application-ca.pem; do
      if [[ -f $trust/$filename ]]; then
        [[ ! -L $trust/$filename ]] || usage
        if grep -Eq -- '-----BEGIN .*PRIVATE KEY-----' "$trust/$filename"; then echo 'Public trust must not contain signing keys' >&2; exit 1; fi
        files+=("--from-file=$filename=$trust/$filename")
      fi
    done
    [[ ${#files[@]} -ge 3 ]] || { echo 'Required public trust inputs are missing' >&2; exit 1; }
    "${api[@]}" create configmap fixture-installer-trust -n "$core" "${files[@]}" --dry-run=client -o json > "$out/input-trust.raw.json"
    label_manifest "$out/input-trust.raw.json" "$out/input-trust.plan.json"
    "${api[@]}" create secret generic fixture-installer-inference -n "$core" --from-file=api-key="$inference" --dry-run=client -o json > "$out/input-inference.raw.private.json"
    label_manifest "$out/input-inference.raw.private.json" "$out/input-inference.plan.private.json"
    "${api[@]}" create configmap fixture-installer-namespace-receipts -n "$core" --from-file=namespaces.json="$out/namespaces.json" --dry-run=client -o json > "$out/input-receipts.raw.json"
    label_manifest "$out/input-receipts.raw.json" "$out/input-receipts.plan.json"
  fi
  for part in configuration trust inference receipts; do
    if [[ $part == inference ]]; then suffix=.private; else suffix=; fi
    create_one "$out/input-$part.plan$suffix.json" "$out/created/input-$part$suffix.json"
  done
  create_one "$out/build-session.job.json" "$out/created/build-session.json"
  observe_build
fi
