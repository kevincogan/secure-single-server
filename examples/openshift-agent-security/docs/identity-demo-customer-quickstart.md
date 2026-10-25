<!-- SPDX-License-Identifier: Apache-2.0 -->
# Setup

Install the synthetic evaluation on an existing OpenShift 4.21 cluster with Linux
AMD64 workers. The installer, coordinator, preparer and issue view run on
OpenShift. Your workstation launches and observes setup; it needs **Bash, a
matching `oc`, `tar` and `sha256sum` or `shasum`**. No local Python, Rust or
container engine is required for this path.

**Verification boundary:** cluster builds, scoped activation and browser controls
passed with reviewed checkpoint recovery. An unassisted run of the final installer
image remains an independent acceptance gate. See [verification](verification.json).

| Stage | Who | Result |
|---|---|---|
| 1. Approve the platform | Administrator | Compatible controllers, identity, TLS and scoped access |
| 2. Prepare inputs | Delivery engineer | One reviewed configuration, public trust and private model key |
| 3. Build the installer | Build-authorized operator | Immutable image of this reviewed checkout |
| 4. Prepare and start builds | Administrator | Scoped installer and target-bound native builds |
| 5. Install the application | Administrator | Separate scoped application installer and cluster workers |
| 6. Verify a demo | Presenter | Protected results, automatic replacement and retained evidence |

Run commands from `examples/openshift-agent-security/`, or the extracted
`openshift-agent-security/` standalone directory. Keep the same Bash session
and private output directories. **Never repeat an uncertain submission.** A
successful Job is setup evidence, not proof of every security scenario.

## 1. Approve the platform

Ask the platform owner to provide the following before installation. Existing
shared prerequisites remain under their owner's control.

| Required input | Check |
|---|---|
| Platform APIs | Compatible SPIRE/ZTWIM, CSI, Agent Sandbox, Gateway/MCP and authorization controllers; see `infra/identity-demo/prerequisites.lock.json` |
| Identity foundation | Approved trust domain, cluster name, attestation, exact-workload registration, HTTPS discovery and kubelet access on current worker IPs |
| Application TLS | Approved cert-manager `Issuer` or `ClusterIssuer`, exact UID and public CA; server **and client** certificate usages must be supported |
| Network and storage | Exact API host/Service/endpoint CIDRs, verified HTTPS trust, allowed model endpoint, approved storage class and sufficient build/runtime capacity |
| Artifacts | Approved digest-pinned Jira runtime, Keycloak images, workload and diagnostic images; registry pull access |
| Administrator handoffs | Permission to create the exact reviewed installation resources and admission boundaries, including named read-only shared prerequisites |

Native compilation is serialized. It needs the pinned build sources and package
registries plus a temporary 30 GiB workspace. Anonymous Docker Hub pulls can be
rate-limited: the platform owner supplies approved pull access or a mirror of the
exact pinned builder. The optional `native_builder_image` input must preserve the
[pinned manifest digest](identity-demo-reference.md#pinned-builder-mirror).
Do not size the installation from idle workers alone. Preview components, artifact rights and support require their
own approvals. This path does not provision OpenShift or install another team's
controllers. See the [platform reference](identity-demo-reference.md#shared-prerequisites-and-ownership)
for administrator preparation and the supported boundary.

If using a namespaced issuer, the administrator first creates the three application
namespaces from the reviewed templates and retains **each original API creation
response** in a private directory. Stage 4 accepts this directory through
`--namespace-receipts`; it will not adopt existing namespaces by name or label.
The issuer's signing Secret is not accessible to runtime ServiceAccounts.

## 2. Prepare inputs

```bash
set -euo pipefail
umask 077
export DEMO_PRIVATE="$HOME/.local/share/agent-security-evaluation"
mkdir -p "$DEMO_PRIVATE"
chmod 700 "$DEMO_PRIVATE"
cp docs/examples/identity-demo-installer.example.yaml "$DEMO_PRIVATE/installation.yaml"
export DEMO_CONFIG="$DEMO_PRIVATE/installation.yaml"
export DEMO_KUBECONFIG="/absolute/private/installer.kubeconfig"
export DEMO_ADMIN_KUBECONFIG="/absolute/private/administrator.kubeconfig"
export DEMO_TRUST="$DEMO_PRIVATE/public-trust"
export DEMO_MODEL_KEY="$DEMO_PRIVATE/inference.key"
```

Edit the private configuration: replace all example identities, namespaces, API
addresses, issuer UID, model settings and zero image digests with reviewed inputs.
The metadata namespace/owner/installation must match its embedded profile. Include
both public API host routes and the in-cluster Kubernetes Service/endpoint host
routes in `kubernetes_api_cidrs`. `prepare` checks these before creating resources;
if any are missing, add the exact reported routes and repeat the same command.
It also checks SPIRE kubelet coverage. Missing worker hosts require the platform
owner’s [guarded reconciliation](identity-demo-reference.md#restore-kubelet-coverage-after-worker-replacement);
the launcher never changes shared policy.
Native base images are pinned in the template; the installer replaces them with verified,
target-built images before deployment. Do not insert passwords into this file.

Create `public-trust/` containing `service-ca.pem`, `spire-ca.pem`,
`upstream-ca.pem`, `kubernetes-ca.pem` and `application-ca.pem`. These contain
**public certificates only**. SPIRE client trust and the application serving CA
remain separate. Put only the approved model API key in the mode-0600 file
`inference.key`. Keep kubeconfigs, generated credentials, receipts and backups
outside Git. Do not share the private directory with the source package.

Expected: all declared inputs exist and target the approved cluster. If a digest,
issuer, trust chain or permission is missing, resolve it before resource creation.
Never use an insecure TLS option or copy a human kubeconfig into an installer Pod.

## 3. Build the installer on OpenShift

This command creates a dedicated owned bootstrap namespace and standard
BuildConfig. Use an account authorized to submit binary builds there; the launcher
never switches to an administrator automatically.

```bash
bash scripts/install.sh build \
  --config "$DEMO_CONFIG" --kubeconfig "$DEMO_KUBECONFIG" \
  --output-dir "$DEMO_PRIVATE/image-01"
bash scripts/install.sh status \
  --config "$DEMO_CONFIG" --kubeconfig "$DEMO_KUBECONFIG" \
  --output-dir "$DEMO_PRIVATE/image-01"
```

Repeat **status**, not build, until `Complete`. Expected: `installer-image.txt`
contains an immutable digest. The image contains inventory-verified source and
pinned tools, never cluster credentials. A rejected or interrupted submission
requires its original Build UID/checkpoint to be reconciled before another attempt.
Keep failed receipts. An existing bootstrap namespace requires its original
creation receipt and SHA-256; see the recovery reference.

## 4. Review the plan and start scoped builds

```bash
bash scripts/install.sh prepare \
  --config "$DEMO_CONFIG" --kubeconfig "$DEMO_ADMIN_KUBECONFIG" \
  --image-build-dir "$DEMO_PRIVATE/image-01" \
  --output-dir "$DEMO_PRIVATE/install-01"
```

Expected: `install-01/plan/` and `plan.sha256`. Review the exact namespaces,
ServiceAccounts, permissions, network policy, quotas and admission checks. The
planning Job is tokenless and cannot apply grants. Stop on a collision or any
resource outside the approved scope.

```bash
bash scripts/install.sh bootstrap \
  --config "$DEMO_CONFIG" --kubeconfig "$DEMO_ADMIN_KUBECONFIG" \
  --image-build-dir "$DEMO_PRIVATE/image-01" \
  --output-dir "$DEMO_PRIVATE/install-01" \
  --public-trust-dir "$DEMO_TRUST" --inference-key "$DEMO_MODEL_KEY"
```

For precreated namespaces, add
`--namespace-receipts "$DEMO_PRIVATE/namespace-receipts"`; that directory must
contain `<namespace>.json` for each of the three original creation responses.

Expected: one scoped build-session Job. It verifies prerequisites, renders private
state, compiles native binaries offline, verifies packaged bytes and builds the
worker image. Its rotating ServiceAccount token is not an agent identity. Native
agent identity continues to use SPIFFE/SPIRE.

## 5. Review the application handoff and activate

```bash
bash scripts/install.sh observe \
  --config "$DEMO_CONFIG" --kubeconfig "$DEMO_ADMIN_KUBECONFIG" \
  --image-build-dir "$DEMO_PRIVATE/image-01" \
  --output-dir "$DEMO_PRIVATE/install-01"
```

Repeat **observe** while builds are running. When complete, inspect
`administrator-plan/` and its hashes. This handoff separates build permissions
from application permissions. Confirm it contains only approved resources and
fixed named reads of shared prerequisites. The administrator also prepares the
workspace isolation policies; the installer verifies and retains them by exact
receipt. It must not grant SPIRE server exec or signing-key reads. Review the exact application image, credential references and
workload-registration admission boundary.

```bash
bash scripts/install.sh install \
  --config "$DEMO_CONFIG" --kubeconfig "$DEMO_ADMIN_KUBECONFIG" \
  --image-build-dir "$DEMO_PRIVATE/image-01" \
  --output-dir "$DEMO_PRIVATE/install-01"
```

Expected: build authority is retired, a separate scoped application Job installs
the services, and workers acquire their own durable leases. **Fresh setup also
creates three synthetic seed issues in OPS and three in SERVICE** as agent input.
Set the optional top-level `fixture_seed_mode: none` in the embedded installation
configuration to create projects without seed issues. The default is `synthetic`.
Approved demonstration runs may create additional issues; seed mode never changes permissions. Use **observe** to
check its original Job. No local workers should run against this installation.
A failed Job is not permission to rerun an uncertain mutation; use its private
stage receipts and the [recovery rules](identity-demo-console.md#recovery-rule-for-an-uncertain-write).

## 6. Verify and present

Open `https://fixture-identity-driver-<core_namespace>.<route_domain>/`.
Use the generated private synthetic Analyst/Viewer credentials. An authorized
installation administrator can extract the original evaluation realm into a
private directory to read its `users` entries:

```bash
DEMO_CORE=$(oc --kubeconfig "$DEMO_ADMIN_KUBECONFIG" create \
  --dry-run=client --validate=false -f "$DEMO_CONFIG" \
  -o jsonpath='{.metadata.namespace}')
mkdir -m 700 "$DEMO_PRIVATE/login"
oc --kubeconfig "$DEMO_ADMIN_KUBECONFIG" extract \
  secret/fixture-credentials -n "$DEMO_CORE" \
  --keys=realm.json --to="$DEMO_PRIVATE/login"
```

The resulting `realm.json` also
contains private evaluation client settings: inspect it locally, never attach it
to a recording, source archive or support ticket. Do not record passwords,
operator endpoints or keys in presentation footage.

1. In Settings, verify coordinator/preparer health and available compatible
   contexts. The profile defaults are six Triage and two Reader, at most 12 managed.
2. Run CVE Triage as Analyst; inspect exact fields before approval. Confirm the
   independently verified Jira outcome. **Approval may create a synthetic issue.**
3. Verify Viewer and Reader create denials and unchanged backend outcomes.
4. Rehearse Incident and Remediation with the approved live model. Incident's
   TEST denial is a deliberate isolation probe, not an autonomous model decision.
5. Confirm a ready workflow can start during replenishment; depleted profiles
   wait without disabling other eligible workflows. Verify audit/issue access
   after cleanup, restart and authorized sign-in.
6. Disconnect local workers and verify browser operation. Only accept or migrate
   the candidate after the security, recovery and retention gates pass.

After acceptance, retire installer-only access while retaining original receipts:

```bash
bash scripts/install.sh finalize \
  --config "$DEMO_CONFIG" --kubeconfig "$DEMO_ADMIN_KUBECONFIG" \
  --image-build-dir "$DEMO_PRIVATE/image-01" \
  --output-dir "$DEMO_PRIVATE/install-01"
```

Expected: original build/application installer bindings, including the named
gateway installer binding, are absent. Runtime
bindings, databases, identity history and recovery state remain. Finalization
requires the original completed application Job and exact creation responses; a
missing response, changed object or uncertain delete stops for review. Do not
re-enable a completed installer principal for ongoing runtime work.

Read [Operations](identity-demo-console.md) for daily use, certificate renewal,
backup, rollback and safe cleanup. Additional backends require a reviewed connector,
policy mappings and acceptance tests; the automated document-backend fixture is
not a supported non-Jira cluster installation.
