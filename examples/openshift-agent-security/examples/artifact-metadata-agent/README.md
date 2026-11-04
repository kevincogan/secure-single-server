<!-- SPDX-License-Identifier: Apache-2.0 -->
# Independent artifact-metadata agent

This optional offline consumer was implemented in a separate session using only
an installed runtime wheel, the public onboarding guide and conformance harness.
It registers artifact metadata in `catalog:*` scopes. It imports the supported
`agent_security_runtime` namespace and does not modify the security core.

The agent computes metadata from local bytes. The trusted synthetic host binds
the user/workload, selects the catalog backend and supplies separate consent.
A curator with a metadata worker can register after exact approval; an observer
or catalog reader cannot. These identities and consent are synthetic. Real
Keycloak authentication and attested isolation are established separately by the
[deployed document proof](../document-agent/README.md).

Use a disposable directory outside the checkout, with the runtime wheel normally
installed in its interpreter. Copy the supplied public harness as an input to
that standalone integration:

```bash
export ARTIFACT_EXAMPLE="$(mktemp -d)"
export ARTIFACT_PYTHON="/absolute/path/to/wheel-installed/venv/bin/python"
unset PYTHONPATH
mkdir -p "$ARTIFACT_EXAMPLE"
cp examples/artifact-metadata-agent/{agent,backend,contract,host,acceptance}.py "$ARTIFACT_EXAMPLE/"
cp examples/adapter_conformance.py "$ARTIFACT_EXAMPLE/"
"$ARTIFACT_PYTHON" "$ARTIFACT_EXAMPLE/agent.py"
"$ARTIFACT_PYTHON" "$ARTIFACT_EXAMPLE/host.py" --approve
"$ARTIFACT_PYTHON" "$ARTIFACT_EXAMPLE/host.py" --approve --user-role catalog-observer
"$ARTIFACT_PYTHON" "$ARTIFACT_EXAMPLE/host.py" --approve --workload-role catalog-reader
"$ARTIFACT_PYTHON" "$ARTIFACT_EXAMPLE/acceptance.py"
```

Unset repository `PYTHONPATH` while running this installed-package acceptance.
No repository path manipulation, private runtime imports, network or cluster is
required. The conformance harness has one canonical source in this repository;
the temporary copy is the public input supplied to a standalone consumer.
Acceptance writes its report beside the disposable copy, outside Git.

The 13 common cases and 17 integration tests cover exact consent, user/workload
and scope distinctions, replay, eight racing callers, interrupted dispatch,
response loss and restart reconciliation, backend/reference mismatches, strict
request schemas and correlated audit. Backend state is local synthetic data.
See [the public contract](../../docs/security-runtime.md) for real authentication,
credential custody, network isolation and host responsibilities.
