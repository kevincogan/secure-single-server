# Agent instructions

Start with README.md and docs/identity-demo-customer-quickstart.md. This is a
synthetic-data evaluation package. Keep credentials, kubeconfigs, output and
runtime snapshots outside Git. Do not commit, publish, deploy, restart services
or change cluster resources without the user's applicable authorization.

Preserve ownership checks, TLS, exact user/workload/run/project binding, original
run deadlines, approval of exact fields, single-use identities, data/history and
uncertain-write stops. Review infrastructure/native build changes with the
platform owner and workload changes with the designated application owner.
No helper success implies security/licensing or production approval.

Run `make test PYTHON=<operator-python>` and `make check PYTHON=<operator-python>`
after relevant changes. Integration checks require explicit private inputs.
Runtime code lives in `runtime/` and `scripts/identity_demo/`; runtime images use
the reviewed `config/runtime-sources.json` allowlist. `tests/identity_demo/`
contains automated checks and optional browser/qualification tools, which must
not become runtime imports. The legacy service-request workflow identifier is
the Remediation change request UI workflow.
