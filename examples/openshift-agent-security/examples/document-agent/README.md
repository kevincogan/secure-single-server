<!-- SPDX-License-Identifier: Apache-2.0 -->
# Document agent: unrelated-agent integration proof

`agent.py` creates content only. `host.py` supplies a reviewed document connector,
synthetic identities, private file-backed backend and the shared security service.
No CVE, Jira, browser or `identity_demo` import is required.

From the example root:

```bash
python3 examples/document-agent/host.py
python3 examples/document-agent/host.py --approve
python3 examples/document-agent/host.py --approve --user-role viewer
python3 examples/document-agent/host.py --approve --workload-role reader
```

Expect awaiting approval, verified publication, user denial and workload denial,
respectively. Temporary private state is removed on exit. `--approve` records
explicitly synthetic consent; identities in this fixture are not authenticated.

For trust boundaries and real integration requirements, see
[the reuse guide](../../docs/security-runtime.md).
