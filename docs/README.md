# Documentation map

Start with the [repository overview](../README.md), then follow the route that
matches your decision. You do not need to read every document in this
repository; the guides below are separated by the question they answer.

## Recommended route

1. **Review the architecture.** Read the
   [Architecture overview](quickstarts/architecture-walkthrough/README.md) to
   understand the component roles, model access paths, and system boundaries.
2. **Deploy a sandboxed harness.** Use
   [OpenShell](https://github.com/NVIDIA/OpenShell/tree/v0.1.5/docs) through the
   [manual container guide](quickstarts/openshell-single-server/manual.md) or
   [bootc deployment guide](quickstarts/openshell-single-server/bootc.md) to deploy [OpenCode](https://github.com/anomalyco/opencode) or
   [OpenClaw](https://github.com/openclaw/openclaw) on one trusted RHEL host.
3. **Add model routing.** Use
   [Praxis](https://github.com/praxis/praxis) through the
   [OpenShell + Praxis guide](quickstarts/openshell-praxis/README.md) when the
   sandboxed harness should use a gateway instead of holding provider
   credentials.
4. **Choose the inference path.** Follow the
   [private vLLM workflow](quickstarts/common/vllm.md) or
   [provider setup](quickstarts/common/providers.md) after selecting the
   gateway route.
5. **Reproduce the evidence.** Use the [testing guide](testing/README.md) and
   [compatibility matrix](testing/compatibility.md) before treating a
   combination as qualified.
6. **Plan the next capability.** Use the [roadmap](roadmap.md) to separate
   accepted behavior from work still in progress.

The separate experimental [MaaS + PriceTag pilot](testing/pricetag.md) documents
finite MaaS API keys, USD usage budgets, and PriceTag metering. Its deployment
and performance guides are linked from that overview.

## Choose by outcome

| If you need to… | Use |
| --- | --- |
| Get a short overview to present or share | [Overview slide deck](slides/secure-single-server-overview.html) |
| Review component roles and model paths | [Architecture overview](quickstarts/architecture-walkthrough/README.md) |
| Install OpenShell and harness containers separately | [Manual single-server deployment](quickstarts/openshell-single-server/manual.md) |
| Choose a deployment method | [Deployment methods](deployment-methods.md) |
| Combine OpenShell with Praxis | [OpenShell + Praxis guide](quickstarts/openshell-praxis/README.md) |
| Try content-aware CPU/GPU routing with the optional Web UI | [llm-d-sc quickstart](quickstarts/llm-d-sc/README.md) |
| Serve users from accounts on one RHEL host | [All-in-one gateway](quickstarts/all-in-one/README.md) |
| Connect harnesses on remote client machines | [Remote HTTPS/JWT gateway](quickstarts/remote-gateway/README.md) |
| Deploy a remote gateway with user keys and USD budgets | [MaaS and PriceTag deployment](quickstarts/remote-gateway-pricetag/README.md), [providers](quickstarts/remote-gateway-pricetag/providers.md), [user administration](quickstarts/remote-gateway-pricetag/users.md) |
| Try a post-deployment workflow | [Example scenarios](examples/README.md) |
| Inspect or adjust shared model-token allowances | [Praxis token quotas scenario](examples/praxis-quotas/README.md) |
| Review the MaaS + PriceTag metering pilot | [Pilot overview](testing/pricetag.md), [AWS deployment runbook](testing/aws-pricetag.md), [performance procedure](testing/pricetag-perf.md) |
| Deploy the OS image | [bootc guide](../bootc/README.md) |
| Configure harnesses, providers, or quotas | [Common configuration index](quickstarts/common/README.md) |
| Inspect OpenShell policies and boundaries | [OpenShell Overview](../openshell/docs/README.md) |
| Review OpenShell upstream release deltas | [OpenShell upstream tracking](development/openshell-upstream.md) |
| Reproduce validation or add a new combination | [Testing guide](testing/README.md) |
| Understand future scope and acceptance | [Roadmap](roadmap.md) |

## Choose by component

| Component | What it provides | Start here |
| --- | --- | --- |
| OpenShell gateway | Policy-controlled execution boundary and sandbox lifecycle for every harness | [OpenShell Overview](../openshell/docs/README.md) |
| Harness sandboxes | Coding agents packaged as digest-pinned images with four profiles: [OpenCode](../openshell/harnesses/opencode/README.md), [OpenClaw](../openshell/harnesses/openclaw/README.md) | [Single-server guide](quickstarts/openshell-single-server/README.md) |
| Praxis | Provider credential custody, model routing, and shared token quotas | [OpenShell + Praxis guide](quickstarts/openshell-praxis/README.md), [token quota reference](quickstarts/common/token-quotas.md), [quota operations scenario](examples/praxis-quotas/README.md) |
| llm-d-sc | Experimental semantic prompt classification for CPU/GPU routing | [llm-d-sc quickstart](quickstarts/llm-d-sc/README.md) |
| MaaS and PriceTag | Finite API keys, per-user USD allowances, usage metering and administrator dashboards | [Deployment and operations](quickstarts/remote-gateway-pricetag/README.md), [performance procedure](testing/pricetag-perf.md) |
| vLLM | Private local model inference on a separate CPU or GPU server | [Private vLLM workflow](quickstarts/common/vllm.md) |
| Valkey | Durable quota ledger for the managed gateway | [All-in-one Valkey profile](quickstarts/all-in-one/valkey.md) |
| bootc images | Repeatable RHEL 9 OS deployment carrying the selected harness | [bootc images](../bootc/README.md) |
| Streamlit security demo | Credential substitution and filesystem confinement, before and after OpenShell | [Streamlit demo](examples/streamlit-security/README.md) |
| OpenCode PR queue | Turn public issues or prompts into reviewable patch bundles | [PR-candidate queue](examples/opencode-pr-queue/README.md) |
| Operator CLI | `sss-bootc` / `sss-praxis` and `scripts/common/*` for install, secrets, quotas, and status | [bootc operations](quickstarts/openshell-single-server/bootc.md), [all-in-one setup](quickstarts/all-in-one/README.md) |

Harness model access is configured with
[harness configuration](quickstarts/common/harness-configuration.md); each
harness README lists its profiles and entry points.

## Reading rules

For maintainers: [build and publish standalone MaaS and PriceTag images](development/pricetag-images.md).

- The recommended route is the sandboxed **harness → OpenShell → Praxis →
  inference** path. Other guides describe alternate deployment shapes, not
  interchangeable substitutes.
- Quickstarts tell you how to run a documented path. Validation records and
  the compatibility matrix determine what is qualified.
- Trust-model and quota documents define boundaries that are easy to miss when
  reading configuration alone.

## Upstream references

- [OpenCode](https://github.com/anomalyco/opencode)
- [OpenClaw](https://github.com/openclaw/openclaw)
- [OpenShell documentation](https://github.com/NVIDIA/OpenShell/tree/v0.1.5/docs)
  and [sandbox overview](https://github.com/NVIDIA/OpenShell/blob/v0.1.5/docs/how-it-works/sandboxes/overview.mdx)
- [Praxis framework](https://github.com/praxis/praxis)
- [Praxis experimental gateway](https://github.com/praxis-proxy/experimental)
- [llm-d-sc semantic classifier](https://github.com/llm-d-incubation/llm-d-semantic-classifier)
  and [Praxis filter](https://github.com/cnuland/llm-d-sc-praxis-filter)
- [Red Hat bootc](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_image_mode_for_rhel_to_build_deploy_and_manage_operating_systems/index)
- [vLLM documentation](https://docs.vllm.ai/en/latest/) and
  [CPU installation](https://docs.vllm.ai/en/v0.19.0/getting_started/installation/cpu/)

This repository tracks only its pinned deployment contracts and acceptance
evidence. Consult upstream documentation for general project features that
this deployment does not qualify.

## Next step

Start with the [Architecture overview](quickstarts/architecture-walkthrough/README.md).
If you already understand the system and only need a disposable evaluation,
use the [bootc quickstart](quickstarts/bootc/README.md).

## Preview the documentation locally

From the repository root, install the pinned documentation dependencies and
start the local preview:

```console
python3 -m venv .venv-docs
. .venv-docs/bin/activate
python -m pip install -r requirements-docs.txt
scripts/docs/serve
```

Open <http://127.0.0.1:8000/>. To refresh the preview after editing docs, run
`python3 scripts/docs/stage.py`; MkDocs rebuilds when `.docs-build/` changes.
To create a static site in `site/`, run `scripts/docs/serve build` instead. The
`mkdocs.yml` navigation includes the PriceTag pilot overview, AWS runbook, and
performance procedure.
