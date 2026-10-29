# OpenCode harness

OpenCode provides the coding-agent experience: prompts, model interactions,
and tool calls. This directory packages its lifecycle scripts, pinned image
reference, and OpenShell profiles; it does not replace OpenCode with a custom
agent.

Deploy and test OpenCode from the
[OpenShell single-server guide](../../../docs/quickstarts/openshell-single-server/README.md).
The optional Praxis route is documented separately for administrators who
select it. The active pins are covered by the [0.1.5 release
review](../../../docs/testing/upgrade-0.1.5.md). The [0.1.3 upgrade
tests](../../../docs/testing/upgrade-0.1.3.md) remain historical evidence for
model responses, streamed write and bash tools, independent file readback, and
policy denials with controlled model fixtures. Qualify the intended real
provider and model separately. In that route, tools do not receive direct vLLM or cloud-provider
access. In standalone OpenShell mode, selected model endpoints remain governed
by the harness policy.

The preinstalled harness image is digest-pinned in `openshell/configs/images.env`.
That upstream image does not yet include `ripgrep`; RHEL 9 also does not package
it. The bootc image and manual quickstart provide the same checksum-pinned
static `rg`, and harness creation copies it into the sandbox's `~/.local/bin` so
OpenCode's built-in `glob` and `grep` tools work without changing the upstream
image or policy.

The `pr-review` profile adds delegated PR review: `review.sh` sends a
batch of PRs as one bounded agent turn and `review-collect.sh` retrieves the
report artifacts. See the [review service
guide](../../../docs/examples/review-service/README.md).

The experimental `pr-queue` profile keeps its queue runner, collector, and agent
instructions in [pr-queue/](pr-queue/). The user-facing entry point is the
[PR-candidate example](../../../docs/examples/opencode-pr-queue/README.md). The
sandbox can read public GitHub issues and clone/fetch a repository, but it
cannot push or create pull requests.
