# Secure Single-Server AI Harness

OpenCode and OpenClaw run inside an OpenShell sandbox, reach models through a Praxis gateway, and ship as a bootc image.

**Office of the CTO** · Oct 26, 2026
_Pavel Anni · Office of the CTO · Red Hat_

---

## Slide 1: Coding agents get a perimeter on *one RHEL host*

Tags: Experimental, RHEL 9, OpenShell, Praxis, bootc

> Contextual notes: Arrow keys or click to navigate, N toggles notes, Cmd/Ctrl+P saves a PDF. Repository: [secure-single-server](https://github.com/redhat-et/secure-single-server). Published docs: [redhat-et.github.io/secure-single-server](https://redhat-et.github.io/secure-single-server/). The stack is experimental and not production-ready.

---

## Slide 2: A coding agent reads your files, runs commands, and calls a model

Those abilities make a harness useful. They also raise four questions the harness does not answer by itself.

- **Files and commands.** Which paths can the agent read and write, and which binaries can it run?
- **Model traffic.** Where do prompts and responses go?
- **Credentials.** Who holds the provider keys?
- **The host.** How does the machine stay consistent from one deployment to the next?

> Contextual notes: Framing from the [Architecture overview](https://github.com/redhat-et/secure-single-server/blob/main/docs/quickstarts/architecture-walkthrough/README.md). Each question is assigned to a separate component on the next slides.

---

## Slide 3: In an ordinary container the app holds the real key

| Ordinary container | OpenShell sandbox |
| --- | --- |
| The real model key lives in the app process | The app gets an opaque placeholder, and OpenShell swaps in the real key for one authorized endpoint |
| The app can write to its own directory | The app directory is read-only |
| The app can read a marker outside its directory | The marker outside the allowed paths is unreadable |

> Contextual notes: Streamlit before-and-after scenario. The provider profile authorizes the credential only for `POST /v1/chat/completions`. Run it on a dedicated RHEL 9 x86_64 host. See [Streamlit before and after OpenShell](https://github.com/redhat-et/secure-single-server/blob/main/docs/examples/streamlit-security/README.md).

**Source:** docs/examples/streamlit-security

---

## Slide 4: Every request follows one path: harness, sandbox, gateway, model

OpenCode / OpenClaw → OpenShell sandbox → Praxis → approved model

Sandbox policy can limit the harness to the gateway while Praxis selects the approved upstream.

> Contextual notes: The model path is separate from the execution boundary. OpenShell governs the harness and its tools. The model route decides where prompts and responses are processed. See [Praxis integration](https://github.com/redhat-et/secure-single-server/blob/main/docs/quickstarts/openshell-praxis/README.md).

---

## Slide 5: Each concern has exactly one owner

- **OpenShell, workspace and tools:** declared writable paths, read-only paths, approved binaries, and network destinations.
- **Praxis, model routing:** one gateway endpoint for the harness, with a local or external upstream behind it.
- **Praxis or provider profile, credentials:** keys stay out of ordinary harness configuration.
- **bootc, host consistency:** the reviewed host environment and pinned workload references ship as one OS image.

> Contextual notes: OpenShell is operated by a trusted administrator and is not a multi-tenant authorization system. Praxis routing and limits depend on the selected profile and upstream.

---

## Slide 6: The sandbox holds no provider key

**0**

provider keys held by the harness or the sandbox on the integrated Praxis paths

> Contextual notes: Applies to the integrated Praxis paths only. A configured OpenShell provider profile is a separate option where the sandbox sees a placeholder. See [README, How It Works](https://github.com/redhat-et/secure-single-server#how-it-works).

**Source:** README, How It Works

---

## Slide 7: Three attack scenarios stop at the same perimeter

- **API key theft:** the key is discoverable. Attempts to spend it outside the approved gateway are blocked and audited.
- **Document exfiltration:** a malicious skill tries several ways to send a document to an attacker destination. The boundary blocks each one.
- **Model escalation:** the gateway catalog refuses an unapproved model before any credential is used.

> Contextual notes: Scenarios run from `/usr/share/secure-single-server` on bootc or `/opt/secure-single-server` on a manual deployment. See [Example scenarios](https://github.com/redhat-et/secure-single-server/blob/main/docs/examples/README.md).

**Source:** docs/examples

---

## Slide 8: One bootc image repeats the host

- **Image variants** exist for OpenCode and OpenClaw.
- **First boot** pulls the selected control-plane and harness images into rootless Podman storage.
- **Manual Podman install** supports the same post-deployment scenarios.
- **Workspace data** needs its own storage plan, because the host image does not preserve it.

> Contextual notes: See [Published bootc images](https://github.com/redhat-et/secure-single-server/blob/main/bootc/README.md) and [Deployment methods](https://github.com/redhat-et/secure-single-server/blob/main/docs/deployment-methods.md).

---

## Slide 9: Agents keep working after your laptop disconnects

- Queue public GitHub issues or prompt files for a public repository.
- Keep a longer batch alive in `tmux` after you drop the SSH session.
- Collect one bundle per task: the task, a proposed patch, metadata, and a report.
- Apply the bundle on your workstation and open a draft PR with your own Git and GitHub credentials.

The sandbox receives no GitHub token and has no GitHub write access.

> Contextual notes: Issue-or-prompt-to-patch only, no pull-request review. See [OpenCode PR-candidate queue](https://github.com/redhat-et/secure-single-server/blob/main/docs/examples/opencode-pr-queue/README.md).

**Source:** docs/examples/opencode-pr-queue

---

## Slide 10: Treat it as an experiment on a disposable host

- **Not production-ready.** Review the qualification evidence before you extend a deployment.
- **One trusted administrator.** OpenShell here is not a multi-tenant authorization system.
- **Qualified combinations only.** The compatibility matrix lists what was exercised.
- **Profile-dependent limits.** Praxis routing and quotas follow the selected profile and upstream.

> Contextual notes: See [Testing and compatibility](https://github.com/redhat-et/secure-single-server/blob/main/docs/testing/README.md).

---

## Slide 11: Start with the Streamlit demo, then pick a scenario

1. **Read the architecture overview** to see which component owns which concern.
2. **Run the Streamlit before-and-after** on a dedicated RHEL 9 x86_64 host.
3. **Try a security scenario** from the examples index.

redhat-et.github.io/secure-single-server · github.com/redhat-et/secure-single-server

> Contextual notes: Complete the manual gateway setup first: install OpenShell, verify Landlock ABI 3 or newer, start the gateway, and define the `repo` and `os_run` helpers.

---

## Slide 12: Thank You

Pavel Anni · Office of the CTO · Red Hat
panni@redhat.com
