# OpenShell single-server deployment

Deploy OpenCode or OpenClaw on one trusted RHEL 9.8+ x86_64 host. Choose how to
install the OpenShell execution boundary:

| Deployment | Use it when… |
| --- | --- |
| [Manual container deployment](manual.md) | You want to install OpenShell from a reviewed, service-readable `/opt` checkout, create a harness sandbox, and add Praxis separately on a VM or bare-metal host. |
| [Bootc deployment](bootc.md) | You want to apply the published OS image with the selected harness configuration. |

After deployment, follow the [harness checks](verification.md). See the
[qualification and policy reference](reference.md) for supported behavior,
recorded AWS evidence, and enforcement limits.

Connect entry points accept an optional remote command after the sandbox name.
For example, use `connect.sh --name opencode-dev bash` for a simple Bash session.
Sandbox names must be simple identifiers (letters, digits and `-`, starting with
a letter or digit, at most 19 characters), and `OPENSHELL_GATEWAY_NAME` must
match `[A-Za-z0-9][A-Za-z0-9_-]*`; the entry points and the shared SSH helpers
reject any other value before connecting.

Praxis model routing is optional and experimental for OpenCode and
[OpenClaw bounded tasks](../openshell-praxis/openclaw.md). Follow the [Praxis installation walkthrough](../openshell-praxis/install.md)
and [integration matrix](../openshell-praxis/users.md) when selecting that path.
