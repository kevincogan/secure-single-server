# Deployment methods

There are two ways to deploy OpenShell for the scenarios in this guide:

Use a dedicated RHEL 9.8+ x86_64 host for either method. The full
scenario run was validated on RHEL 9.8 with Podman 5.8.2. See the
[v0.1.5 validation record](testing/upgrade-0.1.5.md).

- **Bootc deployment:** install the reviewed stack as a repeatable RHEL image.
  Follow the [bootc deployment guide](quickstarts/openshell-single-server/bootc.md).
- **Manual Podman deployment:** install OpenShell and the harnesses on a
  dedicated RHEL host with Podman. Follow the
  [manual deployment guide](quickstarts/openshell-single-server/manual.md).

Both deployment methods support the workflows in the
[scenario catalog](examples/README.md). Choose the guide that fits your host
and follow its setup steps before running a scenario.
