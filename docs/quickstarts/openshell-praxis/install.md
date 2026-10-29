# Experimental OpenShell add-on installation

Use a disposable, trusted single-operator RHEL 9.8+ x86_64 host with a reviewed
checkout available on the VM. Install
[Praxis all-in-one](../all-in-one/README.md) first. Commands below run on that VM
from the repository root. Bootc hosts instead use [bootc reconciliation](../../../bootc/README.md).

```bash
sudo dnf install -y curl python3 podman policycoreutils openssh-clients
sudo scripts/common/status
sudo cat /etc/praxis/gateway.scenario   # remains all-in-one
sudo scripts/openshell-praxis/install --owner openshell-svc
sudo scripts/common/status
curl -fsS http://127.0.0.1:8091/healthz
```

The add-on verifies the Praxis managed manifest and never rewrites its scenario,
configuration, quotas or secrets. The dedicated locked `openshell-svc` account
owns the rootless gateway; `praxis-svc` continues to own Praxis. Delegation is
scoped to the OpenShell user manager and applied without restarting it. Lingering
keeps services running after logout. The installer polls health and CLI access.

Rerun the same installer after failure; machine keys and data are retained. It
refuses an existing data directory owned by another account or unmanaged config.
Remove the add-on with `sudo openshell/scripts/uninstall.sh`, then rerun
`sudo scripts/common/status`. Removal stops the gateway and removes its unit;
it retains account, lingering, CLI, configuration, keys, containers and workspaces.
Export and delete sandbox work before final host disposal. Praxis uninstall
remains its independent managed lifecycle; drift checks stay enabled.

Praxis listens on loopback 8080 (OpenAI inference) and 8081 (Anthropic inference).
Its admin health is private inside the container; use `scripts/common/status`,
not a host health URL. OpenShell uses loopback 8090 (management) and 8091 (health).
Management requires TLS/mTLS using the registered service-operator identity;
individual user/workspace authorization is not implemented. Keep its keys
private and its port on loopback. The health endpoint remains HTTP.

Host-alias reachability and real inference are qualification requirements, not
established by gateway health. See [integration status](users.md).
