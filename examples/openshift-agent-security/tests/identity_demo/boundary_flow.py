# SPDX-License-Identifier: Apache-2.0
"""Credential-free namespace/attestation negatives beside an active native read."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import time
from typing import Callable
from uuid import uuid4

from identity_demo_workspaces import WORKSPACES, ACCOUNT
from agent_egress import program as agent_egress_program
from permission_flow import PermissionFlow
import probe_native_exchange as native
from deployment_profile import active_profile

IMAGE = "registry.example.test/demo/jira-runtime@sha256:0000000000000000000000000000000000000000000000000000000000000000"
TARGETS = {"fixture-keycloak-upstream": [8443], "fixture-mcp-openshift-ai-inference": [8080, 8443],
           "mcp-gateway": [8080], "fixture-protected-adapter": [8443], "fixture-jira": [8080, 8082]}


def manifests(namespace: str, name: str, nonce: str, services: dict, uid: int) -> list[dict]:
    """Permit only this credential-free tester's fixed target/DNS egress."""
    if namespace not in WORKSPACES or set(services) != set(TARGETS) or type(uid) is not int or uid < 1000:
        raise ValueError("Exact owned boundary scope required")
    labels = {**native.LABELS, "identity-demo-boundary-probe": nonce,
        "openshell.ai/boundary-role": "supervisor", "openshell.ai/gateway-id": active_profile().gateway_id}
    metadata = {"name": name, "namespace": namespace, "labels": labels}
    egress = [{"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": native.NAMESPACE}},
        "podSelector": {"matchLabels": services[key]["spec"]["selector"]}}],
        "ports": [{"protocol": "TCP", "port": p} for p in ports]} for key, ports in TARGETS.items()]
    egress.append({"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "openshift-dns"}}}],
        "ports": [{"protocol": proto, "port": port} for proto in ("TCP", "UDP") for port in (53, 5353)]})
    pod = {"apiVersion": "v1", "kind": "Pod", "metadata": metadata,
        "spec": {"serviceAccountName": ACCOUNT, "automountServiceAccountToken": False,
            "restartPolicy": "Never", "securityContext": {"runAsNonRoot": True, "runAsUser": uid,
                "runAsGroup": uid, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{"name": "supervisor", "image": IMAGE,
                "command": ["python", "-u", "-c", "import time;time.sleep(600)"],
                "resources": {"requests": {"cpu": "50m", "memory": "128Mi"}, "limits": {"cpu": "100m", "memory": "256Mi"}},
                "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
                "volumeMounts": [{"name": "socket", "mountPath": "/spiffe-workload-api", "readOnly": True}]}],
            "volumes": [{"name": "socket", "csi": {"driver": "csi.spiffe.io", "readOnly": True}}]}}
    policy = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": deepcopy(metadata),
        "spec": {"podSelector": {"matchLabels": {"identity-demo-boundary-probe": nonce}}, "policyTypes": ["Egress"], "egress": egress}}
    return [policy, pod]


class BoundaryFlow(PermissionFlow):
    """Prove copied labels fail attestation and cannot open protected private paths."""

    def command(self, *words: str, data: bytes | None = None) -> subprocess.CompletedProcess:
        """Capture all diagnostic output privately; expose only fixed classifications."""
        result = subprocess.run(["oc", "--kubeconfig", self.args.kubeconfig, "--request-timeout=20s", *words],
            input=data, capture_output=True, timeout=60)
        self.ordinal = getattr(self, "ordinal", 0) + 1
        native.private_write(self.args.output_dir / ("boundary-command-" + str(self.ordinal) + ".private.json"),
            {"exit": result.returncode, "stdout": result.stdout.decode(errors="replace"), "stderr": result.stderr.decode(errors="replace")})
        return result

    def accept(self, execute: Callable, resource: str, context: object, *, retire: bool = True) -> dict:
        """Leave existing policies untouched; delete only exact disposable resources."""
        if type(retire) is not bool:
            raise ValueError("Explicit boundary lifecycle required")
        before = self.backend_count()
        services = {name: native.kube(self.args, "get", "service", name, "-n", native.NAMESPACE, "-o", "json") for name in TARGETS}
        ca = native.kube(self.args, "get", "configmap", "fixture-service-ca", "-n", native.NAMESPACE, "-o", "json")["data"]["service-ca.crt"]
        all_cases = []
        for namespace in WORKSPACES:
            ns = native.kube(self.args, "get", "namespace", namespace, "-o", "json")
            sa = native.kube(self.args, "get", "serviceaccount", ACCOUNT, "-n", namespace, "-o", "json")
            assert all(ns["metadata"].get("labels", {}).get(k) == v for k, v in native.LABELS.items())
            assert sa.get("automountServiceAccountToken") is False
            uid = int(ns["metadata"]["annotations"]["openshift.io/sa.scc.uid-range"].split("/")[0])
            nonce = str(uuid4())
            name = "fixture-step56-boundary-" + nonce[:8]
            created = []
            try:
                for obj in manifests(namespace, name, nonce, services, uid):
                    assert not native.kube(self.args, "get", obj["kind"], name, "-n", namespace, "--ignore-not-found", "-o", "json")
                    native.kube(self.args, "create", "--dry-run=server", "-f", "-", "-o", "json", payload=obj)
                    value = native.kube(self.args, "create", "-f", "-", "-o", "json", payload=obj)
                    created.append(value)
                    native.private_write(self.args.output_dir / (namespace + "-" + obj["kind"] + ".private.json"), value)
                ready = self.command("wait", "--for=condition=Ready", "pod/" + name, "-n", namespace, "--timeout=45s")
                assert ready.returncode == 0
                binary_path = Path(self.args.spire_agent_cli)
                assert binary_path.is_file() and not binary_path.is_symlink() and binary_path.stat().st_size < 50_000_000
                binary = binary_path.read_bytes()
                staged = self.command("exec", "-i", name, "-n", namespace, "-c", "supervisor", "--", "python", "-c",
                    "import os,sys;d=sys.stdin.buffer.read(50000000);assert len(d)<50000000;f=os.fdopen(os.open('/tmp/step56-spire-agent',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o555),'wb');f.write(d);f.close()", data=binary)
                assert staged.returncode == 0
                identity = self.command("exec", name, "-n", namespace, "-c", "supervisor", "--", "/tmp/step56-spire-agent", "api", "fetch", "x509",
                    "-socketPath", "/spiffe-workload-api/spire-agent.sock", "-timeout", "8s", "-output", "json")
                assert identity.returncode != 0 and b"no identity" in identity.stderr.lower()
                program = '''import json,socket,ssl
CA=CA_VALUE
cases=[]
for label,host,port,wanted in [('issuer_positive','fixture-keycloak-upstream.demo-core.svc.cluster.local',8443,True),('bound_frontend_positive','fixture-mcp-bound.demo-core.svc.cluster.local',443,True),('private_gateway','fixture-mcp-openshift-ai-inference.demo-core.svc.cluster.local',8080,False),('private_broker','mcp-gateway.demo-core.svc.cluster.local',8080,False),('protected_adapter','fixture-protected-adapter.demo-core.svc.cluster.local',8443,False),('direct_jira','fixture-jira.demo-core.svc.cluster.local',8080,False),('legacy_adapter','fixture-jira.demo-core.svc.cluster.local',8082,False),('cluster_api','kubernetes.default.svc.cluster.local',443,False),('public_ip','1.1.1.1',443,False)]:
 address=socket.gethostbyname(host)
 try:
  with socket.create_connection((address,port),timeout=2):connected=True
 except OSError:connected=False
 cases.append({'case':label,'connected':connected,'passed':connected==wanted,'required':label not in ('cluster_api','public_ip')})
denied=False
try:
 with socket.create_connection(('fixture-mcp-bound.demo-core.svc.cluster.local',443),timeout=3) as raw:
  with ssl.create_default_context(cadata=CA).wrap_socket(raw,server_hostname='fixture-mcp-bound.demo-core.svc.cluster.local') as tls:
   tls.sendall(b'GET /mcp HTTP/1.1\\r\\nHost: fixture-mcp-bound.demo-core.svc.cluster.local\\r\\nConnection: close\\r\\n\\r\\n');tls.recv(4096)
except ssl.SSLError as error:denied='CERTIFICATE_REQUIRED' in str(error).upper()
cases.append({'case':'no_client_certificate','tls_certificate_required':denied,'passed':denied,'required':True})
print(json.dumps({'cases':cases,'all_required_passed':all(c['passed'] for c in cases if c['required'])}))'''.replace(
                    'demo-core.svc.cluster.local', active_profile().core_namespace + '.svc.cluster.local'
                ).replace("CA_VALUE", repr(ca))
                checked = self.command("exec", name, "-n", namespace, "-c", "supervisor", "--", "python", "-c", program)
                assert checked.returncode == 0
                result = json.loads(checked.stdout)
                # OpenShell intentionally permits supervisor egress. A trusted
                # operator can create a Pod copying that label; workload users
                # cannot. Keep API/public observations visible rather than
                # claiming namespace NetworkPolicy denies supervisor egress.
                assert result["all_required_passed"] and self.backend_count() == before
                all_cases.append({"namespace": namespace, "copied_labels_and_same_serviceaccount_no_svid": True,
                    "network_cases": result["cases"], "backend_unchanged": True, "passed": True})
                print(json.dumps({"stage": "namespace_boundary_passed", "namespace": namespace,
                    "required_cases_passed": sum(c['required'] for c in result["cases"]),
                    "supervisor_egress_observations_retained": True,
                    "unregistered_svid_denied": True}), flush=True)
            finally:
                for item in reversed(created):
                    live = native.kube(self.args, "get", item["kind"], name, "-n", namespace, "-o", "json")
                    assert live["metadata"]["uid"] == item["metadata"]["uid"]
                    assert live["metadata"]["labels"]["identity-demo-boundary-probe"] == nonce
                    current_spec, before_spec = deepcopy(live["spec"]), deepcopy(item["spec"])
                    if item["kind"] == "Pod":
                        current_spec.pop("nodeName", None)
                        before_spec.pop("nodeName", None)
                    assert current_spec == before_spec, "Disposable boundary resource changed independently"
                    uri = ("/api/v1/namespaces/" + namespace + "/pods/" if item["kind"] == "Pod" else
                        "/apis/networking.k8s.io/v1/namespaces/" + namespace + "/networkpolicies/") + name
                    native.kube(self.args, "delete", "--raw", uri, "-f", "-", payload={"apiVersion": "v1", "kind": "DeleteOptions",
                        **({"gracePeriodSeconds": 1} if item["kind"] == "Pod" else {}),
                        "preconditions": {"uid": live["metadata"]["uid"], "resourceVersion": live["metadata"]["resourceVersion"]}})
                    deadline = time.monotonic() + 15
                    while time.monotonic() < deadline:
                        left = native.kube(self.args, "get", item["kind"], name, "-n", namespace, "--ignore-not-found", "-o", "json")
                        if not left:
                            break
                        assert left["metadata"]["uid"] == item["metadata"]["uid"]
                        time.sleep(.5)
                    else:
                        raise TimeoutError("Disposable boundary resource deletion not complete")
        # Native positive after the negatives: no global outage or policy weakening.
        positive = execute(["sandbox", "exec", "--name", context.sandbox_name, "--no-login-shell", "--timeout", "90", "--no-tty", "--", "python", "-c", self.read_program(resource)], json_output=True)
        assert positive["read_passed"] and self.backend_count() == before
        agent_egress = execute(["sandbox", "exec", "--name", context.sandbox_name,
            "--no-login-shell", "--timeout", "90", "--no-tty", "--", "python", "-c",
            agent_egress_program()], json_output=True)
        assert agent_egress["passed"]
        privilege_cases = []
        for namespace in WORKSPACES:
            for target in ("pods", "clusterstaticentries.spire.spiffe.io"):
                check = self.command("auth", "can-i", "create", target,
                    "--as=system:serviceaccount:" + namespace + ":" + ACCOUNT,
                    *(["-n", namespace] if target == "pods" else []))
                assert check.returncode == 1 and check.stdout.strip() == b"no"
                privilege_cases.append({"namespace": namespace, "resource": target,
                    "workload_create_permission_denied": True})
        if retire:
            self.close()
        summary = {"passed": True, "namespaces": all_cases, "native_positive_after_negatives": True,
            "existing_network_policies_modified": False, "existing_registrations_modified": False,
            "probe_policy_permits_only_fixed_platform_targets_and_dns": True, "backend_before": before,
            "inherited_supervisor_policy_also_allows_egress": True,
            "run_retired_by_boundary_gate": retire,
            "actual_agent_direct_egress": agent_egress,
            "workload_creation_privileges": privilege_cases,
            "trusted_supervisor_label_egress_is_unrestricted": True,
            "scope_limit": "Namespace Pod administrators can copy supervisor labels; they remain trusted. This does not prove namespace-level egress denial for administrators or disconnected operation.",
            "backend_after": self.backend_count(), "original_public_route_carried_from_step4": True,
            "steps5_and6_complete": False}
        native.private_write(self.args.output_dir / (self.args.label + ".boundary.summary.json"), summary)
        return summary
