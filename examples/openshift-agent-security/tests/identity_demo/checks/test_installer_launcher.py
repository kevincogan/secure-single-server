# SPDX-License-Identifier: Apache-2.0
"""No cluster write may precede an exact declared installer API target."""

import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.parametrize(
    "mode", ["different-cluster", "conflicting-declaration", "missing-target"]
)
def test_image_launcher_rejects_wrong_target_before_output_or_cluster_writes(
    tmp_path, mode
):
    tools = tmp_path / "tools"
    tools.mkdir()
    marker = tmp_path / "unexpected-write"
    fake = tools / "oc"
    body = json.dumps(
        {"profile": {"expected_server": "https://api.reviewed.example.test:443"}}
    )
    script = (
        "#!"
        + sys.executable
        + "\n"
        + """import sys
args=sys.argv[1:]
if any(a.startswith('jsonpath={.metadata.namespace}') for a in args):print('owned-core')
elif any(a.startswith('jsonpath={.metadata.labels.identity-demo-owner}') for a in args):print('test-owner')
elif any(a.startswith('jsonpath={.metadata.labels.identity-demo-installation}') for a in args):print('owned-install')
elif any(a.startswith('jsonpath={.kind}') for a in args):print('ConfigMap')
elif 'config' in args and 'view' in args:print('https://api.foreign.example.test:443')
elif any('configuration.profile.expected_server' in a for a in args):print('https://api.reviewed.example.test:443')
elif any('data.installation' in a for a in args):print(BODY)
else:
 from pathlib import Path
 Path(MARKER).write_text('unexpected cluster operation')
 sys.exit(1)
""".replace("BODY", repr("" if mode == "missing-target" else body)).replace(
            "MARKER", repr(str(marker))
        )
    )
    fake.write_text(script)
    fake.chmod(0o700)
    config = tmp_path / "config.json"
    config.write_text("{}")
    kubeconfig = tmp_path / "access.json"
    kubeconfig.write_text("{}")
    command = [
        "bash",
        str(ROOT / "scripts/install.sh"),
        "build",
        "--config",
        str(config),
        "--kubeconfig",
        str(kubeconfig),
        "--output-dir",
        str(tmp_path / "output"),
    ]
    if mode == "conflicting-declaration":
        command += ["--expected-server", "https://api.another.example.test:443"]
    import os

    result = subprocess.run(
        command,
        env=dict(os.environ, PATH=str(tools) + os.pathsep + os.environ["PATH"]),
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode != 0
    assert not marker.exists() and not (tmp_path / "output").exists()
    assert "target" in result.stderr.lower()


def test_tokenless_planning_jobs_use_a_private_parent(tmp_path):
    launcher = (ROOT / "scripts/identity_demo/cluster_install_launch.sh").read_text()
    jobs = [
        json.loads(line)
        for line in launcher.splitlines()
        if line.startswith('{"apiVersion":"batch/v1"')
    ]
    assert len(jobs) == 2
    for index, job in enumerate(jobs):
        pod = job["spec"]["template"]["spec"]
        assert pod["automountServiceAccountToken"] is False
        container = pod["containers"][0]
        assert container["securityContext"]["readOnlyRootFilesystem"] is True
        command = container["args"][0]
        prefix, invocation = command.split("; exec ", 1)
        assert invocation.startswith(
            "python3.12 /app/scripts/identity_demo/identity_demo_setup.py "
        )
        assert invocation.endswith("--output-dir /tmp/private/result")
        sandbox = tmp_path / str(index)
        sandbox.mkdir()
        prefix = prefix.replace("/tmp/private", str(sandbox / "private"))
        subprocess.run(["/bin/sh", "-ec", prefix], check=True)
        assert (sandbox / "private").stat().st_mode & 0o077 == 0
        assert not (sandbox / "private/result").exists()


def test_changed_configuration_cannot_continue_bootstrap(tmp_path):
    import os

    tools = tmp_path / "tools"
    tools.mkdir()
    marker = tmp_path / "unexpected-mutation"
    fake = tools / "oc"
    program = "import sys\nfrom pathlib import Path\nargs=sys.argv[1:]\nexpr=args[-1]\nif 'metadata.namespace' in expr: print('owned-core')\nelif 'metadata.labels.identity-demo-owner' in expr: print('test-owner')\nelif 'metadata.labels.identity-demo-installation' in expr: print('owned-install')\nelif 'metadata.uid' in expr: print('recorded-build-uid')\nelif 'status.phase' in expr: print('Complete')\nelif 'status.output.to.imageDigest' in expr: print('sha256:'+'b'*64)\nelse:\n Path(MARKER).write_text('unexpected mutation')\n raise SystemExit(1)\n"
    fake.write_text(
        "#!" + sys.executable + "\n" + program.replace("MARKER", repr(str(marker)))
    )
    fake.chmod(0o700)
    image_build = tmp_path / "image"
    image_build.mkdir()
    image = (
        "image-registry.openshift-image-registry.svc:5000/owned-core-build/fixture-agent-installer-aaaaaaaaaaaa@sha256:"
        + "b" * 64
    )
    (image_build / "installer-image.txt").write_text(image + "\n")
    (image_build / "build.created.private.json").write_text("{}")
    (image_build / "build-config-name.txt").write_text(
        "fixture-agent-installer-aaaaaaaaaaaa"
    )
    config = tmp_path / "config.json"
    config.write_text('{"changed":true}')
    kube = tmp_path / "access.json"
    kube.write_text("{}")
    out = tmp_path / "state"
    out.mkdir()
    (out / "configuration.original.private.json").write_text('{"changed":false}')
    (out / "installer-image.txt").write_text(image + "\n")
    result = subprocess.run(
        [
            "bash",
            str(ROOT / "scripts/install.sh"),
            "bootstrap",
            "--config",
            str(config),
            "--kubeconfig",
            str(kube),
            "--image-build-dir",
            str(image_build),
            "--output-dir",
            str(out),
        ],
        env=dict(os.environ, PATH=str(tools) + os.pathsep + os.environ["PATH"]),
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode != 0 and "configuration changed" in result.stderr.lower()
    assert not marker.exists()


def test_public_installer_example_is_consistent_and_unfilled_digests_fail_closed():
    import yaml
    from cluster_installer_session import configuration

    document = yaml.safe_load(
        (ROOT / "docs/examples/identity-demo-installer.example.yaml").read_text()
    )
    value = json.loads(document["data"]["installation.json"])
    metadata = document["metadata"]
    profile = value["profile"]
    assert metadata["namespace"] == profile["core_namespace"]
    assert metadata["labels"]["identity-demo-owner"] == profile["owner"]
    assert (
        metadata["labels"]["identity-demo-installation"] == profile["installation_id"]
    )
    with pytest.raises(ValueError, match="digest-pinned"):
        configuration(value)
    for role, image in value["artifacts"]["images"].items():
        value["artifacts"]["images"][role] = image.replace("0" * 64, "a" * 64)
    assert configuration(value) == value


@pytest.mark.parametrize(
    "fault",
    [None, "source", "archive", "version", "existing", "permissions", "symlink"],
)
def test_packaged_cli_copy_preserves_private_executable_guard(tmp_path, fault):
    import hashlib
    import json
    from installer_tools import private_cli, ROOT
    import identity_demo_setup as setup

    runtime = json.loads(
        (ROOT / "infra/identity-demo/console-runtime.lock.json").read_text()
    )
    native = json.loads((ROOT / runtime["cli_lock"]).read_text())
    tools = tmp_path / "public"
    tools.mkdir()
    source = tools / "openshell"
    source.write_bytes(b"reviewed packaged binary")
    source.chmod(0o555)
    receipt = {
        "versions": {
            "oc": runtime["oc_version"],
            "openshell": native["version"],
            "platform": "linux/amd64",
        },
        "openshell": {
            "archive_sha256": native["assets"]["linux-amd64"]["sha256"],
            "binary_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        },
    }
    if fault == "source":
        source.chmod(0o755)
        source.write_bytes(b"substituted binary")
    elif fault == "archive":
        receipt["openshell"]["archive_sha256"] = "b" * 64
    elif fault == "version":
        receipt["versions"]["openshell"] = "other-version"
    proof = tmp_path / "receipt.json"
    proof.write_text(json.dumps(receipt))
    directory = tmp_path / "private"
    if fault in ("existing", "permissions", "symlink"):
        target = private_cli(directory, tool_root=tools, receipt_path=proof)
        if fault == "existing":
            target.write_bytes(b"changed private executable")
        elif fault == "permissions":
            target.chmod(0o755)
        else:
            target.unlink()
            target.symlink_to(source)
    if fault:
        with pytest.raises(ValueError):
            private_cli(directory, tool_root=tools, receipt_path=proof)
    else:
        target = private_cli(directory, tool_root=tools, receipt_path=proof)
        assert target.read_bytes() == source.read_bytes()
        assert target.stat().st_mode & 0o777 == 0o700
        assert setup.private_file(str(target)) == target
        assert private_cli(directory, tool_root=tools, receipt_path=proof) == target
        assert source.stat().st_mode & 0o777 == 0o555


@pytest.mark.parametrize('missing', [None, 'service', 'endpoint', 'kubelet', 'kubelet-contract'])
def test_prepare_checks_internal_api_routes_before_resource_creation(tmp_path, missing):
    import os

    tools = tmp_path / 'tools'
    tools.mkdir()
    marker = tmp_path / 'first-cluster-mutation'
    config = tmp_path / 'configuration.json'
    routes = ['192.0.2.10/32', '172.30.0.1/32', '172.20.0.1/32']
    if missing in ('service', 'endpoint'):
        routes.remove('172.30.0.1/32' if missing == 'service' else '172.20.0.1/32')
    profile = {'expected_server': 'https://api.reviewed.example.test:443',
               'core_namespace': 'owned-core', 'owner': 'test-owner',
               'installation_id': 'owned-install', 'identity_namespace': 'approved-identity'}
    config.write_text(json.dumps({'apiVersion':'v1', 'kind':'ConfigMap',
        'metadata': {'name':'configuration', 'namespace':'owned-core', 'labels':{
            'identity-demo-owner':'test-owner', 'identity-demo-installation':'owned-install'}},
        'data': {'installation.json':json.dumps({'profile':profile,'kubernetes_api_cidrs':routes})}}))
    image_dir = tmp_path / 'image'
    image_dir.mkdir()
    (image_dir/'installer-image.txt').write_text(
        'image-registry.openshift-image-registry.svc:5000/owned-core-build/fixture-agent-installer-aaaaaaaaaaaa@sha256:'+'b'*64+'\n')
    (image_dir/'build-config-name.txt').write_text('fixture-agent-installer-aaaaaaaaaaaa')
    (image_dir/'build.created.private.json').write_text(json.dumps({'metadata':{'uid':'original-build'}}))
    kube = tmp_path/'access.json'
    kube.write_text('{}')
    program = r"""import sys,json
from pathlib import Path
a=sys.argv[1:]
if 'create' in a and '--dry-run=client' in a and '-f' in a:
 v=json.loads(Path(a[a.index('-f')+1]).read_text()); expression=a[-1]
 if v.get('kind')=='List':v=v['items'][0]  # oc create processes List items separately.
 fields={'{.metadata.namespace}':v.get('metadata',{}).get('namespace',''),
  '{.metadata.labels.identity-demo-owner}':v.get('metadata',{}).get('labels',{}).get('identity-demo-owner',''),
  '{.metadata.labels.identity-demo-installation}':v.get('metadata',{}).get('labels',{}).get('identity-demo-installation',''),
  '{.metadata.uid}':v.get('metadata',{}).get('uid',''),
  '{.data.installation\.json}':v.get('data',{}).get('installation.json',''),
  '{.spec.type}':v.get('spec',{}).get('type',''),
  '{.spec.clusterIPs[*]}':' '.join(v.get('spec',{}).get('clusterIPs',[]))}
 c=v.get('configuration',{})
 for key in ('expected_server','core_namespace','owner','installation_id','identity_namespace'):fields['{.configuration.profile.'+key+'}']=c.get('profile',{}).get(key,'')
 fields['{.configuration.kubernetes_api_cidrs[*]}']=' '.join(c.get('kubernetes_api_cidrs',[]))
 fields['{range .observation.items[*].endpoints[*]}{.addresses[*]}{" "}{end}']=' '.join(address for item in v.get('observation',{}).get('items',[]) for endpoint in item.get('endpoints',[]) for address in endpoint['addresses'])
 fields['{range .observation.items[*].status.addresses[?(@.type=="InternalIP")]}{.address}{" "}{end}']=' '.join(address['address'] for item in v.get('observation',{}).get('items',[]) for address in item.get('status',{}).get('addresses',[]) if address['type']=='InternalIP')
 fields['{.spec.egress[*].to[*].ipBlock.cidr}']=' '.join(peer['ipBlock']['cidr'] for rule in v.get('spec',{}).get('egress',[]) for peer in rule.get('to',[]))
 fields['{.spec.egress[*].ports[*].port}']=' '.join(str(port['port']) for rule in v.get('spec',{}).get('egress',[]) for port in rule.get('ports',[]))
 fields['{.spec.podSelector.matchLabels.app\.kubernetes\.io/name}']=v.get('spec',{}).get('podSelector',{}).get('matchLabels',{}).get('app.kubernetes.io/name','')
 print(fields.get(expression.removeprefix('jsonpath='),''))
else:
 if 'config' in a and 'view' in a: print('https://api.reviewed.example.test:443')
 elif 'get' in a and 'build' in a:
  print('original-build' if 'uid' in a[-1] else 'Complete' if 'phase' in a[-1] else 'sha256:'+'b'*64)
 elif 'get' in a and 'service' in a:
  print(json.dumps({'apiVersion':'v1','kind':'Service','metadata':{'name':'kubernetes','uid':'api-service'},'spec':{'type':'ClusterIP','clusterIPs':['172.30.0.1']}}))
 elif 'get' in a and 'endpointslices.discovery.k8s.io' in a:
  print(json.dumps({'apiVersion':'v1','kind':'List','items':[{'endpoints':[{'addresses':['172.20.0.1']}]}]}))
 elif 'get' in a and 'networkpolicy' in a:
  print(json.dumps({'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy','metadata':{'uid':'original-policy'},'spec':{'podSelector':{'matchLabels':{'app.kubernetes.io/name':'spire-agent'}},'egress':[{'to':[{'ipBlock':{'cidr':KUBELET_ROUTE}}],'ports':[{'port':KUBELET_PORT}]}]}}))
 elif 'get' in a and 'nodes' in a:
  print(json.dumps({'apiVersion':'v1','kind':'List','items':[{'status':{'addresses':[{'type':'InternalIP','address':'192.0.2.88'},{'type':'Hostname','address':'ignored-node-name'}]}}]}))
 else:
  Path(MARKER).write_text('first cluster mutation reached')
  raise SystemExit(73)
""".replace('MARKER',repr(str(marker))).replace('KUBELET_ROUTE',repr('192.0.2.37/32' if missing=='kubelet' else '192.0.2.88/32')).replace('KUBELET_PORT',repr(443 if missing=='kubelet-contract' else 10250))
    oc=tools/'oc'
    oc.write_text('#!'+sys.executable+'\n'+program)
    oc.chmod(0o700)
    output=tmp_path/'output'
    result=subprocess.run(['bash',str(ROOT/'scripts/install.sh'),'prepare','--config',str(config),
        '--kubeconfig',str(kube),'--image-build-dir',str(image_dir),'--output-dir',str(output)],
        env=dict(os.environ,PATH=str(tools)+os.pathsep+os.environ['PATH']),capture_output=True,text=True,timeout=15)
    if missing:
        expected = 'SPIRE kubelet coverage is missing' if missing=='kubelet' else 'SPIRE kubelet policy contract' if missing=='kubelet-contract' else 'Add these verified in-cluster API host routes'
        assert result.returncode != 0 and expected in result.stderr
        assert not marker.exists() and not output.exists()
    else:
        assert result.returncode == 73 and marker.exists()
        assert (output/'api-endpointslices.readonly.json').exists()
        assert (output/'api-service.readonly.json').exists()
        assert (output/'kubelet-policy.readonly.json').exists()
        assert (output/'worker-nodes.readonly.json').exists()


@pytest.mark.parametrize("fault", [None, "kind", "name", "namespace"])
def test_resume_receipt_cannot_substitute_another_owned_resource(tmp_path, fault):
    import copy
    import shlex

    document = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": "reviewed-runtime", "namespace": "reviewed-core",
                             "labels": {"identity-demo-owner": "test-owner"}},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                           "resourceNames": ["fixed-input"], "verbs": ["get"]}]}
    saved = copy.deepcopy(document)
    saved["metadata"]["uid"] = "original-uid"
    if fault == "kind":
        saved["kind"] = "ConfigMap"
    elif fault:
        saved["metadata"][fault] = "different-owned-resource"
    manifest, receipt = tmp_path / "desired.json", tmp_path / "created.json"
    manifest.write_text(json.dumps(document))
    receipt.write_text(json.dumps(saved))
    marker = tmp_path / "cluster-read"
    oc = tmp_path / "oc"
    program = r"""import sys,json
from pathlib import Path
a=sys.argv[1:]
if '-f' not in a or not ('get' in a or ('create' in a and '--dry-run=client' in a)):
 raise SystemExit('Unexpected mutating command')
v=json.loads(Path(a[a.index('-f')+1]).read_text())
if 'get' in a:Path(MARKER).write_text('read-only verified get')
expression=a[-1].split('=',1)[-1]
fields={'{.kind}':v['kind'],'{.metadata.name}':v['metadata']['name'],
 '{.metadata.namespace}':v['metadata'].get('namespace',''),
 '{.metadata.uid}':v['metadata'].get('uid',''),
 '{.metadata.labels.identity-demo-owner}':v['metadata']['labels']['identity-demo-owner'],
 '{.rules}{.aggregationRule}':json.dumps(v.get('rules',[]),sort_keys=True)}
assert expression in fields
print(fields[expression])
""".replace('MARKER',repr(str(marker)))
    oc.write_text("#!" + sys.executable + "\n" + program)
    oc.chmod(0o700)
    launcher = (ROOT / "scripts/identity_demo/cluster_install_launch.sh").read_text()
    start = launcher.index("create_one() {")
    function = launcher[start:launcher.index("\n}\n", start) + 3]
    shell = ("set -euo pipefail\nowner=test-owner\napi=(" + shlex.quote(str(oc)) + ")\n"
             + 'field() { "${api[@]}" create --dry-run=client --validate=false -f "$1" -o "jsonpath=$2"; }\n'
             + function + "\ncreate_one " + shlex.quote(str(manifest)) + " " + shlex.quote(str(receipt)))
    result = subprocess.run(["bash", "-c", shell], capture_output=True, text=True, timeout=15)
    if fault:
        assert result.returncode != 0
        assert "reviewed resource identity" in result.stderr
        assert not marker.exists()
    else:
        assert result.returncode == 0, result.stderr
        assert marker.read_text() == "read-only verified get"
