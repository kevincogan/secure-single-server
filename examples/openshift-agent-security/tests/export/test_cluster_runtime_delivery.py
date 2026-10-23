# SPDX-License-Identifier: Apache-2.0
from types import SimpleNamespace
import pytest
from deployment_profile import LEGACY
import cluster_runtime_delivery as tool


def test_cluster_probes_are_bounded_isolated_and_have_no_service_credentials():
    images={'jira_runtime':'registry.customer.example/jira@sha256:'+'a'*64,'cve_workload':'registry.customer.example/cve@sha256:'+'b'*64}
    probes={k:'print("synthetic")' for k in images}
    objects=tool.probe_objects(LEGACY,images,probes,'1234567890')
    policy=objects[0]
    assert policy['spec']['egress']==[] and policy['spec']['ingress']==[]
    assert policy['spec']['podSelector']['matchLabels']=={'identity-demo-runtime-probe':'1234567890'}
    for job in objects[1:]:
        assert job['spec']['backoffLimit']==0 and job['spec']['activeDeadlineSeconds']==180
        pod=job['spec']['template']['spec']
        assert pod['automountServiceAccountToken'] is False and pod['securityContext']['runAsNonRoot']
        assert all('secret' not in v and 'hostPath' not in v and 'persistentVolumeClaim' not in v for v in pod['volumes'])
        container=pod['containers'][0]
        assert container['securityContext']['readOnlyRootFilesystem']
        assert container['securityContext']['capabilities']['drop']==['ALL']
        assert not container.get('envFrom') and not any('valueFrom' in e for e in container['env'])


def test_cleanup_cannot_delete_replaced_resource_even_with_matching_owner(tmp_path,monkeypatch):
    obj={'metadata':{'uid':'replacement','labels':LEGACY.labels}}
    calls=[]
    def kube(args,*words,**kw):
        calls.append(words)
        assert words[0]=='get'
        return obj
    monkeypatch.setattr(tool.setup,'kube',kube)
    with pytest.raises(ValueError,match='UID changed'):
        tool.cleanup(SimpleNamespace(output_dir=tmp_path),LEGACY,[{'kind':'Job','name':'fixture-check-a','uid':'original'}])
    assert len(calls)==1


def test_cleanup_uses_api_uid_and_resource_version_preconditions(tmp_path,monkeypatch):
    calls=[]
    def kube(args,*words,value=None):
        calls.append((words,value))
        if words[0]=='get':return {'metadata':{'uid':'same','resourceVersion':'7','labels':LEGACY.labels}}
        assert value['preconditions']=={'uid':'same','resourceVersion':'7'}
        assert value['propagationPolicy']=='Foreground'
        return {}
    monkeypatch.setattr(tool.setup,'kube',kube)
    tool.cleanup(SimpleNamespace(output_dir=tmp_path),LEGACY,[{'kind':'Job','name':'fixture-check-a','uid':'same'}])
    assert len(calls)==2 and calls[-1][0][0]=='delete'


def test_probe_diagnostics_never_export_exception_text_or_unknown_fields():
    text='arbitrary private output\n'+tool.MARKER+'{"error_type":"KeyError","missing_env":"JIRA_TOKEN","secret":"never export"}'
    assert tool.diagnostic_lines(text)=={'error_type':'KeyError','missing_env':'JIRA_TOKEN'}
    assert tool.diagnostic_lines(tool.MARKER+'{"error_type":"some-secret","missing_env":"some-secret"}')=={}
    namespace={}
    with pytest.raises(SystemExit):
        exec(tool.wrapped_probe("raise KeyError('JIRA_TOKEN')"),namespace)


@pytest.mark.parametrize('fault', [None, 'oc-version', 'missing-release', 'wrong-platform', 'openshell-version', 'oversized'])
def test_runtime_build_verifies_the_packaged_vendor_tools(fault):
    """A successful tool invocation cannot bless a mismatched release or target."""
    import json
    from console_runtime_build import verify_versions
    metadata = {'releaseClientVersion': '4.21.36', 'clientVersion': {
        'gitVersion': '4.21.0-vendor-assembly', 'platform': 'linux/amd64'}}
    openshell = 'openshell 0.1.3\n'
    if fault == 'oc-version':
        metadata['releaseClientVersion'] = '4.21.5'
    elif fault == 'missing-release':
        metadata.pop('releaseClientVersion')
    elif fault == 'wrong-platform':
        metadata['clientVersion']['platform'] = 'darwin/arm64'
    elif fault == 'openshell-version':
        openshell = 'openshell 0.2.0\n'
    elif fault == 'oversized':
        openshell = 'x' * 1025
    if fault:
        with pytest.raises(ValueError):
            verify_versions(json.dumps(metadata), openshell, '4.21.36', '0.1.3')
    else:
        assert verify_versions(json.dumps(metadata), openshell, '4.21.36', '0.1.3') == {
            'oc': '4.21.36', 'openshell': '0.1.3', 'platform': 'linux/amd64'}
