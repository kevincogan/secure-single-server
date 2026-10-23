# SPDX-License-Identifier: Apache-2.0
from argparse import Namespace
import json
import pytest
import cluster_console_plan as plan
from deployment_profile import LEGACY


def test_review_plan_cannot_grant_server_exec_secret_read_or_registration_writes(tmp_path):
    objects=plan.objects(LEGACY)
    assert len([o for o in objects if o['kind']=='ServiceAccount'])==2
    for obj in objects:
        if obj['kind']=='ServiceAccount':assert obj['automountServiceAccountToken'] is False
        if obj['kind']=='Role':
            assert obj['rules']==[{'apiGroups':['coordination.k8s.io'],'resources':['leases'],
                'resourceNames':[obj['metadata']['name'].removesuffix('-lease')],'verbs':['get','update']}]
    assert not any(o['kind'] in ('ClusterRole','ClusterRoleBinding') for o in objects)


def test_no_partial_runtime_activation_is_offered(tmp_path):
    with pytest.raises(ValueError,match='activation unavailable'):
        plan.run(Namespace(apply=True))
    profile=tmp_path/'profile.json';profile.write_text(json.dumps(LEGACY.to_dict()));profile.chmod(0o600)
    result=plan.run(Namespace(apply=False,installation_profile=str(profile),output_dir=tmp_path))
    assert result['activation_ready'] is False and result['cluster_changed'] is False
    value=json.loads((tmp_path/'cluster-runtime.boundary-plan.json').read_text())
    assert value['spire_server_exec_granted'] is False and value['mac_independence_proven'] is False
