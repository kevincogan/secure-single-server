# SPDX-License-Identifier: Apache-2.0
"""A runtime observation never substitutes stale configuration or Pod shell access."""
from argparse import Namespace
from copy import deepcopy
from types import SimpleNamespace

import pytest

import identity_demo_gateway_observation as observed
import identity_demo_gateway_persistence as persistence
import native_backend
import probe_broker_discovery as shared
from deployment_profile import active_profile


def receipt(ca='public-ca'):
    import hashlib
    return {'gateway_before':{'metadata':{'uid':'gateway-uid'}}, 'runtime_observation':{
        'kind':'installer-gateway-observation-v1','profile':active_profile().to_dict(),
        'service_ca_sha256':hashlib.sha256(ca.encode()).hexdigest(),'gateway_uid':'gateway-uid',
        'inventory':{'pod':{'uid':'pod-uid','containers':[{'containerID':'container-1'}]},
                     'filters':[{'name':'filter','uid':'filter-uid','spec_sha256':'digest'}]},
        'checks':{name:True for name in observed.CHECKS}}}


def external(monkeypatch,value):
    monkeypatch.setattr(persistence,'verify',lambda *a,**k:deepcopy(value))
    monkeypatch.setattr(observed,'inventory',lambda *a:deepcopy(value['runtime_observation']['inventory']))
    linked={'spec':{'hosts':['owned.example.test']},'status':{'summary':{'ready':True,'hostsReady':['owned.example.test']},
            'conditions':[{'type':'Ready','status':'True'}]}}
    monkeypatch.setattr(native_backend,'reconciliation_status',lambda *a:(
        deepcopy(linked),{'status':{'discoveredTools':2,'conditions':[{'type':'Ready','status':'True'}]}}))
    monkeypatch.setattr(shared,'owned',lambda *a:deepcopy(linked))


@pytest.mark.parametrize('change', ['missing','pod','container','filter','checks','profile','ca'])
def test_current_gateway_observation_rejects_stale_or_incomplete_evidence(monkeypatch,change):
    original=receipt();external(monkeypatch,original)
    assert observed.current(Namespace(),'public-ca') == original['runtime_observation']['checks']
    modified=deepcopy(original)
    if change=='missing':modified.pop('runtime_observation')
    elif change in ('pod','container','filter'):
        current=deepcopy(original['runtime_observation']['inventory'])
        if change=='pod':current['pod']['uid']='replacement'
        if change=='container':current['pod']['containers'][0]['containerID']='restarted'
        if change=='filter':current['filters'].append({'name':'added','uid':'new','spec_sha256':'digest'})
        monkeypatch.setattr(observed,'inventory',lambda *a:current)
    elif change=='checks':modified['runtime_observation']['checks'].pop(next(iter(observed.CHECKS)))
    elif change=='profile':modified['runtime_observation']['profile']['owner']='another-owner'
    elif change=='ca':modified['runtime_observation']['service_ca_sha256']='different-root'
    monkeypatch.setattr(persistence,'verify',lambda *a,**k:modified)
    with pytest.raises(ValueError):observed.current(Namespace(),'public-ca')


def test_runtime_ready_uses_only_verified_observation_and_never_exec(tmp_path,monkeypatch):
    monkeypatch.setenv('IDENTITY_DEMO_RUNTIME','cluster')
    probe=native_backend.NativeBackend(Namespace(output_dir=tmp_path,label='runtime',
        gateway_mode='persistent',permission_flow=SimpleNamespace()))
    probe.ca='public-ca'
    calls=[]
    monkeypatch.setattr(observed,'current',lambda *a:calls.append(a) or {name:True for name in observed.CHECKS})
    def forbidden(*a,**k):raise AssertionError('No runtime shell observation')
    monkeypatch.setattr(native_backend,'gateway_snapshot',forbidden)
    assert set(probe.ready()) == observed.CHECKS and len(calls)==1
    probe.persistent=False
    with pytest.raises(ValueError):probe.ready()


def test_changed_live_discovery_still_blocks_an_unchanged_snapshot(monkeypatch):
    external(monkeypatch,receipt())
    linked={'spec':{'hosts':['owned.example.test']},'status':{'summary':{'ready':True,'hostsReady':['owned.example.test']},
            'conditions':[{'type':'Ready','status':'True'}]}}
    monkeypatch.setattr(native_backend,'reconciliation_status',lambda *a:(linked,{'status':{'discoveredTools':0}}))
    with pytest.raises(observed.GatewayDiscoveryPending):observed.current(Namespace(),'public-ca')


def test_host_collision_blocks_even_with_valid_gateway_snapshot(monkeypatch):
    external(monkeypatch,receipt())
    monkeypatch.setattr(native_backend,'reconciliation_status',lambda *a:(
        {'spec':{'hosts':['shared-host']},'status':{'summary':{'ready':False,'hostsReady':[]},
         'conditions':[{'type':'Ready','status':'False','reason':'HostsNotLinked'}]}},
        {'status':{'discoveredTools':2,'conditions':[{'type':'Ready','status':'True'}]}}))
    with pytest.raises(ValueError,match='authorization readiness'):observed.current(Namespace(),'public-ca')


def test_summary_success_cannot_conceal_missing_host_link():
    value={'spec':{'hosts':['ours']},'status':{'summary':{'ready':True,'hostsReady':['another']},
           'conditions':[{'type':'Ready','status':'True'}]}}
    assert observed.authorizer_linked(value) is False
