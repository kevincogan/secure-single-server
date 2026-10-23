# SPDX-License-Identifier: Apache-2.0
"""Safety checks for create-only security planning on a shared platform."""
from copy import deepcopy
import pytest
import security_setup as security
from deployment_profile import LEGACY

NETWORK={'api_cidrs':['192.0.2.1/32'],'worker_cidrs':['192.0.2.2/32']}

def observed(value):
    value=deepcopy(value);value['metadata'].update(uid='uid-'+value['metadata']['name'],resourceVersion='1')
    return value

def shared():
    groups=security.render(LEGACY,NETWORK);objects=[];subs=[];csvs=[]
    for x in groups['namespaces']:
        if x['metadata']['name']!=LEGACY.identity_namespace:objects.append(observed(x))
    for x in groups['operators']:
        if x['kind']=='Subscription' and x['spec']['name']!='openshift-zero-trust-workload-identity-manager':
            s=observed(x);s['metadata']['name']='platform-'+s['spec']['name'];version=s['spec']['startingCSV']
            s['status']={'installedCSV':version,'currentCSV':version};subs.append(s)
            csvs.append({'kind':'ClusterServiceVersion','apiVersion':'operators.coreos.com/v1alpha1',
                'metadata':{'name':version,'namespace':s['metadata']['namespace']},'status':{'phase':'Succeeded'}})
    for x in groups['gateway']:
        o=observed(x);o['metadata']['labels']={'managed-by':'another-team'}
        o['status']={'conditions':[{'type':'Accepted' if x['kind']=='GatewayClass' else 'Ready','status':'True'}]}
        objects.append(o)
    return groups,objects,subs,csvs

def test_empty_foundation_is_create_only():
    groups=security.render(LEGACY,NETWORK)
    r=security.classify_foundation(LEGACY,groups,[],[],[])
    assert r['ready'] and all(x['decision']=='create' for x in r['resources'])


def test_shared_platform_is_retained_without_duplicate_installs():
    groups,objects,subs,csvs=shared();original=deepcopy(objects)
    r=security.classify_foundation(LEGACY,groups,objects,subs,csvs)
    assert r['ready'] and objects==original
    assert [x['metadata']['name'] for x in r['create']['namespaces']]==[LEGACY.identity_namespace]
    assert [x['kind'] for x in r['create']['operators']]==['OperatorGroup','Subscription']
    assert r['create']['gateway']==[]
    assert all(x['metadata'].get('namespace')==LEGACY.identity_namespace for x in r['create']['operators'])


@pytest.mark.parametrize('change',['unhealthy-csv','wrong-version','upgrade-pending','duplicate-package','terminating-sub','copied-csv'])
def test_unreviewed_operator_blocks_all_create_files(change):
    groups,objects,subs,csvs=shared()
    if change=='unhealthy-csv':csvs[0]['status']['phase']='Failed'
    if change=='wrong-version':subs[0]['status']['installedCSV']='unreviewed-version'
    if change=='upgrade-pending':subs[0]['status']['currentCSV']='unreviewed-version'
    if change=='duplicate-package':subs.append(deepcopy(subs[0]))
    if change=='terminating-sub':subs[0]['metadata']['deletionTimestamp']='now'
    if change=='copied-csv':csvs[0]['metadata']['labels']={'olm.copiedFrom':'elsewhere'}
    r=security.classify_foundation(LEGACY,groups,objects,subs,csvs)
    assert not r['ready'] and not any(r['create'].values())


@pytest.mark.parametrize('kind',['Namespace','SpireServer','Deployment'])
def test_existing_owned_identity_state_is_not_adopted(kind):
    groups,objects,subs,csvs=shared()
    target=next(x for v in groups.values() for x in v if x['kind']==kind and (kind!='Namespace' or x['metadata']['name']==LEGACY.identity_namespace))
    objects.append(observed(target));r=security.classify_foundation(LEGACY,groups,objects,subs,csvs)
    assert not r['ready'] and not any(r['create'].values())


@pytest.mark.parametrize('change',['wrong-controller','not-accepted','not-ready','terminating'])
def test_invalid_shared_gateway_blocks_install(change):
    groups,objects,subs,csvs=shared();kind='Kuadrant' if change=='not-ready' else 'GatewayClass';x=next(o for o in objects if o['kind']==kind)
    if change=='wrong-controller':x['spec']['controllerName']='foreign.invalid/controller'
    if change in {'not-accepted','not-ready'}:x['status']['conditions'][0]['status']='False'
    if change=='terminating':x['metadata']['deletionTimestamp']='now'
    r=security.classify_foundation(LEGACY,groups,objects,subs,csvs)
    assert not r['ready'] and not any(r['create'].values())


def test_other_served_version_does_not_hide_existing_object():
    groups,objects,subs,csvs=shared();x=next(x for x in objects if x['kind']=='Kuadrant');x['apiVersion']='kuadrant.io/v1'
    r=security.classify_foundation(LEGACY,groups,objects,subs,csvs)
    assert r['ready'] and not r['create']['gateway']
