# SPDX-License-Identifier: Apache-2.0
"""Runtime quota admission in owned namespaces, without listing other workloads.

The installer/admin must supply a measured complete per-context budget including
the workload and its supervisor. Kubernetes scheduler/admission remain final.
"""
import json

from deployment_profile import active_profile
from identity_demo_execution_setup import require

FIELDS = {'pods','persistentvolumeclaims','requests.storage','requests.cpu',
          'requests.memory','limits.cpu','limits.memory'}


def validate_budget(value):
    from identity_demo_presentation import quantity
    if not isinstance(value,dict) or set(value)!={'schema_version','includes_supervisor','per_context'}:
        raise ValueError('Complete measured capacity budget required')
    if value['schema_version']!=1 or value['includes_supervisor'] is not True:
        raise ValueError('Supervisor must be included in capacity accounting')
    if not isinstance(value['per_context'],dict) or set(value['per_context'])!=FIELDS:
        raise ValueError('Complete resource budget required')
    amounts={k:quantity(v) for k,v in value['per_context'].items()}
    if any(v<=0 for v in amounts.values()) or amounts['pods']<2 or amounts['persistentvolumeclaims']<1:
        raise ValueError('Positive workload and supervisor budget required')
    for k in ('cpu','memory'):
        if amounts['requests.'+k]>amounts['limits.'+k]:raise ValueError('Invalid resource budget')
    return amounts


def namespace_capacity(args, additions, by_role):
    from identity_demo_runtime_cli import private_path
    from identity_demo_presentation import quantity, owned, read
    import probe_native_exchange as native
    if type(additions)is not int or not 0<=additions<=12 or sum(by_role.values())!=additions:
        raise ValueError('Bounded exact role additions required')
    budget=validate_budget(json.loads(private_path(args.namespace_capacity_budget_file).read_text()))
    accounts=[]
    for role,count in by_role.items():
        require(role in ('triage','reader') and type(count)is int and count>=0,'Exact owned role required')
        ns=active_profile().namespace_for(role)
        owned(read(args,'namespace',ns))
        quotas=native.kube(args,'get','resourcequotas','-n',ns,'-o','json')['items']
        covered=set()
        for quota in quotas:
            status=quota.get('status',{})
            require(status.get('hard')==quota['spec']['hard'],'Current quota admission status required')
            for key,hard in status['hard'].items():
                if key in budget:
                    covered.add(key)
                    require(key in status.get('used',{}),'Quota usage unavailable')
                    require(quantity(status['used'][key])+budget[key]*count<=quantity(hard),
                            'Insufficient owned namespace quota headroom')
        require(FIELDS<=covered,'Complete owned namespace quota coverage required')
        accounts.append({'role':role,'quota_checks':len(quotas),'contexts_requested':count})
    return {'namespace_accounting':accounts,'additional_contexts':additions,
            'cluster_wide_scan':False,'supervisor_included':True,
            'scheduler_and_admission_remain_authoritative':True}
