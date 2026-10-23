# SPDX-License-Identifier: Apache-2.0
"""Opt-in installer wiring for public-only automatic trust refresh.

Uses the existing idle worker update; no new controller, human credential or
SPIRE write permission. Only the two public CA Secrets become runtime writable.
"""
from copy import deepcopy
import hashlib

import identity_demo_setup as setup
from cluster_console_resources import resource
from identity_demo_public_trust import CA_SECRET, ISSUER_TRUST


def resources(profile, ca):
    name = 'identity-demo-'+profile.installation_id+'-public-trust'
    principal = 'system:serviceaccount:'+profile.core_namespace+':fixture-console-coordinator'
    policy = resource(profile,'admissionregistration.k8s.io/v1','ValidatingAdmissionPolicy',name,
        spec={'failurePolicy':'Fail','matchConstraints':{'resourceRules':[
            {'apiGroups':[''],'apiVersions':['v1'],'operations':['UPDATE'],'resources':['secrets']}]},
            'matchConditions':[
                {'name':'exact-runtime','expression':'request.userInfo.username == '+repr(principal)},
                {'name':'exact-targets','expression':'request.namespace == '+repr(profile.core_namespace)+
                    ' && object.metadata.name in '+repr([CA_SECRET,ISSUER_TRUST])}],
            'validations':[
                {'expression':"object.type == 'Opaque' && oldObject.type == object.type && object.metadata.labels == oldObject.metadata.labels",
                 'message':'Public trust type and ownership must remain unchanged'},
                {'expression':"object.metadata.name == '"+CA_SECRET+"' ? size(object.data) == 1 && 'ca.crt' in object.data : size(object.data) == 2 && 'truststore.p12' in object.data && 'password' in object.data && object.data['password'] == oldObject.data['password']",
                 'message':'Only public CA content may change; no new keys or password changes'}]})
    binding = resource(profile,'admissionregistration.k8s.io/v1','ValidatingAdmissionPolicyBinding',name,
        spec={'policyName':name,'validationActions':['Deny']})
    role = resource(profile,'rbac.authorization.k8s.io/v1','Role',name,profile.core_namespace,
        rules=[{'apiGroups':[''],'resources':['secrets'],'resourceNames':[ISSUER_TRUST,CA_SECRET],
                'verbs':['get','patch']}])
    grant = resource(profile,'rbac.authorization.k8s.io/v1','RoleBinding',name,profile.core_namespace,
        roleRef={'apiGroup':'rbac.authorization.k8s.io','kind':'Role','name':name},
        subjects=[{'kind':'ServiceAccount','name':'fixture-console-coordinator','namespace':profile.core_namespace}])
    return [resource(profile,'v1','Secret',CA_SECRET,profile.core_namespace,type='Opaque',data={'ca.crt':ca}),
            policy,binding,role,grant]


def issuer_reload(spec):
    env=spec['template']['spec']['containers'][0]['env']
    env[:]=[v for v in env if v['name']!='KC_HTTPS_CERTIFICATES_RELOAD_PERIOD']
    env.append({'name':'KC_HTTPS_CERTIFICATES_RELOAD_PERIOD','value':'60s'})


def prepare(args,profile,targets):
    from cluster_console_install import patch
    issuer, = [v for v in targets if v['kind']=='Deployment']
    listener, = [v for v in targets if v['kind']=='Secret' and v['metadata']['name']=='fixture-mcp-bound-mutual']
    import base64
    bundle=setup.kube(args,'get','configmap','spire-bundle','-n',profile.identity_namespace,'-o','json')
    proposed = resources(profile,base64.b64encode(bundle['data']['bundle.crt'].encode()).decode())
    after = deepcopy(issuer)
    issuer_reload(after['spec'])
    patch(args,profile,issuer,after,dry=True)
    retained_ca = None
    for obj in proposed:
        meta = obj['metadata'];scope = ['-n',meta['namespace']] if meta.get('namespace') else []
        current = setup.kube(args,'get',obj['kind'],meta['name'],*scope,'--ignore-not-found','-o','json')
        if current:
            if obj['kind'] != 'Secret':
                raise ValueError('Automatic public trust resource collision; no adoption')
            from cluster_console_operator import receipt
            ledger = receipt(args.ledger, args.console_ledger_sha256)
            recorded = [v for v in ledger.get('created', []) if v['kind'] == 'Secret'
                        and v.get('namespace') == profile.core_namespace and v['metadata']['name'] == CA_SECRET]
            setup.owned(current, profile)
            if (not ledger.get('completed') or ledger.get('installation_profile') != profile.to_dict()
                    or len(recorded) != 1 or recorded[0]['metadata']['uid'] != current['metadata']['uid']
                    or current.get('type') != 'Opaque' or current.get('data') != obj['data']
                    or current['metadata'].get('deletionTimestamp') or current['metadata'].get('ownerReferences')):
                raise ValueError('Exact installer-created public CA Secret required; no adoption')
            retained_ca = current
            continue
        if obj['kind']!='RoleBinding':
            setup.kube(args,'create','--dry-run=server','-f','-','-o','json',value=obj)
    setup.write(args.output_dir/'automatic-trust.plan.private.json',{'objects':proposed,'issuer_after':after})
    return {'objects':proposed,'issuer':after,'bundle':bundle,'retained_ca':retained_ca}


def apply(args,profile,planned):
    from cluster_console_install import namespaces
    issuer = setup.kube(args,'get','deployment','fixture-keycloak-upstream','-n',profile.core_namespace,'-o','json')
    setup.owned(issuer,profile)
    bundle=setup.kube(args,'get','configmap','spire-bundle','-n',profile.identity_namespace,'-o','json')
    if bundle['metadata']['uid']!=planned['bundle']['metadata']['uid'] or bundle['data']!=planned['bundle']['data']:
        raise ValueError('Authority changed during maintenance; inspect without replay')
    expected=deepcopy(planned['issuer']['spec'])
    expected['template'].setdefault('metadata',{}).setdefault('annotations',{})['demo-identity-trust-sha256']=hashlib.sha256(bundle['data']['bundle.crt'].encode()).hexdigest()
    if issuer['metadata']['uid']!=planned['issuer']['metadata']['uid'] or issuer['spec']!=expected:
        raise ValueError('Exact single-rollout issuer configuration required')
    made = []
    for index,obj in enumerate(planned['objects']):
        namespaces(args,profile)
        meta=obj['metadata'];scope=['-n',meta['namespace']] if meta.get('namespace') else []
        current = setup.kube(args,'get',obj['kind'],meta['name'],*scope,'--ignore-not-found','-o','json')
        retained = planned.get('retained_ca') if obj['kind'] == 'Secret' else None
        if retained is not None:
            if (current['metadata']['uid'] != retained['metadata']['uid']
                    or setup.fingerprint(current) != setup.fingerprint(retained)):
                raise ValueError('Recorded public trust Secret changed during maintenance')
            made.append(current)
            continue
        if current:
            raise ValueError('Automatic trust target appeared; inspect without replay')
        setup.kube(args,'create','--dry-run=server','-f','-','-o','json',value=obj)
        setup.write(args.output_dir/f'automatic-trust-{index}.pending.json',obj)
        live=setup.kube(args,'create','-f','-','-o','json',value=obj)
        setup.write(args.output_dir/f'automatic-trust-{index}.receipt.private.json',live)
        made.append(live)
    # Trust refresh already applied the reload option in its single spec patch.
    # Deployment status may change while it rolls out; no second patch races it.
    ca, = [v for v in made if v['kind']=='Secret']
    args.public_trust_ca_uid=ca['metadata']['uid']
    return made
