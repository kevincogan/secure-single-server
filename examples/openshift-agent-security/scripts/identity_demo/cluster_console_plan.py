# SPDX-License-Identifier: Apache-2.0
"""Review-only runtime boundary plan, through the existing setup entry point.

Activation is deliberately unavailable until the registration boundary, runtime
image and candidate recovery/functional acceptance have evidence. This helper
does not grant a preparer unrestricted SPIRE registration or server execution.
"""
from deployment_profile import DeploymentProfile
from source_render import read_json


ROLES=('coordinator','preparer')


def objects(profile):
    result=[]
    ns=profile.core_namespace
    for role in ROLES:
        name='fixture-console-'+role
        def obj(api,kind,suffix,**fields):
            return {'apiVersion':api,'kind':kind,'metadata':{'name':name+suffix,'namespace':ns,
                    'labels':dict(profile.labels)},**fields}
        result.append(obj('v1','ServiceAccount','',automountServiceAccountToken=False))
        result.append(obj('coordination.k8s.io/v1','Lease','',spec={'leaseDurationSeconds':45}))
        result.append(obj('rbac.authorization.k8s.io/v1','Role','-lease',rules=[{
            'apiGroups':['coordination.k8s.io'],'resources':['leases'],
            'resourceNames':[name],'verbs':['get','update']}]))
        result.append(obj('rbac.authorization.k8s.io/v1','RoleBinding','-lease',
            roleRef={'apiGroup':'rbac.authorization.k8s.io','kind':'Role','name':name+'-lease'},
            subjects=[{'kind':'ServiceAccount','name':name,'namespace':ns}]))
    return result


def run(args):
    import identity_demo_setup as setup
    if args.apply:
        raise ValueError('Runtime activation unavailable until the recorded boundary and acceptance gates pass')
    profile=DeploymentProfile.from_dict(read_json(setup.private_file(args.installation_profile)))
    proposed=objects(profile)
    setup.write(args.output_dir/'cluster-runtime.boundary-plan.json',{
        'schema_version':1,'installation_profile':profile.to_dict(),
        'review_only':True,'objects':proposed,
        'required_runtime_contract':{
            'image':'one approved digest-pinned Linux AMD64 image; not yet built or accepted',
            'deployment_strategy':'Recreate','replicas_per_role':1,
            'private_operator_origin':'https://'+profile.service_host('fixture-identity-operator')+':8444',
            'token':'Pod-bound projected tokenFile; verify API authentication and rotation',
            'runtime_secrets':'separate role credentials; no human passwords or bootstrap administrators',
            'state':'separate persistent coordinator/preparer state; preserve history and quarantine',
            'registration_authority':'required; no unrestricted ClusterStaticEntry creation or SPIRE-server exec granted'},
        'blocking_acceptance':[
            'Platform-reviewed enforceable per-installation registration authority',
            'Runtime image, private listener networking and scoped native/backend integration',
            'Durable worker fencing and stopped-local-service handover',
            'Isolated candidate token rotation, recovery, browser/CLI and three-workflow acceptance',
            'Measured complete resource budgets, final image scans and release disposition'],
        'alternative_for_platform_review':'Evaluate installed ClusterSPIFFEID controller-derived exact-Pod registrations; no runtime registration writes. Do not migrate without equivalent attestation/binding tests.',
        'broad_registration_permission_granted':False,'spire_server_exec_granted':False,
        'cluster_changed':False,'mac_independence_proven':False})
    return {'runtime':'cluster','review_plan_prepared':True,'activation_ready':False,
            'cluster_changed':False,'mac_independence_proven':False}
