# SPDX-License-Identifier: Apache-2.0
"""Installer/operator controls for existing private APIs; never a runtime Pod grant."""
from datetime import datetime, timezone
import hashlib
import json
import time
from uuid import uuid4

import identity_demo_setup as setup
from source_render import read_json


def receipt(path, expected):
    path = setup.private_file(path)
    if setup.sha(path) != expected:
        raise ValueError('Exact completed creation receipt hash required')
    return read_json(path)


def recorded(args, profile, records, kind, name):
    matches = [r for r in records if r['kind'] == kind and r['name'] == name]
    live = setup.kube(args, 'get', kind, name, '-n', profile.core_namespace, '-o', 'json')
    setup.owned(live, profile)
    if len(matches) != 1 or live['metadata']['uid'] != matches[0]['uid'] or live['metadata'].get('deletionTimestamp'):
        raise ValueError('Exact recorded operator target required')
    return live


def private_request(args, profile, suffix, data=None):
    """Fixed HTTPS destination from the owned driver; no browser/general proxy.

    Only installer/operator kubeconfigs may execute this fixed command. Runtime
    ServiceAccounts have no Pod exec permission. Credentials stay inside the
    driver, and application authentication/idle checks still authorize the call.
    """
    if suffix not in ('state','pool') or data is not None and suffix != 'pool':
        raise ValueError('Fixed pool/status operation required')
    program = '''import json,os,sys,httpx
from pathlib import Path
value=json.load(sys.stdin)
assert set(value)=={'suffix','data'} and value['suffix'] in ('state','pool')
assert value['data'] is None or value['suffix']=='pool'
key=Path(os.environ['OPERATOR_SECRET_FILE']).read_text().strip()
with httpx.Client(verify='/issuer-ca/service-ca.crt',trust_env=False,follow_redirects=False,timeout=12) as client:
 response=client.request('POST' if value['data'] is not None else 'GET',
  'https://HOST:8444/internal/operator/console/'+value['suffix'],
  headers={'Authorization':'Bearer '+key},json=value['data'])
 assert len(response.content)<=2000000
 print(json.dumps({'status':response.status_code,'body':response.json()}))
'''.replace('HOST', profile.service_host('fixture-identity-operator'))
    result = setup.kube(args, 'exec', '-i', '-n', profile.core_namespace,
        'deployment/fixture-identity-driver', '--', 'python', '-c', program,
        value={'suffix':suffix,'data':data})
    if result.get('status') != 200:
        setup.write(args.output_dir/'private-operator-rejection.private.json', result)
        raise ValueError('Private operator request rejected; inspect retained state')
    return result['body']


def worker(args, profile, records, role):
    name = 'fixture-console-'+role
    deployment = recorded(args,profile,records,'Deployment',name)
    record, = [r for r in records if r['kind']=='Deployment' and r['name']==name]
    if (setup.fingerprint(deployment) != record['fingerprint'] or deployment['spec']['replicas'] != 1
            or deployment.get('status',{}).get('readyReplicas') != 1
            or deployment.get('status',{}).get('observedGeneration',0) < deployment['metadata']['generation']):
        raise ValueError('Exact single ready worker required')
    pods = setup.kube(args,'get','pods','-n',profile.core_namespace,'-l','app='+name,'-o','json')['items']
    current = [p for p in pods if not p['metadata'].get('deletionTimestamp') and p.get('status',{}).get('phase')=='Running']
    if len(current)!=1:
        raise ValueError('One current worker Pod required')
    pod=current[0]
    if (pod['spec'].get('serviceAccountName')!=name or len(pod['spec']['containers'])!=1
            or pod['spec']['containers'][0]['image']!=deployment['spec']['template']['spec']['containers'][0]['image']
            or not all(v.get('ready') for v in pod['status'].get('containerStatuses',[]))):
        raise ValueError('Exact ready scoped worker Pod required')
    owner, = [v for v in pod['metadata'].get('ownerReferences',[]) if v['kind']=='ReplicaSet' and v.get('controller')]
    replica = setup.kube(args,'get','replicaset',owner['name'],'-n',profile.core_namespace,'-o','json')
    if (replica['metadata']['uid']!=owner['uid'] or not any(v.get('kind')=='Deployment'
            and v.get('uid')==deployment['metadata']['uid'] for v in replica['metadata'].get('ownerReferences',[]))):
        raise ValueError('Worker controller association changed')
    claim, = [v['persistentVolumeClaim']['claimName'] for v in pod['spec']['volumes'] if v['name']=='state']
    recorded(args,profile,records,'PersistentVolumeClaim',claim)
    port=18443 if role=='coordinator' else 18444
    names=['installation-profile.json','artifacts.json','runtime-credentials.json','driver-credentials.json',
           'management-ca.crt','service-ca.crt','kubernetes-ca.crt']
    names += ['catalog-credential.json','gateway.receipt.json','sender-trust.receipt.json','inference.json','inference.key'] if role=='coordinator' else ['capacity-budget.json']
    inputs = recorded(args, profile, records, 'Secret', name + '-inputs')
    if 'certificate-management.json' in inputs.get('data', {}):
        names.append('certificate-management.json')
    program='''import hashlib,json,os,subprocess,sys,time
from pathlib import Path
from identity_demo_cluster_bootstrap import mounted
from identity_demo_management_session import validate_profile
value=json.loads(sys.argv[1]);assert os.environ['POD_UID']==value['pod_uid']
files={name:mounted(Path('/runtime-inputs'),name) for name in value['names']}
identity=hashlib.sha256(b''.join(n.encode()+b'\\x00'+files[n] for n in sorted(files))).hexdigest()
config=Path('/state/private')/('config-'+identity[:24])
validate_profile(Path('/state/private/profile'),value['issuer'],value['port'])
health=json.loads(Path('/state/private/worker-lease-health.json').read_text())
assert health['holder'].startswith(value['pod_uid']+'/') and 0<=time.time()-health['at']<15
result=subprocess.run(['oc','--kubeconfig',str(config/'kubeconfig.json'),'whoami'],capture_output=True,text=True,timeout=20)
assert result.returncode==0 and result.stdout.strip()==value['principal']
print(json.dumps({'management_profile_verified':True,'projected_api_identity_verified':True,
 'lease_uid':health['lease_uid'],'holder':health['holder'],'pod_uid':value['pod_uid'],'port':value['port']}))
'''
    observed=setup.kube(args,'exec','-n',profile.core_namespace,pod['metadata']['name'],'--','python3.12','-c',program,
        json.dumps({'names':names,'pod_uid':pod['metadata']['uid'],'port':port,'issuer':profile.origin('fixture-keycloak'),
                    'principal':'system:serviceaccount:'+profile.core_namespace+':'+name}))
    lease=setup.kube(args,'get','lease',name,'-n',profile.core_namespace,'-o','json')
    setup.owned(lease,profile)
    if (lease['metadata']['uid']!=observed['lease_uid'] or lease['spec']['holderIdentity']!=observed['holder']
            or time.time()-datetime.fromisoformat(lease['spec']['renewTime'].replace('Z','+00:00')).timestamp()>12):
        raise ValueError('Fresh matching runtime ownership lease required')
    return observed


def run(args,profile):
    configured=receipt(args.console_configuration_receipt,args.console_configuration_sha256)
    if not configured.get('applied') or configured.get('stage')!='configure':
        raise ValueError('Completed private console configuration required')
    recorded(args,profile,configured['updated'],'Deployment','fixture-identity-driver')
    before=private_request(args,profile,'pool')
    setup.write(args.output_dir/'pool-before.private.json',before)
    if args.console_runtime_stage=='status':
        state=private_request(args,profile,'state');setup.write(args.output_dir/'state.private.json',state)
        return {'cluster_runtime_status_observed':True,'online':state.get('online'),
                'phase':state.get('phase'),'reason':state.get('reason'),'unused_contexts':before.get('unused'),
                'automatic':before.get('automatic')}
    from identity_demo_execution_setup import inspect_state
    args.namespace=profile.core_namespace
    initial = inspect_state(args)
    if not initial['rollback_quiescent']:
        raise ValueError('Idle certain installation required for scheduling change')
    enable=args.console_runtime_stage=='automatic-enable'
    resume = bool(getattr(args, 'resume_retired_pool', False))
    if resume and not enable:
        raise ValueError('Retired-pool resume requires explicit automatic-enable')
    proof=[]
    if enable:
        created=receipt(args.console_worker_receipt,args.console_worker_sha256)
        if not created.get('applied') or created.get('runtime')!='cluster':
            raise ValueError('Completed cluster worker creation receipt required')
        if before.get('contexts') or before.get('unused') or before.get('automatic'):
            raise ValueError('Initial empty pool required; existing inventory needs explicit migration review')
        if resume and (initial.get('pool_items', 0) <= 0 or initial.get('non_retired_pool_items') != 0):
            raise ValueError('History-preserving resume requires only durable retired inventory')
        proof=[worker(args,profile,created['created'],role) for role in ('coordinator','preparer')]
        if proof[0]['pod_uid']==proof[1]['pod_uid'] or proof[0]['port']==proof[1]['port']:
            raise ValueError('Separate worker management contexts required')
        for namespace in (profile.triage_namespace,profile.reader_namespace):
            if setup.kube(args,'get','sandboxes.agents.x-k8s.io','-n',namespace,'-o','json')['items']:
                raise ValueError('Unaccounted native context requires operator review')
        from cluster_console_resources import capacity
        from identity_demo_capacity import namespace_capacity
        _,budget=capacity(profile);path=args.output_dir/'capacity-budget.json';setup.write(path,budget)
        args.namespace_capacity_budget_file=str(path)
        namespace_capacity(args,8,{'triage':6,'reader':2})
        wait_ready(args, profile)
    proof_path=args.output_dir/'pool-activation.receipt.private.json'
    setup.write(proof_path,{'enabled':enable,'target':8,'limit':12,'worker_checks':proof,
        'resume_retired_pool':resume,'checked_at':int(time.time())})
    mode=getattr(args,'pool_mode','legacy')
    if enable and mode=='profiles':
        from identity_demo_pool_profiles import validate
        filename=getattr(args,'pool_profile_configuration',None)
        configuration=validate(read_json(setup.private_file(filename))) if filename else demo_configuration(getattr(args, "workload_image", None))
        setup.write(args.output_dir/'pool-profile-configuration.private.json',configuration)
        payload={'action':'profiles','configuration':configuration,'receipt_sha256':setup.sha(proof_path)}
    else:
        payload={'action':'automatic','enabled':enable,'receipt_sha256':setup.sha(proof_path),
                 'retired_workloads':[], 'initial_empty':enable and not resume}
    if args.apply:
        setup.write(args.output_dir/'pool-activation.pending.json',payload)
        after=private_request(args,profile,'pool',payload)
        setup.write(args.output_dir/'pool-after.private.json',after)
    return {'applied':args.apply,'automatic_pool_enabled':enable if args.apply else False,
            'scoped_worker_profiles_verified':len(proof),'target_ready':8,'managed_limit':12,
            'existing_legacy_inventory_adopted':False,'retired_history_preserved':resume,
            'mutation_replayed':False,'pool_mode':mode if enable else 'disabled'}


def wait_ready(args, profile):
    """Wait only through harmless observations; never retry a state mutation."""
    deadline=time.monotonic()+90
    while True:
        state=private_request(args,profile,'state')
        setup.write(args.output_dir/('readiness-observation-'+uuid4().hex+'.private.json'),state)
        if (not state.get('online') or any(state.get(k) for k in ('running','uncertain','recovery_required'))
                or state.get('phase') not in ('ready','preparing','reconnecting')):
            raise ValueError('Coordinator security/recovery gate blocks automatic scheduling')
        if state['phase']=='ready':return
        if time.monotonic()>=deadline:
            raise ValueError('Coordinator readiness observation timed out; no activation sent')
        time.sleep(1)

def demo_configuration(workload_image=None):
    """The supported Jira demo uses shared capacity; its scopes bind at allocation."""
    import yaml
    from deployment_artifacts import configured_native_image
    from identity_demo_spire_registration import CVE_IMAGE
    from identity_demo_jira_contract import JIRA
    from identity_demo_connector import Denied

    from deployment_profile import active_profile
    from identity_demo_pool_profiles import validate
    installation = active_profile()
    supervisor = configured_native_image("openshell_supervisor")
    if not supervisor:
        raise Denied("pool_native_artifacts")
    policy = yaml.safe_load(
        (
            setup.ROOT / "tests/identity_demo/cve-runtime-policy.yaml"
        ).read_text()
    )
    base = {
        "service_account": "fixture-openshell-sandbox",
        "workload_image": CVE_IMAGE if workload_image is None else workload_image,
        "supervisor_image": supervisor,
        "policy": policy,
        "trust_domain": installation.trust_domain,
        "issuer": installation.native_build_contract["OPENSHELL_DEMO_JWT_AUDIENCE"],
        "tools": ["jira.issue.read", "jira.issue.create"],
    }
    value = {
        "schema_version": 2,
        "profiles": [
            dict(
                base,
                id="triage-v1",
                role="triage",
                namespace=installation.triage_namespace,
                write_actions=["jira.issue.create"],
                target=6,
            ),
            dict(
                base,
                id="reader-v1",
                role="reader",
                namespace=installation.reader_namespace,
                tools=["jira.issue.read"],
                write_actions=[],
                target=2,
            ),
        ],
        "workflows": [
            {
                "workflow": workflow,
                "profile": profile,
                "project": project,
                "connector": JIRA.identifier,
            }
            for workflow, profile, project in [
                ("cve", "triage-v1", "TEST"),
                ("cve", "reader-v1", "TEST"),
                ("incident-triage", "triage-v1", "OPS"),
                ("service-request", "triage-v1", "SERVICE"),
            ]
        ],
    }
    return validate(value)
