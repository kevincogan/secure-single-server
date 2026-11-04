# SPDX-License-Identifier: Apache-2.0
"""Plan by default; install, qualify and clean only receipt-bound proof resources."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import time

from agent_security_runtime import strict_json
from deployment import render, narrow_namespace_policy, isolated_route_filter


RESOURCES={'ServiceAccount':'serviceaccounts','Service':'services','Secret':'secrets','ConfigMap':'configmaps',
    'PersistentVolumeClaim':'persistentvolumeclaims','Deployment':'deployments','Route':'routes',
    'HTTPRoute':'httproutes','DestinationRule':'destinationrules','NetworkPolicy':'networkpolicies','EnvoyFilter':'envoyfilters'}


def private(path, *, directory=False):
    p=Path(path)
    if not p.is_absolute() or p.is_symlink() or not p.exists() or p.stat().st_mode & 0o077:
        raise ValueError('Private absolute existing path required')
    if directory!=p.is_dir():raise ValueError('Wrong private path type')
    return p


def save(path,value):
    path.write_text(json.dumps(value,indent=2)+'\n');path.chmod(0o600)


def fingerprint(value):
    payload={k:v for k,v in value.items() if k not in {'metadata','status'}}
    # These fields are populated asynchronously by platform controllers. PVC
    # binding is immutable after assignment; cleanup still pins its original UID.
    if value.get('kind')=='ServiceAccount':
        payload={k:v for k,v in payload.items() if k not in {'secrets','imagePullSecrets'}}
    elif value.get('kind')=='PersistentVolumeClaim':
        payload['spec']={k:v for k,v in payload['spec'].items() if k!='volumeName'}
    return hashlib.sha256(json.dumps(payload,sort_keys=True).encode()).hexdigest()


class Cluster:
    def __init__(self,kubeconfig,config):
        self.api=['oc','--kubeconfig',str(private(kubeconfig)),'--request-timeout=30s']
        self.config=config
        self.diagnostics=None
        target=self.call(['config','view','--minify','-o','jsonpath={.clusters[0].cluster.server}'],raw=True).decode().strip()
        if target.rstrip('/')!=config['profile']['expected_server'].rstrip('/'):
            raise ValueError('Authenticated cluster target differs')
        receipt=strict_json(private(config['namespace_receipt']).read_bytes())
        ns=config['profile']['core_namespace']
        current=self.call(['get','namespace',ns,'-o','json'])
        if (receipt['kind']!='Namespace' or receipt['metadata']['name']!=ns
                or current['metadata']['uid']!=receipt['metadata']['uid']
                or current['metadata']['labels'].get('identity-demo-owner')!=config['profile']['owner']
                or current['metadata'].get('deletionTimestamp')):
            raise ValueError('Original candidate namespace creation receipt required')

    def call(self,words,value=None,raw=False):
        result=subprocess.run(self.api+words,input=json.dumps(value).encode() if value is not None else None,
            capture_output=True,timeout=90)
        if result.returncode:
            if self.diagnostics is not None:
                save(self.diagnostics / ('api-error-' + secrets.token_hex(8) + '.private.json'), {
                    'command': words, 'exit': result.returncode,
                    'stderr': result.stderr[:65536].decode(errors='replace')})
            raise RuntimeError('Proof API operation failed; inspect the original private checkpoint, never replay an uncertain write')
        return result.stdout if raw else strict_json(result.stdout) if result.stdout.strip() else None

    def uri(self,value):
        api=value['apiVersion'];meta=value['metadata']
        if (meta.get('namespace')!=self.config['profile']['core_namespace']
                or meta.get('labels',{}).get('identity-demo-owner')!=self.config['profile']['owner']
                or meta.get('labels',{}).get('identity-demo-document-proof')!='true'
                or value['kind'] not in RESOURCES or not meta['name'].startswith('fixture-document-')):
            raise ValueError('Exact owned optional proof resource required')
        return ('/api/v1' if api=='v1' else '/apis/'+api)+'/namespaces/'+meta['namespace']+'/'+RESOURCES[value['kind']]+'/'+meta['name']

    def namespace_policy(self):
        original = strict_json(private(self.config['namespace_policy_receipt']).read_bytes())
        meta = original['metadata']
        if (original['kind'] != 'NetworkPolicy' or meta['name'] != 'fixture-isolation'
                or meta.get('namespace') != self.config['profile']['core_namespace']
                or meta.get('labels', {}).get('identity-demo-owner') != self.config['profile']['owner']):
            raise ValueError('Original owned namespace policy receipt required')
        uri = '/apis/networking.k8s.io/v1/namespaces/' + meta['namespace'] + '/networkpolicies/fixture-isolation'
        return original, uri

    def change_namespace_policy(self, output, *, restore=False):
        original, uri = self.namespace_policy()
        current = self.call(['get', '--raw', uri])
        before = output / 'namespace-policy.before.private.json'
        after = output / 'namespace-policy.after.private.json'
        receipt = output / ('namespace-policy.restored.json' if restore else 'namespace-policy.applied.json')
        if receipt.exists() or receipt.with_suffix('.pending.json').exists():
            raise ValueError('Namespace policy checkpoint exists; inspect without replay')
        expected = strict_json(private(after).read_bytes()) if restore else original
        if current['metadata']['uid'] != expected['metadata']['uid'] or fingerprint(current) != fingerprint(expected):
            raise ValueError('Original namespace policy replaced or changed')
        desired = strict_json(private(before).read_bytes())['spec'] if restore else narrow_namespace_policy(current)
        patch = [{'op': 'test', 'path': '/metadata/uid', 'value': current['metadata']['uid']},
            {'op': 'test', 'path': '/metadata/resourceVersion', 'value': current['metadata']['resourceVersion']},
            {'op': 'test', 'path': '/spec', 'value': current['spec']},
            {'op': 'replace', 'path': '/spec', 'value': desired}]
        words = ['patch', 'networkpolicy', 'fixture-isolation', '-n', current['metadata']['namespace'],
            '--type=json', '-p', json.dumps(patch), '-o', 'json']
        self.call([*words, '--dry-run=server'])
        if not restore:
            save(before, current)
        save(receipt.with_suffix('.pending.json'), {'uri': uri, 'patch': patch})
        changed = self.call(words)
        save(receipt, {'uid': changed['metadata']['uid'], 'changed': True})
        if not restore:
            save(after, changed)

    def create(self,value,path):
        if path.exists() or path.with_suffix('.pending.json').exists():
            raise ValueError('Creation checkpoint exists; reconcile it without replay')
        self.uri(value)
        collision=self.call(['get','-f','-','--ignore-not-found','-o','json'],value)
        if collision:raise ValueError('Proof refuses adoption of existing resources')
        self.call(['create','--dry-run=server','-f','-','-o','json'],value)
        save(path.with_suffix('.pending.json'),value)
        made=self.call(['create','-f','-','-o','json'],value)
        if (made['metadata']['name']!=value['metadata']['name'] or not made['metadata'].get('uid')):
            raise ValueError('Unexpected creation response')
        save(path,made)
        return made

    def delete(self,record,path):
        if path.exists() or path.with_suffix('.pending.json').exists():
            raise ValueError('Deletion checkpoint exists; reconcile it without replay')
        uri=self.uri(record)
        current=self.call(['get','--raw',uri])
        self.uri(current)
        if (current['metadata']['uid']!=record['metadata']['uid']
                or fingerprint(current)!=fingerprint(record)):
            raise ValueError('Proof resource replaced or configuration changed')
        options={'apiVersion':'v1','kind':'DeleteOptions','preconditions':{
            'uid':current['metadata']['uid'],'resourceVersion':current['metadata']['resourceVersion']},
            'propagationPolicy':'Foreground'}
        save(path.with_suffix('.pending.json'),{'uri':uri,'options':options})
        result=self.call(['delete','--raw',uri,'-f','-'],options)
        save(path,{'uid':current['metadata']['uid'],'deleted':True,'response':result})



def gateway_routes(cluster):
    ns = cluster.config['profile']['core_namespace']
    pods = cluster.call(['get', 'pods', '-n', ns, '-l',
        'gateway.networking.k8s.io/gateway-name=fixture-mcp', '-o', 'json'])['items']
    pod, = [p for p in pods if p.get('status', {}).get('phase') == 'Running'
        and not p['metadata'].get('deletionTimestamp')]
    gateway = cluster.call(['get', 'gateway', 'fixture-mcp', '-n', ns, '-o', 'json'])
    if gateway['metadata'].get('labels', {}).get('identity-demo-owner') != cluster.config['profile']['owner']:
        raise ValueError('Owned application Gateway required')
    container, = pod['spec']['containers']
    dump = cluster.call(['exec', '-n', ns, pod['metadata']['name'], '-c', container['name'],
        '--', 'pilot-agent', 'request', 'GET', 'config_dump'], raw=True)
    if len(dump) > 8_000_000:
        raise ValueError('Bounded effective gateway observation required')
    value = json.loads(dump)  # Trusted, bounded Envoy diagnostics, not a tool request.
    hosts = []
    def visit(item):
        if isinstance(item, dict):
            hosts.extend(item.get('virtual_hosts', []))
            for child in item.values():
                visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)
    visit(value)
    selected, = [h for h in hosts if h.get('name') ==
        'fixture-mcp-bound.' + ns + '.svc.cluster.local:8443']
    return selected


def configure_document_route(cluster, output, receipts):
    deadline = time.monotonic() + 90
    while True:
        host = gateway_routes(cluster)
        matches = [r for r in host['routes'] if r.get('match', {}).get('path') == '/_document_proof/mcp']
        if len(matches) == 1:
            break
        if time.monotonic() >= deadline:
            raise ValueError('Exact document route has not reconciled; inspect without reinstalling')
        time.sleep(2)
    document = matches[0]
    jira, = [r for r in host['routes'] if r.get('match', {}).get('path') == '/mcp']
    save(output / 'gateway-route.before.private.json', {'jira': jira, 'document': document,
        'vhost_filters': host.get('typed_per_filter_config', {})})
    override = isolated_route_filter(cluster.config['profile']['core_namespace'],
        cluster.config['profile']['owner'], document['name'])
    cluster.create(override, receipts / '999-route.json')
    expected = override['spec']['configPatches'][0]['patch']['value']['typed_per_filter_config']
    deadline = time.monotonic() + 60
    while True:
        current = gateway_routes(cluster)
        new_doc, = [r for r in current['routes'] if r.get('name') == document['name']]
        new_jira, = [r for r in current['routes'] if r.get('name') == jira['name']]
        if new_jira != jira or current.get('typed_per_filter_config', {}) != host.get('typed_per_filter_config', {}):
            raise ValueError('The original Jira route/filter configuration changed')
        if all(new_doc.get('typed_per_filter_config', {}).get(k) == v for k, v in expected.items()):
            save(output / 'gateway-route.after.private.json', {'jira_unchanged': True,
                'document': new_doc, 'vhost_filters_unchanged': True})
            return
        if time.monotonic() >= deadline:
            raise ValueError('Exact document filter overrides have not reconciled')
        time.sleep(2)


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',nargs='?',default='plan',choices=['plan','install','run','cleanup'])
    parser.add_argument('--resume-setup',action='store_true',help='Explicit recovery of verified empty runs before provider setup only')
    parser.add_argument('--config',required=True)
    parser.add_argument('--kubeconfig',required=True)
    parser.add_argument('--output-dir',required=True)
    args=parser.parse_args()
    if args.resume_setup and args.action!='run':raise ValueError('Setup recovery applies only to run')
    config=strict_json(private(args.config).read_bytes())
    cluster=Cluster(args.kubeconfig,config)
    output=Path(args.output_dir)
    if not output.is_absolute() or output.is_symlink():raise ValueError('Absolute private output required')
    output.mkdir(mode=0o700,exist_ok=True);private(output,directory=True)
    cluster.diagnostics=output
    state=output/'plan.private.json'
    if args.action=='plan':
        if state.exists():raise ValueError('Plan already exists; use its original immutable checkpoint')
        policy, _ = cluster.namespace_policy()
        narrow_namespace_policy(policy)
        keys={k:secrets.token_urlsafe(32) for k in ['write','observe','operator']}
        objects=render(config,keys)
        for value in objects:cluster.uri(value)
        from issuer import ProofClient, admin_api
        client_plan = ProofClient(admin_api(config, output), config, output).plan()
        save(state,{'configuration_sha256':fingerprint(config),'objects':objects,'issuer_client':client_plan})
        print(json.dumps({'planned_resources':len(objects),'cluster_changed':False,'proof_passed':False}))
        return
    planned=strict_json(private(state).read_bytes())
    if planned['configuration_sha256']!=fingerprint(config):raise ValueError('Configuration changed after review')
    receipts=output/'created';receipts.mkdir(mode=0o700,exist_ok=True)
    if args.action=='install':
        if list(receipts.glob('*')):raise ValueError('Installation already started; inspect without replay')
        # All collisions/admission are checked before the first write.
        for value in planned['objects']:
            if cluster.call(['get','-f','-','--ignore-not-found','-o','json'],value):raise ValueError('Resource collision')
            cluster.call(['create','--dry-run=server','-f','-','-o','json'],value)
        from issuer import ProofClient, admin_api
        ProofClient(admin_api(config, output), config, output).install(planned['issuer_client'])
        cluster.change_namespace_policy(output)
        for i,value in enumerate(planned['objects']):cluster.create(value,receipts/f'{i:03d}.json')
        configure_document_route(cluster, output, receipts)
        save(output/'installed.json',{'installed':True,'proof_passed':False})
    elif args.action=='run':
        if not (output/'installed.json').exists():raise ValueError('Original installation checkpoint required')
        from qualification import run
        run(cluster,config,output,resume_setup=args.resume_setup)
    else:
        if not config.get('disposable_synthetic_data'):raise ValueError('Explicit disposable proof scope required')
        records=[strict_json(f.read_bytes()) for f in sorted(receipts.glob('*.json')) if '.pending.' not in f.name]
        cleanup=output/'cleanup';cleanup.mkdir(mode=0o700,exist_ok=True)
        # Delete workloads first, preserving fail-closed policies until the end.
        records.sort(key=lambda v:0 if v['kind']=='Deployment' else 2 if v['kind']=='NetworkPolicy' else 1)
        workloads_gone = False
        for i,value in enumerate(records):
            if value['kind'] != 'Deployment' and not workloads_gone:
                # Do not remove isolation while a terminating Pod can still use credentials.
                for deployment in [v for v in records if v['kind'] == 'Deployment']:
                    cluster.call(['wait', '--for=delete', 'deployment/' + deployment['metadata']['name'],
                        '-n', config['profile']['core_namespace'], '--timeout=45s'], raw=True)
                pods = cluster.call(['get', 'pods', '-n', config['profile']['core_namespace'],
                    '-l', 'identity-demo-document-proof=true', '-o', 'json'])
                if pods['items']:
                    raise ValueError('Proof Pods still exist; keep isolation and inspect cleanup')
                workloads_gone = True
            cluster.delete(value,cleanup/f'{i:03d}.json')
        cluster.change_namespace_policy(output, restore=True)
        from issuer import ProofClient, admin_api
        ProofClient(admin_api(config, output), config, output).cleanup()
        save(output/'cleanup.json',{'removed_recorded_objects':len(records),'namespaces_or_shared_resources_deleted':False})


if __name__=='__main__':main()
