# SPDX-License-Identifier: Apache-2.0
"""Temporary, credential-free interface probes inside one owned namespace."""
import json
import subprocess
import time
from uuid import uuid4

from deployment_profile import DeploymentProfile
import identity_demo_setup as setup
from source_render import read_json


MARKER = "DEMO_RUNTIME_CONTRACT_RESULT="
SAFE_ERRORS = {"KeyError", "ImportError", "ModuleNotFoundError", "AssertionError", "PermissionError",
               "FileNotFoundError", "RuntimeError", "TypeError", "ValueError", "OSError", "SystemExit"}
SAFE_ENV = {"JIRA_SERVER", "JIRA_USER", "JIRA_TOKEN", "ADMIN_PASSWORD", "AUTH_MODE", "BASE_URL"}


def wrapped_probe(code):
    # Never stringify an exception: module initialisers can include credentials.
    return ("import json, sys\ntry:\n" + "\n".join("    " + line for line in code.splitlines()) +
        "\nexcept (Exception, SystemExit) as error:\n    data={'error_type':type(error).__name__}\n" +
        "    if isinstance(error,KeyError) and error.args and isinstance(error.args[0],str) and error.args[0] in " + repr(tuple(sorted(SAFE_ENV))) + ":\n" +
        "        data['missing_env']=error.args[0]\n" +
        "    print(" + repr(MARKER) + "+json.dumps(data),flush=True)\n    sys.exit(1)\n")


def diagnostic_lines(text):
    result = {}
    for line in text.splitlines():
        if not line.startswith(MARKER):
            continue
        try:
            value = json.loads(line[len(MARKER):])
        except (ValueError, TypeError):
            continue
        if isinstance(value, dict) and isinstance(value.get('error_type'), str) and value['error_type'] in SAFE_ERRORS:
            result['error_type'] = value['error_type']
            if isinstance(value.get('missing_env'), str) and value['missing_env'] in SAFE_ENV:
                result['missing_env'] = value['missing_env']
    return result


def diagnostics(args, profile, created, objects):
    result = {}
    for job in (v for v in created if v['kind'] == 'Job'):
        pods = setup.kube(args, 'get', 'pods', '-n', profile.core_namespace, '-l',
                          'batch.kubernetes.io/job-name=' + job['name'], '-o', 'json')['items']
        for pod in pods:
            if not any(v.get('kind') == 'Job' and v.get('uid') == job['uid'] and v.get('controller')
                       for v in pod['metadata'].get('ownerReferences', [])):
                raise ValueError('Probe diagnostic Pod owner changed')
            uri = '/api/v1/namespaces/' + profile.core_namespace + '/pods/' + pod['metadata']['name'] + '/log?container=probe&tailLines=20&limitBytes=16384'
            output = subprocess.run([args.oc, '--kubeconfig', args.kubeconfig, '--request-timeout=20s',
                                    'get', '--raw', uri], capture_output=True, text=True, timeout=45)
            result[job['name']] = diagnostic_lines(output.stdout) if output.returncode == 0 else {'diagnostic_available': False}
    setup.write(args.output_dir / 'runtime-safe-diagnostics.json', result)


def probe_objects(profile, images, probes, nonce):
    labels = {**profile.labels, 'identity-demo-runtime-probe': nonce, 'identity-demo-installer-child': 'true'}
    def obj(api, kind, name, spec):
        return {'apiVersion': api, 'kind': kind, 'metadata': {'name': name,
                'namespace': profile.core_namespace, 'labels': dict(labels)}, 'spec': spec}
    policy = obj('networking.k8s.io/v1', 'NetworkPolicy', 'fixture-runtime-check-' + nonce,
        {'podSelector': {'matchLabels': {'identity-demo-runtime-probe': nonce}},
         'policyTypes': ['Ingress', 'Egress'], 'ingress': [], 'egress': []})
    objects = [policy]
    for role, image in images.items():
        objects.append(obj('batch/v1', 'Job', 'fixture-check-' + role.replace('_', '-') + '-' + nonce,
            {'backoffLimit': 0, 'activeDeadlineSeconds': 180,
             'template': {'metadata': {'labels': dict(labels)}, 'spec': {
                'restartPolicy': 'Never', 'automountServiceAccountToken': False,
                'securityContext': {'runAsNonRoot': True, 'seccompProfile': {'type': 'RuntimeDefault'}},
                'containers': [{'name': 'probe', 'image': image, 'imagePullPolicy': 'IfNotPresent',
                    'command': ['python3.12' if role == 'console_runtime' else 'python', '-c', wrapped_probe(probes[role])],
                    'env': [{'name': 'PYTHONDONTWRITEBYTECODE', 'value': '1'}],
                    'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                                        'capabilities': {'drop': ['ALL']}},
                    'resources': {'requests': {'cpu': '50m', 'memory': '128Mi'},
                                  'limits': {'cpu': '500m', 'memory': '1Gi'}},
                    'volumeMounts': [{'name': 'tmp', 'mountPath': '/tmp'}]}],
                'volumes': [{'name': 'tmp', 'emptyDir': {'sizeLimit': '64Mi'}}]}}}))
    return objects


def cleanup(args, profile, created):
    """Delete only this invocation's exact UIDs; never select by a name prefix."""
    for index, item in enumerate(reversed(created)):
        kind, name, uid = item['kind'], item['name'], item['uid']
        live = setup.kube(args, 'get', kind, name, '-n', profile.core_namespace, '-o', 'json')
        setup.owned(live, profile)
        if live['metadata']['uid'] != uid:
            raise ValueError('Runtime probe UID changed; cleanup stopped')
        resource = 'jobs' if kind == 'Job' else 'networkpolicies'
        api = '/apis/batch/v1' if kind == 'Job' else '/apis/networking.k8s.io/v1'
        uri = api + '/namespaces/' + profile.core_namespace + '/' + resource + '/' + name
        setup.write(args.output_dir / f'cleanup-{index:02}.pending.json', item)
        setup.kube(args, 'delete', '--raw', uri, '-f', '-', value={
            'apiVersion': 'v1', 'kind': 'DeleteOptions', 'propagationPolicy': 'Foreground',
            'preconditions': {'uid': uid, 'resourceVersion': live['metadata']['resourceVersion']}})
        setup.write(args.output_dir / f'cleanup-{index:02}.receipt.json', {'uid': uid, 'delete_requested': True})


def run(args, images, probes):
    profile = DeploymentProfile.from_dict(read_json(setup.private_file(args.installation_profile)))
    args.profile = profile
    setup.target(args)
    namespace = setup.kube(args, 'get', 'namespace', profile.core_namespace, '-o', 'json')
    setup.owned(namespace, profile)
    objects = probe_objects(profile, images, probes, uuid4().hex[:10])
    setup.write(args.output_dir / 'cluster-runtime.plan.json', {'namespace_uid': namespace['metadata']['uid'], 'objects': objects})
    for obj in objects:
        if setup.kube(args, 'get', obj['kind'], obj['metadata']['name'], '-n', profile.core_namespace,
                      '--ignore-not-found', '-o', 'json'):
            raise ValueError('Runtime probe collision')
        setup.kube(args, 'create', '--dry-run=server', '-f', '-', '-o', 'json', value=obj)
    if not args.apply:
        return {'runtime_checks_planned': True, 'server_admission_passed': True,
                'executed': False, 'cluster_changed': False}
    created = []
    for index, obj in enumerate(objects):
        setup.write(args.output_dir / f'probe-{index:02}.pending.json', {'object': obj})
        value = setup.kube(args, 'create', '-f', '-', '-o', 'json', value=obj)
        item = {'kind': obj['kind'], 'name': obj['metadata']['name'], 'uid': value['metadata']['uid']}
        created.append(item)
        setup.write(args.output_dir / f'probe-{index:02}.created.json', item)
    jobs = [o for o in objects if o['kind'] == 'Job']
    deadline = time.monotonic() + 240
    results = {}
    while True:
        for obj in jobs:
            name = obj['metadata']['name']
            if name in results:
                continue
            value = setup.kube(args, 'get', 'job', name, '-n', profile.core_namespace, '-o', 'json')
            if value['metadata']['uid'] != next(c['uid'] for c in created if c['name'] == name):
                raise ValueError('Probe job identity changed')
            conditions = value.get('status', {}).get('conditions', [])
            if any(c['type'] in ('Complete', 'Failed') and c['status'] == 'True' for c in conditions):
                results[name] = any(c['type'] == 'Complete' and c['status'] == 'True' for c in conditions)
        if len(results) == len(jobs):
            break
        if time.monotonic() >= deadline:
            setup.write(args.output_dir / 'runtime-timeout.json', {'completed_jobs': results,
                'active_deadline_seconds': 180, 'operator_review_required': True})
            raise TimeoutError('Probe did not reach a confirmed terminal state; inspect receipts')
        time.sleep(3)
    setup.write(args.output_dir / 'runtime-interface-results.json', {'jobs': results, 'log_bodies_exported': False})
    diagnostics(args, profile, created, objects)
    cleanup(args, profile, created)
    return {'runtime_interface_checks_passed': all(results.values()), 'executed': True,
            'temporary_resources_delete_requested': True, 'cluster_changed': True,
            # Namespace allow rules are additive; this probe does not certify isolation.
            'credentials_mounted': False, 'network_access': None, 'network_isolation_verified': False,
            'source_and_redistribution_approved': False, 'functional_scenarios_proven': False}
