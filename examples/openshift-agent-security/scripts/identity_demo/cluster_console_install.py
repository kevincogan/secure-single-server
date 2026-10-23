# SPDX-License-Identifier: Apache-2.0
"""Prepare runtime prerequisites through the existing setup entry point/ledger."""
from pathlib import Path

import identity_demo_setup as setup
from source_render import read_json
from deployment_profile import DeploymentProfile
from deployment_artifacts import validate_artifacts
from cluster_console_resources import permissions, capacity
from identity_demo_controller_identity import policy, gateway_policy


def namespaces(args, profile):
    receipt = setup.private_file(args.namespace_creation_receipt)
    if setup.sha(receipt) != args.namespace_creation_sha256:
        raise ValueError('Exact namespace creation receipt hash required')
    records = read_json(receipt).get('created', [])
    for name in profile.application_namespaces:
        found = [r for r in records if r['kind'] == 'Namespace' and r['name'] == name]
        if len(found) != 1:
            raise ValueError('Three namespace creation identities required')
        live = setup.kube(args, 'get', 'namespace', name, '-o', 'json')
        setup.owned(live, profile)
        if live['metadata']['uid'] != found[0]['uid'] or live['metadata'].get('deletionTimestamp'):
            raise ValueError('Owned namespace was replaced or is terminating')


def run(args):
    profile = DeploymentProfile.from_dict(read_json(setup.private_file(args.installation_profile)))
    args.profile = profile
    setup.target(args)
    namespaces(args, profile)
    if args.console_runtime_stage == 'update-workloads':
        from cluster_console_update import run as update
        return update(args, profile)
    if args.console_runtime_stage == 'realm-permissions':
        from cluster_console_realm import run as realm_permissions
        return realm_permissions(args, profile)
    if args.console_runtime_stage == 'gateway-observation':
        return gateway_observation(args, profile)
    if args.console_runtime_stage in ('status','automatic-enable','automatic-disable'):
        from cluster_console_operator import run as operate
        return operate(args, profile)
    if args.console_runtime_stage == 'trust-observation':
        return trust_observation(args, profile)
    if args.console_runtime_stage == 'configure':
        return configure(args, profile)
    if args.console_runtime_stage == 'workloads':
        return workloads(args, profile)
    if args.console_runtime_stage == 'permissions':
        from gateway_credential_route import READ_NAME
        proposed = permissions(profile, READ_NAME+'-catalog')
        quotas, budget = capacity(profile)
        proposed += quotas
        setup.write(args.output_dir/'capacity-budget.json', budget)
    else:
        artifacts = validate_artifacts(read_json(setup.private_file(args.artifacts_file)))
        if artifacts.get('native_build_contract') != profile.native_build_contract:
            raise ValueError('Target-bound native artifacts required')
        proposed = [policy(profile, role, artifacts['images']['openshell_supervisor']) for role in ('triage','reader')]
        proposed.append(gateway_policy(profile, artifacts['images']['openshell_gateway']))
    # All proposed objects are generated above, never loaded as arbitrary grants.
    # Reject every occupied name before the first mutation; no implicit adoption.
    setup.write(args.output_dir/'console-prerequisites.plan.json', {'objects': proposed,
        'stage': args.console_runtime_stage, 'namespace_creation_sha256': args.namespace_creation_sha256})
    missing_roles = {(o['kind'], o['metadata'].get('namespace'), o['metadata']['name'])
                     for o in proposed if o['kind'] in ('Role', 'ClusterRole')}
    deferred = []
    for obj in proposed:
        meta = obj['metadata']
        scope = ['-n', meta['namespace']] if meta.get('namespace') else []
        if setup.kube(args, 'get', obj['kind'], meta['name'], *scope, '--ignore-not-found', '-o', 'json'):
            raise ValueError('Runtime prerequisite collision; inspect prior receipts')
        key = (obj.get('roleRef', {}).get('kind'), meta.get('namespace'), obj.get('roleRef', {}).get('name'))
        if obj['kind'] in ('RoleBinding','ClusterRoleBinding') and key in missing_roles:
            deferred.append(meta['name'])
        else:
            setup.kube(args, 'create', '--dry-run=server', '-f', '-', '-o', 'json', value=obj)
    created = []
    if args.apply:
        for index, obj in enumerate(proposed):
            namespaces(args, profile)
            meta = obj['metadata']
            scope = ['-n', meta['namespace']] if meta.get('namespace') else []
            if setup.kube(args, 'get', obj['kind'], meta['name'], *scope, '--ignore-not-found', '-o', 'json'):
                raise ValueError('Runtime prerequisite appeared during installation')
            setup.kube(args, 'create', '--dry-run=server', '-f', '-', '-o', 'json', value=obj)
            setup.write(args.output_dir/f'console-{index:02}.pending.json', obj)
            live = setup.kube(args, 'create', '-f', '-', '-o', 'json', value=obj)
            setup.owned(live, profile)
            item = {'kind': obj['kind'], 'name': meta['name'], 'namespace': meta.get('namespace'),
                    'uid': live['metadata']['uid'], 'fingerprint': setup.fingerprint(live)}
            setup.write(args.output_dir/f'console-{index:02}.created.json', item)
            created.append(item)
    return {'applied': args.apply, 'stage': args.console_runtime_stage, 'created': created,
            'bindings_deferred': deferred if not args.apply else [],
            'runtime_workloads_activated': False, 'existing_resources_modified': False}


def updated_web_code(args, profile, name):
    """Verify a later immutable UI creation receipt, without adopting by name.

    Existing installations may have applied a UI update after the bootstrap
    ledger was closed. Only that exact recorded code object is accepted; other
    application objects still require the original creation ledger.
    """
    path = getattr(args, 'console_web_code_receipt', None)
    expected = getattr(args, 'console_web_code_sha256', None)
    if not path or not expected:
        raise ValueError('Exact later web-code creation receipt and hash required')
    path = setup.private_file(path)
    if path.stat().st_size > 2_000_000 or setup.sha(path) != expected:
        raise ValueError('Bounded hash-matched web-code creation receipt required')
    saved = read_json(path)
    meta = saved.get('metadata', {})
    if (saved.get('apiVersion') != 'v1' or saved.get('kind') != 'ConfigMap'
            or meta.get('name') != name or meta.get('namespace') != profile.core_namespace
            or not meta.get('uid') or meta.get('deletionTimestamp')
            or saved.get('immutable') is not True or saved.get('binaryData')
            or not isinstance(saved.get('data'), dict)):
        raise ValueError('Exact immutable web-code creation object required')
    setup.owned(saved, profile)
    live = setup.kube(args, 'get', 'ConfigMap', name, '-n', profile.core_namespace, '-o', 'json')
    setup.owned(live, profile)
    if (live.get('kind') != 'ConfigMap' or live['metadata'].get('namespace') != profile.core_namespace
            or live['metadata'].get('uid') != meta['uid'] or live['metadata'].get('deletionTimestamp')
            or live.get('immutable') is not True or live.get('data') != saved['data']
            or live.get('binaryData') or live['metadata'].get('ownerReferences') != meta.get('ownerReferences')):
        raise ValueError('Recorded web-code identity or immutable content changed')
    return live


def configure(args, profile):
    """Wire only receipt-proven, idle application objects; retain exact rollback."""
    import hashlib
    import json
    import secrets
    from cluster_console_configuration import configure as render
    from cluster_console_resources import private_network
    bundle_path, ledger_path = setup.private_file(args.bundle), setup.private_file(args.ledger)
    if setup.sha(bundle_path) != args.bundle_sha256 or setup.sha(ledger_path) != args.console_ledger_sha256:
        raise ValueError('Exact application bundle and creation ledger hashes required')
    bundle, ledger = read_json(bundle_path), read_json(ledger_path)
    if (ledger.get('bundle_sha256') != args.bundle_sha256
            or bundle.get('installation_profile') != profile.to_dict()
            or ledger.get('installation_profile') != profile.to_dict()):
        raise ValueError('Same fresh application and installation ledger required')
    def read(kind, name):
        records = [r for r in ledger['created'] if r['kind'] == kind and r['metadata']['name'] == name
                   and r.get('namespace') == profile.core_namespace]
        if len(records) != 1:
            raise ValueError('Exact application creation identity required')
        live = setup.kube(args, 'get', kind, name, '-n', profile.core_namespace, '-o', 'json')
        setup.owned(live, profile)
        if live['metadata']['uid'] != records[0]['metadata']['uid'] or live['metadata'].get('deletionTimestamp'):
            raise ValueError('Application object replaced or terminating')
        return live
    from identity_demo_execution_setup import inspect_state
    from connected_install import presenter_subject
    args.namespace = profile.core_namespace
    if not inspect_state(args)['rollback_quiescent']:
        raise ValueError('Idle certain application required')
    driver = read('Deployment', 'fixture-identity-driver')
    adapter = read('Deployment', 'fixture-protected-adapter')
    isolation = read('NetworkPolicy', 'fixture-isolation')
    code_name, = [v['configMap']['name'] for v in driver['spec']['template']['spec']['volumes'] if v['name'] == 'code']
    if any(r['kind'] == 'ConfigMap' and r['metadata']['name'] == code_name
           and r.get('namespace') == profile.core_namespace for r in ledger['created']):
        code = read('ConfigMap', code_name)
    else:
        code = updated_web_code(args, profile, code_name)
    # Load executable modules only from the repository's fixed renderer list.
    # This includes newly added support modules while retaining installed data.
    template = read_json(setup.ROOT/'infra/identity-demo/templates/application.json')
    declared, = [o['data'] for o in template['objects'] if o['kind'] == 'ConfigMap'
                 and 'identity_demo_driver.py' in o.get('data', {})]
    for name, reference in declared.items():
        if name.endswith('.py') and isinstance(reference, dict) and set(reference) == {'$source'}:
            path = setup.ROOT/reference['$source']
            if path.is_symlink() or not path.resolve().is_relative_to(setup.ROOT):
                raise ValueError('Regular repository console module required')
            code['data'][name] = path.read_text()
    keys = {role+'_secret': secrets.token_urlsafe(48) for role in ('coordinator','preparer')}
    new, changed = render(profile, driver, code, adapter, [presenter_subject(bundle['objects'])], keys)
    network, desired_isolation = private_network(profile, isolation)
    new = [*network, *new]
    before = [isolation, adapter, driver]
    desired = [desired_isolation, *changed]
    setup.write(args.output_dir/'configuration-before.private.json', before)
    setup.write(args.output_dir/'configuration-plan.private.json', {'created': new, 'changed': desired})
    # An existing TLS Secret must never be silently adopted by serving-cert setup.
    if setup.kube(args, 'get', 'secret', 'fixture-identity-operator-tls', '-n', profile.core_namespace,
                  '--ignore-not-found', '-o', 'json'):
        raise ValueError('Private serving-certificate collision')
    for obj in new:
        meta = obj['metadata']
        if setup.kube(args, 'get', obj['kind'], meta['name'], '-n', profile.core_namespace, '--ignore-not-found', '-o', 'json'):
            raise ValueError('Console configuration collision; inspect prior receipt')
        setup.kube(args, 'create', '--dry-run=server', '-f', '-', '-o', 'json', value=obj)
    for old, wanted in zip(before, desired, strict=True):
        patch(args, profile, old, wanted, dry=True)
    made, updated = [], []
    if args.apply:
        if not inspect_state(args)['rollback_quiescent']:
            raise ValueError('Console became active before configuration')
        for index, obj in enumerate(new):
            namespaces(args, profile)
            setup.write(args.output_dir/f'configuration-create-{index}.pending.json', obj)
            live = setup.kube(args, 'create', '-f', '-', '-o', 'json', value=obj)
            record = {'kind': live['kind'], 'name': live['metadata']['name'],
                      'uid': live['metadata']['uid'], 'fingerprint': setup.fingerprint(live)}
            setup.write(args.output_dir/f'configuration-create-{index}.receipt.json', record)
            made.append(record)
        for index, (old, wanted) in enumerate(zip(before, desired, strict=True)):
            namespaces(args, profile)
            setup.write(args.output_dir/f'configuration-patch-{index}.pending.json', wanted)
            live = patch(args, profile, old, wanted)
            record = {'kind': live['kind'], 'name': live['metadata']['name'],
                      'uid': live['metadata']['uid'], 'fingerprint': setup.fingerprint(live)}
            setup.write(args.output_dir/f'configuration-patch-{index}.receipt.json', record)
            updated.append(record)
    return {'applied': args.apply, 'stage': 'configure', 'created': made, 'updated': updated,
            'runtime_workloads_activated': False, 'private_listener_wired': args.apply,
            'functional_acceptance_passed': False}


def gateway_observation(args, profile):
    """Reinspect an unchanged installed gateway without editing cluster resources."""
    from types import SimpleNamespace
    from deployment_profile import active_profile
    from identity_demo_execution_setup import inspect_state
    from identity_demo_gateway_persistence import verify
    from identity_demo_gateway_observation import capture
    from native_backend import NativeBackend
    if active_profile().to_dict() != profile.to_dict():
        raise ValueError('Export the same installation profile before gateway inspection')
    args.namespace = profile.core_namespace
    if not inspect_state(args)['rollback_quiescent']:
        raise ValueError('Idle certain installation required for gateway inspection')
    args.gateway_receipt = str(setup.private_file(args.runtime_gateway_receipt))
    ca = setup.kube(args,'get','configmap','fixture-service-ca','-n',profile.core_namespace,'-o','json')
    setup.owned(ca,profile)
    ca = ca['data']['service-ca.crt']
    original = verify(args,ca)
    args.gateway_mode, args.label = 'persistent', 'gateway-observation'
    args.permission_flow = SimpleNamespace(progress=lambda *a:None)
    backend = NativeBackend(args)
    backend.ca = ca
    observation = capture(args,ca,backend.ready)
    if verify(args,ca) != original:
        raise ValueError('Gateway receipt changed during inspection')
    updated = {**original, 'runtime_observation':observation}
    setup.write(args.output_dir/'persistent-gateway.receipt.private.json',updated)
    return {'stage':'gateway-observation','observation_prepared':True,
        'cluster_changed':False,'runtime_inputs_updated':False,
        'gateway_process_uid':observation['inventory']['pod']['uid']}


def patch(args, profile, before, desired, *, dry=False):
    """Test identity, version and prior spec before a bounded configuration patch."""
    operations = [{'op': 'test', 'path': '/metadata/uid', 'value': before['metadata']['uid']},
                  {'op': 'test', 'path': '/metadata/resourceVersion', 'value': before['metadata']['resourceVersion']},
                  {'op': 'test', 'path': '/spec', 'value': before['spec']},
                  {'op': 'replace', 'path': '/spec', 'value': desired['spec']}]
    return setup.kube(args, 'patch', before['kind'], before['metadata']['name'], '-n', profile.core_namespace,
                      '--type=json', '--patch-file=/dev/stdin', *(['--dry-run=server'] if dry else []), '-o', 'json', value=operations)


def workloads(args, profile):
    """Create role-specific inputs and workers after configuration and publication.

    Installer credentials are used only to read public API trust. Only explicitly
    selected service credentials are copied into fixed role-specific Secrets.
    """
    import base64
    import json
    from cluster_console_resources import workloads as render, capacity, resource
    from identity_demo_gateway_persistence import verify
    from identity_demo_execution_setup import inspect_state
    from cryptography import x509
    configured_path = setup.private_file(args.console_configuration_receipt)
    publication_path = setup.private_file(args.runtime_publication_receipt)
    if (setup.sha(configured_path) != args.console_configuration_sha256
            or setup.sha(publication_path) != args.runtime_publication_sha256):
        raise ValueError('Exact configuration/publication receipt hashes required')
    configured, publication = read_json(configured_path), read_json(publication_path)
    if (configured.get('applied') is not True or configured.get('stage') != 'configure'
            or publication.get('published') is not True or publication.get('build_phases') != {'runtime': 'Complete'}):
        raise ValueError('Completed configuration and runtime publication required')
    image = publication['images']['console_runtime']
    prefix = 'image-registry.openshift-image-registry.svc:5000/'+profile.core_namespace+'/'
    if not image.startswith(prefix):
        raise ValueError('Exact owned candidate runtime repository required')
    def read(kind, name):
        return setup.kube(args, 'get', kind, name, '-n', profile.core_namespace, '-o', 'json')
    def created(kind, name):
        records = [r for r in configured['created'] if r['kind'] == kind and r['name'] == name]
        live = read(kind, name)
        setup.owned(live, profile)
        if len(records) != 1 or live['metadata']['uid'] != records[0]['uid']:
            raise ValueError('Exact configured runtime input identity required')
        return live
    args.namespace = profile.core_namespace
    if not inspect_state(args)['rollback_quiescent']:
        raise ValueError('Idle certain candidate required before runtime activation')
    public_ca = read('configmap', 'fixture-service-ca')['data']['service-ca.crt']
    args.gateway_receipt = str(setup.private_file(args.runtime_gateway_receipt))
    verify(args, public_ca)
    from identity_demo_gateway_observation import current as gateway_current
    gateway_current(args, public_ca)
    from identity_demo_controller_identity import verify_gateway, verify_policy, policy
    def identity_read(kind, name, namespace=None):
        return setup.kube(args, 'get', kind, name, *(['-n', namespace] if namespace else []), '-o', 'json')
    verify_gateway(identity_read)
    artifacts_for_policy = validate_artifacts(read_json(setup.private_file(args.artifacts_file)))
    for role in ('triage', 'reader'):
        verify_policy(policy(profile, role, artifacts_for_policy['images']['openshell_supervisor']),
                      identity_read, require_status=False)
    service = created('Service', 'fixture-identity-operator')
    tls = read('secret', 'fixture-identity-operator-tls')
    if not any(v.get('kind') == 'Service' and v.get('uid') == service['metadata']['uid']
               for v in tls['metadata'].get('ownerReferences', [])):
        raise ValueError('Private TLS Secret must belong to the recorded Service')
    certificate = x509.load_pem_x509_certificate(base64.b64decode(tls['data']['tls.crt'], validate=True))
    if profile.service_host('fixture-identity-operator') not in certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName):
        raise ValueError('Private Service TLS identity missing')
    keys = created('Secret', 'fixture-console-role-credentials')['data']
    if set(keys) != {'coordinator_secret', 'preparer_secret'}:
        raise ValueError('Separate role keys required')
    credentials = read_json(setup.private_file(args.credentials_file))
    artifacts_path = setup.private_file(args.artifacts_file)
    artifacts = validate_artifacts(read_json(artifacts_path))
    if credentials['namespace'] != profile.core_namespace or artifacts.get('native_build_contract') != profile.native_build_contract:
        raise ValueError('Same candidate inputs required')
    cluster = setup.kube(args, 'config', 'view', '--minify', '--raw', '-o', 'json')['clusters'][0]['cluster']
    if cluster['server'] != profile.expected_server or cluster.get('insecure-skip-tls-verify'):
        raise ValueError('Exact TLS-verified API endpoint required')
    if cluster.get('certificate-authority-data'):
        api_ca = base64.b64decode(cluster['certificate-authority-data'], validate=True)
    elif cluster.get('certificate-authority'):
        api_ca = Path(cluster['certificate-authority']).read_bytes()
    else:
        # Publicly signed API endpoints use the installer's normal system
        # roots. Export public certificates only, retaining hostname checks.
        import ssl
        api_ca = ''.join(ssl.DER_cert_to_PEM_cert(v) for v in
                         ssl.create_default_context().get_ca_certs(binary_form=True)).encode()
    if b'PRIVATE KEY' in api_ca or not x509.load_pem_x509_certificates(api_ca):
        raise ValueError('Nonempty verified API trust required')
    management_ca = setup.private_file(args.console_management_ca).read_bytes()
    if b'PRIVATE KEY' in management_ca or not x509.load_pem_x509_certificates(management_ca):
        raise ValueError('Management trust must contain public CA certificates only')
    network = read_json(setup.private_file(args.installation_config))['kubernetes_api_cidrs']
    _, budget = capacity(profile)
    objects = []
    for role in ('coordinator','preparer'):
        minimal = {k: credentials[k] for k in ('namespace','keycloak_url','gateway_url','runtime_management')}
        if role == 'coordinator':
            minimal['realm_management'] = credentials['realm_management_clients']
        files = {'installation-profile.json': json.dumps(profile.to_dict()).encode(),
                 'artifacts.json': json.dumps({k: artifacts[k] for k in ('schema_version','images','native_build_contract','native_ca_bundle_sha256')}).encode(),
                 'runtime-credentials.json': json.dumps(minimal).encode(),
                 'driver-credentials.json': json.dumps({'operator_secret': base64.b64decode(keys[role+'_secret'], validate=True).decode()}).encode(),
                 'management-ca.crt': management_ca, 'service-ca.crt': public_ca.encode(), 'kubernetes-ca.crt': api_ca}
        if role == 'preparer':
            files['capacity-budget.json'] = json.dumps(budget).encode()
        else:
            from enmaas_flow import private_inference
            chat = private_inference(args.inference_config)
            inference = read_json(setup.private_file(args.inference_config))
            key = setup.private_file(chat['credential_file'])
            inference['chat']['credential_file'] = '/runtime-inputs/inference.key'
            if not 0 < key.stat().st_size <= 8192:
                raise ValueError('Bounded private inference key required')
            files.update({'catalog-credential.json': setup.private_file(args.console_catalog_credential).read_bytes(),
                'gateway.receipt.json': setup.private_file(args.runtime_gateway_receipt).read_bytes(),
                'sender-trust.receipt.json': setup.private_file(args.console_trust_observation_receipt).read_bytes(),
                'inference.json': json.dumps(inference).encode(), 'inference.key': key.read_bytes()})
        # Exercise the same bootstrap schema before sending credentials to API.
        from identity_demo_cluster_bootstrap import prepare
        temporary = args.output_dir/('validated-inputs-'+role)
        temporary.mkdir(mode=0o700)
        for name, content in files.items():
            path = temporary/name
            path.write_bytes(content)
            path.chmod(0o600)
        prepare(role, temporary, args.output_dir/('bootstrap-check-'+role), profile.core_namespace, 'installer-validation')
        objects.append(resource(profile, 'v1', 'Secret', 'fixture-console-'+role+'-inputs', profile.core_namespace,
            type='Opaque', data={k: base64.b64encode(v).decode() for k,v in files.items()}))
    ingress = setup.kube(args, 'get', 'service', 'router-default', '-n', 'openshift-ingress', '-o', 'json')
    if (ingress['metadata'].get('namespace') != 'openshift-ingress'
            or ingress['metadata']['name'] != 'router-default'
            or not ingress['metadata'].get('uid')
            or ingress.get('spec', {}).get('selector', {}).get('ingresscontroller.operator.openshift.io/deployment-ingresscontroller') != 'default'):
        raise ValueError('Compatible retained default ingress prerequisite required')
    address = ingress['spec']['clusterIP']
    objects += render(profile, image, network, address)
    if getattr(args, 'managed_certificate_config', None):
        from certificate_operations import configure, observe, projections, loading
        configure(args, profile)
        if not observe(args)['ready']:
            raise ValueError('Verified managed certificates required before worker activation')
        loading(args)
        projections([o for o in objects if o['kind'] == 'Deployment'],
            [o for o in objects if o['kind'] == 'Secret'], args.certificate_management, args.certificate_authority_pem)
    setup.write(args.output_dir/'runtime-workloads.plan.private.json', {'objects': objects})
    for obj in objects:
        if setup.kube(args, 'get', obj['kind'], obj['metadata']['name'], '-n', profile.core_namespace, '--ignore-not-found', '-o', 'json'):
            raise ValueError('Worker resource collision; inspect prior receipts')
        setup.kube(args, 'create', '--dry-run=server', '-f', '-', '-o', 'json', value=obj)
    created_records = []
    if args.apply:
        if not inspect_state(args)['rollback_quiescent']:
            raise ValueError('Candidate became active before worker activation')
        # Network policies precede worker Pods. Inputs are inaccessible to other
        # runtime ServiceAccounts; kubelet mounts only the named role Secret.
        objects.sort(key=lambda o: {'NetworkPolicy':0,'Secret':1,'PersistentVolumeClaim':2,'Deployment':3}[o['kind']])
        for index, obj in enumerate(objects):
            namespaces(args, profile)
            setup.write(args.output_dir/f'worker-{index}.pending.json', obj)
            live = setup.kube(args, 'create', '-f', '-', '-o', 'json', value=obj)
            record = {'kind': live['kind'], 'name': live['metadata']['name'], 'uid': live['metadata']['uid'],
                      'fingerprint': setup.fingerprint(live)}
            setup.write(args.output_dir/f'worker-{index}.created.json', record)
            created_records.append(record)
    return {'applied': args.apply, 'created': created_records, 'runtime': 'cluster',
            'runtime_workloads_activated': args.apply, 'functional_acceptance_passed': False,
            'installer_or_human_credentials_included': False}


def trust_observation(args, profile, previous=None):
    """Capture public trust evidence with installer access, not runtime key access."""
    import base64
    import hashlib
    import json
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cluster_console_resources import resource
    from identity_demo_sender_trust import certificates, current
    from identity_demo_execution_setup import inspect_state
    args.namespace = profile.core_namespace
    managed_ca = None
    if getattr(args, 'managed_certificate_config', None):
        from certificate_operations import configure
        from cluster_console_operator import receipt
        from managed_certificates import SPIRE_TRUST
        configure(args, profile)
        ledger = receipt(args.ledger, args.console_ledger_sha256)
        records = [v for v in ledger.get('created', []) if v['kind'] == 'Secret'
            and v.get('namespace') == profile.core_namespace and v['metadata']['name'] == SPIRE_TRUST]
        managed_ca = setup.kube(args, 'get', 'secret', SPIRE_TRUST, '-n', profile.core_namespace, '-o', 'json')
        setup.owned(managed_ca, profile)
        if (ledger.get('installation_profile') != profile.to_dict() or len(records) != 1
                or records[0]['metadata']['uid'] != managed_ca['metadata']['uid']
                or managed_ca.get('type') != 'Opaque' or set(managed_ca.get('data', {})) != {'ca.crt'}):
            raise ValueError('Exact installer-created separate SPIRE trust required')
        args.public_trust_ca_uid = managed_ca['metadata']['uid']
    if not inspect_state(args)['rollback_quiescent'] or not current(args):
        raise ValueError('Idle candidate and currently aligned issuer/listener trust required')
    def read(kind, name, namespace=profile.core_namespace):
        return setup.kube(args, 'get', kind, name, '-n', namespace, '-o', 'json')
    trust = read('secret','fixture-keycloak-upstream-client-trust')
    listener = read('secret','fixture-mcp-bound-mutual')
    issuer = read('deployment','fixture-keycloak-upstream')
    for obj in (trust, listener, issuer): setup.owned(obj,profile)
    # Bind all three reads to the original application creation identities.
    ledger_path = setup.private_file(args.ledger)
    if setup.sha(ledger_path) != args.console_ledger_sha256:
        raise ValueError('Exact application creation ledger hash required')
    ledger = read_json(ledger_path)
    if ledger.get('installation_profile') != profile.to_dict():
        raise ValueError('Same application creation ledger required')
    for obj in (trust,listener,issuer):
        records = [v for v in ledger['created'] if v['kind']==obj['kind']
                   and v['metadata']['name']==obj['metadata']['name'] and v.get('namespace')==profile.core_namespace]
        if len(records)!=1 or records[0]['metadata']['uid']!=obj['metadata']['uid']:
            raise ValueError('Exact original trust/issuer identity required')
    public = read('configmap','spire-bundle', profile.identity_namespace)
    store = pkcs12.load_pkcs12(base64.b64decode(trust['data']['truststore.p12'], validate=True),
                              base64.b64decode(trust['data']['password'], validate=True))
    if store.key is not None or store.cert is not None:
        raise ValueError('Issuer client truststore must contain public CA certificates only')
    fingerprint = lambda cert: cert.fingerprint(hashes.SHA256()).hex()
    observed = {'schema_version':1,'profile':profile.to_dict(),
        'spire_fingerprints':sorted(fingerprint(v) for v in certificates(public['data']['bundle.crt'])),
        'issuer_fingerprints':sorted(fingerprint(v.certificate) for v in store.additional_certs),
        'listener_fingerprints':sorted(fingerprint(v) for v in certificates(base64.b64decode(
            (managed_ca or listener)['data']['ca.crt'],validate=True).decode())),
        'issuer_uid':issuer['metadata']['uid'],
        'issuer_annotation':issuer['spec']['template'].get('metadata',{}).get('annotations',{}).get('demo-identity-trust-sha256'),
        'issuer_trust_volumes':[v for v in issuer['spec']['template']['spec']['volumes']
                                if v.get('secret',{}).get('secretName')=='fixture-keycloak-upstream-client-trust'],
        'issuer_trust_uid':trust['metadata']['uid'],'listener_uid':listener['metadata']['uid'],
        'live_secret_contents_inspected_at_install_only':True}
    if managed_ca is not None:
        observed['listener_ca_uid'] = managed_ca['metadata']['uid']
    if len(observed['issuer_trust_volumes']) != 1 or not observed['spire_fingerprints'] or not (observed['spire_fingerprints']==observed['issuer_fingerprints']==observed['listener_fingerprints']):
        raise ValueError('Current public trust copies differ')
    prior_automatic = bool(previous and json.loads(previous['data']['observation.json']).get('automatic_public_refresh'))
    if getattr(args,'enable_public_trust_refresh',False) or prior_automatic:
        from identity_demo_public_trust import CA_SECRET
        client_ca=read('secret',CA_SECRET)
        setup.owned(client_ca,profile)
        expected_uid = getattr(args,'public_trust_ca_uid',None)
        if prior_automatic:
            expected_uid=json.loads(previous['data']['observation.json'])['listener_ca_uid']
        if not expected_uid or client_ca['metadata']['uid']!=expected_uid or set(client_ca.get('data',{}))!={'ca.crt'}:
            raise ValueError('Exact newly recorded public listener CA required')
        env=issuer['spec']['template']['spec']['containers'][0]['env']
        if [v for v in env if v['name']=='KC_HTTPS_CERTIFICATES_RELOAD_PERIOD'] != [{'name':'KC_HTTPS_CERTIFICATES_RELOAD_PERIOD','value':'60s'}]:
            raise ValueError('Issuer automatic HTTPS reload must be configured')
        observed.update(automatic_public_refresh=True,listener_ca_uid=expected_uid,
            bundle_uid=public['metadata']['uid'],bundle_owners=public['metadata']['ownerReferences'])
    payload = json.dumps(observed,sort_keys=True)
    obj = resource(profile,'v1','ConfigMap','fixture-console-sender-trust',profile.core_namespace,
                   immutable=True,data={'observation.json':payload})
    live = setup.kube(args,'get','configmap',obj['metadata']['name'],'-n',profile.core_namespace,'--ignore-not-found','-o','json')
    if previous is None and live:
        raise ValueError('Public trust observation collision; review prior receipt')
    if previous is not None:
        setup.owned(live,profile)
        if (live['metadata']['uid'] != previous['metadata']['uid'] or setup.fingerprint(live) != setup.fingerprint(previous)
                or live.get('immutable') is not True):
            raise ValueError('Recorded immutable trust observation changed')
        # Existing immutable data cannot be updated. Review admission under a
        # distinct temporary name; no review object is actually created.
        from copy import deepcopy
        review = deepcopy(obj)
        review['metadata']['name'] += '-review'
    else:
        review = obj
    setup.kube(args,'create','--dry-run=server','-f','-','-o','json',value=review)
    setup.write(args.output_dir/'sender-trust-observation.plan.json',obj)
    if args.apply:
        namespaces(args,profile)
        if previous is not None:
            setup.write(args.output_dir/'sender-trust-observation.before.json',live)
            setup.write(args.output_dir/'sender-trust-observation-delete.pending.json',
                        {'uid':live['metadata']['uid'],'name':live['metadata']['name']})
            setup.kube(args,'delete','--raw','/api/v1/namespaces/'+profile.core_namespace+'/configmaps/'+obj['metadata']['name'],
                '-f','-',value={'apiVersion':'v1','kind':'DeleteOptions','preconditions':{
                    'uid':live['metadata']['uid'],'resourceVersion':live['metadata']['resourceVersion']}})
            if setup.kube(args,'get','configmap',obj['metadata']['name'],'-n',profile.core_namespace,'--ignore-not-found','-o','json'):
                raise ValueError('Old public observation still exists; inspect before creating')
        setup.write(args.output_dir/'sender-trust-observation.pending.json',obj)
        made = setup.kube(args,'create','-f','-','-o','json',value=obj)
        reference = {'uid':made['metadata']['uid'],'observation_sha256':hashlib.sha256(payload.encode()).hexdigest()}
        if observed.get('automatic_public_refresh') is True:
            reference['automatic_public_refresh'] = True
        setup.write(args.output_dir/'sender-trust.receipt.json',reference)
    return {'applied':args.apply,'stage':'trust-observation','runtime_serving_key_access_required':False,
            'live_native_protected_path_still_required':True}
