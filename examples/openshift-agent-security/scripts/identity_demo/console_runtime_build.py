# SPDX-License-Identifier: Apache-2.0
"""Build the existing Python services with exact public Linux tools; no credentials."""
from pathlib import Path
import hashlib
import json
import shutil
import tarfile

from native_build import command, capture, digest
from source_render import read_json

ROOT = Path(__file__).resolve().parents[2]


def verify_versions(oc_output: str, cli_output: str, oc_version: str, cli_version: str) -> dict:
    """Verify the actual packaged tools, not just successful version commands."""
    if len(oc_output) > 65536 or len(cli_output) > 1024:
        raise ValueError('Bounded tool version metadata required')
    metadata = json.loads(oc_output)
    if (not isinstance(metadata, dict) or metadata.get('releaseClientVersion') != oc_version
            or not isinstance(metadata.get('clientVersion'), dict)
            or metadata['clientVersion'].get('platform') != 'linux/amd64'
            or cli_output.strip() != 'openshell ' + cli_version):
        raise ValueError('Packaged Linux tool versions must match the pinned inputs')
    return {'oc': oc_version, 'openshell': cli_version, 'platform': 'linux/amd64'}


def unpack(archive, expected, member_name, target):
    path = Path(archive)
    if path.is_symlink() or not path.is_file() or digest(path) != expected:
        raise ValueError('Exact public CLI archive required')
    with tarfile.open(path) as packed:
        matches = [m for m in packed.getmembers() if m.name in (member_name, './'+member_name)]
        if len(matches) != 1 or not matches[0].isfile() or not 0 < matches[0].size <= 250_000_000:
            raise ValueError('One bounded regular CLI archive member required')
        with packed.extractfile(matches[0]) as source:
            target.write_bytes(source.read(250_000_001))
    header = target.read_bytes()[:20]
    if not (header[:6] == b'\x7fELF\x02\x01' and header[18:20] == b'\x3e\x00'):
        raise ValueError('Linux AMD64 ELF executable required')
    target.chmod(0o555)


def prepare_context(args):
    from identity_demo_setup import write, private_file
    if args.apply:
        configured = read_json(private_file(args.runtime_configuration_receipt))
        if configured.get('completed') is not True or not configured.get('files'):
            raise ValueError('Completed fixed-provider configuration receipt required')
        for item in configured['files']:
            source = ROOT/item['path']
            if (not source.resolve().is_relative_to(ROOT) or source.is_symlink()
                    or digest(source) != item['after_sha256']):
                raise ValueError('Configured runtime sources changed')
    lock = read_json(ROOT / 'infra/identity-demo/console-runtime.lock.json')
    cli_lock = read_json(ROOT / lock['cli_lock'])
    cli = cli_lock['assets']['linux-amd64']
    context = args.output_dir / 'context'
    context.mkdir(mode=0o700)
    (context/'tools').mkdir(mode=0o700)
    if getattr(args, 'packaged_installer_tools', False):
        receipt = read_json(Path('/usr/share/installer-tools.json'))
        if receipt.get('versions') != {'oc': lock['oc_version'], 'openshell': cli_lock['version'], 'platform': 'linux/amd64'}:
            raise ValueError('Pinned installer tool versions required')
        for name, expected in (('oc', lock['oc_archive_sha256']), ('openshell', cli['sha256'])):
            source = Path('/usr/local/bin') / name
            if receipt.get(name, {}).get('archive_sha256') != expected or digest(source) != receipt[name].get('binary_sha256'):
                raise ValueError('Packaged installer tool bytes changed')
            shutil.copyfile(source, context/'tools'/name)
            (context/'tools'/name).chmod(0o555)
    else:
        unpack(args.oc_archive, lock['oc_archive_sha256'], 'oc', context/'tools/oc')
        unpack(args.cli_archive, cli['sha256'], cli['archive_member'], context/'tools/openshell')
    for folder in ('scripts', 'tests', 'workloads', 'infra'):
        if any(p.is_symlink() for p in (ROOT/folder).rglob('*')):
            raise ValueError('Runtime source must contain regular repository files')
        shutil.copytree(ROOT/folder, context/folder,
            ignore=shutil.ignore_patterns('__pycache__', '.pytest_cache', '*.pyc'))
    shutil.copyfile(ROOT/'tests/identity_demo/requirements-lock.txt', context/'requirements-lock.txt')
    shutil.copyfile(ROOT/'infra/identity-demo/console-runtime.Containerfile', context/'Containerfile')
    hashes = {str(p.relative_to(context)): digest(p) for p in context.rglob('*') if p.is_file()}
    identity = hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()
    plan = {'schema_version': 1, 'inputs': lock, 'context_sha256': hashes,
            'source_digest': identity, 'credentials_included': False,
            'image_tag': 'localhost/identity-console-runtime:' + identity[:16]}
    write(args.output_dir/'console-runtime-build.plan.json', plan)
    return lock, cli_lock, plan, context


def run(args):
    from identity_demo_setup import write
    lock, cli_lock, plan, context = prepare_context(args)
    if not args.apply:
        return {'runtime_build_prepared': True, 'cluster_changed': False}
    command([args.engine, 'build', '--platform=linux/amd64', '-f', str(context/'Containerfile'), '--build-arg',
        'PYTHON_BASE='+lock['python_base'], '--build-arg', 'PYTHON_RPMS='+' '.join(lock['python_rpms']),
        '--build-arg', 'RPM_MANIFEST_SHA256='+lock['rpm_manifest_sha256'], '-t', plan['image_tag'], str(context)],
        args.output_dir/'runtime-image-build.private.log')
    image_id = capture([args.engine, 'image', 'inspect', plan['image_tag'], '--format', '{{.Id}}'])
    result = capture([args.engine, 'run', '--rm', '--platform=linux/amd64', '--network=none',
        '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
        '--entrypoint=python3.12', image_id, '-c',
        'import json,sqlite3,cryptography,yaml;import identity_demo_driver,identity_demo_console_worker,identity_demo_console_preparer;print(json.dumps({"runtime_imports":True,"sqlite":sqlite3.sqlite_version}))'])
    inspected = json.loads(result)
    for tool, option in [('oc', 'version'), ('openshell', '--version')]:
        words = ['version', '--client=true', '-o', 'json'] if tool == 'oc' else [option]
        command([args.engine, 'run', '--rm', '--platform=linux/amd64', '--network=none',
            '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
            '--entrypoint='+tool, image_id, *words], args.output_dir/(tool+'-version.log'))
    versions = verify_versions((args.output_dir/'oc-version.log').read_text(),
        (args.output_dir/'openshell-version.log').read_text(), lock['oc_version'], cli_lock['version'])
    command([args.engine, 'run', '--rm', '--platform=linux/amd64', '--network=none',
        '--read-only', '--entrypoint=python3.12', image_id, '-m', 'pip', 'inspect'],
        args.output_dir/'python-dependency-inventory.json')
    receipt = {**plan, 'image_id': image_id, 'runtime_imports': inspected, 'tool_versions': versions,
               'built': True, 'published': False, 'live_acceptance_passed': False,
               'security_and_distribution_approved': False}
    write(args.output_dir/'console-runtime-build.receipt.json', receipt)
    return {'runtime_built': True, 'image_id': image_id,
            'cluster_changed': False, 'live_acceptance_passed': False}
