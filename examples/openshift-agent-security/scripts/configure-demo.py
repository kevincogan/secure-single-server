#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Configure one reviewed public provider contract without reading keys.

Plans by default. Changed or previously configured inputs are refused.
Application/test source and Containerfiles are never rewritten. Reconfiguration
uses a fresh export; credentials remain in the private inference configuration.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts/identity_demo'))
sys.path.insert(0, str(ROOT / 'runtime'))
from deployment_profile import in_source_checkout
from provider_contract import unique, validate as validate_provider
FIELDS = {'schema_version', 'chat_request_url', 'chat_model', 'workload_image', 'diagnostic_runtime_image', 'credential_file'}


def load_json(path: Path) -> dict:
    """Reject duplicate configuration keys rather than resolving ambiguity."""
    return json.loads(path.read_text(), object_pairs_hook=unique)


def private(path: Path, *, directory: bool = False) -> Path:
    """Require existing owner-only regular external inputs; never read key bytes."""
    if (not path.is_absolute() or path.is_symlink() or in_source_checkout(path, ROOT)
            or path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077
            or (not path.is_dir() if directory else not path.is_file())):
        raise ValueError('Existing private path outside source required')
    return path


def validate(config: dict) -> dict[str, str]:
    """Share transport/image validation with runtime; keep secrets external."""
    if not isinstance(config, dict) or set(config) != FIELDS or type(config['schema_version']) is not int or config['schema_version'] != 1:
        raise ValueError('Exact schema version 1 fields required')
    public = validate_provider({k: v for k, v in config.items() if k != 'credential_file'} | {'configured': True})
    if not isinstance(config['credential_file'],str):
        raise ValueError('Private credential path required')
    private(Path(config['credential_file']))
    return public


def plan(config: dict) -> list[tuple[Path, bytes, bytes]]:
    """Verify the full immutable target list before any source file changes."""
    public=validate(config)
    targets=load_json(ROOT/'export-manifest.json')
    if targets.get('schema_version') != 1 or not isinstance(targets.get('files'), list):
        raise ValueError('Reviewed source inventory required')
    contract = 'runtime/provider-contract.json'
    observed = set()
    contract_before = None
    for item in targets['files']:
        name = item['path']
        p=ROOT/name
        if (name in observed or Path(name).is_absolute() or '..' in Path(name).parts
                or p.is_symlink() or not p.resolve().is_relative_to(ROOT) or not p.is_file()):
            raise ValueError('Regular source target required')
        observed.add(name)
        before=p.read_bytes()
        if hashlib.sha256(before).hexdigest()!=item['sha256']:
            raise ValueError('Source template changed or already configured; start with a fresh export')
        if name == contract:
            contract_before = before
    if (contract_before is None or 'runtime/provider_contract.py' not in observed
            or load_json(ROOT/contract).get('configured') is not False):
        raise ValueError('Pristine fixed provider contract required')
    return [(ROOT/contract, contract_before,
             (json.dumps(public, indent=2) + '\n').encode())]


def run(args: argparse.Namespace) -> dict:
    """Write protected receipts and configured sources; never contact a service."""
    private(args.config)
    if args.config.stat().st_size>16384:raise ValueError('Bounded configuration required')
    config=load_json(args.config)
    changes=plan(config)
    output=args.output_dir
    private(output.parent,directory=True)
    if output.exists() or output.is_symlink() or in_source_checkout(output, ROOT):
        raise ValueError('New external output directory required')
    result={'planned':True,'source_files':len(changes),'applied':False,'cluster_changed':False,'credential_bytes_read':False}
    if not args.apply:return result
    output.mkdir(mode=0o700)
    changed = {str(p.relative_to(ROOT)): hashlib.sha256(a).hexdigest() for p,b,a in changes}
    receipt={'schema_version':1,'files':[{'path':item['path'],'before_sha256':item['sha256'],
             'after_sha256':changed.get(item['path'],item['sha256'])}
             for item in load_json(ROOT/'export-manifest.json')['files']],
             'contract_sha256':hashlib.sha256(json.dumps(config,sort_keys=True).encode()).hexdigest()}
    def save(name: str, value: dict) -> None:
        with (output/name).open('x') as stream:json.dump(value,stream,indent=2)
        (output/name).chmod(0o600)
    save('configuration.pending.json',receipt)
    for p,before,after in changes:
        backup=output/'source-before'/p.relative_to(ROOT);backup.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
        backup.write_bytes(before);backup.chmod(0o600)
    for p,before,after in changes:
        if p.read_bytes()!=before:raise ValueError('Source changed during configuration; inspect backup and pending receipt')
        p.write_bytes(after)
    url=config['chat_request_url']
    save('inference-config.private.json',{'chat':{'base_url':url.removesuffix('/messages'),'request_url':url,
        'model':config['chat_model'],'http_method':'POST','credential_file':config['credential_file'],
        'authentication':{'header_name':'x-api-key','value_source':'credential_file','credential_file_format':'raw text'},
        'ca_file':None,'tls_verify':True,'follow_redirects':False}})
    save('configuration.receipt.json',{**receipt,'completed':True,'credential_bytes_read':False,'cluster_changed':False})
    return {**result,'applied':True,'inference_config':str(output/'inference-config.private.json')}


def main() -> None:
    """Keep sensitive exception text out of normal command output."""
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--output-dir',type=Path,required=True)
    parser.add_argument('--apply',action='store_true')
    args=parser.parse_args()
    os.umask(0o077)
    try:print(json.dumps(run(args)))
    except Exception as error:
        print(json.dumps({'configured':False,'failure_kind':type(error).__name__,'details_withheld':True}))
        sys.exit(1)


if __name__=='__main__':main()
