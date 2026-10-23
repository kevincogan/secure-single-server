#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Parameterize the exported fixed provider/image templates without reading keys.

Plans by default. Apply only to pristine generic source templates; a changed or
previously configured file is refused. Reconfiguration uses a fresh source export.
No runtime endpoint selection, secret handling or cluster action is introduced.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts/identity_demo'))
from deployment_profile import in_source_checkout
IMAGE = re.compile(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?/[a-z0-9]+(?:[._/-][a-z0-9]+)*@sha256:([a-f0-9]{64})')
FIELDS = {'schema_version', 'chat_request_url', 'chat_model', 'workload_image', 'diagnostic_runtime_image', 'credential_file'}


def load_json(path: Path) -> dict:
    """Reject duplicate configuration keys rather than resolving ambiguity."""
    def unique(pairs: list) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate JSON field')
            result[key] = value
        return result
    return json.loads(path.read_text(), object_pairs_hook=unique)


def private(path: Path, *, directory: bool = False) -> Path:
    """Require existing owner-only regular external inputs; never read key bytes."""
    if (not path.is_absolute() or path.is_symlink() or in_source_checkout(path, ROOT)
            or path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077
            or (not path.is_dir() if directory else not path.is_file())):
        raise ValueError('Existing private path outside source required')
    return path


def validate(config: dict) -> dict[str, str]:
    """Preserve fixed HTTPS Messages and canonical pinned-image restrictions."""
    if not isinstance(config, dict) or set(config) != FIELDS or type(config['schema_version']) is not int or config['schema_version'] != 1:
        raise ValueError('Exact schema version 1 fields required')
    url = config['chat_request_url']
    if not isinstance(url, str) or not url.isascii() or any(c.isspace() for c in url) or '\\' in url:
        raise ValueError('Canonical endpoint required')
    u = urlsplit(url)
    if (u.scheme != 'https' or not u.hostname or u.username is not None or u.password is not None
            or u.port is not None or u.path != '/v1/messages' or u.query or u.fragment
            or url != 'https://' + u.hostname + '/v1/messages'
            or len(u.hostname)>253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',part) for part in u.hostname.split('.'))
            or u.hostname in {'inference.example.test', 'localhost'} or u.hostname.endswith('.invalid')
            or re.fullmatch(r'[0-9.]+',u.hostname)):
        raise ValueError('Reviewed DNS HTTPS endpoint on port 443 at /v1/messages required')
    model=config['chat_model']
    if not isinstance(model,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_./:-]{0,127}',model) or model=='approved-chat-model':
        raise ValueError('Explicit canonical model ID required')
    for field in ('workload_image','diagnostic_runtime_image'):
        v=config[field];m=IMAGE.fullmatch(v) if isinstance(v,str) and len(v)<=512 else None
        if not m or m[1]=='0'*64 or v.startswith('registry.example.test/'):
            raise ValueError('Actual approved digest image required')
    if not isinstance(config['credential_file'],str):
        raise ValueError('Private credential path required')
    private(Path(config['credential_file']))
    return {'endpoint_host':u.hostname,'model':model,'workload_image':config['workload_image'],
            'diagnostic_image':config['diagnostic_runtime_image']}


def plan(config: dict) -> list[tuple[Path, bytes, bytes]]:
    """Verify the full immutable target list before any source file changes."""
    values=validate(config)
    targets=load_json(ROOT/'config/configuration-targets.json')
    substitutions={v:values[k] for k,v in targets['tokens'].items()}
    changes=[]
    for item in targets['files']:
        p=ROOT/item['path']
        if p.is_symlink() or not p.resolve().is_relative_to(ROOT) or not p.is_file():
            raise ValueError('Regular source target required')
        before=p.read_bytes()
        if hashlib.sha256(before).hexdigest()!=item['sha256']:
            raise ValueError('Source template changed or already configured; start with a fresh export')
        after=before.decode()
        for token,replacement in substitutions.items():
            after=after.replace(token,replacement)
        if after.encode()!=before:changes.append((p,before,after.encode()))
    if not changes:raise ValueError('No template targets found')
    return changes


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
    receipt={'schema_version':1,'files':[{'path':str(p.relative_to(ROOT)),'before_sha256':hashlib.sha256(b).hexdigest(),
             'after_sha256':hashlib.sha256(a).hexdigest()} for p,b,a in changes],
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
