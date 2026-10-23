#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify local source syntax, templates, native pins and documentation links."""
from __future__ import annotations
import ast
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote
import yaml

ROOT=Path(__file__).resolve().parents[1]
SKIP={'.git','__pycache__','.pytest_cache','.ruff_cache','.venv','venv','.DS_Store','Thumbs.db'}


def inventory_errors(root: Path) -> list[str]:
    """Detect missing, modified or unlisted delivery files; never follow a manifest escape."""
    try:
        manifest=json.loads((root/'export-manifest.json').read_text())
        if (not isinstance(manifest,dict) or type(manifest.get('schema_version')) is not int
                or manifest['schema_version'] != 1 or not isinstance(manifest.get('files'),list)):
            raise ValueError('Invalid inventory schema')
        expected={}
        for item in manifest['files']:
            if not isinstance(item,dict):raise ValueError('Invalid inventory entry')
            name,digest=item['path'],item['sha256']
            if not isinstance(name,str):raise ValueError('Invalid inventory path')
            path=Path(name)
            if (path.is_absolute() or path.as_posix()!=name
                    or '..' in path.parts or any(v in SKIP for v in path.parts)
                    or name=='export-manifest.json' or name in expected
                    or not isinstance(digest,str) or not re.fullmatch(r'[a-f0-9]{64}',digest)):
                raise ValueError('Invalid inventory entry')
            expected[name]=digest
        actual={}
        for path in root.rglob('*'):
            name=path.relative_to(root).as_posix()
            if name=='export-manifest.json' or any(v in SKIP for v in path.relative_to(root).parts):continue
            if path.is_symlink():raise ValueError('Inventory contains a source symlink')
            if path.is_file():actual[name]=hashlib.sha256(path.read_bytes()).hexdigest()
        return ([name+': inventory file missing' for name in sorted(expected.keys()-actual.keys())]
                +[name+': file absent from inventory' for name in sorted(actual.keys()-expected.keys())]
                +[name+': inventory hash mismatch' for name in sorted(expected.keys()&actual.keys())
                  if expected[name]!=actual[name]])
    except (OSError,ValueError,KeyError,TypeError):
        return ['export-manifest.json: invalid source inventory']

def slug(value: str) -> str:
    value=re.sub(r'<[^>]+>','',value).strip().lower()
    value=re.sub(r'[^\w\- ]','',value)
    return value.replace(' ','-')


def verify(*, include_inventory: bool = False) -> dict:
    errors=[];counts={'python':0,'json':0,'yaml':0,'shell':0,'markdown':0}
    paths=[p for p in ROOT.rglob('*') if not any(s in SKIP for s in p.relative_to(ROOT).parts)]
    for p in paths:
        rel=str(p.relative_to(ROOT))
        if p.is_symlink():errors.append(rel+': source symlink');continue
        if not p.is_file():continue
        try:
            text=p.read_text()
            if p.suffix=='.py':ast.parse(text,filename=rel);counts['python']+=1
            if p.suffix=='.json':json.loads(text);counts['json']+=1
            if p.suffix in {'.yaml','.yml'}:list(yaml.safe_load_all(text));counts['yaml']+=1
            if p.suffix=='.sh':
                r=subprocess.run(['bash','-n',str(p)],capture_output=True)
                if r.returncode:errors.append(rel+': shell syntax')
                counts['shell']+=1
            if p.suffix=='.md':
                counts['markdown']+=1
                for link in re.findall(r'!?\[[^\]]*\]\(([^)]+)\)',text):
                    link=link.split(' "')[0].strip('<>')
                    if re.match(r'[a-zA-Z][\w+.-]*:',link):continue
                    name,_,anchor=unquote(link).partition('#')
                    q=(p.parent/name).resolve() if name else p
                    if not q.is_relative_to(ROOT) or not q.exists():errors.append(rel+': missing link '+link);continue
                    if anchor and q.suffix=='.md':
                        used={};headings=set()
                        for line in q.read_text().splitlines():
                            if re.match(r'^#{1,6} ',line):
                                h=slug(re.sub(r'^#{1,6} ','',line));n=used.get(h,0);used[h]=n+1
                                headings.add(h+('-'+str(n) if n else ''))
                        if anchor not in headings:errors.append(rel+': missing heading '+link)
                for block in re.findall(r'```(?:bash|sh)\n(.*?)```',text,re.S):
                    r=subprocess.run(['bash','-n'],input=block.encode(),capture_output=True)
                    if r.returncode:errors.append(rel+': shell example syntax')
            if p.parts[-3:-1]==('identity-demo','templates') and p.suffix=='.json':
                def walk(value):
                    if isinstance(value,dict):
                        if set(value)=={'$source'}:
                            q=ROOT/value['$source']
                            if not q.is_file() or not q.resolve().is_relative_to(ROOT):errors.append(rel+': missing source')
                        for v in value.values():walk(v)
                    if isinstance(value,list):
                        for v in value:walk(v)
                walk(json.loads(text))
        except (SyntaxError,ValueError,UnicodeError,yaml.YAMLError):errors.append(rel+': invalid source syntax')
    lock=json.loads((ROOT/'infra/openshell/native-build/inputs.lock.json').read_text())
    for entry in lock['patches']:
        p=ROOT/'infra/openshell/patches'/entry['file']
        if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=entry['sha256']:errors.append('Native patch hash mismatch')
    # All modules used by launchd snapshot selection and source templates must exist.
    for d in ('scripts/identity_demo','tests/identity_demo','infra/identity-demo','infra/openshell/patches','workloads/agents/service-request-demo/src'):
        if not (ROOT/d).is_dir():errors.append('Missing runtime directory: '+d)
    if include_inventory:errors.extend(inventory_errors(ROOT))
    return {'verified':not errors,'counts':counts,'inventory_checked':include_inventory,'errors':errors}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory',action='store_true',help='Verify the generic delivery hash inventory; omit for configured private copies')
    args=parser.parse_args()
    result=verify(include_inventory=args.inventory);print(json.dumps(result,indent=2));sys.exit(0 if result['verified'] else 1)
