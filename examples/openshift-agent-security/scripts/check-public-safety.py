#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Review the whole export, including docs/tests and untracked files, before sharing.

Output contains filenames and categories only. This bounded scan is not a full
security/licensing approval or a guarantee that all secrets can be detected.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import sys

SKIP={'.git','__pycache__','.pytest_cache','.ruff_cache','.venv','venv','.DS_Store','Thumbs.db','node_modules'}
RULES={
 'customer branding':re.compile(r'bank[ ._-]*of[ ._-]*america|\bbofa\b|\.boa\.com',re.I),
 'private provider or cluster':re.compile(r'(?:[a-z0-9.-]+\.)?(?:devshift\.net|openshiftapps\.com)\b',re.I),
 'personal machine path':re.compile(r'/(?:Users|home)/[A-Za-z0-9_.-]+/'),
 'bearer credential':re.compile(r'sha256~[A-Za-z0-9_-]{30,}|\bsk-(?:proj-)?[A-Za-z0-9_-]{25,}'),
 'private key bytes':re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\s+[A-Za-z0-9+/]{20}',re.M),
 'encoded access token':re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}\b'),
 'provider credential':re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|(?:AKIA|ASIA)[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{20,})\b'),
 'credential in URL':re.compile(r'https?://[^\s/:@]+:[^\s/@]{16,}@',re.I),
}


def scan(root: Path) -> dict:
    findings=[];count=0
    for p in sorted(root.rglob('*')):
        rel=p.relative_to(root)
        if any(v in SKIP for v in rel.parts):continue
        if p.is_symlink():findings.append({'path':str(rel),'category':'source symlink'});continue
        if not p.is_file():continue
        count+=1
        if ('.private.' in p.name or p.name in {'kubeconfig','credentials.json','secrets.yaml','.env'}
                or p.name.startswith('.env.') and p.name != '.env.example'
                or rel.as_posix() in {'.kube/config','.docker/config.json'}
                or p.suffix in {'.key','.pem','.crt','.p12','.kubeconfig','.db','.sqlite','.sqlite3'}):
            findings.append({'path':str(rel),'category':'private/generated file'})
        try:text=p.read_text()
        except UnicodeDecodeError:
            findings.append({'path':str(rel),'category':'unexpected binary'});continue
        for category,pattern in RULES.items():
            if pattern.search(text):findings.append({'path':str(rel),'category':category})
    return {'passed':not findings,'files_scanned':count,'findings':findings,'approval_granted':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1])
    args=parser.parse_args();result=scan(args.root.resolve());print(json.dumps(result,indent=2))
    sys.exit(0 if result['passed'] else 1)
