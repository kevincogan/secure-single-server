#!/usr/bin/env python3
"""Delete a sandbox and certify absence with successful, complete listings."""
import json
import math
import os
import re
import subprocess
import sys
import time


# OpenShell may retain a removed resource's metadata for its five-minute
# orphan grace plus a one-minute reconciliation sweep when watch events lag.
DEFAULT_TIMEOUT = 420


def destroy(binary, name, timeout=DEFAULT_TIMEOUT):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]*', name):
        raise ValueError('invalid sandbox name')
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError('cleanup timeout must be positive and finite')
    deadline = time.monotonic() + timeout

    def call(*args):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('sandbox cleanup deadline exceeded')
        result = subprocess.run([binary, 'sandbox', *args], capture_output=True,
                                text=True, timeout=remaining, check=False)
        if result.returncode:
            raise RuntimeError(f'sandbox {args[0]} failed (exit {result.returncode})')
        return result.stdout

    def exists():
        token = ''
        seen = set()
        while True:
            data = json.loads(call('list', '--output', 'json', '--page-token', token))
            if not isinstance(data, dict):
                raise ValueError('invalid sandbox listing')
            items = data.get('sandboxes')
            if not isinstance(items, list) or any(not isinstance(s, dict) or
                                                  not isinstance(s.get('name'), str) for s in items):
                raise ValueError('invalid sandbox listing')
            token = data.get('next_page_token')
            if not isinstance(token, str):
                raise ValueError('invalid sandbox continuation token')
            if any(s['name'] == name for s in items):
                return True
            if not token:
                return False
            if token in seen:
                raise ValueError('repeated sandbox continuation token')
            seen.add(token)

    if not exists():
        return
    call('delete', name)
    while exists():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('sandbox still exists after cleanup deadline')
        time.sleep(min(1, remaining))


if __name__ == '__main__':
    try:
        destroy(sys.argv[1], sys.argv[2], float(os.environ.get('OPENSHELL_CLEANUP_TIMEOUT', str(DEFAULT_TIMEOUT))))
    except (ValueError, KeyError, TypeError, OSError, RuntimeError, TimeoutError,
            subprocess.TimeoutExpired) as error:
        print(f'sandbox cleanup failed: {error}', file=sys.stderr)
        raise SystemExit(1)
