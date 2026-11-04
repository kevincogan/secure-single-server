# SPDX-License-Identifier: Apache-2.0
"""Local trusted backend: private append-only metadata records, no agent routing."""
import json
import os
from pathlib import Path
import threading

from agent_security_runtime import Denied

from contract import CONTRACT, check_reference, normalize, valid_scope


class ArtifactCatalog:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.directory.is_symlink() or self.directory.stat().st_uid != os.getuid():
            raise ValueError('Backend requires an owned private directory')
        os.chmod(self.directory, 0o700)
        self._lock = threading.Lock()
        self.dispatch_calls = 0

    def dispatch(self, value):
        effects = normalize(value)
        operation = effects.get('operation_id')
        if operation is None:
            raise Denied('backend_missing_operation')
        reference = 'artifact-meta://' + effects['catalog'] + '/' + operation
        check_reference(effects['catalog'], reference)
        payload = json.dumps(effects, sort_keys=True, separators=(',', ':')).encode()
        path = self.directory / (operation + '.json')
        with self._lock:
            with path.open('xb') as record:
                os.chmod(path, 0o600)
                record.write(payload)
                record.flush()
                os.fsync(record.fileno())
            self.dispatch_calls += 1
        return reference

    def observe(self, reference):
        if type(reference) is not str or '/' not in reference:
            raise Denied('artifact_backend_reference')
        prefix, operation = reference.rsplit('/', 1)
        scope = prefix.removeprefix('artifact-meta://')
        check_reference(scope, reference)
        path = self.directory / (operation + '.json')
        if path.is_symlink():
            raise Denied('artifact_backend_reference')
        with path.open('rb') as record:
            payload = record.read(8193)
        if len(payload) > 8192:
            raise Denied('artifact_backend_response_size')
        effects = normalize(json.loads(payload))
        if effects['catalog'] != scope or not CONTRACT.has_marker(effects, operation):
            raise Denied('artifact_backend_reference')
        return effects

    def read(self, scope):
        if not valid_scope(scope):
            raise Denied('artifact_catalog_schema')
        result = []
        paths = sorted(self.directory.glob('*.json'))
        if len(paths) > 128:
            raise Denied('artifact_catalog_response_size')
        for path in paths:
            if path.is_symlink():
                raise Denied('artifact_backend_reference')
            with path.open('rb') as record:
                payload = record.read(8193)
            if len(payload) > 8192:
                raise Denied('artifact_backend_response_size')
            value = normalize(json.loads(payload))
            if value['catalog'] == scope:
                result.append(value)
        return result
