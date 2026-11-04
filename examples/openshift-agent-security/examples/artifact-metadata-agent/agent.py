# SPDX-License-Identifier: Apache-2.0
"""Deterministic, unprivileged artifact-metadata proposal producer."""
import hashlib


def propose_metadata(payload: bytes, catalog: str = 'catalog:release-lab') -> dict:
    """Describe synthetic build output; this function has no backend or runtime access."""
    return {
        'catalog': catalog,
        'artifact': 'sha256:' + hashlib.sha256(payload).hexdigest(),
        'component': 'offline-acceptance-bundle',
        'media_type': 'application/octet-stream',
        'size_bytes': len(payload),
        'tags': ['acceptance', 'synthetic'],
    }


if __name__ == '__main__':
    import json
    print(json.dumps(propose_metadata(b'local deterministic build output\n'), sort_keys=True))
