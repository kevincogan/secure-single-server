# SPDX-License-Identifier: Apache-2.0
"""Only current HTTPS MCP and isolated backend REST listeners are delivered."""
import json
from pathlib import Path


def test_delivery_keeps_current_backend_and_https_adapter_only():
    root=Path(__file__).resolve().parents[3]
    objects=json.loads((root/'infra/identity-demo/templates/application.json').read_text())['objects']
    selected={o['metadata']['name']:o for o in objects if o['kind']=='Deployment' and o['metadata']['name'] in {'fixture-jira','fixture-protected-adapter'}}
    assert [c['name'] for c in selected['fixture-jira']['spec']['template']['spec']['containers']]==['fixture-jira']
    assert [c['name'] for c in selected['fixture-protected-adapter']['spec']['template']['spec']['containers']]==['adapter-https']
    for o in objects:
        if o['kind']=='Service' and o['metadata']['name'] in selected:
            assert {p['port'] for p in o['spec']['ports']} == ({8080} if o['metadata']['name']=='fixture-jira' else {8443})
    assert not any(o['kind']=='HTTPRoute' and o['metadata']['name']=='fixture-jira' for o in objects)
