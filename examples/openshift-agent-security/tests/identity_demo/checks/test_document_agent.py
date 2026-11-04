# SPDX-License-Identifier: Apache-2.0
"""Packaged client negotiates MCP and does not hide transport denials."""
import importlib.util
import json
from pathlib import Path
from io import BytesIO
from urllib.error import HTTPError
import pytest


@pytest.fixture
def client():
    spec=importlib.util.spec_from_file_location('document_client_test',
        Path(__file__).resolve().parents[3]/'examples/document-agent/live_agent.py')
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


@pytest.mark.parametrize('failure_at', [None, 'initialize', 'tools/call'])
def test_handshake_and_plain_denial(client, monkeypatch, failure_at):
    methods=[]
    class Response(BytesIO):
        status=200
        headers={'Mcp-Session-Id':'test-session'}
    class Transport:
        def open(self, request, timeout):
            rpc=json.loads(request.data);method=rpc['method'];methods.append(method)
            assert timeout==20 and not any(k.lower()=='authorization' for k in request.headers)
            if len(methods)>1:assert request.headers['Mcp-session-id']=='test-session'
            if method==failure_at:raise HTTPError(request.full_url,403,'denied',{},BytesIO(b'Policy denied'))
            return Response(json.dumps({'result': {'protocolVersion':'2025-11-25'}}).encode())
    monkeypatch.setattr(client,'build_opener',lambda *a:Transport())
    result=client.call('https://reviewed.example.test/_document_proof/mcp','documents.read',{'run_id':'public-id'})
    assert methods==(['initialize'] if failure_at=='initialize' else ['initialize','notifications/initialized','tools/call'])
    assert result['status']==(403 if failure_at else 200)
    if failure_at:assert result['body']['reason']=='non_json_response' and len(result['body']['body_sha256'])==64
