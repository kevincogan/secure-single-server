# SPDX-License-Identifier: Apache-2.0
"""Credential-free document tool client, executed inside the attested sandbox."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
import json
import hashlib
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise ValueError("Tool redirects are forbidden")


def call(endpoint, tool, arguments):
    if not endpoint.startswith('https://') or urlparse(endpoint).path != '/_document_proof/mcp':
        raise ValueError('Reviewed HTTPS document endpoint required')
    client = build_opener(ProxyHandler({}), NoRedirect())
    headers = {'Content-Type':'application/json','Accept':'application/json, text/event-stream',
        'MCP-Protocol-Version':'2025-11-25'}
    def rpc(method, params=None, identifier=1):
        payload = {'jsonrpc':'2.0','method':method}
        if identifier is not None:
            payload['id'] = identifier
        if params is not None:
            payload['params'] = params
        request = Request(endpoint, data=json.dumps(payload).encode(), headers=headers)
        try:
            response = client.open(request, timeout=20)
        except HTTPError as error:
            response = error
        with response:
            body = response.read(32769)
            if len(body)>32768:raise ValueError('Bounded tool response required')
            session = response.headers.get('Mcp-Session-Id')
            if session:
                if len(session)>4096 or any(ord(c)<33 or ord(c)>126 for c in session):
                    raise ValueError('Bounded MCP session required')
                headers['Mcp-Session-Id'] = session
            try:
                frames = [json.loads(line[5:].strip()) for line in body.decode().splitlines() if line.startswith('data:')]
                value = frames[-1] if frames else json.loads(body) if body else {}
            except (ValueError, UnicodeError):
                value = {'reason':'non_json_response','body_sha256':hashlib.sha256(body).hexdigest()}
            return {'status':response.status,'body':value}
    initialized = rpc('initialize', {'protocolVersion':'2025-11-25','capabilities':{},
        'clientInfo':{'name':'document-agent','version':'1'}})
    if initialized['status']!=200:
        return initialized
    if initialized['body'].get('result',{}).get('protocolVersion')!='2025-11-25':
        raise ValueError('Reviewed MCP protocol required')
    notification = rpc('notifications/initialized', identifier=None)
    if notification['status'] not in (200,202,204):
        return notification
    return rpc('tools/call', {'name':tool,'arguments':arguments}, identifier=2)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--endpoint',required=True)
    parser.add_argument('--tool',choices=['documents.read','documents.propose','document.publish'],required=True)
    parser.add_argument('--arguments',required=True,help='Public run/action/content JSON; never credentials')
    parser.add_argument('--copies', type=int, choices=(1, 2), default=1, help='Two simultaneous calls for dispatch acceptance')
    args=parser.parse_args()
    arguments = json.loads(args.arguments)
    if args.copies == 1:
        result = call(args.endpoint, args.tool, arguments)
    else:
        barrier = Barrier(2)
        def attempt(_):
            barrier.wait(timeout=5)
            return call(args.endpoint, args.tool, arguments)
        with ThreadPoolExecutor(max_workers=2) as pool:
            result = {'attempts': list(pool.map(attempt, range(2)))}
    print(json.dumps(result))


if __name__=='__main__':main()
