# SPDX-License-Identifier: Apache-2.0
"""Operator-only delegation controls using two real attested supervisors.

These probes deliberately copy a bearer token outside the supervisor to measure
its replay authority. They do not demonstrate access by an untrusted agent or
accept the residual risk on the owner's behalf.
"""
from argparse import Namespace
import base64
import hashlib
import json
import time

from agent_security_runtime import strict_json


def run_controls(args, contexts, credentials_for, runs, output):
    from native_delegation_acceptance import DelegationAcceptance
    from protected_listener import HOST, NAME
    from proof import private, save
    from qualification import require
    delegates = {}
    for name in ('publisher', 'reader'):
        retained = credentials_for(name)
        selected = Namespace(**{**vars(args), 'label': 'document-' + name,
            'execution_context': contexts[name]})
        delegates[name] = DelegationAcceptance(selected, {'sub': retained['user']})
    client = delegates['publisher']
    subjects = client.subject_controls(delegates['reader'])
    token, claims = client.final()
    other, _ = delegates['reader'].final()
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {
        'name': 'documents.read', 'arguments': {'run_id': runs['publisher'], 'collection': 'engineering'}}}).encode()

    # A single reviewed tunnel keeps the 30-second controls specific to each fault.
    with client.tunnel(NAME, 19444, 443):
        def request(value, *, path='/_document_proof/mcp', extra=None, payload=body):
            headers = {'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream'}
            if value is not None:
                headers['Authorization'] = 'Bearer ' + value
            headers.update(extra or {})
            status, data = client._request_once(19444, HOST, path, payload, headers)
            try:
                response = strict_json(data)
            except (ValueError, UnicodeError):
                response = {'body_sha256': hashlib.sha256(data).hexdigest()}
            return {'status': status, 'body': response}

        results = {'positive': request(token), 'operator_copied_token': request(token)}
        require(all(v['status'] == 200 for v in results.values()), 'Legitimate and bearer replay controls required')
        malformed = strict_json(body)
        malformed['params']['approved'] = True
        results['altered_envelope'] = request(token, payload=json.dumps(malformed).encode())
        require(results['altered_envelope']['status'] == 403, 'Altered request envelope accepted')
        require(time.time() + 8 < claims['exp'], 'Delegation too near expiry for specific negative controls')
        human = credentials_for('publisher')['access_token']
        parts = token.split('.')
        signature = bytearray(base64.urlsafe_b64decode(parts[2] + '=' * (-len(parts[2]) % 4)))
        signature[0] ^= 1
        forged = '.'.join([*parts[:2], base64.urlsafe_b64encode(signature).decode().rstrip('=')])
        for name, value in [('missing', None), ('invalid_signature', forged),
                ('wrong_audience_human_token', human), ('other_workload_wrong_run', other)]:
            result = request(value)
            require(result['status'] == 403, 'Delegation negative control accepted: ' + name)
            results[name] = result
        results['forged_identity_headers'] = request(other, extra={
            'X-Forwarded-Client-Cert': 'URI=' + contexts['publisher'].workload,
            'X-User': claims['sub'], 'X-Run-ID': runs['publisher']})
        require(results['forged_identity_headers']['status'] == 403, 'Unsigned identity headers conferred authority')
        metadata = private(__import__('pathlib').Path(args.cli_config_dir) /
            'openshell/gateways/identity-demo-runtime/oidc_token.json')
        management = strict_json(metadata.read_bytes())
        candidate = management.get('access_token', management.get('token'))
        require(isinstance(candidate, str), 'Original private management token unavailable')
        results['wrong_issuer_management_token'] = request(candidate)
        require(results['wrong_issuer_management_token']['status'] == 403, 'Foreign issuer token accepted')
        require(time.time() + 3 < claims['exp'], 'Active delegation required for original Jira-route denial')
        results['jira_route_rejects_document_run'] = request(token, path='/mcp')
        require(results['jira_route_rejects_document_run']['status'] == 403, 'Document token bypassed Jira run checks')
        while time.time() <= claims['exp']:
            time.sleep(max(.01, min(2, claims['exp'] + .1 - time.time())))
        results['expired_delegation'] = request(token)
        require(results['expired_delegation']['status'] == 403, 'Expired delegation accepted')
    save(output / 'delegation-controls.private.json', {'exact_attested_subject_controls': subjects,
        'copied_bearer_token_reusable_before_expiry': True, 'residual_risk_accepted': False,
        'delegation_expires': claims['exp'],
        'verified_claims': {k: claims[k] for k in ('iss', 'aud', 'sub', 'azp', 'iat', 'exp')},
        'native_subject_matches': claims['sub'] == credentials_for('publisher')['user'], 'results': results})
    return {'real_delegation_controls_passed': True, 'count': len(results),
        'sender_constrained_protection': False, 'residual_risk_requires_review': True}
