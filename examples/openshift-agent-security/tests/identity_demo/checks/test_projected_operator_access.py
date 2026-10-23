# SPDX-License-Identifier: Apache-2.0
"""Projected management identity rotates without human login or privilege renewal."""
from argparse import Namespace
import json
import time
from uuid import uuid4

import jwt
import pytest

import identity_demo_operator_access as access
from deployment_profile import active_profile


def fixture(tmp_path, monkeypatch):
    root = tmp_path / 'projected'
    root.mkdir()
    path = root / 'token'
    uid = str(uuid4())
    name = 'fixture-console-coordinator'
    namespace = active_profile().core_namespace
    identity = 'system:serviceaccount:' + namespace + ':' + name
    claims = {'sub': identity, 'iat': int(time.time()), 'exp': int(time.time()) + 7200,
              'kubernetes.io': {'namespace': namespace, 'serviceaccount': {'name': name},
                                'pod': {'uid': uid}}}
    def rotate(value):
        replacement = root / 'replacement'
        replacement.write_text(jwt.encode(value, 'synthetic-api-validation-is-mocked', algorithm='HS256'))
        replacement.chmod(0o444)
        replacement.replace(path)
    rotate(claims)
    config = {'clusters': [{'cluster': {'server': active_profile().expected_server}}],
              'contexts': [{'name': 'runtime'}], 'users': [{'user': {'tokenFile': str(path)}}]}
    kube = tmp_path / 'kubeconfig'
    kube.write_text(json.dumps(config))
    kube.chmod(0o600)
    args = Namespace(kubeconfig=str(kube), expected_server=active_profile().expected_server,
        service_account_token_file=str(path), service_account_token_root=str(root),
        service_account_namespace=namespace, service_account_name=name, pod_uid=uid,
        operator_login_file=None)
    calls = []
    def command(_, *words, **kwargs):
        calls.append(words)
        if words[0] == 'config': return json.dumps(config)
        assert words == ('whoami',)
        return identity
    monkeypatch.setattr(access, 'command', command)
    return args, claims, rotate, calls


def test_rotation_is_read_again_and_never_performs_human_login(tmp_path, monkeypatch):
    args, claims, rotate, calls = fixture(tmp_path, monkeypatch)
    first = access.ensure_access(args)
    rotate({**claims, 'exp': claims['exp'] + 600})
    assert access.ensure_access(args) == first + 600
    assert [c for c in calls if c[0] != 'config'] == [('whoami',), ('whoami',)]


@pytest.mark.parametrize('change', ['expired', 'pod', 'subject', 'api_identity', 'escape'])
def test_wrong_or_unverified_projected_identity_stops_before_work(tmp_path, monkeypatch, change):
    args, claims, rotate, _ = fixture(tmp_path, monkeypatch)
    if change == 'expired': rotate({**claims, 'exp': int(time.time()) + 10})
    elif change == 'pod': args.pod_uid = str(uuid4())
    elif change == 'subject': rotate({**claims, 'sub': 'system:serviceaccount:foreign:admin'})
    elif change == 'escape': args.service_account_token_root = str(tmp_path / 'other')
    else:
        original = access.command
        monkeypatch.setattr(access, 'command', lambda a, *w, **kw: 'foreign' if w == ('whoami',) else original(a, *w, **kw))
    with pytest.raises(access.OperatorAccessUnavailable):
        access.ensure_access(args)
