# SPDX-License-Identifier: Apache-2.0
import ssl
import httpx
import pytest
from deployment_profile import active_profile
from identity_demo_control_transport import OperatorTransport


def factory(monkeypatch,handler):
    real_context=ssl.create_default_context
    monkeypatch.setattr(ssl,'create_default_context',lambda **kw:real_context())
    original=httpx.Client
    clients=[]
    def client(**kw):
        assert kw['trust_env'] is False and kw['follow_redirects'] is False
        assert kw['transport']._pool._retries==0
        kw['transport']=httpx.MockTransport(handler)
        value=original(**kw);clients.append(value);return value
    monkeypatch.setattr(httpx,'Client',client)
    transport=OperatorTransport('https://'+active_profile().service_host('fixture-identity-operator')+':8444','synthetic-ca')
    return transport,clients


def test_control_reuses_connection_but_never_retries_unknown_mutation(monkeypatch):
    calls=[]
    def handler(request):
        calls.append(request)
        if request.url.path.endswith('/next'):raise httpx.ReadTimeout('synthetic ambiguous reply')
        return httpx.Response(200,json={'ready':True})
    transport,clients=factory(monkeypatch,handler)
    for _ in range(2):assert transport.request('/internal/operator/console/state','s'*40)[0]==200
    assert len(clients)==1
    with pytest.raises(httpx.ReadTimeout):transport.request('/internal/operator/console/next','s'*40,b'{}')
    assert len(calls)==3 and clients[0].is_closed
    assert transport.request('/internal/operator/console/state','s'*40)[0]==200
    assert len(clients)==2 and len(calls)==4


def test_control_refuses_redirects_and_caller_selected_paths(monkeypatch):
    calls=[]
    def handler(request):calls.append(request);return httpx.Response(302,headers={'Location':'https://foreign.example'})
    transport,clients=factory(monkeypatch,handler)
    with pytest.raises(ValueError,match='redirect'):transport.request('/internal/operator/console/state','s'*40)
    assert len(calls)==1
    for path in ('https://foreign.example','/internal/operator/../adapter','/internal/operator/x?target=x','//foreign'):
        with pytest.raises(ValueError):transport.request(path,'s'*40)
    assert len(calls)==1


def test_control_bounds_response_body(monkeypatch):
    transport,clients=factory(monkeypatch,lambda request:httpx.Response(200,content=b'x'*131073))
    with pytest.raises(ValueError,match='Bounded'):transport.request('/internal/operator/console/state','s'*40)
    assert clients[0].is_closed


@pytest.mark.parametrize('fault', [None, 'wrong_name', 'wrong_ca', 'redirect', 'oversized', 'lost_reply', 'idle_close'])
def test_operator_tunnel_uses_real_tls_service_identity_and_never_replays(tmp_path, monkeypatch, fault):
    """Exercise the real socket/HTTP implementation against a synthetic TLS server."""
    import http.client
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading
    from cryptography.hazmat.primitives import serialization
    from source_render import _ca, _leaf

    host = active_profile().service_host('fixture-identity-operator')
    key, authority = _ca()
    private, certificate = _leaf(key, authority, ['other.example.test' if fault == 'wrong_name' else host])
    certificate_file, key_file, ca_file = (tmp_path / name for name in ('server.pem', 'server.key', 'ca.pem'))
    certificate_file.write_bytes(certificate)
    key_file.write_bytes(private)
    key_file.chmod(0o600)
    ca_file.write_bytes((_ca()[1] if fault == 'wrong_ca' else authority).public_bytes(serialization.Encoding.PEM))
    seen, names = [], []
    import identity_demo_control_transport as control
    clock = [100.0]
    monkeypatch.setattr(control, 'monotonic', lambda: clock[0])

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def do_GET(self):
            assert self.headers['Host'] == host + ':8444'
            assert self.headers['Authorization'] == 'Bearer ' + 's' * 40
            seen.append((self.command, self.path))
            if self.command == 'POST':
                assert self.rfile.read(int(self.headers['Content-Length'])) == b'{}'
            if fault == 'lost_reply' and self.command == 'POST':
                self.close_connection = True
                return
            self.send_response(302 if fault == 'redirect' else 200)
            if fault == 'redirect':
                self.send_header('Location', 'https://foreign.example/never-follow')
            body = b'x' * 131073 if fault == 'oversized' else b'{}'
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            if fault == 'idle_close':
                self.close_connection = True  # No Connection: close hint.

        do_POST = do_GET

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(str(certificate_file), str(key_file))
    tls.set_servername_callback(lambda socket, name, context: names.append(name))
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    transport = OperatorTransport('https://' + host + ':8444', str(ca_file), loopback_port=server.server_port)
    try:
        if fault in ('wrong_name', 'wrong_ca'):
            with pytest.raises(ssl.SSLCertVerificationError):
                transport.request('/internal/operator/console/state', 's' * 40)
            assert seen == []  # TLS fails before any credential-bearing HTTP request.
        elif fault in ('redirect', 'oversized'):
            with pytest.raises(ValueError, match='redirect' if fault == 'redirect' else 'Bounded'):
                transport.request('/internal/operator/console/state', 's' * 40)
            assert len(seen) == 1 and transport.local.connection is None
        elif fault == 'lost_reply':
            with pytest.raises(http.client.RemoteDisconnected):
                transport.request('/internal/operator/console/next', 's' * 40, b'{}')
            assert seen == [('POST', '/internal/operator/console/next')]
            assert transport.local.connection is None
            assert transport.request('/internal/operator/console/state', 's' * 40)[0] == 200
            assert len(seen) == 2  # A subsequent independent read, never a repeated claim.
        else:
            for _ in range(2):
                assert transport.request('/internal/operator/console/state', 's' * 40)[0] == 200
                if fault == 'idle_close':
                    clock[0] += 10  # Reconnect before dispatch, without a sleep/retry.
            assert len(seen) == 2
            assert names == ([host, host] if fault == 'idle_close' else [host])
    finally:
        transport.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
    assert not thread.is_alive()


@pytest.mark.parametrize('port', [True, 0, 1023, 65536, '18447'])
def test_tunnel_port_must_be_an_explicit_bounded_integer(port):
    origin = 'https://' + active_profile().service_host('fixture-identity-operator') + ':8444'
    with pytest.raises(ValueError, match='loopback port'):
        OperatorTransport(origin, 'unused-ca', loopback_port=port)


def test_cli_operator_requests_use_only_the_explicit_private_transport(tmp_path, monkeypatch):
    from types import SimpleNamespace
    import json
    import identity_demo_control_transport as control
    from permission_flow import PermissionFlow, DRIVER, BASE
    credentials, keys, ca = (tmp_path / name for name in ('users.json', 'keys.json', 'ca.pem'))
    for path, value in ((credentials, {'analyst': 'synthetic'}), (keys, {'operator_secret': 's' * 40})):
        path.write_text(json.dumps(value))
        path.chmod(0o600)
    ca.write_text('synthetic public trust')
    ca.chmod(0o600)
    calls = []

    class Transport:
        def __init__(self, origin, trust, *, loopback_port):
            assert origin == 'https://' + active_profile().service_host('fixture-identity-operator') + ':8444'
            assert trust == str(ca) and loopback_port == 18447

        def request(self, path, secret, data=None):
            assert secret == 's' * 40
            calls.append((path, data))
            return 200, {}, b'{}'

    monkeypatch.setattr(control, 'OperatorTransport', Transport)
    monkeypatch.setenv('IDENTITY_DEMO_OPERATOR_ORIGIN', 'https://' + active_profile().service_host('fixture-identity-operator') + ':8444')
    monkeypatch.setenv('IDENTITY_DEMO_OPERATOR_CA', str(ca))
    monkeypatch.setenv('IDENTITY_DEMO_OPERATOR_LOOPBACK_PORT', '18447')
    args = SimpleNamespace(credentials_file=str(credentials))
    flow = PermissionFlow(args, keys)
    def public_forbidden(*args, **kwargs):
        raise AssertionError('Private operator call must not fall back to public routes')
    flow.client.open = public_forbidden
    assert flow.http(DRIVER + '/internal/operator/credentials/' + 'a' * 32, operator=True)[0] == 200
    assert flow.http(DRIVER + '/internal/operator/revoke', value={'run_id': 'a' * 32}, operator=True)[0] == 200
    assert len(calls) == 2 and calls[1][1] == json.dumps({'run_id': 'a' * 32}).encode()
    for url, fields in ((BASE + '/internal/operator/revoke', None), (DRIVER + '/internal/operator/revoke', {'csrf': 'x'})):
        with pytest.raises(ValueError, match='Exact JSON operator target'):
            flow.http(url, fields=fields, operator=True)
    assert len(calls) == 2
    monkeypatch.delenv('IDENTITY_DEMO_OPERATOR_CA')
    with pytest.raises(ValueError, match='Complete private operator'):
        PermissionFlow(args, keys)


@pytest.mark.parametrize('values', [
    {'IDENTITY_DEMO_OPERATOR_CA': 'ca'},
    {'IDENTITY_DEMO_OPERATOR_LOOPBACK_PORT': '18447'},
    {'IDENTITY_DEMO_OPERATOR_ORIGIN': 'https://foreign.example', 'IDENTITY_DEMO_OPERATOR_CA': 'ca'},
    {'IDENTITY_DEMO_OPERATOR_ORIGIN': 'owned', 'IDENTITY_DEMO_OPERATOR_CA': 'ca', 'IDENTITY_DEMO_OPERATOR_LOOPBACK_PORT': 'not-a-port'},
])
def test_partial_or_foreign_environment_never_falls_back_to_public_operator(monkeypatch, values):
    from identity_demo_control_transport import configured_transport
    for key in ('IDENTITY_DEMO_OPERATOR_ORIGIN', 'IDENTITY_DEMO_OPERATOR_CA', 'IDENTITY_DEMO_OPERATOR_LOOPBACK_PORT'):
        monkeypatch.delenv(key, raising=False)
    assert configured_transport() is None
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    with pytest.raises(ValueError):
        configured_transport()
