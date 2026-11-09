# SPDX-License-Identifier: Apache-2.0
"""Thread-isolated, hostname-verified operator connections; mutations never replay."""
import http.client
import json
import os
import socket
import threading
from time import monotonic
from urllib.parse import urlparse

import httpx
from deployment_profile import active_profile


def configured_transport():
    """Reuse explicit private listener settings for cluster workers and local CLI."""
    origin = os.environ.get('IDENTITY_DEMO_OPERATOR_ORIGIN')
    ca = os.environ.get('IDENTITY_DEMO_OPERATOR_CA')
    port = os.environ.get('IDENTITY_DEMO_OPERATOR_LOOPBACK_PORT')
    if origin is None and ca is None and port is None:
        return None  # Legacy public operator configuration, explicitly unchanged.
    if not origin or not ca:
        raise ValueError('Complete private operator origin and CA required')
    if port is not None and (not port.isascii() or not port.isdecimal()):
        raise ValueError('Integer operator loopback port required')
    return OperatorTransport(origin, ca, loopback_port=int(port) if port is not None else None)


class _LoopbackHTTPS(http.client.HTTPSConnection):
    """Use an operator-owned tunnel while retaining the service hostname/SNI."""

    def __init__(self, host, context, port, timeout):
        super().__init__(host, 8444, context=context, timeout=timeout)
        self.local_port = port

    def connect(self):
        raw = socket.create_connection(('127.0.0.1', self.local_port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


class OperatorTransport:
    def __init__(self, origin: str, ca: str, *, loopback_port: int | None = None):
        expected = 'https://' + active_profile().service_host('fixture-identity-operator') + ':8444'
        if origin != expected or not ca:
            raise ValueError('Exact private operator service and CA required')
        if loopback_port is not None and (type(loopback_port) is not int or not 1024 <= loopback_port <= 65535):
            raise ValueError('Bounded operator loopback port required')
        import ssl
        self.tls = ssl.create_default_context(cafile=ca)
        self.origin = origin
        self.loopback_port = loopback_port
        self.local = threading.local()

    def request(self, path: str, secret: str, data: bytes | None = None, *, timeout=12):
        if (not path.startswith('/internal/operator/') or '?' in path or '#' in path
                or '..' in path or '//' in path or urlparse(path).netloc):
            raise ValueError('Fixed operator path required')
        if (not isinstance(secret, str) or not 32 <= len(secret) <= 4096
                or any(not 33 <= ord(c) <= 126 for c in secret)):
            raise ValueError('Bounded operator credential required')
        if data is not None and (not isinstance(data, bytes) or len(data) > 131072):
            raise ValueError('Bounded operator request required')
        if self.loopback_port is not None:
            return self._loopback_request(path, secret, data, timeout)
        if not getattr(self.local, 'client', None):
            self.local.client = httpx.Client(verify=self.tls, trust_env=False, follow_redirects=False,
                transport=httpx.HTTPTransport(verify=self.tls, retries=0),
                limits=httpx.Limits(max_connections=1, max_keepalive_connections=1, keepalive_expiry=25))
        client=self.local.client
        try:
            with client.stream('POST' if data is not None else 'GET', self.origin+path, content=data,
                headers={'Authorization':'Bearer '+secret, 'Content-Type':'application/json'},timeout=timeout) as response:
                body=bytearray()
                for chunk in response.iter_bytes(chunk_size=16384):
                    body.extend(chunk)
                    if len(body)>131072: raise ValueError('Bounded operator response required')
                if 300<=response.status_code<400: raise ValueError('Operator redirect refused')
                return response.status_code, response.headers, bytes(body)
        except Exception:
            # A failed command is uncertain. Drop this channel, but do not repeat
            # the request; a future independent operation can open a fresh one.
            client.close()
            self.local.client=None
            raise

    def _loopback_request(self, path, secret, data, timeout):
        connection = getattr(self.local, 'connection', None)
        # The private server expires idle HTTP connections. Discard ours before
        # sending a new request; never recover by replaying a failed request.
        if connection and monotonic() - self.local.last_used >= 2:
            connection.close()
            self.local.connection = None
        if not getattr(self.local, 'connection', None):
            self.local.connection = _LoopbackHTTPS(urlparse(self.origin).hostname,
                self.tls, self.loopback_port, timeout)
        connection = self.local.connection
        connection.timeout = timeout
        if connection.sock:
            connection.sock.settimeout(timeout)
        try:
            connection.request('POST' if data is not None else 'GET', path, body=data,
                headers={'Authorization': 'Bearer ' + secret, 'Content-Type': 'application/json'})
            response = connection.getresponse()
            body = response.read(131073)
            if len(body) > 131072:
                raise ValueError('Bounded operator response required')
            if 300 <= response.status < 400:
                raise ValueError('Operator redirect refused')
            self.local.last_used = monotonic()
            return response.status, dict(response.getheaders()), body
        except Exception:
            # No request, including a lost claim/write reply, is replayed.
            connection.close()
            self.local.connection = None
            raise

    def close(self):
        """Close only this thread's explicitly owned control connections."""
        for name in ('client', 'connection'):
            connection = getattr(self.local, name, None)
            if connection:
                connection.close()
                setattr(self.local, name, None)


def driver_request(client, url, fields=None, value=None, *, operator_secret=None, operator_transport=None):
    """Bounded fixed-origin transport shared by headless workers and qualification."""
    from urllib.error import HTTPError
    from urllib.parse import urlencode, urlparse
    from urllib.request import Request
    from identity_demo_action_policy import DRIVER
    from identity_demo_keycloak_upstream import BASE
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in (
        urlparse(DRIVER).hostname,
        urlparse(BASE).hostname,
    ):
        raise ValueError("Approved HTTPS target required")
    headers = {"Origin": DRIVER}
    data = urlencode(fields).encode() if fields is not None else None
    if value is not None:
        data = json.dumps(value).encode()
        headers["Content-Type"] = "application/json"
    if operator_secret is not None:
        if not url.startswith(DRIVER + '/internal/operator/') or fields is not None:
            raise ValueError('Exact JSON operator target required')
        if operator_transport:
            return operator_transport.request(url.removeprefix(DRIVER),
                                                   operator_secret, data)
        headers["Authorization"] = "Bearer " + operator_secret
    try:
        response = client.open(
            Request(url, data=data, headers=headers), timeout=12
        )
    except HTTPError as error:
        response = error
    with response:
        body = response.read(131_073)
        if len(body) > 131_072:
            raise ValueError("Bounded driver response required")
        return response.status, response.headers, body
