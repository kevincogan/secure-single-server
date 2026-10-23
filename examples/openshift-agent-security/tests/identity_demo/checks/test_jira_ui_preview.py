# SPDX-License-Identifier: Apache-2.0
"""Keep local presentation access fixed, read-only and credential-private."""

from io import BytesIO
import ssl

import pytest

import jira_ui_preview as preview


@pytest.mark.parametrize(
    "path", ["/issue/TEST-3", "/static/css/style.css", "/static/logo.svg"]
)
def test_exact_issue_and_static_views_allowed(path: str) -> None:
    """Only approved issue pages and static assets may reach the backend."""
    assert preview.allowed_path(path, frozenset({"TEST-3"}))


def test_service_issue_requires_its_own_exact_allowlist() -> None:
    """Reuse presentation has the same exact-page boundary as CVE presentation."""
    assert preview.allowed_path("/issue/SERVICE-2", frozenset({"SERVICE-2"}))
    assert not preview.allowed_path("/issue/SERVICE-3", frozenset({"SERVICE-2"}))
    assert not preview.allowed_path("/issue/SERVICE-2/edit", frozenset({"SERVICE-2"}))


@pytest.mark.parametrize(
    "path",
    [
        "/issue/OTHER-3",
        "/issue/TEST-4",
        "/issue/TEST-3/edit",
        "/admin/reset",
        "/rest/api/2/search",
        "https://unapproved.test/issue/TEST-3",
        "//unapproved.test/issue/TEST-3",
        "/static/../admin/reset",
        "/static/%2e%2e/admin/reset",
        "/issue/TEST-3?redirect=unapproved",
        "/static/a\\b",
        "/issue/TEST-3#fragment",
    ],
)
def test_other_paths_and_encoded_overrides_denied(path: str) -> None:
    """Do not create a general proxy or open a management/mutation side door."""
    assert not preview.allowed_path(path, frozenset({"TEST-3"}))


def receiver(host: str = "127.0.0.1:18088") -> object:
    """Build a handler without opening network listeners or using live credentials."""
    cls = preview.handler(
        frozenset({"TEST-3"}), ssl.create_default_context(), "synthetic-secret"
    )
    value = object.__new__(cls)
    value.headers = {"Host": host, "Authorization": "attacker-supplied"}
    value.path = "/issue/TEST-3"
    value.events = []
    value.send_error = lambda *args: value.events.append(("error", args))
    value.send_response = lambda *args: value.events.append(("response", args))
    value.send_header = lambda *args: value.events.append(("header", args))
    value.end_headers = lambda: None
    value.wfile = BytesIO()
    return value


def test_rebinding_host_denied_before_upstream_request(monkeypatch: object) -> None:
    """A malicious browser origin cannot rename the loopback observer."""

    def unexpected(*args: object, **kwargs: object) -> object:
        raise AssertionError("no upstream request expected")

    monkeypatch.setattr(preview, "TunnelHTTPS", unexpected)
    value = receiver("unapproved.test:18088")
    value.do_GET()
    assert value.events == [("error", (403, "Read-only presentation path"))]


def test_all_mutations_denied_without_upstream_request(monkeypatch: object) -> None:
    """No form/API mutation is sent to Jira, even by the trusted presenter."""
    value = receiver()
    for method in (value.do_POST, value.do_PUT, value.do_PATCH, value.do_DELETE):
        method()
    assert value.events == [("error", (405, "Read-only presentation"))] * 4


def test_browser_credentials_not_forwarded_and_backend_redirect_not_followed(
    monkeypatch: object,
) -> None:
    """Credentials apply only to the fixed verified cluster hop; redirects fail closed."""

    class Upstream:
        """Model only the exact fixed HTTPS target."""

        status = 302

        def __init__(self, host: str, port: int, **kwargs: object) -> None:
            assert host == preview.HOST and port == 8080

        def request(self, method: str, path: str, headers: dict) -> None:
            """Inspect fixed operation and credential custody."""
            assert method == "GET" and path == "/issue/TEST-3"
            assert headers["Authorization"] == "Basic synthetic-secret"

        def getresponse(self) -> object:
            return self

        def read(self, limit: int) -> bytes:
            assert limit == 2_000_001
            return b"redirect"

        def close(self) -> None:
            return None

    monkeypatch.setattr(preview, "TunnelHTTPS", Upstream)
    value = receiver()
    value.do_GET()
    assert value.events == [("error", (502, "Verified Jira view unavailable"))]


def test_managed_preview_keys_are_dynamic_exact_and_synthetic(tmp_path: object) -> None:
    """A new verified result can be opened without starting another proxy process."""
    from argparse import Namespace
    import threading

    managed = preview.ManagedPreview(Namespace(output_dir=tmp_path), threading.Event())
    assert managed.allow_key("OPS-3") is False
    assert preview.allowed_path("/issue/OPS-3", managed.keys)
    assert not preview.allowed_path("/issue/OPS-4", managed.keys)
    managed.ready.set()
    assert managed.allow_key("SERVICE-5") is True
    for invalid in (
        "OTHER-1",
        "OPS-1/edit",
        "OPS-0",
        "https://unapproved.test/issue/OPS-3",
    ):
        with pytest.raises(ValueError):
            managed.allow_key(invalid)


def test_trusted_history_refresh_replaces_the_bounded_preview_allowlist(
    tmp_path: object,
) -> None:
    from argparse import Namespace
    import threading

    managed = preview.ManagedPreview(Namespace(output_dir=tmp_path), threading.Event())
    managed.allow_key("TEST-1")
    managed.set_keys(["OPS-9", "SERVICE-2"])
    assert managed.keys == {"OPS-9", "SERVICE-2"}
    with pytest.raises(ValueError):
        managed.set_keys(["OPS-9", "OTHER-1"])
    assert managed.keys == {"OPS-9", "SERVICE-2"}


def test_actual_jira_html_is_labelled_read_only_without_inventing_issue_content() -> (
    None
):
    source = b"<html><head><title>OPS-3</title></head><body><h1>Actual issue title</h1><button>Edit</button></body></html>"
    result = preview.read_only_html(source)
    assert b"Actual issue title" in result and b"<title>OPS-3</title>" in result
    assert b"Read-only issue view" in result and b"Return to agent console" in result
    assert (
        b"button,form,input,textarea" in result and b"display:none!important" in result
    )
    assert preview.read_only_html(b"not an HTML document") == b"not an HTML document"


def test_idle_browser_connection_does_not_block_verified_issue_view(monkeypatch):
    """Browsers may pre-open a socket and send no request on it."""
    from http.client import HTTPConnection
    from http.server import HTTPServer
    import socket
    import threading

    class Response:
        status = 200

        def read(self, limit):
            return b"<html><head></head><body>Verified TEST-8</body></html>"

        def getheader(self, name, default=None):
            return "text/html"

    class Upstream:
        def __init__(self, *a, **kw):
            pass

        def request(self, method, path, headers):
            assert method == "GET" and path == "/issue/TEST-8"

        def getresponse(self):
            return Response()

        def close(self):
            pass

    monkeypatch.setattr(preview, "TunnelHTTPS", Upstream)
    factory = getattr(preview, "PreviewHTTPServer", HTTPServer)
    server = factory(
        ("127.0.0.1", 0),
        preview.handler(frozenset({"TEST-8"}), None, "private-fixture"),
    )
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
    )
    thread.start()
    idle = socket.create_connection(server.server_address, timeout=1)
    client = HTTPConnection(*server.server_address, timeout=1)
    try:
        client.request("GET", "/issue/TEST-8", headers={"Host": "127.0.0.1:18088"})
        response = client.getresponse()
        assert response.status == 200 and b"Verified TEST-8" in response.read()
    finally:
        idle.close()
        client.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_managed_preview_key_snapshot_remains_independent_during_updates(tmp_path):
    from argparse import Namespace
    import threading

    managed = preview.ManagedPreview(Namespace(output_dir=tmp_path), threading.Event())
    managed.allow_key("TEST-8")
    snapshot = managed.key_snapshot()
    managed.set_keys(["SERVICE-8"])
    assert snapshot == frozenset({"TEST-8"}) and managed.key_snapshot() == frozenset(
        {"SERVICE-8"}
    )
