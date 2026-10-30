# SPDX-License-Identifier: Apache-2.0
"""Loopback-only, read-only transport for the existing synthetic Jira UI.

This is trusted operator presentation access, not the pilot user/agent path.
It never exposes a cluster Route, accepts mutations, or forwards browser secrets.
The cluster HTTPS hop verifies its service CA and exact hostname.
"""

import argparse
import base64
from html import escape
from http.client import HTTPException, HTTPSConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import socket
import ssl
import subprocess
import time
import threading
from urllib.parse import unquote, urlsplit
from typing import Callable

from deployment_profile import active_profile
from identity_demo_action_policy import DRIVER
from identity_demo_adapter_catalog import kube, owned, NS
from identity_demo_runtime_cli import private_path
from identity_demo_runtime_grants import SERVER

HOST = active_profile().service_host("fixture-jira")


def allowed_path(target: str, keys: frozenset[str]) -> bool:
    """Allow exact verified issue pages and static assets, never admin/API/edit paths."""
    if len(target) > 2048 or any(ord(c) < 32 for c in target):
        return False
    u = urlsplit(target)
    if u.scheme or u.netloc or u.fragment or u.query or unquote(u.path) != u.path:
        return False
    if "\\" in u.path or any(p in (".", "..") for p in u.path.split("/")):
        return False
    return (
        u.path in {"/issue/" + key for key in keys}
        or re.fullmatch(r"/static/[A-Za-z0-9_./-]+", u.path) is not None
    )


class TunnelHTTPS(HTTPSConnection):
    """Preserve verified HTTPS while connecting to an operator's loopback tunnel."""

    def connect(self) -> None:
        """Authenticate the actual fixed Service DNS name, not localhost."""
        if self.host != HOST or self.port != 8080 or self._tunnel_host:
            raise ValueError("Exact Jira Service required")
        raw = socket.create_connection(("127.0.0.1", 18089), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=HOST)
        except Exception:
            raw.close()
            raise


def read_only_html(body: bytes) -> bytes:
    """Make the actual fixture page visibly read-only; transport restrictions remain authoritative."""
    if b"</head>" not in body or re.search(rb"<body(?:\s[^>]*)?>", body) is None:
        return body
    style = b"""<style>
button,form,input,textarea,a[href="/"],a[href="/issues"],a[href="/admin/import"],a[href^="/project/"]{display:none!important}
.demo-readonly{font:14px/1.5 system-ui,sans-serif;background:#eaf3ff;color:#153e70;padding:12px 20px;border-bottom:1px solid #bdd4ef;display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap}
.demo-readonly a{display:inline!important;color:#075bbd;font-weight:600}.demo-readonly small{display:block}
</style></head>"""
    banner = (
        '<aside class="demo-readonly" role="note"><span><strong>Jira · Read-only issue view</strong>'
        "<small>Verified issues only. Creates and edits stay in the approval workflow.</small></span>"
        '<a href="'
        + escape(DRIVER, quote=True)
        + '">Return to agent console</a></aside>'
    ).encode()
    body = body.replace(b"</head>", style, 1)
    return re.sub(
        rb"(<body(?:\s[^>]*)?>)", lambda match: match[1] + banner, body, count=1
    )


class PreviewHTTPServer(ThreadingHTTPServer):
    """Bound idle browser connections without blocking all read-only viewers."""

    daemon_threads = True
    block_on_close = False

    def __init__(self, *args: object, **kwargs: object) -> None:
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(*args, **kwargs)

    def get_request(self) -> tuple:
        """Expire incomplete request headers instead of holding a slot forever."""
        connection, address = super().get_request()
        connection.settimeout(10)
        return connection, address

    def process_request(self, request: socket.socket, address: tuple) -> None:
        """Keep presentation concurrency bounded even with idle preconnections."""
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request: socket.socket, address: tuple) -> None:
        """Release capacity after success, disconnect or handler failure."""
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


def handler(
    keys: frozenset[str] | Callable[[], frozenset[str]],
    context: ssl.SSLContext,
    credential: str,
) -> type:
    """Create a local observer; credentials remain at its fixed trusted boundary."""

    class Preview(BaseHTTPRequestHandler):
        """Render the existing UI without a general-purpose backend proxy."""

        def do_GET(self) -> None:
            """Serve only allowlisted GETs; reject DNS rebinding and redirects."""
            if self.headers.get("Host") != "127.0.0.1:18088" or not allowed_path(
                self.path, keys() if callable(keys) else keys
            ):
                self.send_error(403, "Read-only presentation path")
                return
            upstream = TunnelHTTPS(HOST, 8080, timeout=8, context=context)
            try:
                upstream.request(
                    "GET",
                    self.path,
                    headers={
                        "Authorization": "Basic " + credential,
                        "Accept": "text/html,text/css,application/javascript,image/*",
                    },
                )
                response = upstream.getresponse()
                body = response.read(2_000_001)
                if len(body) > 2_000_000 or response.status != 200:
                    self.send_error(502, "Verified Jira view unavailable")
                    return
                content_type = response.getheader("Content-Type", "text/plain")
                if content_type.startswith("text/html"):
                    body = read_only_html(body)
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header(
                    "Content-Security-Policy",
                    "default-src 'self'; script-src 'none'; "
                    "style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'none'; "
                    "form-action 'none'; base-uri 'none'; frame-ancestors 'none'",
                )
                self.end_headers()
                self.wfile.write(body)
            except (OSError, ValueError, HTTPException):
                try:
                    self.send_error(502, "Verified Jira view unavailable")
                except OSError:
                    pass  # A closed observer connection never disrupts the coordinator.
            finally:
                upstream.close()

        def do_POST(self) -> None:
            """Never allow presentation access to execute backend mutations."""
            self.send_error(405, "Read-only presentation")

        do_PUT = do_DELETE = do_PATCH = do_POST

        def log_message(self, format: str, *args: object) -> None:
            """Never log request URLs, credentials or backend content."""
            return None

    return Preview


class ManagedPreview:
    """Supervise the existing exact-key observer with the operator coordinator."""

    def __init__(self, args: argparse.Namespace, stopping: threading.Event) -> None:
        """Keep the bridge on loopback; no cluster resource or public route is created."""
        self.args, self.stopping = args, stopping
        self.keys: set[str] = set()
        self.keys_lock = threading.Lock()
        self.ready = threading.Event()
        self.thread = threading.Thread(
            target=self.serve, name="jira-read-only-preview", daemon=True
        )

    def allow_key(self, key: str) -> bool:
        """Accept only a coordinator-verified synthetic issue; never a browser URL."""
        if not isinstance(key, str) or not re.fullmatch(
            r"(?:TEST|SERVICE|OPS)-[1-9][0-9]*", key
        ):
            raise ValueError("Verified synthetic Jira issue key required")
        with self.keys_lock:
            if len(self.keys) >= 100 and key not in self.keys:
                self.keys.remove(sorted(self.keys)[0])
            self.keys.add(key)
        return self.ready.is_set()

    def set_keys(self, keys: list[str]) -> None:
        """Restore only independently verified issue references from trusted durable state."""
        if not isinstance(keys, list) or len(keys) > 100:
            raise ValueError("Bounded verified issue references required")
        if any(
            not isinstance(key, str)
            or not re.fullmatch(r"(?:TEST|SERVICE|OPS)-[1-9][0-9]*", key)
            for key in keys
        ):
            raise ValueError("Verified synthetic Jira issue keys required")
        with self.keys_lock:
            self.keys.clear()
            self.keys.update(keys)

    def key_snapshot(self) -> frozenset[str]:
        """Read one coherent allowlist while other requests/verified runs update it."""
        with self.keys_lock:
            return frozenset(self.keys)

    def start(self) -> None:
        """Start an isolated observer thread; it never gates or performs Jira writes."""
        self.thread.start()

    def serve(self) -> None:
        """Reconnect the local read-only transport, preserving verified TLS and host checks."""
        failures = 0
        while not self.stopping.is_set():
            tunnel = None
            try:
                if (
                    self.args.expected_server != SERVER
                    or kube(self.args, "config", "view", "--minify", "-o", "json")[
                        "clusters"
                    ][0]["cluster"]["server"]
                    != SERVER
                ):
                    raise ValueError("Exact approved presentation cluster required")
                owned(self.args, "namespace", NS)
                owned(self.args, "service", "fixture-jira")
                owned(self.args, "deployment", "fixture-jira")
                credentials = json.loads(
                    private_path(self.args.credentials_file).read_text()
                )
                ca = owned(self.args, "configmap", "fixture-service-ca")["data"][
                    "service-ca.crt"
                ]
                context = ssl.create_default_context(cadata=ca)
                credential = base64.b64encode(
                    ("admin:" + credentials["jira_admin"]).encode()
                ).decode()
                log_path = self.args.output_dir / (
                    "jira-preview-" + str(time.monotonic_ns()) + ".private.log"
                )
                with log_path.open("xb") as log:
                    log_path.chmod(0o600)
                    tunnel = subprocess.Popen(
                        [
                            "oc",
                            "--kubeconfig",
                            self.args.kubeconfig,
                            "-n",
                            NS,
                            "port-forward",
                            "--address=127.0.0.1",
                            "service/fixture-jira",
                            "18089:8080",
                        ],
                        stdout=log,
                        stderr=log,
                    )
                    deadline = time.monotonic() + 15
                    while not self.stopping.is_set():
                        if tunnel.poll() is not None or time.monotonic() >= deadline:
                            raise RuntimeError(
                                "Local Jira observer transport unavailable"
                            )
                        try:
                            with socket.create_connection(
                                ("127.0.0.1", 18089), timeout=0.5
                            ):
                                break
                        except OSError:
                            self.stopping.wait(0.2)
                    if self.stopping.is_set():
                        break
                    with PreviewHTTPServer(
                        ("127.0.0.1", 18088),
                        handler(self.key_snapshot, context, credential),
                    ) as server:
                        server.timeout = 0.5
                        failures = 0
                        self.ready.set()
                        while not self.stopping.is_set() and tunnel.poll() is None:
                            server.handle_request()
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                failures += 1
            finally:
                self.ready.clear()
                if tunnel is not None:
                    tunnel.terminate()
                    try:
                        tunnel.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        tunnel.kill()
                        tunnel.wait(timeout=5)
            # Never kill an unrelated listener or weaken verification to recover.
            self.stopping.wait(min(15, 2 ** min(failures, 4)))


def run(args: argparse.Namespace) -> None:
    """Start bounded local observation without modifying any cluster resource."""
    private_path(args.kubeconfig)
    if (
        args.expected_server != SERVER
        or kube(args, "config", "view", "--minify", "-o", "json")["clusters"][0][
            "cluster"
        ]["server"]
        != SERVER
    ):
        raise ValueError("Exact approved cluster required")
    owned(args, "namespace", NS)
    owned(args, "service", "fixture-jira")
    owned(args, "deployment", "fixture-jira")
    keys = frozenset(args.issue_key)
    if (
        not keys
        or any(not re.fullmatch(r"(?:TEST|SERVICE|OPS)-[1-9][0-9]*", k) for k in keys)
        or not 1 <= args.duration <= 1800
    ):
        raise ValueError("Bounded synthetic issue preview required")
    credentials = json.loads(private_path(args.credentials_file).read_text())
    ca = owned(args, "configmap", "fixture-service-ca")["data"]["service-ca.crt"]
    context = ssl.create_default_context(cadata=ca)
    credential = base64.b64encode(
        ("admin:" + credentials["jira_admin"]).encode()
    ).decode()
    directory = private_path(args.output_dir, directory=True)
    log_path = Path(directory) / "jira-ui-tunnel.private.log"
    with log_path.open("xb") as log:
        log_path.chmod(0o600)
        tunnel = subprocess.Popen(
            [
                "oc",
                "--kubeconfig",
                args.kubeconfig,
                "-n",
                NS,
                "port-forward",
                "--address=127.0.0.1",
                "service/fixture-jira",
                "18089:8080",
            ],
            stdout=log,
            stderr=log,
        )
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if tunnel.poll() is not None:
                    raise RuntimeError("Owned UI tunnel failed")
                try:
                    with socket.create_connection(("127.0.0.1", 18089), timeout=0.5):
                        break
                except OSError:
                    time.sleep(0.2)
            else:
                raise TimeoutError("Owned UI tunnel not ready")
            with PreviewHTTPServer(
                ("127.0.0.1", 18088), handler(keys, context, credential)
            ) as server:
                server.timeout = 1
                print(
                    json.dumps(
                        {
                            "stage": "jira_ui_preview_ready",
                            "url": "http://127.0.0.1:18088/issue/" + sorted(keys)[0],
                            "read_only": True,
                            "cluster_https_verified": True,
                            "operator_presentation_only": True,
                        }
                    ),
                    flush=True,
                )
                end = time.monotonic() + args.duration
                while time.monotonic() < end and tunnel.poll() is None:
                    server.handle_request()
        finally:
            tunnel.terminate()
            try:
                tunnel.wait(timeout=5)
            except subprocess.TimeoutExpired:
                tunnel.kill()
                tunnel.wait(timeout=5)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("kubeconfig", "expected-server", "credentials-file", "output-dir"):
        p.add_argument("--" + name, required=True)
    p.add_argument("--issue-key", action="append", required=True)
    p.add_argument("--duration", type=int, default=900)
    try:
        run(p.parse_args())
    except Exception as error:
        print(
            json.dumps(
                {
                    "passed": False,
                    "failure_kind": type(error).__name__,
                    "details_withheld": True,
                }
            )
        )
        raise SystemExit(1) from None
