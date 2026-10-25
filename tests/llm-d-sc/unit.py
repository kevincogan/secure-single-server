#!/usr/bin/env python3
"""Offline contract checks for the llm-d-sc routing profile."""

import importlib.util
import http.client
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / "configs/llm-d-sc/praxis.yaml"
IMAGES_PATH = ROOT / "configs/llm-d-sc/images.env"
INTEGRATION_PATH = ROOT / "tests/llm-d-sc/integration.py"
TRACE_UI_PATH = ROOT / "apps/llm-d-sc/trace-ui/server.py"


class LlmDScConfig(unittest.TestCase):
    def setUp(self):
        self.config = yaml.safe_load(CONFIG_PATH.read_text())

    def step(self, name):
        router = next(
            item for item in self.config["filter_chains"][0]["filters"]
            if item["filter"] == "iterative_request_router"
        )
        return next(step for step in router["steps"] if step["name"] == name)

    def test_filter_chain_has_one_cluster_selector(self):
        filters = self.config["filter_chains"][0]["filters"]
        kinds = [item["filter"] for item in filters]
        self.assertEqual(
            kinds,
            ["request_id", "access_log", "static_response", "iterative_request_router"],
        )
        self.assertNotIn("router", kinds)

    def test_labels_map_to_expected_backends(self):
        filters = self.step("classify-and-route")["filters"]
        classifier = next(item for item in filters if item["filter"] == "llm_d_sc")
        routes = {item["label"]: item["cluster"] for item in classifier["routes"]}
        self.assertEqual(
            routes,
            {
                "SIMPLE": "vllm-cpu",
                "MEDIUM": "vllm-cpu",
                "COMPLEX": "vllm-gpu",
                "REASONING": "vllm-gpu",
            },
        )
        self.assertEqual(classifier["default_cluster"], "vllm-cpu")
        self.assertEqual(classifier["on_unavailable"], "default_cluster")
        self.assertEqual(classifier["status_on_reject"], 503)

    def test_endpoints_stay_on_the_private_container_network(self):
        filters = self.step("classify-and-route")["filters"]
        classifier = next(item for item in filters if item["filter"] == "llm_d_sc")
        load_balancer = next(item for item in filters if item["filter"] == "load_balancer")
        self.assertEqual(classifier["endpoint"], "llm-d-sc:50051")
        self.assertEqual(
            {item["name"]: item["endpoints"] for item in load_balancer["clusters"]},
            {
                "vllm-cpu": ["trace-ui:8081"],
                "vllm-gpu": ["trace-ui:8082"],
            },
        )

    def test_failed_requests_fail_over_to_a_health_checked_pool(self):
        on_result = self.step("classify-and-route")["on_result"]
        self.assertIn({"origin": "transport", "next": "failover"}, on_result)
        self.assertIn(
            {"status": [429, 500, 502, 503, 504], "next": "failover"}, on_result,
        )
        failover = self.step("failover")
        router = next(item for item in failover["filters"] if item["filter"] == "router")
        self.assertEqual(
            {
                next(iter(route.get("headers", {}).values())): route["cluster"]
                for route in router["routes"] if route.get("headers")
            },
            {
                "SIMPLE": "vllm-gpu",
                "MEDIUM": "vllm-gpu",
                "COMPLEX": "vllm-cpu",
                "REASONING": "vllm-cpu",
            },
        )
        self.assertEqual(router["routes"][-1], {"path_prefix": "/", "cluster": "vllm-gpu"})
        balancer = next(item for item in failover["filters"] if item["filter"] == "load_balancer")
        self.assertEqual(
            {item["name"]: item["endpoints"] for item in balancer["clusters"]},
            {
                "vllm-cpu": ["trace-ui:8081"],
                "vllm-gpu": ["trace-ui:8082"],
            },
        )
        clusters = {item["name"]: item for item in self.config["clusters"]}
        self.assertEqual(
            {name: item["endpoints"] for name, item in clusters.items()},
            {
                "vllm-cpu": ["trace-ui:8081"],
                "vllm-gpu": ["trace-ui:8082"],
            },
        )
        self.assertTrue(all("health_check" in item for item in clusters.values()))

    def test_admin_listener_stays_private(self):
        self.assertEqual(self.config["admin"]["address"], "127.0.0.1:9901")
        self.assertEqual(self.config["listeners"][0]["address"], "0.0.0.0:8080")

    def test_optional_ui_images_are_digest_pinned(self):
        images = {}
        for line in IMAGES_PATH.read_text().splitlines():
            if line and not line.startswith("#"):
                key, value = line.split("=", 1)
                images[key] = value
        self.assertIn("sha256:", images["LLM_D_SC_OPENWEBUI_IMAGE"])
        self.assertIn("sha256:", images["LLM_D_SC_TRACE_IMAGE"])
        self.assertNotIn(":latest", " ".join(images.values()))

    def test_opencode_policy_allows_provider_package_and_model_catalog(self):
        policy_path = ROOT / "configs/llm-d-sc/profiles/dev/policy.yaml"
        policy_source = policy_path.read_text().replace("@@PRAXIS_PORT@@", "8080")
        policy_source = policy_source.replace("@@PRAXIS_API_PREFIX@@", "")
        policy = yaml.safe_load(policy_source)
        networks = policy["network_policies"]
        npm_binaries = {item["path"] for item in networks["npm_registry"]["binaries"]}
        self.assertIn("/usr/local/bin/opencode", npm_binaries)
        catalog = networks["models_catalog"]
        self.assertEqual(catalog["endpoints"][0]["host"], "models.opencode.ai")
        self.assertEqual(catalog["endpoints"][0]["protocol"], "rest")
        self.assertEqual(catalog["endpoints"][0]["enforcement"], "enforce")
        self.assertEqual(catalog["endpoints"][0]["access"], "read-only")
        provider = json.loads(
            (ROOT / "configs/llm-d-sc/harness-provider.json.in").read_text()
        )
        self.assertEqual(provider["provider"]["praxis"]["npm"], "@ai-sdk/openai-compatible")

    def test_mock_backend_health_and_failure_fixture_are_available(self):
        spec = importlib.util.spec_from_file_location("llm_d_sc_integration", INTEGRATION_PATH)
        integration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(integration)
        self.assertIn('if self.path == "/health":', integration.BACKEND_SOURCE)
        self.assertIn('self.headers.get("X-Test-Fail-Backend")', integration.BACKEND_SOURCE)

    def test_remote_gpu_mode_requires_real_mode(self):
        spec = importlib.util.spec_from_file_location("llm_d_sc_integration", INTEGRATION_PATH)
        integration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(integration)
        with self.assertRaisesRegex(ValueError, "--remote-gpu requires --real"):
            integration.main(remote_gpu="gpu.example.invalid")

    def test_gpu_only_mode_has_explicit_contracts(self):
        spec = importlib.util.spec_from_file_location("llm_d_sc_integration", INTEGRATION_PATH)
        integration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(integration)
        integration.ENGINE = "podman"
        with self.assertRaisesRegex(ValueError, "--gpu-only requires --real"):
            integration.main(gpu_only=True)
        with self.assertRaisesRegex(ValueError, "--gpu-only cannot use --remote-gpu"):
            integration.main(real=True, gpu_only=True, remote_gpu="gpu.example.invalid")

    def test_webui_request_forwards_timeout(self):
        spec = importlib.util.spec_from_file_location("llm_d_sc_integration", INTEGRATION_PATH)
        integration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(integration)
        with mock.patch.object(
            integration,
            "json_request",
            return_value={"choices": [{"message": {"content": "ok"}}]},
        ) as json_request:
            content = integration.webui_request(
                8080, "token", "prompt", max_tokens=128, timeout=600,
                chat_template_kwargs={"enable_thinking": False},
            )
        self.assertEqual(content, "ok")
        self.assertEqual(json_request.call_args.kwargs["timeout"], 600)
        self.assertEqual(
            json_request.call_args.args[1]["chat_template_kwargs"],
            {"enable_thinking": False},
        )

    def test_mock_backend_supports_openai_streaming(self):
        spec = importlib.util.spec_from_file_location("llm_d_sc_integration", INTEGRATION_PATH)
        integration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(integration)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        source = integration.BACKEND_SOURCE.replace(
            'ThreadingHTTPServer(("0.0.0.0", 8000), Handler)',
            f'ThreadingHTTPServer(("127.0.0.1", {port}), Handler)',
        )
        namespace = {"__name__": "llm_d_sc_mock_backend"}
        with mock.patch.dict(os.environ, {"BACKEND_NAME": "vllm-cpu"}):
            thread = threading.Thread(target=exec, args=(source, namespace), daemon=True)
            thread.start()
            for _ in range(50):
                if "server" in namespace:
                    break
                time.sleep(0.01)
            self.addCleanup(lambda: (namespace["server"].shutdown(),
                                     namespace["server"].server_close(),
                                     thread.join(timeout=2)))
            for path in ("/health", "/v1/models"):
                with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}",
                                            timeout=5) as response:
                    self.assertEqual(response.status, 200)
            request = urllib.request.Request(
                f"http://127.0.0.1:{port}/v1/chat/completions",
                data=json.dumps({
                    "model": "Semantic-Qwen",
                    "messages": [{"role": "user", "content": "hello"}],
                    "stream": True,
                }).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(response.headers["Content-Type"], "text/event-stream")
                body = response.read().decode()
        events = [
            json.loads(line.removeprefix("data: "))
            for line in body.splitlines()
            if line.startswith("data: ") and line != "data: [DONE]"
        ]
        self.assertEqual(events[0]["object"], "chat.completion.chunk")
        self.assertEqual(events[0]["choices"][0]["delta"]["role"], "assistant")
        self.assertIn("vllm-cpu", events[0]["choices"][0]["delta"]["content"])
        self.assertEqual(events[-1]["choices"][0]["finish_reason"], "stop")
        self.assertTrue(body.endswith("data: [DONE]\n\n"))

    def test_relay_streams_sse_before_upstream_completes(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        spec = importlib.util.spec_from_file_location("llm_d_sc_trace_ui", TRACE_UI_PATH)
        trace_ui = importlib.util.module_from_spec(spec)
        with mock.patch.dict(os.environ, {"TRACE_DB_PATH": f"{directory.name}/traces.db"}):
            spec.loader.exec_module(trace_ui)

        release_stream = threading.Event()
        first_event = b'data: {"choices":[{"delta":{"content":"hello"}}]}\n\n'

        class Upstream(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                self.wfile.write(first_event)
                self.wfile.flush()
                release_stream.wait(timeout=5)
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()

            def log_message(self, fmt, *args):
                return

        upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        relay = trace_ui.RelayServer(
            ("127.0.0.1", 0), f"http://127.0.0.1:{upstream.server_port}")
        for server in (upstream, relay):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(lambda server=server, thread=thread: (
                server.shutdown(), server.server_close(), thread.join(timeout=2)))
        self.addCleanup(release_stream.set)

        body = json.dumps({
            "model": "fixture",
            "messages": [{"role": "user", "content": "hello"}],
            "stream": True,
        }).encode()
        client = http.client.HTTPConnection("127.0.0.1", relay.server_port, timeout=5)
        self.addCleanup(client.close)
        client.request(
            "POST", "/v1/chat/completions", body,
            {"Content-Type": "application/json"},
        )
        response = client.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.headers.get("Content-Type"), "text/event-stream")
        self.assertEqual(response.read(len(first_event)), first_event)
        self.assertFalse(release_stream.is_set(), "relay must forward before upstream completes")
        release_stream.set()
        self.assertEqual(response.read(), b"data: [DONE]\n\n")

    def test_backend_relay_preserves_classifier_score(self):
        spec = importlib.util.spec_from_file_location("llm_d_sc_trace_ui", TRACE_UI_PATH)
        trace_ui = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(trace_ui)

        class Upstream(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, fmt, *args):
                return

        upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        relay = trace_ui.RelayServer(
            ("127.0.0.1", 0),
            f"http://127.0.0.1:{upstream.server_port}",
            "vllm-cpu",
        )
        for server in (upstream, relay):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(lambda server=server, thread=thread: (
                server.shutdown(), server.server_close(), thread.join(timeout=2)))
        request = urllib.request.Request(
            f"http://127.0.0.1:{relay.server_port}/v1/models",
            headers={
                "X-Llm-D-Sc-Label": "SIMPLE",
                "X-Llm-D-Sc-Score": "0.9989",
            },
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.headers["X-Demo-Route"], "vllm-cpu")
            self.assertEqual(response.headers["X-Demo-Classification"], "SIMPLE")
            self.assertEqual(response.headers["X-Llm-D-Sc-Score"], "0.9989")

    def test_failover_keeps_the_classifier_score(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        spec = importlib.util.spec_from_file_location("llm_d_sc_trace_ui", TRACE_UI_PATH)
        trace_ui = importlib.util.module_from_spec(spec)
        with mock.patch.dict(os.environ, {"TRACE_DB_PATH": f"{directory.name}/traces.db"}):
            spec.loader.exec_module(trace_ui)

        class Upstream(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, fmt, *args):
                return

        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            stopped_port = probe.getsockname()[1]
        upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        cpu = trace_ui.RelayServer(
            ("127.0.0.1", 0), f"http://127.0.0.1:{stopped_port}", "vllm-cpu")
        gpu = trace_ui.RelayServer(
            ("127.0.0.1", 0), f"http://127.0.0.1:{upstream.server_port}", "vllm-gpu")
        for server in (upstream, cpu, gpu):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(lambda server=server, thread=thread: (
                server.shutdown(), server.server_close(), thread.join(timeout=2)))

        def post(relay, headers):
            request = urllib.request.Request(
                f"http://127.0.0.1:{relay.server_port}/v1/chat/completions?_trace=t1",
                data=b"{}", headers=headers, method="POST",
            )
            return urllib.request.urlopen(request, timeout=5)

        trace_ui.create_trace("t1", "POST", "/v1/chat/completions", None)
        with self.assertRaises(urllib.error.HTTPError) as stopped:
            post(cpu, {"X-Llm-D-Sc-Label": "SIMPLE", "X-Llm-D-Sc-Score": "0.9876"})
        stopped.exception.close()
        with post(gpu, {}) as response:
            self.assertNotIn("X-Llm-D-Sc-Score", response.headers)
            trace_ui.complete_trace("t1", response.status, dict(response.headers.items()), 1)
        trace = trace_ui.traces()[0]
        self.assertEqual(trace["route"], "vllm-gpu")
        self.assertEqual(trace["label"], "SIMPLE")
        self.assertEqual(trace["score"], "0.9876")

    def test_relay_rejects_non_origin_form_request_targets(self):
        spec = importlib.util.spec_from_file_location("llm_d_sc_trace_ui", TRACE_UI_PATH)
        trace_ui = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(trace_ui)
        hits = []

        class Upstream(BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                self.send_response(200)
                self.end_headers()

            def log_message(self, fmt, *args):
                return

        upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        relay = trace_ui.RelayServer(
            ("127.0.0.1", 0),
            f"http://127.0.0.1:{upstream.server_port}",
            "vllm-cpu",
        )
        for server in (upstream, relay):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(lambda server=server, thread=thread: (
                server.shutdown(), server.server_close(), thread.join(timeout=2)))
        for target in ("@attacker.example/x", "http://attacker.example/x"):
            with self.subTest(target=target):
                client = http.client.HTTPConnection(
                    "127.0.0.1", relay.server_port, timeout=5,
                )
                self.addCleanup(client.close)
                client.putrequest("GET", target, skip_host=True)
                client.endheaders()
                response = client.getresponse()
                self.assertEqual(response.status, 400)
                self.assertEqual(json.loads(response.read()),
                                 {"error": "invalid request target"})
        self.assertEqual(hits, [])

    def test_relay_rejects_invalid_and_oversized_content_lengths(self):
        spec = importlib.util.spec_from_file_location("llm_d_sc_trace_ui", TRACE_UI_PATH)
        trace_ui = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(trace_ui)
        relay = trace_ui.RelayServer(("127.0.0.1", 0), "http://127.0.0.1:9")
        thread = threading.Thread(target=relay.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (relay.shutdown(), relay.server_close(), thread.join(timeout=2)))

        invalid_values = (
            "nope", "-1", str(trace_ui.MAX_REQUEST_BODY_BYTES + 1), "9" * 5000,
        )
        expected = (400, 400, 413, 413)
        for value, status in zip(invalid_values, expected):
            with self.subTest(content_length=value):
                client = http.client.HTTPConnection("127.0.0.1", relay.server_port, timeout=5)
                self.addCleanup(client.close)
                client.putrequest("POST", "/v1/chat/completions")
                client.putheader("Content-Length", value)
                client.endheaders()
                response = client.getresponse()
                self.assertEqual(response.status, status)

    def test_incomplete_upstream_bodies_return_502_and_complete_the_trace(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        spec = importlib.util.spec_from_file_location("llm_d_sc_trace_ui", TRACE_UI_PATH)
        trace_ui = importlib.util.module_from_spec(spec)
        with mock.patch.dict(os.environ, {"TRACE_DB_PATH": f"{directory.name}/traces.db"}):
            spec.loader.exec_module(trace_ui)

        class Upstream(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(503 if self.path == "/incomplete-error" else 200)
                self.send_header("Content-Length", "20")
                self.end_headers()
                self.wfile.write(b"partial")
                self.wfile.flush()
                self.close_connection = True

            def log_message(self, fmt, *args):
                return

        upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        relay = trace_ui.RelayServer(
            ("127.0.0.1", 0), f"http://127.0.0.1:{upstream.server_port}"
        )
        for server in (upstream, relay):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(lambda server=server, thread=thread: (
                server.shutdown(), server.server_close(), thread.join(timeout=2)))

        for path in ("/incomplete-success", "/incomplete-error"):
            with self.subTest(path=path):
                with self.assertRaises(urllib.error.HTTPError) as failed:
                    urllib.request.urlopen(
                        f"http://127.0.0.1:{relay.server_port}{path}", timeout=5
                    )
                self.assertEqual(failed.exception.code, 502)
                error_response = failed.exception
                try:
                    self.assertEqual(
                        json.loads(error_response.read()),
                        {"error": "upstream response ended early"},
                    )
                finally:
                    error_response.close()
                trace = next(item for item in trace_ui.traces() if item["path"] == path)
                self.assertEqual(trace["status"], 502)
                self.assertIsNotNone(trace["completed_at"])
                self.assertIn("ended early", trace["error"])

    def test_client_disconnect_does_not_overwrite_a_completed_trace(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        spec = importlib.util.spec_from_file_location("llm_d_sc_trace_ui", TRACE_UI_PATH)
        trace_ui = importlib.util.module_from_spec(spec)
        with mock.patch.dict(os.environ, {"TRACE_DB_PATH": f"{directory.name}/traces.db"}):
            spec.loader.exec_module(trace_ui)

        upstream_ready = threading.Event()
        release_response = threading.Event()
        response_body = json.dumps({
            "choices": [{"message": {"content": "upstream answer"}}],
        }).encode()

        class Upstream(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                self.rfile.read(length)
                upstream_ready.set()
                release_response.wait(timeout=5)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response_body)))
                self.end_headers()
                self.wfile.write(response_body)

            def log_message(self, fmt, *args):
                return

        upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        relay = trace_ui.RelayServer(
            ("127.0.0.1", 0), f"http://127.0.0.1:{upstream.server_port}"
        )
        for server in (upstream, relay):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(lambda server=server, thread=thread: (
                server.shutdown(), server.server_close(), thread.join(timeout=2)))
        self.addCleanup(release_response.set)

        client = http.client.HTTPConnection("127.0.0.1", relay.server_port, timeout=5)
        self.addCleanup(client.close)
        request_body = json.dumps({
            "model": "fixture",
            "messages": [{"role": "user", "content": "hello"}],
        }).encode()
        client.request(
            "POST", "/v1/chat/completions", request_body,
            {"Content-Type": "application/json"},
        )
        self.assertTrue(upstream_ready.wait(timeout=5))
        client.sock.setsockopt(
            socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
        )
        client.close()
        release_response.set()

        for _ in range(50):
            records = trace_ui.traces()
            if records and records[0]["completed_at"]:
                break
            time.sleep(0.02)
        self.assertTrue(records, "request trace was not created")
        self.assertEqual(records[0]["status"], 200)
        self.assertEqual(records[0]["response"], "upstream answer")
        self.assertIsNone(records[0]["error"])


if __name__ == "__main__":
    if not __debug__ or sys.flags.optimize:
        raise SystemExit("Run tests without Python -O or PYTHONOPTIMIZE")
    unittest.main()
