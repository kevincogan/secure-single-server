#!/usr/bin/env python3
"""Contracts for the Streamlit before/after OpenShell demo."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys
import unittest
import urllib.request
from unittest.mock import patch

import yaml


ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "openshell/demos/streamlit-security"


class StreamlitSecurityTests(unittest.TestCase):
    def call_model(self, ticket, *, opener=None, **arguments):
        sys.path.insert(0, str(DEMO))
        try:
            from model_client import call_model

            arguments.setdefault("request_format", "openai")
            if opener is None:
                return call_model(ticket, **arguments)
            with patch("urllib.request.build_opener", return_value=opener):
                return call_model(ticket, **arguments)
        finally:
            sys.path.remove(str(DEMO))

    def test_policy_confines_the_application_directory(self):
        policy = yaml.safe_load((DEMO / "policy.yaml").read_text())
        self.assertEqual(
            policy,
            {
                "version": 1,
                "filesystem_policy": {
                    "include_workdir": False,
                    "read_only": [
                        "/usr",
                        "/lib",
                        "/lib64",
                        "/etc",
                        "/proc",
                        "/dev/urandom",
                        "/opt/openshell-demo",
                    ],
                    "read_write": ["/tmp", "/dev/null"],
                },
                "landlock": {"compatibility": "hard_requirement"},
                "process": {"run_as_user": "1500", "run_as_group": "1500"},
                "network_policies": {},
            },
        )

    def test_model_request_sends_credential_and_model_selection(self):
        """Verify the model request carries the selected model and credential."""
        requests = []

        class FakeResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_value, traceback):
                return False

            def read(self):
                return json.dumps(
                    {"choices": [{"message": {"content": "Safe summary"}}]}
                ).encode()

        class FakeOpener:
            def open(self, request, timeout):
                del timeout
                requests.append(request)
                return FakeResponse()

        response = self.call_model(
            "Checkout is slow",
            base_url="http://host.openshell.internal:18080/v1",
            api_key="opaque-placeholder",
            model="gpt-5.5",
            opener=FakeOpener(),
        )

        self.assertEqual(response, "Safe summary")
        request = requests[0]
        self.assertEqual(request.headers["Authorization"], "Bearer opaque-placeholder")
        body = json.loads(request.data)
        self.assertEqual(body["model"], "gpt-5.5")
        self.assertEqual(body["max_completion_tokens"], 1000)
        self.assertNotIn("max_tokens", body)
        self.assertEqual(body["temperature"], 0.1)

    def test_compatible_request_keeps_legacy_parameters_and_temperature(self):
        """Keep compatibility servers on their supported request fields."""
        requests = []

        class FakeResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_value, traceback):
                return False

            def read(self):
                return json.dumps(
                    {"choices": [{"message": {"content": "Compatible summary"}}]}
                ).encode()

        class FakeOpener:
            def open(self, request, timeout):
                del timeout
                requests.append(request)
                return FakeResponse()

        response = self.call_model(
            "Checkout is slow",
            base_url="https://inference.internal/v1",
            api_key="opaque-placeholder",
            model="local-model",
            request_format="openai-compatible",
            opener=FakeOpener(),
        )

        self.assertEqual(response, "Compatible summary")
        body = json.loads(requests[0].data)
        self.assertEqual(body["max_tokens"], 300)
        self.assertEqual(body["temperature"], 0.1)
        self.assertNotIn("max_completion_tokens", body)

    def test_provider_selects_the_matching_request_format(self):
        """Bind each documented provider alias to its endpoint dialect."""
        sys.path.insert(0, str(DEMO))
        try:
            from model_client import request_format_for_provider

            self.assertEqual(
                request_format_for_provider("streamlit-demo-openai"), "openai"
            )
            self.assertEqual(
                request_format_for_provider("streamlit-demo-compatible"),
                "openai-compatible",
            )
            with self.assertRaisesRegex(ValueError, "not a supported"):
                request_format_for_provider("unknown-provider")
        finally:
            sys.path.remove(str(DEMO))

    def test_model_client_rejects_credential_bearing_endpoint_urls(self):
        for url in (
            "https://user:pass@example.com/v1",
            "https://api.openai.com/v1?key=placeholder",
            "https://api.openai.com/v1#fragment",
            "file:///tmp/model",
            "http://example.com/v1",
            "http://host.openshell.internal:8080/v1",
        ):
            with self.subTest(url=url), self.assertRaisesRegex(
                ValueError, "MODEL_BASE_URL"
            ):
                self.call_model(
                    "Checkout is slow",
                    base_url=url,
                    api_key="opaque-placeholder",
                    model="gpt-5.5",
                )

    def test_model_client_does_not_follow_redirects(self):
        sys.path.insert(0, str(DEMO))
        try:
            from model_client import RejectRedirects

            self.assertIsNone(
                RejectRedirects().redirect_request(
                    None, None, 302, "Found", {}, "https://other.example/v1"
                )
            )
        finally:
            sys.path.remove(str(DEMO))

    def test_model_client_reports_http_and_invalid_responses(self):
        class FakeResponse:
            def __init__(self, status, body):
                self.status = status
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_value, traceback):
                return False

            def read(self):
                return self.body

        class FakeOpener:
            def __init__(self, response):
                self.response = response

            def open(self, request, timeout):
                del request, timeout
                return self.response

        cases = (
            (500, b"{}", "status 500"),
            (200, b"not-json", "not valid JSON"),
            (200, b"{}", "no assistant content"),
            (200, b'{"choices": []}', "no assistant content"),
            (200, b'{"choices": null}', "no assistant content"),
            (200, b'{"choices": [null]}', "no assistant content"),
            (200, b'{"choices": [{"message": null}]}', "no assistant content"),
            (200, b'{"choices": [{"message": {"content": 3}}]}', "no assistant content"),
            (
                200,
                b'{"choices": [{"message": {"content": " "}}]}',
                "no assistant content",
            ),
        )
        for status, body, error in cases:
            with self.subTest(status=status, body=body), self.assertRaisesRegex(
                ValueError, error
            ):
                self.call_model(
                    "Checkout is slow",
                    base_url="https://api.openai.com/v1",
                    api_key="opaque-placeholder",
                    model="gpt-5.5",
                    opener=FakeOpener(FakeResponse(status, body)),
                )

    def test_model_chat_preserves_ticket_and_conversation(self):
        requests = []

        class FakeResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_value, traceback):
                return False

            def read(self):
                return json.dumps(
                    {"choices": [{"message": {"content": "Follow-up answer"}}]}
                ).encode()

        class FakeOpener:
            def open(self, request, timeout):
                del timeout
                requests.append(request)
                return FakeResponse()

        response = self.call_model(
            "Checkout is slow",
            base_url="https://api.openai.com/v1",
            api_key="opaque-placeholder",
            model="gpt-5.5",
            messages=[
                {"role": "user", "content": "Which service should we check first?"},
                {"role": "assistant", "content": "Start with the checkout service."},
                {"role": "user", "content": "What log should we review?"},
            ],
            opener=FakeOpener(),
        )

        self.assertEqual(response, "Follow-up answer")
        body = json.loads(requests[0].data)
        self.assertEqual(
            [message["role"] for message in body["messages"]],
            ["system", "user", "user", "assistant", "user"],
        )
        self.assertEqual(body["messages"][1]["content"], "Checkout is slow")
        self.assertEqual(
            body["messages"][-1]["content"], "What log should we review?"
        )

    def test_provider_profiles_bind_credentials_to_native_endpoints(self):
        """Keep provider profiles aligned with their endpoint policies."""
        openai = yaml.safe_load((DEMO / "providers/openai.yaml").read_text())
        compatible = yaml.safe_load(
            (DEMO / "providers/openai-compatible.yaml").read_text()
        )
        for profile in (openai, compatible):
            self.assertEqual(profile["credentials"][0]["env_vars"], ["OPENAI_API_KEY"])
            self.assertEqual(profile["binaries"], ["/usr/local/bin/python3.12"])
            endpoint = profile["endpoints"][0]
            self.assertEqual(endpoint["protocol"], "rest")
            self.assertEqual(endpoint["enforcement"], "enforce")
            self.assertEqual(endpoint["path"], "/v1/chat/completions")
            self.assertEqual(
                endpoint["rules"],
                [{"allow": {"method": "POST", "path": "/v1/chat/completions"}}],
            )
        self.assertEqual(openai["endpoints"][0]["host"], "api.openai.com")
        self.assertEqual(openai["endpoints"][0]["port"], 443)

    def test_documentation_puts_model_requirements_first(self):
        guide = (ROOT / "docs/examples/streamlit-security/README.md").read_text()
        self.assertLess(guide.index("Before you start"), guide.index("Run the unsafe version"))
        self.assertIn("OpenAI-compatible endpoint", guide)
        self.assertIn("openshell profile import", guide)
        self.assertIn("--credential OPENAI_API_KEY", guide)
        self.assertIn("POST /v1/chat/completions", guide)
        self.assertIn("max_completion_tokens", guide)
        self.assertIn("max_tokens", guide)
        self.assertIn("temperature=0.1", guide)

    def test_documentation_explains_where_to_run_the_demo(self):
        """Require setup guidance to identify the host and execution location."""
        guide = (ROOT / "docs/examples/streamlit-security/README.md").read_text()
        normalized = " ".join(guide.split())
        self.assertIn("dedicated RHEL 9.8+ x86_64 Linux host", normalized)
        self.assertIn("/opt/secure-single-server", normalized)
        self.assertIn("Landlock ABI 3", normalized)
        self.assertIn("not a supported OpenShell host", normalized)
        self.assertIn("manual.md#4-choose-model-access", normalized)
        self.assertIn(
            "model-access.md#local-openai-compatible-service",
            normalized,
        )
        self.assertIn("--name streamlit-demo-openai", normalized)
        self.assertIn("--type streamlit-openai-compatible", normalized)

    def test_documentation_links_manual_setup_before_demo_commands(self):
        guide = (ROOT / "docs/examples/streamlit-security/README.md").read_text()
        setup_link = "../../../openshell/docs/README.md#manual-gateway-setup-on-rhel"
        self.assertIn(setup_link, guide)
        setup_page = setup_link.split("#", 1)[0]
        self.assertTrue(
            (ROOT / "docs/examples/streamlit-security" / setup_page).is_file()
        )
        self.assertLess(guide.index(setup_link), guide.index("## Run the unsafe version"))
        normalized = " ".join(guide.split())
        self.assertIn("/opt/secure-single-server", normalized)
        self.assertIn("Landlock ABI 3 or newer", normalized)
        self.assertIn("define the `repo` and `os_run` shell helper", normalized)
        self.assertIn("same Bash session", normalized)
        self.assertIn("does not need a harness or Praxis", normalized)
        self.assertIn("os_run openshell profile import", normalized)
        self.assertIn('bash "$repo/openshell/demos/streamlit-security/run-safe.sh"', guide)
        self.assertIn("rootless Podman context", guide)

    def test_root_readme_introduces_the_example_catalog(self):
        readme = (ROOT / "README.md").read_text()
        self.assertIn("docs/examples/README.md", readme)
        self.assertIn("docs/examples/streamlit-security/README.md", readme)
        self.assertLess(
            readme.index("docs/examples/streamlit-security/README.md"),
            readme.index("docs/examples/opencode-pr-queue/README.md"),
        )
        self.assertIn("/usr/share/secure-single-server", readme)
        self.assertIn("/opt/secure-single-server", readme)

    def test_demo_entry_points_are_executable(self):
        for name in ("run-unsafe.sh", "run-safe.sh", "verify.sh"):
            path = DEMO / name
            self.assertTrue(path.is_file())
            self.assertTrue(os.access(path, os.X_OK), name)

    def test_unsafe_runner_only_binds_to_loopback(self):
        script = (DEMO / "run-unsafe.sh").read_text()
        self.assertIn("-p 127.0.0.1:8501:8501", script)
        self.assertNotIn("-p 8501:8501", script)

    def test_safe_runner_exposes_service_after_creation(self):
        script = (DEMO / "run-safe.sh").read_text()
        self.assertIn("openshell service expose", script)
        self.assertNotIn("--forward 8501", script)
        self.assertIn('openshell sandbox list --names)', script)
        self.assertIn("MODEL_BASE_URL must be an HTTP(S) URL", script)
        self.assertIn('url.scheme == "http" and (', script)
        self.assertIn("port != 18080", script)
        self.assertIn('"host.openshell.internal"', script)
        self.assertIn('"host.containers.internal"', script)
        self.assertIn('document.get("next_page_token")', script)

    def test_safe_runner_launches_authorized_interpreter(self):
        """Require the runner to use the Python binary allowed by its profile."""
        script = (DEMO / "run-safe.sh").read_text()
        self.assertIn("/usr/local/bin/python3.12 -m streamlit", script)
        self.assertNotIn("/usr/local/bin/python3 -m streamlit", script)
        self.assertIn('--env STREAMLIT_DEMO_PROVIDER="${PROVIDER}"', script)

    def test_ordinary_demo_uses_the_same_authorized_interpreter_and_provider(self):
        dockerfile = (DEMO / "Dockerfile").read_text()
        self.assertIn('CMD ["/usr/local/bin/python3.12"', dockerfile)
        unsafe_runner = (DEMO / "run-unsafe.sh").read_text()
        self.assertIn("${STREAMLIT_DEMO_PROVIDER:?", unsafe_runner)
        self.assertIn("--env STREAMLIT_DEMO_PROVIDER", unsafe_runner)

    def test_safe_runner_allows_gateway_websocket_origin(self):
        script = (DEMO / "run-safe.sh").read_text()
        self.assertIn(
            "--server.corsAllowedOrigins "
            '"http://default--${SANDBOX}--streamlit.openshell.localhost:8090"',
            script,
        )

    def test_verifier_has_positive_write_control(self):
        script = (DEMO / "verify.sh").read_text()
        self.assertIn("/tmp/openshell-verify-", script)
        self.assertIn('bash -lc "${command}" openshell-demo "$@"', script)
        self.assertIn("cleanup_verification_files()", script)
        self.assertIn("test -f /opt/openshell-demo/app.py", script)
        self.assertIn("/opt/openshell-demo-secret", script)

    def test_verifier_requires_permission_denied_evidence(self):
        script = (DEMO / "verify.sh").read_text()
        self.assertIn("openshell sandbox list --names", script)
        self.assertIn("LC_ALL=C", script)
        self.assertIn("Permission denied", script)
        self.assertIn("EACCES", script)

    def test_docker_image_runs_streamlit_as_non_root(self):
        dockerfile = (DEMO / "Dockerfile").read_text()
        self.assertIn("USER 1500:1500", dockerfile)
        self.assertLess(dockerfile.index("COPY --chown"), dockerfile.index("USER"))
        requirements = (DEMO / "requirements.txt").read_text()
        self.assertIn("streamlit==1.66.0", requirements)

    def test_demo_uses_synthetic_file_read_target(self):
        app = (DEMO / "app.py").read_text()
        dockerfile = (DEMO / "Dockerfile").read_text()
        policy = (DEMO / "policy.yaml").read_text()
        guide = (ROOT / "docs/examples/streamlit-security/README.md").read_text()
        self.assertIn("/opt/openshell-demo-secret", app)
        self.assertIn("demo-file-read-marker-not-a-real-secret", dockerfile)
        self.assertIn("Run file-read diagnostic", app)
        self.assertNotIn("/opt/openshell-demo-secret", policy)
        self.assertIn("synthetic marker", guide)
        self.assertIn("Keep the read target synthetic", guide)
        self.assertNotIn("/etc/passwd", guide)

    def test_page_explains_model_input_and_local_diagnostics(self):
        app = (DEMO / "app.py").read_text()
        self.assertIn("The model does not run", app)
        self.assertIn("fixed commands in the application process", app)
        self.assertIn("prompt-injected ticket", app)
        self.assertIn("application tampering", app)
        self.assertIn("data exposure", app)

    def test_diagnostics_require_permission_denied_evidence(self):
        app = (DEMO / "app.py").read_text()
        self.assertIn('"Permission denied" in result.stderr', app)
        self.assertIn('"EACCES" in result.stderr', app)
        self.assertIn("Diagnostic failed without permission-denied evidence", app)
        self.assertIn('st.session_state.diagnostic = "failed"', app)
        self.assertIn('st.session_state.file_diagnostic = "failed"', app)

    def test_page_has_model_only_follow_up_chat_in_both_modes(self):
        app = (DEMO / "app.py").read_text()
        self.assertIn("Ask follow-up questions", app)
        self.assertIn('st.chat_input("Ask the model about this ticket")', app)
        self.assertIn("same model-only path in both versions", app)
        self.assertIn("commands or expand filesystem access", app)
        self.assertIn('if DEMO_MODE == "unsafe"', app)
        self.assertIn('st.chat_message(message["role"])', app)

    def test_page_has_concise_before_after_summary(self):
        app = (DEMO / "app.py").read_text()
        self.assertIn("only the blast radius changes", app)
        self.assertIn("| | Ordinary container | OpenShell sandbox |", app)
        self.assertIn("Opaque placeholder; OpenShell substitutes the key", app)
        self.assertIn("Model access works while filesystem access is contained", app)
        self.assertNotIn("The same app, first with a real key", app)

    def test_page_hides_streamlit_deploy_button(self):
        app = (DEMO / "app.py").read_text()
        self.assertIn('[data-testid="stAppDeployButton"]', app)
        self.assertIn("unsafe_allow_html=True", app)

    def test_demo_uses_marker_not_secret(self):
        app = (DEMO / "app.py").read_text()
        self.assertIn("DEMO_MARKER", app)
        self.assertNotIn("DEMO_FAKE_SECRET", app)

    def test_documentation_mentions_remote_tunnel(self):
        guide = (ROOT / "docs/examples/streamlit-security/README.md").read_text()
        self.assertIn("ssh -N -L 8501:127.0.0.1:8501", guide)
        self.assertIn("ssh -N -L 8090:127.0.0.1:8090", guide)
        self.assertIn("routes exposed services by hostname", guide)
        self.assertIn("http://localhost:8090", guide)
        self.assertLess(
            guide.index("ssh -N -L 8501:127.0.0.1:8501"),
            guide.index("## Run the unsafe version"),
        )

    def test_documentation_mentions_model_only_chat(self):
        guide = (ROOT / "docs/examples/streamlit-security/README.md").read_text()
        self.assertIn("follow-up chat", guide)
        self.assertIn("diagnostics remain the only local actions", guide)

    def test_demo_files_do_not_contain_real_openai_keys(self):
        key_patterns = (
            re.compile(r"sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}"),
            re.compile(r"AKIA[0-9A-Z]{16}"),
            re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
            re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}"),
            re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        )
        paths = [
            *DEMO.rglob("*"),
            *(ROOT / "docs/examples/streamlit-security").rglob("*"),
        ]
        for path in paths:
            if not path.is_file():
                continue
            with path.open(encoding="utf-8", errors="replace") as stream:
                content = stream.read()
            for key_pattern in key_patterns:
                self.assertIsNone(
                    key_pattern.search(content),
                    f"credential-like value in {path.relative_to(ROOT)}",
                )


if __name__ == "__main__":
    unittest.main()
