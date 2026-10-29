"""Contract tests for the fixture, independent of Praxis and container engines."""
import json
import unittest
import urllib.error
import urllib.request

from provider import Provider
from contracts import check


class ProviderTest(unittest.TestCase):
    def test_bounded_history_for_capacity_fixture(self):
        self.fixture.record_limit = 2
        for _ in range(4):
            with self.request('/v1/chat/completions', {'model': 'fixture'}) as response:
                self.assertEqual(response.status, 200)
        self.assertEqual(len(self.fixture.records), 2)

    def test_declared_tools_only_does_not_invent_harness_tools(self):
        self.fixture.declared_tools_only = True
        for route, tool, provider in (
                ('/v1/chat/completions', {'type': 'function', 'function': {'name': 'bash'}}, 0),
                ('/v1/responses', {'type': 'function', 'name': 'bash'}, 0),
                ('/v1/messages', {'name': 'bash', 'input_schema': {}}, 1)):
            for stream in (False, True):
                with self.subTest(route=route, stream=stream):
                    with self.request(route, {'model': 'fixture', 'tools': [tool], 'stream': stream},
                                      provider=provider) as response:
                        check(route, response.read().decode(), stream)
            if 'function' in tool:
                tool['function']['name'] = 'add'
            else:
                tool['name'] = 'add'
            with self.request(route, {'model': 'fixture', 'tools': [tool]}, provider=provider) as response:
                check(route, response.read().decode(), tool=True)

    def test_strict_cloud_rejects_legacy_token_parameter(self):
        self.fixture.strict_openai = True
        for model in ('gpt-5.4-mini', 'gpt-6-luna'):
            body = {'model': model, 'messages': [{'role': 'user', 'content': 'hello'}], 'max_tokens': 4}
            with self.assertRaises(urllib.error.HTTPError) as caught:
                self.request('/v1/chat/completions', body)
            self.assertEqual(caught.exception.code, 400)
            self.assertEqual(json.load(caught.exception)['error']['param'], 'max_tokens')
            body['max_completion_tokens'] = body.pop('max_tokens')
            with self.request('/v1/chat/completions', body) as response:
                self.assertEqual(response.status, 200)
        # Native Messages still requires max_tokens.
        with self.request('/v1/messages', {'model': 'claude-sonnet-5', 'max_tokens': 4}, provider=1) as response:
            self.assertEqual(response.status, 200)

    def test_strict_cloud_rejects_foreign_plaintext_reasoning(self):
        self.fixture.strict_openai = True
        history = [{'role': 'user', 'content': 'hello'}, {'type': 'reasoning', 'summary': [],
                    'content': [{'type': 'reasoning_text', 'text': 'synthetic local reasoning'}]}]
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.request('/v1/responses', {'model': 'gpt-5.4-mini', 'input': history})
        error = json.load(caught.exception)['error']
        self.assertEqual(error['param'], 'input[1].content')
        self.assertEqual(error['code'], 'array_above_max_length')
        history[1] = {'type': 'reasoning', 'summary': [], 'encrypted_content': 'synthetic-opaque'}
        with self.request('/v1/responses', {'model': 'gpt-5.4-mini', 'input': history}) as response:
            self.assertEqual(response.status, 200)
        self.assertNotIn('synthetic local reasoning', json.dumps(self.fixture.records))

    def test_model_discovery_query_parameters_are_supported(self):
        request = urllib.request.Request(f"http://127.0.0.1:{self.fixture.ports[0]}/v1/models?limit=1000",
                                         headers={"Authorization": "Bearer synthetic-openai"})
        with urllib.request.urlopen(request, timeout=2) as response:
            self.assertEqual(json.load(response)["data"][0]["id"], "fixture")
        self.assertEqual(self.fixture.records[-1]["path"], "/v1/models")

    def test_anthropic_beta_query(self):
        with self.request("/v1/messages?beta=true", {"model": "fixture",
                "messages": [{"role": "user", "content": "hello"}]}, provider=1) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(json.load(response)["type"], "message")

    def setUp(self):
        self.fixture = Provider(ports=(0, 0, 0))
        self.fixture.start()
        self.addCleanup(self.fixture.close)

    def request(self, path, body, provider=0, key=None):
        headers = {"Content-Type": "application/json"}
        if provider == 0:
            headers["Authorization"] = key or "Bearer synthetic-openai"
        else:
            headers["x-api-key"] = key or "synthetic-anthropic"
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.fixture.ports[provider]}{path}",
            json.dumps(body).encode(), headers)
        return urllib.request.urlopen(req, timeout=2)

    def test_json_streams_and_usage_for_each_protocol(self):
        for path in ("/v1/chat/completions", "/v1/responses", "/v1/messages"):
            for stream in (False, True):
                with self.subTest(path=path, stream=stream):
                    with self.request(path, {"model": "fixture", "stream": stream},
                                      provider=int(path == "/v1/messages")) as response:
                        body = response.read().decode()
                    self.assertIn("mock answer", body)
                    self.assertIn("usage", body)
                    check(path, body, stream)
                    if stream:
                        self.assertIn("text/event-stream", response.headers["Content-Type"])
                        self.assertIn("data: ", body)
                    else:
                        self.assertEqual(json.loads(body)["model"], "fixture")
        self.assertEqual(len(self.fixture.records), 6)
        self.assertTrue(all(record["credential_ok"] for record in self.fixture.records))

    def test_errors_and_missing_usage_are_controlled(self):
        for mode, status in (("http429", 429), ("http500", 500)):
            self.fixture.mode = mode
            with self.assertRaises(urllib.error.HTTPError) as caught:
                self.request("/v1/responses", {"model": "fixture"})
            self.assertEqual(caught.exception.code, status)
        self.fixture.mode = "missing_usage"
        with self.request("/v1/responses", {"model": "fixture"}) as response:
            self.assertNotIn("usage", json.load(response))

    def test_credentials_are_checked_without_recording_secrets(self):
        secret = "Bearer caller-secret-that-must-not-appear"
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.request("/v1/responses", {"model": "fixture"}, key=secret)
        self.assertEqual(caught.exception.code, 403)
        self.assertFalse(self.fixture.records[0]["credential_ok"])
        self.assertNotIn(secret, json.dumps(self.fixture.records))

    def test_local_model_requires_absent_authorization(self):
        fixture = Provider(ports=(0, 0, 0), openai_authorization=None, model="Qwen/Qwen3-8B")
        fixture.start()
        self.addCleanup(fixture.close)
        base = f"http://127.0.0.1:{fixture.ports[0]}"
        with urllib.request.urlopen(base + "/v1/models", timeout=2) as response:
            self.assertEqual(json.load(response)["data"][0]["id"], "Qwen/Qwen3-8B")
        body = json.dumps({"model": "Qwen/Qwen3-8B"}).encode()
        req = urllib.request.Request(base + "/v1/chat/completions", body,
                                     {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=2) as response:
            check("/v1/chat/completions", response.read().decode(), model="Qwen/Qwen3-8B")
        req.add_header("Authorization", "Bearer must-be-stripped")
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(req, timeout=2)
        self.assertEqual(caught.exception.code, 403)
        self.assertFalse(fixture.records[-1]["credential_ok"])
        self.assertNotIn("must-be-stripped", json.dumps(fixture.records))

    def test_tool_result_is_required_for_continuation(self):
        with self.request("/v1/chat/completions", {"model": "fixture", "tools": [{}]}) as response:
            call = json.load(response)["choices"][0]["message"]["tool_calls"][0]
        self.assertEqual(call["function"]["arguments"], '{"a":2,"b":3}')
        with self.request("/v1/chat/completions", {"model": "fixture", "messages": [
            {"role": "tool", "tool_call_id": call["id"], "content": "5"}]}) as response:
            self.assertEqual(json.load(response)["choices"][0]["message"]["content"], "5")
        self.assertTrue(self.fixture.records[-1]["continuation"])


if __name__ == "__main__":
    unittest.main()
