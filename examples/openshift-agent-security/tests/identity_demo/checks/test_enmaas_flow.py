# SPDX-License-Identifier: Apache-2.0
"""Bounded model output and native credential scope; no live requests here."""

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from enmaas_flow import profile

SOURCE = Path(__file__).resolve().parents[3] / "workloads/agents/service-request-demo/src/inference.py"
spec = importlib.util.spec_from_file_location("bounded_inference", SOURCE)
inference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inference)


def response(text: str, stop: str = "end_turn") -> dict:
    """Build a Messages response without contacting a model."""
    return {"content": [{"type": "text", "text": text}], "stop_reason": stop}


def test_only_two_plain_content_fields() -> None:
    """Provider reasoning is omitted; approved content remains untrusted data."""
    result = response(json.dumps({"summary": "Synthetic workspace", "description": "Read only."}))
    result["content"].insert(0, {"type": "thinking", "thinking": "not retained"})
    assert inference.parse_content(result) == {"summary": "Synthetic workspace", "description": "Read only."}


@pytest.mark.parametrize("text", [
    '{"summary":"a","description":"b","approved":true}',
    '{"summary":"a","summary":"b","description":"c"}',
    '```json\n{"summary":"a","description":"b"}\n```',
    '{"summary":null,"description":"b"}',
    '{"summary":"a\\nb","description":"b"}',
    json.dumps({"summary": "a" * 181, "description": "b"}),
    json.dumps({"summary": "a", "description": "\x00bad"}),
])
def test_invalid_or_security_output_rejected(text: str) -> None:
    """Extra authority fields, malformed/duplicate fields and controls fail closed."""
    with pytest.raises(inference.InferenceFailure, match="output_schema"):
        inference.parse_content(response(text))


def test_truncation_rejected() -> None:
    """A partial generation cannot become an approvable action."""
    with pytest.raises(inference.InferenceFailure, match="incomplete_output"):
        inference.parse_content(response('{}', 'max_tokens'))


def test_profile_scopes_key_and_network() -> None:
    """No blanket internet access or model key in the generated profile."""
    value = profile("synthetic-model")
    assert value["credentials"] == [{"name": "api_key", "required": True,
                                    "auth_style": "header", "header_name": "x-api-key"}]
    assert len(value["endpoints"]) == 1
    endpoint = value["endpoints"][0]
    assert endpoint["host"] == "inference.example.test"
    assert endpoint["rules"] == [{"allow": {"method": "POST", "path": "/v1/messages"}}]
    assert "credential_file" not in json.dumps(value)


def test_redirect_has_no_followup() -> None:
    """The handler cannot forward a request to an unapproved destination."""
    assert inference.NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.invalid") is None


def test_inference_failure_does_not_produce_fallback(monkeypatch: object, capsys: object) -> None:
    """Failure creates no proposal or fake successful inference receipt."""
    def fail() -> dict:
        raise inference.InferenceFailure("connection_or_tls")
    monkeypatch.setattr(inference, "proposal", fail)
    inference.main()
    assert json.loads(capsys.readouterr().out) == {
        "inference_failed": True, "error_category": "connection_or_tls"}


def test_real_key_environment_is_refused_before_transport(monkeypatch: object) -> None:
    """The supported path keeps credentials in the supervisor, outside the agent."""
    monkeypatch.setenv("ENMAAS_API_KEY", "synthetic-test-value")
    with pytest.raises(inference.InferenceFailure, match="unexpected_agent_credential"):
        inference.proposal()


@pytest.mark.parametrize("value", ["openshell:resolve:env:api_key",
    "openshell:resolve:env:v12_api_key", "openshell:resolve:env:s" + "a" * 64 + "_api_key"])
def test_documented_native_placeholder_permitted(value: str) -> None:
    """A native handle is not the real provider credential."""
    inference.check_environment({"api_key": value})


@pytest.mark.parametrize("value", ["synthetic-raw-key", "openshell:resolve:env:wrong",
    "openshell:resolve:env:sbad_api_key", "openshell:resolve:env:api_key\nextra"])
def test_raw_or_malformed_native_key_rejected(value: str) -> None:
    """Only the exact documented native formats are accepted, without logging."""
    with pytest.raises(inference.InferenceFailure, match="unexpected_agent_credential"):
        inference.check_environment({"api_key": value})


def test_static_provider_uses_only_placeholder_header(monkeypatch: object) -> None:
    """Static native rewriting requires the placeholder in the outgoing header."""
    placeholder = "openshell:resolve:env:v3_api_key"
    monkeypatch.setattr(inference, "os", SimpleNamespace(environ={"api_key": placeholder}))
    class Reply:
        status = 200
        def __enter__(self) -> object:
            return self
        def __exit__(self, *args: object) -> None:
            pass
        def read(self, size: int) -> bytes:
            return json.dumps(response('{"summary":"Synthetic task","description":"Read only."}')).encode()
    def send(request: object, timeout: int) -> Reply:
        assert request.full_url == inference.URL
        assert request.get_header("X-api-key") == placeholder
        assert request.get_header("Anthropic-version") == "2023-06-01"
        body = json.loads(request.data)
        assert body["model"] == inference.MODEL and timeout == 60
        assert "api_key" not in body and placeholder not in request.data.decode()
        return Reply()
    monkeypatch.setattr(inference, "build_opener", lambda *args: SimpleNamespace(open=send))
    result = inference.proposal()
    assert result["proposed_create"]["project"] == "SERVICE"
    assert result["inference"]["http_status"] == 200
    assert not result["inference"]["credential_in_agent"]


def test_diagnostic_mode_withholds_even_an_unexpected_successful_draft(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Deadline tests cannot accidentally offer approval or dispatch if a request is fast."""
    import agent_runtime
    from enmaas_flow import EnmaasFlow
    flow = object.__new__(EnmaasFlow)
    flow.args = SimpleNamespace(diagnostic_failure='model-timeout', output_dir=tmp_path, label='diagnostic')
    events = []
    flow.progress = lambda *args: events.append(args)
    monkeypatch.setattr(agent_runtime, 'report', lambda *args: {'proposed_create': {'summary': 'Unexpected draft'}})
    with pytest.raises(agent_runtime.AgentRuntimeFailure, match='diagnostic_not_observed'):
        flow.generate_report(None, 'fixed-resource', None)
    assert events == [('agent_stopping', {'agent_error_category': 'diagnostic_not_observed', 'failure_code': 'agent_failed'})]
    assert json.loads((tmp_path / 'diagnostic.agent-failure.summary.json').read_text())['no_fallback'] is True
