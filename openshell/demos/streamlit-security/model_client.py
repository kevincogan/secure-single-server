"""Model client for the Streamlit before/after OpenShell demo."""
from __future__ import annotations

import json
from urllib.parse import urlsplit
import urllib.error
import urllib.request


SYSTEM_MESSAGE = {
    "role": "system",
    "content": (
        "You are a support-ticket triage assistant. Answer the latest user "
        "message concisely and give one practical next step when useful."
    ),
}

PROVIDER_REQUEST_FORMATS = {
    "streamlit-demo-openai": "openai",
    "streamlit-demo-compatible": "openai-compatible",
}


def request_format_for_provider(provider: str) -> str:
    """Return the Chat Completions parameter format for a demo provider."""
    try:
        return PROVIDER_REQUEST_FORMATS[provider]
    except KeyError as error:
        raise ValueError(
            "STREAMLIT_DEMO_PROVIDER is not a supported demo provider"
        ) from error


class RejectRedirects(urllib.request.HTTPRedirectHandler):
    """Keep bearer credentials from following endpoint redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def call_model(
    ticket: str,
    *,
    base_url: str,
    api_key: str,
    model: str,
    request_format: str,
    messages: list[dict[str, str]] | None = None,
) -> str:
    """Call the configured endpoint with ticket context and ordered chat turns."""
    if not ticket.strip():
        raise ValueError("ticket must not be empty")
    if not api_key:
        raise ValueError("OPENAI_API_KEY is required")
    if not model:
        raise ValueError("OPENAI_MODEL is required")
    if request_format not in {"openai", "openai-compatible"}:
        raise ValueError("request_format must be openai or openai-compatible")
    parsed_url = urlsplit(base_url)
    if (
        parsed_url.scheme not in {"http", "https"}
        or not parsed_url.hostname
        or parsed_url.username is not None
        or parsed_url.password is not None
        or parsed_url.query
        or parsed_url.fragment
        or any(character.isspace() for character in base_url)
    ):
        raise ValueError(
            "MODEL_BASE_URL must be an HTTP(S) URL without userinfo, query, or fragment"
        )
    try:
        port = parsed_url.port
    except ValueError as error:
        raise ValueError("MODEL_BASE_URL has an invalid port") from error
    if parsed_url.scheme == "http" and (
        parsed_url.hostname
        not in {"host.openshell.internal", "host.containers.internal"}
        or port != 18080
    ):
        raise ValueError(
            "MODEL_BASE_URL must use HTTPS outside the OpenShell proxy on port 18080"
        )

    conversation = messages or []
    for message in conversation:
        if (
            not isinstance(message, dict)
            or message.get("role") not in {"user", "assistant"}
            or not isinstance(message.get("content"), str)
            or not message["content"].strip()
        ):
            raise ValueError("chat messages must have user or assistant roles and content")

    headers = {"Authorization": f"Bearer {api_key}"}
    payload = {
        "model": model,
        "messages": [
            SYSTEM_MESSAGE,
            {"role": "user", "content": ticket},
            *conversation,
        ],
        "temperature": 0.1,
    }
    if request_format == "openai":
        payload["max_completion_tokens"] = 1000
    else:
        payload["max_tokens"] = 300

    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/chat/completions",
        data=json.dumps(payload).encode(),
        headers={**headers, "Content-Type": "application/json"},
        method="POST",
    )
    response_opener = urllib.request.build_opener(RejectRedirects())
    try:
        with response_opener.open(request, timeout=60.0) as response:
            if not 200 <= response.status < 300:
                raise ValueError(f"model request failed with status {response.status}")
            document = json.load(response)
    except urllib.error.HTTPError as error:
        raise ValueError(f"model request failed with status {error.code}") from error
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError("model response is not valid JSON") from error

    if not isinstance(document, dict):
        raise ValueError("model response has no assistant content")
    choices = document.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        raise ValueError("model response has no assistant content")
    message = choices[0].get("message")
    if not isinstance(message, dict):
        raise ValueError("model response has no assistant content")
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        raise ValueError("model response has no assistant content")
    return content
