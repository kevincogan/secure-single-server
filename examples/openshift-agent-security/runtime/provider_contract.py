# SPDX-License-Identifier: Apache-2.0
"""Fixed non-secret provider/build configuration, loaded beside reviewed code.

Only the installer writes this file's sibling JSON. No environment variable,
browser input or model output can select another configuration path.
"""
import json
from pathlib import Path
import re
from urllib.parse import urlsplit


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate provider contract field")
        value[key] = item
    return value


def validate(value):
    fields = {"schema_version", "configured", "chat_request_url", "chat_model",
              "workload_image", "diagnostic_runtime_image"}
    if (not isinstance(value, dict) or value.keys() != fields
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or type(value["configured"]) is not bool):
        raise ValueError("Exact public provider contract required")
    url = value["chat_request_url"]
    if not isinstance(url, str) or not url.isascii() or "\\" in url or any(c.isspace() for c in url):
        raise ValueError("Canonical HTTPS provider required")
    parsed = urlsplit(url)
    if (not parsed.hostname or url != "https://" + parsed.hostname + "/v1/messages"
            or len(parsed.hostname) > 253 or parsed.hostname == "localhost"
            or parsed.hostname.endswith(".invalid") or re.fullmatch(r"[0-9.]+", parsed.hostname)
            or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p)
                       for p in parsed.hostname.split("."))):
        raise ValueError("Fixed DNS HTTPS Messages endpoint required")
    model = value["chat_model"]
    if not isinstance(model, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:-]{0,127}", model):
        raise ValueError("Bounded explicit model required")
    for name in ("workload_image", "diagnostic_runtime_image"):
        image = value[name]
        if (not isinstance(image, str) or len(image) > 512
                or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?/[a-z0-9]+(?:[._/-][a-z0-9]+)*@sha256:[a-f0-9]{64}", image)
                or value["configured"] and (image.endswith("0" * 64)
                    or image.startswith("registry.example.test/"))):
            raise ValueError("Digest-pinned public image required")
    if value["configured"] and (parsed.hostname == "inference.example.test" or model == "approved-chat-model"):
        raise ValueError("Configured provider must replace placeholders")
    return value


def load(text):
    """Inspect public configuration without evaluating executable source."""
    if not isinstance(text, str) or len(text) > 16384:
        raise ValueError("Bounded provider contract required")
    return validate(json.loads(text, object_pairs_hook=unique))


def sources():
    """Exact fixed files required by a packaged or temporary agent entrypoint."""
    source = Path(__file__)
    return {source.name: source.read_text(),
            "provider-contract.json": source.with_name("provider-contract.json").read_text()}


DATA = load(Path(__file__).with_name("provider-contract.json").read_text())
URL = DATA["chat_request_url"]
HOST = urlsplit(URL).hostname
MODEL = DATA["chat_model"]
WORKLOAD_IMAGE = DATA["workload_image"]
DIAGNOSTIC_IMAGE = DATA["diagnostic_runtime_image"]
