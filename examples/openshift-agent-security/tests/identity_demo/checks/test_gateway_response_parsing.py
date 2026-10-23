# SPDX-License-Identifier: Apache-2.0
"""Offline checks for observing error-body results without returning sensitive data."""

from __future__ import annotations

import json
from io import BytesIO
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from checks.test_adapter import adapter_request
from checks.test_gateway import sanitized_error_result


class ErrorResponseTests(unittest.TestCase):
    """Use only synthetic content; assertions contain no real credential material."""

    def test_json_error_content_is_discarded(self) -> None:
        """An error envelope never exposes its message or nested diagnostic fields."""
        body = json.dumps({"error": {"message": "synthetic-private-diagnostic", "code": -32000}}).encode()
        self.assertEqual(sanitized_error_result(body), {})

    def test_json_result_is_detected_without_its_contents(self) -> None:
        """A result on an error status is observable without leaking its payload."""
        body = json.dumps({"result": {"content": "synthetic-confidential-value"}, "id": 1}).encode()
        self.assertEqual(sanitized_error_result(body), {"result": True})

    def test_multiline_sse_result_and_later_error_are_detected(self) -> None:
        """Inspect every event so a later error cannot hide an earlier result."""
        body = (b'event: message\ndata: {"result":\ndata: {"value": "synthetic"}}\n\n'
                b'event: message\ndata: {"error": {"message": "synthetic"}}\n\n')
        self.assertEqual(sanitized_error_result(body), {"result": True})

    def test_non_json_and_sse_errors_have_no_result(self) -> None:
        """Plain errors, invalid encoding and error-only SSE do not produce a result marker."""
        for body in (b"upstream unavailable", b"\xff\xfe", b'<html>synthetic error</html>',
                     b'event: message\ndata: {"error": {"message": "synthetic"}}\n\n'):
            self.assertEqual(sanitized_error_result(body), {})

    def test_adapter_error_status_does_not_hide_result(self) -> None:
        """Exercise the HTTPError branch without any network or real credentials."""
        body = b'{"result": {"content": "synthetic-private-result"}}'
        for status in (401, 403, 500):
            with self.subTest(status=status):
                error = HTTPError("http://127.0.0.1:18087/mcp", status, "synthetic", {}, BytesIO(body))
                with patch("checks.test_adapter.urlopen", side_effect=error):
                    actual, _, value = adapter_request("/mcp")
                self.assertEqual(actual, status)
                self.assertEqual(value, {"result": True})

    def test_adapter_rejects_oversized_error_body(self) -> None:
        """Do not infer no result from a response truncated at the proof bound."""
        error = HTTPError("http://127.0.0.1:18087/mcp", 401, "synthetic", {}, BytesIO(b"x" * 2_000_001))
        with patch("checks.test_adapter.urlopen", side_effect=error):
            with self.assertRaisesRegex(RuntimeError, "proof size bound"):
                adapter_request("/mcp")
