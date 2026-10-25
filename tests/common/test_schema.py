"""Connection failures cannot substitute for pinned OpenShell policy parsing."""
import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import unittest

spec = importlib.util.spec_from_file_location("openshell_schema", Path(__file__).resolve().parents[2] / "openshell/tests/schema.py")
schema = importlib.util.module_from_spec(spec)
spec.loader.exec_module(schema)


class SchemaControlsTest(unittest.TestCase):
    def test_connection_failure_before_parsing_is_not_a_pass(self):
        def invoke(_):
            return subprocess.CompletedProcess([], 1, "", "transport error: Connection refused")

        with self.assertRaisesRegex(AssertionError, "invalid-port control"):
            schema.validate_profiles(invoke, [])

    def test_numeric_control_must_reach_gateway(self):
        def invoke(_):
            return subprocess.CompletedProcess([], 1, "", "expected unsigned integer")

        with self.assertRaisesRegex(AssertionError, "numeric-port control"):
            schema.validate_profiles(invoke, [])

    def test_rejected_profile_is_reported_and_fails(self):
        calls = 0

        def invoke(_):
            nonlocal calls
            calls += 1
            output = "expected unsigned integer" if calls in (1, 3) else "transport error: Connection refused"
            return subprocess.CompletedProcess([], 1, "", output)

        results = []
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(AssertionError, "policies failed"):
            schema.validate_profiles(invoke, results)
        self.assertEqual(len(results), 23)
        self.assertEqual(sum(item["status"] == "failed" for item in results), 1)


if __name__ == "__main__":
    unittest.main()
