#!/usr/bin/env python3
"""Unit and merge-gate checks for OpenShell upstream release tracking."""

from pathlib import Path
import contextlib
import io
import os
import re
import subprocess
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/github"))
import upstream_watch


REQUIRED_USAGE_SURFACES = (
    "`sandbox create` flags",
    "Gateway configuration schema",
    "Policy schema",
    "Supervisor network path",
    "Workload images and CLI checksums",
)


class UpstreamWatchTests(unittest.TestCase):
    def test_reads_a_stable_semver_cli_pin(self):
        pin = upstream_watch.read_pin(ROOT / "openshell/configs/images.env")
        self.assertRegex(pin, r"^v\d+\.\d+\.\d+$")

    def test_selects_only_stable_newer_releases(self):
        releases = [
            {"tag_name": "v0.1.4", "draft": False, "prerelease": False},
            {"tag_name": "v0.1.3", "draft": False, "prerelease": False},
            {"tag_name": "v0.1.5", "draft": False, "prerelease": True},
            {"tag_name": "v0.2.0", "draft": True, "prerelease": False},
            {"tag_name": "dev", "draft": False, "prerelease": True},
            {"tag_name": "v0.2.0", "draft": False, "prerelease": False},
        ]
        selected = upstream_watch.newer_stable_releases(releases, "v0.1.3")
        self.assertEqual([release["tag_name"] for release in selected], ["v0.2.0", "v0.1.4"])

    def test_issue_body_contains_delta_and_review_checklist(self):
        release = {
            "tag_name": "v0.1.4",
            "name": "OpenShell v0.1.4",
            "published_at": "2026-10-13T20:48:39Z",
            "html_url": "https://example.invalid/v0.1.4",
            "draft": False,
            "prerelease": False,
            "body": "<!-- injected -->\nRelease notes",
        }
        body = upstream_watch.issue_body("v0.1.3", [release], 12_000)
        self.assertIn(upstream_watch.ISSUE_MARKER, body)
        self.assertIn("Current downstream pin: `v0.1.3`", body)
        self.assertIn(
            "<!-- secure-single-server:openshell-upstream-releases:v0.1.4 -->",
            body)
        self.assertIn("OpenShell v0.1.4 (`v0.1.4`, published 2026-10-13)", body)
        self.assertIn("https://example.invalid/v0.1.4", body)
        self.assertIn("Affects us? checklist", body)
        self.assertIn("`sandbox create` flags", body)
        self.assertIn("Gateway configuration schema", body)
        self.assertIn("Policy schema", body)
        self.assertIn("Supervisor network path", body)
        self.assertIn("docs/development/openshell-upstream.md", body)
        self.assertIn(upstream_watch.REVIEWER_NOTES_MARKER, body)
        self.assertNotIn("injected", body)

    def test_release_notes_are_rendered_as_inert_text(self):
        notes = upstream_watch.clean_release_notes(
            "```inner```\nby @contributor in https://example.invalid/pull/1 #1",
            12_000)
        self.assertTrue(notes.startswith("````text\n"))
        self.assertTrue(notes.endswith("\n````"))
        self.assertIn("by @contributor in https://example.invalid/pull/1 #1", notes)
        self.assertNotIn("\n```inner\n", notes)

    def test_updates_preserve_reviewer_progress_and_notes(self):
        release = {
            "tag_name": "v0.1.4",
            "name": "OpenShell v0.1.4",
            "published_at": "2026-10-13T20:48:39Z",
            "html_url": "https://example.invalid/v0.1.4",
            "body": "Original release notes",
        }
        generated = upstream_watch.issue_body("v0.1.3", [release], 12_000)
        marker_position = generated.index(upstream_watch.REVIEWER_NOTES_MARKER)
        existing = (
            generated[:marker_position]
            .replace("- [ ] `sandbox create` flags, resources, and template contracts",
                     "- [x] `sandbox create` flags, resources, and template contracts", 1)
            + upstream_watch.REVIEWER_NOTES_MARKER
            + "\n\n## Reviewer notes\n\nObserved: no template-contract change.\n"
        )
        updated = upstream_watch.merge_issue_body(existing, generated)
        self.assertIn("- [x] `sandbox create` flags, resources, and template contracts", updated)
        self.assertIn("Observed: no template-contract change.", updated)
        self.assertEqual(updated.count(upstream_watch.REVIEWER_NOTES_MARKER), 1)

    def test_a_new_release_set_clears_old_checklist_decisions(self):
        release = {
            "tag_name": "v0.1.4",
            "name": "OpenShell v0.1.4",
            "published_at": "2026-10-13T20:48:39Z",
            "html_url": "https://example.invalid/v0.1.4",
            "body": "Original release notes",
        }
        newer_release = {
            "tag_name": "v0.1.5",
            "name": "OpenShell v0.1.5",
            "published_at": "2026-10-19T20:48:39Z",
            "html_url": "https://example.invalid/v0.1.5",
            "body": "New release notes",
        }
        existing = upstream_watch.issue_body("v0.1.3", [release], 12_000)
        marker_position = existing.index(upstream_watch.REVIEWER_NOTES_MARKER)
        existing = (
            existing[:marker_position]
            .replace("- [ ] `sandbox create` flags, resources, and template contracts",
                     "- [x] `sandbox create` flags, resources, and template contracts", 1)
            + upstream_watch.REVIEWER_NOTES_MARKER
            + "\n\n## Reviewer notes\n\nObserved: no template-contract change.\n"
        )
        generated = upstream_watch.issue_body(
            "v0.1.3", [newer_release, release], 12_000)
        updated = upstream_watch.merge_issue_body(existing, generated)
        self.assertIn("- [ ] `sandbox create` flags, resources, and template contracts", updated)
        self.assertNotIn("- [x] `sandbox create` flags, resources, and template contracts", updated)
        self.assertIn("Observed: no template-contract change.", updated)

    def test_no_newer_releases_closes_an_existing_tracking_issue(self):
        def fake_github_request(url, token=None, method="GET", payload=None):
            if method == "GET" and url.endswith("/releases?per_page=100"):
                return [], {}
            if method == "GET" and "/issues?state=open" in url:
                return [{"number": 12, "body": upstream_watch.ISSUE_MARKER}], {}
            if method == "PATCH" and url.endswith("/issues/12"):
                return {"number": 12, "html_url": "https://example.invalid/issues/12"}, {}
            raise AssertionError(f"unexpected request: {method} {url}")

        output = io.StringIO()
        with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "token"}), \
             mock.patch.object(upstream_watch, "github_request",
                               side_effect=fake_github_request) as request, \
             contextlib.redirect_stdout(output):
            result = upstream_watch.main(["--repository", "example/example"])
        self.assertEqual(result, 0)
        self.assertIn("Closed tracking issue #12", output.getvalue())
        writes = [call for call in request.call_args_list
                  if call.kwargs.get("method") == "PATCH"]
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0].kwargs["payload"], {"state": "closed"})

    def test_successful_issue_writes_return_api_bodies(self):
        """Create and refresh tracking issues for a release newer than the pin."""
        current_pin = upstream_watch.read_pin(ROOT / "openshell/configs/images.env")
        major, minor, patch = upstream_watch.parse_version(current_pin)
        newer_pin = f"v{major}.{minor}.{patch + 1}"
        if patch:
            stale_pin = f"v{major}.{minor}.{patch - 1}"
        elif minor:
            stale_pin = f"v{major}.{minor - 1}.999"
        elif major:
            stale_pin = f"v{major - 1}.999.999"
        else:
            stale_pin = newer_pin
        release = {
            "tag_name": newer_pin,
            "name": f"OpenShell {newer_pin}",
            "published_at": "2026-10-19T20:48:39Z",
            "html_url": f"https://example.invalid/{newer_pin}",
            "body": "Release notes",
        }
        generated = upstream_watch.issue_body(current_pin, [release], 12_000)
        write_url = f"{upstream_watch.API_BASE}/repos/example/example/issues"
        response = {"number": 12, "html_url": "https://example.invalid/issues/12"}
        cases = [
            ("create", None, "POST", write_url, response),
            ("update", {"number": 12, "title": "Old title",
                        "body": generated.replace(
                            f"Current downstream pin: `{current_pin}`",
                            f"Current downstream pin: `{stale_pin}`")},
             "PATCH", f"{write_url}/12", response),
        ]
        for operation, existing_issue, method, url, api_body in cases:
            with self.subTest(operation=operation):
                def fake_github_request(request_url, token=None, method="GET",
                                        payload=None):
                    if method == "GET" and request_url.endswith("/releases?per_page=100"):
                        return [release], {}
                    if method == "GET" and "/issues?state=open" in request_url:
                        return ([existing_issue] if existing_issue else []), {}
                    if method == cases[0][2] and request_url == cases[0][3]:
                        return cases[0][4], {}
                    if method == cases[1][2] and request_url == cases[1][3]:
                        return cases[1][4], {}
                    raise AssertionError(f"unexpected request: {method} {request_url}")

                output = io.StringIO()
                with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "token"}), \
                     mock.patch.object(upstream_watch, "github_request",
                                       side_effect=fake_github_request) as fake_request, \
                     contextlib.redirect_stdout(output):
                    result = upstream_watch.main(["--repository", "example/example"])
                self.assertEqual(result, 0)
                self.assertIn(f"{operation.capitalize()}d tracking issue #12", output.getvalue())
                writes = [call for call in fake_request.call_args_list
                          if call.kwargs.get("method") == method]
                self.assertEqual(len(writes), 1)
                self.assertEqual(writes[0].args[0], url)
                self.assertEqual(writes[0].kwargs["payload"]["title"],
                                 upstream_watch.issue_title(current_pin))
                self.assertIn(upstream_watch.ISSUE_MARKER,
                              writes[0].kwargs["payload"]["body"])

    def reviewed_delta_row(self):
        pin = upstream_watch.read_pin(ROOT / "openshell/configs/images.env")
        document = (ROOT / "docs/development/openshell-upstream.md").read_text(encoding="utf-8")
        matching_rows = [line for line in document.splitlines()
                         if line.startswith(f"| `{pin}` |")]
        self.assertEqual(len(matching_rows), 1)
        cells = [cell.strip() for cell in matching_rows[0].strip().strip("|").split("|")]
        self.assertEqual(len(cells), 4)
        return cells

    def test_current_pin_requires_a_reviewed_delta_and_surface_declaration(self):
        cells = self.reviewed_delta_row()
        self.assertEqual(cells[1], "Reviewed")
        usage_surface_review = cells[3]
        if usage_surface_review.startswith("Affected usage surfaces:"):
            self.assertTrue(any(surface in usage_surface_review
                                for surface in REQUIRED_USAGE_SURFACES))
        else:
            self.assertEqual(usage_surface_review, "No listed usage surfaces affected.")

    def test_usage_surface_register_covers_required_dependencies(self):
        document = (ROOT / "docs/development/openshell-upstream.md").read_text(encoding="utf-8")
        for surface in ("`sandbox create` flags", "Gateway configuration schema",
                        "Policy schema", "Supervisor network path", "CONNECT/REST handling",
                        "CLI checksums"):
            self.assertIn(surface, document)

    def test_scheduled_workflow_uses_daily_cron_and_issue_write_permission(self):
        workflow = (ROOT / ".github/workflows/upstream-watch.yml").read_text(encoding="utf-8")
        self.assertIn("cron:", workflow)
        self.assertIn('permissions:', workflow)
        self.assertIn("issues: write", workflow)
        self.assertIn("scripts/github/upstream_watch.py", workflow)

    def diff_touches_usage_surface_register(self, diff: str) -> bool:
        document_lines = (ROOT / "docs/development/openshell-upstream.md").read_text(
            encoding="utf-8").splitlines()
        section_start = document_lines.index("## Usage-surface register") + 1
        section_end = next(index for index, line in enumerate(document_lines[section_start:], section_start)
                           if line.startswith("## ")) - 1
        for header in re.finditer(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", diff, re.MULTILINE):
            hunk_start = int(header.group(1))
            hunk_count = int(header.group(2) or "1")
            hunk_end = hunk_start + max(hunk_count, 1) - 1
            if hunk_start <= section_end and hunk_end >= section_start:
                return True
        return False

    def test_usage_surface_diff_detector_only_accepts_register_changes(self):
        document_lines = (ROOT / "docs/development/openshell-upstream.md").read_text(
            encoding="utf-8").splitlines()
        section_start = document_lines.index("## Usage-surface register") + 1
        delta_only = f"@@ -1,1 +{section_start - 1},1 @@\n+Reviewed delta change"
        register_change = f"@@ -1,1 +{section_start + 1},1 @@\n+Usage-surface change"
        self.assertFalse(self.diff_touches_usage_surface_register(delta_only))
        self.assertTrue(self.diff_touches_usage_surface_register(register_change))

    def test_pin_change_requires_a_conditional_usage_surface_register_update(self):
        if os.environ.get("GITHUB_EVENT_NAME") != "pull_request":
            return
        base_ref = os.environ.get("GITHUB_BASE_REF")
        self.assertTrue(base_ref, "GITHUB_BASE_REF is required on pull requests")
        comparison = subprocess.run(
            ["git", "diff", "--name-only", f"origin/{base_ref}...HEAD"],
            cwd=ROOT, capture_output=True, text=True, check=True)
        changed = set(comparison.stdout.splitlines())
        if "openshell/configs/images.env" not in changed:
            return
        base_images = subprocess.run(
            ["git", "show", f"origin/{base_ref}:openshell/configs/images.env"],
            cwd=ROOT, capture_output=True, text=True, check=True)
        base_pin = upstream_watch.read_pin_text(
            base_images.stdout, f"origin/{base_ref}:openshell/configs/images.env")
        if base_pin == upstream_watch.read_pin(ROOT / "openshell/configs/images.env"):
            return

        cells = self.reviewed_delta_row()
        usage_surface_review = cells[3]
        if usage_surface_review == "No listed usage surfaces affected.":
            return
        self.assertTrue(usage_surface_review.startswith("Affected usage surfaces:"))
        self.assertTrue(any(surface in usage_surface_review
                            for surface in REQUIRED_USAGE_SURFACES))
        register_diff = subprocess.run(
            ["git", "diff", "--unified=0", f"origin/{base_ref}...HEAD", "--",
             "docs/development/openshell-upstream.md"],
            cwd=ROOT, capture_output=True, text=True, check=True)
        self.assertTrue(
            self.diff_touches_usage_surface_register(register_diff.stdout),
            "an affected OpenShell pin change must update the usage-surface register")


if __name__ == "__main__":
    if not __debug__:
        raise SystemExit("Run tests without Python -O")
    unittest.main()
