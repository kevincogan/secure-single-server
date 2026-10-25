"""Tests for documentation staging."""

from __future__ import annotations

import shutil
import unittest

import stage


class StageTests(unittest.TestCase):
    def test_public_testing_and_pricetag_guides_are_staged(self):
        destination = stage.STAGE / "test-stage"
        try:
            stage.stage_docs(destination)
            staged_paths = {
                path.relative_to(destination).as_posix()
                for path in destination.rglob("*.md")
            }
        finally:
            shutil.rmtree(destination)

        self.assertIn("docs/testing/README.md", staged_paths)
        self.assertIn("docs/testing/compatibility.md", staged_paths)
        self.assertIn("docs/testing/pricetag.md", staged_paths)
        self.assertIn("docs/testing/aws-pricetag.md", staged_paths)
        self.assertIn("docs/testing/pricetag-perf.md", staged_paths)
        self.assertNotIn("docs/testing/aws.md", staged_paths)
        self.assertNotIn("docs/testing/rhel-real.md", staged_paths)

    def test_published_static_pages_are_staged(self):
        destination = stage.STAGE / "test-static-stage"
        try:
            stage.stage_docs(destination)
            staged_paths = {
                path.relative_to(destination).as_posix()
                for path in destination.rglob("*.html")
            }
        finally:
            shutil.rmtree(destination)

        self.assertIn(
            "docs/examples/document-exfiltration/visual-demo.html",
            staged_paths,
        )
        self.assertTrue(
            all(path.endswith("/visual-demo.html") for path in staged_paths),
            staged_paths,
        )

    def test_roadmap_is_not_staged(self):
        destination = stage.STAGE / "test-roadmap-stage"
        try:
            stage.stage_docs(destination)
            staged_paths = {
                path.relative_to(destination).as_posix()
                for path in destination.rglob("*.md")
            }
        finally:
            shutil.rmtree(destination)

        self.assertNotIn("docs/roadmap.md", staged_paths)

    def test_unpublished_component_documents_are_not_staged(self):
        destination = stage.STAGE / "test-component-stage"
        try:
            stage.stage_docs(destination)
            staged_paths = {
                path.relative_to(destination).as_posix()
                for path in destination.rglob("*.md")
            }
        finally:
            shutil.rmtree(destination)

        self.assertNotIn("openshell/docs/upgrade.md", staged_paths)
        self.assertNotIn("openshell/REVIEW-FOLLOWUP.md", staged_paths)

    def test_reference_documents_are_not_staged(self):
        destination = stage.STAGE / "test-reference-stage"
        try:
            stage.stage_docs(destination)
            staged_paths = {
                path.relative_to(destination).as_posix()
                for path in destination.rglob("*.md")
            }
        finally:
            shutil.rmtree(destination)

        self.assertNotIn("docs/development/workload-templates.md", staged_paths)
        self.assertNotIn(
            "docs/development/sandbox-use-case-analysis.md", staged_paths
        )
        self.assertNotIn(
            "docs/development/review-turn-stdin-hang.md", staged_paths
        )
        self.assertNotIn("docs/development/documentation-site.md", staged_paths)


if __name__ == "__main__":
    unittest.main()
