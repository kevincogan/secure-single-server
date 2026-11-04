"""Regression tests for links between documentation pages and commands."""

from __future__ import annotations

import os
import re
import shlex
import unittest
from pathlib import Path

import yaml
import markdown


ROOT = Path(__file__).parents[2]


class MkDocsTestLoader(yaml.SafeLoader):
    """Read MkDocs YAML without importing tagged Python objects."""


def preserve_python_name_as_text(loader, suffix, node):
    """Keep MkDocs' python/name tags as inert text for the nav contract test."""
    return suffix


MkDocsTestLoader.add_multi_constructor(
    "tag:yaml.org,2002:python/name:", preserve_python_name_as_text
)


def scenario_pages(entries):
    """Yield scenario leaf pages from MkDocs' nested Scenarios navigation."""
    for item in entries:
        title, target = next(iter(item.items()))
        if isinstance(target, list):
            yield from scenario_pages(target)
        elif title not in {"Overview", "Demo task prompt"}:
            yield title, target


class DocumentationContractsTests(unittest.TestCase):
    def test_pricetag_collapsed_sections_render_markdown(self):
        base = ROOT / "docs/quickstarts/remote-gateway-pricetag"
        for path in base.glob("*.md"):
            source = path.read_text(encoding="utf-8")
            for block in re.findall(r"<details[^>]*>.*?</details>", source, re.DOTALL):
                with self.subTest(page=path.name, summary=block.split("</summary>")[0]):
                    rendered = markdown.markdown(
                        block, extensions=["md_in_html", "tables", "pymdownx.superfences"]
                    )
                    if re.search(r"\[[^\]]+\]\([^)]+\)", block):
                        self.assertIn('<a href="', rendered)
                    if "```" in block:
                        self.assertIn("<pre", rendered)
                        self.assertNotIn("```", rendered)
                    if "| ---" in block:
                        self.assertIn("<table>", rendered)
        source = (base / "README.md").read_text(encoding="utf-8")
        rendered = markdown.markdown(source, extensions=["md_in_html", "pymdownx.superfences"])
        self.assertIn('href="../../testing/aws-pricetag.md"', rendered)

    def test_every_scenario_nav_page_is_linked_from_the_scenarios_index(self):
        config = yaml.load(
            (ROOT / "mkdocs.yml").read_text(encoding="utf-8"),
            Loader=MkDocsTestLoader,
        )
        scenario_nav = next(
            section["Scenarios"] for section in config["nav"] if "Scenarios" in section
        )
        index = (ROOT / "docs/examples/README.md").read_text(encoding="utf-8")
        for title, target in scenario_pages(scenario_nav):
            relative = os.path.relpath(target, start="docs/examples")
            with self.subTest(scenario=title, target=relative):
                self.assertIn(f"]({relative})", index)

    def test_older_vm_copy_command_includes_existing_helper_sources(self):
        guide = (ROOT / "docs/examples/praxis-quotas/README.md").read_text(
            encoding="utf-8"
        )
        section = guide.split("## Update the helpers on an existing VM", 1)[1]
        section = section.split("\n## ", 1)[0]
        code = re.search(r"```console\s*(.*?)```", section, re.DOTALL)
        self.assertIsNotNone(code, "the older-VM commands need a console block")
        tokens = shlex.split(code.group(1).replace("\\\n", " "))
        scp_index = tokens.index("scp")
        arguments = tokens[scp_index + 1 :]
        sources = []
        while arguments:
            item = arguments.pop(0)
            if item == "-p":
                continue
            if item in {"-o", "-i"}:
                self.assertTrue(arguments, f"missing value for scp {item}")
                arguments.pop(0)
                continue
            sources.append(item)

        self.assertGreaterEqual(len(sources), 2, "scp needs sources and a destination")
        destination = sources.pop()
        self.assertTrue(destination.startswith("$RHEL_HOST:"))
        self.assertIn("scripts/common/providers", sources)
        for source in sources:
            with self.subTest(source=source):
                self.assertTrue((ROOT / source).is_file(), f"missing scp source: {source}")

    def test_maintainer_guide_and_pages_ci_use_the_same_build_command(self):
        guide = (ROOT / "docs/development/documentation-site.md").read_text(
            encoding="utf-8"
        )
        workflow = (ROOT / ".github/workflows/pages.yml").read_text(encoding="utf-8")
        self.assertIn("\nscripts/docs/serve build\n", guide)
        self.assertIn("run: scripts/docs/serve build", workflow)


if __name__ == "__main__":
    unittest.main()
