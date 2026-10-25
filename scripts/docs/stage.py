#!/usr/bin/env python3
"""Assemble the MkDocs source tree from the repository's Markdown files.

Component documentation stays next to the code it describes. GitHub Pages
needs a single documentation directory, so this script copies the documented
entry points into ``.docs-build/`` while preserving their repository-relative
paths. Preserving the paths keeps existing relative links valid on the site.

The repository README is staged as the site home. It is also the published
landing page, so the site does not maintain a second copy of the overview.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
STAGE = ROOT / ".docs-build"

# Keep this list in sync with mkdocs.yml. Each entry is a file or directory
# relative to the repository root.
SOURCES = (
    "README.md",
    "docs",
    "bootc",
    "openshell/docs",
    "openshell/harnesses",
    "openshell/demos",
)
PUBLISHED_TESTING_DOCS = frozenset(
    ROOT / path
    for path in (
        "docs/testing/README.md",
        "docs/testing/compatibility.md",
        "docs/testing/pricetag.md",
        "docs/testing/aws-pricetag.md",
        "docs/testing/pricetag-perf.md",
    )
)
EXCLUDED_SOURCES = (
    ROOT / "docs/roadmap.md",
    ROOT / "openshell/docs/upgrade.md",
    ROOT / "docs/development/workload-templates.md",
    ROOT / "docs/development/sandbox-use-case-analysis.md",
    ROOT / "docs/development/review-turn-stdin-hang.md",
    ROOT / "docs/development/documentation-site.md",
)


def markdown_files(source: Path) -> list[Path]:
    if source.is_file():
        return [source]
    return sorted(source.rglob("*.md"))


def static_pages() -> list[Path]:
    """Return each scenario's rendered visual demo.

    These self-contained HTML pages are published next to their scenario
    write-up. Staging them keeps them in the MkDocs file set, so links to them
    stay relative. The ``visual-demo.src.html`` sources are not published.
    """
    return sorted((ROOT / "docs/examples").glob("*/visual-demo.html"))


def navigation_paths() -> set[str]:
    document = yaml.compose(
        (ROOT / "mkdocs.yml").read_text(encoding="utf-8"), Loader=yaml.BaseLoader
    )
    if not isinstance(document, yaml.MappingNode):
        raise ValueError("mkdocs.yml must contain a mapping")

    nav_node = None
    for key_node, value_node in document.value:
        if isinstance(key_node, yaml.ScalarNode) and key_node.value == "nav":
            nav_node = value_node
            break
    if nav_node is None:
        raise ValueError("mkdocs.yml does not define nav")

    nav = yaml.constructor.SafeConstructor().construct_object(nav_node, deep=True)
    if not isinstance(nav, list):
        raise ValueError("mkdocs.yml nav must be a list")

    paths: set[str] = set()

    def walk(value: object) -> None:
        if isinstance(value, list):
            for child in value:
                walk(child)
        elif isinstance(value, dict):
            if len(value) != 1:
                raise ValueError("each nav entry must have exactly one label")
            child = next(iter(value.values()))
            if isinstance(child, str):
                paths.add(child)
            else:
                walk(child)
        else:
            raise ValueError("nav entries must be labels, lists, or paths")

    walk(nav)
    return paths


def stage_docs(destination: Path = STAGE) -> int:
    destination = destination.resolve()
    if destination != STAGE and STAGE not in destination.parents:
        raise ValueError("staging destination must be inside .docs-build")
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)

    copied = 0
    staged_paths: set[str] = set()
    for entry in SOURCES:
        source = ROOT / entry
        if not source.exists():
            raise SystemExit(f"documentation source does not exist: {entry}")
        for path in markdown_files(source):
            if any(path.is_relative_to(excluded) for excluded in EXCLUDED_SOURCES):
                continue
            if (
                path.is_relative_to(ROOT / "docs/testing")
                and path not in PUBLISHED_TESTING_DOCS
            ):
                continue
            relative = path.relative_to(ROOT)
            relative_key = relative.as_posix()
            if relative_key in staged_paths:
                raise SystemExit(
                    f"duplicate staged documentation path: {relative_key}"
                )
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
            staged_paths.add(relative_key)
            copied += 1

    for source in static_pages():
        target = destination / source.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)

    nav_paths = navigation_paths()
    if not nav_paths.issubset(staged_paths):
        missing_from_stage = sorted(nav_paths - staged_paths)
        raise SystemExit(
            "nav entries not staged: " + ", ".join(missing_from_stage)
        )
    return copied


def main() -> int:
    copied = stage_docs()
    print(f"Staged {copied} Markdown files in {STAGE.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
