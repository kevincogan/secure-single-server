# Documentation site

The documentation is published with GitHub Pages at
[redhat-et.github.io/secure-single-server](https://redhat-et.github.io/secure-single-server/)
and is the source of truth. The site is built with
[MkDocs Material](https://squidfunk.github.io/mkdocs-material/) from the
Markdown tracked in this repository. The repository README is the published
home page, so there is no separate landing-page copy to maintain.

## Source layout and URL mapping

Repository documentation stays next to the code it describes. The build does
not move or rename the reviewed sources. Instead,
[`scripts/docs/stage.py`](../../scripts/docs/stage.py) copies the documented
entry points into `.docs-build/` while preserving repository-relative paths.

| Repository source | Published URL |
| --- | --- |
| `README.md` | `/` |
| `docs/README.md` | `/docs/` — Introduction |
| `docs/examples/README.md` | `/docs/examples/` — Scenarios |
| `docs/examples/praxis-quotas/README.md` | `/docs/examples/praxis-quotas/` |
| `docs/examples/api-key-theft/README.md` | `/docs/examples/api-key-theft/` |
| `docs/examples/document-exfiltration/README.md` | `/docs/examples/document-exfiltration/` |
| `docs/examples/model-escalation/README.md` | `/docs/examples/model-escalation/` |
| `docs/testing/pricetag.md` | `/docs/testing/pricetag/` — PriceTag pilot overview |
| `docs/testing/aws-pricetag.md` | `/docs/testing/aws-pricetag/` — PriceTag deployment runbook |
| `docs/testing/pricetag-perf.md` | `/docs/testing/pricetag-perf/` — PriceTag performance procedure |
| `docs/quickstarts/bootc/README.md` | `/docs/quickstarts/bootc/` |
| `bootc/README.md` | `/bootc/` |
| `openshell/docs/README.md` | `/openshell/docs/` |
| `openshell/harnesses/opencode/README.md` | `/openshell/harnesses/opencode/` |

The root `README.md` is staged as the site home. Do not add a parallel
`docs/index.md`; MkDocs would map it to `/docs/` and create a second landing
page.

MkDocs treats `README.md` as the directory index, so no source files need to
be renamed to `index.md`. Links between Markdown pages continue to use their
existing repository-relative paths.

[`scripts/docs/mkdocs_hooks.py`](../../scripts/docs/mkdocs_hooks.py) rewrites
links that point to scripts, configuration, workflows, and other source files.
Those targets cannot be served by GitHub Pages, so the site links them to the
matching file on GitHub instead. This keeps the published pages free of broken
links while leaving the repository copies unchanged.

The navigation is declared explicitly in [`mkdocs.yml`](../../mkdocs.yml).
Add a new documentation page to the `nav` section so it appears in the site
sidebar.

Self-contained HTML pages, such as the document-exfiltration
[visual walkthrough](../examples/document-exfiltration/visual-demo.html), are
published from each scenario's `visual-demo.html`. The build copies every
`docs/examples/*/visual-demo.html` next to its scenario page and MkDocs
publishes it unchanged, so Markdown links to it stay relative. The
`visual-demo.src.html` sources are not published. These pages are not in
`nav`: link them from the scenario page. They use the site's Red Hat red,
Roboto fonts, favicon, and light and dark colors, but not the Material layout.
A header button switches the theme. The page starts in the theme its own button
saved, so your choice survives a reload. Without one, it uses the theme you
chose on the site, then your operating system's theme.

To add a visual demo to another scenario, use the project skill in
[`.claude/skills/visual-demo/`](../../.claude/skills/visual-demo/SKILL.md). It
holds the page template, the branding values, and the render and check steps.

## Red Hat branding

The theme uses Red Hat red (`#ee0000`, with `#a60000` and `#f56e6e` as the dark
and light variants from the Red Hat Design System tokens) and the white fedora
logo in the header. The theme keeps the Material default fonts. Branding assets
live in [`overrides/`](../../overrides/), which `theme.custom_dir` in
[`mkdocs.yml`](../../mkdocs.yml) publishes alongside the site:

- `overrides/assets/images/redhat-fedora-white.svg` is the header logo.
- `overrides/assets/images/redhat-favicon.svg` is the red fedora browser-tab
  icon.
- `overrides/assets/stylesheets/redhat.css` defines the brand colors for the
  light and dark schemes.

## File and URL references

Every guide should make it clear whether a named file, command, image, or URL
lives in the repository, on the RHEL host, inside a sandbox or container, or on
a client machine.

- Link repository files instead of only naming them in backticks, for example
  [`configs/templates/opencode.json`](../../configs/templates/opencode.json).
  The site build maps those links to GitHub automatically.
- Keep repository-relative paths relative to the checkout root, such as
  `openshell/harnesses/opencode/README.md`.
- State when a path is on the host, such as `/etc/secure-single-server` or
  `/etc/praxis`, or inside a sandbox, such as `/sandbox` or
  `/home/node/.openclaw/workspace`.
- State when a URL is local to the RHEL host, such as
  `http://127.0.0.1:8080`, or reached from a client through the remote gateway.
- List published image names with their source: the
  [bootc guide](../../bootc/README.md) contains the deployment commands and
  image variants.
- Identify generated or ignored locations, such as `.state/`, `evidence/`, and
  `site/`, and say which machine produces them.

The site home uses the repository overview in [README.md](../../README.md), while
the [documentation map](../README.md) links the architecture, deployment,
scenario, PriceTag, and validation guides.

## Preview locally

Install the pinned documentation dependencies and build the staged sources:

```bash
python3 -m venv .venv-docs
. .venv-docs/bin/activate
python3 -m pip install -r requirements-docs.txt
scripts/docs/serve
```

Open <http://127.0.0.1:8000/> to review the site. To reproduce the CI build
without starting a server, run:

```bash
scripts/docs/serve build
```

CI hook tests cover inline and reference-style source links, page and
directory links, and GitHub-style heading anchors. The staging step verifies
that every nav entry has a staged source, and the hook rejects unresolved
repository-relative links. The strict build fails on missing pages and broken
Markdown links. Contract tests check that each Scenarios nav page is linked
from the scenario index and that every source in the older-VM helper-copy
command exists. Pages CI runs the same `scripts/docs/serve build` command shown
above. The site builds from `.docs-build/`; `scripts/docs/serve` stages the
sources before starting the preview or building the static site. If you edit a
source while the preview is running, rerun `python3 scripts/docs/stage.py` to
refresh the staged copy.

## Publishing

The [documentation workflow](../../.github/workflows/pages.yml) builds the site
on pull requests and deploys it from `main`. GitHub Pages must use **GitHub
Actions** as its source. An administrator can set this under **Settings → Pages
→ Build and deployment → Source**.

The workflow installs `requirements-docs.txt`, runs the documentation tests and
`scripts/docs/serve build`, then publishes the `site/` artifact. The repository
does not use Jekyll or a `gh-pages` branch.
