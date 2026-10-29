---
name: visual-demo
description: Create or update the branded visual walkthrough page (visual-demo.html) for a scenario under docs/examples/. Use when asked to add visuals, diagrams, or a visual demo to a scenario, or to restyle an existing one.
---

# Visual demo for a scenario

Each scenario in `docs/examples/<scenario>/` can ship a self-contained
`visual-demo.html`: figures first, words as captions, styled like the
documentation site. `scripts/docs/stage.py` publishes every
`docs/examples/*/visual-demo.html` next to its scenario page. The reference
example is `docs/examples/document-exfiltration/`.

## Requirements

- The `visual-explainer` plugin, written against version 0.14.0:
  `/plugin marketplace add nicobailon/visual-explainer`, then
  `/plugin install visual-explainer@visual-explainer-marketplace`.
- `playwright-core` in the plugin directory, for the render check:
  `npm install --no-save --prefix <plugin dir> playwright-core`.
- The docs environment, for the build check:
  `python3 -m venv .venv-docs && .venv-docs/bin/python -m pip install -r requirements-docs.txt`.

The plugin directory is
`~/.claude/plugins/cache/visual-explainer-marketplace/visual-explainer/<version>`.

## Steps

1. Read `docs/examples/<scenario>/README.md`. Facts come from there; do not
   invent behavior.
1. Invoke the `visual-explainer:visual-explainer` skill and read the
   references it names. Use the `blueprint` register.
1. Copy `template.src.html` from this directory to
   `docs/examples/<scenario>/visual-demo.src.html`. Keep the head, the site
   bar, and the final script unchanged. Replace the body.
1. Make the title the one sentence the reader must leave with. Put the answer
   in the first screen, one claim per figure, a verb on every arrow, and the
   claim in every caption.
1. Render with `node <plugin dir>/kit/render.mjs <path>/visual-demo.src.html`.
   It writes `visual-demo.html` and preview sheets (git-ignored). Fix every
   `✗` it lists, then look at the sheet once.
1. Link the page from the scenario README with one sentence, as in
   `docs/examples/document-exfiltration/README.md`.
1. Verify: run `.venv-docs/bin/python -m unittest discover -s scripts/docs
   -p 'test_*.py'` and `scripts/docs/serve build`. Open the page and click
   the theme button in both directions.
1. Commit both `visual-demo.src.html` and `visual-demo.html`. The page is not
   in `nav`; the glob in `stage.py` needs no edit.

## Branding contract

The template head holds the single copy of these values. Do not hand-pick
other colors or fonts.

| Part | Value |
| --- | --- |
| Fonts | Roboto and Roboto Mono, from the site's Google Fonts URL |
| Header bar | `#ee0000` with the site logo inline, so the page works from disk |
| Favicon | The site's Red Hat favicon, inline |
| Accent | `#a60000` in light mode, `#f56e6e` in dark mode |
| Surfaces | Material white and slate (`#1e2029` background in dark mode) |
| Status | The `ok`, `warn`, `risk`, and `info` tokens only |
| Theme | `data-site` attribute; the header button flips it |

The page starts in the theme saved by its own button, so a reader's choice
survives a reload. Without one, it uses the theme chosen on the site (read from
the Material palette key in `localStorage`), then the operating system.

If `overrides/assets/stylesheets/redhat.css` changes, update the template head
and render the existing demos again.

## Pitfalls

- Put free-standing SVG labels directly under the `<svg>` or inside a `.ve-n`
  node. Text in other groups has no fill rule and renders black, which is
  unreadable in dark mode.
- Keep labels at 14 units or more, at least 40 units between boxes, and text
  within its box (about 7.5 units per character). The render check flags
  overlaps and clipped labels.
- Use synthetic data and the controlled demo servers only. Show no real
  endpoints.
- For security scenarios, use the README's perimeter, classification, and
  trust-level wording.
- Do not use `<ve-ask>` or other reply prompts. The pages are public, and a
  reader has no agent to receive a reply.
- After upgrading the plugin, render one existing demo and compare it before
  committing the new output.
