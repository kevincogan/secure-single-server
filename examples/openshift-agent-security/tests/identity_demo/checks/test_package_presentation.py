# SPDX-License-Identifier: Apache-2.0
"""Snapshot packaging requires real passing receipts and escapes display content."""

import json

import pytest

from package_presentation import build, bullets, page


def test_presentation_text_is_escaped() -> None:
    """Untrusted text never becomes active HTML in the offline presentation."""
    assert '<script>' not in page('<script>', bullets(['<script>']), 30)
    assert '&lt;script&gt;' in bullets(['<script>'])


def test_failed_rehearsal_cannot_be_packaged_as_acceptance(tmp_path: object) -> None:
    """Reject incomplete evidence before screenshots or recording are loaded."""
    allow, deny = tmp_path / 'allow', tmp_path / 'deny'
    allow.mkdir()
    deny.mkdir()
    for directory, name, value in [
        (allow, 'allow.walkthrough.summary.json', {'passed': False}),
        (deny, 'deny.walkthrough.summary.json', {'passed': True}),
        (allow, 'allow.gateway.summary.json', {'passed': True}),
        (allow, 'allow.inference.summary.json', {'http_status': 200}),
    ]:
        (directory / name).write_text(json.dumps(value))
    with pytest.raises(ValueError, match='Passing model analyst'):
        build(allow, deny, tmp_path / 'missing.png')
