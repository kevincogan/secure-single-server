# SPDX-License-Identifier: Apache-2.0
"""Fixed common fragments preserve both exact issuer exports."""
import json
from copy import deepcopy
import pytest
import source_render as renderer


def test_common_realm_output_matches_recorded_structure():
    import hashlib
    expected = {'initial': '0591dbeed24437db537bdfcb9f2b80ceb0bebad7c6234998c751d7ffdf0747b2', 'management': '6a26d6da2736818f074de8dcaa965fd5b2985be9de306f5bd47db0c426130a3b', 'exchange': '963c59aeac93c5a6b26e494197f2ffea403d03318701e496a2af8289e869f7db'}
    for name, digest in expected.items():
        actual = json.dumps(renderer.realm_template(name), sort_keys=True, separators=(",", ":")).encode()
        assert hashlib.sha256(actual).hexdigest() == digest


def test_other_common_file_and_colliding_fields_are_refused(monkeypatch):
    read = renderer.read_json
    value = read(renderer.TEMPLATES / 'management-realm.json')
    common = read(renderer.TEMPLATES / 'realm-common.json')
    for changed in ({**value, '$common': '../outside.json'}, {**value, next(iter(common['fields'])): 'changed'}):
        monkeypatch.setattr(renderer, 'read_json', lambda path: deepcopy(changed if path.name == 'management-realm.json' else common))
        with pytest.raises(ValueError):
            renderer.realm_template('management')
    monkeypatch.setattr(renderer, 'read_json', read)
