# SPDX-License-Identifier: Apache-2.0
"""Guard temporary supported key rotation and exact restoration."""

from copy import deepcopy

import pytest

from key_rotation_flow import KEYS, RealmKeyProbe


class Admin:
    """Model one owned realm, including generated settings and uncertain POST."""

    def __init__(self) -> None:
        self.values = [{"id": "original", "name": "rsa-generated", "parentId": "realm",
            "providerId": "rsa-generated", "providerType": "org.keycloak.keys.KeyProvider",
            "config": {"priority": ["100"]}}]
        self.mutations = []
        self.lose_post = False

    def __call__(self, path: str, method: str = "GET", value: object = None) -> object:
        if path == KEYS:
            assert method == "GET"
            return deepcopy(self.values)
        self.mutations.append((path, method))
        if method == "POST":
            assert path == "/components"
            made = {**deepcopy(value), "id": "new"}
            made["config"]["certificate"] = ["opaque-generated-fixture"]
            self.values.append(made)
            if self.lose_post:
                raise TimeoutError("response lost")
        else:
            assert method == "DELETE" and path == "/components/new"
            self.values = [v for v in self.values if v["id"] != "new"]


def test_supported_overlap_leaves_original_keys_unchanged() -> None:
    """Only the freshly created provider may be deleted."""
    admin = Admin()
    before = deepcopy(admin.values)
    probe = RealmKeyProbe(admin)
    assert probe.model["config"]["priority"] == ["101"]
    with probe.active() as value:
        assert value["id"] == "new" and admin.values[0] == before[0]
    assert admin.values == before
    assert admin.mutations == [("/components", "POST"), ("/components/new", "DELETE")]


def test_lost_create_response_restores_observed_exact_provider() -> None:
    """An uncertain POST is observed, not retried and not silently ignored."""
    admin = Admin()
    before = deepcopy(admin.values)
    admin.lose_post = True
    with pytest.raises(TimeoutError):
        with RealmKeyProbe(admin).active():
            pytest.fail("must not continue after uncertain response")
    assert admin.values == before and len(admin.mutations) == 2


def test_probe_failure_restores_original_inventory() -> None:
    """A failed native check cannot leave the temporary signer active."""
    admin = Admin()
    before = deepcopy(admin.values)
    with pytest.raises(AssertionError):
        with RealmKeyProbe(admin).active():
            raise AssertionError("probe failure")
    assert admin.values == before


def test_independently_changed_temporary_provider_not_deleted() -> None:
    """Never overwrite or delete an independently altered authority."""
    admin = Admin()
    with pytest.raises(ValueError, match="changed independently"):
        with RealmKeyProbe(admin).active():
            admin.values[1]["config"]["priority"] = ["500"]
    assert len(admin.mutations) == 1


def test_other_realm_parent_inventory_rejected_before_mutation() -> None:
    """A mixed-realm inventory cannot be treated as an owned authority."""
    admin = Admin()
    admin.values.append({**admin.values[0], "id": "other", "parentId": "other-realm"})
    with pytest.raises(ValueError, match="one-realm"):
        RealmKeyProbe(admin)
    assert admin.mutations == []
