# SPDX-License-Identifier: Apache-2.0
"""Guard the narrowly scoped role-removal test and its recovery behavior."""

from copy import deepcopy

import pytest

from lifecycle_flow import RoleChange, role_ids

USER = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
ROLES = [{"id": "analyst-id", "name": "analyst"}, {"id": "default-id", "name": "defaults"}]


class Admin:
    """Model only the exact synthetic user and realm-role mapping calls."""

    def __init__(self) -> None:
        self.roles = deepcopy(ROLES)
        self.mutations = []
        self.lose_delete_response = False

    def __call__(self, path: str, method: str = "GET", value: object = None) -> object:
        if path == "/users/" + USER:
            assert method == "GET"
            return {"id": USER, "username": "analyst"}
        assert path == "/users/" + USER + "/role-mappings/realm"
        if method == "GET":
            return deepcopy(self.roles)
        self.mutations.append((method, deepcopy(value)))
        assert value == [ROLES[0]]
        if method == "DELETE":
            self.roles.remove(ROLES[0])
            if self.lose_delete_response:
                raise TimeoutError("simulated lost response")
        else:
            assert method == "POST"
            self.roles.append(deepcopy(ROLES[0]))


def test_role_mutation_and_restore_touch_only_one_exact_mapping() -> None:
    """Keep all other roles intact and make an already-restored call read-only."""
    admin = Admin()
    change = RoleChange(admin, USER)
    change.remove()
    assert admin.roles == [ROLES[1]]
    change.restore()
    change.restore()
    assert role_ids(admin.roles) == role_ids(ROLES)
    assert [v[0] for v in admin.mutations] == ["DELETE", "POST"]


def test_lost_delete_response_is_recovered_from_actual_mapping() -> None:
    """A transport exception must not leave a confirmed removal unrestored."""
    admin = Admin()
    change = RoleChange(admin, USER)
    admin.lose_delete_response = True
    with pytest.raises(TimeoutError):
        change.remove()
    change.restore()
    assert role_ids(admin.roles) == role_ids(ROLES)


def test_independent_mapping_change_aborts_restoration() -> None:
    """Do not overwrite a different operator's changes to authority."""
    admin = Admin()
    change = RoleChange(admin, USER)
    change.remove()
    admin.roles.append({"id": "other-id", "name": "other"})
    with pytest.raises(ValueError, match="Independent role change"):
        change.restore()
    assert [v[0] for v in admin.mutations] == ["DELETE"]


def test_independent_mapping_change_aborts_removal() -> None:
    """Require the exact original role set immediately before changing it."""
    admin = Admin()
    change = RoleChange(admin, USER)
    admin.roles.clear()
    with pytest.raises(ValueError, match="changed independently"):
        change.remove()
    assert not admin.mutations
