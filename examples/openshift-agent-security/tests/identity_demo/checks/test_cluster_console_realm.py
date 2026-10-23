# SPDX-License-Identifier: Apache-2.0
"""Scope mapping never grants the worker realm/user administration."""
from uuid import uuid4

import pytest

from cluster_console_realm import ACTOR, grants


def test_only_two_role_ids_and_one_service_account_receive_scope_mapping():
    actor = str(uuid4())
    roles = {name:str(uuid4()) for name in ('analyst','viewer')}
    policy, permission = grants(actor,roles)
    assert policy['users'] == [actor] and policy['type'] == 'user'
    assert permission['resourceType'] == 'Roles'
    assert set(permission['resources']) == set(roles.values())
    assert permission['scopes'] == ['map-role-client-scope']
    assert permission['policies'] == [ACTOR]
    assert permission['decisionStrategy'] == 'UNANIMOUS'
    for invalid in ({'analyst':roles['analyst']}, {**roles,'administrator':str(uuid4())},
                    {**roles,'viewer':roles['analyst']}, {**roles,'viewer':'Roles'}):
        with pytest.raises(ValueError): grants(actor,invalid)
    with pytest.raises(ValueError): grants('service-account-name',roles)
