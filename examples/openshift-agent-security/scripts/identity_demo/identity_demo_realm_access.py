# SPDX-License-Identifier: Apache-2.0
"""Reuse Keycloak client credentials for owned-realm administration only."""
from __future__ import annotations

from deployment_profile import active_profile


def realm_token(request, base: str, credentials: dict) -> str:
    """Cluster clients never fall back to a bootstrap administrator password."""
    configured = credentials.get('realm_management')
    if configured is not None:
        profile = active_profile()
        if base not in (profile.origin('fixture-keycloak'), profile.origin('fixture-keycloak-upstream')):
            raise ValueError('Exact owned issuer required')
        client = configured.get(base)
        if (not isinstance(client, dict) or set(client) != {'client_id', 'client_secret'}
                or client['client_id'] != 'fixture-console-realm-coordinator'
                or not isinstance(client['client_secret'], str) or len(client['client_secret']) < 32
                or 'keycloak_admin' in credentials):
            raise ValueError('Dedicated realm client required; bootstrap credential refused')
        fields = {'grant_type': 'client_credentials', **client}
        path = '/realms/identity-demo/protocol/openid-connect/token'
    else:
        fields = {'grant_type': 'password', 'client_id': 'admin-cli', 'username': 'fixture-admin',
                  'password': credentials['keycloak_admin']}
        path = '/realms/master/protocol/openid-connect/token'
    return request(base, path, method='POST', fields=fields)[1]['access_token']
