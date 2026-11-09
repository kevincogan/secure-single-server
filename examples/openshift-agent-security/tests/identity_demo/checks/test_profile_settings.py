# SPDX-License-Identifier: Apache-2.0
"""Signed-in preparation status exposes capacity without a browser mutation route."""
from dataclasses import replace
import pytest

@pytest.mark.parametrize('cluster_jira', [False, True])
def test_automatic_settings_explains_the_configured_jira_view(tmp_path, cluster_jira):
    from checks.support.automatic_warm_pool import automatic
    driver, client, _, _ = automatic(tmp_path)
    if cluster_jira:
        driver.config = replace(driver.config, jira_view_url='https://adapter.test:8443')
    page = client.get('/settings')
    assert page.status_code == 200
    assert '/settings/prepare' not in page.text
    assert client.post('/settings/prepare', data={'csrf': 'csrf-fixture'}).status_code == 404
    assert ('authenticated, read-only run view' in page.text) is cluster_jira
    assert ('preview on the operator machine' in page.text) is not cluster_jira
