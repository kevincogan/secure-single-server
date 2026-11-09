# SPDX-License-Identifier: Apache-2.0
"""Shared unused context retirement test setup; contains no collected tests."""
import hashlib
from checks.support.automatic_warm_pool import automatic
from checks.support.console import operator

def idle_installation(tmp_path):
    driver, client, contexts, _ = automatic(tmp_path)
    response = client.post('/internal/operator/console/pool', headers=operator(driver), json={
        'action': 'automatic', 'enabled': False, 'receipt_sha256': 'c'*64, 'retired_workloads': []})
    assert response.status_code == 200
    with driver.store.transaction() as db:
        db.execute('UPDATE console_worker SET updated=0')
        db.execute('UPDATE console_preparer SET updated=0')
        row = db.execute('SELECT context FROM console_pool_items WHERE workload=?',
                         (contexts[0]['workload'],)).fetchone()
    return driver, client, contexts, hashlib.sha256(row['context'].encode()).hexdigest()
