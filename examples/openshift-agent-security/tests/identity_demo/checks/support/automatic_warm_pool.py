# SPDX-License-Identifier: Apache-2.0
"""A partly filled profile pool for concurrency and recovery checks."""
from checks.support.pool_profiles import prepare, setup


def automatic(tmp_path):
    driver, client, worker = setup(tmp_path)
    contexts = tuple(prepare(driver, client) for _ in range(4))
    return driver, client, contexts, worker
