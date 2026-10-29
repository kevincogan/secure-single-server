#!/usr/bin/env python3
"""Synthetic accounts from interrupted capacity cases are suspended."""
import importlib.machinery
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
loader = importlib.machinery.SourceFileLoader('capacity', str(ROOT / 'scripts/pricetag/capacity'))
spec = importlib.util.spec_from_loader(loader.name, loader)
capacity = importlib.util.module_from_spec(spec)
loader.exec_module(capacity)


class CleanupTest(unittest.TestCase):
    def test_partial_case_suspends_only_its_created_accounts(self):
        updates = []

        def request(method, resource, payload=None):
            if method == 'GET':
                return [{'user_id': name} for name in
                        ('perf-new-00', 'perf-new-01', 'perf-old-00', 'admin')]
            updates.append(payload)

        self.assertTrue(capacity.suspend_synthetic({'perf-new'}, request))
        self.assertEqual(updates, [
            {'subject': 'perf-new-00', 'active': False},
            {'subject': 'perf-new-01', 'active': False}])

    def test_failed_cleanup_can_be_retried(self):
        attempts = []

        def request(method, resource, payload=None):
            if method == 'GET':
                return [{'user_id': 'perf-new-00'}]
            attempts.append(payload)
            if len(attempts) == 1:
                raise RuntimeError('temporary management failure')

        self.assertFalse(capacity.suspend_synthetic({'perf-new'}, request))
        self.assertTrue(capacity.suspend_synthetic({'perf-new'}, request))
        self.assertEqual(len(attempts), 2)


if __name__ == '__main__':
    unittest.main()
