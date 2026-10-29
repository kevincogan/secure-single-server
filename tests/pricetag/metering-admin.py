#!/usr/bin/env python3
"""Management clients must use service APIs without resetting user state."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts/pricetag'))
import metering_admin

class ProvisioningTest(unittest.TestCase):
    @patch('metering_admin.request')
    @patch('metering_admin.os.geteuid',return_value=0)
    def test_rotation_preserves_budget_and_role(self,uid,request):
        metering_admin.provision('alice')
        request.assert_called_once_with('PUT','users',{'subject':'alice'})

    @patch('metering_admin.request')
    @patch('metering_admin.os.geteuid',return_value=0)
    def test_explicit_budget_is_separate_api_operation(self,uid,request):
        metering_admin.provision('alice','Alice',5)
        self.assertEqual(request.call_args_list[0].args,('PUT','users',{'subject':'alice','name':'Alice'}))
        self.assertEqual(request.call_args_list[1].args,('PUT','budgets',{'subject':'alice','monthly_usd':5}))

    @patch('metering_admin.request')
    @patch('metering_admin.os.geteuid',return_value=0)
    def test_reject_invalid_identity_budget_and_admin(self,uid,request):
        for subject,budget,admin in [("bad'subject",5,False),('alice',float('nan'),False),('alice',0,False),('alice',.001,False),('alice',5,True)]:
            with self.assertRaises(ValueError):metering_admin.provision(subject,budget=budget,admin=admin)
        request.assert_not_called()

class PricingTest(unittest.TestCase):
    @patch('metering_admin.request')
    def test_existing_upstream_rate_needs_no_alias_copy(self, request):
        request.return_value = [{'Model': 'upstream-model'}]
        metering_admin.ensure_prices([{'id': 'external/model', 'model': 'upstream-model', 'provider': 'external'}])
        request.assert_called_once_with('GET', 'prices')

    @patch('metering_admin.request')
    def test_explicit_source_populates_billed_id_once(self, request):
        request.return_value = [{'Model': 'source-model'}]
        models = [{'id': alias, 'model': 'upstream-model', 'provider': 'external'}
                  for alias in ('external/one', 'external/two')]
        metering_admin.ensure_prices(models, {m['id']: 'source-model' for m in models})
        self.assertEqual(request.call_count, 2)
        request.assert_called_with('PUT', 'prices', {
            'model': 'upstream-model', 'provider': 'external', 'source_model': 'source-model'})

    @patch('metering_admin.request')
    def test_missing_rate_uses_service_fallback_without_writes(self, request):
        request.return_value = []
        metering_admin.ensure_prices([{'id': 'external/model', 'model': 'missing-model', 'provider': 'external'}])
        request.assert_called_once_with('GET', 'prices')

if __name__=='__main__':unittest.main()
