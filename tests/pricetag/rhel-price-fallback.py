#!/usr/bin/env python3
"""Verify bootstrap pricing through service APIs on the mock RHEL host."""
import contextlib
import importlib.machinery
import importlib.util
import io
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/pricetag'))
import metering_admin


def main():
    loader = importlib.machinery.SourceFileLoader('benchmark', str(ROOT / 'scripts/pricetag/benchmark'))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    benchmark = importlib.util.module_from_spec(spec)
    loader.exec_module(benchmark)
    benchmark.require_mock(Path('/etc/praxis-pricetag'))
    # Unique, unrouted synthetic IDs cannot alter prices of demo traffic.
    target = 'test-pricing-' + uuid.uuid4().hex
    source = target + '-source'
    alias = 'test/' + target
    models = [{'id': alias, 'model': target, 'provider': 'mock'}]
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        metering_admin.ensure_prices(models)
    prices = {p['Model']: p for p in metering_admin.request('GET', 'prices')}
    assert target not in prices and alias not in prices
    assert 'fallback rates apply' in output.getvalue()
    print('PASS: missing rate permits setup with a warning and no invented price')
    metering_admin.request('PUT', 'prices', {
        'model': source, 'provider': 'mock', 'input_cost_per_mtok': 1,
        'output_cost_per_mtok': 2, 'cache_write_cost_per_mtok': 0,
        'cache_read_cost_per_mtok': 0})
    metering_admin.ensure_prices(models, {alias: source})
    prices = {p['Model']: p for p in metering_admin.request('GET', 'prices')}
    assert target in prices and alias not in prices
    assert prices[target]['InputCost'] == prices[source]['InputCost']
    assert prices[target]['OutputCost'] == prices[source]['OutputCost']
    print('PASS: API source copy prices the billed upstream ID, not an unused alias')
    print('Synthetic un-routed price records retained for audit: ' + target)


if __name__ == '__main__':
    main()
