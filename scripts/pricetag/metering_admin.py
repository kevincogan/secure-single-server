"""Private management API client; no deployment-owned business-table writes."""
import json
import math
import os
from pathlib import Path
import re
import urllib.error
import urllib.request

DEPLOY = Path('/etc/praxis-pricetag')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(method, resource, payload=None):
    if os.geteuid() != 0:
        raise ValueError('run with sudo on the gateway host')
    if resource not in ('users', 'budgets', 'prices', 'policy', 'keys', 'key-revocations'):
        raise ValueError('unsupported management resource')
    secret = (DEPLOY / 'management-secret').read_text().strip()
    if not secret:
        raise ValueError('management credential is not configured')
    req = urllib.request.Request('http://127.0.0.1:18087/api/v1/management/' + resource,
        None if payload is None else json.dumps(payload).encode(), method=method,
        headers={'Authorization': 'Bearer ' + secret, 'Content-Type': 'application/json'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(req, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise ValueError(f'PriceTag management returned HTTP {error.code} for {resource}') from None


def provision(subject, name=None, budget=None, admin=False):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}', subject):
        raise ValueError('invalid subject')
    if budget is not None and (not math.isfinite(budget) or not .01 <= budget <= 10000
            or not math.isclose(budget * 100, round(budget * 100), rel_tol=0, abs_tol=1e-8)):
        raise ValueError('monthly-usd must be 0.01–10000 with at most two decimal places')
    if admin and subject != 'admin':
        raise ValueError('bootstrap administrator must be admin')
    body = {'subject': subject}
    if name is not None:
        body['name'] = name
    if admin:
        body['role'] = 'super_admin'
    request('PUT', 'users', body)
    if budget is not None:
        request('PUT', 'budgets', {'subject': subject, 'monthly_usd': budget})


def ensure_prices(models, sources=None):
    # Praxis rewrites the public alias before metering; usage contains the
    # upstream ID. Creating alias-only rows would not price those events.
    prices = {p['Model'] for p in request('GET', 'prices') or []}
    for model in models:
        billed_model = model['model']
        source = (sources or {}).get(model['id'], billed_model)
        if billed_model in prices:
            continue
        if source not in prices:
            print(f'No source price for {billed_model}; configured PriceTag fallback rates apply.')
            continue
        request('PUT', 'prices', {'model': billed_model, 'provider': model['provider'], 'source_model': source})
        prices.add(billed_model)


def bootstrap(path):
    config = json.loads(Path(path).read_text())
    request('PUT', 'policy', {'default_monthly_usd': config['monthly_usd'], 'enforced': True,
                            'allowed_over_limit_models': []})
    ensure_prices(config['models'], config['sources'])


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bootstrap', required=True, type=Path)
    args = parser.parse_args()
    bootstrap(args.bootstrap)
