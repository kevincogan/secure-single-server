'use strict';
// Read the actual deployment inputs before browser mutations; no optional API.
const fs = require('node:fs');
const assert = require('node:assert/strict');
module.exports = function (root = '/etc/praxis-pricetag') {
  assert.equal(process.env.MOCK_DEPLOYMENT_CONFIRMED, 'yes');
  const env = fs.readFileSync(root + '/metering.env', 'utf8');
  const origin = env.split('\n').find(line => line.startsWith('MANAGEMENT_PUBLIC_ORIGIN=')).split('=').slice(1).join('=');
  assert.equal(process.env.GATEWAY_URL, origin, 'browser target must match this mock deployment');
  const models = JSON.parse(fs.readFileSync(root + '/models.json'));
  assert.ok(models.length && models.every(m => m.provider === 'mock' && m.id.startsWith('mock/') && /^fixture(?:-[a-z0-9-]+)?$/.test(m.model)));
  const unit = fs.readFileSync(root + '/quadlets/pricetag-gateway.container', 'utf8');
  assert.ok(unit.includes('Network=pricetag-mock.network'));
  for (const line of unit.split('\n').filter(l => l.startsWith('Secret=') && l.includes('type=env'))) {
    assert.match(line, /^Secret=pricetag-mock-ui-v[0-9]+,type=env,target=CUSTOM_MOCK_API_KEY$/);
  }
  const config = JSON.parse(fs.readFileSync(root + '/gateway/gateway.json'));
  const endpoints = config.filter_chains.flatMap(chain => chain.filters.filter(f => f.filter === 'load_balancer').flatMap(f => f.clusters.flatMap(c => c.endpoints)));
  assert.ok(endpoints.includes('pricetag-provider:18080') && endpoints.includes('pricetag-provider:18081'));
  assert.ok(endpoints.every(e => /^(pricetag-provider:(18080|18081)|pricetag-metering:8080|127\.0\.0\.1:[0-9]+)$/.test(e)), 'external provider endpoint present');
};
