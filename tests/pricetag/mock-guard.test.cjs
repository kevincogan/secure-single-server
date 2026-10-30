'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const assert = require('node:assert/strict');
const guard = require('./mock-guard.cjs');
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pricetag-guard-'));
const origin = 'https://localhost:8443';
process.env.GATEWAY_URL = origin;
process.env.MOCK_DEPLOYMENT_CONFIRMED = 'yes';
function write(name, value) { fs.writeFileSync(path.join(root, name), value); }
try {
  fs.mkdirSync(path.join(root, 'quadlets'));
  fs.mkdirSync(path.join(root, 'gateway'));
  write('metering.env', 'MANAGEMENT_PUBLIC_ORIGIN=' + origin + '\n');
  write('models.json', JSON.stringify([{id:'mock/demo-cheap',provider:'mock',model:'fixture-cheap'}]));
  const unit = 'Network=pricetag-mock.network\nSecret=pricetag-mock-ui-v1,type=env,target=CUSTOM_MOCK_API_KEY\n';
  write('quadlets/pricetag-gateway.container', unit);
  const config = {filter_chains:[{filters:[{filter:'load_balancer',clusters:[{endpoints:['pricetag-provider:18080','pricetag-provider:18081']}]}]}]};
  write('gateway/gateway.json', JSON.stringify(config));
  guard(root);
  process.env.GATEWAY_URL = 'https://other.example:8443';
  assert.throws(() => guard(root));
  process.env.GATEWAY_URL = origin;
  write('quadlets/pricetag-gateway.container', unit.replace('pricetag-mock-ui-v1', 'real-provider-key'));
  assert.throws(() => guard(root));
  write('quadlets/pricetag-gateway.container', unit);
  config.filter_chains[0].filters[0].clusters[0].endpoints.push('api.openai.com:443');
  write('gateway/gateway.json', JSON.stringify(config));
  assert.throws(() => guard(root));
  console.log('PASS: mock guard rejects wrong gateway, real credential references and external providers');
} finally { fs.rmSync(root, {recursive:true,force:true}); }
