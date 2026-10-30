// Browser acceptance uses synthetic accounts on a mock benchmark deployment.
// Supply a server certificate and protected key directory; never enable traces
// or screenshots while a one-time key is visible.
'use strict';
const downloadKey=require('./key-download.cjs');
require('./mock-guard.cjs')();
const { chromium } = require('playwright');
const fs = require('node:fs');
const path = require('node:path');
const { X509Certificate, createHash } = require('node:crypto');
const assert = require('node:assert/strict');
const base = process.env.GATEWAY_URL;
const directory = process.env.KEY_DIRECTORY;
if (!base || !directory || process.env.MOCK_DEPLOYMENT_CONFIRMED !== 'yes') {
  throw new Error('Set GATEWAY_URL, KEY_DIRECTORY and MOCK_DEPLOYMENT_CONFIRMED=yes for the benchmark only');
}
function readKey(name) {
  const file = path.join(directory, name + '.key');
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077)) throw new Error('Key file must be private');
  return fs.readFileSync(file, 'utf8').trim();
}
async function done(page, action) {
  await page.locator('#status').evaluate(el => { el.textContent = ''; });
  await action();
  await page.waitForFunction(() => document.querySelector('#status').textContent === 'Done');
}
(async () => {
  const cert = new X509Certificate(fs.readFileSync(path.join(directory, 'server.pem')));
  const pin = createHash('sha256').update(cert.publicKey.export({ type: 'spki', format: 'der' })).digest('base64');
  const browser = await chromium.launch({ args: ['--ignore-certificate-errors-spki-list=' + pin] });
  async function login(key) {
    const context = await browser.newContext();
    const page = await context.newPage();
    await page.goto(base + '/login');
    await page.locator('#api_key').fill(key);
    await Promise.all([page.waitForURL(url => url.pathname !== '/login'), page.getByRole('button', { name: 'Sign In', exact: true }).click()]);
    await page.goto(base + '/management');
    await page.waitForFunction(() => document.querySelector('#identity')?.textContent.startsWith('Signed in as '));
    return { page, context };
  }
  try {
    const { page: admin, context: adminContext } = await login(readKey('admin'));
    await admin.goto(base + '/admin');
    await admin.locator('#admin').waitFor({ state: 'visible' });
    await admin.locator('#user [name=subject]').fill('demo-ui-onboard');
    await admin.locator('#user [name=name]').fill('Demo UI Onboarding');
    await done(admin, () => admin.locator('#user button').click());
    await admin.locator('#vtab-safety-net').click();
    await admin.locator('#budget [name=subject]').selectOption('demo-ui-onboard');
    await admin.locator('#budget [name=monthly_usd]').fill('5');
    await done(admin, () => admin.getByRole('button', { name: 'Set override', exact: true }).click());
    // Verify the expandable per-user overrides list and inheritance.
    await admin.locator('#budgetDetails summary').click();
    await admin.locator('#budgetSearch [name=search]').fill('demo-ui-onboard');
    await done(admin,()=>admin.locator('#budgetSearch button').click());
    const overrideRow=admin.locator('#budgets tr').filter({hasText:'demo-ui-onboard'});
    await overrideRow.waitFor();assert.equal(await overrideRow.count(),1);
    admin.once('dialog',dialog=>dialog.accept());
    await done(admin,()=>overrideRow.getByRole('button',{name:'Remove override',exact:true}).click());
    assert.match(await admin.locator('#budgetCurrent').textContent(),/Inherits global default/);
    await admin.locator('#budget [name=monthly_usd]').fill('5');
    await done(admin,()=>admin.getByRole('button',{name:'Set override',exact:true}).click());
    await admin.locator('#vtab-people').click();
    await admin.locator('#onboard [name=subject]').selectOption('demo-ui-onboard');
    await admin.locator('#onboard [name=expiresIn]').fill('2d');
    await done(admin, () => admin.getByRole('button', { name: 'Issue key', exact: true }).click());
    const issued = await downloadKey(admin, '#onboardKey');
    assert.ok(issued.key, 'one-time onboarding key missing');
    await admin.locator('#onboardKey').getByRole('button', { name: 'Dismiss key', exact: true }).click();
    assert.equal(await admin.locator('#onboardKey').isVisible(), false);
    const { page: user, context: userContext } = await login(issued.key);user.on('dialog', dialog=>dialog.accept());
    assert.equal(await user.locator('#admin').isVisible(), false);
    const statuses = await user.evaluate(async () => {
      const result = [];
      for (const route of ['/api/v1/management/users', '/api/v1/management/prices', '/api/v1/admin/partner-users']) {
        result.push((await fetch(route, { headers: { 'X-Forwarded-User': 'admin', 'X-MaaS-Username': 'admin' } })).status);
      }
      return result;
    });
    assert.deepEqual(statuses, [403, 403, 403]);
    await done(user, () => user.getByRole('button', { name: 'List my keys', exact: true }).click());
    assert.ok(await user.locator('#keys button').count(), 'issued key absent from personal list');
    await user.locator('#key [name=name]').fill('demo-personal-key');
    await user.locator('#key [name=expiresIn]').fill('1d');
    await done(user, () => user.getByRole('button', { name: 'Create key', exact: true }).click());
    const personal = await downloadKey(user, '#newKey');
    assert.ok(personal.key, 'personal key missing');
    await done(user, () => user.getByRole('button', { name: 'List my keys', exact: true }).click());
    const row = user.locator('#keys p').filter({ hasText: personal.id });
    await done(user, () => row.getByRole('button', { name: 'Revoke', exact: true }).click());
    assert.equal(await row.locator('.key-status').textContent(), 'revoked');
    await userContext.close();
    await adminContext.close();
    console.log('PASS: UI user onboarding, budget save, finite-key issuance/login, role isolation, own-key creation and revocation');
  } finally { await browser.close(); }
})().catch(() => {
  // Avoid Playwright call logs exposing fields or one-time secret responses.
  console.error('FAIL: browser management acceptance; credentials and response bodies withheld');
  process.exitCode = 1;
});
