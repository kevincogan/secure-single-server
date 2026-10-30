'use strict';
require('./mock-guard.cjs')();
const {chromium}=require('playwright');
const fs=require('node:fs'),path=require('node:path');
const {X509Certificate,createHash}=require('node:crypto');
const assert=require('node:assert/strict');
let stage='setup';
(async()=>{
 if(process.env.MOCK_DEPLOYMENT_CONFIRMED!=='yes')throw new Error('mock confirmation required');
 const dir=process.env.KEY_DIRECTORY,base=process.env.GATEWAY_URL;
 const keyPath=path.join(dir,'admin.key');assert.equal(fs.statSync(keyPath).mode&0o077,0);
 const cert=new X509Certificate(fs.readFileSync(path.join(dir,'server.pem')));
 const pin=createHash('sha256').update(cert.publicKey.export({type:'spki',format:'der'})).digest('base64');
 const browser=await chromium.launch({args:['--ignore-certificate-errors-spki-list='+pin]});
 async function login(key){const context=await browser.newContext();const page=await context.newPage();await page.goto(base+'/login');await page.locator('#api_key').fill(key);await Promise.all([page.waitForURL(u=>u.pathname!=='/login'),page.getByRole('button',{name:'Sign In',exact:true}).click()]);return {context,page};}
 async function done(page,action){await page.locator('#status').evaluate(el=>el.textContent='');await action();await page.waitForFunction(()=>document.querySelector('#status').textContent==='Done');}
 let admin, originalPolicy, removeTestRoute=false;
 async function policy(value){
  await admin.goto(base+'/admin');await admin.locator('#vtab-pricing-discounts').click();await admin.locator('#pricing-discount-version').waitFor();
  while(await admin.locator('#pricing-discount-rules button').count())await admin.locator('#pricing-discount-rules button').first().click();
  for(const rule of value.rules){
   await admin.getByRole('button',{name:'Add rule',exact:true}).click();
   for(const name of ['name','provider','model_prefix','multiplier'])await admin.locator('[data-pd='+name+']').last().fill(String(rule[name]??''));
  }
  await admin.locator('#pricing-discount-version').fill(value.version);
  const refreshed=admin.waitForResponse(r=>new URL(r.url()).pathname==='/api/v1/admin/pricing/refresh'&&r.request().method()==='POST',{timeout:90000});
  await admin.getByRole('button',{name:'Save pricing policy',exact:true}).click();
  const response=await refreshed;assert.equal(response.status(),200);assert.equal((await response.json()).error,undefined);
 }
 async function rates(){const row=await admin.evaluate(async()=>{const data=await(await fetch('/api/v1/pricing?used=0')).json();return data.models.find(m=>m.model==='gpt-4o-mini');});assert.ok(row);return row;}
 try{
  ({page:admin}=await login(fs.readFileSync(keyPath,'utf8').trim()));await admin.goto(base+'/admin');await admin.locator('#admin').waitFor({state:'visible'});
  originalPolicy=await admin.evaluate(async()=>await(await fetch('/api/v1/admin/pricing-discounts')).json());
  fs.writeFileSync(path.join(dir,'discount-policy-before-test.json'),JSON.stringify(originalPolicy,null,2),{mode:0o600});
  const policyFor=multiplier=>({version:'synthetic-demo-'+multiplier,rules:[{name:'synthetic-demo',model_prefix:'gpt-4o-mini',multiplier}]});
  stage='apply undiscounted imported rate';await policy(policyFor(1));const before=await rates();
  stage='UI half-price policy';await policy(policyFor(.5));const after=await rates();
  assert.ok(Math.abs(after.input_cost_per_mtok-before.input_cost_per_mtok*.5)<1e-9);assert.ok(Math.abs(after.output_cost_per_mtok-before.output_cost_per_mtok*.5)<1e-9);
  console.log('PASS: UI discount policy persisted, refresh halved imported rates');
 }finally{try{if(originalPolicy){await policy(originalPolicy);console.log('Original discount policy restored through UI');}}finally{await browser.close();}}
})().catch(()=>{console.error('FAIL at '+stage+'; credentials and sensitive details withheld');process.exitCode=1});
