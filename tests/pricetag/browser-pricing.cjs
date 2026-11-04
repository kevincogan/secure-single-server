'use strict';
const downloadKey=require('./key-download.cjs');
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
 async function price(page,model,input,output){await page.locator('#vtab-model-pricing').click();const form=page.locator('#price');await form.locator('[name=model]').fill(model);await form.locator('[name=provider]').fill('mock');await form.locator('[name=source_model]').fill('');for(const [name,value]of Object.entries({input_cost_per_mtok:input,output_cost_per_mtok:output,cache_write_cost_per_mtok:0,cache_read_cost_per_mtok:0}))await form.locator('[name='+name+']').fill(String(value));await done(page,()=>form.getByRole('button',{name:'Save rates',exact:true}).click());}
 async function spend(page,expected){await page.waitForFunction(async expected=>{const r=await fetch('/api/v1/whoami');const v=await r.json();return Math.abs(v.quota.spent_usd-expected)<1e-8;},expected,{timeout:30000,polling:500});}
 let policyPage, originalPolicy;
 async function policy(value){
  await policyPage.goto(base+'/admin');await policyPage.locator('#vtab-safety-net').click();await policyPage.locator('#safety-limit').waitFor();
  while(await policyPage.locator('#safety-net-body button[onclick^="removeSafetyModel"]').count())await policyPage.locator('#safety-net-body button[onclick^="removeSafetyModel"]').first().click();
  for(const model of value.allowed_over_limit_models){await policyPage.locator('#safety-model-add').fill(model);await policyPage.getByRole('button',{name:'Add model',exact:true}).click();}
  await policyPage.locator('#safety-limit').fill(String(value.default_monthly_usd));await policyPage.locator('#safety-enforced').setChecked(value.enforced);
  const response=policyPage.waitForResponse(r=>new URL(r.url()).pathname==='/api/v1/admin/safety-net'&&r.request().method()==='PUT');
  await policyPage.getByRole('button',{name:'Save safety net',exact:true}).click();assert.equal((await response).status(),200);
 }
 try{
  const {page:admin}=await login(fs.readFileSync(keyPath,'utf8').trim());await admin.goto(base+'/admin');await admin.locator('#admin').waitFor({state:'visible'});
  const subject='demo-price-'+Date.now();stage='onboard price-test user';
  await admin.locator('#user [name=subject]').fill(subject);await admin.locator('#user [name=name]').fill('Demo price verification');await done(admin,()=>admin.getByRole('button',{name:'Save user',exact:true}).click());
  await admin.locator('#vtab-user-keys').click();await admin.locator('#onboard [name=subject]').selectOption(subject);await admin.locator('#onboard [name=expiresIn]').fill('1d');await done(admin,()=>admin.getByRole('button',{name:'Issue key',exact:true}).click());
  const issued=await downloadKey(admin, '#onboardKey');await admin.locator('#onboardKey').getByRole('button',{name:'Dismiss key',exact:true}).click();
  const {page:user}=await login(issued.key);user.on('dialog', dialog=>dialog.accept());
  stage='set initial rate through UI';await price(admin,'fixture-cheap',1000,2000);
  async function infer(){const status=await user.evaluate(async key=>(await fetch('/v1/chat/completions',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+key},body:JSON.stringify({model:'mock/demo-cheap',messages:[{role:'user',content:'synthetic price verification'}],max_completion_tokens:16})})).status,issued.key);assert.equal(status,200);}
  stage='readable model rates and edit';
  await admin.locator('#priceSearch [name=search]').fill('fixture-cheap');
  await done(admin,()=>admin.locator('#priceSearch button').click());
  const rateRow=admin.locator('#prices tr').filter({hasText:'fixture-cheap'});assert.equal(await rateRow.count(),1);assert.match(await rateRow.textContent(),/Managed override/);
  await rateRow.getByRole('button',{name:'Edit rates',exact:true}).click();assert.equal(await admin.locator('#price [name=input_cost_per_mtok]').inputValue(),'1000');
  stage='first charge';await infer();await spend(user,.008);
  stage='change future rate through UI';await price(admin,'fixture-cheap',2000,2000);await spend(user,.008);
  stage='second charge preserves history';await infer();await spend(user,.018);
  const models=await user.evaluate(async()=>await(await fetch('/api/v1/dashboard/models')).json());
  console.log('PASS: UI rates changed; first charge stayed $0.008; second request charged $0.010; total $0.018');
  assert.deepEqual(models.map(m=>m.model),['fixture-cheap']);
  console.log('PASS: usage is attributed to the upstream model; no alias price update was needed');
  stage='set individual budget through UI';
  await admin.locator('#vtab-user-quota').click();await admin.locator('#budget [name=subject]').selectOption(subject);await admin.locator('#budget [name=monthly_usd]').fill('0.01');await done(admin,()=>admin.getByRole('button',{name:'Set override',exact:true}).click());
  policyPage=await admin.context().newPage();await policyPage.goto(base+'/admin');
  originalPolicy=await policyPage.evaluate(async()=>await(await fetch('/api/v1/admin/safety-net')).json());
  async function inferenceStatuses(){return await user.evaluate(async key=>{
   const statuses=[];
   for(const [route,body]of [['/v1/chat/completions',{messages:[{role:'user',content:'synthetic quota test'}],max_completion_tokens:16}],['/v1/responses',{input:'synthetic quota test',max_output_tokens:16}],['/v1/messages',{messages:[{role:'user',content:'synthetic quota test'}],max_tokens:16}]]){
    const headers={'Content-Type':'application/json'};if(route==='/v1/messages'){headers['x-api-key']=key;headers['anthropic-version']='2023-06-01';}else headers.Authorization='Bearer '+key;
    const response=await fetch(route,{method:'POST',headers,body:JSON.stringify({...body,model:'mock/demo-cheap'})});statuses.push(response.status);await response.text();
   }return statuses;
  },issued.key);}
  stage='paid requests blocked after UI budget change';await policy({...originalPolicy,enforced:true,allowed_over_limit_models:[]});await new Promise(r=>setTimeout(r,17000));
  assert.deepEqual(await inferenceStatuses(),[429,429,429]);
  stage='configured unused models offered in safety net';
  await policyPage.locator('#vtab-safety-net').click();
  await policyPage.waitForFunction(()=>[...document.querySelectorAll('#safety-model-list option')].some(option=>option.value==='fixture-cheap'));
  stage='upstream model exception configured through UI';await policy({...originalPolicy,enforced:true,allowed_over_limit_models:['fixture-cheap']});await new Promise(r=>setTimeout(r,17000));
  const allowed=await inferenceStatuses();console.log('Upstream-ID exception statuses: '+allowed.join(', '));assert.deepEqual(allowed,[200,200,200]);
  stage='exception removed through UI';await policy({...originalPolicy,enforced:true,allowed_over_limit_models:[]});await new Promise(r=>setTimeout(r,17000));assert.deepEqual(await inferenceStatuses(),[429,429,429]);
  console.log('PASS: UI user budget and global exception controlled Chat, Responses and Messages admission');
 }finally{try{if(originalPolicy)await policy(originalPolicy);}finally{await browser.close();}}
})().catch(()=>{console.error('FAIL at '+stage+'; credentials and response bodies withheld');process.exitCode=1});
