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
 try{
  const {page:admin}=await login(fs.readFileSync(keyPath,'utf8').trim());await admin.goto(base+'/admin');await admin.locator('#admin').waitFor({state:'visible'});
  const subject='demo-offboard-'+Date.now();stage='UI onboarding';
  await admin.locator('#user [name=subject]').fill(subject);await admin.locator('#user [name=name]').fill('Offboarding verification');await done(admin,()=>admin.locator('#user button').click());
  await admin.locator('#onboard [name=subject]').selectOption(subject);await admin.locator('#onboard [name=expiresIn]').fill('1d');await done(admin,()=>admin.getByRole('button',{name:'Issue key',exact:true}).click());
  const issued=await downloadKey(admin, '#onboardKey');await admin.locator('#onboardKey').getByRole('button',{name:'Dismiss key',exact:true}).click();
  const {page:user}=await login(issued.key);user.on('dialog', dialog=>dialog.accept());await user.goto(base+'/management');
  stage='personal key creation';await user.locator('#key [name=name]').fill('own-key');await user.locator('#key [name=expiresIn]').fill('1h');await done(user,()=>user.locator('#key button').click());
  const personal=await downloadKey(user, '#newKey');
  async function infer(key){return await user.evaluate(async key=>{
   const r=await fetch('/v1/chat/completions',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+key},body:JSON.stringify({model:'mock/demo-cheap',messages:[{role:'user',content:'offboarding check'}],max_completion_tokens:16})});await r.text();return r.status;
  },key);}
  assert.equal(await infer(personal.key),200);
  stage='personal budget display';await user.goto(base+'/dashboard');await user.locator('#standalone-budget').waitFor({state:'visible'});
  stage='UI deactivate';await admin.locator('#user [name=active]').selectOption('false');await done(admin,()=>admin.locator('#user button').click());
  // Gateway authentication/admission may have bounded caches.
  await new Promise(r=>setTimeout(r,17000));
  stage='inactive session and inference denied';
  const sessionStatus=await user.evaluate(async()=>(await fetch('/api/v1/whoami')).status);assert.equal(sessionStatus,403);
  for(const key of [issued.key,personal.key]){const status=await infer(key);assert.ok([403,429].includes(status),'inactive account must receive an authorization/admission denial, not a service error');console.log('Inactive key inference HTTP '+status);}
  console.log('PASS: UI deactivation denies existing session, onboarding key and personal key; personal budget visible');
 }finally{await browser.close();}
})().catch(()=>{console.error('FAIL at '+stage+'; sensitive details withheld');process.exitCode=1});
