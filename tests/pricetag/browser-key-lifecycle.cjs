'use strict';
const downloadKey=require('./key-download.cjs');
require('./mock-guard.cjs')();
const {chromium}=require('playwright');
const fs=require('node:fs'),path=require('node:path');
const {X509Certificate,createHash}=require('node:crypto');
const assert=require('node:assert/strict');
let stage='setup', throttledResponses=0;
(async()=>{
 if(process.env.MOCK_DEPLOYMENT_CONFIRMED!=='yes')throw new Error('mock confirmation required');
 const dir=process.env.KEY_DIRECTORY,base=process.env.GATEWAY_URL;
 const keyPath=path.join(dir,'admin.key');assert.equal(fs.statSync(keyPath).mode&0o077,0);
 const cert=new X509Certificate(fs.readFileSync(path.join(dir,'server.pem')));
 const pin=createHash('sha256').update(cert.publicKey.export({type:'spki',format:'der'})).digest('base64');
 const browser=await chromium.launch({args:['--ignore-certificate-errors-spki-list='+pin]});
 async function login(key){const context=await browser.newContext();const page=await context.newPage();page.on('response',r=>{if(r.status()===429)throttledResponses++;});await page.goto(base+'/login');await page.locator('#api_key').fill(key);await Promise.all([page.waitForURL(u=>u.pathname!=='/login'),page.getByRole('button',{name:'Sign In',exact:true}).click()]);return {context,page};}
 async function done(page,action){await page.locator('#status').evaluate(el=>el.textContent='');await action();await page.waitForFunction(()=>document.querySelector('#status').textContent==='Done');}
 try{
  const {page:admin}=await login(fs.readFileSync(keyPath,'utf8').trim());await admin.goto(base+'/admin');await admin.locator('#admin').waitFor({state:'visible'});
  const subject='demo-lifecycle-'+Date.now();stage='UI onboarding';
  await admin.locator('#user [name=subject]').fill(subject);await admin.locator('#user [name=name]').fill('Key lifecycle verification');await done(admin,()=>admin.locator('#user button').click());
  await admin.locator('#onboard [name=subject]').selectOption(subject);await admin.locator('#onboard [name=expiresIn]').fill('1d');await done(admin,()=>admin.getByRole('button',{name:'Issue key',exact:true}).click());
  const issued=await downloadKey(admin, '#onboardKey');await admin.locator('#onboardKey').getByRole('button',{name:'Dismiss key',exact:true}).click();
  const {page:user}=await login(issued.key);user.on('dialog', dialog=>dialog.accept());await user.goto(base+'/management');
  async function create(name,lifetime){await user.locator('#key [name=name]').fill(name);await user.locator('#key [name=expiresIn]').fill(lifetime);await done(user,()=>user.locator('#key button').click());return await downloadKey(user, '#newKey');}
  async function infer(key){return await user.evaluate(async key=>{const r=await fetch('/v1/chat/completions',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+key},body:JSON.stringify({model:'mock/demo-cheap',messages:[{role:'user',content:'synthetic key test'}],max_completion_tokens:16})});await r.text();return r.status;},key);}
  stage='duplicate submissions and additional keys';
  let posts=0,release;
  const gate=new Promise(resolve=>release=resolve);
  await user.route('**/me/keys', async route=>{
   if(route.request().method()!=='POST')return route.continue();
   posts++;await gate;await route.continue();
  });
  await user.locator('#key [name=name]').fill('double-click-test');
  await user.locator('#key [name=expiresIn]').fill('1h');
  await user.locator('#key').evaluate(form=>{form.requestSubmit();form.requestSubmit();});
  await user.waitForFunction(()=>document.querySelector('#key button').disabled);
  release();await user.waitForFunction(()=>document.querySelector('#status').textContent==='Done');
  assert.equal(posts,1);await user.unroute('**/me/keys');
  const first=await downloadKey(user,'#newKey');
  const second=await create('deliberate-additional-key','1h');assert.notEqual(first.id,second.id);
  assert.equal(await infer(first.key),200);assert.equal(await infer(second.key),200);
  const otherLogin=await login(second.key);await otherLogin.page.goto(base+'/manager');
  stage='cross-key usage aggregation';
  await otherLogin.page.waitForFunction(async()=>{const r=await fetch('/api/v1/org/usage');if(!r.ok)throw new Error('usage API HTTP '+r.status);const rows=await r.json();return rows.length===1&&rows[0].requests>=2;},{},{timeout:30000});
  await otherLogin.page.evaluate(()=>loadCharts());
  await otherLogin.page.waitForFunction(()=>chartsCache?.overview?.total_requests>=2 && chartsCache.models.length>0);
  await otherLogin.context.close();
  assert.match(await user.locator('[data-key-id="'+second.id+'"]').first().textContent(), /remaining/);
  stage='own key revocation';const own=await create('revoke-test','1h');assert.equal(await infer(own.key),200);
  await done(user,()=>user.getByRole('button',{name:'List my keys',exact:true}).click());await done(user,()=>user.locator('#keys p').filter({hasText:own.id}).getByRole('button',{name:'Revoke',exact:true}).click());
  assert.equal(await infer(own.key),401);
  stage='cross-user revocation denied';
  const adminKeys=await admin.evaluate(async()=>(await(await fetch('/me/keys')).json()).data);assert.ok(adminKeys.length);
  const cross=await user.evaluate(async id=>(await fetch('/me/keys/'+encodeURIComponent(id),{method:'DELETE'})).status,adminKeys[0].id);assert.ok([403,404].includes(cross));
  stage='finite key expiry';const short=await create('expiry-test','10s');assert.equal(await infer(short.key),200);await new Promise(r=>setTimeout(r,12000));assert.equal(await infer(short.key),401);
  stage='maximum lifetime enforced';await user.locator('#key [name=expiresIn]').fill('9999d');const rejected=user.waitForResponse(r=>new URL(r.url()).pathname==='/me/keys'&&r.request().method()==='POST');await user.locator('#key button').click();assert.equal((await rejected).status(),400);
  stage='replacement key preserves access';const replacement=await create('replacement','1h');assert.equal(await infer(replacement.key),200);
  stage='active key pagination';
  const batch=await user.evaluate(async()=>{
   for(let i=0;i<51;i++){
    const response=await fetch('/me/keys',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:'pagination-'+i,expiresIn:'1h'})});
    if(!response.ok)return response.status;await response.text();
   }return 200;
  });assert.equal(batch,200);
  await done(user,()=>user.getByRole('button',{name:'List my keys',exact:true}).click());
  assert.equal(await user.locator('#keys p').count(),50);
  await done(user,()=>user.locator('#activePages').getByRole('button',{name:'Next',exact:true}).click());
  assert.ok(await user.locator('#keys p').count()>0);
  await done(user,()=>user.locator('#activePages').getByRole('button',{name:'Previous',exact:true}).click());
  stage='administrator user-scoped revoke all';
  const denied=await user.evaluate(async subject=>(await fetch('/api/v1/management/key-revocations',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({subject,dry_run:false})})).status,subject);
  assert.equal(denied,403);
  admin.on('dialog',dialog=>dialog.accept());
  await admin.locator('#revokeUserKeys [name=subject]').selectOption(subject);
  await done(admin,()=>admin.getByRole('button',{name:'Check active keys',exact:true}).click());
  assert.match(await admin.locator('#userKeyCount').textContent(),/[1-9][0-9]* active keys/);
  assert.equal(await infer(replacement.key),200);
  await done(admin,()=>admin.getByRole('button',{name:'Revoke all keys',exact:true}).click());
  assert.equal(await infer(replacement.key),401);assert.equal(await infer(first.key),401);assert.equal(await infer(second.key),401);
  await done(user,()=>user.getByRole('button',{name:'List my keys',exact:true}).click());
  assert.equal(await user.locator('#keys button').count(),0);
  await user.locator('#inactiveKeys summary').click();
  await user.waitForFunction(()=>document.querySelector('#archivedKeys .key-status')?.textContent==='revoked');
  const later=await create('after-revocation','1h');assert.equal(await infer(later.key),200);
  console.log('PASS: UI-created keys revoke and expire; cross-user revocation rejected; excessive lifetime rejected; replacement works');
 }finally{await browser.close();}
})().catch(error=>{
 const status=typeof error.actual==='number'&&typeof error.expected==='number'
  ?' (actual '+error.actual+', expected '+error.expected+')':'';
 // Capture only a known test filename and numeric location, never the message,
 // assertion values, source text or the rest of a potentially sensitive stack.
 const reason=[['Execution context was destroyed','navigation'],['Cannot read properties of null','missing-element'],['Timeout','timeout'],['Unexpected token','invalid-json'],['Target page','page-closed'],['frame was detached','frame-detached'],['is not a function','missing-function']].find(([message])=>String(error.message||'').includes(message));
 const httpStatus=String(error.message||'').match(/usage API HTTP (\d{3})/);
 const location=String(error.stack||'').match(/(?:browser-key-lifecycle|key-download)\.cjs:(\d+):(\d+)/);
 console.error('FAIL at '+stage+status+' (HTTP 429 responses '+throttledResponses+')'+(reason?' (reason '+reason[1]+')':'')+(httpStatus?' (usage HTTP '+httpStatus[1]+')':'')+(location?' (source '+location[0]+')':'')+'; sensitive details withheld');
 process.exitCode=1;
});
