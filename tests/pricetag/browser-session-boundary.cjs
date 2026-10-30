'use strict';
require('./mock-guard.cjs')();
const {chromium}=require('playwright');
const fs=require('node:fs'),path=require('node:path');
const {X509Certificate,createHash}=require('node:crypto');
const assert=require('node:assert/strict');
let stage='setup';
(async()=>{
 if(!process.env.NODE_EXTRA_CA_CERTS)throw new Error('NODE_EXTRA_CA_CERTS must trust the benchmark CA for API requests');
 if(process.env.MOCK_DEPLOYMENT_CONFIRMED!=='yes')throw new Error('mock confirmation required');
 const dir=process.env.KEY_DIRECTORY,base=process.env.GATEWAY_URL;
 const keyPath=path.join(dir,'admin.key');assert.equal(fs.statSync(keyPath).mode&0o077,0);
 const cert=new X509Certificate(fs.readFileSync(path.join(dir,'server.pem')));
 const pin=createHash('sha256').update(cert.publicKey.export({type:'spki',format:'der'})).digest('base64');
 const browser=await chromium.launch({args:['--ignore-certificate-errors-spki-list='+pin]});
 async function login(key){const context=await browser.newContext();const page=await context.newPage();await page.goto(base+'/login');await page.locator('#api_key').fill(key);await Promise.all([page.waitForURL(u=>u.pathname!=='/login'),page.getByRole('button',{name:'Sign In',exact:true}).click()]);return {context,page};}
 async function done(page,action){await page.locator('#status').evaluate(el=>el.textContent='');await action();await page.waitForFunction(()=>document.querySelector('#status').textContent==='Done');}
 try{
  const key=fs.readFileSync(keyPath,'utf8').trim();const {page}=await login(key);await page.goto(base+'/admin');await page.locator('#admin').waitFor({state:'visible'});
  async function who(){return await page.evaluate(async()=>await(await fetch('/api/v1/whoami')).json());}
  const original=await who();assert.equal(original.user,'admin');
  stage='view-as GET requires confirmation';await page.locator('#onboard [name=subject]').selectOption('alice');await page.getByRole('link',{name:'View selected user’s usage',exact:true}).click();await page.getByRole('heading',{name:'Change dashboard view'}).waitFor();assert.equal((await who()).user,'admin');
  stage='cross-origin session writes denied';
  for(const route of ['/admin/impersonate?as=alice','/logout']){const response=await page.context().request.post(base+route,{headers:{Origin:'https://attacker.invalid'},maxRedirects:0});console.log('Cross-origin '+route.split('?')[0]+' HTTP '+response.status());assert.equal(response.status(),403);}
  stage='confirm scoped view';await Promise.all([page.waitForURL(u=>u.pathname==='/dashboard'),page.getByRole('button',{name:'Continue',exact:true}).click()]);assert.equal((await who()).user,'alice');assert.equal((await who()).impersonating,true);
  const keyResponse=await page.context().request.post(base+'/me/keys',{headers:{Origin:base},data:{name:'forbidden-impersonated-key',expiresIn:'1h'},maxRedirects:0});assert.equal(keyResponse.status(),403);
  stage='return to administrator';await page.goto(base+'/admin/impersonate');await Promise.all([page.waitForURL(u=>u.pathname==='/dashboard'),page.getByRole('button',{name:'Continue',exact:true}).click()]);assert.equal((await who()).user,'admin');
  stage='nonexistent impersonation target rejected';
  const missing=await page.context().request.post(base+'/admin/impersonate?as=missing-test-identity',{headers:{Origin:base},maxRedirects:0});assert.equal(missing.status(),403);assert.equal((await who()).user,'admin');
  stage='logout confirmation';await page.goto(base+'/logout');await page.getByRole('heading',{name:'Sign out'}).waitFor();assert.equal((await who()).user,'admin');await Promise.all([page.waitForURL(u=>u.pathname==='/login'),page.getByRole('button',{name:'Continue',exact:true}).click()]);
  console.log('PASS: view-as/logout require same-origin confirmation; impersonated key issuance denied; admin identity restored');
 }finally{await browser.close();}
})().catch(()=>{console.error('FAIL at '+stage+'; sensitive details withheld');process.exitCode=1});
