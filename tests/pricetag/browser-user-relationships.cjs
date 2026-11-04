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
 async function login(key){const context=await browser.newContext(),page=await context.newPage();await page.goto(base+'/login');await page.locator('#api_key').fill(key);await Promise.all([page.waitForURL(u=>u.pathname!=='/login'),page.getByRole('button',{name:'Sign In',exact:true}).click()]);return page;}
 async function done(page,action){await page.locator('#status').evaluate(el=>el.textContent='');await action();await page.waitForFunction(()=>document.querySelector('#status').textContent==='Done');}
 try{
  const admin=await login(fs.readFileSync(keyPath,'utf8').trim());await admin.goto(base+'/admin');await admin.locator('#admin').waitFor({state:'visible'});
  const prefix='demo-relationship-'+Date.now(),names=[prefix+'-lead-a',prefix+'-lead-b',prefix+'-member'];
  stage='create three users through UI';
  for(const subject of names){await admin.locator('#user [name=subject]').fill(subject);await admin.locator('#user [name=name]').fill(subject);await done(admin,()=>admin.getByRole('button',{name:'Save user',exact:true}).click());}
  async function users(){return await admin.evaluate(async()=>await(await fetch('/api/v1/management/users')).json());}
  const initial=await users(),ids=names.map(n=>initial.find(u=>u.logins.includes(n)).user_id);
  async function relationship(user,manager,success=true){
   await admin.locator('#partner-users-search').fill(user);
   const row=admin.locator('#partner-users-list tr[data-user-id="'+user+'"]');
   await row.waitFor();
   const response=admin.waitForResponse(r=>new URL(r.url()).pathname==='/api/v1/admin/partner-users/'+user&&r.request().method()==='PATCH');
   await row.locator('.partner-manager').selectOption(manager);
   assert.equal((await response).ok(),success);assert.equal(await admin.locator('#partner-detail-ov.show').count(),0);
   await row.locator('.partner-manager').waitFor({state:'visible'});
  }
  stage='assign and reassign manager';await relationship(ids[2],ids[0]);assert.equal((await users()).find(u=>u.user_id===ids[2]).manager_user_id,ids[0]);
  await relationship(ids[2],ids[1]);assert.equal((await users()).find(u=>u.user_id===ids[2]).manager_user_id,ids[1]);
  stage='reject hierarchy cycle';await relationship(ids[1],ids[2],false);assert.ok(!(await users()).find(u=>u.user_id===ids[1]).manager_user_id);
  stage='issue member key';await admin.locator('#vtab-user-keys').click();await admin.locator('#onboard [name=subject]').selectOption(names[2]);await admin.locator('#onboard [name=expiresIn]').fill('1d');await done(admin,()=>admin.getByRole('button',{name:'Issue key',exact:true}).click());const issued=await downloadKey(admin, '#onboardKey');await admin.locator('#onboardKey').getByRole('button',{name:'Dismiss key',exact:true}).click();
  const member=await login(issued.key);
  async function quota(){return await member.evaluate(async()=>(await(await fetch('/api/v1/whoami')).json()).quota);}
  const before=await quota();
  stage='budget override and default inheritance';await admin.locator('#vtab-user-quota').click();await admin.locator('#budget [name=subject]').selectOption(names[2]);await admin.locator('#budget [name=monthly_usd]').fill('7.25');await done(admin,()=>admin.getByRole('button',{name:'Set override',exact:true}).click());assert.equal((await quota()).base_usd,7.25);
  await done(admin,()=>admin.getByRole('button',{name:'Use global default',exact:true}).click());assert.equal((await quota()).base_usd,before.base_usd);
  stage='edit, suspend and reactivate stable identity';await admin.locator('#vtab-people').click();await admin.locator('#user [name=subject]').fill(names[2]);await admin.locator('#user [name=name]').fill('Renamed member');await done(admin,()=>admin.getByRole('button',{name:'Save user',exact:true}).click());assert.equal((await users()).find(u=>u.logins.includes(names[2])).user_id,ids[2]);
  await admin.locator('#user [name=active]').selectOption('false');await done(admin,()=>admin.getByRole('button',{name:'Save user',exact:true}).click());assert.equal(await member.evaluate(async()=>(await fetch('/api/v1/whoami')).status),403);
  for(const route of ['/api/v1/dashboard/overview','/api/v1/dashboard/models','/api/v1/org/usage','/api/v1/org/charts']){
   assert.equal(await member.evaluate(async path=>(await fetch(path)).status,route),403,'suspended identity cannot read usage with its existing session');
  }
  await admin.locator('#partner-users-state').selectOption('inactive');await admin.locator('#partner-users-search').fill(names[2]);await admin.locator('#partner-users-list tbody tr').filter({hasText:names[2]}).waitFor();
  await admin.locator('#user [name=active]').selectOption('true');await done(admin,()=>admin.getByRole('button',{name:'Save user',exact:true}).click());assert.equal(await member.evaluate(async()=>(await fetch('/api/v1/whoami')).status),200);
  assert.equal((await users()).find(u=>u.logins.includes(names[2])).user_id,ids[2]);assert.equal((await quota()).spent_usd,before.spent_usd);
  console.log('PASS: UI manager reassignment, cycle rejection, override removal/default inheritance and stable-identity edit/suspension/reactivation');
 }finally{await browser.close();}
})().catch(()=>{console.error('FAIL at '+stage+'; sensitive response details withheld');process.exitCode=1});
