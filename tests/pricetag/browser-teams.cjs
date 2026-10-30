'use strict';
require('./mock-guard.cjs')();
const {chromium}=require('playwright');
const fs=require('node:fs');
const path=require('node:path');
const {X509Certificate,createHash}=require('node:crypto');
const assert=require('node:assert/strict');
let stage='setup';
(async()=>{
 if(process.env.MOCK_DEPLOYMENT_CONFIRMED!=='yes')throw new Error('mock confirmation required');
 const dir=process.env.KEY_DIRECTORY,base=process.env.GATEWAY_URL;
 const manifest=JSON.parse(fs.readFileSync(path.join(dir,'manifest.json')));
 assert.equal(manifest.synthetic,true);assert.equal(manifest.users.length,20);
 const cert=new X509Certificate(fs.readFileSync(path.join(dir,'server.pem')));
 const pin=createHash('sha256').update(cert.publicKey.export({type:'spki',format:'der'})).digest('base64');
 const browser=await chromium.launch({args:['--ignore-certificate-errors-spki-list='+pin]});
 async function session(user){
  const file=path.join(dir,user.subject+'.key');assert.equal(fs.statSync(file).mode&0o077,0);
  const context=await browser.newContext();context.setDefaultTimeout(15000);const page=await context.newPage();
  await page.goto(base+'/login');await page.locator('#api_key').fill(fs.readFileSync(file,'utf8').trim());
  await Promise.all([page.waitForURL(u=>u.pathname!=='/login'),page.getByRole('button',{name:'Sign In',exact:true}).click()]);
  return {context,page};
 }
 async function verifyPersonalAPI(context,user){
  const other=manifest.users.find(u=>u.subject!==user.subject).subject;
  const headers={'X-Forwarded-User':other,'X-MaaS-Username':other};
  const routes=['overview','groups','users','models','tools','recent','timeline'];
  for(const route of routes){
   await new Promise(resolve=>setTimeout(resolve,150));
   stage='personal API boundary '+route;
   const endpoint=base+'/api/v1/dashboard/'+route+'?range=mtd';
   const own=await context.request.get(endpoint,{headers});assert.equal(own.status(),200,route+' own read');
   const data=await own.json();
   if(route==='overview'){assert.ok(data.total_requests>0);assert.equal(data.active_users,1);}
   if(route==='users')assert.deepEqual(data.map(r=>r.username),[user.subject]);
   if(route==='recent')assert.ok(data.length>0 && data.every(r=>r.username===user.subject));
   for(const query of [other,user.subject+','+other]){
    const denied=await context.request.get(endpoint+'&user='+encodeURIComponent(query),{headers});
    assert.equal(denied.status(),403,route+' cross-user filter');
   }
  }
 }
 try{
  stage='anonymous backend access';
  const anonymous=await browser.newContext();
  for(const route of ['/api/v1/dashboard/overview','/api/v1/dashboard/users','/api/v1/org/usage','/api/v1/org/charts']){
   const response=await anonymous.request.get(base+route,{headers:{'X-Forwarded-User':'admin','X-MaaS-Username':'admin'},maxRedirects:0});
   console.log('Anonymous '+route+' HTTP '+response.status());
   assert.ok([302,303,401,403].includes(response.status()),'anonymous backend access denied');
  }
  await anonymous.close();
  for(const index of [0,10,1]){
   const user=manifest.users[index];stage='session '+(user.manager?'manager':'personal')+' team '+user.team;
   const {context,page}=await session(user);
   stage='render personal Usage charts for '+(user.manager?'manager':'member');
   await page.goto(base+'/dashboard');
   await page.waitForFunction(()=>cachedOverview && cachedOverview.total_requests>0 && cachedModels.length>0 && tokenChart && tokenChart.data.datasets[0].data.some(n=>n>0),{},{timeout:15000}).catch(async error=>{console.log('Chart state',await page.evaluate(()=>({requests:cachedOverview?.total_requests,models:cachedModels.length,chart:!!tokenChart,chartLibrary:typeof Chart,failed:document.querySelector('#last-refresh').textContent.includes('could not be loaded')})));throw error;});
   assert.equal(await page.evaluate(()=>directoryUsers.length),0);
   const personal=await page.evaluate(async(subject)=>{
    const own=await(await fetch('/api/v1/dashboard/users?range=mtd')).json();
    const forbidden=await fetch('/api/v1/dashboard/overview?user='+encodeURIComponent(subject),{headers:{'X-Forwarded-User':subject,'X-MaaS-Username':subject}});
    return {own,forbidden:forbidden.status};
   },manifest.users.find(u=>u.subject!==user.subject).subject);
   assert.deepEqual(personal.own.map(u=>u.username),[user.subject]);
   assert.equal(personal.forbidden,403);
   stage='backend personal isolation for '+(user.manager?'manager':'member');
   await verifyPersonalAPI(context,user);
   stage='personal chart failure and retry';
   await page.route('**/api/v1/dashboard/models?**',route=>route.fulfill({status:503,body:'synthetic failure'}));
   await page.evaluate(()=>refresh(true));
   await page.waitForFunction(()=>document.querySelector('#last-refresh').textContent.includes('could not be loaded'));
   await page.unroute('**/api/v1/dashboard/models?**');await page.evaluate(()=>refresh(true));
   await page.waitForFunction(()=>!document.querySelector('#last-refresh').textContent.includes('could not be loaded'));
   stage='team scope for '+(user.manager?'manager':'member');

   await page.goto(base+(user.manager?'/manager':'/dashboard'));
   const allowed=manifest.users.filter(u=>user.manager?u.team===user.team:u.subject===user.subject).map(u=>u.user_id);
   const outside=manifest.users.find(u=>u.team!==user.team);
   const result=await page.evaluate(async({allowed,outside})=>{
    const scope=await(await fetch('/api/v1/org/scope')).json();
    const response=await fetch('/api/v1/org/usage');const rows=await response.json();
    const inside=await fetch('/api/v1/org/person?slug='+encodeURIComponent(allowed[0]));
    const denied=await fetch('/api/v1/org/person?slug='+encodeURIComponent(outside));
    const rootDenied=await fetch('/api/v1/org/usage?root='+encodeURIComponent(outside));
    const charts=await fetch('/api/v1/org/charts?range=mtd');
    const chartData=await charts.json();
    const chartsDenied=await fetch('/api/v1/org/charts?root='+encodeURIComponent(outside));
    const directory=await fetch('/api/v1/dashboard/directory-users');
    const admin=await fetch('/api/v1/management/users',{headers:{'X-Forwarded-User':'admin','X-MaaS-Username':'admin'}});
    const who=await(await fetch('/api/v1/whoami')).json();
    return {scope,status:response.status,rows,inside:inside.status,denied:denied.status,rootDenied:rootDenied.status,chartsStatus:charts.status,chartData,chartsDenied:chartsDenied.status,directory:directory.status,admin:admin.status,quota:who.quota};
   },{allowed,outside:outside.user_id});
   assert.equal(result.status,200);assert.equal(result.scope.scope,user.manager?'manager':'self');
   assert.equal(result.scope.isManager,user.manager);
   assert.deepEqual(result.rows.map(r=>r.slug).sort(),allowed.sort());
   assert.ok(result.rows.every(r=>r.requests>0),'synthetic usage missing');
   assert.ok(result.rows.every(r=>r.quota_usd>0),'monthly budget missing');
   assert.ok(result.rows.every(r=>r.quota_spent_usd>=0),'monthly spending missing');
   assert.equal(result.inside,200);assert.equal(result.denied,403);assert.equal(result.rootDenied,403);
   assert.equal(result.chartsStatus,200);assert.equal(result.chartsDenied,403);
   assert.ok(result.chartData.models.length>0);
   assert.equal(result.directory,403);assert.equal(result.admin,403);
   if(user.manager){
    await page.waitForFunction(()=>document.querySelector('#scopeSub')?.textContent.includes('10 people in your tree'));
    await page.waitForFunction(()=>chartsCache && chartsCache.models.length>0);
    await page.route('**/api/v1/org/charts?**',route=>route.fulfill({status:503,body:'synthetic failure'}));
    await page.evaluate(()=>loadCharts());await page.locator('#chartsError').waitFor({state:'visible'});
    await page.unroute('**/api/v1/org/charts?**');await page.evaluate(()=>loadCharts());await page.locator('#chartsError').waitFor({state:'hidden'});
   }
   console.log('PASS: '+(user.manager?'manager':'personal')+' team '+user.team+' sees '+result.rows.length+' scoped profiles; cross-team and admin access denied');
   await context.close();
  }
  stage='impersonated personal Usage charts and scope';
  const adminFile=path.join(process.env.ADMIN_KEY_DIRECTORY||dir,'admin.key');
  const adminContext=await browser.newContext(),admin=await adminContext.newPage();adminContext.setDefaultTimeout(15000);
  await admin.goto(base+'/login');await admin.locator('#api_key').fill(fs.readFileSync(adminFile,'utf8').trim());
  await Promise.all([admin.waitForURL(u=>u.pathname!=='/login'),admin.getByRole('button',{name:'Sign In',exact:true}).click()]);
  for(const target of [manifest.users[0],manifest.users[1]]){
   stage='start impersonation '+(target.manager?'manager':'member');
   await admin.goto(base+'/admin/impersonate?as='+encodeURIComponent(target.subject));
   await Promise.all([admin.waitForURL(u=>u.pathname==='/dashboard'),admin.getByRole('button',{name:'Continue',exact:true}).click()]);
   stage='impersonated charts '+(target.manager?'manager':'member');
   await admin.waitForFunction(()=>cachedOverview && cachedOverview.total_requests>0 && cachedModels.length>0 && tokenChart && tokenChart.data.datasets[0].data.some(n=>n>0));
   await verifyPersonalAPI(adminContext,target);
   const scoped=await admin.evaluate(async()=>({users:await(await fetch('/api/v1/dashboard/users?range=mtd')).json(),directory:(await fetch('/api/v1/dashboard/directory-users')).status}));
   assert.deepEqual(scoped.users.map(u=>u.username),[target.subject]);assert.equal(scoped.directory,403);
   stage='return from impersonation';
   await admin.goto(base+'/admin/impersonate');
   await Promise.all([admin.waitForURL(u=>u.pathname==='/dashboard'),admin.getByRole('button',{name:'Continue',exact:true}).click()]);
  }
  stage='restored administrator charts';
  await admin.waitForFunction(()=>isAdmin && directoryUsers.length>0 && cachedOverview.total_requests>0);
  console.log('PASS: impersonated manager/member Usage remains personal; administrator directory and aggregate charts restored');
 }finally{await browser.close();}
})().catch(error=>{console.error('FAIL at '+stage+'; '+error.name+'; credentials and response bodies withheld');if(typeof error.actual==='number' && typeof error.expected==='number')console.error('actual='+error.actual+' expected='+error.expected);process.exitCode=1});
