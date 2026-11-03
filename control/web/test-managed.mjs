// Run: node --test control/web/test-managed.mjs
// Optional real Chromium UI: PLAYWRIGHT_MODULE=/path/to/playwright/index.mjs node control/web/test-managed.mjs --browser
import assert from 'node:assert/strict';
import {webcrypto,randomUUID} from 'node:crypto';
import {test} from 'node:test';
import {createServer} from 'node:http';
import {readFile,mkdir} from 'node:fs/promises';
import {sealStorage,canonical,canReuseStorage,waitForCompletionObservation} from './managed.js';
const {subtle}=webcrypto;
const pair=await subtle.generateKey({name:'RSA-OAEP',modulusLength:3072,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['wrapKey','unwrapKey']);
const der=await subtle.exportKey('spki',pair.publicKey);
const key={algorithm:'RSA-OAEP-256+A256GCM',publicKey:Buffer.from(der).toString('base64'),id:Buffer.from(await subtle.digest('SHA-256',der)).toString('hex')};
const secret='SECRET-SENTINEL-<private>&"';
function validJobRequest(body) {
 const uuid=value=>typeof value==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);
 return body!==null&&typeof body==='object'&&!Array.isArray(body)&&Object.keys(body).length===2&&Object.keys(body).every(name=>['planId','idempotencyKey'].includes(name))&&uuid(body.planId)&&uuid(body.idempotencyKey);
}
const ids={source:randomUUID(),target:randomUUID(),storage:randomUUID(),request:randomUUID()};
const challenge={metadata:{id:ids.storage,name:'Example',kind:'rest',endpoint:'https://storage.example.test/'+ids.storage},requestId:ids.request,expiresAt:new Date(Date.now()+900000).toISOString()};
const binding={nodeId:ids.source,key,bindingGeneration:1,mode:'create'};
async function decrypt(envelope,metadata=challenge.metadata) {
 const aes=await subtle.unwrapKey('raw',Buffer.from(envelope.wrappedKey,'base64'),pair.privateKey,{name:'RSA-OAEP'},{name:'AES-GCM',length:256},false,['decrypt']);
 const {v,nodeId,keyId,storageId,requestId,bindingGeneration,mode,expiresAt}=envelope;
 const aad=canonical({v,nodeId,keyId,storageId,requestId,bindingGeneration,mode,expiresAt,purpose:'storage'});
 const raw=await subtle.decrypt({name:'AES-GCM',iv:Buffer.from(envelope.iv,'base64'),additionalData:new TextEncoder().encode(aad),tagLength:128},aes,Buffer.from(envelope.ciphertext,'base64'));
 const payload=JSON.parse(new TextDecoder().decode(raw));assert.deepEqual(payload.metadata,metadata);return payload;
}
test('RSA3072/OAEP-SHA256 + AES256-GCM exact AAD and payload; fresh envelopes',async()=>{
 const one=await sealStorage(challenge,binding,secret,{username:'u',password:secret});
 const two=await sealStorage(challenge,binding,secret,{username:'u',password:secret});
 assert.equal(Buffer.from(one.wrappedKey,'base64').length,384);assert.equal(Buffer.from(one.iv,'base64').length,12);assert.notEqual(one.iv,two.iv);assert.notEqual(one.wrappedKey,two.wrappedKey);
 assert.deepEqual(await decrypt(one),{metadata:challenge.metadata,repoPassword:secret,credentials:{username:'u',password:secret},bindingGeneration:1,requestId:ids.request,mode:'create'});
 assert.equal(JSON.stringify(one).includes(secret),false);
 for(const binary of ['wrappedKey','iv','ciphertext']){const bytes=Buffer.from(one[binary],'base64');bytes[0]^=1;await assert.rejects(()=>decrypt({...one,[binary]:bytes.toString('base64')}));}
 for(const field of ['v','nodeId','keyId','storageId','requestId','bindingGeneration','mode','expiresAt'])await assert.rejects(()=>decrypt({...one,[field]:typeof one[field]==='number'?one[field]+1:one[field]+'x'}));
 await assert.rejects(()=>sealStorage({...challenge,expiresAt:'2000-01-01T00:00:00Z'},binding,secret,{}));
 await assert.rejects(()=>sealStorage(challenge,{...binding,key:{...key,id:'0'.repeat(64)}},secret,{}));
});


test('storage reuse requires fresh matching catalog and host binding identity',()=>{
 const storage={id:ids.storage,repositoryId:'a'.repeat(64),bindings:[ids.source,ids.target].map(nodeId=>({nodeId,state:'connected',repositoryId:'a'.repeat(64),bindingGeneration:3,requestId:ids.request}))};
 const nodes=storage.bindings.map(b=>({id:b.nodeId,status:{compose:{ready:true,storages:[{storageId:storage.id,connected:true,repositoryId:b.repositoryId,bindingGeneration:b.bindingGeneration,requestId:b.requestId}]}}}));
 assert.equal(canReuseStorage(storage,nodes,()=>true),true);
 for(const field of ['repositoryId','bindingGeneration','requestId','connected']){const changed=structuredClone(nodes);changed[1].status.compose.storages[0][field]=field==='bindingGeneration'?4:field==='connected'?false:'mismatch';assert.equal(canReuseStorage(storage,changed,()=>true),false,field);}
 assert.equal(canReuseStorage({...storage,bindings:storage.bindings.slice(0,1)},nodes,()=>true),false);
 assert.equal(canReuseStorage(storage,nodes,n=>n.id!==ids.target),false);
 assert.equal(canReuseStorage(storage,[nodes[0],nodes[0]],()=>true),false);
 assert.equal(canReuseStorage({...storage,repositoryId:''},nodes,()=>true),false);const unconnected=structuredClone(storage);unconnected.bindings[1].state='prepared';assert.equal(canReuseStorage(unconnected,nodes,()=>true),false);
});

test('job fixture accepts exactly planId/idempotencyKey and canonical UUID strings',()=>{
 const valid={planId:randomUUID(),idempotencyKey:randomUUID()};
 assert.equal(validJobRequest(valid),true);
 for(const body of [null,[],{},...Object.keys(valid).map(key=>({[key]:valid[key]})),{...valid,expectedRevision:1},{...valid,unexpected:true},{...valid,planId:12},{...valid,idempotencyKey:'bad'}])assert.equal(validJobRequest(body),false);
});

function completionFixture() {
 const service={id:randomUUID(),sourceNodeId:ids.source,recoveryNodeId:ids.target,storageId:ids.storage,projectId:'app',fingerprint:'c'.repeat(64),backupInterval:'15min'};
 const point={snapshot:'a'.repeat(64),repositoryId:'b'.repeat(64),manifestDigest:'d'.repeat(64),sourceFingerprint:service.fingerprint};
 const restoreId=randomUUID(),checks=['compose-model','data-hashes','metadata','image-identities','fresh-resources','runtime-isolation','application-health'];
 const restore={id:restoreId,serviceId:service.id,nodeId:ids.target,snapshotId:point.snapshot,repositoryId:point.repositoryId,manifestDigest:point.manifestDigest,sourceFingerprint:point.sourceFingerprint,state:'isolated_ready',applicationHealthVerified:true,healthScope:'http',checks};
 const storage={id:ids.storage,repositoryId:point.repositoryId,bindings:[ids.source,ids.target].map(nodeId=>({nodeId,state:'connected',repositoryId:point.repositoryId,bindingGeneration:1,requestId:ids.request}))};
 const nodes=[ids.source,ids.target].map(id=>({id,connected:true,fresh:true,status:{compose:{ready:true,storages:[{storageId:ids.storage,repositoryId:point.repositoryId,connected:true,bindingGeneration:1,requestId:ids.request}],services:id===ids.source?[{serviceId:service.id,projectId:service.projectId,fingerprint:service.fingerprint,storageId:service.storageId,state:'running',schedule:{enabled:true,interval:'15min'}}]:[],restores:id===ids.target?[{...restore,ports:[]}]:[]}}}));
 return {service,point,restoreId,overview:{services:[{...service,latestBackup:{...point}}],storages:[storage],restores:[restore],nodes}};
}
async function completionRun(fixture,change=()=>{},extra={}) {
 let clock=0,reads=0,waits=[];
 const result=await waitForCompletionObservation({service:fixture.service,point:fixture.point,restoreId:fixture.restoreId,isFresh:n=>n.fresh&&n.connected,readOverview:async()=>{change(fixture.overview,++reads);return fixture.overview;},now:()=>clock,pause:async ms=>{waits.push(ms);clock+=ms;},timeoutMs:4500,...extra});
 return {result,reads,waits,clock};
}
test('completion waits read-only for observed schedule; catalog ports may be absent',async()=>{
 const fixture=completionFixture();assert.equal('ports' in fixture.overview.restores[0],false);
 const result=await completionRun(fixture,(o,read)=>{o.nodes[0].status.compose.services[0].schedule.enabled=read>=4;},{timeoutMs:6000});
 assert.equal(result.reads,4);assert.deepEqual(result.waits,[1500,1500,1500]);assert.equal(result.result.id,fixture.service.id);
});
test('completion timeout and stale/offline/missing/health/port proofs never confirm',async()=>{
 const changes={disabled:o=>o.nodes[0].status.compose.services[0].schedule.enabled=false,wrongInterval:o=>o.nodes[0].status.compose.services[0].schedule.interval='hourly',stale:o=>o.nodes[1].fresh=false,offline:o=>o.nodes[0].connected=false,missingPorts:o=>delete o.nodes[1].status.compose.restores[0].ports,published:o=>o.nodes[1].status.compose.restores[0].ports=[{published:8080}],missingHealth:o=>delete o.nodes[1].status.compose.restores[0].applicationHealthVerified,missingChecks:o=>o.nodes[1].status.compose.restores[0].checks=[],missingSource:o=>o.nodes[0].status.compose.services=[],missingRestore:o=>o.nodes[1].status.compose.restores=[]};
 for(const [name,change]of Object.entries(changes))await assert.rejects(()=>completionRun(completionFixture(),change),e=>['completion_observation_timeout','completion_proof_unavailable'].includes(e.code),name);
 const unhealthy=completionFixture();unhealthy.overview.restores[0].applicationHealthVerified=false;await assert.rejects(()=>completionRun(unhealthy),{code:'application_health_unverified'});
});
test('completion refuses identity/point/restore changes and cancellation',async()=>{
 const changes=[o=>o.services[0].sourceNodeId=ids.target,o=>o.services[0].recoveryNodeId=ids.source,o=>o.services[0].fingerprint='e'.repeat(64),o=>o.services[0].latestBackup.snapshot='e'.repeat(64),o=>o.services[0].latestBackup.manifestDigest='e'.repeat(64),o=>o.restores[0].snapshotId='e'.repeat(64),o=>o.nodes[1].status.compose.restores[0].manifestDigest='e'.repeat(64),o=>o.restores[0].nodeId=ids.source,o=>o.storages[0].repositoryId='e'.repeat(64)];
 for(const change of changes)await assert.rejects(()=>completionRun(completionFixture(),change),{code:'completion_identity_changed'});
 let cancelled=false;const fixture=completionFixture();await assert.rejects(()=>completionRun(fixture,o=>{o.nodes[0].status.compose.services[0].schedule.enabled=false;},{cancelled:()=>cancelled,pause:async()=>{cancelled=true;}}),{code:'session_ended'});
 let reads=0;await assert.rejects(()=>completionRun(completionFixture(),()=>{reads++;},{cancelled:()=>true}),{code:'session_ended'});assert.equal(reads,0);
});

test('completion default deadline is 120 seconds with no faster read polling',async()=>{
 const fixture=completionFixture();let clock=0,reads=0,pauses=[];
 fixture.overview.nodes[0].status.compose.services[0].schedule.enabled=false;
 await assert.rejects(()=>waitForCompletionObservation({service:fixture.service,point:fixture.point,restoreId:fixture.restoreId,isFresh:()=>true,readOverview:async()=>{reads++;return fixture.overview;},now:()=>clock,pause:async ms=>{pauses.push(ms);clock+=ms;}}),{code:'completion_observation_timeout'});
 assert.equal(clock,120000);assert.equal(reads,80);assert.equal(pauses.length,80);assert(pauses.every(ms=>ms===1500));
 let cancelled=false;
 await assert.rejects(()=>waitForCompletionObservation({service:fixture.service,point:fixture.point,restoreId:fixture.restoreId,isFresh:()=>true,readOverview:async()=>{cancelled=true;return fixture.overview;},cancelled:()=>cancelled}),{code:'session_ended'});
 await assert.rejects(()=>waitForCompletionObservation({service:fixture.service,point:fixture.point,restoreId:fixture.restoreId,isFresh:()=>true,readOverview:()=>new Promise(()=>{}),timeoutMs:1}),{code:'completion_observation_timeout'});
});

async function browserChecks() {
 const {chromium}=await import(process.env.PLAYWRIGHT_MODULE||'playwright');
 const repositoryId='a'.repeat(64),snapshot='b'.repeat(64);let outcomes=new Map();let revision=1,storage,service,restores=[],jobs=[],plans=new Map(),requests=[],envelopes=[],failBinding=false,unverified=false,protectedActivation=false,sourceFenced=false,dropConnectReply=false,dropJobReply=false,expireNext=false,legacyMode=false,legacyPreview=null,reuseFault='',emptyNodes=false,observationError='',selectedDemo=false,legacyOnly=false,omitDemoMarker=false;let replies=new Map(),rejectedJobs=[];
 const expectJobRejection=process.argv.includes('--expect-job-contract-rejection');
 const expectEarlyCompletion=process.argv.includes('--expect-early-complete-rejection');
 const restoreChecks=['compose-model','data-hashes','metadata','image-identities','fresh-resources','runtime-isolation','application-health'];
 let observedSchedule={enabled:false},desiredSchedule,timerPollsRemaining=0,holdTimer=false,earlyCompleteAttempts=0;
 const fixtureProject={id:'ordinary',name:'Ordinary <script>alert(1)</script>',fingerprint:'f'.repeat(64),supported:true,reasons:[],architecture:'linux/amd64',estimatedBytes:2048,services:[{name:'web',imageId:'c'.repeat(64),healthcheck:true,ports:[8080]}],mounts:[{kind:'volume',target:'/data',label:'app-data',readOnly:false}]};
 function overview(){
  if(timerPollsRemaining>0)timerPollsRemaining--;
  if(timerPollsRemaining===0&&!holdTimer&&desiredSchedule)observedSchedule={...desiredSchedule};
  if(service)service.schedule={...observedSchedule};
  const now=new Date().toISOString();
  const records=emptyNodes?[]:[{id:ids.source,name:'Source',role:'primary'},{id:ids.target,name:'Recovery',role:'recovery'}];
  const nodeRecords=records.map(n=>{
   const catalog=(storage?.bindings||[]).filter(b=>b.nodeId===n.id);
   const bindings=catalog.map(b=>({storageId:storage.id,connected:b.state==='connected',repositoryId:b.repositoryId,bindingGeneration:b.bindingGeneration,requestId:b.requestId}));
   if(n.id===ids.target&&reuseFault==='missing')bindings.length=0;
   if(n.id===ids.target&&reuseFault==='mismatch'&&bindings[0])bindings[0].repositoryId='d'.repeat(64);
   if(n.id===ids.target&&reuseFault==='generation'&&bindings[0])bindings[0].bindingGeneration++;
   return {...n,connected:true,lastSeen:n.id===ids.target&&reuseFault==='stale'?'2000-01-01T00:00:00Z':now,status:{observedAt:n.id===ids.target&&reuseFault==='stale-observation'?'2000-01-01T00:00:00Z':now,supported:legacyMode,serviceHealthy:legacyMode,snapshots:legacyMode?[{id:snapshot,time:now}]:[],preview:legacyMode&&n.id===ids.target?legacyPreview:null,...(!legacyOnly?{compose:{ready:!observationError,error:observationError||undefined,key,storages:bindings,projects:[fixtureProject,{...fixtureProject,id:'unsafe',name:'Unsafe',supported:false,reasons:['privileged']}],addresses:['203.0.113.10'],services:service&&n.id===service.sourceNodeId?[{serviceId:service.id,state:sourceFenced?'fenced':'running',projectId:service.projectId,fingerprint:service.fingerprint,storageId:service.storageId,schedule:{...observedSchedule}}]:[],restores:restores.filter(r=>r.nodeId===n.id).map(r=>({...r}))}}:{})}};
  });
  const alerts=observationError?[{code:observationError,nodeId:ids.source,severity:'warning'}]:(selectedDemo||legacyOnly)&&!legacyMode?[{code:'package_unsupported',nodeId:ids.source,severity:'warning'}]:[];
  return {revision,version:'0.2.0',setup:{completed:false,profile:'pair_assisted',...(omitDemoMarker?{}:{demoSelected:legacyMode||selectedDemo})},alerts,orphanReports:[],jobs,storages:storage?[storage]:[],services:service?[service]:[],restores:restores.map(({ports,...catalog})=>catalog),nodes:nodeRecords};
 }
 function job(action,nodeId,parameters,result={},error){const j={id:randomUUID(),action,nodeId,serviceId:parameters?.serviceId,storageId:parameters?.storageId,restoreId:parameters?.restoreId,status:action.startsWith('compose-')||action==='storage-configure'?'queued':error?'failed':'succeeded',error,createdAt:new Date().toISOString(),result};outcomes.set(j.id,error?'failed':'succeeded');jobs.push(j);return j;}
 const server=createServer(async(req,res)=>{try{
  const url=new URL(req.url,'http://localhost');const path=url.pathname.replace(/^\/ops/,'');
  // Chromium may request the optional icon after every navigation.
  if(path==='/favicon.ico'){res.statusCode=404;res.end();return;}
  let body;if(req.method==='POST'){let raw='';for await(const chunk of req)raw+=chunk;body=JSON.parse(raw);requests.push({path,body});if(path.includes('/connect'))assert(!raw.includes(secret));}
  if(req.method==='POST'){assert.equal(req.headers['x-csrf-token'],'test-csrf');assert.equal(req.headers.origin,`http://127.0.0.1:${server.address().port}`);}
  // Match controller.enqueue before looking up an idempotent reply or plan.
  if(req.method==='POST'&&path==='/api/jobs'&&!validJobRequest(body)){rejectedJobs.push({body,status:400,error:'invalid_request'});res.statusCode=400;res.setHeader('Content-Type','application/json');res.end(JSON.stringify({error:'invalid_request'}));return;}
  let data;const repeatKey=body?.idempotencyKey?path+'/'+body.idempotencyKey:null;if(repeatKey&&replies.has(repeatKey)){assert.deepEqual(body,replies.get(repeatKey).body);res.setHeader('Content-Type','application/json');res.end(JSON.stringify(replies.get(repeatKey).data));return;}
  if(path==='/api/session')data={authenticated:true,csrf:'test-csrf',version:'0.2.0'};
  else if(path==='/api/overview')data=overview();
  else if(path==='/api/logout')data={};
  else if(path==='/api/storages'){storage={...body,repositoryId:null,bindings:[]};delete storage.expectedRevision;delete storage.idempotencyKey;data={storage,revision:++revision};}
  else if(path.endsWith('/prepare')){if(body.mode==='create'){if(storage.kind==='rest')storage.endpoint=storage.endpoint.replace(/\/$/,'')+'/'+storage.id;else storage.prefix=(storage.prefix?storage.prefix+'/':'')+storage.id;}data={metadata:storage,requestId:randomUUID(),expiresAt:new Date(Date.now()+(expireNext?-1000:900000)).toISOString(),bindings:body.nodeIds.map((nodeId,i)=>({nodeId,key,bindingGeneration:1,mode:i?'attach':body.mode})),revision:++revision}; // Metadata must omit catalog-only fields.
   data.metadata={...storage};delete data.metadata.repositoryId;delete data.metadata.bindings;storage={...data.metadata,repositoryId:null,bindings:[]};challengeForBrowser=data;
  }
  else if(path.endsWith('/connect')){for(const b of body.bindings){const payload=await decrypt(b.envelope,challengeForBrowser.metadata);assert.equal(payload.repoPassword,secret);assert.equal(payload.credentials[storage.kind==='rest'?'password':'secretAccessKey'],secret);envelopes.push(b.envelope);}const pipeline=body.bindings.map(b=>job('storage-configure',b.nodeId,{},failBinding?{}:{connected:true,repositoryId},failBinding?'repository_auth_failed':null));if(!failBinding){storage.repositoryId=repositoryId;storage.bindings=body.bindings.map(b=>({nodeId:b.nodeId,state:'connected',repositoryId,bindingGeneration:b.envelope.bindingGeneration,requestId:b.envelope.requestId}));}data={jobs:pipeline,storage,revision:++revision};}
  else if(path==='/api/services'){service={...body,setupState:'registered',schedule:{},snapshots:[]};delete service.expectedRevision;delete service.idempotencyKey;data={service,job:job('compose-register',body.sourceNodeId,{serviceId:body.id},{registered:true}),revision:++revision};}
  else if(path==='/api/plans'){const id=randomUUID();plans.set(id,body);data={...body,id,expiresAt:new Date(Date.now()+900000).toISOString()};}
  else if(path==='/api/jobs'){const plan=plans.get(body.planId);let result={serviceId:service.id};if(plan.action==='compose-backup'){result={...result,snapshot,repositoryId,manifestDigest:'d'.repeat(64),sourceFingerprint:service.fingerprint,at:new Date().toISOString()};service.snapshots=[{id:snapshot,time:result.at,serviceId:service.id,repositoryId}];service.latestBackup=result;if(service.setupState==='active_unprotected')service.setupState='restore_required';}if(plan.action==='compose-schedule'){desiredSchedule={enabled:true,interval:plan.parameters.interval};observedSchedule={enabled:false};service.schedule={...observedSchedule};timerPollsRemaining=expectEarlyCompletion?9999:4;}const j=job(plan.action,plan.nodeId,plan.parameters,result);if(plan.action==='compose-restore'){j.result.restoreId=j.id;restores.push({id:j.id,serviceId:service.id,nodeId:plan.nodeId,snapshotId:plan.snapshotId,state:'isolated_ready',repositoryId,manifestDigest:'d'.repeat(64),sourceFingerprint:service.fingerprint,checks:[...restoreChecks],healthScope:unverified?'running-only':'docker',applicationHealthVerified:!unverified,ports:[]});}if(plan.action==='restore-preview')legacyPreview={id:j.id,snapshot,at:new Date().toISOString(),checks:['http']};if(plan.action==='remove-preview')legacyPreview=null;if(plan.action==='compose-remove')restores=restores.filter(r=>r.id!==plan.parameters.restoreId);data={job:j};}
  else if(path.endsWith('/complete')){assert.equal(body.restoreId,restores.at(-1).id);if(timerPollsRemaining>0||holdTimer||!observedSchedule.enabled||observedSchedule.interval!==service.backupInterval){earlyCompleteAttempts++;res.statusCode=409;data={error:'schedule_required'};}else if(unverified){res.statusCode=409;data={error:'application_health_unverified'};}else{service.setupState='complete';data={completed:true,service};}}
  else if(path.endsWith('/activate')){assert.equal(body.acceptSnapshotLoss,true);assert.equal(body.allowEgress,true);const r=restores.find(r=>r.id===body.restoreId);r.state='active';r.ports=body.ports;[service.sourceNodeId,service.recoveryNodeId]=[service.recoveryNodeId,service.sourceNodeId];service.setupState=protectedActivation?'restore_required':'active_unprotected';const firstBackup=protectedActivation?{serviceId:service.id,repositoryId,snapshot:'e'.repeat(64),manifestDigest:'d'.repeat(64),sourceFingerprint:service.fingerprint,at:new Date().toISOString()}:undefined;if(firstBackup){service.latestBackup=firstBackup;service.snapshots.push({id:firstBackup.snapshot,time:firstBackup.at,serviceId:service.id,repositoryId});}data={activationGroupId:randomUUID(),jobs:[job('compose-stop',ids.source,{serviceId:service.id},{fenced:true}),job('compose-activate',ids.target,{serviceId:service.id},{activated:true,protected:protectedActivation,firstBackup})],revision:++revision};}
  else if(path.endsWith('/resume-source')){assert.equal(body.activationGroupId,service.activationGroupId);assert.equal(jobs.find(j=>j.id===service.activation.sourceStopJobId).status,'succeeded');assert.equal(jobs.find(j=>j.id===service.activation.targetJobId).status,'failed');assert(sourceFenced);sourceFenced=false;service.setupState='backup_required';data={job:job('compose-resume',service.sourceNodeId,{serviceId:service.id},{resumed:true}),revision:++revision};}
  else if(path.startsWith('/api/jobs/')){const j=jobs.find(j=>j.id===path.split('/').at(-1));j.status=outcomes.get(j.id);data={job:j};}
  else {const name=path==='/'?'index.html':path.slice(1);const raw=await readFile(new URL(name,import.meta.url));res.setHeader('Content-Type',name.endsWith('.js')?'application/javascript':name.endsWith('.css')?'text/css':'text/html');res.end(raw);return;}
  if(repeatKey&&res.statusCode<400)replies.set(repeatKey,{body,data:structuredClone(data)});if((path.endsWith('/connect')&&dropConnectReply)||(path==='/api/jobs'&&dropJobReply)){if(path==='/api/jobs')dropJobReply=false;else dropConnectReply=false;res.statusCode=503;res.setHeader('Content-Type','application/json');res.end(JSON.stringify({error:'network'}));return;}
  res.setHeader('Content-Type','application/json');res.end(JSON.stringify(data));
 }catch(e){res.statusCode=500;res.end(JSON.stringify({error:'fixture_assertion_failed'}));serverErrors.push(String(e.stack));}});
 let challengeForBrowser,serverErrors=[];
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 console.log('Browser fixture listening');let browser;try{browser=await chromium.launch({headless:true,timeout:20000,...(process.env.CHROMIUM_EXECUTABLE?{executablePath:process.env.CHROMIUM_EXECUTABLE}:{})});console.log('Chromium started');const page=await browser.newPage();let errors=[];page.setDefaultTimeout(10000);page.on('pageerror',e=>errors.push(String(e)));
 if(process.env.UI_SCREENSHOT_DIR)await mkdir(process.env.UI_SCREENSHOT_DIR,{recursive:true});
  const origin=`http://127.0.0.1:${server.address().port}`;
  for(const invalid of [{planId:randomUUID(),idempotencyKey:randomUUID(),expectedRevision:revision},{planId:randomUUID()},{idempotencyKey:randomUUID()},{}]){const rejected=await page.request.post(origin+'/ops/api/jobs',{headers:{'x-csrf-token':'test-csrf',origin},data:invalid});assert.equal(rejected.status(),400);assert.deepEqual(await rejected.json(),{error:'invalid_request'});}assert.equal(jobs.length,0);rejectedJobs=[];
  await page.goto(origin+'/ops/');await page.getByRole('heading',{name:'Сервисы Compose',exact:true}).waitFor();
  if(process.env.UI_SCREENSHOT_DIR)await page.screenshot({path:process.env.UI_SCREENSHOT_DIR+'/home-compose-only-ru.png',fullPage:true});
  assert.equal(await page.getByRole('button',{name:'Создать копию',exact:true}).count(),0);assert.equal(await page.getByRole('button',{name:'Завершить настройку',exact:true}).count(),0);assert.equal(await page.getByText('Тестовый веб-сервис',{exact:true}).count(),0);
  await page.goto(origin+'/ops/#nodes');await page.reload();assert.equal(await page.getByText('Сервис не поддерживается',{exact:true}).count(),0);await page.goto(origin+'/ops/#dashboard');
  emptyNodes=true;await page.reload();await page.getByRole('button',{name:'Подключить сервер',exact:true}).waitFor();if(process.env.UI_SCREENSHOT_DIR)await page.screenshot({path:process.env.UI_SCREENSHOT_DIR+'/home-empty-ru.png',fullPage:true});assert.equal(await page.getByRole('button',{name:'Создать копию',exact:true}).count(),0);emptyNodes=false;
  await page.goto(origin+'/ops/#services');await page.reload();console.log('Own services loaded');
  await page.getByRole('button',{name:'Подключить свой сервис',exact:true}).click();
  await page.getByLabel('Исходный сервер',{exact:true}).selectOption(ids.source);
  await page.getByLabel('Отдельный сервер восстановления').selectOption(ids.target);
  await page.getByLabel('Обнаруженная группа Compose').selectOption('unsafe');
  assert.equal(await page.getByRole('button',{name:'Подготовить защищенное подключение'}).isDisabled(),true);
  await page.getByLabel('Обнаруженная группа Compose').selectOption('ordinary');
  await page.getByLabel('Название сервиса',{exact:true}).fill('My application');
  await page.getByLabel('Подтверждаю:').check();
  await page.getByLabel('Название хранилища',{exact:true}).fill('Repository');
  await page.getByLabel('Адрес HTTPS').fill('https://storage.example.test/base');
  await page.getByLabel('Имя пользователя REST').fill('tester');await page.getByLabel('Пароль REST',{exact:true}).fill(secret);await page.getByLabel('Независимый пароль шифрования restic').fill(secret);
  await page.getByRole('button',{name:'Подготовить защищенное подключение'}).click();
  await page.getByRole('button',{name:'Подтвердить подключение',exact:true}).waitFor();
  assert((await page.locator('.managed-code').textContent()).includes(storage.id));
  dropConnectReply=true;await page.getByRole('button',{name:'Подтвердить подключение',exact:true}).click();await page.getByText(/\[network\]/).first().waitFor();await page.getByRole('button',{name:'Подтвердить подключение',exact:true}).click();assert.deepEqual(requests.filter(r=>r.path.endsWith('/connect')).map(r=>r.body)[0],requests.filter(r=>r.path.endsWith('/connect')).map(r=>r.body)[1]);
  await page.getByRole('button',{name:'Продолжить настройку',exact:true}).waitFor();dropJobReply=!expectJobRejection;await page.getByRole('button',{name:'Продолжить настройку',exact:true}).click();
  if(expectJobRejection){await page.getByText(/\[invalid_request\]/).first().waitFor();assert.equal(rejectedJobs.length,1);assert.equal(rejectedJobs[0].status,400);assert.equal(rejectedJobs[0].error,'invalid_request');assert.equal(typeof rejectedJobs[0].body.expectedRevision,'number');assert.equal(jobs.filter(j=>j.action==='compose-backup').length,0);assert.notEqual(service.setupState,'complete');assert.equal(serverErrors.length,0,serverErrors.join('\n'));assert.equal(errors.length,0,errors.join('\n'));console.log('PASS negative control: old UI first compose-backup enqueue rejected HTTP400 invalid_request by strict job contract; no backup job created.');return;}
  await page.getByText(/\[network\]/).first().waitFor();const firstEnqueue=requests.filter(r=>r.path==='/api/jobs').at(-1).body;assert.equal(jobs.filter(j=>j.action==='compose-backup').length,1);await page.getByRole('button',{name:'Продолжить настройку',exact:true}).click();
  if(expectEarlyCompletion){await page.getByText(/\[schedule_required\]/).first().waitFor();assert.equal(earlyCompleteAttempts,1);assert.notEqual(service.setupState,'complete');assert.equal(requests.filter(r=>r.path.endsWith('/complete')).length,1);console.log('PASS negative control: UI with completion wait bypassed sends early POST while schedule observation is disabled; strict fixture rejects409schedule_required, no completion.');return;}
  await page.getByText('Настройка подтверждена сервером.',{exact:true}).waitFor();
  const enqueueReplay=requests.filter(r=>r.path==='/api/jobs'&&r.body.planId===firstEnqueue.planId);assert.equal(enqueueReplay.length,2);assert.deepEqual(enqueueReplay[0].body,enqueueReplay[1].body);assert.equal(jobs.filter(j=>j.action==='compose-backup').length,1);assert.deepEqual(Object.keys(firstEnqueue).sort(),['idempotencyKey','planId']);
  assert.equal(service.setupState,'complete');assert.equal(restores.length,1);assert.equal(envelopes.length,2);assert.equal(earlyCompleteAttempts,0);assert.equal(requests.filter(r=>r.path.endsWith('/complete')).length,1);
  assert(!JSON.stringify(await page.evaluate(()=>({...localStorage}))).includes(secret));assert(!JSON.stringify(await page.evaluate(()=>({...sessionStorage}))).includes(secret));assert.deepEqual(await page.evaluate(async()=>await indexedDB.databases()),[]);assert(!(await page.content()).includes(secret));assert.equal(await page.locator('script').count(),1);
  await page.getByRole('button',{name:'Закрыть',exact:true}).click();
  // A known failed stopped copy exposes Remove only; normal ready-copy actions remain.
  const readyCopies=[...restores];
  for(const language of ['ru','en']){
   const toggle=page.getByRole('button',{name:language==='en'?'Switch to English':'Переключить на русский',exact:true});if(await toggle.count())await toggle.click();
   for(const width of [1440,390]){
    await page.setViewportSize({width,height:900});
    const stopped={id:randomUUID(),serviceId:service.id,nodeId:ids.target,snapshotId:snapshot,state:'failed',canRemoveStopped:true,ports:[],applicationHealthVerified:false,healthScope:'stopped',checks:['runtime-stopped','no-published-ports','owned-resources']};
    restores=[...readyCopies,stopped];
    const reloadStopped=async()=>{await page.goto(origin+'/ops/#services');await page.reload();const row=page.locator('.managed-restore').filter({hasText:stopped.id});await row.waitFor();return row;};
    for(const eligibility of [undefined,false,'true']){if(eligibility===undefined)delete stopped.canRemoveStopped;else stopped.canRemoveStopped=eligibility;const row=await reloadStopped();assert.equal(await row.getByRole('button').count(),0,`no stopped authority ${language}/${width}/${eligibility}`);}
    stopped.canRemoveStopped=true;reuseFault='stale';let row=await reloadStopped();assert.equal(await row.getByRole('button').count(),0,'stale node must hide stopped removal');reuseFault='';
    row=await reloadStopped();assert.equal(await row.getByRole('button').count(),1);assert.equal(await row.getByRole('button',{name:language==='en'?'Remove stopped copy':'Удалить остановленную копию',exact:true}).count(),1);
    const normal=page.locator('.managed-restore').filter({hasText:readyCopies[0].id});assert.equal(await normal.getByRole('button').count(),3,'normal Ready/Move/Remove remain');
    if(process.env.UI_SCREENSHOT_DIR)await page.screenshot({path:process.env.UI_SCREENSHOT_DIR+`/stopped-remove-only-${width}-${language}.png`,fullPage:true});
    const before=requests.length;await row.getByRole('button').click();await page.getByRole('button',{name:language==='en'?'Confirm':'Подтвердить',exact:true}).click();await row.waitFor({state:'detached'});
    const planned=requests.slice(before).find(r=>r.path==='/api/plans');assert.equal(planned.body.action,'compose-remove');assert.equal(planned.body.nodeId,ids.target);assert.deepEqual(planned.body.parameters,{serviceId:service.id,restoreId:stopped.id});assert.equal(restores.some(r=>r.id===stopped.id),false);
   }
  }
  restores=readyCopies;await page.getByRole('button',{name:'Переключить на русский',exact:true}).click();await page.reload();
  await page.getByRole('button',{name:'Перенести сюда'}).click();
  await page.getByLabel('web:8080',{exact:true}).check();await page.getByLabel('Порт сервера',{exact:true}).first().fill('18190');if(process.env.UI_SCREENSHOT_DIR)await page.screenshot({path:process.env.UI_SCREENSHOT_DIR+'/port-target8080-host18190-ru.png',fullPage:true});await page.getByLabel('Разрешаю исходящие подключения новой копии').check();await page.getByLabel('Принимаю потерю изменений после выбранного снимка').check();await page.getByRole('button',{name:'Подтвердить',exact:true}).click();
  await page.locator('[data-setup-state="active_unprotected"]').waitFor();assert.equal(service.sourceNodeId,ids.target);assert.deepEqual(requests.find(r=>r.path.endsWith('/activate')).body.ports,[{service:'web',target:8080,published:18190,hostIp:'0.0.0.0',protocol:'tcp'}]);
  // Recover protection using persisted service identities after an incomplete move.
  await page.reload();await page.getByRole('button',{name:'Создать копию',exact:true}).click();await page.getByRole('button',{name:'Подтвердить',exact:true}).click();await page.getByRole('button',{name:'Завершить проверку защиты',exact:true}).waitFor();await page.getByRole('button',{name:'Завершить проверку защиты',exact:true}).click();await page.getByRole('button',{name:'Подтвердить',exact:true}).click();await page.locator('[data-setup-state="complete"]').waitFor();
  // A protected activation automatically checks the exact new-source firstBackup on its new recovery host.
  protectedActivation=true;await page.getByRole('button',{name:'Перенести сюда',exact:true}).last().click();await page.getByLabel('Разрешаю исходящие подключения новой копии').check();await page.getByLabel('Принимаю потерю изменений после выбранного снимка').check();await page.getByRole('button',{name:'Подтвердить',exact:true}).click();await page.locator('#dialog').waitFor({state:'hidden'});await page.locator('[data-setup-state="complete"]').waitFor();assert.equal(service.sourceNodeId,ids.source);assert.equal(restores.at(-1).snapshotId,'e'.repeat(64));assert.equal(restores.at(-1).nodeId,ids.target);
  // Finish waits read-only, can be cancelled, and resumes without new restore/schedule jobs.
  for(const language of ['ru','en'])for(const width of [1440,390]){
   const toggle=page.getByRole('button',{name:language==='en'?'Switch to English':'Переключить на русский',exact:true});if(await toggle.count())await toggle.click();await page.setViewportSize({width,height:900});
   const finishLabel=language==='en'?'Finish protection check':'Завершить проверку защиты',confirmLabel=language==='en'?'Confirm':'Подтвердить',cancelLabel=language==='en'?'Cancel':'Отмена',waitingText=language==='en'?'Waiting for fresh schedule and exact restore observations.':'Ожидаем свежие данные о расписании и точном восстановлении.';
   service.setupState='schedule_required';holdTimer=true;observedSchedule={enabled:false};desiredSchedule={enabled:true,interval:service.backupInterval};timerPollsRemaining=0;
   await page.reload();const beforeCancelledComplete=requests.filter(r=>r.path.endsWith('/complete')).length;
   await page.getByRole('button',{name:finishLabel,exact:true}).click();await page.getByRole('button',{name:confirmLabel,exact:true}).click();
   await page.locator('#dialog [data-completion-wait]').getByText(waitingText,{exact:true}).waitFor();assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),`completion wait overflow ${language}/${width}`);
   if(process.env.UI_SCREENSHOT_DIR)await page.screenshot({path:process.env.UI_SCREENSHOT_DIR+`/completion-wait-${width}-${language}.png`,fullPage:true});
   assert.equal(requests.filter(r=>r.path.endsWith('/complete')).length,beforeCancelledComplete,'no completion during wait');
   await page.getByRole('button',{name:cancelLabel,exact:true}).click();await page.waitForTimeout(1600);assert.equal(requests.filter(r=>r.path.endsWith('/complete')).length,beforeCancelledComplete,'no completion after cancellation');
   let expectedNewJobs=0;
   if(language==='ru'&&width===1440){
    const advancedPoint='9'.repeat(64);service.latestBackup={...service.latestBackup,snapshot:advancedPoint};service.snapshots.push({id:advancedPoint,time:new Date().toISOString(),serviceId:service.id,repositoryId});
    await page.getByText(advancedPoint,{exact:true}).first().waitFor();const beforeChangedPoint=jobs.length;
    await page.getByRole('button',{name:finishLabel,exact:true}).click();await page.getByRole('button',{name:confirmLabel,exact:true}).click();await page.getByText(/completion_identity_changed/).waitFor();
    assert.equal(jobs.length,beforeChangedPoint,'changed point must fail before any command');assert.equal(requests.filter(r=>r.path.endsWith('/complete')).length,beforeCancelledComplete);await page.getByRole('button',{name:cancelLabel,exact:true}).click();expectedNewJobs=1;
   }
   holdTimer=false;const beforeResumeJobs=jobs.length;await page.getByRole('button',{name:finishLabel,exact:true}).click();await page.getByRole('button',{name:confirmLabel,exact:true}).click();await page.locator('#dialog').waitFor({state:'hidden'});assert.equal(jobs.length,beforeResumeJobs+expectedNewJobs,'same-point resume must not replay; an explicitly new point gets one restore');assert.equal(requests.filter(r=>r.path.endsWith('/complete')).length,beforeCancelledComplete+1);assert.equal(earlyCompleteAttempts,0);
  }
  await page.getByRole('button',{name:'Переключить на русский',exact:true}).click();
  // Reloaded finish validation does not activate again, and missing health cannot complete.
  const unverifiedRestore=restores.find(r=>r.nodeId===service.recoveryNodeId&&r.snapshotId===service.latestBackup.snapshot);unverifiedRestore.applicationHealthVerified=false;unverifiedRestore.healthScope='running-only';
  const beforeUnverified=requests.filter(r=>r.path.endsWith('/complete')).length;unverified=true;service.setupState='unverified';await page.reload();await page.getByRole('button',{name:'Завершить проверку защиты',exact:true}).click();await page.getByRole('button',{name:'Подтвердить',exact:true}).click();await page.getByText(/application_health_unverified/).waitFor();assert.equal(service.setupState,'unverified');assert.equal(requests.filter(r=>r.path.endsWith('/complete')).length,beforeUnverified);await page.getByRole('button',{name:'Отмена',exact:true}).click();unverified=false;service.setupState='complete';unverifiedRestore.applicationHealthVerified=true;unverifiedRestore.healthScope='docker';
  // Both languages and mobile shell; preserve all original routes.
  for(const width of [1440,390]){await page.setViewportSize({width,height:900});for(const route of ['services','storages','dashboard','restore','nodes','history','settings']){await page.goto(`http://127.0.0.1:${server.address().port}/ops/#${route}`);await page.locator('.main').waitFor();await page.waitForTimeout(60);assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),`overflow ${route} ${width}`);if(process.env.UI_SCREENSHOT_DIR&&route==='services')await page.screenshot({path:process.env.UI_SCREENSHOT_DIR+`/own-services-${width}-ru.png`,fullPage:true});}}
  const english=page.getByRole('button',{name:'Switch to English',exact:true});if(await english.count())await english.click();await page.goto(`http://127.0.0.1:${server.address().port}/ops/#services`);await page.getByRole('heading',{name:'Compose services',exact:true}).waitFor();for(const width of [1440,390]){await page.setViewportSize({width,height:900});for(const route of ['services','storages','dashboard','restore','nodes','history','settings']){await page.goto(origin+'/ops/#'+route);await page.locator('.main').waitFor();await page.waitForTimeout(60);assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),`overflow en ${route} ${width}`);if(process.env.UI_SCREENSHOT_DIR&&route==='services')await page.screenshot({path:process.env.UI_SCREENSHOT_DIR+`/own-services-${width}-en.png`,fullPage:true});}}await page.goto(origin+'/ops/#services');await page.getByRole('heading',{name:'Compose services',exact:true}).waitFor();
  // S3 form and bad-credential failure may never mark a connection successful.
  await page.getByRole('button',{name:'Connect your service',exact:true}).click();await page.getByLabel('Source host',{exact:true}).selectOption(ids.source);await page.getByLabel('Separate recovery host').selectOption(ids.target);await page.getByLabel('Discovered Compose project').selectOption('ordinary');await page.getByLabel('I confirm').check();await page.getByLabel('Storage',{exact:true}).selectOption('');await page.getByLabel('Storage name',{exact:true}).fill('S3');await page.getByLabel('Storage kind').selectOption('s3');await page.getByLabel('HTTPS endpoint').fill('https://s3.example.test');await page.getByLabel('Bucket',{exact:true}).fill('test-bucket');await page.getByLabel('S3 access key').fill('access');await page.getByLabel('S3 secret key',{exact:true}).fill(secret);await page.getByLabel('Independent restic encryption password').fill(secret);await page.getByRole('button',{name:'Prepare secure connection'}).click();failBinding=true;await page.getByRole('button',{name:'Confirm connection',exact:true}).click();await page.getByText(/repository_auth_failed/).first().waitFor();assert.equal(await page.getByRole('button',{name:'Continue setup',exact:true}).count(),0);
  const beforeExpiry=requests.filter(r=>r.path.endsWith('/connect')).length;expireNext=true;await page.getByRole('button',{name:'Start fresh challenge'}).click();await page.getByRole('button',{name:'Prepare secure connection'}).click();await page.getByRole('button',{name:'Confirm connection',exact:true}).click();await page.getByText(/challenge_expired/).first().waitFor();assert.equal(requests.filter(r=>r.path.endsWith('/connect')).length,beforeExpiry);expireNext=false;
  // Persistent safe activation scope: unknown result hides resume, known failure plus fresh isolation permits it.
  service.setupState='attention_required';sourceFenced=true;const isolated=restores.find(r=>r.state==='isolated_ready'&&r.nodeId===service.recoveryNodeId);const stop=job('compose-stop',service.sourceNodeId,{serviceId:service.id},{fenced:true});stop.status='succeeded';const target=job('compose-activate',service.recoveryNodeId,{serviceId:service.id,restoreId:isolated.id},{},'activation_failed');target.status='outcome_unknown';service.activationGroupId=randomUUID();service.activation={groupId:service.activationGroupId,sourceStopJobId:stop.id,targetJobId:target.id,status:'outcome_unknown'};await page.reload();assert.equal(await page.getByRole('button',{name:'Resume source',exact:true}).count(),0);target.status='failed';service.activation.status='failed';await page.reload();await page.getByRole('button',{name:'Resume source',exact:true}).click();await page.getByRole('button',{name:'Confirm',exact:true}).click();await page.locator('#dialog').waitFor({state:'hidden'});assert.equal(requests.filter(r=>r.path.endsWith('/resume-source')).length,1);assert.equal(await page.getByRole('button',{name:'Resume source',exact:true}).count(),0);
  // Original demo actions remain wired to their original action names and plan/job flow.
  legacyMode=true;
  for(const [route,label,action] of [['dashboard','Back up now','backup'],['restore','Verify integrity','verify'],['restore','Run restore check','restore-check'],['restore','Keep a restored copy','restore-preview'],['restore','Remove this copy','remove-preview'],['settings','Apply schedule','set-schedule']]){
    await page.goto(`http://127.0.0.1:${server.address().port}/ops/#${route}`);await page.reload();await page.getByRole('button',{name:label,exact:true}).click();await page.getByRole('button',{name:'Start operation',exact:true}).click();await page.locator('#dialog').waitFor({state:'hidden'});assert(jobs.some(j=>j.action===action),action);
  }
  // A fresh Compose-only home with connected storage stays free of phantom demo setup.
  legacyMode=false;service=null;restores=[];jobs=[];storage={id:randomUUID(),name:'Connected repository',kind:'rest',endpoint:'https://storage.example.test/connected',repositoryId,bindings:[ids.source,ids.target].map(nodeId=>({nodeId,state:'connected',repositoryId,bindingGeneration:7,requestId:randomUUID()}))};
  await page.goto(origin+'/ops/#dashboard');await page.reload();await page.getByRole('heading',{name:'Compose services',exact:true}).waitFor();assert.equal(await page.getByRole('button',{name:'Finish setup',exact:true}).count(),0);assert.equal(await page.getByRole('button',{name:'Back up now',exact:true}).count(),0);
  async function selectConnectedStorage(){await page.getByRole('button',{name:'Connect your service',exact:true}).click();await page.getByLabel('Source host',{exact:true}).selectOption(ids.source);await page.getByLabel('Separate recovery host').selectOption(ids.target);await page.getByLabel('Discovered Compose project').selectOption('ordinary');await page.getByLabel('I confirm').check();await page.getByLabel('Storage',{exact:true}).selectOption(storage.id);}
  await selectConnectedStorage();await page.getByText('Reusing the existing connection',{exact:false}).waitFor();assert(!(await page.locator('.managed-form').innerText()).includes('null'));assert.equal(await page.getByLabel('Storage',{exact:true}).evaluate(el=>el===document.activeElement),true);assert.equal(await page.locator('input[type=password]').count(),0);if(process.env.UI_SCREENSHOT_DIR)await page.screenshot({path:process.env.UI_SCREENSHOT_DIR+'/reuse-no-credentials-en.png',fullPage:true});
  const beforeReuse=requests.length;await page.getByRole('button',{name:'Use connected storage and continue',exact:true}).click();await page.getByText('Setup confirmed by the server.',{exact:true}).waitFor();const reuseRequests=requests.slice(beforeReuse);assert(reuseRequests.some(r=>r.path==='/api/services'));assert(!reuseRequests.some(r=>r.path.includes('/prepare')||r.path.includes('/connect')||r.path==='/api/storages'));assert(!JSON.stringify(reuseRequests).includes('repoPassword'));assert(!JSON.stringify(reuseRequests).includes('credentials'));
  await page.getByRole('button',{name:'Close',exact:true}).click();await page.goto(origin+'/ops/#dashboard');await page.reload();await page.locator('[data-setup-state="complete"]').waitFor();assert.equal(await page.getByRole('button',{name:'Finish setup',exact:true}).count(),0);
  for(const fault of ['missing','mismatch','generation','stale','stale-observation']){reuseFault=fault;await page.reload();await selectConnectedStorage();assert.equal(await page.getByRole('button',{name:'Use connected storage and continue',exact:true}).count(),0);assert(await page.locator('input[type=password]').count()>0);await page.getByRole('button',{name:'Prepare secure connection',exact:true}).waitFor();}
  // Catalog omission also blocks reuse even if the other node has an older connected observation.
  reuseFault='';const originalBindings=storage.bindings;storage.bindings=storage.bindings.slice(0,1);await page.reload();await selectConnectedStorage();assert(await page.locator('input[type=password]').count()>0);storage.bindings=originalBindings;
  // A binding changing after form render is re-observed before import, without a passwordless mutation.
  await page.reload();await selectConnectedStorage();reuseFault='mismatch';const beforeRace=requests.length;await page.getByRole('button',{name:'Use connected storage and continue',exact:true}).click();await page.getByText(/storage_binding_stale/).first().waitFor();assert.equal(requests.length,beforeRace);assert(await page.locator('input[type=password]').count()>0);reuseFault='';
  // Storage-only reconnect remains an explicit credential-bearing flow.
  await page.goto(origin+'/ops/#storages');await page.reload();await page.getByRole('button',{name:'Connect hosts or retry binding',exact:true}).click();await page.getByLabel('Source host',{exact:true}).selectOption(ids.source);await page.getByLabel('Separate recovery host').selectOption(ids.target);assert(await page.locator('input[type=password]').count()>0);assert.equal(await page.getByRole('button',{name:'Use connected storage and continue',exact:true}).count(),0);
  // Real Compose observations and selected/legacy demo faults remain visible and code-specific.
  observationError='prerequisite_unavailable';await page.goto(origin+'/ops/#dashboard');await page.reload();await page.getByText(/required host dependency is unavailable/).first().waitFor();assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'mobile prerequisite error overflow');if(process.env.UI_SCREENSHOT_DIR)await page.screenshot({path:process.env.UI_SCREENSHOT_DIR+'/compose-prerequisite-error-en.png',fullPage:true});assert.equal(await page.getByText('A protection condition needs attention.',{exact:true}).count(),0);observationError='';selectedDemo=true;await page.reload();await page.getByText(/bundled demo package is unsupported/).first().waitFor();await page.getByRole('button',{name:'Finish setup',exact:true}).waitFor();selectedDemo=false;legacyOnly=true;omitDemoMarker=true;await page.reload();await page.getByText(/bundled demo package is unsupported/).first().waitFor();assert.equal(await page.getByRole('button',{name:'Back up now',exact:true}).isDisabled(),true);
  assert.equal(rejectedJobs.length,0);for(const request of requests.filter(r=>r.path==='/api/storages'||r.path==='/api/services'||r.path.endsWith('/prepare')||r.path.endsWith('/connect')||r.path.endsWith('/activate')||r.path.endsWith('/resume-source'))){assert.equal(Number.isInteger(request.body.expectedRevision),true,request.path);assert.equal(typeof request.body.idempotencyKey,'string',request.path);}
  assert.equal(serverErrors.length,0,serverErrors.join('\n'));assert.equal(errors.length,0,errors.join('\n'));
  console.log('PASS real Chromium synthetic transport: strict two-field job contract, identical uncertain enqueue retry without duplicate job, revision/idempotency retained on other mutations, REST wizard, exact scoped restore, schedule/complete, controlled move with unprotected state, S3 bad credentials, unsupported discovery, RU/EN, 390/1440px, credential-free same-repository reuse with missing/mismatch/generation/stale negatives, fresh Compose-only home, selected/legacy demo faults, internal8080/published18190 port selection, legacy actions/routes, identical uncertain retry, expiry, persistent guarded resume, no secret browser storage, no HTML execution.');
 }finally{await browser?.close();server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
}
if(process.argv.includes('--browser'))await browserChecks();
