/* Own-service UI. Secrets live only in this module's transient wizard object. */
export const canonical = value => JSON.stringify(value && typeof value === 'object' && !Array.isArray(value)
  ? Object.fromEntries(Object.keys(value).sort().map(k => [k, JSON.parse(canonical(value[k]))]))
  : Array.isArray(value) ? value.map(v => JSON.parse(canonical(v))) : value);
const decode = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));
const encode = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
export async function sealStorage(challenge, binding, repoPassword, credentials) {
  const {metadata, requestId, expiresAt} = challenge;
  const {nodeId, key, bindingGeneration, mode} = binding;
  if (key.algorithm !== 'RSA-OAEP-256+A256GCM' || !Number.isInteger(bindingGeneration) || bindingGeneration < 1 || Date.parse(expiresAt) <= Date.now()) throw Object.assign(new Error(), {code:'challenge_expired'});
  const publicBytes = decode(key.publicKey);
  const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', publicBytes)), b => b.toString(16).padStart(2,'0')).join('');
  if (digest !== key.id) throw Object.assign(new Error(), {code:'key_identity_mismatch'});
  const rsa = await crypto.subtle.importKey('spki', publicBytes, {name:'RSA-OAEP',hash:'SHA-256'}, false, ['wrapKey']);
  if (rsa.algorithm.modulusLength !== 3072) throw Object.assign(new Error(), {code:'invalid_key'});
  const aes = await crypto.subtle.generateKey({name:'AES-GCM',length:256}, true, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = {v:1,nodeId,keyId:key.id,storageId:metadata.id,requestId,bindingGeneration,mode,expiresAt,purpose:'storage'};
  const plaintext = new TextEncoder().encode(canonical({metadata,repoPassword,credentials,bindingGeneration,requestId,mode}));
  if (plaintext.length > 16384) throw Object.assign(new Error(), {code:'credentials_too_large'});
  try {
    const ciphertext = await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:new TextEncoder().encode(canonical(aad)),tagLength:128}, aes, plaintext);
    const wrappedKey = await crypto.subtle.wrapKey('raw', aes, rsa, {name:'RSA-OAEP'});
    return {v:1,algorithm:key.algorithm,nodeId,keyId:key.id,storageId:metadata.id,requestId,bindingGeneration,mode,expiresAt,wrappedKey:encode(wrappedKey),iv:encode(iv),ciphertext:encode(ciphertext)};
  } finally { plaintext.fill(0); }
}

export function canReuseStorage(storage, selectedNodes, isFresh) {
  if (!storage || !/^[a-f0-9]{64}$/.test(storage.repositoryId || '') || selectedNodes.length !== 2 || selectedNodes[0]?.id === selectedNodes[1]?.id) return false;
  return selectedNodes.every(node => {
    if (!node || !isFresh(node) || node.status?.compose?.ready !== true) return false;
    const binding = storage.bindings?.find(b => b.nodeId === node.id);
    const seen = node.status.compose.storages?.find(b => b.storageId === storage.id);
    return binding?.state === 'connected' && binding.repositoryId === storage.repositoryId &&
      Number.isInteger(binding.bindingGeneration) && binding.bindingGeneration > 0 && Boolean(binding.requestId) &&
      seen?.connected === true && seen.repositoryId === storage.repositoryId &&
      seen.bindingGeneration === binding.bindingGeneration && seen.requestId === binding.requestId;
  });
}

// Completion waits only for authenticated observations; it never submits a command.
export async function waitForCompletionObservation({readOverview,isFresh,service,point,restoreId,cancelled=()=>false,onWait=()=>{},now=()=>performance.now(),pause=ms=>new Promise(resolve=>setTimeout(resolve,ms)),timeoutMs=120000}) {
  const fail=code=>{throw Object.assign(new Error(),{code});};
  const hex=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
  const scope=Object.fromEntries(['id','sourceNodeId','recoveryNodeId','storageId','fingerprint','projectId','backupInterval'].map(k=>[k,service?.[k]]));
  const exact=Object.fromEntries(['snapshot','repositoryId','manifestDigest','sourceFingerprint'].map(k=>[k,point?.[k]]));
  if(!restoreId || Object.values(scope).some(v=>typeof v!=='string'||!v) || scope.sourceNodeId===scope.recoveryNodeId || !Object.values(exact).every(hex) || exact.sourceFingerprint!==scope.fingerprint)fail('completion_proof_unavailable');
  const deadline=now()+Math.min(120000,Math.max(1,timeoutMs));
  const check=()=>{if(cancelled())fail('session_ended');if(now()>=deadline)fail('completion_observation_timeout');};
  const single=(items,match)=>{const found=(items||[]).filter(match);return found.length===1?found[0]:undefined;};
  const checks=['compose-model','data-hashes','metadata','image-identities','fresh-resources','runtime-isolation','application-health'];
  const healthy=r=>r?.applicationHealthVerified===true&&['http','docker'].includes(r.healthScope)&&Array.isArray(r.checks)&&checks.every(k=>r.checks.includes(k));
  const bound=r=>r&&r.serviceId===scope.id&&r.snapshotId===exact.snapshot&&r.repositoryId===exact.repositoryId&&r.manifestDigest===exact.manifestDigest&&r.sourceFingerprint===exact.sourceFingerprint;
  for(;;){
    check();let timer;
    const overview=await Promise.race([Promise.resolve().then(readOverview),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Object.assign(new Error(),{code:'completion_observation_timeout'})),Math.max(1,deadline-now()));})]).finally(()=>clearTimeout(timer));
    check();
    if(!overview || typeof overview!=='object')fail('completion_proof_unavailable');
    const current=single(overview.services,s=>s.id===scope.id);
    if(!current || Object.keys(scope).some(k=>current[k]!==scope[k]))fail('completion_identity_changed');
    const backup=current.latestBackup;
    if(backup && Object.keys(exact).some(k=>backup[k]!==undefined&&backup[k]!==exact[k]))fail('completion_identity_changed');
    const storage=single(overview.storages,s=>s.id===scope.storageId);
    if(storage?.repositoryId && storage.repositoryId!==exact.repositoryId)fail('completion_identity_changed');
    const source=single(overview.nodes,n=>n.id===scope.sourceNodeId),target=single(overview.nodes,n=>n.id===scope.recoveryNodeId);
    const catalog=single(overview.restores,r=>r.id===restoreId);
    const observed=single(target?.status?.compose?.restores,r=>(r.id||r.restoreId)===restoreId);
    for(const restore of [catalog,observed])if(restore && ['serviceId','snapshotId','repositoryId','manifestDigest','sourceFingerprint'].some(k=>restore[k]!==undefined&&restore[k]!==({serviceId:scope.id,snapshotId:exact.snapshot,...exact})[k]))fail('completion_identity_changed');
    if(catalog && catalog.nodeId!==scope.recoveryNodeId)fail('completion_identity_changed');
    if(catalog?.applicationHealthVerified===false || catalog?.healthScope==='running-only')fail('application_health_unverified');
    if(catalog && catalog.state!=='isolated_ready')fail('completion_proof_unavailable');
    const seen=single(source?.status?.compose?.services,s=>(s.serviceId||s.id)===scope.id);
    const fresh=source&&target&&isFresh(source)&&isFresh(target)&&source.status?.compose?.ready===true&&target.status?.compose?.ready===true;
    if(fresh && seen && ['fingerprint','storageId','projectId'].some(k=>seen[k]!==undefined&&seen[k]!==scope[k]))fail('completion_identity_changed');
    if(fresh && observed?.state==='isolated_ready' && Array.isArray(observed.ports) && observed.ports.length)fail('completion_proof_unavailable');
    if(fresh && canReuseStorage(storage,[source,target],isFresh) && backup && Object.keys(exact).every(k=>backup[k]===exact[k]) && bound(catalog) && catalog.state==='isolated_ready' && healthy(catalog) && bound(observed) && observed.state==='isolated_ready' && healthy(observed) && Array.isArray(observed.ports) && observed.ports.length===0 && seen && seen.fingerprint===scope.fingerprint && seen.storageId===scope.storageId && seen.projectId===scope.projectId && (seen.state||seen.sourceState)==='running' && seen.schedule?.enabled===true && seen.schedule.interval===scope.backupInterval)return current;
    onWait();check();await pause(Math.min(1500,deadline-now()));
  }
}

export function createManagedUI(ctx) {
  const {h,button,field,select,notice,pill,head,state,api,render,fresh,date,bytes,showJob,refreshOverview} = ctx;
  const tr = (ru,en) => state.lang === 'ru' ? ru : en;
  const stateLabel = code => ({configuring:tr('Настраивается','Configuring'),registered:tr('Зарегистрирован','Registered'),backup_required:tr('Нужна копия','Backup required'),restore_required:tr('Нужно проверить восстановление','Restore required'),schedule_required:tr('Нужно применить расписание','Schedule required'),unverified:tr('Здоровье приложения не проверено','Application health unverified'),complete:tr('Защита проверена','Protection verified'),moving:tr('Перенос выполняется','Move in progress'),active_unprotected:tr('Работает без подтвержденной копии','Running without a confirmed backup'),attention_required:tr('Требуется проверка','Needs attention')})[code]||tr('Состояние не подтверждено','State unconfirmed');
  const list = name => state.overview?.[name] || [];
  const nodes = () => list('nodes');
  const node = id => nodes().find(n=>n.id===id);
  const ready = n => fresh(n) && n.status?.compose?.ready === true;
  const reuse = a => !a.storageOnly && canReuseStorage(list('storages').find(s=>s.id===a.storage),[node(a.source),node(a.target)],fresh);
  const rev = () => state.overview.revision;
  let wizard, busy=false, error='', progress='', pending=new Map(), activations=new Map(), alive=0, waitingCompletion=false;
  const init = () => ({id:crypto.randomUUID(),serviceId:crypto.randomUUID(),name:'',source:'',target:'',project:'',storage:'',storageName:'',kind:'rest',mode:'create',endpoint:'',bucket:'',prefix:'',region:'',username:'',password:'',accessKeyId:'',secretAccessKey:'',sessionToken:'',repoPassword:'',interval:'hourly',exclusive:false,http:false,healthService:'',port:'8080',path:'/',expectedStatus:'200',stage:'select',jobs:[]});
  const w = () => wizard ||= init();
  function clear() { alive++;waitingCompletion=false; if(wizard)wipeSecrets(wizard);wizard=null; pending.clear(); activations.clear(); busy=false;error='';progress=''; }
  async function mutate(path,body) {
    // Keep the exact request identity after an uncertain HTTP response. No new effect on retry.
    const signature=path+'\n'+canonical(body);
    let request=pending.get(signature);
    if (!request) {request={...body,...(path==='/api/jobs'?{}:{expectedRevision:rev()}),idempotencyKey:crypto.randomUUID()};pending.set(signature,request);}
    try {
      const result=await api(path,request);pending.delete(signature);
      if (result.revision !== undefined) state.overview.revision=result.revision;
      return result;
    } catch(e) {
      // A definite rejection has no effect to replay. Uncertain transport keeps its exact request.
      if(e.http && e.http<500)pending.delete(signature);
      throw e;
    }
  }
  function explain(code) {
    const explanations={
      operation_busy:tr('Сервер занят. Дождитесь завершения и повторите действие.','Host busy. Wait for completion and retry.'),
      envelope_expired:tr('Срок шифрованного запроса истек. Получите новый запрос.','The sealed request expired. Request a fresh challenge.'),
      challenge_expired:tr('Срок запроса истек. Подготовьте новый запрос подключения.','The challenge expired. Prepare a fresh connection request.'),
      outcome_unknown:tr('Результат неизвестен. Сначала проверьте фактическое состояние в операциях.','Outcome unknown. Inspect its actual state in Operations first.'),
      operation_outcome_unknown:tr('Результат операции неизвестен. Новые изменения заблокированы до проверки ее состояния.','An operation outcome is unknown. New changes are blocked until its state is inspected.'),
      network:tr('Нет ответа панели. Повтор использует тот же номер запроса.','Panel response unavailable. Retry uses the same request identity.'),
      package_unsupported:tr('Тестовый пакет этого сервера не поддерживается. Проверьте его установку и совместимость.','This host’s bundled demo package is unsupported. Check its installation and compatibility.'),
      compose_not_ready:tr('Служба сервера еще не подтвердила готовность Compose. Проверьте требования и дождитесь свежего состояния.','The host has not confirmed Compose readiness. Check prerequisites and wait for a fresh observation.'),
      compose_key_unavailable:tr('Открытый ключ сервера недоступен. Защищенное подключение хранилища пока невозможно.','The host public key is unavailable. Secure storage binding cannot proceed.'),
      prerequisite_unavailable:tr('На сервере отсутствует обязательная зависимость. Проверьте требования установки Compose.','A required host dependency is unavailable. Check Compose installation prerequisites.'),
      observation_deadline:tr('Проверка сервера не завершилась вовремя. Дождитесь свежих сведений.','Host observation timed out. Wait for fresh observations.'),
      managed_observation_failed:tr('Не удалось получить состояние Compose на сервере. Готовность не подтверждена.','The host could not observe Compose state. Readiness is unconfirmed.'),
      compose_status_invalid:tr('Сервер передал неполное состояние Compose. Требуется новая проверка.','The host reported invalid Compose state. A new observation is required.'),
      docker_result_invalid:tr('Не удалось проверить ответ Docker на сервере. Состояние приложений не подтверждено.','The host could not validate Docker’s response. Application state is unconfirmed.'),
      discovery_limit:tr('Обнаружение превысило допустимое число проектов или ресурсов. Этот набор не поддерживается.','Discovery exceeded project or resource limits. This inventory is unsupported.'),
      storage_binding_stale:tr('Подключение хранилища изменилось или устарело. Дождитесь свежих серверов; если подключение не подтвердится, введите учетные данные заново.','The storage binding changed or became stale. Wait for fresh hosts; if the binding remains unconfirmed, reenter credentials.'),
      storage_not_connected:tr('Хранилище не подключено к выбранному серверу. Выполните защищенное подключение.','Storage is not connected on the selected host. Complete the secure connection.'),
      repository_password_required:tr('Для нового или неподтвержденного подключения нужен пароль шифрования restic.','A new or unconfirmed binding requires the restic encryption password.'),
      choose_two_ready_nodes:tr('Выберите два разных сервера со свежим подтверждением готовности Compose.','Choose two different hosts with fresh confirmed Compose readiness.'),
      repository_auth_failed:tr('Хранилище отклонило учетные данные. Исправьте их перед новым подключением.','Storage rejected the credentials. Correct them before connecting again.'),
      completion_observation_timeout:tr('Свежие данные не получены за две минуты. Настройку можно продолжить после обновления состояния серверов.','Fresh observations were not received within two minutes. Continue setup after the hosts update.'),
      completion_identity_changed:tr('Сервис или точная копия изменились. Проверьте выбранное восстановление перед продолжением.','The service or exact backup changed. Review the selected restore before continuing.'),
      completion_proof_unavailable:tr('Для завершения не хватает подтвержденных сведений о точной копии и восстановлении.','Confirmed proof of the exact backup and restore is required before completion.'),
      application_health_unverified:tr('Здоровье приложения не подтверждено. Настройте Docker healthcheck или проверку HTTP и повторите восстановление.','Application health is unverified. Configure Docker healthcheck or an HTTP check and repeat recovery.')
    };
    return (explanations[code] || tr('Служба сообщила условие, требующее проверки.','The service reported a condition that requires inspection.'))+' ['+String(code||'unknown_error').slice(0,100)+']';
  }
  const message = e => explain(e.code||'unknown_error');
  async function run(fn) { if(busy)return;const epoch=alive;busy=true;error='';render();try{await fn();}catch(e){if(epoch===alive){progress='';error=message(e);}}finally{if(epoch===alive){busy=false;render();}} }
  async function observeJobs(items) {
    const epoch=alive;
    if(wizard) wizard.jobs=items.map(j=>j.id);
    for(const item of items) {
      let job=item;
      if(job.status==='outcome_unknown'){const response=await api('/api/jobs/'+encodeURIComponent(job.id));job=response.job||response;}
      while(['queued','dispatched','running'].includes(job.status)) {
        if(epoch!==alive)throw Object.assign(new Error(),{code:'session_ended'});
        progress=tr('Ожидание операции: ','Waiting for operation: ')+ctx.t(job.action)+' · '+ctx.t(job.status);render();
        await new Promise(resolve=>setTimeout(resolve,1500));
        const response=await api('/api/jobs/'+encodeURIComponent(job.id));job=response.job||response;
      }
      Object.assign(item,job);
      if(job.status!=='succeeded')throw Object.assign(new Error(),{code:job.error||job.status||'job_not_confirmed'});
      Object.assign(item,job);
    }
    await refreshOverview(false);progress='';return items;
  }
  async function operation(service,action,targetId,extra={},snapshot) {
    const parameters={serviceId:service.id,...extra};
    if(['compose-backup','compose-verify','compose-restore'].includes(action))parameters.storageId=service.storageId;
    if(snapshot)parameters.snapshotId=snapshot;
    const body={nodeId:targetId,action,parameters};if(snapshot)body.snapshotId=snapshot;
    const operationKey='operation\n'+canonical(body);
    const accepted=pending.get(operationKey);
    if(accepted){try{return (await observeJobs([accepted]))[0];}finally{if(['succeeded','failed','outcome_unknown'].includes(accepted.status))pending.delete(operationKey);}}
    const signature='/api/plans\n'+canonical(body);
    let plan=pending.get(signature);
    if(!plan){plan=await api('/api/plans',body);pending.set(signature,plan);}
    let result;try{result=await mutate('/api/jobs',{planId:plan.id});}catch(e){if(e.http && e.http<500)pending.delete(signature);throw e;}pending.delete(signature);
    pending.set(operationKey,result.job);
    try{return (await observeJobs([result.job]))[0];}finally{if(['succeeded','failed','outcome_unknown'].includes(result.job.status))pending.delete(operationKey);}
  }
  const serviceById = id => list('services').find(s=>s.id===id);
  async function connect() {
    const a=w();
    if(!ready(node(a.source))||!ready(node(a.target))||a.source===a.target)throw Object.assign(new Error(),{code:'choose_two_ready_nodes'});
    const wasReusable=reuse(a);
    if(wasReusable) {
      await refreshOverview(false);
      if(!reuse(a))throw Object.assign(new Error(),{code:'storage_binding_stale'});
      wipeSecrets(a);a.stage='import';a.reused=true;
      await advance();return;
    }
    if(!a.repoPassword)throw Object.assign(new Error(),{code:'repository_password_required'});
    if(!a.created && !a.storage){const body={id:a.id,name:a.storageName,kind:a.kind,endpoint:a.endpoint};if(a.kind==='s3'){body.bucket=a.bucket;body.prefix=a.prefix;if(a.region)body.region=a.region;}await mutate('/api/storages',body);a.created=true;}
    const sid=a.storage||a.id;
    if(!a.challenge) a.challenge=await mutate('/api/storages/'+sid+'/prepare',{sourceNodeId:a.source,nodeIds:[a.source,a.target],mode:a.storage?'attach':a.mode});
    a.stage='seal';render();
  }
  async function confirmConnect() {
    const a=w(),challenge=a.challenge;
    if(!challenge || (!a.connectResult && Date.parse(challenge.expiresAt)<=Date.now()))throw Object.assign(new Error(),{code:'challenge_expired'});
    if(!a.sealed) {
      const credentials=a.kind==='rest'?{username:a.username,password:a.password}:{accessKeyId:a.accessKeyId,secretAccessKey:a.secretAccessKey,...(a.sessionToken?{sessionToken:a.sessionToken}:{})};
      a.sealed=await Promise.all(challenge.bindings.map(async b=>({nodeId:b.nodeId,envelope:await sealStorage(challenge,b,a.repoPassword,credentials)})));
    }
    const result=a.connectResult||await mutate('/api/storages/'+challenge.metadata.id+'/connect',{requestId:challenge.requestId,bindings:a.sealed});a.connectResult=result;
    try {await observeJobs(result.jobs);} catch(e){if(e.code!=='network'){a.challenge=null;a.sealed=null;a.connectResult=null;a.stage='storage';}throw e;}
    const observed=list('storages').find(s=>s.id===challenge.metadata.id);
    if(!observed?.repositoryId || ![a.source,a.target].every(nodeId=>observed.bindings?.some(b=>b.nodeId===nodeId&&b.state==='connected'&&b.repositoryId===observed.repositoryId)))throw Object.assign(new Error(),{code:'storage_binding_unconfirmed'});
    a.connectResult=null;a.stage=a.storageOnly?'done':'import'; a.sealed=null;a.challenge=null;
    if(a.storageOnly){wipeSecrets(a);progress=tr('Подключение подтверждено операциями серверов.','Connection confirmed by host jobs.');}
  }
  function wipeSecrets(a) { for(const k of ['password','secretAccessKey','sessionToken','repoPassword','accessKeyId','username'])a[k]=''; }
  async function observedCompletion(service,point,restoreId) {
    const epoch=alive;
    return waitForCompletionObservation({service,point,restoreId,isFresh:fresh,cancelled:()=>epoch!==alive,
      readOverview:async()=>{await refreshOverview(false);if(state.online!==true||!state.overview)throw Object.assign(new Error(),{code:'completion_proof_unavailable'});return state.overview;},
      onWait:()=>{waitingCompletion=true;progress=tr('Ожидаем свежие данные о расписании и точном восстановлении.','Waiting for fresh schedule and exact restore observations.');render();const d=document.getElementById('dialog');if(d?.open){const text=d.querySelector('[data-completion-wait]'),cancel=d.querySelector('[data-completion-cancel]');if(text)text.textContent=progress;if(cancel)cancel.disabled=false;}}}).finally(()=>{waitingCompletion=false;});
  }
  async function advance() {
    const a=w();let service=serviceById(a.serviceId);
    if(a.stage==='import') {
      const p=node(a.source)?.status?.compose?.projects?.find(p=>p.id===a.project);
      if(!p?.supported||!a.exclusive)throw Object.assign(new Error(),{code:'project_confirmation_required'});
      const body={id:a.serviceId,name:a.name||p.name,sourceNodeId:a.source,recoveryNodeId:a.target,projectId:p.id,fingerprint:p.fingerprint,storageId:a.storage||a.id,backupInterval:a.interval,exclusiveWriters:true};
      if(a.http)body.healthCheck={service:a.healthService,port:Number(a.port),path:a.path,expectedStatus:Number(a.expectedStatus)};
      const result=a.registerResult||await mutate('/api/services',body);a.registerResult=result;service=result.service;try{await observeJobs([result.job]);}catch(e){if(result.job.status==='failed')a.registerResult=null;throw e;}a.registerResult=null;a.stage='backup';
    }
    service=serviceById(a.serviceId)||service;
    a.completionService ||= {...service};
    if(a.stage==='backup'){const job=await operation(service,'compose-backup',service.sourceNodeId);a.point=job.result;a.snapshot=job.result?.snapshot;if(!a.snapshot)throw Object.assign(new Error(),{code:'backup_snapshot_missing'});a.stage='restore';}
    if(a.stage==='restore'){const job=await operation(service,'compose-restore',service.recoveryNodeId,{},a.snapshot);a.restoreId=job.result?.restoreId||job.id;a.stage='schedule';}
    if(a.stage==='schedule'){await operation(service,'compose-schedule',service.sourceNodeId,{interval:a.interval});a.stage='complete';}
    if(a.stage==='complete'){await observedCompletion(a.completionService,a.point,a.restoreId);const completed=await api('/api/services/'+a.serviceId+'/complete',{restoreId:a.restoreId,expectedRevision:rev()});if(completed.completed!==true||completed.service?.setupState!=='complete')throw Object.assign(new Error(),{code:'completion_unconfirmed'});a.stage='done';wipeSecrets(a);await refreshOverview(false);}
  }
  function input(a,key,label,type='text',required=false) {return field(label,h('input',{type,value:a[key]||'',required,autocomplete:'off',maxlength:type==='password'?4096:1024,oninput:e=>{a[key]=e.target.value;}}));}
  function choice(a,key,label,options){const id='managed-choice-'+key;return field(label,select(options,a[key],value=>{a[key]=value;render();document.getElementById(id)?.focus();},{id}));}
  function check(a,key,label){return h('label',{class:'managed-check'},h('input',{type:'checkbox',checked:a[key],onchange:e=>{a[key]=e.target.checked;}}),label);}
  function reason(code) {
    const reasons={
      compose_security_unsupported:tr('Опасные полномочия или доступ к серверу','Unsafe privileges or host access'),
      privileged:tr('Привилегированный контейнер','Privileged container'),
      compose_mount_unsupported:tr('Неподдерживаемое подключение данных','Unsupported data mount'),
      compose_field_unsupported:tr('Неподдерживаемое поле Compose','Unsupported Compose field'),
      compose_model_unsupported:tr('Неподдерживаемая модель Compose','Unsupported Compose model'),
      compose_replicas_unsupported:tr('Несколько экземпляров контейнера','Multiple container replicas'),
      compose_profiles_unresolved:tr('Неразрешенные профили Compose','Unresolved Compose profiles'),
      discovery_limit:tr('Превышен предел обнаружения','Discovery limit exceeded'),
      mount_source_unsafe:tr('Опасный источник подключенных данных','Unsafe mount source'),
      project_changed:tr('Конфигурация проекта изменилась','Project configuration changed'),
      prerequisite_unavailable:tr('Не выполнены требования сервера','Host prerequisite unavailable')
    };
    return (reasons[code]||tr('Служба не разрешила этот проект','Host service refused this project'))+' ['+code+']';
  }
  function optionsNodes(){return [['',tr('Выберите сервер','Select server')],...nodes().map(n=>[n.id,n.name+' · '+(ready(n)?tr('готов','ready'):n.status?.compose?.error||tr('нет свежих данных','not fresh'))])];}
  function alerts(){return [error?notice(error,'bad'):null,progress?notice(progress):null,busy?h('p',{'aria-live':'polite'},tr('Выполняется. Ожидаем подтвержденный результат.','Working. Waiting for a confirmed result.')):null].filter(Boolean);}
  function kit() {
    const a=w();const data={format:'rolypolyops-recovery-kit-v1',metadata:a.challenge?.metadata||list('storages').find(s=>s.id===(a.storage||a.id)),repoPassword:a.repoPassword,credentials:a.kind==='rest'?{username:a.username,password:a.password}:{accessKeyId:a.accessKeyId,secretAccessKey:a.secretAccessKey,sessionToken:a.sessionToken}};
    const url=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}));const link=h('a',{href:url,download:'rolypolyops-recovery-kit.json'});document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
  }
  function wizardView(storageOnly=false) {
    const a=w();a.storageOnly=storageOnly;
    const project=node(a.source)?.status?.compose?.projects?.find(p=>p.id===a.project);
    const form=h('form',{class:'card managed-form',onsubmit:e=>{e.preventDefault();run(()=>a.stage==='seal'?confirmConnect():['import','backup','restore','schedule','complete'].includes(a.stage)?advance():connect());}});
    form.append(h('h2',{},storageOnly?tr('Подключить хранилище','Connect storage'):tr('Подключить свой сервис','Connect your service')),notice(storageOnly?tr('Подключите отдельный репозиторий REST или S3. Учетные данные шифруются в браузере для выбранных серверов.','Connect a dedicated REST or S3 repository. Credentials are encrypted in this browser for the selected hosts.'):tr('Вся группа Compose останавливается на время копирования данных на локальный диск. Длительность зависит от объема данных и скорости диска. Постоянные данные должны находиться в перечисленных томах и подключенных файлах или каталогах. Изменяемый слой контейнера в копию не входит. Внешние маршруты и автоматизация по меткам не переносятся.','The whole Compose project pauses while data is staged locally. Pause length depends on data size and disk speed. Persistent data must be in the listed volumes and file or directory mounts. The container writable layer is excluded. External routing and label-driven automation are not reproduced.')),...alerts());
    if(a.stage==='done'){form.append(...(a.restoreId?[h('p',{class:'mono'},tr('Восстановление: ','Restore: ')+a.restoreId)]:[]),notice(storageOnly?tr('Хранилище подключено.','Storage connected.'):tr('Настройка подтверждена сервером.','Setup confirmed by the server.')),button(tr('Закрыть','Close'),()=>{clear();render();}));return form;}
    if(['select','storage'].includes(a.stage)) {
      form.append(h('fieldset',{disabled:busy},h('legend',{},tr('1. Сервис и серверы','1. Service and servers')),choice(a,'source',tr('Исходный сервер','Source host'),optionsNodes()),choice(a,'target',tr('Отдельный сервер восстановления','Separate recovery host'),optionsNodes())));
      if(!storageOnly){
        const projectOptions=(node(a.source)?.status?.compose?.projects||[]).map(p=>[p.id,p.name+' · '+(p.supported?tr('поддерживается','supported'):(p.reasons||[]).map(reason).join(', '))]);
        form.append(choice(a,'project',tr('Обнаруженная группа Compose','Discovered Compose project'),[['',tr('Выберите проект','Select project')],...projectOptions]));
        if(project)form.append(h('section',{class:'managed-preflight'},pill(project.supported?tr('Поддерживается','Supported'):tr('Не поддерживается','Unsupported'),project.supported?'neutral':'bad'),h('p',{},project.architecture||'', ' · ',tr('Образы, оценка: ','Image estimate: '),bytes(project.estimatedBytes)),h('p',{},tr('Контейнеры: ','Containers: ')+(project.services||[]).map(s=>s.name).join(', ')),h('p',{},tr('Подключенные данные: ','Data mounts: ')+(project.mounts||[]).map(m=>m.kind+': '+m.label+' → '+m.target).join('; ')),h('p',{},(project.reasons||[]).map(reason).join(', ')),h('p',{class:'mono'},project.fingerprint)));
        form.append(input(a,'name',tr('Название сервиса','Service name')),choice(a,'interval',tr('Расписание','Schedule'),[['15min',tr('Каждые 15 минут','Every 15 minutes')],['hourly',tr('Каждый час','Hourly')],['daily',tr('Каждый день','Daily')]]),check(a,'exclusive',tr('Подтверждаю: данные меняют только контейнеры этой группы. Внешние процессы могут быть не обнаружены.','I confirm that only this project’s containers write its data. Host-native writers may not be discoverable.')),check(a,'http',tr('Добавить проверку HTTP','Add HTTP health check')));
        // Health fields are always shown so checking the box cannot lose keyboard focus.
        form.append(h('details',{},h('summary',{},tr('Проверка приложения (необязательно)','Application health (optional)')),choice(a,'healthService',tr('Контейнер для HTTP','HTTP service'),[['','—'],...(project?.services||[]).map(s=>[s.name,s.name])]),input(a,'port',tr('Внутренний порт','Internal port'),'number'),input(a,'path',tr('Путь HTTP','HTTP path')),input(a,'expectedStatus',tr('Ожидаемый код HTTP','Expected HTTP status'),'number')),notice(tr('Без Docker healthcheck или указанной проверки HTTP запуск остается непроверенным. Полная готовность не подтверждается.','Without Docker healthcheck or a configured HTTP check, startup remains unverified and full readiness cannot be confirmed.'),'warn'));
      }
      form.append(h('h3',{},tr('2. Хранилище','2. Storage')),choice(a,'storage',tr('Хранилище','Storage'),[['',tr('Новое хранилище','New storage')],...list('storages').map(s=>[s.id,s.name])]));
      const existing=list('storages').find(s=>s.id===a.storage);if(existing)a.kind=existing.kind;
      const reusing=reuse(a);
      if(reusing){wipeSecrets(a);form.append(notice(tr('Используется существующее подключение к одному репозиторию на обоих выбранных серверах. Повторный ввод паролей и изменение подключения не требуются.','Reusing the existing connection to the same repository on both selected hosts. No passwords or binding changes are needed.')),h('p',{class:'mono'},existing.repositoryId));}
      if(!existing)form.append(input(a,'storageName',tr('Название хранилища','Storage name')),choice(a,'kind',tr('Тип хранилища','Storage kind'),[['rest','REST'],['s3','S3']]),choice(a,'mode',tr('Репозиторий','Repository'),[['create',tr('Создать в новом выделенном месте','Create in a new dedicated namespace')],['attach',tr('Подключить существующий','Attach existing')]]),input(a,'endpoint',tr('Адрес HTTPS','HTTPS endpoint'),'url',true));
      else form.append(h('p',{class:'mono'},existing.endpoint));
      if(!reusing){
      if(a.kind==='s3'){if(!existing)form.append(input(a,'bucket',tr('Бакет','Bucket')),input(a,'prefix',tr('Префикс','Prefix')),input(a,'region',tr('Регион','Region')));form.append(input(a,'accessKeyId',tr('Ключ доступа S3','S3 access key')),input(a,'secretAccessKey',tr('Секретный ключ S3','S3 secret key'),'password'),input(a,'sessionToken',tr('Временный токен S3 (необязательно)','S3 session token (optional)'),'password'));}else form.append(input(a,'username',tr('Имя пользователя REST','REST username')),input(a,'password',tr('Пароль REST','REST password'),'password'));
      form.append(input(a,'repoPassword',tr('Независимый пароль шифрования restic','Independent restic encryption password'),'password',true),button(tr('Создать случайный пароль','Generate random password'),()=>{a.repoPassword=encode(crypto.getRandomValues(new Uint8Array(32)));render();}),notice(tr('Пароль шифрования нужен для восстановления. Сохраните комплект локально в защищенном месте. Учетные данные шифруются в браузере отдельно для каждого сервера. Сервер панели их не расшифровывает.','The encryption password is required for recovery. Save the kit locally in a secure place. Credentials are encrypted separately for each host in this browser. The controller cannot decrypt them.')),button(tr('Скачать закрытый комплект восстановления','Download private recovery kit'),kit,'',{disabled:!a.challenge&&!list('storages').some(s=>s.id===(a.storage||a.id))}));
      }
    }
    if(a.stage==='seal')form.append(h('h3',{},tr('Подтвердите точное место хранения','Confirm the exact repository namespace')),h('pre',{class:'managed-code'},JSON.stringify(a.challenge.metadata,null,2)),h('p',{},tr('Срок запроса: ','Challenge expires: ')+date(a.challenge.expiresAt)),h('p',{},a.challenge.bindings.map(b=>(node(b.nodeId)?.name||b.nodeId)+' · '+b.mode+' · '+b.bindingGeneration).join('; ')),notice(tr('Создание допускается только после подтверждения пустого выделенного места. Ошибка пароля, TLS или прав завершает подключение ошибкой.','Creation requires proof that the dedicated namespace is empty. Password, TLS or permission failure fails the connection.')),button(tr('Скачать закрытый комплект восстановления','Download private recovery kit'),kit));
    if(['import','backup','restore','schedule','complete'].includes(a.stage))form.append(h('p',{},tr('Следующий этап: ','Next step: ')+a.stage),notice(tr('Будут выполнены: регистрация, копия, восстановление точной копии на другом сервере, применение расписания и проверка готовности. При ошибке этап не считается завершенным.','The flow registers, captures, restores the exact snapshot on the other host, applies a schedule and checks readiness. Failed stages remain incomplete.')));
    form.append(h('div',{class:'actions'},h('button',{class:'btn primary',type:'submit',disabled:busy||(!storageOnly&&!project?.supported&&['select','storage'].includes(a.stage))},tr(a.stage==='seal'?'Подтвердить подключение':['select','storage'].includes(a.stage)?reuse(a)?'Использовать подключение и продолжить':'Подготовить защищенное подключение':'Продолжить настройку',a.stage==='seal'?'Confirm connection':['select','storage'].includes(a.stage)?reuse(a)?'Use connected storage and continue':'Prepare secure connection':'Continue setup')),button(tr('Начать новый запрос','Start fresh challenge'),()=>{a.challenge=null;a.sealed=null;a.connectResult=null;pending.clear();a.stage='storage';error='';render();},'',{disabled:busy}),button(tr('Отменить и удалить секреты из формы','Cancel and clear credentials'),()=>{clear();render();},'',{'data-completion-cancel':'',disabled:busy})));
    if(a.jobs.length)form.append(h('p',{class:'mono'},a.jobs.join('\n')));
    if(busy)for(const control of form.querySelectorAll('input,select,button'))control.disabled=true;
    if(waitingCompletion)form.querySelector('[data-completion-cancel]')?.removeAttribute('disabled');
    return form;
  }
  function confirm(title,content,fn) {
    const d=document.getElementById('dialog');d.replaceChildren();
    const err=h('p',{class:'form-error',role:'alert'});
    const cancelAction=()=>{if(waitingCompletion){alive++;waitingCompletion=false;busy=false;progress='';render();}d.close();};
    const cancel=button(tr('Отмена','Cancel'),cancelAction,'',{'data-completion-cancel':''});
    const waiting=h('p',{'data-completion-wait':'',role:'status'});
    d.oncancel=e=>{if(busy&&!waitingCompletion)e.preventDefault();else if(waitingCompletion)cancelAction();};
    const yes=button(tr('Подтвердить','Confirm'),async()=>{const epoch=alive;yes.disabled=true;cancel.disabled=true;busy=true;try{await fn();if(epoch===alive){d.close();await refreshOverview(true);}}catch(e){if(epoch===alive){progress='';err.textContent=message(e);}}finally{if(epoch===alive){busy=false;yes.disabled=false;cancel.disabled=false;}}},'primary');
    d.append(h('div',{class:'dialog-content'},h('h2',{id:'dialog-title'},title),content,waiting,err,h('div',{class:'actions'},cancel,yes)));if(!d.open)d.showModal();
  }
  function confirmOp(s,action,nodeId,extra={},snapshot) {
    const warning=action==='compose-backup'?tr('Вся группа Compose будет кратко остановлена. Ранее работавшие контейнеры должны быть возобновлены до успешного завершения.','The whole Compose project pauses briefly. The previously running containers must resume before success.'):action==='compose-remove'?tr('Будет удалена только эта отдельная проверочная копия.','Only this isolated owned restore will be removed.'):action==='compose-verify'?tr('Полная проверка restic с чтением данных проверяет репозиторий. Она не доказывает правильность приложения.','A full restic read-data check verifies the repository. It does not establish application correctness.'):tr('Восстановление создает отдельную копию без опубликованных портов.','Restore creates an isolated copy without published ports.');
    confirm(tr('Подтвердите действие','Confirm action'),h('div',{},notice(warning,'warn'),h('p',{},s.name+' · '+ctx.t(action)),h('p',{},node(nodeId)?.name||nodeId),snapshot?h('p',{class:'mono'},snapshot):null),()=>operation(s,action,nodeId,extra,snapshot));
  }
  function activate(s,r) {
    const point=(s.snapshots||[]).find(p=>p.id===r.snapshotId);
    const p=node(s.sourceNodeId)?.status?.compose?.projects?.find(p=>p.id===s.projectId);
    const choices=(p?.services||[]).flatMap(s=>(s.ports||[]).map(port=>({service:s.name,target:port,published:port,hostIp:'0.0.0.0',protocol:'tcp',include:false})));
    const a={accepted:false,egress:false};
    const body=h('div',{},notice(tr('Перенос использует историческую копию. Изменения на источнике после этой точки будут потеряны на новом сервере. Источник сначала останавливается. Обновление DNS, правила внешнего межсетевого экрана и TLS выполняются отдельно.','This move uses a historical snapshot. Source changes after this point will be absent on the destination. The source stops first. DNS, upstream firewall and TLS require separate configuration.'),'warn'),h('p',{},tr('Время снимка: ','Snapshot time: ')+(point?date(point.time):tr('неизвестно, перенос недоступен','unknown; move unavailable'))),h('p',{},tr('Возраст снимка: ','Snapshot age: ')+(point?Math.max(0,Math.floor((Date.now()-Date.parse(point.time))/1000))+' s':'—')),h('p',{class:'mono'},r.snapshotId),h('h3',{},tr('Опубликовать выбранные порты TCP','Publish selected TCP ports')));
    for(const mapping of choices)body.append(h('div',{class:'managed-port'},check(mapping,'include',mapping.service+':'+mapping.target),field(tr('Порт сервера','Host port'),h('input',{type:'number',min:1,max:65535,value:mapping.published,oninput:e=>mapping.published=Number(e.target.value)})),field(tr('Адрес привязки','Bind address'),h('input',{value:mapping.hostIp,oninput:e=>mapping.hostIp=e.target.value}))));
    // Discovered services with no declared ports can still choose an explicit mapping.
    const manual={service:p?.services?.[0]?.name||'',target:'',published:'',hostIp:'0.0.0.0'};
    body.append(h('details',{},h('summary',{},tr('Указать дополнительный порт TCP','Specify an additional TCP port')),input(manual,'service',tr('Имя контейнера Compose','Compose service name')),input(manual,'target',tr('Внутренний порт','Internal port'),'number'),input(manual,'published',tr('Порт сервера','Host port'),'number'),input(manual,'hostIp',tr('Адрес привязки','Bind address'))),check(a,'egress',tr('Разрешаю исходящие подключения новой копии','Allow destination network egress')),check(a,'accepted',tr('Принимаю потерю изменений после выбранного снимка','I accept loss of changes after this snapshot')));
    confirm(tr('Остановить источник и активировать копию','Stop source and activate restore'),body,async()=>{
      if(!point||!a.accepted||!a.egress)throw Object.assign(new Error(),{code:'snapshot_loss_confirmation_required'});
      const ports=choices.filter(p=>p.include).map(({include,...p})=>p);
      if(manual.target||manual.published)ports.push({...manual,target:Number(manual.target),published:Number(manual.published),protocol:'tcp'});
      const response=await mutate('/api/services/'+s.id+'/activate',{restoreId:r.id,ports,allowEgress:true,acceptSnapshotLoss:true});
      // Identity is retained in memory for explicit known-failure recovery only.
      activations.set(s.id,{...response,restoreId:r.id});
      const completed=await observeJobs(response.jobs);
      const activationResult=completed.find(j=>j.action==='compose-activate')?.result;
      if(activationResult?.protected===true && activationResult.firstBackup?.snapshot) {
        const current=serviceById(s.id);
        if(!current || current.sourceNodeId===s.sourceNodeId)throw Object.assign(new Error(),{code:'new_source_not_observed'});
        await finishValidation(current,activationResult.firstBackup.snapshot);
      }
    });
  }
  async function finishValidation(service,snapshot=service.latestBackup?.snapshot) {
    if(!snapshot)throw Object.assign(new Error(),{code:'new_source_backup_required'});
    const key='finish/'+service.id;
    let attempt=pending.get(key);
    if(!attempt){attempt={service:{...service},point:{...service.latestBackup},snapshot};pending.set(key,attempt);}
    if(attempt.snapshot!==snapshot || ['id','sourceNodeId','recoveryNodeId','storageId','fingerprint','projectId','backupInterval'].some(k=>attempt.service[k]!==service[k])){pending.delete(key);throw Object.assign(new Error(),{code:'completion_identity_changed'});}
    progress=tr('Проверка точной копии нового источника на выбранном сервере восстановления.','Checking the exact new-source backup on the selected recovery host.');render();
    if(!attempt.restoreId){
      const existing=list('restores').find(r=>r.serviceId===service.id && r.nodeId===service.recoveryNodeId && r.snapshotId===snapshot && r.state==='isolated_ready');
      const restore=existing || await operation(service,'compose-restore',service.recoveryNodeId,{},snapshot);
      attempt.restoreId=restore.result?.restoreId||restore.id;
    }
    await refreshOverview(false);
    const current=serviceById(service.id)||service;
    if(!attempt.scheduled){
      if(!current.schedule?.enabled || current.schedule.interval!==current.backupInterval)await operation(current,'compose-schedule',current.sourceNodeId,{interval:current.backupInterval});
      attempt.scheduled=true;
    }
    try{await observedCompletion(attempt.service,attempt.point,attempt.restoreId);}catch(e){if(e.code==='completion_identity_changed')pending.delete(key);throw e;}
    const completed=await api('/api/services/'+service.id+'/complete',{restoreId:attempt.restoreId,expectedRevision:rev()});
    if(completed.completed!==true||completed.service?.setupState!=='complete')throw Object.assign(new Error(),{code:'completion_unconfirmed'});
    pending.delete(key);progress='';await refreshOverview(false);
  }
  function serviceCard(s) {
    const source=node(s.sourceNodeId), target=node(s.recoveryNodeId),disabled=!ready(source)||busy;
    const card=h('article',{class:'card managed-service','data-setup-state':s.setupState},h('div',{class:'card-head'},h('h2',{},s.name),pill(stateLabel(s.setupState),s.setupState==='complete'?'':s.setupState==='active_unprotected'?'bad':'warn')),h('p',{class:'mono'},s.id),h('p',{},tr('Источник: ','Source: ')+(source?.name||s.sourceNodeId)+' · '+tr('Восстановление: ','Recovery: ')+(target?.name||s.recoveryNodeId)),h('p',{},tr('Расписание: ','Schedule: ')+(s.schedule?.enabled?s.schedule.interval:tr('не подтверждено','unconfirmed'))));
    if(!fresh(source)||!fresh(target))card.append(notice(tr('Нет свежих сведений с одной из площадок. Сохраненный результат проверки не подтверждает ее текущее состояние.','One site lacks fresh observations. A saved verification result does not establish its current state.'),'warn'));
    if(s.setupState==='active_unprotected')card.append(notice(tr('Новый сервер работает, но первая копия после переноса не подтверждена. Прежний источник остается остановленным. Повторите копирование с нового источника.','The new source is running, but its first backup has not been confirmed. The former source remains stopped. Retry backup from the new source.'),'bad'));
    if(s.setupState==='unverified')card.append(notice(tr('Запуск не подтверждает здоровье приложения. Добавьте HTTP или Docker healthcheck и повторите проверку.','Startup does not establish application health. Add HTTP or Docker healthcheck and repeat verification.'),'warn'));
    const activation=activations.get(s.id);
    const targetJob=activation?.jobs?.find(j=>j.action==='compose-activate')||list('jobs').find(j=>j.id===s.activation?.targetJobId);
    const stopJob=activation?.jobs?.find(j=>j.action==='compose-stop')||list('jobs').find(j=>j.id===s.activation?.sourceStopJobId);
    const activationGroupId=activation?.activationGroupId||s.activationGroupId||s.activation?.groupId;
    const failedRestore=list('restores').find(r=>r.id===(targetJob?.restoreId||activation?.restoreId));
    const sourceFenced=source?.status?.compose?.services?.some(item=>item.serviceId===s.id && item.state==='fenced');
    if(sourceFenced && activationGroupId && stopJob?.status==='succeeded' && targetJob?.status==='failed' && !['parent_failed','parent_unknown','result_unverified','cancelled_before_dispatch'].includes(targetJob.error) && failedRestore?.state==='isolated_ready' && !(failedRestore.ports||[]).length && ready(target) && ready(source))card.append(button(tr('Возобновить исходный сервис','Resume source'),()=>confirm(tr('Возобновить исходный сервис','Resume source'),notice(tr('Действие разрешено только после подтвержденной ошибки активации и свежей проверки, что целевая копия изолирована. При неизвестном результате возобновление запрещено.','Resume requires a known failed activation and fresh proof that the target remains isolated. Unknown activation blocks resume.'),'warn'),async()=>{const result=await mutate('/api/services/'+s.id+'/resume-source',{activationGroupId});await observeJobs([result.job]);}),'danger'));
    if(s.latestBackup?.snapshot && s.setupState!=='complete')card.append(button(tr('Завершить проверку защиты','Finish protection check'),()=>confirm(tr('Завершить проверку защиты','Finish protection check'),h('div',{},notice(tr('Точная последняя копия текущего источника будет проверена восстановлением на выбранном другом сервере. Повторная активация не выполняется.','The current source’s exact latest backup will be restored on the selected other host. Activation is not repeated.')),h('p',{class:'mono'},s.latestBackup.snapshot)),()=>finishValidation(s)),'primary',{disabled:disabled||!ready(target)}));
    const schedule={interval:pending.get('schedule/'+s.id)||s.backupInterval};
    card.append(h('div',{class:'actions'},button(tr('Создать копию','Back up now'),()=>confirmOp(s,'compose-backup',s.sourceNodeId),'primary',{disabled}),button(tr('Проверить репозиторий','Check repository'),()=>confirmOp(s,'compose-verify',ready(target)?s.recoveryNodeId:s.sourceNodeId),'',{disabled}),field(tr('Интервал','Interval'),select([['15min','15 min'],['hourly',tr('Час','Hourly')],['daily',tr('Сутки','Daily')]],schedule.interval,value=>{schedule.interval=value;pending.set('schedule/'+s.id,value);})),button(tr('Применить расписание','Apply schedule'),()=>confirmOp(s,'compose-schedule',s.sourceNodeId,{interval:schedule.interval}),'',{disabled}),button(tr('Обновить регистрацию','Update registration'),()=>{wizard={...init(),...s,serviceId:s.id,source:s.sourceNodeId,target:s.recoveryNodeId,project:s.projectId,storage:s.storageId,interval:s.backupInterval,stage:'select',name:s.name};render();},'',{disabled})));
    card.append(h('h3',{},tr('Точки восстановления этого сервиса','Recovery points for this service')));
    const points=(s.snapshots||[]).filter(p=>p.serviceId===s.id&&p.repositoryId===list('storages').find(st=>st.id===s.storageId)?.repositoryId).sort((a,b)=>Date.parse(b.time)-Date.parse(a.time));
    if(!points.length)card.append(h('p',{},tr('Подтвержденных точек пока нет.','No confirmed points yet.')));
    for(const point of points)card.append(h('div',{class:'managed-row'},h('div',{},date(point.time),h('p',{class:'mono'},point.id)),button(tr('Восстановить на выбранном сервере','Restore on recovery host'),()=>confirmOp(s,'compose-restore',s.recoveryNodeId,{},point.id),'',{disabled:!ready(target)||busy})));
    card.append(h('h3',{},tr('Отдельные восстановленные копии','Retained restored copies')));
    const restores=list('restores').filter(r=>r.serviceId===s.id);
    if(!restores.length)card.append(h('p',{},tr('Восстановлений пока нет.','No restores yet.')));
    for(const r of restores) {
      const row=h('section',{class:'managed-restore'},h('p',{},(node(r.nodeId)?.name||r.nodeId)+' · '+r.state),h('p',{class:'mono'},r.id+' · '+r.snapshotId),h('p',{},tr('Проверки: ','Checks: ')+(r.checks||[]).join(', ')+' · '+(r.healthScope||tr('здоровье неизвестно','health unknown'))));
      if(r.state==='isolated_ready')row.append(h('div',{class:'actions'},button(tr('Подтвердить готовность','Confirm readiness'),()=>confirm(tr('Проверка готовности','Readiness check'),notice(tr('Панель проверит точный снимок, другой сервер, здоровье приложения и действующее расписание.','The controller checks the exact point, other host, application health and observed schedule.')),()=>api('/api/services/'+s.id+'/complete',{restoreId:r.id,expectedRevision:rev()})),'',{disabled:busy}),button(tr('Перенести сюда','Move here'),()=>activate(s,r),'',{disabled:disabled||r.nodeId!==s.recoveryNodeId}),button(tr('Удалить отдельную копию','Remove isolated copy'),()=>confirmOp(s,'compose-remove',r.nodeId,{restoreId:r.id}),'danger',{disabled:!ready(node(r.nodeId))||busy})));
      if(r.state==='failed' && r.canRemoveStopped===true && ready(node(r.nodeId)))row.append(notice(tr('Копия остановлена. Проверка не завершена. Данные сохранены до явного удаления.','The copy is stopped. Validation is incomplete. Data is retained until explicit removal.')),button(tr('Удалить остановленную копию','Remove stopped copy'),()=>confirmOp(s,'compose-remove',r.nodeId,{restoreId:r.id}),'danger',{disabled:busy}));
      if(r.state==='active')row.append(h('p',{},tr('Фактические адреса: ','Observed addresses: ')+(node(r.nodeId)?.status?.compose?.addresses||[]).join(', ')),h('p',{},(r.ports||[]).map(p=>p.hostIp+':'+p.published+' → '+p.service+':'+p.target+'/tcp').join('; ')));
      card.append(row);
    }
    const history=list('jobs').filter(j=>j.serviceId===s.id||j.parameters?.serviceId===s.id||j.result?.serviceId===s.id);
    card.append(h('details',{},h('summary',{},tr('История сервиса','Service history')),history.length?history.map(j=>h('div',{class:'managed-row'},h('span',{},ctx.t(j.action)+' · '+ctx.t(j.status)+(j.error?' · '+j.error:'')),button(tr('Подробнее','Details'),()=>showJob(j)))):h('p',{},tr('Нет операций.','No operations.'))));
    return card;
  }
  function servicesView() {
    const view=h('div',{},head(tr('Свои приложения','Your applications'),tr('Сервисы Compose','Compose services'),tr('Отдельная история, хранилище и расписание для каждого сервиса.','Separate history, repository and schedule for every service.'),[button(tr('Подключить свой сервис','Connect your service'),()=>{clear();wizard=init();render();},'primary',{disabled:busy}),button(tr('Хранилища','Storage'),()=>ctx.setRoute('storages'))]),...alerts());
    if(wizard&&!wizard.storageOnly)view.append(wizardView());
    if(!nodes().length)view.append(notice(tr('Сначала подключите серверы через раздел «Серверы».','Enroll hosts in Servers first.')),button(tr('Подключить сервер','Enroll host'),()=>ctx.setRoute('nodes')));
    if(!list('services').length&&!wizard)view.append(notice(tr('Своих сервисов пока нет. Подключение начинается с обнаруженной группы Compose.','No own services yet. Start with a discovered Compose project.')));
    for(const s of list('services'))view.append(serviceCard(s));return view;
  }
  function storagesView() {
    const view=h('div',{},head(tr('Зашифрованные копии','Encrypted backups'),tr('Хранилища','Storage'),tr('REST или S3 по HTTPS. Пароль restic хранится отдельно от учетных данных провайдера.','REST or S3 over HTTPS. Keep the restic password separate from provider credentials.'),[button(tr('Подключить хранилище','Connect storage'),()=>{clear();wizard=init();wizard.storageOnly=true;render();},'primary',{disabled:busy})]),...alerts());
    if(wizard?.storageOnly)view.append(wizardView(true));
    for(const s of list('storages'))view.append(h('article',{class:'card'},h('h2',{},s.name),h('p',{class:'mono'},s.id),h('p',{},s.kind+' · '+s.endpoint),h('p',{},[s.bucket,s.prefix,s.region].filter(Boolean).join(' / ')),h('p',{class:'mono'},tr('Репозиторий: ','Repository: ')+(s.repositoryId||tr('не подтвержден','unconfirmed'))),(s.bindings||[]).map(b=>h('p',{},(node(b.nodeId)?.name||b.nodeId)+' · '+b.state+(b.error?' · '+b.error:''))),button(tr('Подключить серверы или повторить проверку','Connect hosts or retry binding'),()=>{clear();wizard={...init(),storage:s.id,kind:s.kind,storageOnly:true};render();})));
    return view;
  }
  function nodeSummary() {
    return h('section',{class:'card'},h('h2',{},tr('Готовность своих сервисов Compose','Own-service Compose readiness')),nodes().map(n=>h('div',{class:'managed-row'},h('span',{},n.name),pill(ready(n)?tr('Compose готов','Compose ready'):!fresh(n)?tr('Нет свежей связи','No fresh connection'):explain(n.status?.compose?.error||'compose_not_ready'),ready(n)?'neutral':'warn'),h('span',{},tr('Обнаружено проектов: ','Discovered projects: ')+(n.status?.compose?.projects?.length||0)))));
  }
  function homeView(){const view=servicesView();if(nodes().length)view.append(nodeSummary());return view;}
  return {servicesView,storagesView,homeView,nodeSummary,explain,clear};
}
