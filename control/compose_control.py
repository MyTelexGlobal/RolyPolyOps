"""Compose catalog validation and typed pipelines using the control service queue.

Only public metadata and sealed credential envelopes cross this boundary. This
module deliberately has no cryptographic dependency or host execution facility.
"""
import base64
import hashlib
import ipaddress
import json
import re
import secrets
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import unquote, urlsplit

ACTIONS = frozenset(('storage-configure', 'compose-register', 'compose-backup', 'compose-verify', 'compose-restore', 'compose-remove', 'compose-schedule', 'compose-stop', 'compose-activate', 'compose-resume'))
INTERNAL = frozenset(('storage-configure', 'compose-register', 'compose-stop', 'compose-activate', 'compose-resume'))
INTERVALS = frozenset(('15min', 'hourly', 'daily'))
HEX = re.compile(r'[a-f0-9]{64}\Z')
SLUG = re.compile(r'[a-z0-9][a-z0-9_-]{0,63}\Z')
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
RESTORE_CHECKS = frozenset(('compose-model', 'data-hashes', 'metadata', 'image-identities', 'fresh-resources', 'runtime-isolation'))
ALGORITHM = 'RSA-OAEP-256+A256GCM'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def identity(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def text(value, limit=100):
    return isinstance(value, str) and 0 < len(value) <= limit and all(ord(c) >= 32 and ord(c) != 127 and not 0xd800 <= ord(c) <= 0xdfff for c in value)


def integer(value, low=0, high=2**63-1):
    return isinstance(value, int) and not isinstance(value, bool) and low <= value <= high


def iso(value):
    try:
        parsed = datetime.fromisoformat(value)
        return isinstance(value, str) and len(value) <= 40 and parsed.tzinfo is not None and parsed.timestamp() >= 0
    except (TypeError, ValueError, OverflowError):
        return False


def when(value):
    return datetime.fromisoformat(value).timestamp()


def key(value):
    if not isinstance(value, dict) or set(value) != {'id', 'publicKey', 'algorithm'} or value.get('algorithm') != ALGORITHM or not isinstance(value.get('id'), str) or not HEX.fullmatch(value['id']):
        return None
    try:
        raw = base64.b64decode(value['publicKey'], validate=True)
    except (ValueError, TypeError):
        return None
    # The agent generates canonical RSA-3072 SPKI with exponent 65537. Check
    # its transport encoding and hash; no cryptographic operation runs here.
    prefix=bytes.fromhex('308201a2300d06092a864886f70d01010105000382018f003082018a0282018100')
    if len(raw) != 422 or not raw.startswith(prefix) or not raw.endswith(bytes.fromhex('0203010001')) or not raw[len(prefix)] & 128 or base64.b64encode(raw).decode() != value['publicKey'] or hashlib.sha256(raw).hexdigest() != value['id']:
        return None
    return {k: value[k] for k in ('id', 'publicKey', 'algorithm')}


def points(value):
    result = []
    if not isinstance(value, list):
        return result
    for p in value[:100]:
        if not isinstance(p, dict) or not isinstance(p.get('id'), str) or not HEX.fullmatch(p['id']) or not iso(p.get('time')) or when(p['time']) > time.time()+60 or not identity(p.get('serviceId')) or not isinstance(p.get('repositoryId'), str) or not HEX.fullmatch(p['repositoryId']):
            continue
        item = {k: p[k] for k in ('id', 'time', 'serviceId', 'repositoryId')}
        for name in ('manifestDigest', 'sourceFingerprint'):
            if isinstance(p.get(name), str) and HEX.fullmatch(p[name]):
                item[name] = p[name]
        if all(k in item for k in ('manifestDigest', 'sourceFingerprint')):
            result.append(item)
    return result


def schedule(value):
    if not isinstance(value, dict) or not isinstance(value.get('enabled'), bool):
        return {}
    result = {'enabled': value['enabled']}
    if isinstance(value.get('interval'), str) and value['interval'] in INTERVALS:
        result['interval'] = value['interval']
    if iso(value.get('next')):
        result['next'] = value['next']
    return result


def ports(value):
    if not isinstance(value, list) or not 0 <= len(value) <= 100:
        return None
    result, used = [], set()
    for p in value:
        if not isinstance(p, dict) or set(p) != {'service', 'target', 'published', 'hostIp', 'protocol'} or not isinstance(p.get('service'), str) or not NAME.fullmatch(p['service']) or not integer(p.get('target'), 1, 65535) or not integer(p.get('published'), 1, 65535) or p.get('protocol') != 'tcp':
            return None
        try:
            ipaddress.ip_address(p.get('hostIp'))
        except (ValueError, TypeError):
            return None
        slot = (p['hostIp'], p['published'])
        if slot in used:
            return None
        used.add(slot)
        result.append({k: p[k] for k in ('service', 'target', 'published', 'hostIp', 'protocol')})
    return result


def sanitize_status(value):
    """Whitelist bounded metadata; never copy unknown fields or rendered models."""
    if not isinstance(value, dict):
        return {'ready': False, 'error': 'compose_status_invalid', 'projects': [], 'storages': [], 'services': [], 'restores': [], 'addresses': []}
    result = {'ready': value.get('ready') is True, 'projects': [], 'storages': [], 'services': [], 'restores': [], 'addresses': []}
    if isinstance(value.get('error'), str) and SLUG.fullmatch(value['error']):
        result['error'] = value['error']
    if (k := key(value.get('key'))) is not None:
        result['key'] = k
    else:
        result.update(ready=False, error='compose_key_unavailable')
    for p in value.get('projects', [])[:20] if isinstance(value.get('projects'), list) else []:
        if not isinstance(p, dict) or not isinstance(p.get('id'), str) or not NAME.fullmatch(p['id']) or not text(p.get('name'), 128) :
            continue
        item = {k: p[k] for k in ('id', 'name')}
        if isinstance(p.get('fingerprint'),str) and HEX.fullmatch(p['fingerprint']):
            item['fingerprint']=p['fingerprint']
        item.update(supported=p.get('supported') is True and 'fingerprint' in item, reasons=[r for r in p.get('reasons', [])[:20] if isinstance(r, str) and SLUG.fullmatch(r)] if isinstance(p.get('reasons'), list) else [], services=[], mounts=[])
        if p.get('supported') is True and 'fingerprint' not in item:
            item['reasons']=['discovery_invalid']
        services, mounts = p.get('services', []), p.get('mounts', [])
        if not isinstance(services, list) or not isinstance(mounts, list) or len(services) > 20 or len(mounts) > 100:
            item.update(supported=False, reasons=['discovery_limit'])
            services, mounts = [], []
        for s in services:
            if not isinstance(s, dict) or not isinstance(s.get('name'), str) or not NAME.fullmatch(s['name']) or not isinstance(s.get('imageId'), str) or not re.fullmatch(r'(?:sha256:)?[a-f0-9]{64}', s['imageId']):
                item.update(supported=False, reasons=['discovery_invalid'])
                continue
            item['services'].append({'name': s['name'], 'imageId': s['imageId'], 'healthcheck': s.get('healthcheck') is True, 'ports': [x for x in s.get('ports', [])[:100] if integer(x, 1, 65535)] if isinstance(s.get('ports'), list) else []})
        for m in mounts:
            if isinstance(m, dict) and m.get('kind') in ('volume', 'bind', 'config', 'secret') and text(m.get('target'), 4096) and text(m.get('label'), 4096) and isinstance(m.get('readOnly'), bool):
                item['mounts'].append({k: m[k] for k in ('kind', 'target', 'label', 'readOnly')})
        if integer(p.get('estimatedBytes'), 0, 256*1024**3):
            item['estimatedBytes'] = p['estimatedBytes']
        if text(p.get('architecture'), 64):
            item['architecture'] = p['architecture']
        result['projects'].append(item)
    if isinstance(value.get('projects'), list) and len(value['projects']) > 20:
        result.update(ready=False, error='discovery_limit')
    for b in value.get('storages', [])[:8] if isinstance(value.get('storages'), list) else []:
        sid = b.get('storageId', b.get('id')) if isinstance(b, dict) else None
        if not identity(sid):
            continue
        item = {'storageId': sid, 'connected': b.get('connected') is True}
        if isinstance(b.get('repositoryId'), str) and HEX.fullmatch(b['repositoryId']):
            item['repositoryId'] = b['repositoryId']
        if integer(b.get('bindingGeneration'), 1):
            item['bindingGeneration'] = b['bindingGeneration']
        if identity(b.get('requestId')):
            item['requestId'] = b['requestId']
        if isinstance(b.get('error'), str) and SLUG.fullmatch(b['error']):
            item['error'] = b['error']
        item['snapshots'] = points(b.get('snapshots'))
        result['storages'].append(item)
    for s in value.get('services', [])[:20] if isinstance(value.get('services'), list) else []:
        sid = s.get('serviceId', s.get('id')) if isinstance(s, dict) else None
        if not identity(sid):
            continue
        item = {'serviceId': sid, 'schedule': schedule(s.get('schedule')), 'snapshots': points(s.get('snapshots'))}
        for name in ('storageId',):
            if identity(s.get(name)):
                item[name] = s[name]
        for name in ('fingerprint', 'repositoryId'):
            if isinstance(s.get(name), str) and HEX.fullmatch(s[name]):
                item[name] = s[name]
        state=s.get('state',s.get('sourceState'))
        if state in ('running', 'capture_stopped', 'fenced', 'unknown'):
            item['state'] = state
            item['sourceState'] = state
        if isinstance(s.get('projectId'), str) and NAME.fullmatch(s['projectId']):
            item['projectId'] = s['projectId']
        latest = s.get('latestBackup')
        if isinstance(latest,dict):
            b = sanitize_result('compose-backup',latest,None,{'serviceId':sid},sid)
            if b is not None:
                item['latestBackup'] = b
        result['services'].append(item)
    for r in value.get('restores', [])[:100] if isinstance(value.get('restores'), list) else []:
        rid = r.get('restoreId', r.get('id')) if isinstance(r, dict) else None
        if not identity(rid) or not identity(r.get('serviceId')) or r.get('state') not in ('isolated_ready', 'active', 'failed', 'outcome_unknown'):
            continue
        item = {'id': rid, 'serviceId': r['serviceId'], 'state': r['state']}
        for name in ('snapshotId', 'repositoryId', 'manifestDigest', 'sourceFingerprint'):
            if isinstance(r.get(name, r.get('snapshot') if name == 'snapshotId' else None), str) and HEX.fullmatch(r.get(name, r.get('snapshot') if name == 'snapshotId' else None)):
                item[name] = r.get(name, r.get('snapshot') if name == 'snapshotId' else None)
        item['ports'] = ports(r.get('ports', [])) or []
        item['checks'] = safe_checks(r.get('checks'))
        if r.get('healthScope') in ('http', 'docker', 'running-only'):
            item['healthScope'] = r['healthScope']
        item['applicationHealthVerified'] = r.get('applicationHealthVerified') is True
        result['restores'].append(item)
    for address in value.get('addresses', [])[:32] if isinstance(value.get('addresses'), list) else []:
        try:
            ip = ipaddress.ip_address(address)
            if not (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified):
                result['addresses'].append(str(ip))
        except (ValueError, TypeError):
            pass
    # Autonomous timer uncertainty is authenticated host evidence, not a job.
    result['operations'] = []
    for op in value.get('operations', [])[:128] if isinstance(value.get('operations'), list) else []:
        if isinstance(op, dict) and identity(op.get('id')) and op.get('status') in ('outcome_unknown', 'running', 'succeeded', 'failed'):
            result['operations'].append({'id': op['id'], 'status': op['status']})
    if value.get('operationOverflow') is True or (isinstance(value.get('operations'),list) and len(value['operations']) > 128):
        result['operationOverflow'] = True
    if any(isinstance(value.get(k),list) and len(value[k]) > limit for k,limit in (('storages',8),('services',20),('restores',100),('operations',128))):
        result.update(ready=False,error='discovery_limit')
    return result


def safe_checks(value):
    return [x for x in value[:32] if isinstance(x, str) and SLUG.fullmatch(x)] if isinstance(value, list) else []


def sanitize_result(action, value, snapshot, params, job_id):
    if not isinstance(value, dict):
        return None
    result = {}
    for name in ('serviceId', 'storageId', 'restoreId', 'requestId', 'stopOperationId', 'sourceNodeId'):
        if identity(value.get(name)):
            result[name] = value[name]
    for name in ('repositoryId', 'snapshot', 'manifestDigest', 'sourceFingerprint', 'fingerprint'):
        if isinstance(value.get(name), str) and HEX.fullmatch(value[name]):
            result[name] = value[name]
    for name in ('connected', 'registered', 'verified', 'isolated', 'applicationHealthVerified', 'removed', 'enabled', 'fenced', 'activated', 'protected', 'resumed', 'sourceResumed'):
        if isinstance(value.get(name), bool):
            result[name] = value[name]
    if isinstance(value.get('interval'), str) and value['interval'] in INTERVALS:
        result['interval'] = value['interval']
    if value.get('healthScope') in ('http', 'docker', 'running-only'):
        result['healthScope'] = value['healthScope']
    if integer(value.get('bindingGeneration'), 1):
        result['bindingGeneration'] = value['bindingGeneration']
    if isinstance(value.get('projectId'), str) and NAME.fullmatch(value['projectId']):
        result['projectId'] = value['projectId']
    if iso(value.get('at')) and when(value['at']) <= time.time()+60:
        result['at'] = value['at']
    result['checks'] = safe_checks(value.get('checks'))
    if action != 'storage-configure' and result.get('serviceId') != params.get('serviceId'):
        return None
    if action == 'storage-configure':
        e = params.get('envelope', {})
        if result.get('storageId') != params.get('storageId') or result.get('connected') is not True or 'repositoryId' not in result or result.get('bindingGeneration') != e.get('bindingGeneration', params.get('bindingGeneration')) or result.get('requestId') != e.get('requestId', params.get('requestId')) or (params.get('expectedRepositoryId') and result['repositoryId'] != params['expectedRepositoryId']):
            return None
    elif action == 'compose-register':
        if result.get('registered') is not True or result.get('projectId') != params.get('projectId') or result.get('fingerprint') != params.get('fingerprint'):
            return None
    elif action == 'compose-backup':
        if not all(k in result for k in ('snapshot', 'repositoryId', 'manifestDigest', 'sourceFingerprint', 'at')) or result.get('sourceResumed') is not True or not {'source-stopped','data-archived','images-saved','source-resumed','repository-written'} <= set(result['checks']):
            return None
    elif action == 'compose-verify':
        if result.get('storageId') != params.get('storageId') or 'repositoryId' not in result or result.get('verified') is not True or 'repository-data' not in result['checks']:
            return None
    elif action == 'compose-restore':
        if result.get('storageId') != params.get('storageId') or result.get('restoreId') != job_id or result.get('snapshot') != snapshot or result.get('isolated') is not True or not RESTORE_CHECKS <= set(result['checks']) or 'repositoryId' not in result or 'manifestDigest' not in result or result.get('healthScope') not in ('http','docker','running-only'):
            return None
        if result.get('applicationHealthVerified') and ('application-health' not in result['checks'] or result['healthScope'] == 'running-only'):
            return None
    elif action == 'compose-remove':
        if result.get('restoreId') != params.get('restoreId') or result.get('removed') is not True:
            return None
    elif action == 'compose-schedule':
        if result.get('interval') != params.get('interval') or result.get('enabled') is not True:
            return None
    elif action == 'compose-stop':
        if result.get('fingerprint') != params.get('fingerprint') or result.get('fenced') is not True or result.get('stopOperationId') != job_id:
            return None
    elif action == 'compose-activate':
        result['ports'] = ports(value.get('ports'))
        if result.get('restoreId') != params.get('restoreId') or result.get('activated') is not True or result.get('enabled') is not True or result.get('interval') != params.get('interval') or 'sourceNodeId' not in result or 'projectId' not in result or 'fingerprint' not in result or result['ports'] != params.get('ports') or not isinstance(result.get('protected'), bool):
            return None
        if 'firstBackup' in value:
            result['firstBackup'] = sanitize_result('compose-backup', value['firstBackup'], None, {'serviceId': params['serviceId']}, job_id)
        if result['protected'] and not result.get('firstBackup'):
            return None
    elif action == 'compose-resume':
        if result.get('resumed') is not True or result.get('fingerprint') != params.get('fingerprint') or not isinstance(result.get('enabled'), bool) or result.get('interval') != params.get('interval'):
            return None
    else:
        return None
    return result


class ComposeControl:
    def __init__(self, control, error):
        self.c, self.error = control, error

    def fail(self, code, status=409):
        raise self.error(status, code)

    def fields(self, body, required=(), optional=()):
        if not isinstance(body, dict) or not set(required) <= set(body) or set(body) - set(required) - set(optional):
            self.fail('invalid_request', 400)

    def initialize(self, db):
        db.executescript('''
            CREATE TABLE IF NOT EXISTS compose_storages(id TEXT PRIMARY KEY,metadata TEXT NOT NULL,repository_id TEXT);
            CREATE TABLE IF NOT EXISTS compose_bindings(storage_id TEXT NOT NULL,node_id TEXT NOT NULL,generation INTEGER NOT NULL,request_id TEXT,state TEXT NOT NULL,repository_id TEXT,error TEXT,PRIMARY KEY(storage_id,node_id));
            CREATE TABLE IF NOT EXISTS compose_challenges(id TEXT PRIMARY KEY,storage_id TEXT NOT NULL,metadata TEXT NOT NULL,bindings TEXT NOT NULL,expires REAL NOT NULL,consumed INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS compose_services(id TEXT PRIMARY KEY,config TEXT NOT NULL,state TEXT NOT NULL,registered INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS compose_restores(id TEXT PRIMARY KEY,service_id TEXT NOT NULL,node_id TEXT NOT NULL,snapshot_id TEXT NOT NULL,repository_id TEXT NOT NULL,state TEXT NOT NULL,proof TEXT NOT NULL,observed REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS compose_points(service_id TEXT NOT NULL,repository_id TEXT NOT NULL,snapshot_id TEXT NOT NULL,point TEXT NOT NULL,node_id TEXT NOT NULL,PRIMARY KEY(service_id,repository_id,snapshot_id));
            CREATE TABLE IF NOT EXISTS compose_requests(key TEXT PRIMARY KEY,fingerprint TEXT NOT NULL,response TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS compose_jobs(job_id TEXT PRIMARY KEY,parent_id TEXT,group_id TEXT,service_id TEXT,storage_id TEXT,intent TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS compose_activations(id TEXT PRIMARY KEY,service_id TEXT NOT NULL,source_node TEXT NOT NULL,target_node TEXT NOT NULL,stop_job TEXT NOT NULL,activate_job TEXT NOT NULL,acceptance TEXT NOT NULL);
        ''')

    def revision(self, db, body):
        if not integer(body.get('expectedRevision'), 1):
            self.fail('invalid_revision', 400)
        if body['expectedRevision'] != self.c.revision(db):
            self.fail('revision_conflict')

    def repeat(self, db, route, body):
        if not identity(body.get('idempotencyKey')):
            self.fail('invalid_idempotency_key', 400)
        try:
            fingerprint = hashlib.sha256(canonical({'route': route, 'body': body}).encode()).hexdigest()
        except (UnicodeError,TypeError,ValueError):
            self.fail('invalid_request',400)
        row = db.execute('SELECT * FROM compose_requests WHERE key=?', (body['idempotencyKey'],)).fetchone()
        if row:
            if row['fingerprint'] != fingerprint:
                self.fail('idempotency_conflict')
            return json.loads(row['response'])
        return None

    def remember(self, db, route, body, result):
        fingerprint = hashlib.sha256(canonical({'route': route, 'body': body}).encode()).hexdigest()
        db.execute('INSERT INTO compose_requests VALUES(?,?,?)', (body['idempotencyKey'], fingerprint, canonical(result)))
        return result

    def idle(self, db):
        if db.execute("SELECT 1 FROM jobs WHERE status IN ('queued','dispatched','running','outcome_unknown')").fetchone():
            self.fail('operation_in_progress')
        if db.execute("SELECT 1 FROM orphan_reports WHERE status IN ('running','outcome_unknown')").fetchone() or db.execute('SELECT 1 FROM nodes WHERE orphan_overflow=1').fetchone():
            self.fail('catalog_receipt_orphaned')

    def live(self, db, node_id):
        node = self.c.node(db, node_id)
        status = json.loads(node['status'])
        if node['revoked'] or not self.c.connected(node) or not self.c.status_fresh(status):
            self.fail('node_stale')
        compose = status.get('compose', {})
        if compose.get('ready') is not True or not key(compose.get('key')):
            self.fail('compose_not_ready')
        return node, compose

    def storage(self, db, sid):
        if not identity(sid):
            self.fail('invalid_storage', 400)
        row = db.execute('SELECT * FROM compose_storages WHERE id=?', (sid,)).fetchone()
        if not row:
            self.fail('storage_not_found', 404)
        return row

    def service(self, db, sid):
        if not identity(sid):
            self.fail('invalid_service', 400)
        row = db.execute('SELECT * FROM compose_services WHERE id=?', (sid,)).fetchone()
        if not row:
            self.fail('service_not_found', 404)
        return row, json.loads(row['config'])

    def binding(self, db, storage_id, node_id, *, fresh=True):
        row = db.execute('SELECT * FROM compose_bindings WHERE storage_id=? AND node_id=?', (storage_id, node_id)).fetchone()
        storage = self.storage(db, storage_id)
        if not row or row['state'] != 'connected' or not storage['repository_id'] or row['repository_id'] != storage['repository_id']:
            self.fail('storage_not_connected')
        if fresh:
            _, status = self.live(db, node_id)
            seen = next((b for b in status.get('storages', []) if b['storageId'] == storage_id), {})
            if seen.get('connected') is not True or seen.get('repositoryId') != row['repository_id'] or seen.get('bindingGeneration') != row['generation'] or seen.get('requestId') != row['request_id']:
                self.fail('storage_binding_stale')
        return row

    def public_storage(self, db, row):
        result = json.loads(row['metadata'])
        result['repositoryId'] = row['repository_id']
        result['bindings'] = [{'nodeId': b['node_id'], 'bindingGeneration': b['generation'], 'requestId': b['request_id'], 'state': b['state'], 'repositoryId': b['repository_id'], 'error': b['error']} for b in db.execute('SELECT * FROM compose_bindings WHERE storage_id=? ORDER BY node_id', (row['id'],))]
        return result

    def public_service(self, db, row):
        result = json.loads(row['config'])
        result.update(setupState=row['state'], registered=bool(row['registered']))
        node = db.execute('SELECT status FROM nodes WHERE id=?', (result['sourceNodeId'],)).fetchone()
        seen = next((s for s in json.loads(node['status']).get('compose', {}).get('services', []) if s['serviceId'] == row['id']), {}) if node else {}
        result['schedule'] = seen.get('schedule', {})
        activation=db.execute('SELECT a.*,j.status FROM compose_activations a JOIN jobs j ON j.id=a.activate_job WHERE a.service_id=? ORDER BY j.created DESC LIMIT 1',(row['id'],)).fetchone()
        if activation:
            result['activationGroupId']=activation['id']
            result['activation']={'groupId':activation['id'],'sourceStopJobId':activation['stop_job'],'targetJobId':activation['activate_job'],'status':activation['status']}
        for action, label, node_id in (('compose-backup', 'latestBackup',result['sourceNodeId']), ('compose-restore', 'latestRestore',result['recoveryNodeId'])):
            job = db.execute('SELECT j.* FROM jobs j JOIN compose_jobs c ON c.job_id=j.id WHERE c.service_id=? AND j.node_id=? AND j.action=? AND j.status=\'succeeded\' ORDER BY j.ended DESC LIMIT 1', (row['id'],node_id,action)).fetchone()
            result[label] = json.loads(job['result']) if job and job['result'] else None
        candidates=[result['latestBackup'],seen.get('latestBackup')]
        activation_result=db.execute("SELECT j.result FROM jobs j JOIN compose_jobs c ON c.job_id=j.id WHERE c.service_id=? AND j.node_id=? AND j.action='compose-activate' AND j.status='succeeded' ORDER BY j.ended DESC LIMIT 1",(row['id'],result['sourceNodeId'])).fetchone()
        if activation_result and activation_result['result']:
            candidates.append(json.loads(activation_result['result']).get('firstBackup'))
        candidates=[b for b in candidates if isinstance(b,dict) and iso(b.get('at')) and b.get('sourceFingerprint') == result['fingerprint']]
        result['latestBackup']=max(candidates,key=lambda b:when(b['at'])) if candidates else None
        result['snapshots'] = [json.loads(p['point']) for p in db.execute('SELECT * FROM compose_points WHERE service_id=? ORDER BY snapshot_id LIMIT 100', (row['id'],))]
        return result

    def overview(self, db):
        return {'storages': [self.public_storage(db, s) for s in db.execute('SELECT * FROM compose_storages ORDER BY id')], 'services': [self.public_service(db, s) for s in db.execute('SELECT * FROM compose_services ORDER BY id')], 'restores': [dict(json.loads(r['proof']), id=r['id'], serviceId=r['service_id'], nodeId=r['node_id'], snapshotId=r['snapshot_id'], state=r['state']) for r in db.execute('SELECT * FROM compose_restores ORDER BY observed DESC LIMIT 100')]}

    def metadata(self, body):
        self.fields(body, ('id','name','kind','endpoint','expectedRevision','idempotencyKey'), ('bucket','prefix','region'))
        if not identity(body['id']) or not text(body['name'], 80) or body['kind'] not in ('rest','s3') or not text(body['endpoint'], 1024) or not body['endpoint'].isascii() or any(ord(c)<=32 for c in body['endpoint']):
            self.fail('invalid_storage', 400)
        p = urlsplit(body['endpoint'])
        try:
            valid_port = p.port is None or 1 <= p.port <= 65535
            addr = ipaddress.ip_address(p.hostname)
            public = addr.is_global
        except ValueError:
            try:
                valid_port = p.port is None or 1 <= p.port <= 65535
            except ValueError:
                self.fail('invalid_endpoint',400)
            public = bool(p.hostname and len(p.hostname) <= 253 and all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', x) for x in p.hostname.rstrip('.').split('.')) and p.hostname.lower() not in ('localhost',) and not p.hostname.lower().endswith('.localhost'))
        except TypeError:
            public, valid_port = False, False
        if p.scheme != 'https' or not p.netloc or p.username or p.password or p.query or p.fragment or not valid_port or not public or '%' in p.netloc or p.hostname.endswith('.') or any(x in ('..','.') for x in unquote(p.path).split('/')) or '\\' in body['endpoint']:
            self.fail('invalid_endpoint', 400)
        result = {k: body[k] for k in ('id','name','kind','endpoint')}
        if body['kind'] == 's3':
            if p.path not in ('','/') or not isinstance(body.get('bucket'), str) or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', body['bucket']):
                self.fail('invalid_bucket', 400)
            prefix = body.get('prefix','')
            if not isinstance(prefix, str) or len(prefix) > 512 or any(ord(x) < 32 or ord(x) == 127 for x in prefix) or prefix.startswith('/') or any(x in ('.','..') for x in prefix.split('/')) or '\\' in prefix:
                self.fail('invalid_prefix', 400)
            result.update(bucket=body['bucket'], prefix=prefix.rstrip('/'))
            if 'region' in body:
                if not isinstance(body['region'], str) or not re.fullmatch(r'[a-z0-9-]{1,64}', body['region']):
                    self.fail('invalid_region', 400)
                result['region'] = body['region']
        elif set(body) & {'bucket','prefix','region'}:
            self.fail('invalid_storage', 400)
        return result

    def create_storage(self, db, body):
        metadata = self.metadata(body)
        if (old := self.repeat(db, 'storage', body)) is not None:
            return old
        self.revision(db, body)
        if db.execute('SELECT 1 FROM compose_storages WHERE id=?', (body['id'],)).fetchone():
            self.fail('storage_exists')
        if db.execute('SELECT COUNT(*) FROM compose_storages').fetchone()[0] >= 8*max(1,db.execute('SELECT COUNT(*) FROM nodes').fetchone()[0]):
            self.fail('storage_limit')
        db.execute('INSERT INTO compose_storages VALUES(?,?,NULL)', (body['id'], canonical(metadata)))
        result = {'storage': self.public_storage(db, self.storage(db, body['id'])), 'revision': self.c.bump(db)}
        return self.remember(db, 'storage', body, result)

    def prepare(self, db, sid, body):
        self.fields(body, ('sourceNodeId','nodeIds','mode','expectedRevision','idempotencyKey'))
        if (old := self.repeat(db, 'prepare/'+sid, body)) is not None:
            return old
        self.revision(db, body)
        storage = self.storage(db, sid)
        if not identity(body['sourceNodeId']) or not isinstance(body['nodeIds'], list) or not 1 <= len(body['nodeIds']) <= 20 or any(not identity(x) for x in body['nodeIds']) or len(set(body['nodeIds'])) != len(body['nodeIds']) or body['sourceNodeId'] not in body['nodeIds'] or body['mode'] not in ('create','attach'):
            self.fail('invalid_binding', 400)
        if body['mode'] == 'create' and storage['repository_id']:
            self.fail('repository_already_connected')
        metadata = json.loads(storage['metadata'])
        if body['mode'] == 'create':
            if metadata['kind'] == 'rest':
                if metadata['endpoint'].rstrip('/').split('/')[-1] != sid:
                    metadata['endpoint'] = metadata['endpoint'].rstrip('/') + '/' + sid
            else:
                if metadata.get('prefix','').split('/')[-1] != sid:
                    metadata['prefix'] = (metadata.get('prefix','').rstrip('/') + '/' + sid).lstrip('/')
            if metadata['kind'] == 's3' and len(metadata['prefix']) > 512:
                self.fail('invalid_prefix',400)
            db.execute('UPDATE compose_storages SET metadata=? WHERE id=?', (canonical(metadata), sid))
        bindings = []
        request_id, expiry = str(uuid.uuid4()), time.time()+900
        for node_id in [body['sourceNodeId']] + [n for n in body['nodeIds'] if n != body['sourceNodeId']]:
            _, status = self.live(db, node_id)
            if db.execute("SELECT 1 FROM compose_jobs c JOIN jobs j ON c.job_id=j.id LEFT JOIN compose_services s ON s.id=c.service_id WHERE (c.storage_id=? OR json_extract(s.config,'$.storageId')=?) AND j.node_id=? AND j.status IN ('queued','dispatched','running','outcome_unknown')", (sid,sid,node_id)).fetchone():
                self.fail('binding_busy')
            current = db.execute('SELECT * FROM compose_bindings WHERE storage_id=? AND node_id=?', (sid,node_id)).fetchone()
            if not current and db.execute('SELECT COUNT(*) FROM compose_bindings WHERE node_id=?',(node_id,)).fetchone()[0] >= 8:
                self.fail('storage_limit')
            generation = current['generation']+1 if current else 1
            mode = body['mode'] if node_id == body['sourceNodeId'] else 'attach'
            db.execute('INSERT INTO compose_bindings VALUES(?,?,?,?,\'prepared\',NULL,NULL) ON CONFLICT(storage_id,node_id) DO UPDATE SET generation=excluded.generation,request_id=excluded.request_id,state=\'prepared\',error=NULL', (sid,node_id,generation,request_id))
            bindings.append({'nodeId': node_id,'key': status['key'],'mode': mode,'bindingGeneration': generation})
        db.execute('INSERT INTO compose_challenges VALUES(?,?,?,?,?,0)', (request_id,sid,canonical(metadata),canonical(bindings),expiry))
        result = {'requestId': request_id,'expiresAt': datetime.fromtimestamp(expiry,timezone.utc).isoformat(),'metadata': metadata,'bindings': bindings,'revision': self.c.bump(db)}
        return self.remember(db, 'prepare/'+sid, body, result)

    def envelope(self, env, challenge, b):
        required = {'v','algorithm','nodeId','keyId','storageId','requestId','bindingGeneration','mode','expiresAt','wrappedKey','iv','ciphertext'}
        if not isinstance(env, dict) or set(env) != required:
            self.fail('invalid_envelope', 400)
        expected = {'v':1,'algorithm':ALGORITHM,'nodeId':b['nodeId'],'keyId':b['key']['id'],'storageId':challenge['storage_id'],'requestId':challenge['id'],'bindingGeneration':b['bindingGeneration'],'mode':b['mode'],'expiresAt':datetime.fromtimestamp(challenge['expires'],timezone.utc).isoformat()}
        if any(type(env[k]) is not type(v) or env[k] != v for k,v in expected.items()):
            self.fail('envelope_binding_mismatch', 400)
        try:
            raw = {k: base64.b64decode(env[k],validate=True) for k in ('wrappedKey','iv','ciphertext')}
            if len(raw['wrappedKey']) != 384 or len(raw['iv']) != 12 or not 16 <= len(raw['ciphertext']) <= 16400 or any(base64.b64encode(v).decode() != env[k] for k,v in raw.items()):
                raise ValueError()
        except (ValueError,TypeError):
            self.fail('invalid_envelope',400)

    def queue(self, db, node, action, params, *, parent=None, group=None, snapshot=None, intent=None):
        plan_id, job_id, idem = (str(uuid.uuid4()) for _ in range(3))
        db.execute('INSERT INTO plans VALUES(?,?,?,?,?,?,?)', (plan_id,node,action,snapshot,canonical(params),self.c.revision(db),time.time()+900))
        db.execute('INSERT INTO jobs(id,node_id,plan_id,action,snapshot,parameters,nonce,status,idempotency_key,created,stage) VALUES(?,?,?,?,?,?,?,\'queued\',?,?,\'queued\')', (job_id,node,plan_id,action,snapshot,canonical(params),secrets.token_urlsafe(32),idem,time.time()))
        db.execute('INSERT INTO job_requests VALUES(?,?,?)', (idem,plan_id,job_id))
        db.execute('INSERT INTO compose_jobs VALUES(?,?,?,?,?,?)', (job_id,parent,group,params.get('serviceId'),params.get('storageId'),canonical(intent or {})))
        return db.execute('SELECT * FROM jobs WHERE id=?',(job_id,)).fetchone()

    def connect_storage(self, db, sid, body):
        self.fields(body, ('requestId','bindings','expectedRevision','idempotencyKey'))
        if (old := self.repeat(db, 'connect/'+sid, body)) is not None:
            return old
        self.revision(db, body)
        storage = self.storage(db,sid)
        challenge = db.execute('SELECT * FROM compose_challenges WHERE id=? AND storage_id=?',(body['requestId'],sid)).fetchone() if identity(body['requestId']) else None
        if not challenge or challenge['consumed'] or challenge['expires'] < time.time():
            self.fail('challenge_stale')
        bindings = json.loads(challenge['bindings'])
        if not isinstance(body['bindings'],list) or len(body['bindings']) != len(bindings) or any(not isinstance(x,dict) or set(x) != {'nodeId','envelope'} for x in body['bindings']) or len({x['nodeId'] for x in body['bindings'] if isinstance(x.get('nodeId'),str)}) != len(bindings):
            self.fail('invalid_binding',400)
        supplied = {x['nodeId']: x['envelope'] for x in body['bindings']}
        for b in bindings:
            row = db.execute('SELECT * FROM compose_bindings WHERE storage_id=? AND node_id=?',(sid,b['nodeId'])).fetchone()
            _, seen = self.live(db,b['nodeId'])
            if not row or row['request_id'] != challenge['id'] or row['generation'] != b['bindingGeneration'] or row['state'] != 'prepared' or seen['key']['id'] != b['key']['id'] or b['nodeId'] not in supplied:
                self.fail('challenge_stale')
            self.envelope(supplied[b['nodeId']],challenge,b)
        self.c.bump(db)
        jobs, parent = [], None
        for b in bindings:
            params = {'storageId':sid,'envelope':supplied[b['nodeId']],'mode':b['mode'],'metadata':json.loads(challenge['metadata'])}
            if storage['repository_id']:
                params['expectedRepositoryId'] = storage['repository_id']
            job = self.queue(db,b['nodeId'],'storage-configure',params,parent=parent,group=challenge['id'],intent={'metadata':json.loads(challenge['metadata']),'requestId':challenge['id'],'bindingGeneration':b['bindingGeneration']})
            # All recipients depend on the creator, rather than each other.
            parent = parent or job['id']
            jobs.append(self.c.public_job(job,db))
            db.execute('UPDATE compose_bindings SET state=\'connecting\' WHERE storage_id=? AND node_id=?',(sid,b['nodeId']))
        db.execute('UPDATE compose_challenges SET consumed=1 WHERE id=?',(challenge['id'],))
        result = {'jobs':jobs,'storage':self.public_storage(db,self.storage(db,sid)),'revision':self.c.revision(db)}
        return self.remember(db,'connect/'+sid,body,result)

    def import_service(self, db, body):
        self.fields(body, ('id','name','sourceNodeId','recoveryNodeId','projectId','fingerprint','storageId','backupInterval','exclusiveWriters','expectedRevision','idempotencyKey'),('healthCheck',))
        if (old := self.repeat(db,'service',body)) is not None:
            return old
        self.revision(db,body)
        self.idle(db)
        if not identity(body['id']) or not text(body['name'],80) or not isinstance(body['projectId'],str) or not NAME.fullmatch(body['projectId']) or not isinstance(body['fingerprint'],str) or not HEX.fullmatch(body['fingerprint']) or (not isinstance(body['backupInterval'],str) or body['backupInterval'] not in INTERVALS) or body['exclusiveWriters'] is not True or body['sourceNodeId'] == body['recoveryNodeId']:
            self.fail('invalid_service',400)
        _, seen = self.live(db,body['sourceNodeId'])
        self.live(db,body['recoveryNodeId'])
        self.binding(db,body['storageId'],body['sourceNodeId'])
        self.binding(db,body['storageId'],body['recoveryNodeId'])
        project = next((p for p in seen['projects'] if p['id'] == body['projectId'] and p.get('fingerprint') == body['fingerprint'] and p['supported']),None)
        if not project:
            self.fail('project_unavailable')
        if 'healthCheck' in body:
            h = body['healthCheck']
            self.fields(h,('service','port','path','expectedStatus'))
            if h['service'] not in {s['name'] for s in project['services']} or not integer(h['port'],1,65535) or not text(h['path'],1024) or not h['path'].startswith('/') or h['path'].startswith('//') or any(ord(c)<=32 for c in h['path']) or not integer(h['expectedStatus'],100,599):
                self.fail('invalid_health_check',400)
        existing = db.execute('SELECT * FROM compose_services WHERE id=?',(body['id'],)).fetchone()
        if not existing and db.execute("SELECT COUNT(*) FROM compose_services WHERE json_extract(config,'$.sourceNodeId')=?",(body['sourceNodeId'],)).fetchone()[0] >= 20:
            self.fail('service_limit')
        if db.execute('SELECT 1 FROM compose_services WHERE id<>? AND json_extract(config,\'$.sourceNodeId\')=? AND json_extract(config,\'$.projectId\')=?',(body['id'],body['sourceNodeId'],body['projectId'])).fetchone():
            self.fail('project_already_registered')
        config = {k:v for k,v in body.items() if k not in ('expectedRevision','idempotencyKey')}
        db.execute('INSERT INTO compose_services VALUES(?,?,\'configuring\',0) ON CONFLICT(id) DO UPDATE SET config=excluded.config,state=\'configuring\',registered=0',(body['id'],canonical(config)))
        self.c.bump(db)
        params = {k:body[k] for k in ('projectId','fingerprint','storageId','backupInterval','exclusiveWriters')}
        params['serviceId'] = body['id']
        if 'healthCheck' in body:
            params['healthCheck'] = body['healthCheck']
        job = self.queue(db,body['sourceNodeId'],'compose-register',params)
        result = {'service':self.public_service(db,self.service(db,body['id'])[0]),'job':self.c.public_job(job,db),'revision':self.c.revision(db)}
        return self.remember(db,'service',body,result)

    def plan(self, db, body):
        self.fields(body,('nodeId','action'),('snapshotId','parameters'))
        action, params, snapshot = body['action'], body.get('parameters',{}), body.get('snapshotId')
        if not isinstance(action,str):
            self.fail('invalid_action',400)
        if action in INTERNAL:
            self.fail('internal_action',403)
        if action not in ACTIONS or not isinstance(params,dict):
            self.fail('invalid_action',400)
        sid = params.get('serviceId')
        row, service = self.service(db,sid)
        if not row['registered']:
            self.fail('service_not_registered')
        node, seen = self.live(db,body['nodeId'])
        if action in ('compose-backup','compose-verify','compose-restore'):
            self.fields(params,('serviceId','storageId'),('snapshotId',) if action == 'compose-restore' else ())
            if params['storageId'] != service['storageId']:
                self.fail('storage_scope_mismatch',400)
            self.binding(db,service['storageId'],node['id'])
        elif action == 'compose-schedule':
            self.fields(params,('serviceId','interval'))
            if (not isinstance(params['interval'],str) or params['interval'] not in INTERVALS):
                self.fail('invalid_schedule',400)
        elif action == 'compose-remove':
            self.fields(params,('serviceId','restoreId'))
            restore = self.restore(db,params['restoreId'],service)
            if restore['node_id'] != node['id'] or restore['state'] != 'isolated_ready':
                self.fail('restore_not_removable')
        if action in ('compose-backup','compose-schedule') and node['id'] != service['sourceNodeId']:
            self.fail('source_required')
        if action == 'compose-restore':
            if node['id'] != service['recoveryNodeId'] or node['id'] == service['sourceNodeId']:
                self.fail('recovery_required')
            if not isinstance(snapshot,str) or not HEX.fullmatch(snapshot) or params.get('snapshotId') != snapshot:
                self.fail('snapshot_scope_mismatch',400)
            repository = self.storage(db,service['storageId'])['repository_id']
            if not db.execute('SELECT 1 FROM compose_points WHERE service_id=? AND repository_id=? AND snapshot_id=?',(sid,repository,snapshot)).fetchone():
                self.fail('snapshot_unavailable')
        elif snapshot is not None:
            self.fail('unexpected_snapshot',400)
        pid, expiry = str(uuid.uuid4()), time.time()+600
        db.execute('INSERT INTO plans VALUES(?,?,?,?,?,?,?)',(pid,node['id'],action,snapshot,canonical(params),self.c.revision(db),expiry))
        return {'id':pid,'nodeId':node['id'],'action':action,'snapshotId':snapshot,'parameters':params,'expiresAt':datetime.fromtimestamp(expiry,timezone.utc).isoformat(),'revision':self.c.revision(db),'summary':{'code':action,'pausesService':action=='compose-backup','isolated':action=='compose-restore','retainsCopy':action=='compose-restore'}}

    def track_enqueued(self, db, job):
        params = json.loads(job['parameters'])
        if job['action'] in INTERNAL:
            if not db.execute('SELECT 1 FROM compose_jobs WHERE job_id=?',(job['id'],)).fetchone():
                self.fail('internal_action',403)
            return
        db.execute('INSERT OR IGNORE INTO compose_jobs VALUES(?,NULL,NULL,?,?,\'{}\')',(job['id'],params.get('serviceId'),params.get('storageId')))

        if job['action'] == 'compose-schedule':
            row, service = self.service(db,params['serviceId'])
            if service['backupInterval'] != params['interval']:
                service['backupInterval'] = params['interval']
                db.execute('UPDATE compose_services SET config=?,state=? WHERE id=?',(canonical(service),'schedule_required',service['id']))
                revision=self.c.bump(db)
                db.execute('UPDATE plans SET revision=? WHERE id=?',(revision,job['plan_id']))

    def restore(self, db, rid, service):
        if not identity(rid):
            self.fail('invalid_restore',400)
        restore = db.execute('SELECT * FROM compose_restores WHERE id=?',(rid,)).fetchone()
        if not restore or restore['service_id'] != service['id'] or restore['repository_id'] != self.storage(db,service['storageId'])['repository_id']:
            self.fail('restore_scope_mismatch')
        return restore

    def validate_result(self, db, job, result):
        params = json.loads(job['parameters'])
        result = sanitize_result(job['action'],result,job['snapshot'],params,job['id'])
        if result is None:
            return None
        if job['action'] == 'storage-configure':
            storage = self.storage(db,params['storageId'])
            if storage['repository_id'] and storage['repository_id'] != result['repositoryId']:
                return None
        elif job['action'] in ('compose-backup','compose-verify','compose-restore','compose-activate'):
            _, service = self.service(db,params['serviceId'])
            repository = self.storage(db,service['storageId'])['repository_id']
            if job['action'] != 'compose-activate' and result.get('repositoryId') != repository:
                return None
            if job['action'] == 'compose-restore':
                point = db.execute('SELECT * FROM compose_points WHERE service_id=? AND repository_id=? AND snapshot_id=?',(service['id'],repository,job['snapshot'])).fetchone()
                if not point or json.loads(point['point'])['manifestDigest'] != result['manifestDigest']:
                    return None
            if job['action'] == 'compose-backup' and result['sourceFingerprint'] != service['fingerprint']:
                return None
            if job['action'] == 'compose-activate':
                if result['sourceNodeId'] != job['node_id']:
                    return None
                first = result.get('firstBackup')
                if first and (first['repositoryId'] != repository or first['sourceFingerprint'] != result['fingerprint']):
                    return None
        return result

    def point(self, db, sid, repository, value, node_id):
        selected = points([dict(value,serviceId=sid,repositoryId=repository)])
        if selected:
            p = selected[0]
            db.execute('INSERT INTO compose_points VALUES(?,?,?,?,?) ON CONFLICT(service_id,repository_id,snapshot_id) DO UPDATE SET point=excluded.point,node_id=excluded.node_id',(sid,repository,p['id'],canonical(p),node_id))

    def observed(self, db, node_id, status):
        compose = status.get('compose',{})
        if compose.get('operationOverflow'):
            db.execute('UPDATE nodes SET orphan_overflow=1 WHERE id=?',(node_id,))
        for op in compose.get('operations',[]):
            # Timer identities are not assigned nonces and cannot impersonate a
            # catalog job. Unknown local operations create an own-node hold.
            if op['status'] == 'outcome_unknown' and not db.execute('SELECT 1 FROM jobs WHERE id=?',(op['id'],)).fetchone():
                self.c.record_orphan(db,node_id,op['id'],op['status'],'generic_operation')
        for s in compose.get('services',[]):
            row = db.execute('SELECT * FROM compose_services WHERE id=?',(s['serviceId'],)).fetchone()
            if not row:
                continue
            service = json.loads(row['config'])
            repository = self.storage(db,service['storageId'])['repository_id']
            if node_id != service['sourceNodeId'] or s.get('fingerprint') != service['fingerprint'] or s.get('storageId') != service['storageId']:
                continue
            latest = s.get('latestBackup')
            if isinstance(latest,dict) and latest.get('repositoryId') == repository and latest.get('sourceFingerprint') == service['fingerprint']:
                if row['state'] == 'active_unprotected':
                    db.execute("UPDATE compose_services SET state='restore_required' WHERE id=?",(row['id'],))
                self.point(db,row['id'],repository,{'id':latest['snapshot'],'time':latest['at'],'manifestDigest':latest['manifestDigest'],'sourceFingerprint':latest['sourceFingerprint']},node_id)
            for p in s.get('snapshots',[]):
                if p['serviceId'] == row['id'] and p['repositoryId'] == repository:
                    self.point(db,row['id'],repository,p,node_id)
        for b in compose.get('storages',[]):
            binding = db.execute('SELECT * FROM compose_bindings WHERE storage_id=? AND node_id=?',(b['storageId'],node_id)).fetchone()
            if not binding or binding['state'] != 'connected' or b.get('repositoryId') != binding['repository_id'] or b.get('bindingGeneration') != binding['generation']:
                continue
            for p in b.get('snapshots',[]):
                row = db.execute('SELECT * FROM compose_services WHERE id=?',(p['serviceId'],)).fetchone()
                if row and json.loads(row['config'])['storageId'] == b['storageId'] and p['repositoryId'] == binding['repository_id']:
                    self.point(db,row['id'],binding['repository_id'],p,node_id)

    def purge(self, db, job):
        params = json.loads(job['parameters'])
        if 'envelope' in params:
            envelope = params.pop('envelope')
            params.update(envelopeDigest=hashlib.sha256(canonical(envelope).encode()).hexdigest(),requestId=envelope['requestId'],bindingGeneration=envelope['bindingGeneration'])
            encoded = canonical(params)
            db.execute('UPDATE jobs SET parameters=? WHERE id=?',(encoded,job['id']))
            db.execute('UPDATE plans SET parameters=? WHERE id=?',(encoded,job['plan_id']))

    def settle(self, db):
        """Observe terminal jobs once; dependency closure never reopens children."""
        for job in db.execute('SELECT j.*,c.intent FROM jobs j JOIN compose_jobs c ON c.job_id=j.id WHERE j.status IN (\'succeeded\',\'failed\')').fetchall():
            intent = json.loads(job['intent'])
            if intent.get('settled'):
                continue
            params, result = json.loads(job['parameters']), json.loads(job['result']) if job['result'] else {}
            success, action = job['status'] == 'succeeded', job['action']
            if action == 'storage-configure':
                env = params.get('envelope',{})
                request, generation = env.get('requestId',params.get('requestId')),env.get('bindingGeneration',params.get('bindingGeneration'))
                if success:
                    db.execute('UPDATE compose_storages SET repository_id=? WHERE id=?',(result['repositoryId'],params['storageId']))
                db.execute('UPDATE compose_bindings SET state=?,repository_id=?,error=? WHERE storage_id=? AND node_id=? AND request_id=? AND generation=?',('connected' if success else 'failed',result.get('repositoryId'),job['error'],params['storageId'],job['node_id'],request,generation))
            elif action == 'compose-register':
                db.execute('UPDATE compose_services SET registered=?,state=? WHERE id=?',(int(success),'backup_required' if success else 'attention_required',params['serviceId']))
            elif action == 'compose-backup' and success:
                self.point(db,params['serviceId'],result['repositoryId'],{'id':result['snapshot'],'time':result['at'],'manifestDigest':result['manifestDigest'],'sourceFingerprint':result['sourceFingerprint']},job['node_id'])
                db.execute('UPDATE compose_services SET state=CASE WHEN state=\'active_unprotected\' THEN \'restore_required\' WHEN state IN (\'backup_required\',\'registered\') THEN \'restore_required\' ELSE state END WHERE id=?',(params['serviceId'],))
            elif action == 'compose-restore':
                if success:
                    db.execute('INSERT OR REPLACE INTO compose_restores VALUES(?,?,?,?,?,?,?,?)',(job['id'],params['serviceId'],job['node_id'],job['snapshot'],result['repositoryId'],'isolated_ready',canonical(result),time.time()))
                    db.execute('UPDATE compose_services SET state=? WHERE id=?',('schedule_required' if result.get('applicationHealthVerified') else 'unverified',params['serviceId']))
                else:
                    repository=self.storage(db,params['storageId'])['repository_id']
                    db.execute('INSERT OR REPLACE INTO compose_restores VALUES(?,?,?,?,?,?,?,?)',(job['id'],params['serviceId'],job['node_id'],job['snapshot'],repository,'failed',canonical({'checks':[],'applicationHealthVerified':False}),time.time()))
                    db.execute('UPDATE compose_services SET state=\'attention_required\' WHERE id=?',(params['serviceId'],))
            elif action == 'compose-remove' and success:
                db.execute('DELETE FROM compose_restores WHERE id=? AND state=\'isolated_ready\'',(params['restoreId'],))
            elif action == 'compose-activate':
                if success:
                    row, service = self.service(db,params['serviceId'])
                    former = service['sourceNodeId']
                    service.update(sourceNodeId=job['node_id'],recoveryNodeId=former,projectId=result['projectId'],fingerprint=result['fingerprint'])
                    db.execute('UPDATE compose_services SET config=?,state=?,registered=1 WHERE id=?',(canonical(service),'restore_required' if result['protected'] else 'active_unprotected',service['id']))
                    proof = db.execute('SELECT proof FROM compose_restores WHERE id=?',(params['restoreId'],)).fetchone()
                    updated = dict(json.loads(proof['proof']),ports=result['ports'],isolated=False) if proof else result
                    db.execute('UPDATE compose_restores SET state=\'active\',proof=?,observed=? WHERE id=?',(canonical(updated),time.time(),params['restoreId']))
                    if result.get('firstBackup'):
                        b = result['firstBackup']
                        self.point(db,service['id'],b['repositoryId'],{'id':b['snapshot'],'time':b['at'],'manifestDigest':b['manifestDigest'],'sourceFingerprint':b['sourceFingerprint']},job['node_id'])
                else:
                    db.execute('UPDATE compose_services SET state=\'attention_required\' WHERE id=?',(params['serviceId'],))
            elif action == 'compose-resume' and success:
                db.execute('UPDATE compose_services SET state=\'registered\' WHERE id=?',(params['serviceId'],))
            self.purge(db,job)
            intent['settled'] = True
            db.execute('UPDATE compose_jobs SET intent=? WHERE job_id=?',(canonical(intent),job['id']))
        self.close_dependencies(db)
        # Missing/unknown outcomes remain visible without inventing proof.
        for job in db.execute('SELECT j.* FROM jobs j JOIN compose_jobs c ON c.job_id=j.id WHERE j.status=\'outcome_unknown\'').fetchall():
            params=json.loads(job['parameters'])
            if job['action'] == 'storage-configure':
                env=params.get('envelope',{})
                db.execute("UPDATE compose_bindings SET state='outcome_unknown',error=? WHERE storage_id=? AND node_id=? AND request_id=?",(job['error'],params['storageId'],job['node_id'],env.get('requestId',params.get('requestId'))))
            elif 'serviceId' in params:
                db.execute('UPDATE compose_services SET state=\'attention_required\' WHERE id=?',(params['serviceId'],))
                if job['action'] == 'compose-restore':
                    repository=self.storage(db,params['storageId'])['repository_id']
                    db.execute('INSERT OR REPLACE INTO compose_restores VALUES(?,?,?,?,?,?,?,?)',(job['id'],params['serviceId'],job['node_id'],job['snapshot'],repository,'outcome_unknown',canonical({'checks':[],'applicationHealthVerified':False}),time.time()))

    def close_dependencies(self, db):
        # Unknown and failed parent closure takes precedence over all timeouts.
        for child in db.execute('SELECT j.*,c.parent_id FROM jobs j JOIN compose_jobs c ON c.job_id=j.id WHERE j.status=\'queued\' AND c.parent_id IS NOT NULL').fetchall():
            parent = db.execute('SELECT * FROM jobs WHERE id=?',(child['parent_id'],)).fetchone()
            if not parent or parent['status'] in ('failed','outcome_unknown'):
                unknown = not parent or parent['status'] == 'outcome_unknown'
                db.execute('UPDATE jobs SET status=\'failed\',stage=?,error=?,ended=? WHERE id=?',('blocked' if unknown else 'cancelled','parent_unknown' if unknown else 'parent_failed',time.time(),child['id']))
                self.purge(db,child)

    def dispatch(self, db, job):
        """Return a refreshed immutable wire row only after typed prerequisites."""
        meta = db.execute('SELECT * FROM compose_jobs WHERE job_id=?',(job['id'],)).fetchone()
        if not meta:
            db.execute("UPDATE jobs SET status='failed',stage='completed',error='generic_job_untyped',ended=? WHERE id=?",(time.time(),job['id']))
            return None
        params = json.loads(job['parameters'])
        if meta['parent_id']:
            parent = db.execute('SELECT * FROM jobs WHERE id=?',(meta['parent_id'],)).fetchone()
            if not parent or parent['status'] != 'succeeded':
                return None
            if job['action'] == 'storage-configure':
                proof = json.loads(parent['result'] or '{}')
                expected = proof.get('repositoryId')
                if not isinstance(expected,str) or not HEX.fullmatch(expected):
                    return None
                params['expectedRepositoryId'] = expected
                # Persist learned identity before the first dispatch. Later
                # delivery/reconciliation uses exactly these wire parameters.
                db.execute('UPDATE jobs SET parameters=? WHERE id=?',(canonical(params),job['id']))
                db.execute('UPDATE plans SET parameters=? WHERE id=?',(canonical(params),job['plan_id']))
        if job['action'] == 'compose-activate':
            activation = db.execute('SELECT * FROM compose_activations WHERE activate_job=?',(job['id'],)).fetchone()
            if not activation or activation['stop_job'] != params['sourceStopJobId']:
                db.execute("UPDATE jobs SET status='failed',stage='completed',error='source_stop_unproven',ended=? WHERE id=?",(time.time(),job['id']))
                return None
            stop = db.execute('SELECT * FROM jobs WHERE id=?',(activation['stop_job'],)).fetchone()
            source = self.c.node(db,activation['source_node'])
            _, service = self.service(db,params['serviceId'])
            proof = json.loads(stop['result'] or '{}') if stop else {}
            if not stop or stop['status'] != 'succeeded' or stop['action'] != 'compose-stop' or stop['node_id'] != activation['source_node'] or not stop['dispatch_instance'] or stop['dispatch_instance'] != source['instance_id'] or proof.get('stopOperationId') != stop['id'] or proof.get('serviceId') != service['id'] or proof.get('fingerprint') != service['fingerprint'] or proof.get('fenced') is not True or not stop['nonce']:
                db.execute("UPDATE jobs SET status='failed',stage='completed',error='source_stop_unproven',ended=? WHERE id=?",(time.time(),job['id']))
                db.execute("UPDATE compose_services SET state='attention_required' WHERE id=?",(service['id'],))
                return None
        return db.execute('SELECT * FROM jobs WHERE id=?',(job['id'],)).fetchone()

    def fresh_restore(self, db, rid, service):
        restore = self.restore(db,rid,service)
        if restore['state'] != 'isolated_ready' or restore['node_id'] != service['recoveryNodeId'] or restore['node_id'] == service['sourceNodeId']:
            self.fail('recovery_restore_required')
        _, status = self.live(db,restore['node_id'])
        seen = next((r for r in status['restores'] if r['id'] == rid and r['serviceId'] == service['id']),{})
        if seen.get('state') != 'isolated_ready' or seen.get('ports') or seen.get('repositoryId') != restore['repository_id'] or seen.get('snapshotId') != restore['snapshot_id'] or not RESTORE_CHECKS <= set(seen.get('checks',[])):
            self.fail('restore_state_unverified')
        return restore

    def complete(self, db, sid, body):
        self.fields(body,('restoreId','expectedRevision'))
        self.revision(db,body)
        self.settle(db)
        self.idle(db)
        row, service = self.service(db,sid)
        if not row['registered']:
            self.fail('service_not_registered')
        self.binding(db,service['storageId'],service['sourceNodeId'])
        self.binding(db,service['storageId'],service['recoveryNodeId'])
        restore = self.fresh_restore(db,body['restoreId'],service)
        proof = json.loads(restore['proof'])
        if proof.get('applicationHealthVerified') is not True or proof.get('healthScope') not in ('http','docker') or 'application-health' not in proof.get('checks',[]):
            self.fail('application_health_unverified')
        _, seen = self.live(db,service['sourceNodeId'])
        source = next((s for s in seen['services'] if s['serviceId'] == sid),{})
        if source.get('fingerprint') != service['fingerprint'] or source.get('state') != 'running':
            self.fail('source_state_unverified')
        timer=source.get('schedule',{})
        if timer.get('enabled') is not True or timer.get('interval') != service['backupInterval']:
            self.fail('schedule_required')
        max_age={'15min':1020,'hourly':3720,'daily':86520}[service['backupInterval']]
        backup=db.execute('SELECT j.* FROM jobs j JOIN compose_jobs c ON c.job_id=j.id WHERE c.service_id=? AND j.node_id=? AND j.action=\'compose-backup\' AND j.status=\'succeeded\' AND j.snapshot IS NULL AND j.ended>? ORDER BY j.ended DESC LIMIT 1',(sid,service['sourceNodeId'],time.time()-max_age)).fetchone()
        activation=db.execute("SELECT j.* FROM jobs j JOIN compose_jobs c ON c.job_id=j.id WHERE c.service_id=? AND j.node_id=? AND j.action='compose-activate' AND j.status='succeeded' AND j.ended>? ORDER BY j.ended DESC LIMIT 1",(sid,service['sourceNodeId'],time.time()-max_age)).fetchone()
        activation_backup=json.loads(activation['result']).get('firstBackup') if activation and activation['result'] else None
        candidates=[]
        if backup and backup['result']:
            candidates.append((json.loads(backup['result']),backup['ended']))
        if activation_backup:
            candidates.append((activation_backup,activation['ended']))
        if source.get('latestBackup'):
            candidates.append((source['latestBackup'],when(source['latestBackup']['at'])))
        candidates=[(b,at) for b,at in candidates if iso(b.get('at')) and time.time()-when(b['at']) <= max_age and b.get('sourceFingerprint') == service['fingerprint'] and b.get('repositoryId') == restore['repository_id']]
        if not candidates:
            self.fail('backup_required')
        b,backed_at=max(candidates,key=lambda pair:when(pair[0]['at']))
        if b['snapshot'] != restore['snapshot_id'] or b['manifestDigest'] != proof['manifestDigest'] or backed_at > restore['observed']:
            self.fail('matching_restore_required')
        db.execute('UPDATE compose_services SET state=\'complete\' WHERE id=?',(sid,))
        return {'completed':True,'service':self.public_service(db,self.service(db,sid)[0])}

    def activate(self, db, sid, body):
        self.fields(body,('restoreId','ports','allowEgress','acceptSnapshotLoss','expectedRevision','idempotencyKey'))
        if (old := self.repeat(db,'activate/'+sid,body)) is not None:
            return old
        self.revision(db,body)
        self.settle(db)
        self.idle(db)
        row, service = self.service(db,sid)
        if not row['registered'] or body['allowEgress'] is not True or body['acceptSnapshotLoss'] is not True or ports(body['ports']) is None:
            self.fail('activation_confirmation_required',400)
        source_node, source = self.live(db,service['sourceNodeId'])
        current = next((s for s in source['services'] if s['serviceId']==sid),{})
        if current.get('state') != 'running' or current.get('fingerprint') != service['fingerprint']:
            self.fail('source_state_unverified')
        self.binding(db,service['storageId'],service['sourceNodeId'])
        self.binding(db,service['storageId'],service['recoveryNodeId'])
        restore = self.fresh_restore(db,body['restoreId'],service)
        if db.execute("SELECT COUNT(*) FROM compose_services WHERE json_extract(config,'$.sourceNodeId')=?",(restore['node_id'],)).fetchone()[0] >= 20:
            self.fail('service_limit')
        proof = json.loads(restore['proof'])
        if proof.get('applicationHealthVerified') is not True:
            self.fail('application_health_unverified')
        project = next((p for p in source['projects'] if p['id']==service['projectId']),{})
        if any(p['service'] not in {s['name'] for s in project.get('services',[])} for p in body['ports']):
            self.fail('invalid_ports',400)
        point = db.execute('SELECT point FROM compose_points WHERE service_id=? AND repository_id=? AND snapshot_id=?',(sid,restore['repository_id'],restore['snapshot_id'])).fetchone()
        if not point:
            self.fail('snapshot_unavailable')
        snapshot_time=json.loads(point['point'])['time']
        acceptance={'snapshotId':restore['snapshot_id'],'snapshotTime':snapshot_time,'acceptedAt':datetime.now(timezone.utc).isoformat(),'ageSeconds':max(0,int(time.time()-when(snapshot_time))),'acceptSnapshotLoss':True,'ports':body['ports'],'allowEgress':True,'sourceFingerprint':service['fingerprint'],'sourceInstance':source_node['instance_id']}
        group=str(uuid.uuid4())
        self.c.bump(db)
        stop=self.queue(db,service['sourceNodeId'],'compose-stop',{'serviceId':sid,'fingerprint':service['fingerprint']},group=group,intent={'acceptance':acceptance})
        target=self.queue(db,restore['node_id'],'compose-activate',{'serviceId':sid,'restoreId':restore['id'],'sourceStopJobId':stop['id'],'interval':service['backupInterval'],'ports':body['ports'],'allowEgress':True},parent=stop['id'],group=group,intent={'acceptance':acceptance})
        db.execute('INSERT INTO compose_activations VALUES(?,?,?,?,?,?,?)',(group,sid,service['sourceNodeId'],restore['node_id'],stop['id'],target['id'],canonical(acceptance)))
        db.execute('UPDATE compose_services SET state=\'moving\' WHERE id=?',(sid,))
        result={'activationGroupId':group,'jobs':[self.c.public_job(stop,db),self.c.public_job(target,db)],'plan':acceptance,'revision':self.c.revision(db)}
        return self.remember(db,'activate/'+sid,body,result)

    def resume(self, db, sid, body):
        self.fields(body,('activationGroupId','expectedRevision','idempotencyKey'))
        if (old := self.repeat(db,'resume/'+sid,body)) is not None:
            return old
        self.revision(db,body)
        self.settle(db)
        self.idle(db)
        _,service=self.service(db,sid)
        activation=db.execute('SELECT * FROM compose_activations WHERE id=? AND service_id=?',(body['activationGroupId'],sid)).fetchone() if identity(body['activationGroupId']) else None
        if not activation or activation['source_node'] != service['sourceNodeId']:
            self.fail('activation_not_resumable')
        stop=db.execute('SELECT * FROM jobs WHERE id=?',(activation['stop_job'],)).fetchone()
        target=db.execute('SELECT * FROM jobs WHERE id=?',(activation['activate_job'],)).fetchone()
        if stop['status'] != 'succeeded' or target['status'] != 'failed':
            self.fail('target_absence_unverified')
        # Fresh live engine inventory must positively identify the exact isolated
        # retained copy, stopped or isolated with no published ports. No absence
        # of a report is evidence that an activation did not become online.
        params=json.loads(target['parameters'])
        self.fresh_restore(db,params['restoreId'],service)
        source_node, source=self.live(db,service['sourceNodeId'])
        current=next((s for s in source['services'] if s['serviceId']==sid),{})
        stop_proof=json.loads(stop['result'] or '{}')
        if current.get('state') != 'fenced' or current.get('fingerprint') != service['fingerprint'] or stop_proof.get('fenced') is not True or stop_proof.get('stopOperationId') != stop['id'] or source_node['instance_id'] != stop['dispatch_instance']:
            self.fail('source_stop_unproven')
        self.c.bump(db)
        job=self.queue(db,service['sourceNodeId'],'compose-resume',{'serviceId':sid,'fingerprint':service['fingerprint'],'interval':service['backupInterval']},group=activation['id'])
        result={'job':self.c.public_job(job,db),'revision':self.c.revision(db)}
        return self.remember(db,'resume/'+sid,body,result)
