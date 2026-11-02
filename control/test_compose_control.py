"""Metadata, durable binding and controlled move authorization regressions."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch

from control import compose_control as cc
from control.controller import APIError, Control, stamp


def uid():
    return str(uuid.uuid4())


SNAP, REPO, FINGER, MANIFEST = ('a'*64,'b'*64,'c'*64,'d'*64)
RAW_KEY = bytes.fromhex('308201a2300d06092a864886f70d01010105000382018f003082018a0282018100') + bytes([129])*384 + bytes.fromhex('0203010001')
KEY = {'id':hashlib.sha256(RAW_KEY).hexdigest(),'publicKey':base64.b64encode(RAW_KEY).decode(),'algorithm':cc.ALGORITHM}


def compose(**extra):
    return {'ready':True,'key':KEY,'projects':[], 'storages':[], 'services':[], 'restores':[], 'addresses':['203.0.113.5'], **extra}


class ComposeCatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.c=Control(self.temp.name,'https://control.example.test')
        self.nodes=[]
        for role in ('primary','recovery'):
            e=self.call(self.c.enrollment,{'name':role,'role':role})
            n=self.call(self.c.enroll_agent,{'code':e['code'],'hostname':'fixture','version':'0.2.0'})
            n.update(instanceId=uid(),compose=compose())
            self.nodes.append(n)
            self.sync(n)
        self.source,self.target=self.nodes

    def tearDown(self):
        self.temp.cleanup()

    def call(self,fn,*args):
        with self.c.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            return fn(db,*args)

    def rev(self):
        return self.call(self.c.revision)

    def mutate(self,**extra):
        return dict(expectedRevision=self.rev(),idempotencyKey=uid(),**extra)

    def sync(self,n,reports=None):
        status={'supported':False,'observedAt':stamp(),'compose':n['compose']}
        return self.call(self.c.sync,{'nodeId':n['nodeId'],'instanceId':n['instanceId'],'status':status,'reports':reports or []},'Bearer '+n['token'])

    def error(self,code,fn,*args):
        with self.assertRaises(APIError) as raised:
            self.call(fn,*args)
        self.assertEqual(raised.exception.code,code)

    def metadata(self):
        sid=uid()
        body=self.mutate(id=sid,name='Storage',kind='rest',endpoint='https://storage.example.test/base')
        self.call(self.c.compose.create_storage,body)
        return sid,body

    def prepare(self,sid,**extra):
        body=self.mutate(sourceNodeId=self.source['nodeId'],nodeIds=[n['nodeId'] for n in self.nodes],mode='create',**extra)
        return self.call(self.c.compose.prepare,sid,body),body

    def envelopes(self,challenge):
        result=[]
        for b in challenge['bindings']:
            env={k:v for k,v in b.items() if k in ('nodeId','mode','bindingGeneration')}
            env.update(v=1,algorithm=cc.ALGORITHM,keyId=b['key']['id'],storageId=challenge['metadata']['id'],requestId=challenge['requestId'],expiresAt=challenge['expiresAt'],wrappedKey=base64.b64encode(b'w'*384).decode(),iv=base64.b64encode(b'i'*12).decode(),ciphertext=base64.b64encode(b'e'*64).decode())
            result.append({'nodeId':b['nodeId'],'envelope':env})
        return result

    def connection(self):
        sid,_=self.metadata()
        challenge,_=self.prepare(sid)
        body=self.mutate(requestId=challenge['requestId'],bindings=self.envelopes(challenge))
        pipeline=self.call(self.c.compose.connect_storage,sid,body)
        return sid,challenge,body,pipeline

    def success(self,n,wire,result):
        return self.sync(n,[{'id':wire['id'],'nonce':wire['nonce'],'status':'succeeded','result':result}])

    def connected(self):
        sid,challenge,body,pipeline=self.connection()
        for n,b in zip(self.nodes,challenge['bindings']):
            wire=self.sync(n)['job']
            result={'storageId':sid,'repositoryId':REPO,'connected':True,'bindingGeneration':b['bindingGeneration'],'requestId':challenge['requestId']}
            self.success(n,wire,result)
            n['compose']['storages']=[dict(result)]
            self.sync(n)
        return sid

    def service(self):
        storage=self.connected()
        sid=uid()
        project={'id':'example','name':'Example','fingerprint':FINGER,'supported':True,'reasons':[],'services':[{'name':'web','imageId':'sha256:'+'f'*64,'healthcheck':True,'ports':[8080]}],'mounts':[],'estimatedBytes':4,'architecture':'amd64'}
        self.source['compose']['projects']=[project]
        self.sync(self.source)
        body=self.mutate(id=sid,name='Application',sourceNodeId=self.source['nodeId'],recoveryNodeId=self.target['nodeId'],projectId='example',fingerprint=FINGER,storageId=storage,backupInterval='hourly',exclusiveWriters=True,healthCheck={'service':'web','port':8080,'path':'/health','expectedStatus':200})
        self.call(self.c.compose.import_service,body)
        wire=self.sync(self.source)['job']
        self.success(self.source,wire,{'serviceId':sid,'registered':True,'projectId':'example','fingerprint':FINGER})
        self.source['compose']['services']=[{'serviceId':sid,'projectId':'example','fingerprint':FINGER,'storageId':storage,'state':'running','schedule':{'enabled':True,'interval':'hourly'}}]
        self.sync(self.source)
        return sid,storage

    def backup_restore(self):
        sid,storage=self.service()
        plan=self.call(self.c.plan,{'nodeId':self.source['nodeId'],'action':'compose-backup','parameters':{'serviceId':sid,'storageId':storage}})
        self.call(self.c.enqueue,{'planId':plan['id'],'idempotencyKey':uid()})
        wire=self.sync(self.source)['job']
        backup={'serviceId':sid,'repositoryId':REPO,'snapshot':SNAP,'manifestDigest':MANIFEST,'sourceFingerprint':FINGER,'sourceResumed':True,'at':stamp(),'checks':['source-stopped','data-archived','images-saved','source-resumed','repository-written']}
        self.success(self.source,wire,backup)
        plan=self.call(self.c.plan,{'nodeId':self.target['nodeId'],'action':'compose-restore','snapshotId':SNAP,'parameters':{'serviceId':sid,'storageId':storage,'snapshotId':SNAP}})
        self.call(self.c.enqueue,{'planId':plan['id'],'idempotencyKey':uid()})
        wire=self.sync(self.target)['job']
        proof={'serviceId':sid,'storageId':storage,'repositoryId':REPO,'restoreId':wire['id'],'snapshot':SNAP,'manifestDigest':MANIFEST,'isolated':True,'applicationHealthVerified':True,'healthScope':'http','checks':sorted(cc.RESTORE_CHECKS|{'application-health'})}
        self.success(self.target,wire,proof)
        self.target['compose']['restores']=[dict(proof,id=wire['id'],state='isolated_ready',ports=[])]
        self.sync(self.target)
        return sid,storage,wire['id'],proof

    def test_historical_preview_does_not_rewrite_protection_progress(self):
        sid,storage,rid,proof=self.backup_restore()
        with self.c.connect() as db:
            # A move has changed source identity; the retained historical point
            # is still a valid service preview, not the required new backup.
            row,config=self.c.compose.service(db,sid)
            config.update(sourceNodeId=self.target['nodeId'],recoveryNodeId=self.source['nodeId'],fingerprint='e'*64)
            db.execute("UPDATE compose_services SET config=?,state='active_unprotected' WHERE id=?",(json.dumps(config),sid))
        for outcome in ('succeeded','failed','outcome_unknown'):
            with self.subTest(outcome=outcome):
                plan=self.call(self.c.plan,{'nodeId':self.source['nodeId'],'action':'compose-restore','snapshotId':SNAP,'parameters':{'serviceId':sid,'storageId':storage,'snapshotId':SNAP}})
                self.call(self.c.enqueue,{'planId':plan['id'],'idempotencyKey':uid()})
                wire=self.sync(self.source)['job']
                report={'id':wire['id'],'nonce':wire['nonce'],'status':outcome}
                if outcome=='succeeded':
                    report['result']=dict(proof,restoreId=wire['id'])
                else:
                    report['error']='operation_failed'
                self.sync(self.source,[report])
                self.assertEqual(self.call(self.c.overview)['services'][0]['setupState'],'active_unprotected')
                if outcome=='outcome_unknown':
                    self.sync(self.source,[dict(report,status='failed')])

    def test_demo_install_evidence_survives_later_missing_demo_status(self):
        status={'supported':True,'serviceHealthy':True,'observedAt':stamp(),'compose':self.source['compose']}
        self.call(self.c.sync,{'nodeId':self.source['nodeId'],'instanceId':self.source['instanceId'],'status':status,'reports':[]},'Bearer '+self.source['token'])
        self.sync(self.source)
        self.c=Control(self.temp.name,'https://control.example.test')
        self.assertTrue(self.call(self.c.overview)['setup']['demoSelected'])
        self.assertIn('package_unsupported',[a['code'] for a in self.call(self.c.overview)['alerts']])

    def test_prepare_preserves_working_binding_and_connect_rechecks_work(self):
        sid,storage=self.service()
        before=self.call(self.c.compose.binding,storage,self.source['nodeId'])
        body=self.mutate(sourceNodeId=self.source['nodeId'],nodeIds=[self.source['nodeId']],mode='attach')
        challenge=self.call(self.c.compose.prepare,storage,body)
        after=self.call(self.c.compose.binding,storage,self.source['nodeId'])
        self.assertEqual(dict(before),dict(after))
        self.assertGreater(challenge['bindings'][0]['bindingGeneration'],before['generation'])
        with self.c.connect() as db:
            db.execute('UPDATE compose_challenges SET expires=0 WHERE id=?',(challenge['requestId'],))
        self.error('challenge_stale',self.c.compose.connect_storage,storage,self.mutate(requestId=challenge['requestId'],bindings=self.envelopes(challenge)))
        self.assertEqual(dict(self.call(self.c.compose.binding,storage,self.source['nodeId'])),dict(before))
        self.c=Control(self.temp.name,'https://control.example.test')
        newer=self.call(self.c.compose.prepare,storage,self.mutate(sourceNodeId=self.source['nodeId'],nodeIds=[self.source['nodeId']],mode='attach'))
        self.assertGreater(newer['bindings'][0]['bindingGeneration'],challenge['bindings'][0]['bindingGeneration'])
        plan=self.call(self.c.plan,{'nodeId':self.source['nodeId'],'action':'compose-verify','parameters':{'serviceId':sid,'storageId':storage}})
        self.call(self.c.enqueue,{'planId':plan['id'],'idempotencyKey':uid()})
        self.error('binding_busy',self.c.compose.connect_storage,storage,self.mutate(requestId=newer['requestId'],bindings=self.envelopes(newer)))
        self.assertEqual(dict(self.call(self.c.compose.binding,storage,self.source['nodeId'])),dict(before))

    def test_snapshot_metadata_and_observed_origin_are_immutable(self):
        sid,_,_,_=self.backup_restore()
        with self.c.connect() as db:
            before=dict(db.execute('SELECT * FROM compose_points WHERE service_id=?',(sid,)).fetchone())
            original=json.loads(before['point'])
            self.c.compose.point(db,sid,REPO,dict(original,time='2020-01-01T00:00:00+00:00',manifestDigest='0'*64),self.target['nodeId'])
            self.c.compose.point(db,sid,REPO,original,self.target['nodeId'])
            after=dict(db.execute('SELECT * FROM compose_points WHERE service_id=?',(sid,)).fetchone())
        self.assertEqual(before,after)

    def test_import_scope_type_errors_are_controlled_and_do_not_mutate(self):
        sid,storage=self.service()
        _,config=self.call(self.c.compose.service,sid)
        for field,bad in [('storageId',[]),('storageId',{}),('sourceNodeId',[]),('recoveryNodeId',{}),('id',False),('healthCheck',{'service':['web'],'port':8080,'path':'/','expectedStatus':200})]:
            with self.subTest(field=field,bad=bad):
                body=self.mutate(**config);body[field]=bad
                self.error('invalid_health_check' if field=='healthCheck' else 'invalid_service',self.c.compose.import_service,body)
        self.assertEqual(self.call(self.c.compose.service,sid)[1],config)

    def test_optional_demo_selection_and_real_faults_remain_distinct(self):
        overview=self.call(self.c.overview)
        self.assertFalse(overview['setup']['demoSelected'])
        self.assertNotIn('package_unsupported',[a['code'] for a in overview['alerts']])
        storage=self.connected()
        self.assertNotIn('package_unsupported',[a['code'] for a in self.call(self.c.overview)['alerts']])
        self.source['compose']['ready']=False
        self.source['compose']['error']='docker_unavailable'
        self.sync(self.source)
        self.assertIn('docker_unavailable',[a['code'] for a in self.call(self.c.overview)['alerts']])
        self.call(self.c.settings,{'profile':'pair_assisted','backupInterval':'hourly','expectedRevision':self.rev()})
        self.assertTrue(self.call(self.c.overview)['setup']['demoSelected'])
        self.assertIn('package_unsupported',[a['code'] for a in self.call(self.c.overview)['alerts']])
        # Legacy agents without generic capability retain the old warning.
        status={'supported':False,'observedAt':stamp()}
        self.call(self.c.sync,{'nodeId':self.source['nodeId'],'instanceId':self.source['instanceId'],'status':status,'reports':[]},'Bearer '+self.source['token'])
        self.assertIn('package_unsupported',[a['code'] for a in self.call(self.c.overview)['alerts']])

    def unknown_attach(self):
        storage,_=self.metadata()
        challenge=self.call(self.c.compose.prepare,storage,self.mutate(sourceNodeId=self.source['nodeId'],nodeIds=[n['nodeId'] for n in self.nodes],mode='attach'))
        body=self.mutate(requestId=challenge['requestId'],bindings=self.envelopes(challenge))
        pipeline=self.call(self.c.compose.connect_storage,storage,body)
        return storage,challenge,body,pipeline

    def test_initial_attach_discovers_only_parent_then_persists_recipient_identity(self):
        storage,challenge,body,pipeline=self.unknown_attach()
        with self.c.connect() as db:
            child=json.loads(db.execute('SELECT parameters FROM jobs WHERE id=?',(pipeline['jobs'][1]['id'],)).fetchone()['parameters'])
            self.assertNotIn('discoverRepositoryId',child)
            self.assertNotIn('expectedRepositoryId',child)
        wire=self.sync(self.source)['job']
        self.assertIs(wire['parameters']['discoverRepositoryId'],True)
        self.assertEqual(wire['parameters']['mode'],'attach')
        self.assertNotIn('expectedRepositoryId',wire['parameters'])
        self.assertEqual(wire,self.sync(self.source)['job'])
        result={'storageId':storage,'repositoryId':REPO,'connected':True,'bindingGeneration':challenge['bindings'][0]['bindingGeneration'],'requestId':challenge['requestId']}
        self.success(self.source,wire,result)
        recipient=self.sync(self.target)['job']
        self.assertEqual(recipient['parameters']['expectedRepositoryId'],REPO)
        self.assertNotIn('discoverRepositoryId',recipient['parameters'])
        with self.c.connect() as db:
            self.assertEqual(json.loads(db.execute('SELECT parameters FROM jobs WHERE id=?',(recipient['id'],)).fetchone()['parameters']),recipient['parameters'])
        self.assertEqual(self.call(self.c.compose.connect_storage,storage,body),pipeline)

    def test_known_repository_rotation_never_discovers_and_cannot_replace_identity(self):
        storage=self.connected()
        challenge=self.call(self.c.compose.prepare,storage,self.mutate(sourceNodeId=self.source['nodeId'],nodeIds=[self.source['nodeId']],mode='attach'))
        self.call(self.c.compose.connect_storage,storage,self.mutate(requestId=challenge['requestId'],bindings=self.envelopes(challenge)))
        wire=self.sync(self.source)['job']
        self.assertEqual(wire['parameters']['expectedRepositoryId'],REPO)
        self.assertNotIn('discoverRepositoryId',wire['parameters'])
        self.success(self.source,wire,{'storageId':storage,'repositoryId':'e'*64,'connected':True,'bindingGeneration':challenge['bindings'][0]['bindingGeneration'],'requestId':challenge['requestId']})
        with self.c.connect() as db:
            self.assertEqual(db.execute('SELECT repository_id FROM compose_storages WHERE id=?',(storage,)).fetchone()[0],REPO)
            self.assertEqual(db.execute('SELECT status FROM jobs WHERE id=?',(wire['id'],)).fetchone()[0],'outcome_unknown')

    def test_browser_cannot_supply_repository_discovery_authority(self):
        storage,_=self.metadata()
        body=self.mutate(sourceNodeId=self.source['nodeId'],nodeIds=[self.source['nodeId']],mode='attach')
        self.error('invalid_request',self.c.compose.prepare,storage,dict(body,discoverRepositoryId=True))
        challenge=self.call(self.c.compose.prepare,storage,body)
        connect=self.mutate(requestId=challenge['requestId'],bindings=self.envelopes(challenge))
        self.error('invalid_request',self.c.compose.connect_storage,storage,dict(connect,discoverRepositoryId=True))
        injected=copy.deepcopy(connect)
        injected['bindings'][0]['envelope']['discoverRepositoryId']=True
        self.error('invalid_envelope',self.c.compose.connect_storage,storage,injected)
        self.error('internal_action',self.c.plan,{'nodeId':self.source['nodeId'],'action':'storage-configure','parameters':{'storageId':storage,'discoverRepositoryId':True}})
        with self.c.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0],0)

    def test_failed_initial_attach_closes_recipient_without_adopting_identity(self):
        storage,_,_,pipeline=self.unknown_attach()
        wire=self.sync(self.source)['job']
        self.sync(self.source,[{'id':wire['id'],'nonce':wire['nonce'],'status':'failed','error':'repository_password_invalid'}])
        self.assertNotIn('job',self.sync(self.target))
        with self.c.connect() as db:
            self.assertIsNone(db.execute('SELECT repository_id FROM compose_storages WHERE id=?',(storage,)).fetchone()[0])
            child=db.execute('SELECT status,error FROM jobs WHERE id=?',(pipeline['jobs'][1]['id'],)).fetchone()
            self.assertEqual(tuple(child),('failed','parent_failed'))

    def test_metadata_idempotency_and_plaintext_rejection(self):
        sid,body=self.metadata()
        self.assertEqual(self.call(self.c.compose.create_storage,body)['storage']['id'],sid)
        self.error('idempotency_conflict',self.c.compose.create_storage,dict(body,name='changed'))
        self.error('invalid_request',self.c.compose.create_storage,dict(self.mutate(id=uid(),name='X',kind='rest',endpoint='https://storage.example'),repoPassword='SECRET_SENTINEL'))
        self.assertNotIn(b'SECRET_SENTINEL',Path(self.temp.name,'control.sqlite3').read_bytes())

    def test_nonpublic_or_credential_endpoints_refused(self):
        for endpoint in ('http://storage.example','https://127.0.0.1/x','https://10.0.0.1/x','https://localhost/x','https://user:secret@storage.example/x','https://storage.example/x?secret=1','https://storage.example:bad/x','https://storage.example/../x'):
            self.error('invalid_endpoint',self.c.compose.create_storage,self.mutate(id=uid(),name='x',kind='rest',endpoint=endpoint))

    def test_prepare_namespace_generation_and_stale_challenge(self):
        sid,_=self.metadata()
        old,oldbody=self.prepare(sid)
        self.assertTrue(old['metadata']['endpoint'].endswith('/'+sid))
        self.assertEqual(self.call(self.c.compose.prepare,sid,oldbody),old)
        newer,_=self.prepare(sid)
        self.assertTrue(all(x['bindingGeneration']==2 for x in newer['bindings']))
        self.error('challenge_stale',self.c.compose.connect_storage,sid,self.mutate(requestId=old['requestId'],bindings=self.envelopes(old)))

    def test_envelope_exact_bound_fields_and_lengths(self):
        sid,_=self.metadata()
        challenge,_=self.prepare(sid)
        for field,bad in [('nodeId',uid()),('keyId','0'*64),('storageId',uid()),('requestId',uid()),('bindingGeneration',2),('expiresAt',stamp()),('mode','attach'),('v',True),('wrappedKey','YQ=='),('iv','YQ=='),('ciphertext','!')]:
            bindings=self.envelopes(challenge)
            bindings[0]['envelope'][field]=bad
            code='invalid_envelope' if field in ('wrappedKey','iv','ciphertext') else 'envelope_binding_mismatch'
            self.error(code,self.c.compose.connect_storage,sid,self.mutate(requestId=challenge['requestId'],bindings=bindings))
        bindings=self.envelopes(challenge)
        bindings[0]['envelope']['repoPassword']='SECRET'
        self.error('invalid_envelope',self.c.compose.connect_storage,sid,self.mutate(requestId=challenge['requestId'],bindings=bindings))

    def test_parent_first_repo_identity_and_immutable_redelivery(self):
        sid,challenge,body,pipeline=self.connection()
        self.assertNotIn('job',self.sync(self.target))
        wire=self.sync(self.source)['job']
        self.assertEqual(wire['parameters']['metadata'],challenge['metadata'])
        self.assertEqual(wire,self.sync(self.source)['job'])
        b=challenge['bindings'][0]
        self.success(self.source,wire,{'storageId':sid,'connected':True,'repositoryId':REPO,'requestId':challenge['requestId'],'bindingGeneration':b['bindingGeneration']})
        target=self.sync(self.target)['job']
        self.assertEqual(target['parameters']['expectedRepositoryId'],REPO)
        with self.c.connect() as db:
            row=db.execute('SELECT parameters FROM jobs WHERE id=?',(target['id'],)).fetchone()
            self.assertEqual(json.loads(row['parameters']),target['parameters'])
            terminal=db.execute('SELECT parameters FROM jobs WHERE id=?',(wire['id'],)).fetchone()[0]
            self.assertNotIn('"envelope":',terminal)
            self.assertIn('envelopeDigest',terminal)
        self.assertEqual(self.call(self.c.compose.connect_storage,sid,body),pipeline)

    def test_parent_failure_closes_child_and_never_requeues(self):
        sid,ch,_,pipe=self.connection()
        wire=self.sync(self.source)['job']
        self.sync(self.source,[{'id':wire['id'],'nonce':wire['nonce'],'status':'failed','error':'bad_credentials'}])
        with self.c.connect() as db:
            child=db.execute('SELECT * FROM jobs WHERE id=?',(pipe['jobs'][1]['id'],)).fetchone()
            self.assertEqual((child['status'],child['stage'],child['error']),('failed','cancelled','parent_failed'))
        self.assertNotIn('job',self.sync(self.target))

    def test_unknown_parent_hold_closes_child_before_expiry(self):
        _,_,_,pipe=self.connection()
        wire=self.sync(self.source)['job']
        with self.c.connect() as db:
            db.execute('UPDATE plans SET expires=0 WHERE id=(SELECT plan_id FROM jobs WHERE id=?)',(pipe['jobs'][1]['id'],))
        self.sync(self.source,[{'id':wire['id'],'nonce':wire['nonce'],'status':'outcome_unknown','error':'interrupted'}])
        with self.c.connect() as db:
            child=db.execute('SELECT * FROM jobs WHERE id=?',(pipe['jobs'][1]['id'],)).fetchone()
            self.assertEqual((child['stage'],child['error']),('blocked','parent_unknown'))
        b=wire['parameters']['envelope']
        self.success(self.source,wire,{'storageId':wire['parameters']['storageId'],'connected':True,'repositoryId':REPO,'requestId':b['requestId'],'bindingGeneration':b['bindingGeneration']})
        self.assertNotIn('job',self.sync(self.target))

    def test_report_nonce_and_node_cannot_cross_storage_pipeline(self):
        _,_,_,_=self.connection()
        wire=self.sync(self.source)['job']
        report={'id':wire['id'],'nonce':wire['nonce'],'status':'failed','error':'x'}
        self.error('job_report_forbidden',self.c.sync,{'nodeId':self.target['nodeId'],'instanceId':self.target['instanceId'],'status':{'observedAt':stamp()},'reports':[report]},'Bearer '+self.target['token'])
        report['nonce']='z'*40
        self.error('job_report_forbidden',self.c.sync,{'nodeId':self.source['nodeId'],'instanceId':self.source['instanceId'],'status':{'observedAt':stamp()},'reports':[report]},'Bearer '+self.source['token'])

    def test_internal_actions_cannot_be_forged_through_plans(self):
        for action in cc.INTERNAL:
            self.error('internal_action',self.c.plan,{'nodeId':self.source['nodeId'],'action':action,'parameters':{'serviceId':uid()}})

    def test_generic_runs_without_legacy_supported(self):
        sid=self.connected()
        self.assertEqual(self.call(self.c.overview)['storages'][0]['repositoryId'],REPO)
        self.assertFalse(self.call(self.c.overview)['nodes'][0]['status']['supported'])

    def test_missing_or_changed_discovery_cannot_register(self):
        sid,storage=self.service()
        _,service=self.call(self.c.compose.service,sid)
        body=self.mutate(**service)
        body['fingerprint']='f'*64
        self.error('project_unavailable',self.c.compose.import_service,body)

    def test_scope_and_exact_snapshot_identity(self):
        sid,storage,rid,proof=self.backup_restore()
        body={'nodeId':self.target['nodeId'],'action':'compose-restore','snapshotId':SNAP,'parameters':{'serviceId':sid,'storageId':uid(),'snapshotId':SNAP}}
        self.error('storage_scope_mismatch',self.c.plan,body)
        body['parameters']['storageId']=storage
        body['parameters']['snapshotId']='f'*64
        self.error('snapshot_scope_mismatch',self.c.plan,body)
        body['parameters']['snapshotId']='f'*64
        body['snapshotId']='f'*64
        self.error('snapshot_unavailable',self.c.plan,body)
        body['parameters']['snapshotId']=SNAP
        body['snapshotId']=SNAP
        body['nodeId']=self.source['nodeId']
        self.error('recovery_required',self.c.plan,body)

    def test_multiple_services_share_repository_without_sharing_snapshot_authority(self):
        first,storage,_,_=self.backup_restore()
        second=uid()
        project=copy.deepcopy(self.source['compose']['projects'][0])
        project.update(id='second-project',name='Second',fingerprint='e'*64)
        self.source['compose']['projects'].append(project)
        self.sync(self.source)
        body=self.mutate(id=second,name='Second service',sourceNodeId=self.source['nodeId'],recoveryNodeId=self.target['nodeId'],projectId='second-project',fingerprint='e'*64,storageId=storage,backupInterval='daily',exclusiveWriters=True)
        result=self.call(self.c.compose.import_service,body)
        self.assertEqual(result['job']['serviceId'],second)
        wire=self.sync(self.source)['job']
        self.success(self.source,wire,{'serviceId':second,'registered':True,'projectId':'second-project','fingerprint':'e'*64})
        self.error('snapshot_unavailable',self.c.plan,{'nodeId':self.target['nodeId'],'action':'compose-restore','snapshotId':SNAP,'parameters':{'serviceId':second,'storageId':storage,'snapshotId':SNAP}})
        services={s['id']:s for s in self.call(self.c.overview)['services']}
        self.assertEqual(len(services[first]['snapshots']),1)
        self.assertEqual(services[second]['snapshots'],[])
        another,_=self.metadata()
        self.assertNotEqual(another,storage)
        self.assertEqual(len(self.call(self.c.overview)['storages']),2)

    def test_complete_requires_exact_selected_restore_health_and_schedule(self):
        sid,storage,rid,proof=self.backup_restore()
        body={'restoreId':rid,'expectedRevision':self.rev()}
        self.source['compose']['services'][0]['schedule']['enabled']=False
        self.sync(self.source)
        self.error('schedule_required',self.c.compose.complete,sid,body)
        self.source['compose']['services'][0]['schedule']['enabled']=True
        self.sync(self.source)
        self.assertTrue(self.call(self.c.compose.complete,sid,body)['completed'])
        self.assertEqual(self.call(self.c.overview)['services'][0]['setupState'],'complete')

    def test_complete_cannot_use_unverified_health(self):
        sid,_,rid,_=self.backup_restore()
        with self.c.connect() as db:
            r=db.execute('SELECT proof FROM compose_restores WHERE id=?',(rid,)).fetchone()
            p=json.loads(r['proof']);p['applicationHealthVerified']=False
            db.execute('UPDATE compose_restores SET proof=? WHERE id=?',(json.dumps(p),rid))
        self.error('application_health_unverified',self.c.compose.complete,sid,{'restoreId':rid,'expectedRevision':self.rev()})

    def test_activation_stop_before_target_and_partial_new_source_authority(self):
        sid,storage,rid,_=self.backup_restore()
        body=self.mutate(restoreId=rid,ports=[{'service':'web','target':8080,'published':18080,'hostIp':'0.0.0.0','protocol':'tcp'}],allowEgress=True,acceptSnapshotLoss=True)
        pipeline=self.call(self.c.compose.activate,sid,body)
        self.assertEqual(pipeline,self.call(self.c.compose.activate,sid,body))
        self.assertEqual(pipeline['plan']['snapshotId'],SNAP)
        self.assertNotIn('job',self.sync(self.target))
        stop=self.sync(self.source)['job']
        self.assertEqual(stop['action'],'compose-stop')
        self.success(self.source,stop,{'serviceId':sid,'fingerprint':FINGER,'fenced':True,'stopOperationId':stop['id']})
        activate=self.sync(self.target)['job']
        self.assertEqual(activate['parameters']['sourceStopJobId'],stop['id'])
        result={'serviceId':sid,'restoreId':rid,'activated':True,'sourceNodeId':self.target['nodeId'],'projectId':'rpo-owned','fingerprint':'e'*64,'ports':body['ports'],'interval':'hourly','enabled':True,'protected':False}
        self.success(self.target,activate,result)
        service=self.call(self.c.overview)['services'][0]
        self.assertEqual((service['sourceNodeId'],service['recoveryNodeId'],service['setupState']),(self.target['nodeId'],self.source['nodeId'],'active_unprotected'))
        self.error('activation_not_resumable',self.c.compose.resume,sid,self.mutate(activationGroupId=pipeline['activationGroupId']))

    def test_activation_requires_loss_acceptance_and_online_source(self):
        sid,_,rid,_=self.backup_restore()
        body=self.mutate(restoreId=rid,ports=[],allowEgress=True,acceptSnapshotLoss=False)
        self.error('activation_confirmation_required',self.c.compose.activate,sid,body)
        body['acceptSnapshotLoss']=True
        with self.c.connect() as db:
            db.execute('UPDATE nodes SET last_seen=0 WHERE id=?',(self.source['nodeId'],))
        self.error('node_stale',self.c.compose.activate,sid,body)

    def test_incarnation_change_cannot_reuse_stop_proof(self):
        sid,_,rid,_=self.backup_restore()
        pipeline=self.call(self.c.compose.activate,sid,self.mutate(restoreId=rid,ports=[],allowEgress=True,acceptSnapshotLoss=True))
        stop=self.sync(self.source)['job']
        self.success(self.source,stop,{'serviceId':sid,'fingerprint':FINGER,'fenced':True,'stopOperationId':stop['id']})
        self.source['instanceId']=uid()
        self.sync(self.source)
        self.assertNotIn('job',self.sync(self.target))
        with self.c.connect() as db:
            target=db.execute('SELECT * FROM jobs WHERE id=?',(pipeline['jobs'][1]['id'],)).fetchone()
            self.assertEqual(target['error'],'source_stop_unproven')

    def test_unknown_activation_blocks_resume_and_all_work(self):
        sid,_,rid,_=self.backup_restore()
        pipeline=self.call(self.c.compose.activate,sid,self.mutate(restoreId=rid,ports=[],allowEgress=True,acceptSnapshotLoss=True))
        stop=self.sync(self.source)['job']
        self.success(self.source,stop,{'serviceId':sid,'fingerprint':FINGER,'fenced':True,'stopOperationId':stop['id']})
        activate=self.sync(self.target)['job']
        self.sync(self.target,[{'id':activate['id'],'nonce':activate['nonce'],'status':'outcome_unknown','error':'interrupted'}])
        self.error('operation_in_progress',self.c.compose.resume,sid,self.mutate(activationGroupId=pipeline['activationGroupId']))

    def test_timer_unknown_is_authenticated_own_node_hold_without_job(self):
        op=uid()
        self.source['compose']['operations']=[{'id':op,'status':'outcome_unknown','result':{'secret':'DROP'}}]
        self.sync(self.source)
        with self.c.connect() as db:
            self.assertIsNone(db.execute('SELECT 1 FROM jobs WHERE id=?',(op,)).fetchone())
            orphan=db.execute('SELECT * FROM orphan_reports WHERE job_id=?',(op,)).fetchone()
            self.assertEqual((orphan['node_id'],orphan['reason']),(self.source['nodeId'],'generic_operation'))
        self.assertNotIn('DROP',json.dumps(self.call(self.c.overview)))

    def test_additive_migration_preserves_legacy_catalog_authority(self):
        with self.c.connect() as db:
            self.c.new_session(db)
            for index in range(6):
                plan,job,key=uid(),uid(),uid()
                db.execute('INSERT INTO plans VALUES(?,?,?,?,?,?,?)',(plan,self.source['nodeId'],'backup',None,'{}',self.c.revision(db),time.time()+600))
                db.execute("INSERT INTO jobs(id,node_id,plan_id,action,parameters,nonce,status,idempotency_key,created,ended,result) VALUES(?,?,?,'backup','{}',?,'succeeded',?,?,?,?)",(job,self.source['nodeId'],plan,'n'*40,key,time.time(),time.time(),json.dumps({'snapshot':SNAP})))
                db.execute('INSERT INTO job_requests VALUES(?,?,?)',(key,plan,job))
            tables=('settings','nodes','plans','jobs','job_requests','sessions')
            before={t:[dict(r) for r in db.execute('SELECT * FROM '+t+' ORDER BY rowid')] for t in tables}
            for table in ('compose_storages','compose_bindings','compose_challenges','compose_services','compose_restores','compose_points','compose_requests','compose_jobs','compose_activations'):
                db.execute('DROP TABLE '+table)
        again=Control(self.temp.name,'https://control.example.test')
        with again.connect() as db:
            for table in tables:
                self.assertEqual([dict(r) for r in db.execute('SELECT * FROM '+table+' ORDER BY rowid')],before[table])
            self.assertEqual(db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0],6)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM compose_jobs').fetchone()[0],0)

    def test_failed_activation_can_resume_only_with_fresh_isolated_target(self):
        sid,_,rid,_=self.backup_restore()
        group=self.call(self.c.compose.activate,sid,self.mutate(restoreId=rid,ports=[],allowEgress=True,acceptSnapshotLoss=True))
        stop=self.sync(self.source)['job']
        self.success(self.source,stop,{'serviceId':sid,'fingerprint':FINGER,'fenced':True,'stopOperationId':stop['id']})
        self.source['compose']['services'][0]['state']='fenced'
        self.sync(self.source)
        activate=self.sync(self.target)['job']
        self.sync(self.target,[{'id':activate['id'],'nonce':activate['nonce'],'status':'failed','error':'operation_busy'}])
        self.target['compose']['restores'][0]['state']='active'
        self.sync(self.target)
        self.error('restore_state_unverified',self.c.compose.resume,sid,self.mutate(activationGroupId=group['activationGroupId']))
        self.target['compose']['restores'][0]['state']='isolated_ready'
        self.sync(self.target)
        result=self.call(self.c.compose.resume,sid,self.mutate(activationGroupId=group['activationGroupId']))
        wire=self.sync(self.source)['job']
        self.assertEqual((wire['id'],wire['action']),(result['job']['id'],'compose-resume'))
        self.success(self.source,wire,{'serviceId':sid,'fingerprint':FINGER,'resumed':True,'interval':'hourly','enabled':True})

    def test_resume_refuses_missing_and_malformed_port_inventory(self):
        sid,_,rid,_=self.backup_restore()
        group=self.call(self.c.compose.activate,sid,self.mutate(restoreId=rid,ports=[],allowEgress=True,acceptSnapshotLoss=True))
        stop=self.sync(self.source)['job']
        self.success(self.source,stop,{'serviceId':sid,'fingerprint':FINGER,'fenced':True,'stopOperationId':stop['id']})
        self.source['compose']['services'][0]['state']='fenced'
        self.sync(self.source)
        target=self.sync(self.target)['job']
        self.sync(self.target,[{'id':target['id'],'nonce':target['nonce'],'status':'failed','error':'operation_busy'}])
        original=copy.deepcopy(self.target['compose']['restores'][0])
        invalid=[None,{},'8080',[{'service':'web','target':80,'published':8080,'hostIp':True,'protocol':'tcp'}]]
        for bad in invalid:
            self.target['compose']['restores'][0]=dict(original,ports=bad)
            self.sync(self.target)
            self.error('restore_state_unverified',self.c.compose.resume,sid,self.mutate(activationGroupId=group['activationGroupId']))
        self.target['compose']['restores'][0]=dict(original)
        self.target['compose']['restores'][0].pop('ports')
        self.sync(self.target)
        self.error('restore_state_unverified',self.c.compose.resume,sid,self.mutate(activationGroupId=group['activationGroupId']))

    def test_unverified_repository_success_keeps_global_unknown_hold(self):
        sid,challenge,_,pipeline=self.connection()
        wire=self.sync(self.source)['job']
        b=challenge['bindings'][0]
        self.success(self.source,wire,{'storageId':uid(),'connected':True,'repositoryId':REPO,'requestId':challenge['requestId'],'bindingGeneration':b['bindingGeneration']})
        with self.c.connect() as db:
            source=db.execute('SELECT * FROM jobs WHERE id=?',(wire['id'],)).fetchone()
            child=db.execute('SELECT * FROM jobs WHERE id=?',(pipeline['jobs'][1]['id'],)).fetchone()
            self.assertEqual((source['status'],source['error']),('outcome_unknown','result_unverified'))
            self.assertEqual(child['error'],'parent_unknown')

    def test_schedule_changes_owner_interval_once_before_dispatch(self):
        sid,storage=self.service()
        plan=self.call(self.c.plan,{'nodeId':self.source['nodeId'],'action':'compose-schedule','parameters':{'serviceId':sid,'interval':'daily'}})
        body={'planId':plan['id'],'idempotencyKey':uid()}
        revision=self.rev()
        queued=self.call(self.c.enqueue,body)
        self.assertEqual(self.rev(),revision+1)
        self.assertEqual(self.call(self.c.enqueue,body),queued)
        self.assertEqual(self.rev(),revision+1)
        wire=self.sync(self.source)['job']
        self.success(self.source,wire,{'serviceId':sid,'enabled':True,'interval':'daily'})
        self.assertEqual(self.rev(),revision+1)
        self.assertEqual(self.call(self.c.overview)['services'][0]['backupInterval'],'daily')

    def test_protected_activation_stays_restore_required_until_exact_new_source_restore(self):
        sid,storage,rid,_=self.backup_restore()
        pipeline=self.call(self.c.compose.activate,sid,self.mutate(restoreId=rid,ports=[],allowEgress=True,acceptSnapshotLoss=True))
        self.assertEqual(pipeline['jobs'][0]['serviceId'],sid)
        self.assertEqual(pipeline['jobs'][1]['parentJobId'],pipeline['jobs'][0]['id'])
        self.assertEqual(pipeline['jobs'][1]['groupId'],pipeline['activationGroupId'])
        stop=self.sync(self.source)['job']
        self.success(self.source,stop,{'serviceId':sid,'fingerprint':FINGER,'fenced':True,'stopOperationId':stop['id']})
        self.source['compose']['services'][0]['state']='fenced'
        self.sync(self.source)
        activate=self.sync(self.target)['job']
        new_snapshot,new_fingerprint,new_manifest='e'*64,'f'*64,'0'*64
        first={'serviceId':sid,'repositoryId':REPO,'snapshot':new_snapshot,'manifestDigest':new_manifest,'sourceFingerprint':new_fingerprint,'sourceResumed':True,'at':stamp(),'checks':['source-stopped','data-archived','images-saved','source-resumed','repository-written']}
        self.success(self.target,activate,{'serviceId':sid,'restoreId':rid,'activated':True,'sourceNodeId':self.target['nodeId'],'projectId':'rpo-owned','fingerprint':new_fingerprint,'ports':[],'interval':'hourly','enabled':True,'protected':True,'firstBackup':first})
        public=self.call(self.c.overview)['services'][0]
        self.assertEqual(public['setupState'],'restore_required')
        self.assertEqual(public['latestBackup']['snapshot'],new_snapshot)
        self.assertEqual(public['activation']['targetJobId'],activate['id'])
        self.assertEqual(public['activation']['status'],'succeeded')
        self.c=Control(self.temp.name,'https://control.example.test')
        self.assertEqual(self.call(self.c.overview)['services'][0]['activationGroupId'],pipeline['activationGroupId'])
        self.target['compose']['services']=[{'serviceId':sid,'storageId':storage,'projectId':'rpo-owned','fingerprint':new_fingerprint,'sourceState':'running','schedule':{'enabled':True,'interval':'hourly'}}]
        self.sync(self.target)
        plan=self.call(self.c.plan,{'nodeId':self.source['nodeId'],'action':'compose-restore','snapshotId':new_snapshot,'parameters':{'serviceId':sid,'storageId':storage,'snapshotId':new_snapshot}})
        self.call(self.c.enqueue,{'planId':plan['id'],'idempotencyKey':uid()})
        wire=self.sync(self.source)['job']
        proof={'serviceId':sid,'storageId':storage,'repositoryId':REPO,'restoreId':wire['id'],'snapshot':new_snapshot,'manifestDigest':new_manifest,'isolated':True,'applicationHealthVerified':True,'healthScope':'http','checks':sorted(cc.RESTORE_CHECKS|{'application-health'})}
        self.success(self.source,wire,proof)
        self.source['compose']['restores']=[dict(proof,id=wire['id'],state='isolated_ready',ports=[])]
        self.sync(self.source)
        self.assertTrue(self.call(self.c.compose.complete,sid,{'restoreId':wire['id'],'expectedRevision':self.rev()})['completed'])
        with self.c.connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM jobs WHERE action='compose-backup' AND node_id=?",(self.target['nodeId'],)).fetchone()[0],0)

    def test_autonomous_running_operation_does_not_create_unknown_hold(self):
        self.source['compose']['operations']=[{'id':uid(),'status':'running'}]
        self.sync(self.source)
        self.assertEqual(self.call(self.c.overview)['orphanReports'],[])

    def test_terminal_cancel_purges_sealed_plan_and_job(self):
        _,_,_,pipeline=self.connection()
        identity=pipeline['jobs'][0]['id']
        self.call(self.c.cancel_job,identity,{})
        with self.c.connect() as db:
            row=db.execute('SELECT * FROM jobs WHERE id=?',(identity,)).fetchone()
            plan=db.execute('SELECT * FROM plans WHERE id=?',(row['plan_id'],)).fetchone()
            self.assertNotIn('"envelope":',row['parameters'])
            self.assertNotIn('"envelope":',plan['parameters'])



class MetadataBoundaryTests(unittest.TestCase):
    def test_sanitizer_drops_private_models_env_and_unbounded_data(self):
        source=compose(secret='SECRET',renderedModel={'environment':'SECRET'},projects=[{'id':'ok','name':'OK','fingerprint':FINGER,'supported':True,'reasons':[],'services':[{'name':'web','imageId':'sha256:'+FINGER,'healthcheck':True,'ports':[80],'environment':{'PASSWORD':'SECRET'}}],'mounts':[]}])
        value=cc.sanitize_status(source)
        self.assertTrue(value['ready'])
        self.assertNotIn('SECRET',json.dumps(value))
        value=cc.sanitize_status(compose(projects=source['projects']*21))
        self.assertFalse(value['ready'])
        self.assertEqual(value['error'],'discovery_limit')

    def test_unsupported_projects_and_engine_source_state_are_preserved(self):
        sid=uid()
        value=cc.sanitize_status(compose(projects=[{'id':'unsupported','name':'Unsupported','supported':False,'reasons':['unsafe_mount'],'services':[],'mounts':[]}],services=[{'serviceId':sid,'sourceState':'fenced'}]))
        self.assertFalse(value['projects'][0]['supported'])
        self.assertEqual(value['projects'][0]['reasons'],['unsafe_mount'])
        self.assertEqual(value['services'][0]['state'],'fenced')

    def test_repository_and_service_result_identity_are_required(self):
        sid,storage,rid=uid(),uid(),uid()
        value={'serviceId':sid,'storageId':storage,'repositoryId':REPO,'verified':True,'checks':['repository-data'],'credentials':'SECRET'}
        self.assertNotIn('SECRET',json.dumps(cc.sanitize_result('compose-verify',value,None,{'serviceId':sid,'storageId':storage},rid)))
        value['serviceId']=uid()
        self.assertIsNone(cc.sanitize_result('compose-verify',value,None,{'serviceId':sid,'storageId':storage},rid))

    def test_ip_values_are_strings_and_bind_slots_use_canonical_ipv6(self):
        base={'service':'web','target':80,'published':8080,'hostIp':'0:0:0:0:0:0:0:1','protocol':'tcp'}
        self.assertEqual(cc.ports([base])[0]['hostIp'],'::1')
        self.assertIsNone(cc.ports([base,dict(base,hostIp='::1')]))
        for bad in (True,False,1,3325256711):
            self.assertIsNone(cc.ports([dict(base,hostIp=bad)]))
        self.assertEqual(cc.sanitize_status(compose(addresses=[True,5,'198.51.100.7']))['addresses'],['198.51.100.7'])

    def test_udp_duplicate_ports_and_shell_fields_refused(self):
        base={'service':'web','target':80,'published':8080,'hostIp':'0.0.0.0','protocol':'tcp'}
        self.assertIsNone(cc.ports([dict(base,protocol='udp')]))
        self.assertIsNone(cc.ports([base,base]))
        self.assertIsNone(cc.ports([dict(base,command='shell')]))


if __name__=='__main__':
    unittest.main()
