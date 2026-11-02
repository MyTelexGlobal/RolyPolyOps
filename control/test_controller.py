"""Authentication, recovery, and dispatch boundary tests for the control service."""
import http.client
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
import uuid

from control.controller import APIError, CHECKS, Control, ControlHTTPServer, handler_for, password_matches, sanitize_status, stamp
from http.server import ThreadingHTTPServer

SNAP = 'a' * 64
OTHER = 'b' * 64


def observation(**overrides):
    result = {'supported': True, 'serviceHealthy': True, 'version': '0.0.1', 'serviceLabel': 'Demo', 'observedAt': stamp(), 'disk': {'total': 1000, 'free': 800}, 'snapshots': [{'id': SNAP, 'time': stamp()}, {'id': OTHER, 'time': stamp()}], 'schedule': {'backup': {'enabled': True, 'interval': 'hourly'}, 'restore': {'enabled': True}}}
    result.update(overrides)
    return result


class DomainCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.control = Control(self.temp.name, 'https://control.example.test')

    def tearDown(self):
        self.temp.cleanup()

    def call(self, method, *args):
        with self.control.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            return getattr(self.control, method)(db, *args)

    def error(self, code, method, *args):
        with self.assertRaises(APIError) as exc:
            self.call(method, *args)
        self.assertEqual(exc.exception.code, code)

    def add(self, role='primary', name='Site'):
        enrollment = self.call('enrollment', {'name': name, 'role': role})
        node = self.call('enroll_agent', {'code': enrollment['code'], 'hostname': 'test-host', 'version': '0.1.0'})
        self.sync(node)
        return node

    def sync(self, node, reports=None, status=None, **extra):
        node.setdefault('instanceId', str(uuid.uuid4()))
        return self.call('sync', {'nodeId': node['nodeId'], 'instanceId': node['instanceId'], 'status': status or observation(), 'reports': reports or [], **extra}, 'Bearer ' + node['token'])

    def job(self, node, action='backup', snap=None, parameters=None):
        body = {'nodeId': node['nodeId'], 'action': action}
        if snap is not None:
            body['snapshotId'] = snap
        if parameters is not None:
            body['parameters'] = parameters
        plan = self.call('plan', body)
        body = {'planId': plan['id'], 'idempotencyKey': str(uuid.uuid4())}
        return self.call('enqueue', body)['job'], body

    def finish(self, node, action='backup', snap=None, result=None):
        queued, _ = self.job(node, action, snap)
        assigned = self.sync(node)['job']
        self.assertEqual(assigned['id'], queued['id'])
        result = result if result is not None else {'snapshot': SNAP}
        report = {'id': queued['id'], 'nonce': assigned['nonce'], 'status': 'succeeded', 'result': result}
        self.sync(node, [report])
        return queued

    def test_credentials_only_digests_and_reinstall_preserves(self):
        initial = (Path(self.temp.name) / 'admin-password').read_text().strip()
        self.assertEqual((Path(self.temp.name) / 'admin-password').stat().st_mode & 0o777, 0o600)
        self.assertEqual((Path(self.temp.name) / 'control.sqlite3').stat().st_mode & 0o777, 0o600)
        again = Control(self.temp.name, 'https://control.example.test')
        with again.connect() as db:
            self.assertTrue(password_matches(initial, again.setting(db, 'password')))
        self.assertNotIn(initial.encode(), (Path(self.temp.name) / 'control.sqlite3').read_bytes())

    def test_same_password_preserves_first_change_gate_and_existing_session(self):
        initial = (Path(self.temp.name) / 'admin-password').read_text().strip()
        session, token = self.call('login', {'password': initial}, 'test')
        self.error('password_unchanged', 'change_password', {'currentPassword': initial, 'newPassword': initial})
        with self.control.connect() as db:
            self.assertTrue(self.control.setting(db, 'needsPasswordChange'))
            self.assertTrue(password_matches(initial, self.control.setting(db, 'password')))
            self.assertEqual(db.execute('SELECT COUNT(*) FROM sessions').fetchone()[0], 1)
        replacement = 'new-password-after-bootstrap-1234'
        self.call('change_password', {'currentPassword': initial, 'newPassword': replacement})
        self.error('password_unchanged', 'change_password', {'currentPassword': replacement, 'newPassword': replacement})
        with self.control.connect() as db:
            self.assertFalse(self.control.setting(db, 'needsPasswordChange'))
            self.assertTrue(password_matches(replacement, self.control.setting(db, 'password')))

    def test_enrollment_consumed_once_and_tokens_not_stored(self):
        enrollment = self.call('enrollment', {'name': 'A', 'role': 'primary'})
        body = {'code': enrollment['code'], 'hostname': 'test', 'version': '0.1.0'}
        node = self.call('enroll_agent', body)
        self.error('invalid_enrollment', 'enroll_agent', body)
        with self.control.connect() as db:
            self.assertNotEqual(db.execute('SELECT token_hash FROM nodes').fetchone()[0], node['token'])
            self.assertNotEqual(db.execute('SELECT code_hash FROM enrollments').fetchone()[0], enrollment['code'])
        self.error('primary_exists', 'enrollment', {'name': 'Duplicate', 'role': 'primary'})

    def test_expired_enrollment_refused(self):
        enrollment = self.call('enrollment', {'name': 'A', 'role': 'primary'})
        with self.control.connect() as db:
            db.execute('UPDATE enrollments SET expires=?', (time.time() - 1,))
        self.error('invalid_enrollment', 'enroll_agent', {'code': enrollment['code'], 'hostname': 'test', 'version': '0.1.0'})

    def test_reenrollment_rotates_token_and_refuses_busy_node(self):
        node = self.add()
        enrollment = self.call('enrollment', {}, node['nodeId'])
        replacement = self.call('enroll_agent', {'code': enrollment['code'], 'hostname': 'replacement', 'version': '0.1.0'})
        self.assertEqual(replacement['nodeId'], node['nodeId'])
        self.error('agent_unauthorized', 'sync', {'nodeId': node['nodeId'], 'instanceId': node['instanceId'], 'status': observation(), 'reports': []}, 'Bearer ' + node['token'])
        self.sync(replacement)
        self.job(replacement)
        self.error('node_busy', 'enrollment', {}, node['nodeId'])

    def test_plan_is_not_a_command_shell(self):
        node = self.add()
        self.error('invalid_action', 'plan', {'nodeId': node['nodeId'], 'action': 'sh -c id'})
        self.error('invalid_request', 'plan', {'nodeId': node['nodeId'], 'action': 'backup', 'command': 'id'})
        self.error('invalid_request', 'plan', {'nodeId': node['nodeId'], 'action': 'verify', 'parameters': {'path': '/etc/shadow'}})
        self.error('invalid_schedule', 'plan', {'nodeId': node['nodeId'], 'action': 'set-schedule', 'parameters': {'interval': '* * * * *;id'}})
        self.error('invalid_action', 'plan', {'nodeId': node['nodeId'], 'action': {}})
        self.error('invalid_schedule', 'plan', {'nodeId': node['nodeId'], 'action': 'set-schedule', 'parameters': {'interval': []}})

    def test_restores_select_exact_known_snapshot(self):
        node = self.add()
        for value in ['latest', '../etc/shadow', 'c' * 63, None]:
            self.error('invalid_snapshot', 'plan', {'nodeId': node['nodeId'], 'action': 'restore-check', 'snapshotId': value})
        self.error('snapshot_unavailable', 'plan', {'nodeId': node['nodeId'], 'action': 'restore-check', 'snapshotId': 'c' * 64})
        self.assertEqual(self.call('plan', {'nodeId': node['nodeId'], 'action': 'restore-check', 'snapshotId': SNAP})['snapshotId'], SNAP)

    def test_expired_and_revised_plans_refused(self):
        node = self.add()
        plan = self.call('plan', {'nodeId': node['nodeId'], 'action': 'backup'})
        request = {'planId': plan['id'], 'idempotencyKey': str(uuid.uuid4())}
        with self.control.connect() as db:
            db.execute('UPDATE plans SET expires=? WHERE id=?', (time.time() - 1, plan['id']))
        self.error('plan_expired', 'enqueue', request)
        plan = self.call('plan', {'nodeId': node['nodeId'], 'action': 'backup'})
        self.call('settings', {'profile': 'single', 'backupInterval': 'hourly', 'expectedRevision': plan['revision']})
        self.error('revision_conflict', 'enqueue', {'planId': plan['id'], 'idempotencyKey': str(uuid.uuid4())})

    def test_stale_or_cached_status_refuses_mutations(self):
        node = self.add()
        self.sync(node, status=observation(observedAt=stamp(time.time() - 1000)))
        self.error('node_stale', 'plan', {'nodeId': node['nodeId'], 'action': 'backup'})
        overview = self.call('overview')
        self.assertTrue(overview['nodes'][0]['connected'])
        self.assertIn('service_status_stale', [alert['code'] for alert in overview['alerts']])
        self.sync(node)
        with self.control.connect() as db:
            db.execute('UPDATE nodes SET last_seen=?', (time.time() - 60,))
        self.error('node_stale', 'plan', {'nodeId': node['nodeId'], 'action': 'backup'})

    def test_idempotency_and_plan_aliases_survive_restart(self):
        node = self.add()
        queued, request = self.job(node)
        self.control = Control(self.temp.name, 'https://control.example.test')
        self.assertEqual(self.call('enqueue', request)['job']['id'], queued['id'])
        alias = {'planId': request['planId'], 'idempotencyKey': str(uuid.uuid4())}
        self.assertEqual(self.call('enqueue', alias)['job']['id'], queued['id'])
        other = self.call('plan', {'nodeId': node['nodeId'], 'action': 'verify'})
        for key in [request['idempotencyKey'], alias['idempotencyKey']]:
            self.error('idempotency_conflict', 'enqueue', {'planId': other['id'], 'idempotencyKey': key})
        with self.control.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0], 1)

    def test_lost_dispatch_reply_resends_identical_job(self):
        node = self.add()
        queued, _ = self.job(node)
        first = self.sync(node)['job']
        self.control = Control(self.temp.name, 'https://control.example.test')
        second = self.sync(node)['job']
        self.assertEqual(first, second)
        self.assertEqual(first['id'], queued['id'])

    def test_only_one_node_dispatches_and_wrong_node_cannot_complete(self):
        a, b = self.add(), self.add('recovery', 'B')
        first, _ = self.job(a)
        second, _ = self.job(b, 'verify')
        self.assertNotIn('job', self.sync(b))
        active = self.sync(a)['job']
        forged = {'id': first['id'], 'nonce': active['nonce'], 'status': 'succeeded', 'result': {'snapshot': SNAP}}
        self.error('job_report_forbidden', 'sync', {'nodeId': b['nodeId'], 'instanceId': b['instanceId'], 'status': observation(), 'reports': [forged]}, 'Bearer ' + b['token'])
        self.assertNotIn('job', self.sync(b))
        self.sync(a, [forged])
        self.assertEqual(self.sync(b)['job']['id'], second['id'])

    def test_queued_receipt_quarantines_and_wrong_nonce_is_refused(self):
        node = self.add()
        queued, _ = self.job(node)
        with self.control.connect() as db:
            nonce = db.execute('SELECT nonce FROM jobs').fetchone()[0]
        report = {'id': queued['id'], 'nonce': nonce, 'status': 'running'}
        response = self.sync(node, [report])
        self.assertIn(queued['id'], response['discarded'])
        self.assertNotIn('job', response)
        self.sync(node)
        report['nonce'] = 'incorrect'
        self.error('job_report_forbidden', 'sync', {'nodeId': node['nodeId'], 'instanceId': node['instanceId'], 'status': observation(), 'reports': [report]}, 'Bearer ' + node['token'])

    def test_disconnected_unknown_holds_global_lock_until_reconciled(self):
        a, b = self.add(), self.add('recovery', 'B')
        first, _ = self.job(a)
        self.job(b, 'verify')
        assigned = self.sync(a)['job']
        with self.control.connect() as db:
            db.execute('UPDATE nodes SET last_seen=? WHERE id=?', (time.time() - 100, a['nodeId']))
        overview = self.call('overview')
        self.assertEqual(next(j for j in overview['jobs'] if j['id'] == first['id'])['status'], 'outcome_unknown')
        self.assertNotIn('job', self.sync(b))
        self.sync(a, [{'id': first['id'], 'nonce': assigned['nonce'], 'status': 'succeeded', 'result': {'snapshot': SNAP}}])
        self.assertIn('job', self.sync(b))

    def test_success_requires_actual_proof_and_no_secret_fields(self):
        node = self.add()
        queued, _ = self.job(node, 'restore-check', SNAP)
        job = self.sync(node)['job']
        self.sync(node, [{'id': queued['id'], 'nonce': job['nonce'], 'status': 'succeeded', 'result': {'snapshot': SNAP, 'checks': ['application-http'], 'password': 'private'}}])
        overview = self.call('overview')
        result = next(x for x in overview['jobs'] if x['id'] == queued['id'])
        self.assertEqual((result['status'], result['error']), ('failed', 'result_unverified'))
        self.assertNotIn('private', json.dumps(overview))

    def test_terminal_report_is_idempotent_and_cannot_regress(self):
        node = self.add()
        queued, _ = self.job(node)
        job = self.sync(node)['job']
        done = {'id': queued['id'], 'nonce': job['nonce'], 'status': 'succeeded', 'result': {'snapshot': SNAP}}
        self.sync(node, [done])
        self.sync(node, [done, {'id': queued['id'], 'nonce': job['nonce'], 'status': 'running'}])
        self.assertEqual(self.call('overview')['jobs'][0]['status'], 'succeeded')
        done['status'] = 'failed'
        response = self.sync(node, [done])
        self.assertIn(queued['id'], response['discarded'])
        self.assertEqual(self.call('overview')['jobs'][0]['status'], 'succeeded')

    def test_setup_requires_same_snapshot_and_successful_schedule(self):
        a, b = self.add(), self.add('recovery', 'B')
        self.error('backup_required', 'complete_setup', {})
        self.finish(a)
        self.error('restore_check_required', 'complete_setup', {})
        self.finish(b, 'restore-check', OTHER, {'snapshot': OTHER, 'checks': sorted(CHECKS)})
        self.error('restore_check_required', 'complete_setup', {})
        self.finish(b, 'restore-check', SNAP, {'snapshot': SNAP, 'checks': sorted(CHECKS)})
        self.sync(a, status=observation(schedule={'backup': {'enabled': False, 'interval': 'hourly'}}))
        self.error('schedule_required', 'complete_setup', {})
        self.sync(a)
        self.assertEqual(self.call('complete_setup', {}), {'completed': True})

    def test_setup_rejects_old_backup_even_after_fresh_restore(self):
        a, b = self.add(), self.add('recovery', 'B')
        self.finish(a)
        self.finish(b, 'restore-check', SNAP, {'snapshot': SNAP, 'checks': sorted(CHECKS)})
        with self.control.connect() as db:
            db.execute("UPDATE jobs SET ended=? WHERE action='backup'", (time.time() - 7200,))
        self.error('backup_required', 'complete_setup', {})

    def test_status_fields_are_whitelisted(self):
        value = observation(secret='hidden', privateKey='hidden', snapshots=[{'id': SNAP, 'time': stamp(), 'password': 'hidden'}, {'id': '../secret', 'time': stamp()}], lastBackup={'snapshot': SNAP, 'at': stamp(), 'password': 'hidden'}, preview={'id': str(uuid.uuid4()), 'snapshot': SNAP, 'root': '/private/path'})
        out = sanitize_status(value)
        self.assertEqual(len(out['snapshots']), 1)
        self.assertNotIn('hidden', json.dumps(out))
        self.assertNotIn('/private', json.dumps(out))

    def test_enrollment_cancellation_and_bounded_attempts(self):
        item = self.call('enrollment', {'name': 'A', 'role': 'primary'})
        self.assertEqual(self.call('cancel_enrollment', item['id'], {}), {'cancelled': True})
        self.error('invalid_enrollment', 'enroll_agent', {'code': item['code'], 'hostname': 'test', 'version': '0.1.0'})
        for _ in range(9):
            self.error('invalid_enrollment', 'enroll_agent', {'code': 'x' * 43, 'hostname': 'test', 'version': '0.1.0'})
        self.error('enrollment_rate_limited', 'enroll_agent', {'code': 'x' * 43, 'hostname': 'test', 'version': '0.1.0'})
        public = self.call('overview')['enrollments'][0]
        self.assertEqual(public['status'], 'cancelled')
        self.assertNotIn('code', public)

    def test_revoke_requires_no_pending_work_and_replacement_clears_revoked(self):
        node = self.add()
        job, _ = self.job(node)
        self.error('node_busy', 'revoke_node', node['nodeId'], {})
        result = self.call('cancel_job', job['id'], {})
        self.assertEqual(result['job']['error'], 'cancelled_before_dispatch')
        self.assertEqual(self.call('revoke_node', node['nodeId'], {}), {'revoked': True})
        self.error('agent_unauthorized', 'sync', {'nodeId': node['nodeId'], 'instanceId': node['instanceId'], 'status': observation(), 'reports': []}, 'Bearer ' + node['token'])
        self.assertTrue(self.call('overview')['nodes'][0]['revoked'])
        replacement_code = self.call('enrollment', {}, node['nodeId'])
        self.assertIn('--replace-enrollment', replacement_code['command'])
        replacement = self.call('enroll_agent', {'code': replacement_code['code'], 'hostname': 'new', 'version': '0.1.0'})
        self.assertEqual(replacement['role'], 'primary')
        self.sync(replacement)
        self.assertFalse(self.call('overview')['nodes'][0]['revoked'])

    def test_queued_work_is_revalidated_at_dispatch(self):
        node = self.add()
        queued, _ = self.job(node)
        self.call('enrollment', {'name': 'B', 'role': 'recovery'})
        self.assertNotIn('job', self.sync(node))
        result = next(x for x in self.call('overview')['jobs'] if x['id'] == queued['id'])
        self.assertEqual((result['status'], result['error']), ('failed', 'revision_conflict'))
        queued, _ = self.job(node)
        with self.control.connect() as db:
            db.execute('UPDATE plans SET expires=? WHERE id=(SELECT plan_id FROM jobs WHERE id=?)', (time.time() - 1, queued['id']))
        self.assertNotIn('job', self.sync(node))
        self.assertEqual(self.call('overview')['jobs'][0]['error'], 'plan_expired')

    def test_active_assignment_survives_catalog_revision_without_new_identity(self):
        node = self.add()
        self.job(node)
        first = self.sync(node)['job']
        self.call('enrollment', {'name': 'B', 'role': 'recovery'})
        second = self.sync(node)['job']
        self.assertEqual(first, second)
        self.error('job_not_cancellable', 'cancel_job', first['id'], {})

    def test_unknown_requires_explicit_reconciliation_and_never_plain_dispatch(self):
        a, b = self.add(), self.add('recovery', 'B')
        queued, _ = self.job(a)
        assigned = self.sync(a)['job']
        self.job(b, 'verify')
        with self.control.connect() as db:
            db.execute('UPDATE nodes SET last_seen=? WHERE id=?', (time.time() - 100, a['nodeId']))
        self.call('overview')
        self.assertNotIn('job', self.sync(a))
        self.assertNotIn('job', self.sync(b))
        result = self.call('reconcile_job', queued['id'], {})
        self.assertEqual(result['job']['status'], 'outcome_unknown')
        self.control = Control(self.temp.name, 'https://control.example.test')
        reconciliation = self.sync(a)['job']
        self.assertTrue(reconciliation['reconcile'])
        for key in ['id', 'nonce', 'action', 'snapshotId', 'parameters']:
            self.assertEqual(reconciliation[key], assigned[key])
        self.sync(a, [{'id': assigned['id'], 'nonce': assigned['nonce'], 'status': 'running'}])
        self.assertEqual(self.call('overview')['jobs'][-1]['status'], 'outcome_unknown')
        self.sync(a, [{'id': assigned['id'], 'nonce': assigned['nonce'], 'status': 'succeeded', 'result': {'snapshot': SNAP}}])
        self.assertIn('job', self.sync(b))

    def test_rejected_success_receipt_is_acknowledged_after_lost_reply(self):
        node = self.add()
        self.job(node, 'verify')
        assigned = self.sync(node)['job']
        bad = {'id': assigned['id'], 'nonce': assigned['nonce'], 'status': 'succeeded', 'result': {}}
        self.sync(node, [bad])
        response = self.sync(node, [bad])
        self.assertIn(assigned['id'], response['acknowledged'])
        self.assertEqual(self.call('overview')['jobs'][0]['status'], 'failed')

    def test_future_schedule_preserved_while_future_observation_rejected(self):
        observed = sanitize_status(observation(observedAt=stamp(time.time() + 7200), schedule={'backup': {'enabled': True, 'interval': 'hourly', 'next': stamp(time.time() + 7200)}}))
        self.assertNotIn('observedAt', observed)
        self.assertIn('next', observed['schedule']['backup'])

    def test_repeated_unknown_receipt_does_not_consume_reconciliation_request(self):
        node = self.add()
        queued, _ = self.job(node)
        assigned = self.sync(node)['job']
        unknown = {'id': assigned['id'], 'nonce': assigned['nonce'], 'status': 'outcome_unknown', 'error': 'agent_restarted'}
        self.sync(node, [unknown])
        self.call('reconcile_job', queued['id'], {})
        self.control = Control(self.temp.name, 'https://control.example.test')
        for _ in range(3):
            response = self.sync(node, [unknown])
            self.assertTrue(response['job']['reconcile'])
            self.assertEqual(response['job']['id'], assigned['id'])
            self.assertEqual(response['job']['nonce'], assigned['nonce'])
        terminal = {**unknown, 'status': 'succeeded', 'result': {'snapshot': SNAP}}
        response = self.sync(node, [terminal])
        self.assertNotIn('job', response)
        self.assertFalse(self.call('overview')['jobs'][0].get('reconcileRequested', False))

    def test_running_identity_not_redispatched_after_receipt_loss(self):
        node = self.add()
        self.job(node)
        assigned = self.sync(node)['job']
        self.sync(node, [{'id': assigned['id'], 'nonce': assigned['nonce'], 'status': 'running'}])
        self.assertNotIn('job', self.sync(node))
        self.control = Control(self.temp.name, 'https://control.example.test')
        self.assertNotIn('job', self.sync(node))
        result = self.call('overview')['jobs'][0]
        self.assertEqual((result['status'], result['error']), ('outcome_unknown', 'agent_receipt_missing'))
        self.call('reconcile_job', assigned['id'], {})
        reconciliation = self.sync(node)['job']
        self.assertTrue(reconciliation['reconcile'])
        self.assertEqual(reconciliation['id'], assigned['id'])
        self.assertEqual(reconciliation['nonce'], assigned['nonce'])

    def test_terminal_orphan_acknowledged_without_accepting_proof(self):
        node = self.add()
        orphan = {'id': str(uuid.uuid4()), 'nonce': 'n' * 43, 'status': 'succeeded', 'result': {'snapshot': SNAP, 'password': 'secret-value'}}
        result = self.sync(node, [orphan])
        self.assertIn(orphan['id'], result['acknowledged'])
        self.assertIn(orphan['id'], result['discarded'])
        overview = self.call('overview')
        self.assertTrue(overview['nodes'][0]['connected'])
        self.assertEqual(overview['jobs'], [])
        self.assertEqual(overview['orphanReports'][0]['status'], 'succeeded')
        self.assertNotIn('secret-value', json.dumps(overview))
        self.assertNotIn('nonce', overview['orphanReports'][0])
        self.assertNotIn('result', overview['orphanReports'][0])
        self.error('nodes_required', 'complete_setup', {})

    def test_orphan_receipt_does_not_abort_known_receipt_in_same_sync(self):
        node = self.add()
        self.job(node)
        assigned = self.sync(node)['job']
        orphan = {'id': str(uuid.uuid4()), 'nonce': 'n' * 43, 'status': 'failed'}
        known = {'id': assigned['id'], 'nonce': assigned['nonce'], 'status': 'succeeded', 'result': {'snapshot': SNAP}}
        response = self.sync(node, [orphan, known])
        self.assertEqual(set(response['acknowledged']), {orphan['id'], assigned['id']})
        self.assertEqual(self.call('overview')['jobs'][0]['status'], 'succeeded')

    def test_quarantine_holds_unacknowledged_dispatch_until_orphan_settles(self):
        a, b = self.add(), self.add('recovery', 'B')
        self.job(b, 'verify')
        assigned = self.sync(b)['job']
        orphan = {'id': str(uuid.uuid4()), 'nonce': 'n' * 43, 'status': 'outcome_unknown'}
        self.sync(a, [orphan])
        self.assertNotIn('job', self.sync(b))
        self.sync(a, [{**orphan, 'status': 'failed'}])
        self.assertEqual(self.sync(b)['job'], assigned)

    def test_unknown_orphan_allows_heartbeat_but_blocks_global_mutations(self):
        a, b = self.add(), self.add('recovery', 'B')
        orphan = {'id': str(uuid.uuid4()), 'nonce': 'n' * 43, 'status': 'outcome_unknown'}
        response = self.sync(a, [orphan])
        self.assertIn(orphan['id'], response['acknowledged'])
        self.job(b, 'verify')
        self.assertNotIn('job', self.sync(b))
        self.error('node_busy', 'revoke_node', a['nodeId'], {})
        self.error('node_busy', 'enrollment', {}, a['nodeId'])
        overview = self.call('overview')
        self.assertTrue(next(node for node in overview['nodes'] if node['id'] == a['nodeId'])['connected'])
        self.assertIn('catalog_receipt_orphaned', [alert['code'] for alert in overview['alerts']])
        self.control = Control(self.temp.name, 'https://control.example.test')
        self.assertNotIn('job', self.sync(b))
        # Another authenticated node cannot clear the first node's quarantine.
        self.sync(b, [{**orphan, 'status': 'failed'}])
        self.assertNotIn('job', self.sync(b))
        self.sync(a, [{**orphan, 'status': 'failed'}])
        self.assertIn('job', self.sync(b))
        self.assertEqual(len(self.call('overview')['jobs']), 1)

    def test_invalid_unicode_nonce_and_password_are_stable_errors(self):
        node = self.add()
        self.job(node)
        assigned = self.sync(node)['job']
        bad = {'id': assigned['id'], 'nonce': '\u00e9' * 43, 'status': 'running'}
        self.error('job_report_forbidden', 'sync', {'nodeId': node['nodeId'], 'instanceId': node['instanceId'], 'status': observation(), 'reports': [bad]}, 'Bearer ' + node['token'])
        self.error('invalid_request', 'login', {'password': '\ud800abc'}, 'test-client')
        self.error('invalid_request', 'enrollment', {'name': '\ud800abc', 'role': 'recovery'})

    def test_initial_password_deleted_only_after_successful_change(self):
        path = Path(self.temp.name) / 'admin-password'
        initial = path.read_text().strip()
        self.call('login', {'password': initial}, 'test')
        self.assertTrue(path.is_file())
        self.error('password_unchanged', 'change_password', {'currentPassword': initial, 'newPassword': initial})
        self.assertTrue(path.is_file())
        self.call('change_password', {'currentPassword': initial, 'newPassword': 'a-new-password-for-recovery-123'})
        self.assertFalse(path.exists())
        self.control = Control(self.temp.name, 'https://control.example.test')
        self.assertFalse(path.exists())
        result, _ = self.call('login', {'password': 'a-new-password-for-recovery-123'}, 'test')
        self.assertFalse(result['needsPasswordChange'])

    def test_origin_rejects_unit_injection_and_invalid_hosts_before_writing(self):
        path = Path(self.temp.name) / 'rejected-origin'
        invalid = ['https://example.test\nExecStartPre=/bin/false', 'https://é.example', 'https://example.test\x00', 'https://bad..example', 'https://-bad.example', 'https://example.test:0', 'https://example.test:99999', 'https://example.test:notaport', 'https://example.test:', 'https://example.test;bad', 'https://[fe80::1%eth0]']
        for origin in invalid:
            with self.subTest(origin=origin):
                with self.assertRaises(ValueError):
                    Control(path, origin)
                self.assertFalse(path.exists())
        for index, origin in enumerate(['https://example.test', 'https://127.0.0.1:8443', 'https://[2001:db8::1]:8443']):
            Control(Path(self.temp.name) / str(index), origin)

    def test_incarnation_is_required_and_prevents_dispatched_replay(self):
        node = self.add()
        self.error('invalid_request', 'sync', {'nodeId': node['nodeId'], 'status': observation(), 'reports': []}, 'Bearer ' + node['token'])
        self.error('invalid_instance', 'sync', {'nodeId': node['nodeId'], 'instanceId': 'invalid', 'status': observation(), 'reports': []}, 'Bearer ' + node['token'])
        self.job(node)
        assigned = self.sync(node)['job']
        replacement = {**node, 'instanceId': str(uuid.uuid4())}
        self.assertNotIn('job', self.sync(replacement))
        job = self.call('overview')['jobs'][0]
        self.assertEqual((job['status'], job['error']), ('outcome_unknown', 'agent_instance_changed'))
        self.control = Control(self.temp.name, 'https://control.example.test')
        self.assertNotIn('job', self.sync(replacement))
        self.call('reconcile_job', assigned['id'], {})
        inspection = self.sync(replacement)['job']
        self.assertTrue(inspection['reconcile'])
        self.assertEqual(inspection['nonce'], assigned['nonce'])
        self.sync(replacement, [{'id': assigned['id'], 'nonce': assigned['nonce'], 'status': 'succeeded', 'result': {'snapshot': SNAP}}])
        self.assertEqual(self.call('overview')['jobs'][0]['status'], 'succeeded')

    def test_incarnation_change_invalidates_older_queued_work(self):
        node = self.add()
        queued, _ = self.job(node)
        replacement = {**node, 'instanceId': str(uuid.uuid4())}
        self.assertNotIn('job', self.sync(replacement))
        job = self.call('overview')['jobs'][0]
        self.assertEqual((job['status'], job['error']), ('failed', 'agent_instance_changed'))
        self.assertEqual(job['id'], queued['id'])

    def test_missing_catalog_orphan_can_be_inspected_without_job_authority(self):
        node = self.add()
        orphan = {'id': str(uuid.uuid4()), 'nonce': 'n' * 43, 'status': 'outcome_unknown'}
        self.sync(node, [orphan])
        result = self.call('inspect_orphan', node['nodeId'], orphan['id'], {})
        self.assertTrue(result['inspectionRequested'])
        response = self.sync(node, [orphan])
        self.assertIn(orphan['id'], response['inspectOrphans'])
        self.assertNotIn(orphan['id'], response['inspectionNonces'])
        self.assertNotIn('job', response)
        self.sync(node, [{**orphan, 'status': 'failed', 'inspected': True}])
        self.assertEqual(self.call('overview')['jobs'], [])
        self.assertEqual(self.call('overview')['orphanReports'][0]['status'], 'failed')
        self.error('orphan_already_resolved', 'inspect_orphan', node['nodeId'], orphan['id'], {})

    def test_known_queued_wrongstate_requires_inspection_and_never_replays(self):
        node = self.add()
        queued, _ = self.job(node)
        with self.control.connect() as db:
            nonce = db.execute('SELECT nonce FROM jobs WHERE id=?', (queued['id'],)).fetchone()[0]
        receipt = {'id': queued['id'], 'nonce': nonce, 'status': 'succeeded', 'result': {'snapshot': SNAP}}
        self.assertNotIn('job', self.sync(node, [receipt]))
        self.assertTrue(self.call('overview')['nodes'][0]['connected'])
        self.assertEqual(self.call('overview')['jobs'][0]['error'], 'catalog_delivery_state_lost')
        self.call('inspect_orphan', node['nodeId'], queued['id'], {})
        duplicate = self.sync(node, [receipt])
        self.assertEqual(duplicate['inspectionNonces'][queued['id']], nonce)
        self.assertEqual(self.call('overview')['jobs'][0]['status'], 'outcome_unknown')
        self.sync(node, [{**receipt, 'status': 'failed', 'inspected': True}])
        job = self.call('overview')['jobs'][0]
        self.assertEqual((job['status'], job['error']), ('failed', 'catalog_delivery_state_lost'))
        self.assertNotIn('result', job)
        self.assertNotIn('job', self.sync(node, [receipt]))

    def test_conflicting_terminal_inspection_preserves_catalog_truth(self):
        node = self.add()
        queued, _ = self.job(node)
        with self.control.connect() as db:
            nonce = db.execute('SELECT nonce FROM jobs WHERE id=?', (queued['id'],)).fetchone()[0]
        self.call('cancel_job', queued['id'], {})
        receipt = {'id': queued['id'], 'nonce': nonce, 'status': 'succeeded', 'result': {'snapshot': SNAP}}
        self.assertNotIn('job', self.sync(node, [receipt]))
        self.assertEqual(self.call('overview')['jobs'][0]['error'], 'cancelled_before_dispatch')
        self.call('inspect_orphan', node['nodeId'], queued['id'], {})
        self.sync(node, [{**receipt, 'inspected': True}])
        job = self.call('overview')['jobs'][0]
        self.assertEqual((job['status'], job['error']), ('failed', 'cancelled_before_dispatch'))
        self.assertEqual(self.call('overview')['orphanReports'][0]['status'], 'succeeded')

    def test_orphan_bound_and_overflow_need_owner_requested_host_inspection(self):
        node = self.add()
        receipts = [{'id': str(uuid.uuid4()), 'nonce': 'n' * 43, 'status': 'outcome_unknown'} for _ in range(400)]
        for start in range(0, 400, 100):
            self.sync(node, receipts[start:start + 100])
        with self.control.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM orphan_reports WHERE node_id=?', (node['nodeId'],)).fetchone()[0], 128)
        self.assertTrue(self.call('overview')['nodes'][0]['orphanOverflow'])
        self.sync(node, orphanInventoryComplete=True)
        self.assertTrue(self.call('overview')['nodes'][0]['orphanOverflow'])
        retained = self.call('overview')['orphanReports']
        for item in retained[:20]:
            self.call('inspect_orphan', node['nodeId'], item['id'], {})
        response = self.sync(node)
        self.assertLessEqual(len(response['inspectOrphans']), 16)
        self.assertTrue(response['inspectOverflow'])
        next_response = self.sync(node)
        self.assertEqual(len(set(response['inspectOrphans']) | set(next_response['inspectOrphans'])), 20)
        for start in range(0, len(retained), 100):
            terminal = [{'id': item['id'], 'nonce': 'n' * 43, 'status': 'failed', 'inspected': True} for item in retained[start:start + 100]]
            self.sync(node, terminal, orphanInventoryComplete=True)
        self.assertFalse(self.call('overview')['nodes'][0]['orphanOverflow'])
        self.assertFalse(any(item['status'] in {'running', 'outcome_unknown'} for item in self.call('overview')['orphanReports']))
        self.job(node)
        self.assertIn('job', self.sync(node))

    def test_inventory_request_recovers_overflow_with_only_terminal_rows(self):
        node = self.add()
        receipts = [{'id': str(uuid.uuid4()), 'nonce': 'n' * 43, 'status': 'outcome_unknown'} for _ in range(200)]
        for start in range(0, 200, 100):
            self.sync(node, receipts[start:start + 100])
        retained = self.call('overview')['orphanReports']
        for start in range(0, len(retained), 100):
            self.sync(node, [{'id': item['id'], 'nonce': 'n' * 43, 'status': 'failed'} for item in retained[start:start + 100]])
        overview = self.call('overview')
        self.assertTrue(overview['nodes'][0]['orphanOverflow'])
        self.assertTrue(all(item['status'] == 'failed' for item in overview['orphanReports']))
        queued, _ = self.job(node)
        self.assertNotIn('job', self.sync(node))
        expected = {'inspectionRequested': True, 'scope': 'inventory'}
        self.assertEqual(self.call('inspect_orphan_inventory', node['nodeId'], {}), expected)
        self.assertEqual(self.call('inspect_orphan_inventory', node['nodeId'], {}), expected)
        self.control = Control(self.temp.name, 'https://control.example.test')
        pending = self.sync(node)
        self.assertTrue(pending['inspectOverflow'])
        self.assertNotIn('job', pending)
        completed = self.sync(node, orphanInventoryComplete=True)
        self.assertEqual(completed['job']['id'], queued['id'])
        self.assertFalse(self.call('overview')['nodes'][0]['orphanOverflow'])
        self.assertEqual(self.call('inspect_orphan_inventory', node['nodeId'], {}), {'inspectionRequested': False, 'scope': 'inventory'})

    def test_inventory_request_requires_fresh_node(self):
        node = self.add()
        self.sync(node, status=observation(observedAt=stamp(time.time() - 1000)))
        self.error('node_stale', 'inspect_orphan_inventory', node['nodeId'], {})
        self.sync(node)
        with self.control.connect() as db:
            db.execute('UPDATE nodes SET last_seen=? WHERE id=?', (time.time() - 100, node['nodeId']))
        self.error('node_stale', 'inspect_orphan_inventory', node['nodeId'], {})


class HTTPCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        web = Path(self.temp.name) / 'web'
        web.mkdir()
        (web / 'index.html').write_text('<!doctype html><title>Control</title>')
        (web / 'app.js').write_text('console.log("ok")')
        (web / 'private.env').write_text('password=hidden')
        self.control = Control(self.temp.name, 'https://control.example.test', web_dir=web)
        self.server = ControlHTTPServer(('127.0.0.1', 0), handler_for(self.control))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.cookie, self.csrf = '', ''

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp.cleanup()

    def request(self, method, path, body=None, headers=None):
        request_headers = {'Origin': self.control.origin}
        if self.cookie:
            request_headers['Cookie'] = self.cookie
        if self.csrf:
            request_headers['X-CSRF-Token'] = self.csrf
        payload = None
        if body is not None:
            payload = json.dumps(body)
            request_headers['Content-Type'] = 'application/json'
        if headers:
            request_headers.update(headers)
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        conn.request(method, path, body=payload, headers=request_headers)
        response = conn.getresponse()
        content = response.read()
        result = (response.status, dict(response.getheaders()), json.loads(content) if content and response.getheader('Content-Type').startswith('application/json') else content)
        conn.close()
        return result

    def login(self, change=True):
        password = (Path(self.temp.name) / 'admin-password').read_text().strip()
        status, headers, body = self.request('POST', '/ops/api/login', {'password': password})
        self.assertEqual(status, 200)
        self.cookie, self.csrf = headers['Set-Cookie'].split(';')[0], body['csrf']
        if change:
            status, headers, body = self.request('POST', '/ops/api/password', {'currentPassword': password, 'newPassword': 'a-new-test-password-123456'})
            self.assertEqual(status, 200)
            self.cookie, self.csrf = headers['Set-Cookie'].split(';')[0], body['csrf']
        return headers

    def test_private_data_require_login_static_shell_is_public(self):
        status, headers, _ = self.request('GET', '/ops/')
        self.assertEqual(status, 200)
        self.assertIn("style-src 'self'", headers['Content-Security-Policy'])
        self.assertNotIn("'unsafe-inline'", headers['Content-Security-Policy'])
        self.assertEqual(self.request('GET', '/ops/app.js')[0], 200)
        self.assertEqual(self.request('GET', '/ops/api/session')[2]['authenticated'], False)
        for path in ['/ops/api/overview', '/ops/api/jobs/' + str(uuid.uuid4())]:
            self.assertEqual(self.request('GET', path)[0], 401)
        for path in ['/ops/private.env', '/ops/../admin-password', '/ops/%2e%2e/admin-password', '/controller.py', '/ops/control.sqlite3']:
            self.assertEqual(self.request('GET', path)[0], 404)

    def test_login_cookie_and_password_rotation_revoke_old_session(self):
        headers = self.login(change=False)
        for flag in ['HttpOnly', 'Secure', 'SameSite=Strict', 'Path=/']:
            self.assertIn(flag, headers['Set-Cookie'])
        old_cookie = self.cookie
        password = (Path(self.temp.name) / 'admin-password').read_text().strip()
        status, headers, body = self.request('POST', '/ops/api/password', {'currentPassword': password, 'newPassword': 'second-test-password-123456'})
        self.assertEqual(status, 200)
        self.assertFalse(body['needsPasswordChange'])
        self.assertFalse(self.request('GET', '/ops/api/session', headers={'Cookie': old_cookie})[2]['authenticated'])

    def test_initial_password_must_change_before_mutation(self):
        self.login(change=False)
        self.assertEqual(self.request('GET', '/ops/api/overview')[2]['error'], 'password_change_required')
        self.assertEqual(self.request('POST', '/ops/api/enrollments', {'name': 'A', 'role': 'primary'})[2]['error'], 'password_change_required')

    def test_same_initial_password_cannot_unlock_private_data(self):
        self.login(change=False)
        initial = (Path(self.temp.name) / 'admin-password').read_text().strip()
        original_cookie = self.cookie
        status, headers, body = self.request('POST', '/ops/api/password', {'currentPassword': initial, 'newPassword': initial})
        self.assertEqual((status, body['error']), (400, 'password_unchanged'))
        self.assertNotIn('Set-Cookie', headers)
        session = self.request('GET', '/ops/api/session')[2]
        self.assertTrue(session['authenticated'])
        self.assertTrue(session['needsPasswordChange'])
        self.assertEqual(self.cookie, original_cookie)
        self.assertEqual(self.request('GET', '/ops/api/overview')[0], 403)
        self.assertEqual(self.request('POST', '/ops/api/enrollments', {'name': 'A', 'role': 'primary'})[0], 403)

    def test_csrf_and_origin_enforced(self):
        self.login()
        body = {'name': 'A', 'role': 'primary'}
        self.assertEqual(self.request('POST', '/ops/api/enrollments', body, {'X-CSRF-Token': ''})[2]['error'], 'csrf_forbidden')
        self.assertEqual(self.request('POST', '/ops/api/enrollments', body, {'Origin': 'https://evil.example'})[2]['error'], 'origin_forbidden')
        self.assertEqual(self.request('POST', '/ops/api/enrollments', body)[0], 200)

    def test_nonascii_csrf_and_surrogate_password_are_stable_client_errors(self):
        self.login()
        status, _, body = self.request('POST', '/ops/api/enrollments', {'name': 'A', 'role': 'primary'}, {'X-CSRF-Token': '\u00e9'})
        self.assertEqual((status, body['error']), (403, 'csrf_forbidden'))
        status, _, body = self.request('POST', '/ops/api/login', {'password': '\ud800abc'})
        self.assertEqual((status, body['error']), (400, 'invalid_request'))
        status, _, body = self.request('POST', '/ops/api/password', {'currentPassword': 'a-new-test-password-123456', 'newPassword': '\ud800' + 'a' * 32})
        self.assertEqual((status, body['error']), (400, 'invalid_password'))

    def test_orphan_inspection_http_requires_owner_csrf_and_returns_no_mutation(self):
        self.login()
        _, _, enrollment = self.request('POST', '/ops/api/enrollments', {'name': 'A', 'role': 'primary'})
        _, _, node = self.request('POST', '/ops/agent/enroll', {'code': enrollment['code'], 'hostname': 'test', 'version': '0.1.0'})
        identity = str(uuid.uuid4())
        receipt = {'id': str(uuid.uuid4()), 'nonce': 'n' * 43, 'status': 'outcome_unknown'}
        body = {'nodeId': node['nodeId'], 'instanceId': identity, 'status': observation(), 'reports': [receipt]}
        status, _, _ = self.request('POST', '/ops/agent/sync', body, {'Authorization': 'Bearer ' + node['token']})
        self.assertEqual(status, 200)
        path = '/ops/api/nodes/' + node['nodeId'] + '/orphans/' + receipt['id'] + '/reconcile'
        self.assertEqual(self.request('POST', path, {}, {'X-CSRF-Token': ''})[0], 403)
        self.assertEqual(self.request('POST', path, {})[2], {'inspectionRequested': True, 'id': receipt['id']})
        status, _, result = self.request('POST', '/ops/agent/sync', body, {'Authorization': 'Bearer ' + node['token']})
        self.assertEqual(status, 200)
        self.assertEqual(result['inspectOrphans'], [receipt['id']])
        self.assertNotIn('job', result)

    def test_inventory_inspection_http_path_requires_owner_csrf(self):
        self.login()
        _, _, enrollment = self.request('POST', '/ops/api/enrollments', {'name': 'A', 'role': 'primary'})
        _, _, node = self.request('POST', '/ops/agent/enroll', {'code': enrollment['code'], 'hostname': 'test', 'version': '0.1.0'})
        body = {'nodeId': node['nodeId'], 'instanceId': str(uuid.uuid4()), 'status': observation(), 'reports': []}
        self.request('POST', '/ops/agent/sync', body, {'Authorization': 'Bearer ' + node['token']})
        with self.control.connect() as db:
            db.execute('UPDATE nodes SET orphan_overflow=1 WHERE id=?', (node['nodeId'],))
        path = '/ops/api/nodes/' + node['nodeId'] + '/orphans/reconcile'
        self.assertEqual(self.request('POST', path, {}, {'Cookie': ''})[0], 401)
        self.assertEqual(self.request('POST', path, {}, {'X-CSRF-Token': ''})[0], 403)
        self.assertEqual(self.request('POST', path, {})[2], {'inspectionRequested': True, 'scope': 'inventory'})
        _, _, response = self.request('POST', '/ops/agent/sync', body, {'Authorization': 'Bearer ' + node['token']})
        self.assertTrue(response['inspectOverflow'])
        self.assertNotIn('job', response)

    def test_login_origin_and_rate_limit(self):
        self.assertEqual(self.request('POST', '/ops/api/login', {'password': 'wrong'}, {'Origin': 'https://evil.example'})[0], 403)
        for _ in range(5):
            self.assertEqual(self.request('POST', '/ops/api/login', {'password': 'wrong'})[0], 401)
        self.assertEqual(self.request('POST', '/ops/api/login', {'password': 'wrong'})[0], 429)

    def test_unexpected_fields_and_methods_rejected(self):
        self.login()
        self.assertEqual(self.request('POST', '/ops/api/enrollments', {'name': 'A', 'role': 'primary', 'command': 'id'})[0], 400)
        self.assertEqual(self.request('GET', '/ops/api/overview?token=bad')[0], 400)
        self.assertEqual(self.request('DELETE', '/ops/api/overview')[0], 405)

    def test_session_and_queue_survive_controller_reconstruction(self):
        self.login()
        previous = self.control
        self.control = Control(self.temp.name, 'https://control.example.test', web_dir=previous.web_dir)
        self.server.RequestHandlerClass = handler_for(self.control)
        self.assertTrue(self.request('GET', '/ops/api/session')[2]['authenticated'])
        self.assertEqual(self.request('GET', '/ops/api/overview')[0], 200)

    def test_json_size_and_content_type_enforced(self):
        self.assertEqual(self.request('POST', '/ops/api/login', {'password': 'x'}, {'Content-Type': 'text/plain'})[0], 415)
        self.assertEqual(self.request('POST', '/ops/api/login', {'password': 'x' * 262144})[0], 413)

    def test_concurrent_handler_limit_does_not_block_existing_requests(self):
        for _ in range(32):
            self.assertTrue(self.server.request_slots.acquire(blocking=False))
        try:
            self.assertEqual(self.request('GET', '/ops/api/session')[0], 503)
        finally:
            for _ in range(32):
                self.server.request_slots.release()
        self.assertEqual(self.request('GET', '/ops/api/session')[0], 200)


if __name__ == '__main__':
    unittest.main()
