"""Allocation/API fault controls: pure fake API and monotonic clock, no network."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import os
import signal

import run_macos_actions_validation as subject

SHA = 'a' * 40


class Clock:
    def __init__(self): self.value = 0
    def now(self): return self.value
    def sleep(self, seconds): self.value += seconds


class FakeAPI:
    def __init__(self, plans):
        self.plans = plans; self.calls = []; self.runs = {}; self.cancelled = []; self.posts = 0
    def request(self, method, path, body=None):
        self.calls.append((method, path, copy.deepcopy(body)))
        if path.endswith('/dispatches'):
            self.posts += 1
            plan = copy.deepcopy(self.plans[self.posts - 1])
            if plan.get('deny'): raise subject.Failure(plan['deny'])
            run_id = self.posts
            self.runs[run_id] = {'plan': plan, 'body': body, 'cursor': 0, 'last': None}
            if plan.get('post_timeout'): raise subject.Failure('api_unavailable')
            return (204, None) if plan.get('legacy') else (200, {'workflow_run_id': run_id})
        if '/actions/workflows/' in path and '/runs?' in path:
            return 200, {'workflow_runs': [self.metadata(i, r, 'queued') for i, r in self.runs.items()]}
        if '/check-runs/' in path:
            run_id = int(path.split('/check-runs/')[1].split('/')[0])
            message = self.runs[run_id]['plan'].get('annotation', subject.ACQUISITION_FAILURE)
            return 200, [{'annotation_level': 'failure', 'message': message}]
        run_id = int(path.split('/actions/runs/')[1].split('/')[0]); record = self.runs[run_id]
        if path.endswith('/cancel'):
            self.cancelled.append(run_id)
            conflict = record['plan'].get('cancel_conflict')
            record['plan']['states'] = [{'status': 'completed',
                'conclusion': 'failure' if conflict else 'cancelled',
                'started': record['plan'].get('cancel_race', False) or conflict == 'actual_test'}]
            record['cursor'] = 0
            if conflict in ('409_acquisition', 'actual_test'): raise subject.Failure('api_http_409')
            return 202, None
        if '/jobs?' in path:
            state = record['last']; plan = record['plan']
            if plan.get('no_jobs'): return 200, {'jobs': []}
            guard = {'name': subject.ADMISSION_JOB, 'status': 'completed', 'conclusion': 'success'}
            if plan.get('no_mac'): return 200, {'jobs': [guard]}
            started = state.get('started', state['status'] == 'in_progress' or state.get('conclusion') == 'success')
            steps = [{'name': name, 'status': 'completed', 'conclusion': 'success'} for name in subject.REQUIRED_STEPS] if started else []
            if plan.get('missing_proof') and steps: steps.pop()
            if plan.get('failed_step') and steps: steps[-1]['conclusion'] = 'failure'
            mac = {'id': run_id, 'name': subject.MAC_JOB, 'status': state['status'],
                   'check_run_url': 'https://api.github.com' + subject.BASE + '/check-runs/' + str(run_id),
                   'conclusion': state.get('conclusion'), 'runner_id': 100 if started else 0,
                   'runner_name': 'owned hosted' if started else '', 'steps': steps,
                   'labels': [record['body']['inputs']['runner']]}
            return 200, {'jobs': [guard, mac]}
        states = record['plan']['states']; index = min(record['cursor'], len(states) - 1)
        state = states[index]; record['last'] = state; record['cursor'] += 1
        return 200, self.metadata(run_id, record, state['status'], state.get('conclusion'))
    def metadata(self, run_id, record, status, conclusion=None):
        v = record['body']['inputs']; title = 'macos-validation ' + '.'.join((v['parent_run_id'], v['parent_run_attempt'], v['request_id'])) + ' ' + v['runner']
        result = {'id': run_id, 'head_branch': 'main', 'head_sha': 'b'*40 if record['plan'].get('wrong_source') else SHA,
                'event': 'workflow_dispatch', 'path': subject.WORKFLOW_PATH, 'display_title': title,
                'repository': {'full_name': subject.REPOSITORY}, 'run_attempt': 1,
                'status': 'completed' if status == 'completed' else 'in_progress', 'conclusion': conclusion}
        sequence = record['plan'].get('identity_sequence', [{}])
        index = min(record.get('metadata_reads', 0), len(sequence)-1)
        result.update(sequence[index]); record['metadata_reads'] = record.get('metadata_reads', 0) + 1
        return result


def success(): return {'states': [{'status': 'completed', 'conclusion': 'success'}]}
def unavailable(): return {'states': [{'status': 'completed', 'conclusion': 'failure', 'started': False}]}


class Allocation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name)/'result.json'; self.clock = Clock(); self.count = 0
    def controller(self, plans, **kwargs):
        self.api = FakeAPI(plans)
        def nonce(): self.count += 1; return f'{self.count:032x}'
        return subject.Controller(self.api, SHA, '900', '2', self.output, now=self.clock.now,
            sleep=self.clock.sleep, nonce=nonce, queue_seconds=3, poll_seconds=1,
            active_seconds=5, overall_seconds=25, **kwargs)
    def test_only_actual_worker_and_all_critical_steps_qualify(self):
        result = self.controller([success()]).execute()
        self.assertTrue(result['success']); self.assertEqual(result['qualified_runner'], 'macos-15')
        self.assertEqual(self.api.posts, 1)
        self.assertEqual(self.api.calls[0][2]['ref'], 'main')
        self.assertEqual(self.api.calls[0][2]['inputs']['expected_sha'], SHA)
    def test_zero_step_acquisition_failure_falls_back_and_keeps_history(self):
        result = self.controller([unavailable(), success()]).execute()
        self.assertTrue(result['success']); self.assertEqual(self.api.posts, 2)
        self.assertEqual(result['attempts'][0]['allocation_result'], 'hosted_runner_acquisition_failed')
        self.assertNotEqual(result['attempts'][0]['request_id'], result['attempts'][1]['request_id'])
    def test_initial_transient_metadata_must_all_match_before_any_jobs_lookup(self):
        plan = success(); plan['identity_sequence'] = [{'display_title':'macOS validation worker'}, {'run_attempt':None}, {}]
        result = self.controller([plan]).execute()
        self.assertTrue(result['success']); self.assertEqual(self.api.cancelled, [])
        first_jobs = next(i for i,(_,p,_) in enumerate(self.api.calls) if '/jobs?' in p)
        self.assertEqual(sum('/actions/runs/' in p and '/jobs?' not in p for _,p,_ in self.api.calls[:first_jobs]),3)
        observations = result['attempts'][0]['identity_observations']
        self.assertEqual(set(observations[0]['mismatches']), {'display_title'})
        self.assertEqual(set(observations[1]['mismatches']), {'run_attempt'})
    def test_permanent_source_nonce_or_path_mismatch_never_inspects_jobs_or_cancels(self):
        for override in [{'head_sha':'b'*40}, {'display_title':'foreign nonce'}, {'path':'.github/workflows/foreign.yml'}]:
            plan = success(); plan['identity_sequence'] = [override]
            c = self.controller([plan])
            with self.assertRaisesRegex(subject.Failure, 'child_identity_mismatch'): c.execute()
            self.assertEqual(self.api.cancelled, [])
            self.assertFalse(any('/jobs?' in p for _,p,_ in self.api.calls))
            self.assertFalse(c.report['success'])
    def test_binding_is_strict_immediately_after_first_verified_snapshot(self):
        plan = {'states':[{'status':'in_progress'}], 'identity_sequence':[{}, {'head_sha':'b'*40}]}
        c = self.controller([plan])
        with self.assertRaisesRegex(subject.Failure, 'child_identity_mismatch'): c.execute()
        self.assertEqual(self.clock.value, 1)
        self.assertEqual(sum('/jobs?' in p for _,p,_ in self.api.calls),1)
        self.assertEqual(self.api.cancelled, [])
    def test_initial_identity_wait_is_bounded_by_30_seconds(self):
        plan = success(); plan['identity_sequence'] = [{'run_attempt':None}]
        c = self.controller([plan]); c.deadline = 100
        with self.assertRaisesRegex(subject.Failure, 'child_identity_mismatch'): c.execute()
        self.assertLessEqual(self.clock.value, 30)
        self.assertFalse(any('/jobs?' in p for _,p,_ in self.api.calls))
        self.assertEqual(self.api.cancelled, [])
    def test_queue_deadline_cancels_only_the_bound_own_pending_run(self):
        result = self.controller([{'states': [{'status': 'queued'}]}, success()]).execute()
        self.assertTrue(result['success']); self.assertEqual(self.api.cancelled, [1])
    def test_started_worker_is_not_cancelled_by_queue_deadline(self):
        result = self.controller([{'states': [{'status': 'in_progress'}, {'status': 'completed', 'conclusion': 'success'}]}]).execute()
        self.assertTrue(result['success']); self.assertEqual(self.api.cancelled, [])
    def test_actual_failure_is_fatal_not_retried_on_another_pool(self):
        c = self.controller([{'states': [{'status': 'completed', 'conclusion': 'failure', 'started': True}], 'failed_step': True}])
        with self.assertRaisesRegex(subject.Failure, 'actual_worker_failed'): c.execute()
        self.assertEqual(self.api.posts, 1); self.assertFalse(c.report['success'])
    def test_billing_or_nonallocation_error_is_not_treated_as_capacity(self):
        plan = unavailable(); plan['annotation'] = 'Payment or spending limit error'
        with self.assertRaisesRegex(subject.Failure, 'actual_worker_failed'): self.controller([plan]).execute()
        self.assertEqual(self.api.posts, 1)
    def test_green_run_without_proof_step_is_rejected(self):
        plan = success(); plan['missing_proof'] = True
        with self.assertRaisesRegex(subject.Failure, 'actual_worker_failed'): self.controller([plan]).execute()
    def test_foreign_source_cannot_be_cancelled_or_accepted(self):
        plan = {'states': [{'status': 'queued'}], 'wrong_source': True}
        with self.assertRaisesRegex(subject.Failure, 'child_identity_mismatch'): self.controller([plan]).execute()
        self.assertEqual(self.api.cancelled, [])
    def test_admission_without_mac_job_has_finite_deadline_and_cleanup(self):
        c = self.controller([{'states': [{'status': 'queued'}], 'no_mac': True}])
        with self.assertRaisesRegex(subject.Failure, 'admission_unavailable'): c.execute()
        self.assertEqual(self.api.posts, 1); self.assertEqual(self.api.cancelled, [1])
        self.assertEqual(c.report['attempts'][0]['abort_cleanup'], 'owned_child_terminal_after_abort')
    def test_permission_failure_stops_without_fallback(self):
        with self.assertRaisesRegex(subject.Failure, 'api_http_403'): self.controller([{'deny': 'api_http_403'}]).execute()
        self.assertEqual(self.api.posts, 1)
    def test_assignment_race_during_cancel_never_becomes_a_pass_or_retry(self):
        c = self.controller([{'states': [{'status': 'queued'}], 'cancel_race': True}])
        with self.assertRaisesRegex(subject.Failure, 'runner_assignment_during_cancel'): c.execute()
        self.assertEqual(self.api.posts, 1); self.assertFalse(c.report['success'])
    def test_platform_acquisition_failure_winning_cancel202_is_still_infrastructure(self):
        result = self.controller([{'states':[{'status':'queued'}], 'cancel_conflict':'202_acquisition'}, success()]).execute()
        self.assertTrue(result['success']); self.assertEqual(self.api.posts, 2)
        self.assertEqual(result['attempts'][0]['allocation_result'], 'hosted_runner_acquisition_failed_during_cancel')
    def test_cancel409_requires_fresh_exact_acquisition_failure_proof(self):
        result = self.controller([{'states':[{'status':'queued'}], 'cancel_conflict':'409_acquisition'}, success()]).execute()
        self.assertTrue(result['success']); self.assertEqual(self.api.posts, 2)
        self.assertEqual(result['attempts'][0]['allocation_result'], 'hosted_runner_acquisition_failed_before_cancel')
    def test_cancel409_with_actual_test_failure_cannot_fall_back(self):
        c = self.controller([{'states':[{'status':'queued'}], 'cancel_conflict':'actual_test'}])
        with self.assertRaisesRegex(subject.Failure, 'queue_cancel_conflict_not_proven'): c.execute()
        self.assertEqual(self.api.posts, 1); self.assertFalse(c.report['success'])
    def test_all_pools_unavailable_is_explicit_failure(self):
        c = self.controller([unavailable() for _ in subject.RUNNERS])
        with self.assertRaisesRegex(subject.Failure, 'all_hosted_mac_pools_unavailable'): c.execute()
        self.assertEqual(self.api.posts, len(subject.RUNNERS)); self.assertFalse(c.report['success'])
    def test_legacy204_is_discovered_by_nonce_without_second_post(self):
        plan = success(); plan['legacy'] = True
        self.assertTrue(self.controller([plan]).execute()['success']); self.assertEqual(self.api.posts, 1)
    def test_ambiguous_post_timeout_binds_existing_nonce_without_duplicate(self):
        plan = success(); plan['post_timeout'] = True
        self.assertTrue(self.controller([plan]).execute()['success']); self.assertEqual(self.api.posts, 1)
    def test_running_worker_has_its_own_finite_deadline(self):
        c = self.controller([{'states': [{'status': 'in_progress'}]}])
        with self.assertRaisesRegex(subject.Failure, 'active_worker_deadline'): c.execute()
        self.assertEqual(self.api.cancelled, [1]); self.assertEqual(self.api.posts, 1)
    def test_overall_bound_covers_admission_queue(self):
        c = self.controller([{'states': [{'status': 'queued'}], 'no_jobs': True}])
        c.deadline = 2
        with self.assertRaisesRegex(subject.Failure, 'overall_deadline'): c.execute()
        self.assertEqual(self.api.cancelled, [1])
    def test_malformed_job_payload_fails_and_cleans_exact_pending_child(self):
        c = self.controller([{'states': [{'status': 'queued'}]}]); original = self.api.request
        first = True
        def request(method, path, body=None):
            nonlocal first
            if '/jobs?' in path and first:
                first = False; return 200, None
            return original(method, path, body)
        self.api.request = request
        with self.assertRaisesRegex(subject.Failure, 'malformed_api_response'): c.execute()
        self.assertEqual(self.api.cancelled, [1]); self.assertFalse(c.report['success'])
    def test_SIGINT_uses_the_same_bounded_pending_child_cleanup(self):
        c = self.controller([{'states': [{'status': 'queued'}]}]); original = self.api.request
        handlers = {}; fired = False
        def request(method, path, body=None):
            nonlocal fired
            if method == 'GET' and '/actions/runs/' in path and not fired:
                fired = True; handlers[signal.SIGINT](signal.SIGINT, None)
            return original(method, path, body)
        self.api.request = request
        env = {'GITHUB_ACTIONS':'true','GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_REF':'refs/heads/main',
               'GITHUB_REPOSITORY':subject.REPOSITORY,'GH_TOKEN':'inert-test-token','GITHUB_SHA':SHA,
               'GITHUB_RUN_ID':'900','GITHUB_RUN_ATTEMPT':'2'}
        with patch.dict(os.environ, env), patch.object(subject, 'API', return_value=self.api), \
                patch.object(subject, 'Controller', return_value=c), \
                patch.object(subject.signal, 'signal', side_effect=lambda number, handler: handlers.update({number:handler})), \
                patch('sys.argv', ['controller','--output',str(self.output)]):
            self.assertEqual(subject.main(), 1)
        self.assertIs(handlers[signal.SIGINT], handlers[signal.SIGTERM])
        self.assertEqual(self.api.cancelled, [1]); self.assertEqual(self.api.posts, 1)
    def test_SIGINT_during_dispatch_recovers_only_its_nonce_without_redispatch(self):
        c = self.controller([{'states': [{'status': 'queued'}]}]); original = self.api.request
        handlers = {}; fired = False
        def request(method, path, body=None):
            nonlocal fired
            value = original(method, path, body)
            if method == 'POST' and path.endswith('/dispatches') and not fired:
                fired = True; handlers[signal.SIGINT](signal.SIGINT, None)
            return value
        self.api.request = request
        env = {'GITHUB_ACTIONS':'true','GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_REF':'refs/heads/main',
               'GITHUB_REPOSITORY':subject.REPOSITORY,'GH_TOKEN':'inert-test-token','GITHUB_SHA':SHA,
               'GITHUB_RUN_ID':'900','GITHUB_RUN_ATTEMPT':'2'}
        with patch.dict(os.environ, env), patch.object(subject, 'API', return_value=self.api), \
                patch.object(subject, 'Controller', return_value=c), \
                patch.object(subject.signal, 'signal', side_effect=lambda number, handler: handlers.update({number:handler})), \
                patch('sys.argv', ['controller','--output',str(self.output)]):
            self.assertEqual(subject.main(), 1)
        self.assertEqual(self.api.cancelled, [1]); self.assertEqual(self.api.posts, 1)
        self.assertEqual(c.report['attempts'][0]['run_id'], 1)
    def test_unidentified_abort_records_unknown_without_foreign_cancellation(self):
        for match in ['absent', 'foreign']:
            c = self.controller([{'states': [{'status': 'queued'}], 'wrong_source': match == 'foreign'}])
            body = {'inputs': {'runner': subject.RUNNERS[0], 'expected_sha': SHA, 'request_id':'1'*32,
                              'parent_run_id':'900','parent_run_attempt':'2'}}
            self.api.request('POST', subject.BASE+'/actions/workflows/'+subject.WORKFLOW+'/dispatches', body)
            c.report['attempts'] = [{'runner':subject.RUNNERS[0], 'request_id':'1'*32,
                'title':'macos-validation 900.2.'+'1'*32+' '+subject.RUNNERS[0], 'dispatch_may_exist':True}]
            if match == 'absent': self.api.runs = {}
            c.abort_cleanup()
            row = c.report['attempts'][0]
            self.assertEqual(row['abort_cleanup'], 'untracked_dispatch_outcome_unknown')
            self.assertEqual(self.api.cancelled, []); self.assertEqual(self.api.posts, 1)
            self.assertEqual(sum('/actions/workflows/' in p and '/runs?' in p for _,p,_ in self.api.calls),1)


class Workflow(unittest.TestCase):
    def test_scopes_and_real_worker_gates_remain_present(self):
        root = Path(__file__).resolve().parents[1]
        parent = (root/'.github/workflows/macos-validation.yml').read_text()
        worker = (root/'.github/workflows/macos-validation-worker.yml').read_text()
        self.assertIn('actions: write', parent); self.assertNotIn('actions: write', worker)
        self.assertIn('checks: read', parent); self.assertNotIn('checks: read', worker)
        self.assertIn('run: exec python3 tool/run_macos_actions_validation.py', parent)
        self.assertNotIn('macos-validation-main', worker)
        for text in [parent, worker]:
            self.assertIn('refs/heads/main', text); self.assertIn('persist-credentials: false', text)
            self.assertNotIn('pull_request:', text); self.assertNotIn('self-hosted', text)
        for runner in subject.RUNNERS: self.assertIn(runner, worker)
        self.assertNotIn('-large', worker)
        for name in subject.REQUIRED_STEPS: self.assertIn('name: ' + name, worker)
        self.assertIn('--platform macos --verify-installed', worker)
        self.assertIn('if-no-files-found: error', worker)
        self.assertNotIn('simctl', worker)


if __name__ == '__main__': unittest.main()
