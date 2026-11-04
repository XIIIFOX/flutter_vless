#!/usr/bin/env python3
"""Bounded main-only macOS allocation fallback; never retry a started test failure.

Only standard hosted pools are used. Queue admission is not a promise of
capacity: exhausting every pool is a failing infrastructure result, not a pass.
The Actions token is used solely against this repository's Actions REST API.
"""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

REPOSITORY = 'XIIIFOX/flutter_vless'
WORKFLOW = 'macos-validation-worker.yml'
WORKFLOW_PATH = '.github/workflows/' + WORKFLOW
RUNNERS = ('macos-15', 'macos-26-intel', 'macos-26', 'macos-15-intel')
MAC_JOB = 'macOS published runtime'
ADMISSION_JOB = 'Validate main request'
REQUIRED_STEPS = ('Verify exact main source', 'Test macOS host and DNS lifecycle',
                  'Build macOS example', 'Test macOS published runtime',
                  'Test shipped HEV packets', 'Qualify macOS acceptance evidence')
ACQUISITION_FAILURE = 'The job was not acquired by Runner of type hosted even after multiple attempts'
BASE = '/repos/' + REPOSITORY


class Failure(RuntimeError):
    def __init__(self, kind):
        self.kind = kind
        super().__init__(kind)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Failure('unexpected_api_redirect')


class API:
    def __init__(self, token):
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect)
        self.timeout = 20

    def request(self, method, path, body=None):
        if not path.startswith(BASE + '/') or '\n' in path or not path.isascii():
            raise Failure('foreign_api_path')
        request = urllib.request.Request('https://api.github.com' + path,
            data=None if body is None else json.dumps(body).encode(), method=method,
            headers={'Authorization': 'Bearer ' + self.token, 'Accept': 'application/vnd.github+json',
                     'X-GitHub-Api-Version': '2026-03-10', 'Content-Type': 'application/json'})
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                data = response.read(8 * 1024 * 1024 + 1)
                if len(data) > 8 * 1024 * 1024: raise Failure('oversized_api_response')
                try:
                    return response.status, json.loads(data) if data else None
                except (ValueError, UnicodeDecodeError):
                    raise Failure('api_response_invalid') from None
        except urllib.error.HTTPError as error:
            # Never print response bodies, authorization headers or token values.
            raise Failure('api_http_' + str(error.code)) from None
        except (urllib.error.URLError, TimeoutError):
            raise Failure('api_unavailable') from None


class Controller:
    def __init__(self, api, sha, parent, attempt, output, now=time.monotonic,
                 sleep=time.sleep, nonce=lambda: uuid.uuid4().hex,
                 queue_seconds=900, active_seconds=2700, poll_seconds=10, overall_seconds=6300,
                 first_runner=None):
        if re.fullmatch(r'[0-9a-f]{40}', sha) is None or not str(parent).isdigit() or int(parent) < 1 \
                or not str(attempt).isdigit() or int(attempt) < 1:
            raise Failure('invalid_parent_identity')
        if first_runner is not None and first_runner not in RUNNERS:
            raise Failure('invalid_runner_preference')
        self.runners = RUNNERS if first_runner is None else (first_runner,) + tuple(r for r in RUNNERS if r != first_runner)
        self.api, self.sha, self.parent, self.attempt = api, sha, str(parent), str(attempt)
        self.output, self.now, self.sleep, self.nonce = Path(output), now, sleep, nonce
        self.queue_seconds, self.active_seconds, self.poll_seconds = queue_seconds, active_seconds, poll_seconds
        self.deadline = self.now() + overall_seconds
        self.report = {'success': False, 'repository': REPOSITORY, 'source_sha': sha,
                       'ref': 'main', 'parent_run_id': self.parent, 'parent_run_attempt': self.attempt,
                       'attempts': [], 'private_user_profiles': False, 'runtime_source': 'published'}

    def save(self):
        self.output.parent.mkdir(parents=True, exist_ok=True)
        self.output.write_text(json.dumps(self.report, indent=2) + '\n')

    def call(self, method, path, body=None):
        if self.now() >= self.deadline: raise Failure('overall_deadline')
        status, value = self.api.request(method, path, body)
        return status, value

    def identity(self, run, row):
        if run.get('id') != row['run_id'] or run.get('head_branch') != 'main' \
                or run.get('head_sha') != self.sha or run.get('event') != 'workflow_dispatch' \
                or run.get('path') != WORKFLOW_PATH or run.get('display_title') != row['title'] \
                or run.get('repository', {}).get('full_name') != REPOSITORY \
                or run.get('run_attempt') != 1:
            raise Failure('child_identity_mismatch')

    def record_identity_difference(self, run, row, elapsed):
        """Persist only the generated/public identity fields, never API bodies."""
        expected = {'id': row['run_id'], 'head_branch': 'main', 'head_sha': self.sha,
                    'event': 'workflow_dispatch', 'path': WORKFLOW_PATH, 'display_title': row['title'],
                    'repository': REPOSITORY, 'run_attempt': 1}
        repository = run.get('repository')
        actual = {name: run.get(name) for name in expected}
        actual['repository'] = repository.get('full_name') if isinstance(repository, dict) else None
        def safe(value):
            if isinstance(value, str): return value[:200]
            if value is None or type(value) in (int, bool): return value
            return '<' + type(value).__name__ + '>'
        difference = {name: {'expected': safe(value), 'actual': safe(actual[name])}
                      for name, value in expected.items() if actual[name] != value}
        history = row.setdefault('identity_observations', [])
        if history and history[-1]['mismatches'] == difference:
            history[-1]['last_elapsed_seconds'] = round(elapsed, 3)
        elif len(history) < 8:
            history.append({'elapsed_seconds': round(elapsed, 3), 'mismatches': difference})
        else:
            row['additional_identity_observations'] = row.get('additional_identity_observations', 0) + 1
        self.save()

    def read_bound_run(self, row):
        """Allow initial API metadata evaluation to settle, with every fence intact.

        Before all fields agree this performs only GET of the already returned
        run ID. After the first binding, later reads are strict immediately.
        """
        began = self.now()
        end = min(self.deadline, began + 30)
        observed_mismatch = False
        while True:
            if observed_mismatch and self.now() >= end: raise Failure('child_identity_mismatch')
            previous_timeout = getattr(self.api, 'timeout', 20)
            self.api.timeout = min(previous_timeout, max(.1, end - self.now()))
            try:
                _, run = self.call('GET', BASE + '/actions/runs/' + str(row['run_id']))
            finally:
                self.api.timeout = previous_timeout
            try:
                self.identity(run, row)
            except Failure:
                self.record_identity_difference(run, row, self.now() - began)
                if row.get('identity_verified') or self.now() >= end: raise
                observed_mismatch = True
                self.sleep(min(2, self.poll_seconds, end - self.now()))
                continue
            if self.now() > end: raise Failure('child_identity_mismatch')
            row['identity_verified'] = True
            self.save()
            return run

    def snapshot(self, row):
        run = self.read_bound_run(row)
        _, value = self.call('GET', BASE + '/actions/runs/' + str(row['run_id']) + '/jobs?filter=latest&per_page=100')
        jobs = value.get('jobs', [])
        if any(j.get('name') not in (MAC_JOB, ADMISSION_JOB) for j in jobs) \
                or len({j.get('name') for j in jobs}) != len(jobs):
            raise Failure('unexpected_worker_jobs')
        admission = next((j for j in jobs if j.get('name') == ADMISSION_JOB), None)
        mac = next((j for j in jobs if j.get('name') == MAC_JOB), None)
        if admission and admission.get('status') == 'completed' and admission.get('conclusion') != 'success':
            raise Failure('worker_admission_failed')
        if mac and mac.get('labels') != [row['runner']]: raise Failure('worker_runner_mismatch')
        row.update(run_status=run.get('status'), run_conclusion=run.get('conclusion'),
                   mac_status=mac.get('status') if mac else None,
                   mac_conclusion=mac.get('conclusion') if mac else None)
        self.save()
        return run, admission, mac

    @staticmethod
    def unassigned(mac):
        return mac and mac.get('status') == 'queued' and not mac.get('runner_id') \
            and not mac.get('runner_name') and not mac.get('steps')

    @staticmethod
    def started(mac):
        return mac and (mac.get('status') == 'in_progress' or bool(mac.get('runner_id'))
                        or bool(mac.get('runner_name')) or bool(mac.get('steps')))

    def acquisition_failure(self, mac):
        if not mac or self.started(mac) or mac.get('status') != 'completed': return False
        url = mac.get('check_run_url', '')
        pattern = r'https://api\.github\.com' + re.escape(BASE) + r'/check-runs/([1-9][0-9]*)'
        match = re.fullmatch(pattern, url)
        if not match: raise Failure('worker_check_identity_missing')
        _, annotations = self.call('GET', BASE + '/check-runs/' + match[1] + '/annotations?per_page=100')
        failures = [a.get('message', '') for a in annotations if a.get('annotation_level') == 'failure']
        return bool(failures) and all(message == ACQUISITION_FAILURE for message in failures)

    def successful(self, run, admission, mac):
        if run.get('conclusion') != 'success' or not admission or admission.get('conclusion') != 'success' \
                or not mac or mac.get('conclusion') != 'success' or not self.started(mac):
            return False
        steps = mac.get('steps', [])
        return all(sum(s.get('name') == name and s.get('status') == 'completed' \
                       and s.get('conclusion') == 'success' for s in steps) == 1 for name in REQUIRED_STEPS)

    def discover(self, row):
        end = self.now() + 45
        query = urllib.parse.urlencode({'event': 'workflow_dispatch', 'branch': 'main',
                                       'head_sha': self.sha, 'per_page': 100})
        while self.now() < end:
            _, value = self.call('GET', BASE + '/actions/workflows/' + WORKFLOW + '/runs?' + query)
            matches = [r for r in value.get('workflow_runs', []) if r.get('display_title') == row['title']]
            if len(matches) > 1: raise Failure('ambiguous_dispatch')
            if matches:
                row['run_id'] = matches[0]['id']; self.read_bound_run(row); return
            self.sleep(self.poll_seconds)
        raise Failure('dispatch_untracked_no_redispatch')

    def cancel_queued(self, row):
        # There is no conditional-cancel REST operation. Recheck immediately,
        # then record any runner-assignment race without claiming a test pass.
        run, admission, mac = self.snapshot(row)
        if not self.unassigned(mac): return False
        if not admission or admission.get('conclusion') != 'success': raise Failure('admission_unavailable')
        try:
            status, _ = self.call('POST', BASE + '/actions/runs/' + str(row['run_id']) + '/cancel')
        except Failure as error:
            if error.kind != 'api_http_409': raise
            run, admission, mac = self.snapshot(row)
            if run.get('status') == 'completed' and self.acquisition_failure(mac):
                row['allocation_result'] = 'hosted_runner_acquisition_failed_before_cancel'
                self.save(); return True
            raise Failure('queue_cancel_conflict_not_proven_infrastructure') from None
        if status != 202: raise Failure('queue_cancel_not_acknowledged')
        end = self.now() + 60
        while self.now() < end:
            run, admission, mac = self.snapshot(row)
            if self.started(mac): raise Failure('runner_assignment_during_cancel')
            if run.get('status') == 'completed':
                if run.get('conclusion') != 'cancelled':
                    if self.acquisition_failure(mac):
                        row['allocation_result'] = 'hosted_runner_acquisition_failed_during_cancel'
                        self.save(); return True
                    raise Failure('queue_cancel_conclusion_changed')
                row['allocation_result'] = 'queue_deadline_cancelled_without_mac_steps'; self.save(); return True
            self.sleep(self.poll_seconds)
        raise Failure('queue_cancel_not_terminal')

    def abort_cleanup(self):
        """Do not strand a known own pending child after an API/admission error.

        Parent abort differs from queue fallback: it cancels even an active
        exact-owned child, without retrying its tests. The short cleanup budget
        is best effort; a force-kill or unavailable API may prevent its ACK.
        """
        if not self.report['attempts']: return
        row = self.report['attempts'][-1]
        if 'run_id' not in row and not row.get('dispatch_may_exist'): return
        previous = self.deadline
        self.deadline = self.now() + 8
        previous_timeout = getattr(self.api, 'timeout', 20)
        self.api.timeout = 2
        try:
            if 'run_id' not in row:
                row['abort_cleanup'] = 'untracked_dispatch_outcome_unknown'
                query = urllib.parse.urlencode({'event': 'workflow_dispatch', 'branch': 'main',
                                               'head_sha': self.sha, 'per_page': 100})
                _, value = self.call('GET', BASE + '/actions/workflows/' + WORKFLOW + '/runs?' + query)
                matches = [r for r in value.get('workflow_runs', []) if r.get('display_title') == row['title']]
                if len(matches) != 1:
                    row['abort_cleanup'] = 'untracked_dispatch_outcome_unknown'; return
                row['run_id'] = matches[0]['id']
                self.identity(matches[0], row)
            _, run = self.call('GET', BASE + '/actions/runs/' + str(row['run_id']))
            self.identity(run, row)
            if run.get('status') == 'completed':
                row['abort_cleanup'] = 'already_terminal'
            else:
                status, _ = self.call('POST', BASE + '/actions/runs/' + str(row['run_id']) + '/cancel')
                if status != 202: raise Failure('abort_cancel_not_acknowledged')
                row['abort_cancel_requested'] = True
                while self.now() < self.deadline:
                    _, run = self.call('GET', BASE + '/actions/runs/' + str(row['run_id']))
                    self.identity(run, row)
                    if run.get('status') == 'completed':
                        row['abort_cleanup'] = 'owned_child_terminal_after_abort'; break
                    self.sleep(min(1, self.poll_seconds))
                else: raise Failure('abort_cancel_not_terminal')
        except (Failure, ValueError, KeyError, TypeError, AttributeError) as error:
            row['abort_cleanup_error'] = error.kind if isinstance(error, Failure) else 'malformed_api_response'
        finally:
            self.deadline = previous
            self.api.timeout = previous_timeout
            self.save()

    def execute(self):
        try:
            for runner in self.runners:
                nonce = self.nonce()
                if re.fullmatch(r'[0-9a-f]{32}', nonce) is None: raise Failure('invalid_nonce')
                title = 'macos-validation ' + '.'.join((self.parent, self.attempt, nonce)) + ' ' + runner
                row = {'runner': runner, 'request_id': nonce, 'title': title}
                self.report['attempts'].append(row); self.save()
                body = {'ref': 'main', 'return_run_details': True,
                        'inputs': {'runner': runner, 'expected_sha': self.sha, 'request_id': nonce,
                                   'parent_run_id': self.parent, 'parent_run_attempt': self.attempt}}
                row['dispatch_may_exist'] = True
                try:
                    status, value = self.call('POST', BASE + '/actions/workflows/' + WORKFLOW + '/dispatches', body)
                except Failure as error:
                    if error.kind.startswith('api_http_4'):
                        row['dispatch_may_exist'] = False
                    if error.kind not in ('api_unavailable', 'api_response_invalid', 'oversized_api_response') \
                            and not error.kind.startswith('api_http_5'): raise
                    # A timed-out POST may have succeeded. Find this nonce;
                    # never dispatch a replacement until its outcome is known.
                    row['dispatch_response_ambiguous'] = True
                    self.discover(row)
                    status, value = 200, {'workflow_run_id': row['run_id']}
                if status == 200 and isinstance(value, dict) and type(value.get('workflow_run_id')) is int:
                    row['run_id'] = value['workflow_run_id']
                    if row['run_id'] < 1: raise Failure('dispatch_run_id_invalid')
                elif status == 204:
                    # One dispatch only: correlate the nonce, never repeat POST.
                    self.discover(row)
                else: raise Failure('dispatch_response_invalid')
                queued_until = self.now() + self.queue_seconds
                active_until = None
                while True:
                    run, admission, mac = self.snapshot(row)
                    if run.get('status') == 'completed':
                        if self.successful(run, admission, mac):
                            row['allocation_result'] = 'actual_mac_validation_passed'
                            self.report.update(success=True, qualified_child_run_id=row['run_id'], qualified_runner=runner)
                            self.save(); return self.report
                        if self.acquisition_failure(mac):
                            row['allocation_result'] = 'hosted_runner_acquisition_failed'; self.save(); break
                        raise Failure('actual_worker_failed_or_incomplete')
                    if self.started(mac):
                        if active_until is None: active_until = self.now() + self.active_seconds
                        if self.now() >= active_until: raise Failure('active_worker_deadline')
                    elif self.now() >= queued_until:
                        if not mac or not admission or admission.get('conclusion') != 'success':
                            raise Failure('admission_unavailable')
                        if self.cancel_queued(row): break
                    self.sleep(self.poll_seconds)
            raise Failure('all_hosted_mac_pools_unavailable')
        except Failure as error:
            self.report['failure_kind'] = error.kind
            self.abort_cleanup()
            self.save()
            raise
        except (ValueError, KeyError, TypeError, AttributeError):
            self.report['failure_kind'] = 'malformed_api_response'
            self.abort_cleanup()
            self.save()
            raise Failure('malformed_api_response') from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('build/macos-actions-dispatch/result.json'))
    args = parser.parse_args()
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch' \
            or os.environ.get('GITHUB_REF') != 'refs/heads/main' or os.environ.get('GITHUB_REPOSITORY') != REPOSITORY:
        parser.error('Only the trusted main workflow_dispatch may allocate hosted Mac workers')
    token = os.environ.get('GH_TOKEN')
    if not token: parser.error('Actions token is required; no personal token fallback')
    controller = Controller(API(token), os.environ.get('GITHUB_SHA', ''), os.environ.get('GITHUB_RUN_ID', ''),
                            os.environ.get('GITHUB_RUN_ATTEMPT', ''), args.output,
                            first_runner=os.environ.get('MACOS_FIRST_RUNNER') or None)
    def cancelled(_signum, _frame):
        raise Failure('parent_cancelled')
    signal.signal(signal.SIGTERM, cancelled)
    signal.signal(signal.SIGINT, cancelled)
    try:
        report = controller.execute()
    except Failure as error:
        print('MACOS_ACTIONS_VALIDATION_FAILED=' + error.kind, flush=True)
        return 1
    print('MACOS_ACTIONS_VALIDATION_PASS=' + str(report['qualified_child_run_id']), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
