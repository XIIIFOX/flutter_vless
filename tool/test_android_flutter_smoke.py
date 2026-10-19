#!/usr/bin/env python3
"""Bounded private smoke evidence; one genuine pre-entry DDS retry only."""
import argparse
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time

from capture_android_emulator_failure import capture

ROOT = Path(__file__).resolve().parents[1]
DDS_FAILURE = 'Failed to start Dart Development Service'
TEST_ENTRY = 'ANDROID_XRAY_SMOKE_TEST_ENTRY'
MAX_CONTEXT_BYTES = 64 * 1024
MAX_LOG_BYTES = 8 * 1024 * 1024
# Prior successful cold builds took about225s. Ten minutes bounds build+three
# tiny tests while leaving over30min of the unchanged45min job for native tests.
SMOKE_TIMEOUT = 600
EXAMPLE_PACKAGE = 'com.example.flutter_vless_example'


def write_private(path, value):
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0)
    with os.fdopen(os.open(path, flags, 0o600), 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(value.encode('utf-8') if isinstance(value, str) else value)


class Markers:
    patterns = {'dds': DDS_FAILURE.encode(), 'entry': TEST_ENTRY.encode(),
                'core_version': b'ANDROID_XRAY_CORE_VERSION=',
                'gradle': b'Running Gradle task', 'install': b'Installing build/',
                'install_completed': b'', 'vm_service': b'',
                'summary3': b'3 tests passed.', 'standard_summary3': b'+3: All tests passed!'}

    def __init__(self):
        self.found = dict.fromkeys(self.patterns, False)
        self.tail = b''
        self.line = b''
        self.line_overflow = False

    def _line(self, value):
        if value is None:  # An overlong line cannot become a tail-only success.
            self.found['summary3'] = self.found['standard_summary3'] = False
            return
        value = re.sub(rb'\x1b\[[0-?]*[ -/]*[@-~]', b'', value).strip()
        if not value or value == b'::endgroup::':
            return
        if re.fullmatch(rb'Installing build/[^\r\n]{1,2048}\.apk\.\.\. +[0-9,]+(?:\.[0-9]+)?(?:ms|s)', value):
            self.found['install_completed'] = True
        if b'Dart VM Service on ' in value or b'Dart VM service is listening on ' in value:
            self.found['vm_service'] = True
        self.found['summary3'] = value == '🎉 3 tests passed.'.encode()
        self.found['standard_summary3'] = re.fullmatch(
            rb'(?:[0-9]{1,2}:[0-9]{2}(?::[0-9]{2})? +)?\+3: All tests passed!', value) is not None

    def feed(self, chunk):
        text = self.tail + chunk
        for name, marker in self.patterns.items():
            if name not in ('summary3', 'standard_summary3', 'install_completed', 'vm_service'):
                self.found[name] |= marker in text
        self.tail = text[-max(map(len, self.patterns.values())):]
        # Terminal success is a complete exact line, not a quoted substring or
        # an earlier +3 progress/summary followed by another meaningful line.
        for fragment in chunk.splitlines(keepends=True):
            if not self.line_overflow and len(self.line) + len(fragment) <= 4096:
                self.line += fragment
            else:
                self.line = b''; self.line_overflow = True
            if fragment.endswith((b'\n', b'\r')):
                self._line(None if self.line_overflow else self.line)
                self.line = b''; self.line_overflow = False

    def finish(self):
        if self.line or self.line_overflow:
            self._line(None if self.line_overflow else self.line)
            self.line = b''; self.line_overflow = False

    def stage(self):
        for marker, stage in [('core_version', 'core_reported'), ('entry', 'test_entered'),
                              ('install_completed', 'installed_awaiting_test_entry'),
                              ('install', 'installing'), ('gradle', 'building')]:
            if self.found[marker]:
                return stage
        return 'tool_startup'


def qualified(markers):
    return (markers['entry'] and markers['core_version'] and
            (markers['summary3'] or markers['standard_summary3']))


class Cancellation:
    def __init__(self):
        self.signum = None

    def receive(self, signum, _frame):
        if self.signum is None:
            self.signum = signum


@contextmanager
def cancellation_handlers(state):
    old = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        for number in old:
            signal.signal(number, state.receive)
        yield
    finally:
        for number, handler in old.items():
            signal.signal(number, handler)


def _signal_group(pid, number):
    try:
        os.killpg(pid, number)
    except ProcessLookupError:
        pass


def _cleanup_group(process):
    """The new-session PGID belongs to this attempt; never target shared daemons."""
    result = {'leader_reaped': False, 'pipe_closed': False, 'error': None}
    try:
        _signal_group(process.pid, signal.SIGTERM)
        time.sleep(0.2)  # Bounded graceful opportunity, including descendants.
    except (OSError, KeyboardInterrupt) as error:
        result['error'] = type(error).__name__
    finally:
        # One shared bound covers interruptible KILL delivery and leader reap.
        deadline = time.monotonic() + 1
        try:
            while time.monotonic() < deadline:
                try:
                    _signal_group(process.pid, signal.SIGKILL)
                    break
                except KeyboardInterrupt:
                    result['error'] = 'KeyboardInterrupt'
                except OSError as error:
                    result['error'] = type(error).__name__
                    break
            while not result['leader_reaped'] and time.monotonic() < deadline:
                try:
                    process.wait(timeout=max(0.001, deadline - time.monotonic()))
                    result['leader_reaped'] = True
                except KeyboardInterrupt:
                    continue # Keep the same reap bound; an interrupt cannot skip cleanup.
                except (subprocess.TimeoutExpired, OSError) as error:
                    result['error'] = type(error).__name__
                    break
        finally:
            # Even a reap/delivery error must close our pipe descriptor.
            try:
                process.stdout.close()
                result['pipe_closed'] = True
            except (OSError, KeyboardInterrupt) as error:
                result['error'] = type(error).__name__
    return result


def stream_attempt(command, path, *, cwd, cancellation, on_failure, progress=lambda _: None,
                   timeout=SMOKE_TIMEOUT, max_bytes=MAX_LOG_BYTES, pipe_grace=1):
    """Stream bytes immediately, scan after cap, and own even post-parent pipe holders."""
    started = time.monotonic()
    markers = Markers()
    result = {'reason': None, 'exit_code': None, 'child_returncode': None,
              'bytes_seen': 0, 'bytes_written': 0, 'truncated': False,
              'timeout_seconds': timeout, 'stage': 'launch', 'signal': None,
              'diagnostic_error': None, 'cleanup': None, 'process_started': False}
    process = None
    failure_captured = False

    def snapshot():
        return {**result, 'markers': dict(markers.found),
                'owned_process': None if process is None else {
                    'pid': process.pid, 'pgid': process.pid,
                    'returncode': result['child_returncode']},
                'elapsed_seconds': round(time.monotonic() - started, 3)}

    def failure():
        nonlocal failure_captured
        if failure_captured:
            return
        failure_captured = True
        try:
            on_failure(snapshot())  # Read-only context BEFORE destructive cleanup.
        except (Exception, KeyboardInterrupt) as error:
            result['diagnostic_error'] = type(error).__name__

    try:
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                               getattr(os, 'O_NOFOLLOW', 0), 0o600), 'wb', buffering=0) as log:
            try:
                process = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT, start_new_session=True,
                                           bufsize=0)
            except OSError as error:
                result.update(reason='launch', exit_code=127, error=type(error).__name__)
            else:
                result['process_started'] = True
                deadline = started + timeout
                exited_at = None
                eof = False
                last_progress = 0
                previous_stage = None
                os.set_blocking(process.stdout.fileno(), False)
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    while result['reason'] is None:
                        now = time.monotonic()
                        code = process.poll()
                        result['child_returncode'] = code
                        if code is not None and exited_at is None:
                            exited_at = now
                        if cancellation.signum is not None:
                            result.update(reason='signal', signal=cancellation.signum,
                                          exit_code=128 + cancellation.signum)
                        elif now >= deadline:
                            result.update(reason='timeout', exit_code=124)
                        elif code is not None and eof:
                            result.update(reason='exit', exit_code=code if code >= 0 else 128 - code)
                            if code == 0 and result['truncated']:
                                result.update(reason='output_limit', exit_code=125)
                        elif exited_at is not None and now - exited_at >= pipe_grace:
                            # A parent can exit while its child keeps PIPE open.
                            result.update(reason='pipe_timeout', exit_code=code if code and code > 0 else 125)
                        if result['reason'] is not None:
                            break
                        for key, _ in selector.select(0.05):
                            try:
                                chunk = os.read(key.fd, 65536)
                            except BlockingIOError:
                                continue
                            if not chunk:
                                selector.unregister(key.fileobj)
                                eof = True
                                markers.finish()
                                continue
                            markers.feed(chunk)  # Never stop scanning at the disk cap.
                            result['bytes_seen'] += len(chunk)
                            keep = min(len(chunk), max_bytes - result['bytes_written'])
                            if keep:
                                written = log.write(chunk[:keep])
                                result['bytes_written'] += written or 0
                                if written != keep:
                                    raise OSError('short-private-log-write')
                            result['truncated'] |= keep < len(chunk)
                        result['stage'] = markers.stage()
                        if result['stage'] != previous_stage or now - last_progress >= 30:
                            progress(snapshot())
                            previous_stage = result['stage']
                            last_progress = now
            if result['exit_code'] == 0 and not qualified(markers.found):
                result.update(reason='unqualified', exit_code=125)
            if result['exit_code'] != 0:
                failure()
    except (Exception, KeyboardInterrupt) as error:
        if result['exit_code'] in (None, 0):
            result.update(reason='capture_error', exit_code=125, error=type(error).__name__)
        failure()
    finally:
        if process is not None:
            # Runs even if the log/context/write/selector failed or was interrupted.
            result['cleanup'] = _cleanup_group(process)
            if not (result['cleanup']['leader_reaped'] and result['cleanup']['pipe_closed']
                    and result['cleanup']['error'] is None) and result['exit_code'] == 0:
                result.update(reason='cleanup_error', exit_code=125)
                failure()
    if cancellation.signum is not None and result['exit_code'] == 0:
        result.update(reason='signal', signal=cancellation.signum, exit_code=128 + cancellation.signum)
        failure()
    return snapshot()


def collect_failure_context(serial, output, attempt, *, timeout=10, cancellation=None):
    """Bounded generic collector: the test-APK-specific collect() has the wrong UID/package."""
    commands = {'crash': ['logcat', '-d', '-b', 'crash', '-t', '200', '-v', 'threadtime'],
                'logcat': ['logcat', '-d', '-b', 'main', '-b', 'system', '-t', '400', '-v', 'threadtime'],
                'exit-info': ['shell', 'dumpsys', 'activity', 'exit-info', EXAMPLE_PACKAGE],
                'app-pid': ['shell', 'pidof', EXAMPLE_PACKAGE]}
    initial_signal = cancellation.signum if cancellation is not None else None
    def one(item):
        name, arguments = item
        try:
            path = output / f'flutter-smoke-{attempt}-{name}.log'
            result = capture(['adb', '-s', serial, *arguments],
                             path, timeout=timeout,
                             max_bytes=4096 if name == 'app-pid' else MAX_CONTEXT_BYTES,
                             cancelled=lambda: initial_signal is None and cancellation is not None and cancellation.signum is not None)
            if name == 'app-pid':
                # Only bounded numeric identities may leave the private raw file.
                raw = path.read_bytes()
                fields = raw.split()
                if (result.get('returncode') == 0 and 0 < len(fields) <= 16
                        and all(re.fullmatch(rb'[1-9][0-9]{0,9}', field) for field in fields)):
                    result['app_process'] = {'state': 'running', 'pids': [int(field) for field in fields]}
                elif result.get('returncode') == 1 and not fields:
                    result['app_process'] = {'state': 'absent', 'pids': []}
                else:
                    result['app_process'] = {'state': 'unknown', 'pids': []}
        except (OSError, subprocess.SubprocessError) as error:
            result = {'error': type(error).__name__}
        return name, result
    # Independent read-only captures share the same bounded observation window.
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix='smoke-context') as workers:
        metadata = dict(workers.map(one, commands.items()))
    write_private(output / f'flutter-smoke-{attempt}-context.json', json.dumps(metadata, indent=2) + '\n')
    return metadata


def preflight_ownership(serial, output, *, cancellation=None):
    """Only a fresh dedicated emulator can grant cleanup ownership of the example."""
    queries = [('hardware', ['shell', 'getprop', 'ro.hardware']),
               ('qemu', ['shell', 'getprop', 'ro.kernel.qemu']),
               ('package', ['shell', 'pm', 'path', EXAMPLE_PACKAGE])]
    values = {}
    for name, arguments in queries:
        path = output / f'baseline-{name}.log'
        report = capture(['adb', '-s', serial, *arguments], path, timeout=5, max_bytes=4096,
                         cancelled=lambda: cancellation is not None and cancellation.signum is not None)
        if report.get('timed_out') or report.get('cancelled') or report.get('truncated') or report.get('error'):
            raise RuntimeError('baseline-query-failed')
        values[name] = path.read_text(errors='replace').strip()
        if name != 'package' and report.get('returncode') != 0:
            raise RuntimeError('baseline-query-failed')
        if name == 'package' and report.get('returncode') not in (0, 1):
            raise RuntimeError('baseline-query-failed')
    if values['hardware'] not in ('ranchu', 'goldfish') or values['qemu'] != '1':
        raise RuntimeError('dedicated-emulator-required')
    if values['package']:
        raise RuntimeError('unknown-preinstalled-example')
    return True


def cleanup_example(serial, output, attempt, *, cancellation=None):
    return capture(['adb', '-s', serial, 'shell', 'am', 'force-stop', EXAMPLE_PACKAGE],
                   output / f'flutter-smoke-{attempt}-example-cleanup.log',
                   timeout=2 if cancellation is not None and cancellation.signum else 5, max_bytes=4096)


def run_smoke(serial, output, *, runner=stream_attempt, pause=time.sleep,
              collect=collect_failure_context, ownership=preflight_ownership,
              cleanup_app=cleanup_example, cancellation=None):
    if re.fullmatch(r'emulator-[0-9]+', serial) is None:
        raise ValueError('Smoke acceptance requires an explicitly selected emulator.')
    output.mkdir(parents=True, mode=0o700, exist_ok=True)
    if output.is_symlink() or any(output.iterdir()):
        raise ValueError('Smoke evidence requires a fresh private directory.')
    state = cancellation or Cancellation()
    summary = {'version': 1, 'serial': serial, 'package': EXAMPLE_PACKAGE,
               'attempts': [], 'exit_code': 125, 'stage': 'preflight'}
    def save():
        try:
            write_private(output / 'summary.json', json.dumps(summary, indent=2) + '\n')
            return True
        except (OSError, KeyboardInterrupt) as error:
            summary['metadata_error'] = type(error).__name__
            if summary['exit_code'] == 0:
                summary.update(stage='summary_write', exit_code=125)
            # There may be no writable filesystem left; retain the primary code
            # and emit only a fixed nonsecret failure marker to the runner.
            try:
                print('ANDROID_SMOKE_STATUS={"stage":"summary_write","reason":"metadata_error"}', flush=True)
            except OSError:
                pass
            return False
    def progress(value):
        # No raw child/context output, paths, addresses, config or credentials.
        safe = {key: value.get(key) for key in
                ('attempt', 'stage', 'reason', 'bytes_written', 'elapsed_seconds', 'owned_process')}
        safe['vm_service_observed'] = value.get('markers', {}).get('vm_service', False)
        print('ANDROID_SMOKE_STATUS=' + json.dumps(safe), flush=True)
    try:
        ownership(serial, output, cancellation=state)
    except (Exception, KeyboardInterrupt) as error:
        summary['error'] = type(error).__name__
        if state.signum is not None:
            summary.update(stage='preflight_cancelled', exit_code=128 + state.signum)
        save(); progress(summary)
        return summary['exit_code']
    if state.signum is not None:
        summary.update(stage='preflight_cancelled', exit_code=128 + state.signum)
        save(); progress(summary)
        return summary['exit_code']
    command = ['flutter', 'test', 'integration_test/android_xray_runtime_smoke_test.dart', '-d', serial]
    for attempt in range(1, 3):
        failure_report = {}
        startup_observation = {}
        def attempt_progress(value):
            progress(dict(value, attempt=attempt))
            if (startup_observation or value['stage'] != 'installed_awaiting_test_entry'
                    or value.get('markers', {}).get('entry') or state.signum is not None):
                return
            remaining = value['timeout_seconds'] - value['elapsed_seconds']
            if remaining <= 0:
                return
            # This synchronous capture consumes the attempt's existing absolute
            # deadline; stream_attempt never restarts its clock after the hook.
            startup_observation.update(stage=value['stage'], owned_process=value.get('owned_process'),
                                       vm_service_observed=value.get('markers', {}).get('vm_service', False))
            summary['startup_observation'] = startup_observation
            save()
            try:
                startup_observation['context'] = collect(serial, output, f'{attempt}-installed',
                    timeout=min(2, remaining), cancellation=state)
            except (Exception, KeyboardInterrupt) as error:
                startup_observation['error'] = type(error).__name__
            save()
        def on_failure(value):
            summary.update(stage=value['stage'], exit_code=value['exit_code'])
            summary['active_failure'] = dict(value, attempt=attempt)
            save()
            # Signal cancellation has a smaller best-effort context budget before
            # an outer runner's SIGKILL. All partial files stream independently.
            failure_report['context'] = collect(serial, output, attempt,
                                                 timeout=2 if state.signum else 10, cancellation=state)
            if any((item.get('returncode') != 0 and not (name == 'app-pid'
                        and item.get('returncode') == 1 and item.get('app_process', {}).get('state') == 'absent'))
                   or item.get('timed_out') or item.get('cancelled') or item.get('truncated') or item.get('error')
                   for name, item in failure_report['context'].items()):
                raise RuntimeError('context-incomplete')
        try:
            result = runner(command, output / f'flutter-smoke-{attempt}.log', cwd=ROOT / 'example',
                            cancellation=state, on_failure=on_failure,
                            progress=attempt_progress)
        except (Exception, KeyboardInterrupt) as error:
            # A runner/metadata failure must still reach the owned-app finally.
            result = {'reason': 'wrapper_error', 'exit_code': 125, 'stage': 'wrapper',
                      'error': type(error).__name__, 'process_started': True,
                      'markers': dict.fromkeys(Markers.patterns, False),
                      'truncated': False, 'diagnostic_error': type(error).__name__}
        result['attempt'] = attempt
        result['context'] = failure_report.get('context')
        result['startup_observation'] = startup_observation or None
        if result['process_started']:
            try:
                result['example_cleanup'] = cleanup_app(serial, output, attempt, cancellation=state)
            except (Exception, KeyboardInterrupt) as error:
                result['example_cleanup'] = {'error': type(error).__name__}
            clean = result['example_cleanup']
            cleanup_ok = clean.get('returncode') == 0 and not clean.get('timed_out') and not clean.get('error')
            if not cleanup_ok and result['exit_code'] == 0:
                result.update(reason='example_cleanup_error', stage='example_cleanup', exit_code=125,
                              diagnostic_order='after_cleanup_failure')
                try:
                    on_failure(result)
                except (Exception, KeyboardInterrupt) as error:
                    result['diagnostic_error'] = type(error).__name__
                result['context'] = failure_report.get('context')
        else:
            cleanup_ok = True
        if state.signum is not None and result['exit_code'] == 0:
            result.update(reason='signal', signal=state.signum, exit_code=128 + state.signum)
        result['observed_signal'] = state.signum
        summary['attempts'].append(result)
        summary.update(stage=result['stage'], exit_code=result['exit_code'])
        summary.pop('active_failure', None)
        summary.pop('startup_observation', None)
        save()
        if summary.get('metadata_error') and result['exit_code'] == 0:
            result.update(reason='metadata_error', stage='summary_write', exit_code=125)
        progress(result)
        markers = result['markers']
        group = result.get('cleanup') or {}
        group_clean = group.get('leader_reaped') and group.get('pipe_closed') and group.get('error') is None
        retry = (attempt == 1 and result['reason'] == 'exit' and 0 < (result.get('child_returncode') or 0) < 128
                 and group_clean
                 and markers['dds'] and not markers['entry'] and not markers['core_version']
                 and not result['truncated'] and result['diagnostic_error'] is None
                 and cleanup_ok and state.signum is None and not summary.get('metadata_error'))
        if not retry:
            return result['exit_code']
        pause(2)
        if state.signum is not None:
            summary.update(stage='retry_cancelled', exit_code=128 + state.signum)
            save(); return summary['exit_code']
    return 125


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--serial', required=True)
    parser.add_argument('--output', type=Path, default=ROOT / 'build/android-flutter-smoke')
    args = parser.parse_args()
    state = Cancellation()
    with cancellation_handlers(state):
        try:
            return run_smoke(args.serial, args.output, cancellation=state)
        except (OSError, ValueError, subprocess.SubprocessError, KeyboardInterrupt) as error:
            print('ANDROID_SMOKE_STATUS=' + json.dumps({'stage': 'wrapper', 'reason': type(error).__name__}), flush=True)
            return 128 + state.signum if state.signum else 125


if __name__ == '__main__':
    sys.exit(main())
