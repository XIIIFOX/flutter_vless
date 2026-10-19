#!/usr/bin/env python3
"""Bound a single owned Apple probe; stdout/stderr remain available to tee."""
import argparse
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time

IOS_BUNDLE = 'dev.tfox.security-runtime-probe'
STOP_SECONDS = 5
MAX_IPS_BYTES = 2 * 1024 * 1024
MAX_IPS_REPORTS = 16
MAX_PHASE_BYTES = 2048


def _phase_app_pid(log_path, launched_at):
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    with os.fdopen(os.open(log_path, flags), 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mtime < launched_at:
            return None
        # The app emits this marker at entry, before the runtime fixtures.
        text = source.read(65536).decode('utf-8', errors='replace')
    matches = re.findall(r'^PROBE_APP_PID=([1-9][0-9]{0,9})\r?$', text, re.MULTILINE)
    if len(matches) != 1 or int(matches[0]) > 2147483647:
        return None
    pid = int(matches[0])
    console = re.findall(r'^' + re.escape(IOS_BUNDLE) + r': ([1-9][0-9]{0,9})\r?$', text, re.MULTILINE)
    return pid if all(int(value) == pid for value in console) else None


def _unique_phase_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate-phase-field')
        result[key] = value
    return result


def _read_phase_receipt(container, launched_at):
    descriptors = []
    directory_flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    try:
        descriptors.append(os.open(container, directory_flags))
        for component in ('Library', 'Caches'):
            descriptors.append(os.open(component, directory_flags, dir_fd=descriptors[-1]))
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
        descriptor = os.open('flutter-vless-probe-phase.json', flags, dir_fd=descriptors[-1])
        with os.fdopen(descriptor, 'rb') as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_PHASE_BYTES
                    or info.st_mtime < launched_at or info.st_mtime > time.time()):
                return None
            raw = source.read(MAX_PHASE_BYTES + 1)
        if len(raw) > MAX_PHASE_BYTES:
            return None
        return json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_phase_fields)
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def collect_ios_phase(log_path, simulator, launched_at, run=None):
    """Read one fixed app receipt; this is diagnostic data, never acceptance."""
    def unavailable(reason):
        return {'state': 'unavailable', 'reason': reason}
    if not math.isfinite(launched_at) or launched_at <= 0:
        return unavailable('invalid-launch-time')
    if re.fullmatch(r'[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}', simulator) is None:
        return unavailable('invalid-simulator')
    try:
        pid = _phase_app_pid(log_path, launched_at)
        if pid is None:
            return unavailable('app-pid-unavailable')
        command = ['xcrun', 'simctl', 'get_app_container', simulator, IOS_BUNDLE, 'data']
        result = (run or subprocess.run)(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                         timeout=10, check=False)
        raw_path = result.stdout
        if result.returncode != 0 or not isinstance(raw_path, bytes) or len(raw_path) > 4096:
            return unavailable('container-unavailable')
        container = raw_path.decode('utf-8').rstrip('\r\n')
        if not os.path.isabs(container) or any(char in container for char in ('\0', '\r', '\n')):
            return unavailable('container-unavailable')
        receipt = _read_phase_receipt(container, launched_at)
        if (not isinstance(receipt, dict) or type(receipt.get('schema')) is not int or receipt['schema'] != 1
                or type(receipt.get('pid')) is not int or receipt['pid'] != pid
                or type(receipt.get('phase')) is not int or not 1 <= receipt['phase'] <= 8
                or type(receipt.get('completed_modes')) is not int or not 0 <= receipt['completed_modes'] <= 12):
            return unavailable('invalid-receipt')
        return {'state': 'matched', 'schema': 1, 'pid': pid, 'phase': receipt['phase'],
                'completed_modes': receipt['completed_modes']}
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError, RecursionError):
        return unavailable('receipt-unavailable')


def append_ios_phase(log_path, simulator, launched_at):
    metadata = collect_ios_phase(log_path, simulator, launched_at)
    line = 'PROBE_IOS_PHASE=' + json.dumps(metadata, separators=(',', ':'), sort_keys=True)
    assert len(line.encode('ascii')) <= 2048
    appended = False
    try:
        flags = os.O_WRONLY | os.O_APPEND | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
        with os.fdopen(os.open(log_path, flags), 'a', encoding='utf-8') as output:
            if not stat.S_ISREG(os.fstat(output.fileno()).st_mode):
                raise OSError('nonregular-runtime-log')
            output.write('\n' + line + '\n')
            appended = True
    except OSError:
        pass
    print(line, flush=True)
    return metadata['state'] == 'matched' and appended


def _ips_documents(path, launched_at):
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_IPS_BYTES or info.st_mtime < launched_at:
            return None
        raw = source.read(MAX_IPS_BYTES + 1)
    if len(raw) > MAX_IPS_BYTES:
        return None
    text = raw.decode('utf-8')
    decoder = json.JSONDecoder()
    first, end = decoder.raw_decode(text.lstrip())
    remaining = text.lstrip()[end:].strip()
    second = json.loads(remaining) if remaining else first
    return (first, second) if isinstance(first, dict) and isinstance(second, dict) else None


def collect_ios_termination(log_path, launched_at, reports_directory=None):
    """Read bounded, identity-matched crash metadata; never infer app success."""
    unavailable = {'state': 'unavailable', 'reason': 'no-matching-report'}
    if not math.isfinite(launched_at) or launched_at <= 0:
        return {'state': 'unavailable', 'reason': 'invalid-launch-time'}
    try:
        with Path(log_path).open('rb') as source:
            source.seek(0, os.SEEK_END)
            source.seek(max(0, source.tell() - 65536))
            text = source.read(65536).decode('utf-8', errors='replace')
        matches = re.findall(r'^' + re.escape(IOS_BUNDLE) + r': ([1-9][0-9]{0,9})\r?$', text, re.MULTILINE)
        pids = {int(value) for value in matches if int(value) <= 2147483647}
        if len(pids) != 1:
            return {'state': 'unavailable', 'reason': 'app-pid-unavailable'}
        pid = pids.pop()
        directory = Path(reports_directory) if reports_directory is not None else Path.home() / 'Library/Logs/DiagnosticReports'
        candidates = []
        with os.scandir(directory) as entries:
            for index, entry in enumerate(entries):
                if index >= 512:
                    break
                if not entry.name.startswith('Probe') or not entry.name.endswith('.ips') or not entry.is_file(follow_symlinks=False):
                    continue
                info = entry.stat(follow_symlinks=False)
                if info.st_mtime >= launched_at and info.st_size <= MAX_IPS_BYTES:
                    candidates.append((info.st_mtime, entry.path))
        for _, path in sorted(candidates, reverse=True)[:MAX_IPS_REPORTS]:
            try:
                documents = _ips_documents(path, launched_at)
                if documents is None:
                    continue
                header, body = documents
                bundle_info = body.get('bundleInfo')
                bundles = [header.get('bundleID')]
                if isinstance(bundle_info, dict):
                    bundles.append(bundle_info.get('CFBundleIdentifier'))
                bundles = [value for value in bundles if value is not None]
                if not bundles or any(value != IOS_BUNDLE for value in bundles):
                    continue
                if type(body.get('pid')) is not int or body['pid'] != pid or body.get('procName') != 'Probe':
                    continue
                termination = body.get('termination')
                exception = body.get('exception')
                termination = termination if isinstance(termination, dict) else {}
                exception = exception if isinstance(exception, dict) else {}
                result = {'state': 'matched', 'pid': pid, 'reason': 'termination'}
                namespaces = {'FRONTBOARD', 'RUNNINGBOARD', 'SPRINGBOARD', 'SIGNAL', 'CODESIGNING', 'DYLD', 'JETSAM', 'WATCHDOG', 'LIBSYSTEM', 'TCC', 'ENDPOINTSECURITY', 'ASSERTIOND', 'EXC_GUARD', 'EXEC'}
                namespace = termination.get('namespace')
                result['namespace'] = namespace if isinstance(namespace, str) and namespace in namespaces else 'unknown'
                code = termination.get('code')
                if type(code) is int and 0 <= code <= 0xffffffffffffffff:
                    result['code'] = code
                    if code == 0x8badf00d:
                        result['reason'] = 'watchdog'
                signals = {'SIGABRT', 'SIGKILL', 'SIGTERM', 'SIGSEGV', 'SIGBUS', 'SIGILL', 'SIGPIPE', 'SIGTRAP', 'SIGQUIT', 'SIGXCPU', 'SIGXFSZ'}
                signal_name = exception.get('signal')
                if isinstance(signal_name, str) and signal_name in signals:
                    result['signal'] = signal_name
                types = {'EXC_BAD_ACCESS', 'EXC_BAD_INSTRUCTION', 'EXC_ARITHMETIC', 'EXC_EMULATION', 'EXC_SOFTWARE', 'EXC_BREAKPOINT', 'EXC_CRASH', 'EXC_RESOURCE', 'EXC_GUARD', 'EXC_CORPSE_NOTIFY'}
                exception_type = exception.get('type')
                if isinstance(exception_type, str) and exception_type in types:
                    result['exception'] = exception_type
                return result
            except (OSError, UnicodeError, ValueError, RecursionError):
                continue
        return unavailable
    except OSError:
        return {'state': 'unavailable', 'reason': 'metadata-unavailable'}


def append_ios_termination(log_path, launched_at):
    metadata = collect_ios_termination(log_path, launched_at)
    line = 'PROBE_IOS_TERMINATION=' + json.dumps(metadata, separators=(',', ':'), sort_keys=True)
    assert len(line.encode('utf-8')) <= 2048
    try:
        with Path(log_path).open('a', encoding='utf-8') as output:
            output.write('\n' + line + '\n')
    except OSError:
        pass
    print(line, flush=True)


class Interrupted(Exception):
    def __init__(self, signum):
        self.signum = signum


def stop_owned(process):
    # A live, unreaped Popen child identifies our process. Never search by name,
    # kill a process group, or signal a PID taken from an old artifact.
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=STOP_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=STOP_SECONDS)


def terminate_ios_probe(simulator, run=subprocess.run):
    # The caller installed and launched this fixed test bundle in its disposable
    # simulator. The simctl console process is not the application's own PID.
    try:
        result = run(['xcrun', 'simctl', 'terminate', simulator, IOS_BUNDLE],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     timeout=10, check=False)
        print(f'PROBE_CLEANUP=ios-bundle;status={result.returncode}', flush=True)
    except (OSError, subprocess.TimeoutExpired) as error:
        print(f'PROBE_CLEANUP=ios-bundle;error={type(error).__name__}', flush=True)


def run_probe(command, timeout, simulator=None, cleanup_ios=terminate_ios_probe):
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError('Probe timeout must be positive and finite')
    if simulator is not None and command != ['xcrun', 'simctl', 'launch', '--console', simulator, IOS_BUNDLE]:
        raise ValueError('Simulator cleanup requires the exact owned probe launch command')
    process = subprocess.Popen(command)
    previous = {}
    needs_ios_cleanup = True
    def interrupt(signum, _frame):
        raise Interrupted(signum)
    try:
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous[signum] = signal.signal(signum, interrupt)
        print(f'PROBE_PROCESS_STARTED=owned-child;pid={process.pid}', flush=True)
        try:
            code = process.wait(timeout=timeout)
            needs_ios_cleanup = code != 0
            print(f'PROBE_PROCESS_EXIT=status-{code if code >= 0 else 128 - code}', flush=True)
            return code if code >= 0 else 128 - code
        except subprocess.TimeoutExpired:
            print('PROBE_TIMEOUT=runtime', flush=True)
            return 124
        except Interrupted as error:
            print(f'PROBE_INTERRUPTED=signal-{error.signum}', flush=True)
            return 128 + error.signum
    finally:
        # Bound cleanup even if the outer CI ceiling interrupts this helper.
        for signum in previous:
            signal.signal(signum, signal.SIG_IGN)
        try:
            try:
                if simulator is not None and needs_ios_cleanup:
                    cleanup_ios(simulator)
            finally:
                stop_owned(process)
        except (OSError, subprocess.TimeoutExpired) as error:
            print(f'PROBE_CLEANUP=owned-child;error={type(error).__name__}', flush=True)
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--timeout', type=float, default=600)
    parser.add_argument('--ios-simulator')
    parser.add_argument('--collect-ios-termination', metavar='RUNTIME_LOG')
    parser.add_argument('--collect-ios-phase', metavar='RUNTIME_LOG')
    parser.add_argument('--launched-at', type=float)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    if arguments.collect_ios_phase is not None:
        if (arguments.launched_at is None or arguments.ios_simulator is None or arguments.command
                or arguments.collect_ios_termination is not None):
            parser.error('Phase metadata requires only a runtime log, simulator and launch time')
        return 0 if append_ios_phase(arguments.collect_ios_phase, arguments.ios_simulator, arguments.launched_at) else 1
    if arguments.collect_ios_termination is not None:
        if arguments.launched_at is None or arguments.command or arguments.ios_simulator is not None:
            parser.error('Termination metadata requires only a runtime log and launch time')
        append_ios_termination(arguments.collect_ios_termination, arguments.launched_at)
        return 0
    command = arguments.command
    if command[:1] == ['--']:
        command = command[1:]
    if not command:
        parser.error('A probe command is required')
    try:
        return run_probe(command, arguments.timeout, arguments.ios_simulator)
    except (OSError, ValueError) as error:
        print(f'PROBE_LAUNCH_FAILED={type(error).__name__}', file=sys.stderr, flush=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())
