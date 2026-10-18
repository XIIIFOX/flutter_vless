#!/usr/bin/env python3
"""Build unpublished Core capability; run loopback acceptance only in CI."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
CAPABILITY = ROOT / 'third_party/xray-native-dns'
EVIDENCE = ROOT / 'build/native_dns_context_runtime'
MANIFEST = json.loads((CAPABILITY / 'pin-manifest.json').read_text())
OUTPUT_JOIN_SECONDS = 10


def runtime_authorized(environment=None, system=None):
    environment = os.environ if environment is None else environment
    system = platform.system() if system is None else system
    return environment.get('CI', '').lower() == 'true' and (
        system != 'Darwin' or environment.get('GITHUB_ACTIONS', '').lower() == 'true')


def stop_owned_process(process):
    """Only the child/tree whose new process group this runner created."""
    if os.name == 'nt':
        if process.poll() is not None:
            # Do not guess descendant PIDs after their parent has gone. Actual
            # runtime owns no workers; inherited output remains a failure.
            return
        # go compilation can own compiler children; runtime fixture owns none.
        try:
            subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'],
                           capture_output=True, timeout=15, check=False)
        except (OSError, subprocess.SubprocessError):
            pass
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if process.poll() is None:
        process.kill()
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def write_console(value):
    """Escape console-only unsupported characters; keep artifact text intact."""
    stream = sys.stdout
    encoding = getattr(stream, 'encoding', None)
    if encoding:
        value = value.encode(encoding, errors='backslashreplace').decode(encoding)
    stream.write(value)
    stream.flush()


def checked(name, command, *, cwd, environment, seconds, results):
    """Drain stdout/stderr independently of sinks; fail on incomplete evidence."""
    started = time.monotonic()
    output_errors = []
    errors_lock = threading.Lock()
    console_available = True

    def record_error(sink, operation, error):
        with errors_lock:
            output_errors.append({'sink': sink, 'operation': operation,
                                  'error': f'{type(error).__name__}: {error}'})

    def console(value):
        nonlocal console_available
        if console_available:
            try:
                write_console(value)
            except Exception as error:
                # A broken console must not stop draining the child's pipe.
                console_available = False
                record_error('console', 'write/flush', error)

    console(f'PHASE {name}: start\n')
    creation = ({'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP}
                if os.name == 'nt' else {'start_new_session': True})
    log = None
    try:
        log = (EVIDENCE / f'{name}.log').open('w', encoding='utf-8')
    except Exception as error:
        record_error('log', 'open', error)
    output_eof = threading.Event()
    stop_sinks = threading.Event()
    try:
        process = subprocess.Popen(command, cwd=cwd, env=environment,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, encoding='utf-8', errors='replace', **creation)

        def reader():
            log_available = log is not None
            try:
                for line in process.stdout:
                    if stop_sinks.is_set():
                        continue
                    if log_available:
                        try:
                            log.write(line)
                            log.flush()
                        except Exception as error:
                            log_available = False
                            record_error('log', 'write/flush', error)
                    console(line)
                # Thread termination alone is not evidence of pipe EOF.
                output_eof.set()
            except Exception as error:
                record_error('pipe', 'read', error)

        output_thread = threading.Thread(target=reader, daemon=True)
        output_thread.start()
        timed_out = False
        try:
            code = process.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            stop_owned_process(process)
            code = 124
        finally:
            if process.poll() is None:
                stop_owned_process(process)
            output_thread.join(timeout=OUTPUT_JOIN_SECONDS)
        if output_thread.is_alive():
            code = code or 125
            record_error('pipe', 'drain', TimeoutError('Child output did not reach EOF before drain deadline'))
            # An exited leader may still own compiler grandchildren holding
            # the pipe. Its Unix session/group ID is the one created above.
            stop_owned_process(process)
            output_thread.join(timeout=OUTPUT_JOIN_SECONDS)
        stop_sinks.set()
        if not output_thread.is_alive():
            try:
                process.stdout.close()
            except Exception as error:
                record_error('pipe', 'close', error)
        output_closed = not output_thread.is_alive() and output_eof.is_set() and process.stdout.closed
        if not output_closed:
            code = code or 126
    finally:
        if log is not None:
            try:
                log.close()
            except Exception as error:
                record_error('log', 'close', error)
    if output_errors:
        code = code or 126
    console(f'PHASE {name}: {"PASS" if code == 0 else "FAIL"} ({code})\n')
    # The final console write/flush is evidence too, including when child exit
    # and pipe EOF succeeded. Preserve a nonzero child/timeout status verbatim.
    if output_errors:
        code = code or 126
    result = {'name': name, 'exit_code': code, 'process_exit_code': process.returncode,
              'timed_out': timed_out, 'output_closed': output_closed,
              'output_eof': output_eof.is_set(),
              'output_errors': output_errors,
              'elapsed_seconds': round(time.monotonic() - started, 3)}
    results.append(result)
    if code:
        raise RuntimeError(f'{name} failed with status {code}')


def load_apply_module():
    spec = importlib.util.spec_from_file_location('native_dns_capability_apply', CAPABILITY / 'apply.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require_selected_test_pass(output, name):
    if not re.search(r'^--- PASS: ' + re.escape(name) + r' \(', output, re.MULTILINE):
        raise RuntimeError('Selected actual runtime acceptance test did not report PASS')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-runtime', action='store_true')
    parser.add_argument('--go', default='go', help='Go 1.27+ executable; no toolchain mutation')
    arguments = parser.parse_args()
    if arguments.run_runtime and not runtime_authorized():
        parser.error('Runtime execution requires CI=true; Darwin also requires GITHUB_ACTIONS=true')
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    results = []
    report = {'capability': MANIFEST['capability'], 'published': False,
              'core_commit': MANIFEST['core_commit'], 'runtime_requested': arguments.run_runtime,
              'go_binary': str(Path(shutil.which(arguments.go) or arguments.go).resolve()),
              'results': results}
    environment = dict(os.environ, GOTOOLCHAIN='local', GOWORK='off')
    core = EVIDENCE / 'Core'
    source = None
    # Refuse to remove a pre-existing directory. Existing evidence belongs to
    # its earlier invocation and must be handled explicitly by the caller.
    if core.exists() or core.is_symlink():
        parser.error('build/native_dns_context_runtime/Core already exists; use a fresh checkout/evidence directory')
    try:
        checked('python-copier-guards', [sys.executable, str(CAPABILITY / 'test_apply.py')],
                cwd=ROOT, environment=environment, seconds=30, results=results)
        checked('python-runner-guards', [sys.executable, str(ROOT / 'tool/test_native_dns_context_runner.py')],
                cwd=ROOT, environment=environment, seconds=30, results=results)
        download = subprocess.run([arguments.go, 'mod', 'download', '-json',
                                   f"{MANIFEST['module']}@{MANIFEST['module_version']}"],
                                  cwd=ROOT / 'third_party/xray-mobile', env=environment,
                                  text=True, capture_output=True, check=True, timeout=180)
        metadata = json.loads(download.stdout)
        if metadata.get('Version') != MANIFEST['module_version'] or metadata.get('Sum') != MANIFEST['module_sum']:
            raise RuntimeError('Pinned Core version/checksum mismatch')
        source = Path(metadata['Dir']).resolve()
        report['module_sum'] = metadata['Sum']
        report['apply_sha256'] = hashlib.sha256((CAPABILITY / 'apply.py').read_bytes()).hexdigest()
        report['patch_modules_sha256'] = {
            'local_resolver_patch.py': hashlib.sha256((CAPABILITY / 'local_resolver_patch.py').read_bytes()).hexdigest()}
        report['overlay_sha256'] = {
            str(path.relative_to(CAPABILITY / 'overlay')).replace(os.sep, '/'):
            hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted((CAPABILITY / 'overlay').rglob('*.go'))}
        report['fixture_sha256'] = {
            str(path.relative_to(ROOT / 'tool/fixtures/native_dns_context_runtime')).replace(os.sep, '/'):
            hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted((ROOT / 'tool/fixtures/native_dns_context_runtime').rglob('*.go'))}
        overlay = load_apply_module()
        overlay.copy_and_apply(source, core, go=arguments.go)
        report['patched_source_sha256'] = {path: hashlib.sha256((core / path).read_bytes()).hexdigest()
                                          for path in MANIFEST['upstream_sha256'] if path.endswith('.go')}
        fixture = core / 'native_dns_context_runtime'
        shutil.copytree(ROOT / 'tool/fixtures/native_dns_context_runtime', fixture)
        for name, package in [('internet', 'transport/internet'),
                              ('outbound', 'app/proxyman/outbound'),
                              ('freedom', 'proxy/freedom'),
                              ('nativeconfig', 'common/nativeconfig'),
                              ('dnsfeature', 'features/dns'),
                              ('localdns', 'features/dns/localdns'),
                              ('appdns', 'app/dns'),
                              ('core', 'core'),
                              ('nativednsruntime', 'common/nativednsruntime'),
                              ('nativeinstance', 'common/nativeinstance'),
                              ('nativepreview', 'main/nativepreview')]:
            binary = EVIDENCE / (name + ('.test.exe' if os.name == 'nt' else '.test'))
            checked(name + '-compile', [arguments.go, 'test', '-c', '-o', str(binary), './' + package],
                    cwd=core, environment=environment, seconds=300, results=results)
            # nativeconfig contains only decode/plan/static-host value tests;
            # its package has no Core execution, resolver or socket operations.
            selection = '^TestNative'
            checked(name + '-pure-tests', [str(binary), '-test.run', selection, '-test.v', '-test.timeout=20s'],
                    cwd=core, environment=environment, seconds=35, results=results)
        binary = EVIDENCE / ('acceptance.test.exe' if os.name == 'nt' else 'acceptance.test')
        checked('runtime-compile', [arguments.go, 'test', '-c', '-o', str(binary), './native_dns_context_runtime'],
                cwd=core, environment=environment, seconds=300, results=results)
        launcher = EVIDENCE / ('native-preview.exe' if os.name == 'nt' else 'native-preview')
        checked('native-launcher-build', [arguments.go, 'build', '-trimpath', '-buildvcs=false', '-o', str(launcher), './main/nativepreview'],
                cwd=core, environment=environment, seconds=300, results=results)
        report['native_launcher_sha256'] = hashlib.sha256(launcher.read_bytes()).hexdigest()
        if arguments.run_runtime:
            runtime_environment = dict(environment, FLUTTER_VLESS_NATIVE_PREVIEW=str(launcher.resolve()))
            selected_tests = ['TestAcceptanceNativeDNSRuntime', 'TestAcceptanceNativeDNSLocalDefault', 'TestAcceptanceNativeDNSLauncher']
            checked('runtime-loopback', [str(binary), '-test.run', '^TestAcceptanceNativeDNS(Runtime|LocalDefault|Launcher)$', '-test.v', '-test.timeout=75s'],
                    cwd=core, environment=runtime_environment, seconds=90, results=results)
            for name in selected_tests:
                require_selected_test_pass((EVIDENCE / 'runtime-loopback.log').read_text(encoding='utf-8'), name)
            results[-1]['selected_test_pass'] = True
            results[-1]['selected_tests'] = selected_tests
        report['module_cache_targeted_sources_unchanged'] = all(
            hashlib.sha256((source / path).read_bytes()).hexdigest() == expected
            for path, expected in MANIFEST['upstream_sha256'].items())
        if not report['module_cache_targeted_sources_unchanged']:
            raise RuntimeError('Source cache verification changed')
        for folder, key, copied in [(CAPABILITY / 'overlay', 'overlay_sha256', core),
                                    (ROOT / 'tool/fixtures/native_dns_context_runtime', 'fixture_sha256', fixture)]:
            current = {str(path.relative_to(folder)).replace(os.sep, '/'):
                       hashlib.sha256(path.read_bytes()).hexdigest()
                       for path in sorted(folder.rglob('*.go'))}
            if current != report[key] or any(hashlib.sha256((copied / path).read_bytes()).hexdigest() != expected
                                             for path, expected in report[key].items()):
                raise RuntimeError('Source snapshot changed during verification; repeat in a stable checkout')
        report['source_snapshot_unchanged'] = True
        if hashlib.sha256((CAPABILITY / 'apply.py').read_bytes()).hexdigest() != report['apply_sha256']:
            raise RuntimeError('Overlay application source changed during verification')
        if any(hashlib.sha256((CAPABILITY / path).read_bytes()).hexdigest() != digest
               for path, digest in report['patch_modules_sha256'].items()):
            raise RuntimeError('Overlay patch module changed during verification')
        if any(hashlib.sha256((core / path).read_bytes()).hexdigest() != digest
               for path, digest in report['patched_source_sha256'].items()):
            raise RuntimeError('Patched Core source changed during verification')
        report['success'] = True
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report['success'] = False
        report['error'] = str(error)
        print(f'Native DNS capability check failed: {error}', file=sys.stderr)
    finally:
        if source is not None:
            report['module_cache_targeted_sources_unchanged'] = all(
                hashlib.sha256((source / path).read_bytes()).hexdigest() == expected
                for path, expected in MANIFEST['upstream_sha256'].items())
        (EVIDENCE / 'result.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return 0 if report.get('success') else 1


if __name__ == '__main__':
    raise SystemExit(main())
