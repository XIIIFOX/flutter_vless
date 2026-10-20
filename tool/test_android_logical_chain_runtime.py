#!/usr/bin/env python3
"""Exact Android-native-output SOCKS chain and XHTTP TLS, only in Linux GitHub CI."""
from __future__ import annotations

import argparse
import collections
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('android_chain_helpers', ROOT / 'tool/test_native_vpn_routing.py')
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)
common = helpers.common
HARD_STOP = common.stop_owned_process
EVIDENCE = ROOT / 'build/android_logical_chain_runtime'
TEST = 'TestAndroidLogicalChainRuntime'
MARKER = 'ANDROID_LOGICAL_CHAIN_RUNTIME_PASS=1'
TLS_TEST = 'TestAndroidXHTTPTLSRuntime'
TLS_MODES = ('independent', 'wrong_ca', 'wrong_sni')
TLS_MARKER = 'ANDROID_XHTTP_TLS_H2_PASS'
TLS_SOURCE = 'android_xhttp_tls_runtime_linux_test.go'
MANIFEST_PATH = ROOT / 'third_party/xray-native-dns/pin-manifest.json'


def authorized(environment=None, system=None):
    environment = os.environ if environment is None else environment
    return (platform.system() if system is None else system) == 'Linux' and all(
        environment.get(key, '').lower() == 'true' for key in ('CI', 'GITHUB_ACTIONS'))


def interrupted(number, frame):
    raise helpers.Interrupted(number)


def gradle_source_files(directory):
    return sorted(path for path in directory.glob('*.gradle*') if path.is_file())


def source_snapshot():
    paths = [Path(__file__).resolve(), ROOT / 'tool/test_native_vpn_routing.py',
             ROOT / 'tool/test_native_dns_context_runtime.py', ROOT / 'tool/with_android_local_runtime.py',
             ROOT / 'tool/verify_android_runtime_inputs.py', MANIFEST_PATH,
             ROOT / 'third_party/xray-mobile/go.mod', ROOT / 'third_party/xray-mobile/go.sum',
             ROOT / 'android_runtime/xray_android/runtime-inputs.sha256.json',
             ROOT / 'example/android/gradle/wrapper/gradle-wrapper.properties']
    paths += sorted((ROOT / 'third_party/xray-mobile').rglob('*.go'))
    paths += sorted((ROOT / 'packages/flutter_vless_android/android/src').rglob('*.kt'))
    paths += gradle_source_files(ROOT / 'packages/flutter_vless_android/android')
    return {str(path.relative_to(ROOT)): helpers.digest(path) for path in paths}


def stop_runtime(process):
    """Give Go time to interrupt/reap its separately owned Gradle group first."""
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGINT)
            process.wait(timeout=12)
        except (OSError, subprocess.TimeoutExpired):
            HARD_STOP(process)
    # Also close an exited leader's owned descendants holding output open.
    HARD_STOP(process)


def checked(name, command, *, cwd, environment, seconds, results, runtime=False):
    common.EVIDENCE = EVIDENCE
    previous = common.stop_owned_process
    if runtime:
        common.stop_owned_process = stop_runtime
    try:
        common.checked(name, command, cwd=cwd, environment=environment, seconds=seconds, results=results)
    finally:
        common.stop_owned_process = previous


def verify_runtime(log, result):
    if result.get('exit_code') != 0 or not result.get('output_eof') or not result.get('output_closed') or result.get('output_errors'):
        raise ValueError('Actual Android chain output did not close successfully')
    if len(re.findall(r'(?:^|\s)' + re.escape(MARKER) + r'\s*$', log, re.M)) != 1:
        raise ValueError('Exactly one Android native-output wire marker is required')
    if not re.search(r'^--- PASS: ' + TEST + r'(?:\s|$)', log, re.M) or re.search(r'--- (?:FAIL|SKIP):', log):
        raise ValueError('Selected Android wire test did not pass without skip')


def verify_export(directory):
    data = (directory / 'config.json').read_bytes()
    metadata = json.loads((directory / 'metadata.json').read_bytes())
    if metadata.get('version') != 1 or metadata.get('configSHA256') != hashlib.sha256(data).hexdigest():
        raise ValueError('Exact production-native Android output hash changed')
    for name in ('sourceSHA256', 'preparedSHA256'):
        if not re.fullmatch('[0-9a-f]{64}', metadata.get(name, '')):
            raise ValueError('Android source/prepared provenance is missing')
    return {key: metadata[key] for key in ('version', 'configSHA256', 'sourceSHA256', 'preparedSHA256', 'privatePort', 'outerPort')}


def verify_tls_runtime(log, result):
    if (result.get('exit_code') != 0 or result.get('process_exit_code') != 0 or
            result.get('timed_out') is not False or result.get('output_eof') is not True or
            result.get('output_closed') is not True or result.get('output_errors') != []):
        raise ValueError('Actual Android TLS output did not complete successfully')
    marker = re.compile(r'^\s+' + re.escape(TLS_SOURCE) + r':\d+: ' + TLS_MARKER +
                        r' mode=(independent|wrong_ca|wrong_sni)\r?$')
    modes = []
    for line in log.splitlines():
        if TLS_MARKER not in line:
            continue
        match = marker.fullmatch(line)
        if not match:
            raise ValueError('Android TLS marker has an unexpected source or mode')
        modes.append(match.group(1))
    if collections.Counter(modes) != collections.Counter(TLS_MODES):
        raise ValueError('Exactly three Android TLS mode markers are required')
    selected = [TLS_TEST, *(TLS_TEST + '/' + mode for mode in TLS_MODES)]
    for name in selected:
        if len(re.findall(r'^\s*--- PASS: ' + re.escape(name) + r' \(', log, re.M)) != 1:
            raise ValueError('Every selected Android TLS mode must pass exactly once')
    if re.search(r'^\s*--- (?:FAIL|SKIP):', log, re.M) or not re.search(r'\nPASS\r?\n?\Z', log):
        raise ValueError('Android TLS tests or cleanup failed, skipped or did not finish')


def private_file(path, limit):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= limit:
        raise ValueError('Android TLS export requires bounded private regular files')
    return path.read_bytes()


def private_directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('Android TLS export requires private real directories')


def verify_tls_exports(directory):
    """Bind receipts only; exact configs and CA/source files stay private."""
    private_directory(directory)
    manifest = json.loads(private_file(directory / 'manifest.json', 32768))
    if not isinstance(manifest, dict):
        raise ValueError('Android TLS manifest must be an object')
    entries = manifest.get('entries', [])
    if (type(manifest.get('version')) is not int or manifest['version'] != 1 or
            not isinstance(entries, list) or any(not isinstance(entry, dict) for entry in entries) or
            [entry.get('mode') for entry in entries] != list(TLS_MODES)):
        raise ValueError('Android TLS manifest must contain the exact three fresh modes')
    summaries = []
    seen_ports = set()
    for entry in entries:
        mode = entry['mode']
        owned = directory / mode
        assets, output = owned / 'assets', owned / 'export'
        for path in (owned, assets, output):
            private_directory(path)
        paths = {'sourcePath': owned / 'source.json', 'outputDirectory': output,
                 'certificateAssetsDirectory': assets}
        if any(entry.get(key) != str(path) for key, path in paths.items()):
            raise ValueError('Android TLS export was retargeted outside its mode')
        ports = {key: entry.get(key) for key in ('privatePort', 'uploadPort', 'downloadPort')}
        if any(type(value) is not int or not 1 <= value <= 65535 for value in ports.values()):
            raise ValueError('Android TLS listener ports must be exact numeric ports')
        if len(set(ports.values())) != 3 or seen_ports.intersection(ports.values()):
            raise ValueError('Android TLS mode reservations must remain distinct')
        seen_ports.update(ports.values())
        source_hash = hashlib.sha256(private_file(paths['sourcePath'], 1 << 20)).hexdigest()
        if entry.get('sourceSHA256') != source_hash:
            raise ValueError('Android TLS source hash changed after planning')
        certificates = entry.get('caFiles')
        ca_paths = [assets / 'upload-ca.pem', assets / 'download-ca.pem']
        if (not isinstance(certificates, list) or len(certificates) != 2 or
                any(not isinstance(record, dict) for record in certificates) or
                any(record.get('path') != str(path) for record, path in zip(certificates, ca_paths))):
            raise ValueError('Android TLS CA owners changed')
        for record, path in zip(certificates, ca_paths):
            if record.get('sha256') != hashlib.sha256(private_file(path, 32768)).hexdigest():
                raise ValueError('Android TLS CA hash changed after planning')
        data = private_file(output / 'config.json', 1 << 20)
        metadata = json.loads(private_file(output / 'metadata.json', 32768))
        if not isinstance(metadata, dict):
            raise ValueError('Android TLS metadata must be an object')
        if (type(metadata.get('version')) is not int or metadata['version'] != 1 or metadata.get('mode') != mode or
                metadata.get('configSHA256') != hashlib.sha256(data).hexdigest() or
                metadata.get('sourceSHA256') != source_hash or
                not isinstance(metadata.get('preparedSHA256'), str) or
                not re.fullmatch('[0-9a-f]{64}', metadata['preparedSHA256']) or
                any(type(metadata.get(key)) is not int or metadata[key] != value for key, value in ports.items()) or
                metadata.get('certificateAssetsDirectory') != str(assets) or metadata.get('caFiles') != certificates or
                not isinstance(metadata.get('managedInboundTag'), str) or not metadata['managedInboundTag'] or
                metadata.get('username') != 'session-user' or metadata.get('password') != 'session-password'):
            raise ValueError('Android TLS native-output provenance or listener binding changed')
        summaries.append({key: metadata[key] for key in
                          ('version', 'mode', 'configSHA256', 'sourceSHA256', 'preparedSHA256', *ports)})
        summaries[-1]['caSHA256'] = [record['sha256'] for record in certificates]
    return summaries


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-runtime', action='store_true')
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--go', default='go')
    args = parser.parse_args(argv)
    if args.self_test:
        if args.run_runtime:
            parser.error('Self-tests cannot authorize actual runtime')
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(AndroidChainRunnerTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    # This precedes all evidence directories, Go and Gradle invocations.
    if not args.run_runtime or not authorized():
        parser.error('Actual Android chain requires --run-runtime and Linux CI=true/GITHUB_ACTIONS=true')
    if EVIDENCE.exists():
        parser.error('Evidence already exists; preserve it before a fresh run')
    os.umask(0o077)
    EVIDENCE.mkdir(parents=True)
    before = source_snapshot()
    metadata_path = ROOT / 'example/android/gradle/verification-metadata.xml'
    metadata_before = metadata_path.read_bytes()
    kotlin_cache_before = (ROOT / 'example/android/.kotlin').exists()
    report = {'success': False, 'selected_test': TEST, 'selected_tls_test': TLS_TEST,
              'source_sha256': before, 'results': [],
              'scope': 'ordinary pinned Core using exact actual Android preparation+manager output; IPv4 double SOCKS and XHTTP TLS/h2 only, no TUN/device'}
    source = source_before = copied_before = None
    previous_handlers = {}
    try:
        for number in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[number] = signal.signal(number, interrupted)
        environment = helpers.child_environment(os.environ)
        go = str(Path(shutil.which(args.go) or args.go).resolve())
        mobile = EVIDENCE / 'Mobile'
        mobile.mkdir()
        for path in (ROOT / 'third_party/xray-mobile').iterdir():
            if path.is_file() and (path.suffix == '.go' or path.name in ('go.mod', 'go.sum')):
                shutil.copyfile(path, mobile / path.name)
        shutil.copytree(ROOT / 'third_party/xray-mobile/native_dns_preservation', mobile / 'native_dns_preservation')
        copied_before = helpers.tree_snapshot(mobile)
        run = lambda name, command, seconds=30, runtime=False: checked(name, command, cwd=mobile,
            environment=environment, seconds=seconds, results=report['results'], runtime=runtime)
        manifest = json.loads(MANIFEST_PATH.read_text())
        run('core-pin', [go, 'mod', 'download', '-json', manifest['module'] + '@' + manifest['module_version']], 180)
        pin = json.loads((EVIDENCE / 'core-pin.log').read_text())
        source = helpers.validate_metadata(manifest, pin)
        source_before = helpers.tree_snapshot(source)
        for name, digest in manifest['upstream_sha256'].items():
            if helpers.digest(source / name) != digest:
                raise ValueError('Pinned ordinary Core upstream source differs: ' + name)
        run('core-selection', [go, 'list', '-m', '-json', manifest['module']])
        selected = json.loads((EVIDENCE / 'core-selection.log').read_text())
        if selected.get('Replace') or helpers.validate_metadata(manifest, selected) != source:
            raise ValueError('Runtime must select the unchanged ordinary pinned Core module')
        report['ordinary_core'] = {key: selected[key] for key in ('Path', 'Version', 'Sum')}
        binary = EVIDENCE / 'android-chain.test'
        run('runtime-compile', [go, 'test', '-mod=readonly', '-c', '-o', str(binary), './native_dns_preservation'], 300)
        environment.update(ANDROID_LOGICAL_CHAIN_REPO=str(ROOT), ANDROID_LOGICAL_CHAIN_EVIDENCE=str(EVIDENCE),
                           ANDROID_LOGICAL_CHAIN_PYTHON=str(Path(sys.executable).resolve()))
        run('actual-android-chain', [str(binary), '-test.run=^' + TEST + '$', '-test.v', '-test.timeout=200s'], 215, runtime=True)
        verify_runtime((EVIDENCE / 'actual-android-chain.log').read_text(), report['results'][-1])
        report['native_export'] = verify_export(EVIDENCE / 'export-pair')
        run('actual-android-xhttp-tls', [str(binary), '-test.run=^' + TLS_TEST + '$', '-test.v', '-test.timeout=240s'], 255, runtime=True)
        verify_tls_runtime((EVIDENCE / 'actual-android-xhttp-tls.log').read_text(), report['results'][-1])
        report['native_tls_exports'] = verify_tls_exports(EVIDENCE / 'xhttp-tls')
        report['success'] = True
    except (OSError, ValueError, RuntimeError, KeyError, helpers.Interrupted) as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        report['source_unchanged'] = source_snapshot() == before
        report['android_verification_metadata_restored'] = metadata_path.read_bytes() == metadata_before
        if not kotlin_cache_before and (ROOT / 'example/android/.kotlin').exists():
            shutil.rmtree(ROOT / 'example/android/.kotlin')
        report['new_kotlin_cache_removed'] = kotlin_cache_before or not (ROOT / 'example/android/.kotlin').exists()
        if source is not None and source_before is not None:
            report['ordinary_core_cache_unchanged'] = helpers.tree_snapshot(source) == source_before
        if copied_before is not None:
            report['copied_mobile_source_unchanged'] = helpers.tree_snapshot(EVIDENCE / 'Mobile') == copied_before
        for key in ('source_unchanged', 'android_verification_metadata_restored', 'new_kotlin_cache_removed', 'ordinary_core_cache_unchanged', 'copied_mobile_source_unchanged'):
            if not report.get(key):
                report['success'] = False
        (EVIDENCE / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        for number, handler in previous_handlers.items():
            signal.signal(number, handler)
    return 0 if report['success'] else 1


class AndroidChainRunnerTests(unittest.TestCase):
    def good_log(self):
        return '    fixture.go:1: ' + MARKER + '\n--- PASS: ' + TEST + ' (0.01s)\nPASS\n'

    def good_result(self):
        return {'exit_code': 0, 'process_exit_code': 0, 'timed_out': False,
                'output_eof': True, 'output_closed': True, 'output_errors': []}

    def good_tls_log(self):
        body = ''.join('    ' + TLS_SOURCE + ':123: ' + TLS_MARKER + ' mode=' + mode + '\n' +
                       '    --- PASS: ' + TLS_TEST + '/' + mode + ' (0.01s)\n' for mode in TLS_MODES)
        return body + '--- PASS: ' + TLS_TEST + ' (0.03s)\nPASS\n'

    def make_tls_exports(self, directory):
        directory.mkdir(mode=0o700)
        entries = []

        def write(path, data):
            path.write_bytes(data)
            path.chmod(0o600)

        for index, mode in enumerate(TLS_MODES):
            owned = directory / mode; owned.mkdir(mode=0o700)
            assets = owned / 'assets'; assets.mkdir(mode=0o700)
            output = owned / 'export'; output.mkdir(mode=0o700)
            source = json.dumps({'syntheticSource': mode}).encode()
            config = json.dumps({'syntheticNativeOutput': mode}).encode()
            write(owned / 'source.json', source)
            write(output / 'config.json', config)
            certificates = []
            for role in ('upload', 'download'):
                path = assets / (role + '-ca.pem')
                data = ('synthetic CA bytes ' + mode + role).encode()
                write(path, data)
                certificates.append({'path': str(path), 'sha256': hashlib.sha256(data).hexdigest()})
            ports = {'privatePort': 18100 + index * 10, 'uploadPort': 18101 + index * 10,
                     'downloadPort': 18102 + index * 10}
            entry = {'mode': mode, 'sourcePath': str(owned / 'source.json'),
                     'sourceSHA256': hashlib.sha256(source).hexdigest(), 'outputDirectory': str(output),
                     'certificateAssetsDirectory': str(assets), 'caFiles': certificates, **ports}
            entries.append(entry)
            metadata = {'version': 1, 'mode': mode, 'sourceSHA256': entry['sourceSHA256'],
                        'preparedSHA256': 'b' * 64, 'configSHA256': hashlib.sha256(config).hexdigest(),
                        'certificateAssetsDirectory': str(assets), 'caFiles': certificates, **ports,
                        'managedInboundTag': 'generated-native-input',
                        'username': 'session-user', 'password': 'session-password'}
            write(output / 'metadata.json', json.dumps(metadata).encode())
        manifest = {'version': 1, 'entries': entries}
        write(directory / 'manifest.json', json.dumps(manifest).encode())
        return manifest

    def test_tls_requires_each_exact_source_marker_and_selected_mode(self):
        good = self.good_tls_log()
        verify_tls_runtime(good, self.good_result())
        for body in (good.replace('mode=wrong_ca', 'mode=wrong_sni'),
                     good.replace(TLS_SOURCE, 'stale_fixture.go'),
                     good.replace(TLS_MARKER, TLS_MARKER + '_OLD'),
                     good + '    ' + TLS_SOURCE + ':123: ' + TLS_MARKER + ' mode=independent\n',
                     good.replace('    ' + TLS_SOURCE + ':123: ' + TLS_MARKER + ' mode=wrong_sni\n', ''),
                     good.replace('--- PASS: ' + TLS_TEST + '/wrong_ca', '--- SKIP: ' + TLS_TEST + '/wrong_ca'),
                     good.replace('--- PASS: ' + TLS_TEST + '/wrong_ca', '--- PASS: stale_test/wrong_ca'),
                     good + '--- FAIL: owned_refusal_cleanup (0.01s)\n',
                     good.removesuffix('PASS\n')):
            with self.subTest(body=body), self.assertRaises(ValueError):
                verify_tls_runtime(body, self.good_result())

    def test_tls_rejects_partial_or_unsuccessful_output(self):
        for key, value in [('exit_code', 1), ('process_exit_code', 1), ('timed_out', True),
                           ('output_eof', False), ('output_closed', False), ('output_errors', ['failure'])]:
            result = self.good_result(); result[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                verify_tls_runtime(self.good_tls_log(), result)
        result = self.good_result(); del result['output_eof']
        with self.assertRaises(ValueError):
            verify_tls_runtime(self.good_tls_log(), result)

    def test_tls_export_binds_exact_mode_source_ports_ca_and_native_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            owned = Path(directory) / 'xhttp-tls'
            self.make_tls_exports(owned)
            summary = verify_tls_exports(owned)
            self.assertEqual([row['mode'] for row in summary], list(TLS_MODES))
            self.assertTrue(all(len(row['caSHA256']) == 2 for row in summary))
            rendered = json.dumps(summary)
            self.assertNotIn('session-password', rendered)
            self.assertNotIn('syntheticNativeOutput', rendered)
            self.assertNotIn(str(owned), rendered)

    def test_tls_export_rejects_stale_retargeted_or_omitted_inputs(self):
        for defect in ('source', 'config', 'ca', 'source-hash', 'prepared-hash', 'port', 'ca-binding',
                       'retarget', 'missing', 'duplicate', 'foreign-mode', 'credentials', 'permission', 'symlink'):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as directory:
                owned = Path(directory) / 'xhttp-tls'
                manifest = self.make_tls_exports(owned)
                output = owned / 'wrong_ca/export'
                metadata = json.loads((output / 'metadata.json').read_text())
                if defect in ('source', 'config', 'ca'):
                    path = {'source': owned / 'wrong_ca/source.json', 'config': output / 'config.json',
                            'ca': owned / 'wrong_ca/assets/download-ca.pem'}[defect]
                    path.write_bytes(path.read_bytes() + b' ')
                elif defect == 'source-hash': metadata['sourceSHA256'] = '0' * 64
                elif defect == 'prepared-hash': metadata['preparedSHA256'] = None
                elif defect == 'port': metadata['privatePort'] += 1
                elif defect == 'ca-binding': metadata['caFiles'][1]['sha256'] = '0' * 64
                elif defect == 'retarget': manifest['entries'][1]['outputDirectory'] = str(owned / 'independent/export')
                elif defect == 'missing': manifest['entries'].pop()
                elif defect == 'duplicate': manifest['entries'][2] = manifest['entries'][1]
                elif defect == 'foreign-mode': metadata['mode'] = 'independent'
                elif defect == 'credentials': metadata['password'] = 'stale-password'
                elif defect == 'permission': (output / 'config.json').chmod(0o644)
                elif defect == 'symlink':
                    path = output / 'config.json'; other = output / 'old-config.json'
                    path.rename(other); path.symlink_to(other.name)
                (owned / 'manifest.json').write_text(json.dumps(manifest))
                (output / 'metadata.json').write_text(json.dumps(metadata))
                with self.assertRaises(ValueError):
                    verify_tls_exports(owned)

    def test_interrupt_uses_the_actual_shared_exception(self):
        with self.assertRaises(helpers.Interrupted):
            interrupted(signal.SIGTERM, None)

    def test_gradle_cache_directory_is_not_a_source_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.gradle').mkdir()
            (root / 'build.gradle').write_text('synthetic')
            (root / 'settings.gradle.kts').write_text('synthetic')
            self.assertEqual([path.name for path in gradle_source_files(root)], ['build.gradle', 'settings.gradle.kts'])

    def test_runtime_authorization_precedes_children_and_files(self):
        for environment, system, argv in [({}, 'Linux', ['--run-runtime']),
            ({'CI': 'true'}, 'Linux', ['--run-runtime']),
            ({'CI': 'true', 'GITHUB_ACTIONS': 'true'}, 'Darwin', ['--run-runtime']),
            ({'CI': 'true', 'GITHUB_ACTIONS': 'true'}, 'Linux', [])]:
            with self.subTest(system=system, argv=argv), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / 'absent'
                with patch.dict(os.environ, environment, clear=True), patch.object(platform, 'system', return_value=system), \
                     patch.object(sys.modules[__name__], 'EVIDENCE', output), patch.object(common, 'checked') as child, \
                     contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        main(argv)
                child.assert_not_called()
                self.assertFalse(output.exists())

    def test_exact_marker_and_full_selected_pass(self):
        verify_runtime(self.good_log(), self.good_result())
        for log in ('', self.good_log().replace(MARKER, MARKER + '0'), self.good_log() + self.good_log(),
                    self.good_log().replace('--- PASS:', '--- SKIP:'), self.good_log() + '--- FAIL: other\n'):
            with self.subTest(log=log), self.assertRaises(ValueError):
                verify_runtime(log, self.good_result())

    def test_exit_and_complete_output_are_required(self):
        for key, value in [('exit_code', 1), ('output_eof', False), ('output_closed', False), ('output_errors', ['failure'])]:
            result = self.good_result(); result[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                verify_runtime(self.good_log(), result)

    def test_owned_runtime_gets_cooperative_interrupt_before_hard_cleanup(self):
        child = Mock(pid=4321); child.poll.return_value = None
        with patch.object(os, 'killpg') as kill, patch.object(sys.modules[__name__], 'HARD_STOP') as hard:
            stop_runtime(child)
        kill.assert_called_once_with(4321, signal.SIGINT)
        child.wait.assert_called_once_with(timeout=12)
        hard.assert_called_once_with(child)

    def test_owned_runtime_timeout_still_hard_reaps(self):
        child = Mock(pid=4321); child.poll.return_value = None
        child.wait.side_effect = subprocess.TimeoutExpired('owned', 12)
        with patch.object(os, 'killpg'), patch.object(sys.modules[__name__], 'HARD_STOP') as hard:
            stop_runtime(child)
        self.assertTrue(hard.called)
        self.assertTrue(all(call.args == (child,) for call in hard.call_args_list))

    def test_interrupted_checked_call_restores_cleanup_hook(self):
        original = common.stop_owned_process
        def interrupted_call(*args, **kwargs):
            self.assertIs(common.stop_owned_process, stop_runtime)
            raise KeyboardInterrupt()
        with patch.object(common, 'checked', side_effect=interrupted_call):
            with self.assertRaises(KeyboardInterrupt):
                checked('actual', [], cwd=ROOT, environment={}, seconds=1, results=[], runtime=True)
        self.assertIs(common.stop_owned_process, original)

    def test_native_export_hash_is_not_retargeted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); data = b'{"synthetic":true}'
            (root / 'config.json').write_bytes(data)
            metadata = {'version': 1, 'configSHA256': hashlib.sha256(data).hexdigest(),
                        'sourceSHA256': 'a' * 64, 'preparedSHA256': 'b' * 64, 'privatePort': 10807, 'outerPort': 19090}
            (root / 'metadata.json').write_text(json.dumps(metadata))
            self.assertEqual(verify_export(root)['configSHA256'], metadata['configSHA256'])
            (root / 'config.json').write_bytes(data + b' ')
            with self.assertRaises(ValueError):
                verify_export(root)

    def test_main_runs_both_bounded_wire_phases_from_one_compiled_binary(self):
        # Exercise the actual main dispatch with inert commands and private temp
        # files. A successful old-chain phase cannot qualify the new TLS phase.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mobile = root / 'third_party/xray-mobile'
            (mobile / 'native_dns_preservation').mkdir(parents=True)
            (mobile / 'go.mod').write_text('module inert')
            (mobile / 'native_dns_preservation/inert_test.go').write_text('package inert')
            metadata = root / 'example/android/gradle/verification-metadata.xml'
            metadata.parent.mkdir(parents=True)
            metadata.write_text('unchanged')
            manifest = root / 'pin.json'
            manifest.write_text(json.dumps({'module': 'inert/core', 'module_version': 'v1', 'upstream_sha256': {}}))
            output = root / 'evidence'
            cache = root / 'cache'; cache.mkdir()
            commands = []

            def fake_checked(name, command, **options):
                commands.append((name, command, options['seconds'], options.get('runtime', False)))
                options['results'].append({'name': name, **self.good_result(),
                                          'process_exit_code': 0, 'timed_out': False})
                if name in ('core-pin', 'core-selection'):
                    body = json.dumps({'Path': 'inert/core', 'Version': 'v1', 'Sum': 'inert', 'Dir': str(cache)})
                elif name == 'actual-android-chain':
                    body = self.good_log()
                    pair = output / 'export-pair'; pair.mkdir()
                    data = b'{"synthetic":true}'
                    (pair / 'config.json').write_bytes(data)
                    (pair / 'metadata.json').write_text(json.dumps({'version': 1,
                        'configSHA256': hashlib.sha256(data).hexdigest(), 'sourceSHA256': 'a' * 64,
                        'preparedSHA256': 'b' * 64, 'privatePort': 10807, 'outerPort': 19090}))
                elif name == 'actual-android-xhttp-tls':
                    body = self.good_tls_log()
                    self.make_tls_exports(output / 'xhttp-tls')
                else:
                    body = ''
                (output / (name + '.log')).write_text(body)

            module = sys.modules[__name__]
            with patch.object(module, 'ROOT', root), patch.object(module, 'EVIDENCE', output), \
                 patch.object(module, 'MANIFEST_PATH', manifest), patch.object(module, 'authorized', return_value=True), \
                 patch.object(module, 'source_snapshot', return_value={'inert': 'unchanged'}), \
                 patch.object(module, 'checked', side_effect=fake_checked), \
                 patch.object(module, 'verify_tls_runtime', wraps=verify_tls_runtime) as verify_tls, \
                 patch.object(module, 'verify_tls_exports', wraps=verify_tls_exports) as verify_exports, \
                 patch.object(helpers, 'validate_metadata', return_value=cache), \
                 patch.object(helpers, 'tree_snapshot', return_value={'inert': 'unchanged'}), \
                 patch.object(shutil, 'which', return_value='/inert/go'):
                self.assertEqual(main(['--run-runtime']), 0)
            verify_tls.assert_called_once()
            self.assertEqual(verify_tls.call_args.args[0], self.good_tls_log())
            verify_exports.assert_called_once_with(output / 'xhttp-tls')
            report = json.loads((output / 'result.json').read_text())
            self.assertEqual(report['selected_tls_test'], TLS_TEST)
            self.assertEqual([row['mode'] for row in report['native_tls_exports']], list(TLS_MODES))
            for key in ('source_unchanged', 'android_verification_metadata_restored',
                        'new_kotlin_cache_removed', 'ordinary_core_cache_unchanged', 'copied_mobile_source_unchanged'):
                self.assertIs(report[key], True)
            compile_commands = [row for row in commands if row[0] == 'runtime-compile']
            self.assertEqual(len(compile_commands), 1)
            phases = [row for row in commands if row[3]]
            binary = str(output / 'android-chain.test')
            self.assertEqual(phases, [
                ('actual-android-chain', [binary, '-test.run=^TestAndroidLogicalChainRuntime$', '-test.v', '-test.timeout=200s'], 215, True),
                ('actual-android-xhttp-tls', [binary, '-test.run=^TestAndroidXHTTPTLSRuntime$', '-test.v', '-test.timeout=240s'], 255, True)])

    def test_inherited_core_and_browser_environment_is_sanitized(self):
        environment = helpers.child_environment({'XRAY_LOCATION_ASSET': 'outside', 'xray.browser.dialer': 'outside', 'KEEP': 'yes'})
        self.assertNotIn('XRAY_LOCATION_ASSET', environment)
        self.assertEqual(environment['xray.browser.dialer'], '')
        self.assertEqual(environment['XRAY_BROWSER_DIALER'], '')
        self.assertEqual(environment['KEEP'], 'yes')


if __name__ == '__main__':
    raise SystemExit(main())
