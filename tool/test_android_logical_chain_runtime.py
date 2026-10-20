#!/usr/bin/env python3
"""One actual Android-native-output SOCKS chain, only in Linux GitHub CI."""
from __future__ import annotations

import argparse
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
    report = {'success': False, 'selected_test': TEST, 'source_sha256': before, 'results': [],
              'scope': 'ordinary pinned Core using exact actual Android preparation+manager output; local IPv4 double SOCKS only, no TUN/device'}
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
        return {'exit_code': 0, 'output_eof': True, 'output_closed': True, 'output_errors': []}

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

    def test_inherited_core_and_browser_environment_is_sanitized(self):
        environment = helpers.child_environment({'XRAY_LOCATION_ASSET': 'outside', 'xray.browser.dialer': 'outside', 'KEEP': 'yes'})
        self.assertNotIn('XRAY_LOCATION_ASSET', environment)
        self.assertEqual(environment['xray.browser.dialer'], '')
        self.assertEqual(environment['XRAY_BROWSER_DIALER'], '')
        self.assertEqual(environment['KEEP'], 'yes')


if __name__ == '__main__':
    raise SystemExit(main())
