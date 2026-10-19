#!/usr/bin/env python3
"""Pure runner guard/command tests; never invokes Core or network."""
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('native_dns_preservation_runner', Path(__file__).with_name('test_native_dns_preservation.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class PreservationRunnerGuards(unittest.TestCase):
    def test_child_environment_disables_core_init_listener_without_parent_mutation(self):
        source = {'PATH': 'keep-toolchain', 'CI': 'true', 'xray.browser.dialer': 'must-not-listen',
                  'XRAY_BROWSER_DIALER': 'must-not-listen', 'Xray_Location_Cert': 'caller-location'}
        before = dict(source)
        result = runner.child_environment(source)
        self.assertEqual(source, before)
        self.assertEqual(result['PATH'], source['PATH'])
        self.assertEqual(result['CI'], 'true')
        self.assertEqual(result['xray.browser.dialer'], '')
        self.assertEqual(result['XRAY_BROWSER_DIALER'], '')
        self.assertNotIn('Xray_Location_Cert', result)
        self.assertEqual(result['GOTOOLCHAIN'], 'local')
        self.assertEqual(result['GOWORK'], 'off')

    def test_runtime_refused_before_any_child_or_evidence(self):
        for system, environment in [('Linux', {}), ('Windows', {}), ('Darwin', {'CI': 'true'})]:
            with self.subTest(system=system), tempfile.TemporaryDirectory() as directory:
                evidence = Path(directory) / 'not-created'
                with mock.patch.object(runner, 'EVIDENCE', evidence), mock.patch.dict(os.environ, environment, clear=True), \
                        mock.patch.object(runner.common.platform, 'system', return_value=system), \
                        mock.patch.object(runner.sys, 'argv', ['runner', '--run-runtime']), \
                        mock.patch.object(runner.common, 'checked') as checked, \
                        mock.patch.object(runner.sys, 'stderr', io.StringIO()), self.assertRaises(SystemExit) as exit_status:
                    runner.main()
                self.assertEqual(exit_status.exception.code, 2)
                checked.assert_not_called()
                self.assertFalse(evidence.exists())

    def test_existing_evidence_is_not_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(runner, 'EVIDENCE', Path(directory)), mock.patch.object(runner.sys, 'argv', ['runner']), \
                    mock.patch.object(runner.sys, 'stderr', io.StringIO()), mock.patch.object(runner.common, 'checked') as checked, \
                    self.assertRaises(SystemExit):
                runner.main()
            checked.assert_not_called()

    def test_windows_batch_has_bounded_trusted_toolchain_commands(self):
        script = runner.msvc_script(Path(r'C:\safe path\dns-preparer.exe'), Path(r'C:\safe path\config-pure.exe'), {})
        self.assertIn('setlocal DisableDelayedExpansion', script)
        self.assertIn('-requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64', script)
        self.assertIn('vcvars64.bat', script)
        self.assertEqual(script.count('cl /nologo /std:c++17'), 2)
        self.assertEqual(script.count('/W4 /WX /DNOMINMAX'), 2)
        self.assertIn('/Fe:"C:\\safe path\\dns-preparer.exe"', script)
        self.assertGreaterEqual(script.count('if errorlevel 1 exit /b 1'), 4)
        self.assertNotIn('acceptance.test', script)

    def test_batch_paths_do_not_expand_environment_or_inject_lines(self):
        self.assertEqual(runner.cmd_path(Path('owned%PATH%file')), '"owned%%PATH%%file"')
        for value in ['bad"path', 'bad\npath', 'bad\rpath']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                runner.cmd_path(Path(value))

    def test_apple_build_only_links_production_json_preparer_without_core(self):
        binary, phases = runner.apple_commands(Path('/owned/test package'))
        self.assertEqual(binary, Path('/owned/test package/apple-dns-preparer'))
        self.assertEqual(len(phases), 3)
        commands = [command for _, command in phases]
        self.assertTrue(all(command[:2] == ['xcrun', 'swiftc'] for command in commands))
        flattened = '\n'.join(argument for command in commands for argument in command)
        self.assertIn('native_dns_preparer.swift', flattened)
        self.assertIn('TunnelDNSPolicy.swift', flattened)
        self.assertNotIn('FlutterVlessPacketTunnelProvider.swift', flattened)
        self.assertNotIn('libXRay', flattened)
        self.assertNotIn('CXRay', flattened)

    def test_actual_success_requires_exact_selected_pass(self):
        for output in ['PASS\n', 'testing: warning: no tests to run\nPASS\n', '--- PASS: OtherTest (0.00s)\nPASS\n']:
            with self.subTest(output=output), self.assertRaises(RuntimeError):
                runner.common.require_selected_test_pass(output, runner.SELECTED_TEST)
        runner.common.require_selected_test_pass('--- PASS: TestNativeDNSPreservation (0.01s)\nPASS\n', runner.SELECTED_TEST)

    def test_default_selects_pure_preparation_without_core_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / 'evidence'
            core = Path(directory) / 'ordinary-core'
            core.mkdir()
            (core / 'guarded.go').write_text('synthetic source')
            manifest = {'module': 'synthetic.invalid/core', 'module_version': 'v1.0.0', 'module_sum': 'synthetic',
                        'upstream_sha256': {'guarded.go': runner.digest(core / 'guarded.go')}}
            commands = []

            def fake_checked(name, command, **kwargs):
                commands.append(command)
                kwargs['results'].append({'name': name, 'exit_code': 0})
                if '-o' in command:
                    Path(command[command.index('-o') + 1]).write_text('synthetic compiled output')
                if name == 'core-pin':
                    (evidence / 'core-pin.log').write_text(json.dumps({'Version': 'v1.0.0', 'Sum': 'synthetic', 'Dir': str(core)}))
                if name == 'protocol-preparation-pure':
                    (evidence / 'protocol-preparation-pure.log').write_text(
                        '--- PASS: TestNativeProtocolPreparation (0.01s)\n--- PASS: TestProtocolCorpusBuilds (0.01s)\n--- PASS: TestNativeDoHMaterialOnly (0.01s)\n--- PASS: TestNativeSelectorPrefixAllocation (0.01s)\n')

            with mock.patch.object(runner, 'EVIDENCE', evidence), mock.patch.object(runner.sys, 'argv', ['runner']), \
                    mock.patch.object(runner.platform, 'system', return_value='Linux'), \
                    mock.patch.object(runner, 'os', SimpleNamespace(name='posix', environ=os.environ, sep=os.sep)), \
                    mock.patch.object(runner.common, 'MANIFEST', manifest), \
                    mock.patch.object(runner, 'source_snapshot', return_value={'synthetic': 'hash'}), \
                    mock.patch.object(runner.common, 'checked', side_effect=fake_checked):
                self.assertEqual(runner.main(), 0)
            self.assertTrue(any('test' in command and '-c' in command for command in commands))
            selections = [command[command.index('-test.run') + 1] for command in commands if '-test.run' in command]
            self.assertEqual(selections, ['^(TestNativeProtocolPreparation|TestProtocolCorpusBuilds|TestNativeDoHMaterialOnly|TestNativeSelectorPrefixAllocation)$'])
            self.assertFalse(any(runner.SELECTED_TEST in selection for selection in selections))
            report = json.loads((evidence / 'result.json').read_text())
            self.assertFalse(report['runtime_requested'])
            self.assertFalse(report['core_overlay_applied'])
            self.assertTrue(report['success'])


if __name__ == '__main__':
    unittest.main()
