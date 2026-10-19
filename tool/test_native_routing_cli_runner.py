#!/usr/bin/env python3
"""File-only guards for the additive routing CLI build/Check verifier."""
import contextlib
import errno
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('routing_cli_guard_subject', ROOT / 'tool/test_native_routing_cli.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class RoutingCLIRunnerTest(unittest.TestCase):
    def test_no_runtime_option_before_files_or_children(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / 'absent'
            with patch.object(runner, 'EVIDENCE', evidence), patch.object(runner.core_runner, 'checked') as child, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    runner.main(['--run-runtime'])
            child.assert_not_called()
            self.assertFalse(evidence.exists())

    def test_execution_allowlist_never_admits_constructor_commands(self):
        for command in [['version'], ['native-routing', 'capabilities'], ['native-routing', 'check', '--config', '/config', '--spec', '/spec']]:
            self.assertEqual(runner.safe_cli_args(command), command)
        for command in [[], ['run'], ['run', '-test'], ['native-routing', 'run'], ['native-routing', 'check'], ['native-routing', 'check', '--config', '/config', '--spec', '/spec', 'extra']]:
            with self.subTest(command=command), self.assertRaises(ValueError):
                runner.safe_cli_args(command)

    def test_exact_pure_selection_excludes_runtime(self):
        self.assertEqual(runner.MAIN_TESTS, [
            'TestNativeRoutingCLIStockLogger', 'TestNativeRoutingCLIRegisteredOnce',
            'TestNativeRoutingCLIParentInputLifecycle', 'TestNativeRoutingCLIParentInputRefusal',
            'TestNativeRoutingCLIParentInputGrammar', 'TestNativeRoutingCLIParentInputOrdinaryForeground',
        ])
        pattern = runner.core_runner.test_pattern(runner.MAIN_TESTS)
        import re
        for name in runner.MAIN_TESTS:
            self.assertRegex(name, pattern)
        self.assertIsNone(re.search(pattern, 'TestNativeRoutingCLIRuntime'))
        self.assertTrue(runner.NATIVE_TESTS)
        self.assertTrue(all(name.startswith('TestNativeCLI') and 'Runtime' not in name for name in runner.NATIVE_TESTS))

    def test_expected_nonzero_requires_real_exit_and_complete_eof(self):
        valid = {'name': 'expected', 'exit_code': 17, 'process_exit_code': 17, 'output_closed': True, 'output_eof': True, 'timed_out': False, 'output_errors': []}
        runner.validate_phase(valid, 17)
        for change in [{'exit_code': 0}, {'process_exit_code': 0}, {'output_closed': False}, {'output_eof': False}, {'timed_out': True}, {'output_errors': ['sink failed']}, {'exit_code': 126}]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                runner.validate_phase(dict(valid, **change), 17)

    def test_expected_nonzero_cannot_hide_output_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            results = []
            def child(name, command, **kwargs):
                results.append({'name': name, 'exit_code': 17, 'process_exit_code': 17, 'output_closed': True, 'output_eof': True, 'timed_out': False, 'output_errors': ['write failed']})
                raise RuntimeError('child failed')
            with patch.object(runner, 'EVIDENCE', Path(directory)), patch.object(runner.core_runner, 'checked', side_effect=child), self.assertRaises(RuntimeError):
                runner.checked('refused', ['inert'], cwd=Path(directory), environment={}, seconds=1, results=results, expected=17)
            self.assertNotIn('expected_exit_matched', results[-1])

    def test_complete_expected_refusal_is_recorded_without_losing_status(self):
        results = []
        def child(name, command, **kwargs):
            results.append({'name': name, 'exit_code': 32, 'process_exit_code': 32, 'output_closed': True, 'output_eof': True, 'timed_out': False, 'output_errors': []})
            raise RuntimeError('expected native refusal')
        with patch.object(runner.core_runner, 'checked', side_effect=child):
            runner.checked('capability', ['inert'], cwd=ROOT, environment={}, seconds=1, results=results, expected=32)
        self.assertEqual(results[-1]['exit_code'], 32)
        self.assertEqual(results[-1]['process_exit_code'], 32)
        self.assertTrue(results[-1]['expected_exit_matched'])

    def test_tidy_fallback_does_not_hide_module_cycles_or_other_failures(self):
        refusal = 'go: updates to go.mod needed; to update it:\n\tgo mod tidy\n'
        self.assertTrue(runner.tidy_required(refusal))
        for text in ['import cycle not allowed', 'missing go.sum entry', refusal + 'import cycle not allowed\n', 'unrelated error\n' + refusal]:
            self.assertFalse(runner.tidy_required(text))

    def test_status_json_is_exact_and_single_document(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            wanted = {'stage': 'check', 'code': 17}
            with patch.object(runner, 'EVIDENCE', evidence):
                for document in [wanted, dict(wanted, raw='secret'), dict(wanted, code=0), [wanted]]:
                    (evidence / 'case.log').write_text(json.dumps(document) + '\n')
                    if document == wanted:
                        runner.require_status('case', wanted)
                    else:
                        with self.assertRaises(ValueError):
                            runner.require_status('case', wanted)
                (evidence / 'case.log').write_text(json.dumps(wanted) + '\n' + json.dumps(wanted))
                with self.assertRaises(ValueError):
                    runner.require_status('case', wanted)

    def test_copies_are_separate_before_module_edits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'verified-Core'; source.mkdir()
            (source / 'go.mod').write_text('module core\n')
            (source / 'fixture.go').write_text('package core\n')
            mobile = root / 'mobile'; mobile.mkdir()
            (mobile / 'go.mod').write_text('module mobile\n')
            (mobile / 'go.sum').write_text('fixed sum\n')
            (mobile / 'factory.go').write_text('package XRay\n')
            (mobile / 'nativecli').mkdir()
            (mobile / 'nativecli/cli.go').write_text('package nativecli\n')
            evidence = root / 'evidence'; evidence.mkdir()
            with patch.object(runner, 'MOBILE', mobile), patch.object(runner, 'EVIDENCE', evidence):
                core_copy, mobile_copy = runner.copy_inputs(source)
            (core_copy / 'go.mod').write_text('edited copy\n')
            (mobile_copy / 'go.mod').write_text('edited mobile copy\n')
            self.assertEqual((source / 'go.mod').read_text(), 'module core\n')
            self.assertEqual((mobile / 'go.mod').read_text(), 'module mobile\n')
            self.assertEqual((mobile_copy / 'nativecli/cli.go').read_text(), 'package nativecli\n')
            self.assertNotEqual(core_copy.resolve(), source.resolve())

    def test_mobile_input_symlink_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'Core'; source.mkdir()
            (source / 'go.mod').write_text('module core\n')
            mobile = root / 'mobile'; mobile.mkdir()
            (mobile / 'go.mod').write_text('module mobile\n')
            (mobile / 'go.sum').write_text('sum\n')
            (mobile / 'nativecli').mkdir()
            try:
                (mobile / 'factory.go').symlink_to(source / 'go.mod')
            except OSError as error:
                if error.errno in (errno.EPERM, errno.EACCES, errno.ENOSYS, errno.ENOTSUP) or getattr(error, 'winerror', None) in (50, 1314):
                    self.skipTest('Runner does not permit creating the negative symlink fixture')
                raise
            evidence = root / 'evidence'; evidence.mkdir()
            with patch.object(runner, 'MOBILE', mobile), patch.object(runner, 'EVIDENCE', evidence), self.assertRaises(ValueError):
                runner.copy_inputs(source)

    def test_missing_prerequisite_fails_before_children(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / 'evidence'
            with patch.object(runner, 'EVIDENCE', evidence), patch.object(runner.factory, 'checked_core', side_effect=ValueError('stale receipt')), patch.object(runner, 'inputs', return_value={}), patch.object(runner.core_runner, 'checked') as child:
                self.assertEqual(runner.main([]), 1)
            child.assert_not_called()
            report = json.loads((evidence / 'result.json').read_text())
            self.assertFalse(report['success'])
            self.assertFalse(report['runtime_executed'])

    def test_existing_evidence_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            (evidence / 'keep').write_text('previous')
            with patch.object(runner, 'EVIDENCE', evidence), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    runner.main([])
            self.assertEqual((evidence / 'keep').read_text(), 'previous')


if __name__ == '__main__':
    unittest.main()
