#!/usr/bin/env python3
"""File-only and log-admission tests; never call Go, Core, VPN or OS firewall."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('core31_followup_subject', Path(__file__).with_name('test_core31_followups.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def sample_log(group):
    """Go -test.v-shaped positive witness, then mutate one contract at a time."""
    lines = ['=== RUN   '+group['tests'][0]]
    for source, marker in runner.marker_patterns(group['name']):
        marker = marker.replace(r'\d+', '1024').replace('(?:build|start)', 'start').replace(r'\.', '.').replace(r'\-', '-')
        lines.append('    '+source+':42: '+marker)
    lines.extend('--- PASS: '+name+' (0.01s)' for name in group['passes'])
    return '\n'.join(lines)+'\nPASS\n'


class Core31EvidenceAdmission(unittest.TestCase):
    def group(self, name='geodat'):
        return next(group for group in runner.groups('Windows') if group['name'] == name)

    def test_all_reviewed_groups_accept_complete_evidence_and_crlf(self):
        for group in runner.groups('Windows'):
            with self.subTest(group=group['name']):
                report = runner.qualify(sample_log(group), group)
                self.assertTrue(report['no_skips'])
                self.assertEqual(report['test_and_subtest_PASS_count'], len(group['passes']))
                runner.qualify(sample_log(group).replace('\n', '\r\n'), group)

    def test_reviewed_scope_counts_and_windows_applicability(self):
        self.assertEqual({g['name']: len(g['passes']) for g in runner.groups('Windows')}, {
            'examples': 8, 'geodat': 14, 'xhttp': 10, 'xhttp-admission': 1,
            'http-continue': 6, 'quic': 60, 'windows-core-tun-wfp': 1})
        for system in ['Linux', 'Darwin']:
            group = next(g for g in runner.groups(system) if g['name'] == 'windows-core-tun-wfp')
            self.assertFalse(group['applicable'])
        self.assertTrue(self.group('windows-core-tun-wfp')['applicable'])

    def test_empty_and_no_test_selection_are_not_passes(self):
        for output in ['', '\nPASS\n', 'testing: warning: no tests to run\nPASS\n']:
            with self.subTest(output=output), self.assertRaises(ValueError):
                runner.qualify(output, self.group())

    def test_stale_other_group_log_is_rejected(self):
        with self.assertRaises(ValueError):
            runner.qualify(sample_log(self.group('quic')), self.group())

    def test_skipped_or_failed_subtest_cannot_be_hidden_by_terminal_pass(self):
        group = self.group()
        original = sample_log(group)
        child = group['passes'][4]
        for status in ['SKIP', 'FAIL']:
            changed = original.replace('--- PASS: '+child, '--- '+status+': '+child)
            with self.subTest(status=status), self.assertRaises(ValueError):
                runner.qualify(changed, group)

    def test_missing_duplicate_or_unexpected_test_pass_is_rejected(self):
        group = self.group('quic')
        output = sample_log(group)
        line = '--- PASS: '+group['passes'][-1]+' (0.01s)\n'
        for changed in [output.replace(line, ''), output.replace(line, line+line),
                        output.replace('\nPASS\n', '\n--- PASS: TestUnrelated (0.01s)\nPASS\n')]:
            with self.subTest(changed=changed[-200:]), self.assertRaises(ValueError):
                runner.qualify(changed, group)

    def test_truncated_or_missing_final_output_is_rejected(self):
        group = self.group()
        output = sample_log(group)
        for changed in [output.removesuffix('PASS\n'), output+'late worker output\n', output.replace('\nPASS\n', '\nFAIL\n')]:
            with self.subTest(tail=changed[-80:]), self.assertRaises(ValueError):
                runner.qualify(changed, group)

    def test_marker_must_come_from_exact_fixture_and_have_exact_fields(self):
        group = self.group('windows-core-tun-wfp')
        output = sample_log(group)
        for changed in [output.replace('native_core31_wfp_windows_test.go:', 'unrelated.go:'),
                        output.replace('cases=8', 'cases=4'),
                        output.replace('filters_delta=0', 'filters_delta=1'),
                        output.replace('CORE31_WFP_SELF_EXEMPT_PASS', 'CORE31_WFP_SELF_EXEMPT_PASS extra=true')]:
            with self.subTest(tail=changed[-400:]), self.assertRaises(ValueError):
                runner.qualify(changed, group)

    def test_missing_or_duplicate_marker_is_not_a_pass(self):
        group = self.group('http-continue')
        output = sample_log(group)
        marker = next(line for line in output.splitlines(keepends=True) if 'mode=cancelled_origin' in line)
        for changed in [output.replace(marker, ''), output.replace(marker, marker+marker)]:
            with self.assertRaises(ValueError):
                runner.qualify(changed, group)

    def test_admission_marker_requires_valid_sibling_settings(self):
        group = self.group('xhttp-admission')
        with self.assertRaises(ValueError):
            runner.qualify(sample_log(group).replace(' valid_settings=true', ''), group)

    def test_examples_require_each_exact_json_name_and_semantics(self):
        group = self.group('examples')
        output = sample_log(group)
        for changed in [output.replace('name=geodat-gzip.json', 'name=geodat-gzipXjson'),
                        output.replace(' semantics=true', ' semantics=false'),
                        output.replace('native_core31_examples_test.go:', 'unrelated.go:')]:
            with self.subTest(changed=changed[:150]), self.assertRaises(ValueError):
                runner.qualify(changed, group)

    def test_successful_child_exit_requires_owned_complete_output(self):
        good = {'exit_code': 0, 'process_exit_code': 0, 'timed_out': False,
                'output_closed': True, 'output_eof': True, 'output_errors': []}
        runner.verify_phase(good)
        for field, wrong in [('exit_code', 1), ('process_exit_code', None), ('timed_out', True),
                             ('output_closed', False), ('output_eof', False), ('output_errors', ['sink failure'])]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                runner.verify_phase(dict(good, **{field: wrong}))

    def test_exact_selection_is_anchored_and_never_empty_or_duplicate(self):
        self.assertEqual(runner.test_pattern(['TestOne', 'TestTwo']), '^(TestOne|TestTwo)$')
        for selected in [[], ['TestOne', 'TestOne']]:
            with self.assertRaises(ValueError):
                runner.test_pattern(selected)


class Core31SourceOwnership(unittest.TestCase):
    def test_pin_requires_all_exact_identities_and_mobile_requirement(self):
        module = 'require '+runner.PIN['module']+' '+runner.PIN['module_version']+'\n'
        sums = runner.PIN['module']+' '+runner.PIN['module_version']+' '+runner.PIN['module_sum']+'\n'
        runner.validate_pin(runner.PIN, module, sums)
        for key in runner.PIN:
            with self.subTest(key=key), self.assertRaises(ValueError):
                runner.validate_pin(dict(runner.PIN, **{key: 'different'}), module, sums)
        for bad_module, bad_sums in [(module.replace('a4a3dff5b20c', 'deadbeef0000'), sums), (module, sums+'suffix') , ('// '+module, sums), (module, '')]:
            # A separate appended line cannot change an already valid exact
            # go.sum line; mutate that line itself when testing trailing data.
            if bad_sums == sums+'suffix':
                bad_sums = sums.rstrip()+' suffix\n'
            with self.assertRaises(ValueError):
                runner.validate_pin(runner.PIN, bad_module, bad_sums)

    def test_download_metadata_rejects_wrong_sum_error_and_missing_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            good = {'Path': runner.PIN['module'], 'Version': runner.PIN['module_version'],
                    'Sum': runner.PIN['module_sum'], 'Dir': directory}
            self.assertEqual(runner.validate_metadata(good), Path(directory).resolve())
            for field, wrong in [('Path', 'wrong'), ('Version', 'old'), ('Sum', 'wrong'),
                                 ('Error', 'download failed'), ('Dir', ''), ('Dir', directory+'/missing')]:
                with self.subTest(field=field), self.assertRaises(ValueError):
                    runner.validate_metadata(dict(good, **{field: wrong}))

    def test_snapshot_detects_changed_added_deleted_and_symlinked_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'source.go'
            path.write_text('original')
            expected = runner.tree_snapshot(root)
            runner.verify_tree(root, expected)
            path.write_text('changed')
            with self.assertRaises(ValueError): runner.verify_tree(root, expected)
            path.write_text('original')
            extra = root/'extra.go'; extra.write_text('extra')
            with self.assertRaises(ValueError): runner.verify_tree(root, expected)
            extra.unlink(); path.unlink()
            with self.assertRaises(ValueError): runner.verify_tree(root, expected)
            if hasattr(Path, 'symlink_to'):
                try: path.symlink_to(root/'missing')
                except OSError: pass  # Windows runner may lack symlink privilege.
                else:
                    with self.assertRaises(ValueError): runner.tree_snapshot(root)

    def test_existing_identical_copier_helper_is_verified_but_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root/'fixture.go'; source.write_text('new exact fixture')
            core = root/'Core'; core.mkdir()
            runner.copy_fixture(source, core, 'app/geodata/fixture.go')
            target = core/'app/geodata/fixture.go'
            runner.copy_fixture(source, core, 'app/geodata/fixture.go')
            target.write_text('foreign collision')
            with self.assertRaises(ValueError): runner.copy_fixture(source, core, 'app/geodata/fixture.go')
            self.assertEqual(target.read_text(), 'foreign collision')

    def test_ambient_xray_policy_is_removed_and_module_writes_are_disabled(self):
        environment = runner.child_environment({'PATH': 'kept', 'XRAY_LOCATION_ASSET': 'foreign',
                                                'xray.location.asset': 'foreign', 'GOFLAGS': '-mod=mod'})
        self.assertEqual(environment['PATH'], 'kept')
        self.assertNotIn('XRAY_LOCATION_ASSET', environment)
        self.assertNotIn('xray.location.asset', environment)
        self.assertEqual(environment['GOFLAGS'], '-mod=readonly')
        self.assertEqual(environment['GOTOOLCHAIN'], 'local')


class Core31ExecutionBoundary(unittest.TestCase):
    def test_darwin_requires_actions_even_if_ci_was_set(self):
        self.assertFalse(runner.runtime_authorized({}, 'Darwin'))
        self.assertFalse(runner.runtime_authorized({'CI': 'true'}, 'Darwin'))
        self.assertFalse(runner.runtime_authorized({'GITHUB_ACTIONS': 'true'}, 'Darwin'))
        self.assertTrue(runner.runtime_authorized({'CI': 'true', 'GITHUB_ACTIONS': 'true'}, 'Darwin'))
        self.assertTrue(runner.runtime_authorized({'CI': 'true'}, 'Linux'))
        self.assertTrue(runner.runtime_authorized({'CI': 'true'}, 'Windows'))

    def test_default_mode_runs_only_python_unit_entry(self):
        with patch.object(runner, 'run_units', return_value=0) as units, \
                patch.object(runner.common, 'checked') as checked, \
                patch.object(runner, 'source_snapshot') as snapshot, \
                patch.object(runner.subprocess, 'run') as subprocess_run:
            self.assertEqual(runner.main([]), 0)
            units.assert_called_once_with()
            checked.assert_not_called(); snapshot.assert_not_called(); subprocess_run.assert_not_called()

    def test_unauthorized_runtime_refuses_before_output_or_go(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'new-output'
            with patch.object(runner, 'runtime_authorized', return_value=False), \
                    patch.object(runner.common, 'checked') as checked, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as stopped:
                    runner.main(['--run-runtime', '--output-dir', str(output)])
            self.assertEqual(stopped.exception.code, 2)
            self.assertFalse(output.exists()); checked.assert_not_called()

    def test_stale_output_refuses_and_preserves_every_byte(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'prior'; output.mkdir()
            receipt = output/'result.json'; receipt.write_text(json.dumps({'prior': True}))
            before = receipt.read_bytes()
            with patch.object(runner, 'runtime_authorized', return_value=True), \
                    patch.object(runner.common, 'checked') as checked, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as stopped:
                    runner.main(['--run-runtime', '--output-dir', str(output)])
            self.assertEqual(stopped.exception.code, 2)
            self.assertEqual(receipt.read_bytes(), before); checked.assert_not_called()


if __name__ == '__main__':
    unittest.main()
