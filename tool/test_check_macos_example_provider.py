"""Pure temporary bundle fixtures; no codesign, registry, process or VPN calls."""
import hashlib
import contextlib
import io
import json
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest import mock

import check_macos_example_provider as subject


class ProviderIdentity(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.app = self.root/'Example.app'
        self.provider = self.app/'Contents/PlugIns/XrayTunnel.appex'
        self.provider_id = subject.DEFAULT_BUNDLE_ID + '.XrayTunnel'
        for bundle, bundle_id, executable in [(self.app, subject.DEFAULT_BUNDLE_ID, 'Example'),
                                               (self.provider, self.provider_id, 'XrayTunnel')]:
            (bundle/'Contents/MacOS').mkdir(parents=True)
            (bundle/'Contents/Info.plist').write_bytes(plistlib.dumps({
                'CFBundleIdentifier': bundle_id, 'CFBundleShortVersionString': '1.1.7',
                'CFBundleVersion': '117', 'CFBundleExecutable': executable}))
            (bundle/'Contents/MacOS'/executable).write_bytes(b'inert fixture, never executed')
        self.binary = self.provider/'Contents/MacOS/XrayTunnel'
        self.hash = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.receipt = {'success': True, 'app_path': str(self.app), 'provider_sha256': self.hash}
        self.launched = [{'bundle_id': self.provider_id, 'provider_path': str(self.provider),
                          'provider_sha256': self.hash}]

    def registration(self, path=None, *, version='1.1.7', bundle_id=None):
        return f"     {bundle_id or self.provider_id}({version})\tB1D43268-AD91-45E7-BA01-455BA175B88C\t2026-11-04 18:08:44 +0000\t{path or self.provider}\n"

    def inspect(self, registrations=None, observations=None, **kwargs):
        return subject.inspect(self.receipt, registrations if registrations is not None else self.registration(),
                               self.launched if observations is None else observations,
                               verify_signature=lambda path: True, **kwargs)

    def test_exact_signed_build_registration_and_actual_launch_qualify(self):
        report = self.inspect()
        self.assertEqual(report['status'], 'qualified')
        self.assertTrue(report['success'])
        self.assertFalse(report['VPN_started'])
        self.assertFalse(report['registry_mutated'])

    def test_duplicate_old_and_new_paths_fail_even_when_versions_tie(self):
        report = self.inspect(self.registration() + self.registration(self.root/'Old.app/Contents/PlugIns/XrayTunnel.appex'))
        self.assertIn('multiple_registered_provider_paths', report['failures'])
        self.assertTrue(report['duplicate_version_tie'])
        self.assertFalse(report['success'])

    def test_duplicate_versions_do_not_need_to_tie_to_fail(self):
        report = self.inspect(self.registration() + self.registration(self.root/'Old.appex', version='1.1.6'))
        self.assertFalse(report['duplicate_version_tie'])
        self.assertIn('multiple_registered_provider_paths', report['failures'])

    def test_adjacent_and_separated_selection_markers_do_not_hide_duplicates(self):
        old = self.root/'Old.app/Contents/PlugIns/XrayTunnel.appex'
        for marker in '+!-':
            for separator in ['', ' ', '\t']:
                with self.subTest(marker=marker, separator=separator):
                    marked = marker + separator + self.registration(old).lstrip()
                    report = self.inspect(self.registration() + marked)
                    self.assertEqual(report['status'], 'failed')
                    self.assertIn('multiple_registered_provider_paths', report['failures'])
                    self.assertEqual(len(report['registrations']), 2)
                    self.assertTrue(report['duplicate_version_tie'])

    def test_marked_malformed_own_entries_fail_instead_of_disappearing(self):
        for marker in '+!-':
            for separator in ['', ' ', '\t']:
                with self.subTest(marker=marker, separator=separator):
                    malformed = f'{marker}{separator}{self.provider_id}(1.1.7) malformed\n'
                    report = self.inspect(self.registration() + malformed)
                    self.assertEqual(report['status'], 'failed')
                    self.assertIn('own_registration_unreadable', report['failures'])

    def test_single_marked_current_registration_parses_consistently(self):
        for marker in '+!-':
            for separator in ['', ' ', '\t']:
                with self.subTest(marker=marker, separator=separator):
                    report = self.inspect(marker + separator + self.registration().lstrip())
                    self.assertEqual(len(report['registrations']), 1)
                    self.assertTrue(report['success'])

    def test_symlink_and_dot_path_aliases_are_one_registration(self):
        alias = self.root/'Alias.app'
        alias.symlink_to(self.app, target_is_directory=True)
        alias_provider = alias/'Contents/PlugIns/XrayTunnel.appex'
        report = self.inspect(self.registration() + self.registration(alias_provider),
                              [{'bundle_id': self.provider_id, 'provider_path': str(alias_provider/'Contents/MacOS/XrayTunnel'),
                                'provider_sha256': self.hash}])
        self.assertTrue(report['success'])
        self.assertEqual(len(report['registrations']), 1)

    def test_foreign_registration_and_foreign_launch_are_ignored(self):
        report = self.inspect(self.registration() + self.registration(self.root/'Foreign.appex', bundle_id='org.other.XrayTunnel'),
                              self.launched + [{'bundle_id': 'org.other.XrayTunnel', 'secret': 'never print'}])
        self.assertTrue(report['success'])
        self.assertNotIn('never print', json.dumps(report))

    def test_new_registration_never_proves_actual_launch(self):
        for observations in [[], [{'bundle_id': 'org.other.XrayTunnel'}]]:
            report = self.inspect(observations=observations)
            self.assertEqual(report['status'], 'unqualified')
            self.assertIn('actual_provider_launch_unobserved', report['unqualified'])

    def test_old_actual_launch_path_is_rejected_despite_current_registration(self):
        report = self.inspect(observations=[dict(self.launched[0], provider_path=str(self.root/'Old.appex'))])
        self.assertIn('launched_provider_path_mismatch', report['failures'])

    def test_launch_hash_mismatch_and_missing_hash_cannot_pass(self):
        report = self.inspect(observations=[dict(self.launched[0], provider_sha256='a'*64)])
        self.assertIn('launched_provider_hash_mismatch', report['failures'])
        report = self.inspect(observations=[{'bundle_id': self.provider_id, 'provider_path': str(self.provider)}])
        self.assertEqual(report['status'], 'unqualified')
        self.assertIn('launched_provider_hash_unobserved', report['unqualified'])

    def test_replaced_signed_binary_fails_build_receipt_hash(self):
        self.binary.write_bytes(b'new or stale signed image')
        self.assertIn('signed_provider_hash_mismatch', self.inspect()['failures'])

    def test_missing_receipt_hash_never_qualifies(self):
        del self.receipt['provider_sha256']
        for observations in [[], self.launched]:
            report = self.inspect(observations=observations)
            self.assertIn('signed_provider_hash_missing_from_build_receipt', report['unqualified'])
            self.assertEqual(report['status'], 'unqualified')

    def test_wrong_bundle_identifier_or_version_or_build_number_fails(self):
        path = self.provider/'Contents/Info.plist'
        original = plistlib.loads(path.read_bytes())
        for key, value, expected in [('CFBundleIdentifier', 'org.wrong', 'bundle_identifier_mismatch'),
                                      ('CFBundleShortVersionString', '1.1.6', 'bundle_version_mismatch'),
                                      ('CFBundleVersion', '116', 'app_provider_build_number_mismatch')]:
            path.write_bytes(plistlib.dumps(dict(original, **{key: value})))
            self.assertIn(expected, self.inspect()['failures'])
        path.write_bytes(plistlib.dumps(original))
        self.receipt['build_number'] = 118
        self.assertIn('build_receipt_number_mismatch', self.inspect()['failures'])

    def test_signature_failure_and_no_signature_check_never_qualify(self):
        report = subject.inspect(self.receipt, self.registration(), self.launched, verify_signature=lambda path: False)
        self.assertIn('code_signature_invalid', report['failures'])
        report = subject.inspect(self.receipt, self.registration(), self.launched)
        self.assertIn('code_signature_not_verified', report['unqualified'])

    def test_malformed_own_registration_is_not_silently_ignored(self):
        self.assertIn('own_registration_unreadable', self.inspect(f'{self.provider_id}(1.1.7) unparseable\n')['failures'])

    def test_provider_or_executable_symlink_outside_app_is_refused(self):
        outside = self.root/'outside'
        outside.write_bytes(b'outside executable')
        self.binary.unlink()
        self.binary.symlink_to(outside)
        self.assertIn('bundle_executable_escaped', self.inspect()['failures'])

    def test_invalid_metadata_and_relative_paths_return_fixed_failures(self):
        path = self.provider/'Contents/Info.plist'
        original = path.read_bytes()
        path.write_bytes(plistlib.dumps(['unexpected metadata']))
        self.assertIn('invalid_bundle_metadata', self.inspect()['failures'])
        path.write_bytes(original)
        self.receipt['app_path'] = 'relative.app'
        self.assertIn('absolute_path_required', self.inspect()['failures'])

    def test_launchd_reused_path_is_actual_not_requested_overlay(self):
        old = self.root/'Old.appex'
        logs = [{'eventMessage': f'Attempt to re-bootstrap service from different path, will use existing: service = {self.provider_id}, existing = {old}, conflicting = {self.provider}'},
                {'eventMessage': f'Submitting extension overlay path {self.provider}'},
                {'eventMessage': 'private profile contents that must not be returned'}]
        observations = subject.observations_from_logs(logs, self.provider_id)
        self.assertEqual(len(observations), 1)
        report = self.inspect(observations=observations)
        self.assertIn('launched_provider_path_mismatch', report['failures'])
        self.assertNotIn('private profile', json.dumps(report))
        self.assertEqual(subject.observations_from_logs(logs[1:], self.provider_id), [])

    def test_log_window_is_bounded_and_uses_matching_clock_forms(self):
        self.assertEqual(subject.log_window('2026-11-04 21:12:00', '2026-11-04 21:13:00'),
                         ['2026-11-04 21:12:00', '2026-11-04 21:13:00'])
        for start, end in [('bad', 'bad'), ('2026-11-04 21:12:00', '2026-11-04 21:12:00'),
                            ('2026-11-04 21:12:00', '2026-11-04 21:18:00'),
                            ('2026-11-04 21:12:00+03:00', '2026-11-04 21:13:00'),
                            ('2026-11-04 21:12:00+03:00', '2026-11-04 21:13:00+03:00')]:
            with self.assertRaises(subject.InspectionError):
                subject.log_window(start, end)

    def test_pure_inspection_never_invokes_subprocess_or_mutates_input(self):
        before = {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        receipt = dict(self.receipt)
        with mock.patch.object(subject.subprocess, 'run', side_effect=AssertionError('native command forbidden')):
            self.assertTrue(self.inspect()['success'])
        after = {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        self.assertEqual(before, after)
        self.assertEqual(receipt, self.receipt)

    def test_cli_uses_only_read_only_inspection_commands(self):
        receipt = self.root/'receipt.json'
        observations = self.root/'observations.json'
        receipt.write_text(json.dumps(self.receipt))
        observations.write_text(json.dumps(self.launched))
        calls = []
        def command(arguments, **kwargs):
            calls.append(arguments)
            output = self.registration().encode() if arguments[0] == 'pluginkit' else b''
            return subject.subprocess.CompletedProcess(arguments, 0, output, b'')
        output = io.StringIO()
        with mock.patch.object(subject.sys, 'platform', 'darwin'), \
                mock.patch.object(subject.subprocess, 'run', side_effect=command), \
                contextlib.redirect_stdout(output):
            code = subject.main(['--receipt', str(receipt), '--observations', str(observations)])
        self.assertEqual(code, 0)
        self.assertEqual(calls[0], ['pluginkit', '-m', '-A', '-D', '-v', '-i', self.provider_id])
        self.assertEqual(calls[1:], [['codesign', '--verify', '--deep', '--strict', str(bundle)]
                                    for bundle in [self.app, self.provider]])
        self.assertTrue(json.loads(output.getvalue())['success'])
        self.assertIn('trusted input', json.loads(output.getvalue())['launch_evidence_policy'])


if __name__ == '__main__':
    unittest.main()
