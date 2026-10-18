import copy
import hashlib
import json
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile

import verify_android_preview_apk as verifier


class PreviewAPKVerificationTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.apk = self.root / 'preview.apk'
        self.core_bytes = b'Core preview synthetic bytes\x00' * 17
        self.tun_bytes = b'Forwarder preview synthetic bytes\x00' * 23
        self.core = self.report('native-instance-preview-1', self.core_bytes)
        self.tun = self.report('native-tun-forwarder-preview-1', self.tun_bytes)
        self.core_name = 'lib/x86_64/' + verifier.CORE_NAME
        self.tun_name = 'lib/x86_64/' + verifier.TUN_NAME

    @staticmethod
    def report(capability, payload, arch='x86_64'):
        return dict(capability=capability, arch=arch,
                    artifact_sha256=hashlib.sha256(payload).hexdigest(),
                    production_enabled=False, host_qualified=False)

    def write(self, entries=None):
        if entries is None:
            entries = [(self.core_name, self.core_bytes)]
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(self.apk, 'w', compression=zipfile.ZIP_STORED) as archive:
                for name, payload in entries:
                    archive.writestr(name, payload)

    def verify(self, core=None, tun=None):
        return verifier.verify(self.apk, self.core if core is None else core, tun)

    def test_core_only_and_official_other_libraries_allowed(self):
        self.write([(self.core_name, self.core_bytes), ('lib/x86_64/libflutter.so', b'Flutter'),
                    ('lib/arm64-v8a/libunrelated.so', b'official unrelated native input'),
                    ('AndroidManifest.xml', b'synthetic')])
        result = self.verify()
        self.assertIs(result['verified'], True)
        self.assertEqual(result['entries'], {self.core_name: self.core['artifact_sha256']})
        self.assertIs(result['production_enabled'], False)
        self.assertIs(result['host_qualified'], False)

    def test_both_preview_libraries_match_streamed_bytes(self):
        self.core_bytes = bytes(range(256)) * 8193  # More than two read chunks.
        self.core = self.report('native-instance-preview-1', self.core_bytes)
        self.write([(self.core_name, self.core_bytes), (self.tun_name, self.tun_bytes)])
        self.assertEqual(self.verify(tun=self.tun)['entries'], {
            self.core_name: self.core['artifact_sha256'], self.tun_name: self.tun['artifact_sha256']})

    def test_each_supported_abi(self):
        for arch in verifier.SUPPORTED_ABIS:
            with self.subTest(arch=arch):
                self.write([(f'lib/{arch}/{verifier.CORE_NAME}', self.core_bytes)])
                report = dict(self.core, arch=arch)
                self.assertEqual(self.verify(core=report)['arch'], arch)

    def test_mutation_or_stale_verified_digest_refused(self):
        self.write([(self.core_name, self.core_bytes + b'changed')])
        with self.assertRaisesRegex(ValueError, 'checksum'):
            self.verify()
        self.write([(self.core_name, self.core_bytes), (self.tun_name, self.tun_bytes + b'changed')])
        with self.assertRaisesRegex(ValueError, 'checksum'):
            self.verify(tun=self.tun)

    def test_preview_under_extra_abi_or_wrong_path_refused(self):
        for name in [f'lib/arm64-v8a/{verifier.CORE_NAME}', f'assets/{verifier.CORE_NAME}',
                     f'lib/x86_64/../x86_64/{verifier.CORE_NAME}',
                     '\\'.join(('lib', 'x86_64', verifier.CORE_NAME)),
                     '/' + self.core_name, self.core_name + '/', self.core_name.upper(),
                     self.core_name + '/nested']:
            with self.subTest(name=name):
                self.write([(self.core_name, self.core_bytes), (name, self.core_bytes)])
                with self.assertRaisesRegex(ValueError, 'unexpected preview'):
                    self.verify()

    def test_tun_present_in_core_only_or_extra_tun_abi_refused(self):
        for name, tun in [(self.tun_name, None), (f'lib/x86/{verifier.TUN_NAME}', self.tun)]:
            with self.subTest(name=name):
                self.write([(self.core_name, self.core_bytes), (name, self.tun_bytes)])
                with self.assertRaisesRegex(ValueError, 'unexpected preview'):
                    self.verify(tun=tun)

    def test_missing_selected_entry_refused(self):
        for entries, tun in [([], None), ([(self.core_name, self.core_bytes)], self.tun),
                             ([(self.tun_name, self.tun_bytes)], self.tun)]:
            with self.subTest(entries=entries), self.assertRaisesRegex(ValueError, 'missing'):
                self.write(entries)
                self.verify(tun=tun)

    def test_duplicate_preview_names_refused_even_if_bytes_match(self):
        for name, payload in [(self.core_name, self.core_bytes), (self.tun_name, self.tun_bytes)]:
            with self.subTest(name=name):
                self.write([(self.core_name, self.core_bytes), (self.tun_name, self.tun_bytes), (name, payload)])
                with self.assertRaisesRegex(ValueError, 'duplicate'):
                    self.verify(tun=self.tun)

    def test_nul_truncated_preview_name_cannot_hide_an_extra_entry(self):
        alias = self.core_name + '_suffix'
        self.write([(self.core_name, self.core_bytes), (alias, b'foreign preview')])
        # Python's ZIP reader keeps orig_filename but truncates filename at NUL.
        # Mutate both local/central names while retaining their recorded lengths.
        data = self.apk.read_bytes().replace(alias.encode(), self.core_name.encode() + b'\x00suffix')
        self.apk.write_bytes(data)
        with self.assertRaisesRegex(ValueError, 'unexpected preview'):
            self.verify()

    def test_symlink_and_other_nonregular_selected_entry_refused(self):
        for kind in [stat.S_IFLNK, stat.S_IFIFO, stat.S_IFDIR]:
            with self.subTest(kind=kind):
                entry = zipfile.ZipInfo(self.core_name)
                entry.create_system = 3
                entry.external_attr = (kind | 0o600) << 16
                self.write([(entry, self.core_bytes)])
                with self.assertRaisesRegex(ValueError, 'regular file'):
                    self.verify()

    def test_report_capability_abi_checksum_and_exact_false_required(self):
        self.write()
        for key, value in [('capability', 'other'), ('arch', 'unknown'), ('arch', []),
                           ('artifact_sha256', 'A' * 64), ('artifact_sha256', '0' * 63),
                           ('artifact_sha256', None), ('production_enabled', 0),
                           ('production_enabled', True), ('host_qualified', None), ('host_qualified', 0)]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.verify(core=dict(self.core, **{key: value}))
        for key in self.core:
            with self.subTest(missing=key), self.assertRaises(ValueError):
                report = copy.deepcopy(self.core)
                del report[key]
                self.verify(core=report)
        for report in [None, [], 'report']:
            with self.subTest(report=report), self.assertRaises(ValueError):
                verifier.verify(self.apk, report)

    def test_tun_report_and_same_abi_required(self):
        self.write([(self.core_name, self.core_bytes), (self.tun_name, self.tun_bytes)])
        for key, value in [('arch', 'arm64-v8a'), ('capability', self.core['capability']),
                           ('artifact_sha256', 'invalid'), ('production_enabled', True), ('host_qualified', True)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.verify(tun=dict(self.tun, **{key: value}))

    def test_crc_corruption_and_invalid_zip_refused(self):
        self.write()
        data = bytearray(self.apk.read_bytes())
        # Corrupt the local stored payload without changing its recorded CRC.
        name_size, extra_size = struct.unpack_from('<HH', data, 26)
        data[30 + name_size + extra_size] ^= 0x01
        self.apk.write_bytes(data)
        with self.assertRaisesRegex(ValueError, 'ZIP data'):
            self.verify()
        self.apk.write_bytes(b'not an APK')
        with self.assertRaisesRegex(ValueError, 'ZIP data'):
            self.verify()

    def test_apk_symlink_refused(self):
        self.write()
        target = self.root / 'target.apk'
        self.apk.rename(target)
        try:
            self.apk.symlink_to(target)
        except OSError:
            self.skipTest('Symlink creation unavailable')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.verify()

    def test_cli_reads_reports_and_fails_nonzero_for_mutation(self):
        self.write([(self.core_name, self.core_bytes), (self.tun_name, self.tun_bytes)])
        core_path, tun_path = self.root / 'core.json', self.root / 'tun.json'
        core_path.write_text(json.dumps(self.core), encoding='utf-8')
        tun_path.write_text(json.dumps(self.tun), encoding='utf-8')
        command = [sys.executable, str(Path(verifier.__file__)), '--apk', str(self.apk),
                   '--core-verification', str(core_path), '--tun-verification', str(tun_path)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIs(json.loads(result.stdout)['verified'], True)
        self.write([(self.core_name, b'mutation'), (self.tun_name, self.tun_bytes)])
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
        self.assertIn('checksum', result.stderr)


if __name__ == '__main__':
    unittest.main()
