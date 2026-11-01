"""File-only published-byte and workflow controls; never execute a Core binary."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import install_published_runtime as subject


class PublishedRuntime(unittest.TestCase):
    def setUp(self):
        pe = bytearray(128)
        pe[:2] = b'MZ'; pe[60:64] = (64).to_bytes(4, 'little'); pe[64:70] = b'PE\0\0\x64\x86'
        self.files = {'xray.exe': bytes(pe), 'geoip.dat': b'full geoip',
                      'geosite.dat': b'full geosite', 'LICENSE.xray-core': b'license'}
        packed = io.BytesIO()
        with zipfile.ZipFile(packed, 'w', zipfile.ZIP_DEFLATED) as target:
            for name, data in self.files.items(): target.writestr(name, data)
        self.archive = packed.getvalue()
        self.doc = dict(success=True, head=subject.PRODUCER_HEAD, platform='windows-amd64',
                        core='26.10.31', core_commit=subject.CORE_COMMIT, runtime_revision='26.10.31-r1',
                        archive=subject.ARCHIVE, archive_sha256=hashlib.sha256(self.archive).hexdigest(),
                        files_sha256={name: hashlib.sha256(data).hexdigest() for name, data in self.files.items()},
                        capabilities={'stage': 'capabilities', 'code': 0, 'managed_service_lifetimes': 7})
        self.manifest = json.dumps(self.doc).encode()
        pins = patch.multiple(subject, ZIP_SHA256=self.doc['archive_sha256'],
                              CORE_SHA256=self.doc['files_sha256']['xray.exe'],
                              MANIFEST_SHA256=hashlib.sha256(self.manifest).hexdigest())
        pins.start(); self.addCleanup(pins.stop)

    def test_exact_pinned_archive_preserves_all_public_files(self):
        with patch.object(subject.subprocess, 'run', side_effect=AssertionError('no execution')):
            manifest, files = subject.verify(self.archive, self.manifest)
        self.assertEqual(files, self.files)
        self.assertEqual(manifest, self.doc)

    def test_byte_tampering_refuses_before_install_or_execution(self):
        for archive, manifest in [(self.archive + b'x', self.manifest), (self.archive, self.manifest + b' ')]:
            with self.subTest(archive=archive == self.archive), self.assertRaises(ValueError):
                subject.verify(archive, manifest)

    def test_pinned_metadata_must_match_release_and_extracted_files(self):
        changes = [{'head': 'b' * 40}, {'core': '26.10.29'}, {'runtime_revision': '26.10.31-r2'},
                   {'archive_sha256': 'b' * 64}, {'files_sha256': dict(self.doc['files_sha256'], **{'geoip.dat': 'b' * 64})},
                   {'capabilities': {'stage': 'capabilities', 'code': False, 'managed_service_lifetimes': 7}}]
        for change in changes:
            document = json.dumps(dict(self.doc, **change)).encode()
            with self.subTest(change=change), patch.object(subject, 'MANIFEST_SHA256', hashlib.sha256(document).hexdigest()), self.assertRaises(ValueError):
                subject.verify(self.archive, document)

    def test_host_cannot_install_or_execute_a_core(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder) / 'absent'
            with patch.object(subject.sys, 'platform', 'darwin'), patch.object(subject.subprocess, 'run') as child:
                with self.assertRaisesRegex(ValueError, 'Windows CI'):
                    subject.install(directory, self.archive, self.manifest)
            child.assert_not_called(); self.assertFalse(directory.exists())

    def test_install_probes_actual_version_and_capability_then_records_public_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            version = b'Xray 26.10.31 (Xray, Penetrates Everything.) Custom (fixture)\r\n'
            with patch.object(subject.sys, 'platform', 'win32'), \
                    patch.object(subject.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, version, b'')) as child, \
                    patch.object(subject, 'capabilities', return_value=self.doc['capabilities']) as capability:
                result = subject.install(directory, self.archive, self.manifest)
            self.assertEqual(child.call_args.args[0], [str(directory/'xray.exe'), 'version'])
            self.assertEqual(child.call_args.kwargs['timeout'], 10)
            capability.assert_called_once_with(directory/'xray.exe')
            self.assertEqual(result['core_sha256'], hashlib.sha256(self.files['xray.exe']).hexdigest())
            self.assertEqual(result['runtime_source'], 'published')
            self.assertEqual(json.loads((directory/'published-runtime-results.json').read_text()), result)
            self.assertEqual((directory/'published-runtime-manifest-results.json').read_bytes(), self.manifest)
            for name, data in self.files.items(): self.assertEqual((directory/name).read_bytes(), data)

    def test_old_prefix_or_failed_version_never_reaches_capability_or_success_receipt(self):
        for output in [b'Xray 26.10.29 (old)', b'Xray 26.10.310 (prefix)', b'Xray 26.10.31-custom (suffix)', b'']:
            with tempfile.TemporaryDirectory() as folder:
                directory = Path(folder)
                with patch.object(subject.sys, 'platform', 'win32'), \
                        patch.object(subject.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, output, b'')), \
                        patch.object(subject, 'capabilities') as capability, self.assertRaises(ValueError):
                    subject.install(directory, self.archive, self.manifest)
                capability.assert_not_called()
                self.assertFalse((directory/'published-runtime-results.json').exists())


class PublishedWorkflow(unittest.TestCase):
    def test_fixed_public_asset_identity(self):
        self.assertEqual(subject.TAG, 'xray-windows-v26.10.31-r1')
        self.assertEqual(subject.ZIP_SHA256, '19268b7f9f5ddedbcf9c3cb294175f28f1c6a4d495327e790f8e519e8073aa48')
        self.assertEqual(subject.CORE_SHA256, '00842f12870358c85a67fc3816a3dd75439566aef96a7d41d5a54e14e9a80eb0')
        self.assertEqual(subject.MANIFEST_SHA256, '70aaad33abab2a7ff81e2e13771d5d74996eefbc323c0caa977f0c20674a1842')

    def test_published_mode_never_builds_or_repackages_the_runtime(self):
        text = (Path(__file__).resolve().parents[2]/'.github/workflows/windows-runtime.yml').read_text()
        self.assertIn('options: [build, published]', text)
        self.assertIn('default: build', text)
        steps = text.split('\n      - ')
        for marker in ['uses: actions/setup-go@v6', 'name: Build unpublished routing runtime',
                       'name: Package the exact managed Core', 'name: Upload the newly built managed runtime']:
            matching = [step for step in steps if step.startswith(marker)]
            self.assertEqual(len(matching), 1, marker)
            self.assertIn("if: ${{ inputs.runtime_source != 'published' }}", matching[0])
        install = next(step for step in steps if step.startswith('name: Install the checksum-pinned published managed runtime'))
        self.assertIn("if: ${{ inputs.runtime_source == 'published' }}", install)
        self.assertIn('python tool/windows/install_published_runtime.py --directory build/windows-runtime', install)
        self.assertLess(text.index('name: Install the checksum-pinned published managed runtime'),
                        text.index('name: Build and run native configuration'))
        for name in ['build-and-proxy:', 'example-build:', 'vpn-routing:']:
            self.assertIn('\n  '+name, text)
        self.assertEqual(text.count('os: [windows-2022, windows-2025]'), 3)
        self.assertIn('Copy-Item build/windows-runtime/xray.exe build/windows-runtime/xray-official.exe', text)


if __name__ == '__main__': unittest.main()
