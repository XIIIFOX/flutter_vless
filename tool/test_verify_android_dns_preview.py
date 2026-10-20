import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

import verify_android_dns_preview as verifier


class PreviewVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.binary = self.root / 'jniLibs/x86_64/libxray_dns_preview.so'
        self.binary.parent.mkdir(parents=True)
        image = bytearray(256)
        image[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<HH', image, 16, 3, 62)
        struct.pack_into('<QQ', image, 24, 0x1000, 64)
        struct.pack_into('<HH', image, 54, 56, 1)
        struct.pack_into('<I', image, 64, 1)
        struct.pack_into('<Q', image, 64+48, 16384)
        self.binary.write_bytes(image)
        pin = json.loads((verifier.builder.CAPABILITY / 'pin-manifest.json').read_text())
        self.metadata = {'success': True, 'source_snapshot_unchanged': True, 'module_cache_targeted_sources_unchanged': True,
                         'published': False, 'production_enabled': False, 'host_qualified': False,
                         'runtime_executed': False, 'classic_dns_lifetime_applied': True, 'h3_lifetime_applied': True,
                         'lifetime_patch_scope': ['classic_dns', 'xhttp_h3_dial'], 'h3_lifetime_patch_sha256': 'a'*64,
                         'core_commit': pin['core_commit'], 'capability': 'native-instance-preview-1',
                         'arch': 'x86_64', 'artifact': str(self.binary), 'artifact_sha256': hashlib.sha256(image).hexdigest(),
                         'input_sha256': {'source': 'verified', 'third_party/xray-native-dns/h3_lifetime_patch.py': 'a'*64}}
        patch = mock.patch.object(verifier.builder, 'input_hashes', return_value=self.metadata['input_sha256'])
        patch.start()
        self.addCleanup(patch.stop)

    def check(self, metadata=None):
        (self.root / 'result.json').write_text(json.dumps(self.metadata if metadata is None else metadata))
        return verifier.verify(self.root)

    def test_exact_build_is_admitted(self):
        result = self.check()
        self.assertEqual(result['artifact_sha256'], self.metadata['artifact_sha256'])
        self.assertEqual(result['load_alignments'], [16384])
        self.assertFalse(result['host_qualified'])

    def test_incomplete_stale_or_published_build_is_refused(self):
        changes = [('success', False), ('source_snapshot_unchanged', False), ('module_cache_targeted_sources_unchanged', False),
                   ('published', True), ('production_enabled', True), ('host_qualified', True), ('arch', 'unknown'),
                   ('capability', 'legacy'), ('core_commit', 'wrong'), ('input_sha256', {'old': 'snapshot'}),
                   ('runtime_executed', True), ('runtime_executed', 0), ('h3_lifetime_applied', False), ('h3_lifetime_applied', 1),
                   ('classic_dns_lifetime_applied', False), ('lifetime_patch_scope', ['classic_dns']),
                   ('lifetime_patch_scope', ['classic_dns', 'xhttp_h3_dial', 'full_dns']), ('h3_lifetime_patch_sha256', 'b'*64),
                   ('artifact', str(self.root/'foreign')), ('artifact_sha256', 'bad')]
        for key, value in changes:
            with self.subTest(key=key), self.assertRaises(ValueError):
                metadata = copy.deepcopy(self.metadata)
                metadata[key] = value
                self.check(metadata)

    def test_missing_h3_scope_cannot_qualify_existing_preview(self):
        for key in ('h3_lifetime_applied', 'lifetime_patch_scope', 'h3_lifetime_patch_sha256'):
            with self.subTest(key=key), self.assertRaises(ValueError):
                metadata = copy.deepcopy(self.metadata)
                del metadata[key]
                self.check(metadata)

    def test_mutated_binary_and_bad_elf_alignment_are_refused(self):
        image = bytearray(self.binary.read_bytes())
        image[-1] ^= 1
        self.binary.write_bytes(image)
        with self.assertRaisesRegex(ValueError, 'checksum'):
            self.check()
        struct.pack_into('<Q', image, 64+48, 4096)
        self.binary.write_bytes(image)
        self.metadata['artifact_sha256'] = hashlib.sha256(image).hexdigest()
        with self.assertRaisesRegex(ValueError, '16 KiB'):
            self.check()

    def test_32_bit_android_program_table_at_standard_offset(self):
        for arch, machine in [('x86', 3), ('armeabi-v7a', 40)]:
            with self.subTest(arch=arch):
                image = bytearray(256)
                image[:6] = b'\x7fELF\x01\x01'
                struct.pack_into('<HH', image, 16, 3, machine)
                struct.pack_into('<II', image, 24, 0x1000, 52)
                struct.pack_into('<HH', image, 42, 32, 1)
                struct.pack_into('<I', image, 52, 1)
                struct.pack_into('<I', image, 52+28, 16384)
                self.binary.write_bytes(image)
                self.assertEqual(verifier.elf_alignment(self.binary, arch), [16384])

    def test_extra_jni_payloads_cannot_enter_debug_apk(self):
        for relative in ['x86_64/libforeign.so', 'arm64-v8a/libxray_dns_preview.so', '.unverified']:
            with self.subTest(relative=relative):
                extra = self.root / 'jniLibs' / relative
                extra.parent.mkdir(parents=True, exist_ok=True)
                extra.write_bytes(b'unverified')
                try:
                    with self.assertRaisesRegex(ValueError, 'unverified'):
                        self.check()
                finally:
                    extra.unlink()
                    if extra.parent.name == 'arm64-v8a':
                        extra.parent.rmdir()


if __name__ == '__main__':
    unittest.main()
