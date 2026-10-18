import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

import verify_android_tun_preview as verifier


class ForwarderVerificationTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.binary = self.root / 'jniLibs/x86_64/libtun2socks_preview.so'
        self.binary.parent.mkdir(parents=True)
        image = bytearray(256)
        image[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<HH', image, 16, 3, 62)
        struct.pack_into('<QQ', image, 24, 0x1000, 64)
        struct.pack_into('<HH', image, 54, 56, 1)
        struct.pack_into('<I', image, 64, 1)
        struct.pack_into('<Q', image, 112, 16384)
        self.binary.write_bytes(image)
        pin = json.loads((verifier.builder.CAPABILITY / 'pin-manifest.json').read_text())
        self.guarded = {}
        for relative in pin['upstream_sha256']:
            path = self.root / 'Source' / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('synthetic post-apply source: ' + relative).encode())
            self.guarded[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.metadata = dict(success=True, source_snapshot_unchanged=True, module_cache_targeted_sources_unchanged=True,
                             copied_guarded_sources_unchanged=True, patched_source_sha256=self.guarded.copy(),
                             published=False, production_enabled=False, host_qualified=False, runtime_executed=False,
                             capability=pin['capability'], forwarder_commit=pin['commit'], module_sum=pin['module_sum'],
                             arch='x86_64', artifact=str(self.binary), artifact_sha256=hashlib.sha256(image).hexdigest(),
                             input_sha256={'snapshot': 'current'})
        patch = mock.patch.object(verifier.builder, 'input_hashes', return_value={'snapshot': 'current'})
        patch.start()
        self.addCleanup(patch.stop)

    def verify(self, metadata=None):
        (self.root / 'result.json').write_text(json.dumps(self.metadata if metadata is None else metadata))
        return verifier.verify(self.root)

    def test_verified_forwarder_admitted(self):
        self.assertEqual(self.verify()['load_alignments'], [16384])

    def test_changed_provenance_and_published_inputs_refused(self):
        for key, value in [('success', False), ('source_snapshot_unchanged', False), ('module_cache_targeted_sources_unchanged', False),
                           ('copied_guarded_sources_unchanged', False),
                           ('published', True), ('production_enabled', True), ('host_qualified', True), ('runtime_executed', True),
                           ('forwarder_commit', 'old'), ('module_sum', 'wrong'), ('capability', 'legacy'), ('arch', 'unknown'),
                           ('artifact', str(self.root / 'elsewhere')), ('input_sha256', {'snapshot': 'old'})]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                changed = copy.deepcopy(self.metadata)
                changed[key] = value
                self.verify(changed)

    def test_guarded_evidence_requires_exact_manifest_keys(self):
        for patched in [None, {}, dict(self.guarded, unexpected='0' * 64),
                        {key: value for key, value in self.guarded.items() if key != 'proxy/socks5.go'}]:
            with self.subTest(patched=patched), self.assertRaisesRegex(ValueError, 'guarded source evidence'):
                changed = copy.deepcopy(self.metadata)
                changed['patched_source_sha256'] = patched
                self.verify(changed)

    def test_mutated_patched_original_refused(self):
        # These are original upstream files modified by apply.py, not additive
        # overlay files. The artifact and checkout hashes remain unchanged.
        for relative in ('proxy/socks5.go', 'transport/socks5/socks5.go', 'go.mod'):
            with self.subTest(relative=relative):
                path = self.root / 'Source' / relative
                original = path.read_bytes()
                try:
                    path.write_bytes(original + b' unrecorded build-source mutation')
                    with self.assertRaisesRegex(ValueError, 'guarded source checksum differs'):
                        self.verify()
                finally:
                    path.write_bytes(original)

    def test_symlinked_guarded_source_refused_even_with_equal_digest(self):
        path = self.root / 'Source/proxy/socks5.go'
        outside = self.root / 'same-bytes.go'
        outside.write_bytes(path.read_bytes())
        path.unlink()
        try:
            path.symlink_to(outside)
        except OSError:
            self.skipTest('Symlink creation unavailable')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.verify()

    def test_symlinked_guarded_parent_refused(self):
        parent = self.root / 'Source/proxy'
        moved = self.root / 'same-proxy'
        parent.rename(moved)
        try:
            parent.symlink_to(moved, target_is_directory=True)
        except OSError:
            self.skipTest('Symlink creation unavailable')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.verify()

    def test_missing_guarded_original_refused(self):
        (self.root / 'Source/transport/socks5/socks5.go').unlink()
        with self.assertRaisesRegex(ValueError, 'guarded source file is missing'):
            self.verify()

    def test_mutated_or_unverified_payload_refused(self):
        original = self.binary.read_bytes()
        self.binary.write_bytes(original + b'mutation')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            self.verify()
        self.binary.write_bytes(original)
        extra = self.binary.with_name('libunverified.so')
        extra.write_bytes(b'extra')
        with self.assertRaisesRegex(ValueError, 'unverified'):
            self.verify()


if __name__ == '__main__':
    unittest.main()
