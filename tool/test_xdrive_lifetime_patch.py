#!/usr/bin/env python3
"""File-only regression against full reviewed upstream sources; never runs Go."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tool/fixtures/xdrive-v26.10.29'
spec = importlib.util.spec_from_file_location('xdrive_lifetime_patch', ROOT / 'third_party/xray-native-dns/xdrive_lifetime_patch.py')
patch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patch)


class XdriveLifetimePatchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / 'Core'
        shutil.copytree(FIXTURE, self.root)
        self.calls = []

    def replace(self, path, before, after):
        self.assertIn(path, patch.PATHS)
        target = self.root / path
        original = target.read_text()
        self.assertEqual(original.count(before), 1)
        target.write_text(original.replace(before, after))
        self.calls.append(path)

    def snapshot(self):
        return {p: (self.root / p).read_bytes() for p in patch.PATHS}

    def test_full_fixture_is_bound_to_reviewed_official_module(self):
        receipt = json.loads((FIXTURE / 'manifest.json').read_text())
        self.assertEqual(receipt['core_commit'], '0afec66085a85191e9dd2a4a6646c7c9a94688d1')
        self.assertEqual(receipt['upstream_sha256'], patch.UPSTREAM_SHA256)
        for path, expected in receipt['upstream_sha256'].items():
            self.assertEqual(hashlib.sha256((FIXTURE / path).read_bytes()).hexdigest(), expected, path)

    def test_legacy_fixture_exposes_detached_sessions_and_process_cache(self):
        self.assertIn('shared   = make(map[string]Storage)', (self.root / 'transport/internet/xdrive/storage.go').read_text())
        self.assertIn('newSlotConn(context.Background()', (self.root / 'transport/internet/xdrive/xdrive.go').read_text())
        self.assertNotIn('nativeXdriveLifetime', (self.root / 'core/xray.go').read_text())

    def test_patched_core_owns_services_and_preserves_request_context(self):
        patch.apply(self.root, self.replace)
        core = (self.root / 'core/xray.go').read_text()
        self.assertIn('xdrive.ContextWithNativeLifetime(server.ctx)', core)
        self.assertIn('if done { server.nativeXdriveLifetime.Close() }', core)
        self.assertLess(core.index('s.nativeXdriveLifetime.Close()'), core.index('for _, f := range s.features', core.index('func (s *Instance) Close')))
        source = (self.root / 'transport/internet/xdrive/xdrive.go').read_text()
        self.assertEqual(source.count('newNativeStorage(ctx, streamSettings)'), 2)
        self.assertIn('newSlotConn(ctx, slots,', source)
        self.assertIn('newConn(ctx, storage,', source)
        self.assertNotIn('newConn(context.Background()', source)
        self.assertNotIn('newSlotConn(context.Background()', source)
        client = (self.root / 'transport/internet/xdrive/client.go').read_text()
        self.assertIn('owner: connCtx', client)
        self.assertIn('context.AfterFunc(t.owner', client)
        self.assertIn('context.WithCancel(nativeLifetimeContext(lifetime))', client)
        owned = client[client.index('closeOwnedTransport :='):]
        self.assertLess(owned.index('pktConn.Close()'), owned.index('tr.Close()'))
        self.assertIn('if err != nil { closeOwnedTransport(); return nil, err }', owned)
        self.assertEqual((self.root / 'transport/internet/xdrive/storage.go').read_bytes(), (FIXTURE / 'transport/internet/xdrive/storage.go').read_bytes())

    def test_all_boundaries_are_checked_before_any_write(self):
        for relative in {item[0] for item in patch.replacements()}:
            with self.subTest(path=relative):
                shutil.rmtree(self.root)
                shutil.copytree(FIXTURE, self.root)
                target = self.root / relative
                target.write_text('unreviewed future implementation')
                before = self.snapshot()
                with self.assertRaisesRegex(ValueError, 'boundary changed'):
                    patch.apply(self.root, self.replace)
                self.assertEqual(before, self.snapshot())
                self.assertEqual(self.calls, [])

    def test_reapplication_refused_without_partial_mutation(self):
        patch.apply(self.root, self.replace)
        before = self.snapshot()
        self.calls.clear()
        with self.assertRaisesRegex(ValueError, 'boundary changed'):
            patch.apply(self.root, self.replace)
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.calls, [])

    def test_source_symlink_is_refused_before_writing(self):
        target = self.root / patch.PATHS[-2]
        external = self.root / 'unrelated.go'
        target.rename(external)
        target.symlink_to(external)
        with self.assertRaisesRegex(ValueError, 'boundary changed'):
            patch.apply(self.root, self.replace)
        self.assertEqual(self.calls, [])

    def test_independent_prior_edits_compose_without_changing_boundaries(self):
        path = self.root / 'core/xray.go'
        path.write_text(path.read_text() + '\n// independent reviewed patch\n')
        patch.apply(self.root, self.replace)
        self.assertTrue(path.read_text().endswith('// independent reviewed patch\n'))


if __name__ == '__main__':
    unittest.main()
