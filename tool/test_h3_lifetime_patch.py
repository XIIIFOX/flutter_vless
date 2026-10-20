#!/usr/bin/env python3
"""File-only guards for the pinned H3 ownership edit; no Core execution."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    'h3_lifetime_patch', ROOT / 'third_party/xray-native-dns/h3_lifetime_patch.py')
patch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patch)

LEGACY = '''\t\t\t\tconn, err := tr.DialEarly(ctx, udpAddr, tlsCfg, cfg)
\t\t\t\tif err != nil {
\t\t\t\t\treturn nil, err
\t\t\t\t}
\t\t\t\tcontext.AfterFunc(conn.Context(), func() { tr.Close(); pktConn.Close() })'''
RELATIVE = 'transport/internet/splithttp/dialer.go'


class H3LifetimePatchGuards(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.path = self.root / RELATIVE
        self.path.parent.mkdir(parents=True)
        self.original = 'untouched before\n' + LEGACY + '\nuntouched after\n'
        self.path.write_text(self.original)
        self.calls = []

    def replace(self, relative, before, after):
        self.assertEqual(relative, RELATIVE)
        self.calls.append(relative)
        path = self.root / relative
        source = path.read_text()
        if source.count(before) != 1:
            raise ValueError('replacement must be unique')
        path.write_text(source.replace(before, after))

    def test_owns_only_the_exact_dial_block(self):
        sibling = self.path.with_name('client.go')
        sibling.write_bytes(b'unchanged sibling')
        patch.apply(self.root, self.replace)
        changed = self.path.read_text()
        self.assertEqual(self.calls, [RELATIVE])
        self.assertTrue(changed.startswith('untouched before\n'))
        self.assertTrue(changed.endswith('\nuntouched after\n'))
        self.assertEqual(sibling.read_bytes(), b'unchanged sibling')
        self.assertNotIn(LEGACY, changed)
        self.assertIn('sync.OnceFunc(', changed)
        self.assertLess(changed.index('_ = pktConn.Close()'), changed.index('_ = tr.Close()'))
        self.assertIn('if err != nil {\n\t\t\t\t\tcloseOwnedTransport()\n', changed)
        self.assertIn('context.AfterFunc(conn.Context(), closeOwnedTransport)', changed)

    def test_unknown_or_duplicate_boundary_refused_before_callback(self):
        for source in ['unknown future H3 implementation', LEGACY + '\n' + LEGACY,
                       self.original.replace('return nil, err', 'return nil, changedError')]:
            with self.subTest(source=source):
                self.path.write_text(source)
                with self.assertRaisesRegex(ValueError, 'boundary changed'):
                    patch.apply(self.root, self.replace)
                self.assertEqual(self.path.read_text(), source)
                self.assertEqual(self.calls, [])

    def test_double_application_refused_without_further_changes(self):
        patch.apply(self.root, self.replace)
        changed = self.path.read_bytes()
        with self.assertRaisesRegex(ValueError, 'boundary changed'):
            patch.apply(self.root, self.replace)
        self.assertEqual(self.path.read_bytes(), changed)
        self.assertEqual(self.calls, [RELATIVE])

    def test_unrelated_prior_edits_can_compose(self):
        source = self.original.replace('untouched before', 'guarded DNS or routing edit')
        self.path.write_text(source)
        patch.apply(self.root, self.replace)
        self.assertTrue(self.path.read_text().startswith('guarded DNS or routing edit\n'))

    def test_callback_error_propagates(self):
        def refuse(*args):
            raise ValueError('caller guard refused')
        with self.assertRaisesRegex(ValueError, 'caller guard refused'):
            patch.apply(self.root, refuse)
        self.assertEqual(self.path.read_text(), self.original)

    def test_missing_source_refused_before_callback(self):
        self.path.unlink()
        with self.assertRaises(OSError):
            patch.apply(self.root, self.replace)
        self.assertEqual(self.calls, [])

    def test_symlink_source_refused_without_touching_target(self):
        target = self.path.with_name('external.go')
        self.path.rename(target)
        self.path.symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'real file'):
            patch.apply(self.root, self.replace)
        self.assertEqual(target.read_text(), self.original)
        self.assertEqual(self.calls, [])


if __name__ == '__main__':
    unittest.main()
