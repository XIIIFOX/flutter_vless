"""File-only XHTTP listener ownership guards; no Core, Go build or networking."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('xhttp_listener_lifetime_patch', HERE / 'xhttp_listener_lifetime_patch.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class XHTTPListenerPatchGuards(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / 'disposable'
        self.path = self.root / module.PATH
        self.path.parent.mkdir(parents=True)
        self.original = 'unchanged prefix\n' + module.BEFORE + '\nunchanged suffix\n'
        self.path.write_text(self.original, encoding='utf-8')
        self.calls = []

    def pins(self):
        return patch.dict(module.UPSTREAM_SHA256, {module.PATH: hashlib.sha256(self.path.read_bytes()).hexdigest()}, clear=True)

    def replace(self, name, before, after):
        self.assertEqual(name, module.PATH)
        self.calls.append(name)
        path = self.root / name
        source = path.read_text(encoding='utf-8')
        self.assertEqual(source.count(before), 1)
        path.write_text(source.replace(before, after), encoding='utf-8')

    def test_real_full_source_pin_is_shared_by_both_compositions(self):
        expected = 'a651b04643dde70653955a55501f4607d7ed6bb647ea3d39596fb63f7d734aaa'
        self.assertEqual(module.UPSTREAM_SHA256, {module.PATH: expected})
        for manifest in [HERE / 'pin-manifest.json', HERE.parent / 'xray-vpn-routing/pin-manifest.json']:
            self.assertEqual(json.loads(manifest.read_text())['upstream_sha256'][module.PATH], expected)

    def test_unknown_full_source_refused_before_callback(self):
        with self.assertRaisesRegex(ValueError, 'source mismatch'):
            module.apply(self.root, self.replace)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.path.read_text(), self.original)

    def test_unrelated_source_drift_refused_before_callback(self):
        with self.pins():
            changed = self.original.replace('unchanged prefix', 'unexpected upstream drift')
            self.path.write_text(changed)
            with self.assertRaisesRegex(ValueError, 'source mismatch'):
                module.apply(self.root, self.replace)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.path.read_text(), changed)

    def test_missing_or_duplicate_boundary_refused_without_writes(self):
        for content in [self.original.replace(module.BEFORE, 'new implementation'), self.original + module.BEFORE]:
            with self.subTest(content=content):
                self.path.write_text(content)
                before = self.path.read_bytes()
                with self.pins(), self.assertRaisesRegex(ValueError, 'boundary changed'):
                    module.apply(self.root, self.replace)
                self.assertEqual(self.calls, [])
                self.assertEqual(self.path.read_bytes(), before)

    def test_exact_owned_failure_path_only(self):
        sibling = self.path.with_name('client.go')
        sibling.write_bytes(b'unchanged sibling')
        with self.pins():
            module.apply(self.root, self.replace)
        self.assertEqual(self.calls, [module.PATH])
        self.assertEqual(self.path.read_text(), self.original.replace(module.BEFORE, module.AFTER))
        self.assertEqual(sibling.read_bytes(), b'unchanged sibling')
        self.assertEqual(module.AFTER.count('l.listener.Close()'), 1)
        self.assertLess(module.AFTER.index('l.listener.Close()'), module.AFTER.index('return nil'))

    def test_noop_callback_cannot_report_applied(self):
        before = self.path.read_bytes()
        with self.pins(), self.assertRaisesRegex(ValueError, 'did not apply the exact owned edit'):
            module.apply(self.root, lambda *_: None)
        self.assertEqual(self.path.read_bytes(), before)

    def test_partial_or_unrelated_callback_write_is_rejected(self):
        def wrong_edit(*_):
            self.path.write_text(self.original.replace('unchanged prefix', 'not the listener fix'))
        with self.pins(), self.assertRaisesRegex(ValueError, 'did not apply the exact owned edit'):
            module.apply(self.root, wrong_edit)

    def test_refusing_callback_propagates_without_touching_source(self):
        def refuse(*_):
            raise RuntimeError('producer callback refused')
        before = self.path.read_bytes()
        with self.pins(), self.assertRaisesRegex(RuntimeError, 'producer callback refused'):
            module.apply(self.root, refuse)
        self.assertEqual(self.path.read_bytes(), before)

    def test_second_application_refused_without_further_changes(self):
        with self.pins():
            module.apply(self.root, self.replace)
            changed = self.path.read_bytes()
            with self.assertRaisesRegex(ValueError, 'source mismatch'):
                module.apply(self.root, self.replace)
        self.assertEqual(self.calls, [module.PATH])
        self.assertEqual(self.path.read_bytes(), changed)

    def test_symlink_file_refused_without_touching_target(self):
        with self.pins():
            external = self.root / 'external.go'
            self.path.rename(external)
            before = external.read_bytes()
            self.path.symlink_to(external)
            with self.assertRaisesRegex(ValueError, 'real file'):
                module.apply(self.root, self.replace)
            self.assertEqual(external.read_bytes(), before)
        self.assertEqual(self.calls, [])

    def test_symlink_parent_refused_without_touching_target(self):
        with self.pins():
            parent = self.path.parent
            external = self.root / 'external-directory'
            parent.rename(external)
            before = (external / self.path.name).read_bytes()
            parent.symlink_to(external, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'symlink parents'):
                module.apply(self.root, self.replace)
            self.assertEqual((external / self.path.name).read_bytes(), before)
        self.assertEqual(self.calls, [])

    def test_missing_or_nonregular_source_refused_without_callback(self):
        self.path.unlink()
        with self.assertRaisesRegex(ValueError, 'real file'):
            module.apply(self.root, self.replace)
        self.path.mkdir()
        with self.assertRaisesRegex(ValueError, 'real file'):
            module.apply(self.root, self.replace)
        self.assertEqual(self.calls, [])

    def test_editing_a_disposable_copy_keeps_source_bytes_unchanged(self):
        source = self.root
        original = self.path.read_bytes()
        destination = Path(self.directory.name) / 'owned-copy'
        shutil.copytree(source, destination)
        with self.pins():
            self.root = destination
            module.apply(self.root, self.replace)
        self.assertEqual((source / module.PATH).read_bytes(), original)
        self.assertEqual((destination / module.PATH).read_text(), self.original.replace(module.BEFORE, module.AFTER))


if __name__ == '__main__':
    unittest.main()
