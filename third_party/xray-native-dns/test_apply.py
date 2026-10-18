#!/usr/bin/env python3
"""Pure destination/cache guards; no Go, Core, or network execution."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('native_dns_apply', Path(__file__).with_name('apply.py'))
overlay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(overlay)


class ApplyGuards(unittest.TestCase):
    def test_refuses_existing_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(ValueError, 'new disposable'):
                overlay.validate_destination(root / 'source', root, [])

    def test_refuses_explicit_module_cache_and_children(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / 'custom-cache'
            for destination in [cache, cache / 'package']:
                with self.subTest(destination=destination), self.assertRaisesRegex(ValueError, 'module cache'):
                    overlay.validate_destination(root / 'source', destination, [cache])

    def test_refuses_conventional_module_cache_without_go(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(ValueError, 'module cache'):
                overlay.validate_destination(root / 'source', root / 'pkg/mod/package', [])

    def test_refuses_copy_inside_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(ValueError, 'outside the source'):
                overlay.validate_destination(root, root / 'copy', [])

    def test_refuses_changed_pin_before_creating_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, destination = root / 'source', root / 'copy'
            first = next(iter(overlay.MANIFEST['upstream_sha256']))
            target = source / first
            target.parent.mkdir(parents=True)
            target.write_text('not the pinned Core source')
            with self.assertRaisesRegex(ValueError, 'Pinned source mismatch'):
                overlay.copy_and_apply(source, destination, caches=[])
            self.assertFalse(destination.exists())
            self.assertEqual(target.read_text(), 'not the pinned Core source')

    def test_discovers_custom_module_cache_without_tool_download(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(overlay.os.environ, {'GOMODCACHE': temporary}), \
                mock.patch.object(overlay.subprocess, 'run', side_effect=OSError):
            self.assertEqual(overlay.module_cache_paths('missing-go'), [Path(temporary).resolve()])

    def test_refuses_symlink_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            link = root / 'link'
            try:
                link.symlink_to(root / 'absent', target_is_directory=True)
            except OSError:
                self.skipTest('Symlink creation unavailable')
            with self.assertRaisesRegex(ValueError, 'new disposable'):
                overlay.validate_destination(root / 'source', link, [])


if __name__ == '__main__':
    unittest.main()
